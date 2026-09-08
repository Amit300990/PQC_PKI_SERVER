import base64
import ipaddress
import shutil
import unittest
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from src.api.main import Settings, create_app


class PkiApiTestCase(unittest.TestCase):
    def setUp(self):
        self.runtime_path = Path("tests/.runtime") / str(uuid.uuid4())
        self.runtime_path.mkdir(parents=True)
        self.settings = Settings(
            database_url=f"sqlite:///{(self.runtime_path / 'pki.db').resolve()}",
            ca_cert_path=self.runtime_path / "root.crt",
            ca_key_path=self.runtime_path / "root.key",
            admin_token="admin-test-token",
            operator_token="operator-test-token",
            auditor_token="auditor-test-token",
        )
        self.client = TestClient(create_app(self.settings))
        self.client.__enter__()
        self.headers = {
            "admin": {"X-API-Key": self.settings.admin_token},
            "operator": {"X-API-Key": self.settings.operator_token},
            "auditor": {"X-API-Key": self.settings.auditor_token},
        }

    def tearDown(self):
        if self.client is not None:
            self.client.__exit__(None, None, None)
        shutil.rmtree(self.runtime_path)

    def initialize_ca(self):
        response = self.client.post("/ca/init", headers=self.headers["admin"])
        self.assertEqual(response.status_code, 200, response.text)

    @staticmethod
    def make_csr(common_name="api.example.com", sans=None):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        )
        if sans is not None:
            san_entries = []
            for value in sans:
                try:
                    san_entries.append(x509.IPAddress(ipaddress.ip_address(value)))
                except ValueError:
                    san_entries.append(x509.DNSName(value))
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_entries),
                critical=False,
            )
        csr = builder.sign(private_key, hashes.SHA256())
        return private_key, csr.public_bytes(serialization.Encoding.PEM)

    def issue_certificate(self, csr_pem):
        response = self.client.post(
            "/certs/issue",
            headers=self.headers["operator"],
            json={"csr_pem": csr_pem.decode(), "valid_days": 90, "enable_pqc": False},
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_csr_issuance_uses_client_public_key_and_no_private_key(self):
        self.initialize_ca()
        private_key, csr_pem = self.make_csr(sans=["api.example.com", "192.0.2.10"])

        issued = self.issue_certificate(csr_pem)
        certificate = x509.load_pem_x509_certificate(issued["classical_cert_pem"].encode())

        self.assertNotIn("classical_key_pem", issued)
        self.assertEqual(
            certificate.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            private_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )
        self.assertEqual(issued["common_name"], "api.example.com")
        self.assertEqual(issued["sans"], ["api.example.com", "192.0.2.10"])
        self.assertRegex(issued["serial"], r"^[0-9A-F]+$")

        fetched = self.client.get(f"/certs/{issued['serial']}", headers=self.headers["auditor"])
        self.assertEqual(fetched.status_code, 200, fetched.text)
        self.assertEqual(fetched.json()["public_key_sha256"], issued["public_key_sha256"])

    def test_invalid_csr_signature_is_rejected(self):
        self.initialize_ca()
        _, csr_pem = self.make_csr()
        der = bytearray(x509.load_pem_x509_csr(csr_pem).public_bytes(serialization.Encoding.DER))
        der[-1] ^= 1
        invalid_csr = (
            b"-----BEGIN CERTIFICATE REQUEST-----\n"
            + base64.encodebytes(bytes(der))
            + b"-----END CERTIFICATE REQUEST-----\n"
        )

        response = self.client.post(
            "/certs/issue",
            headers=self.headers["operator"],
            json={"csr_pem": invalid_csr.decode()},
        )
        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn("signature", response.json()["detail"].lower())

    def test_rbac_returns_401_403_and_503(self):
        _, csr_pem = self.make_csr()

        self.assertEqual(self.client.post("/ca/init").status_code, 401)
        self.assertEqual(self.client.post("/ca/init", headers=self.headers["auditor"]).status_code, 403)
        self.initialize_ca()
        self.assertEqual(
            self.client.post("/certs/issue", headers=self.headers["admin"], json={"csr_pem": csr_pem.decode()}).status_code,
            403,
        )
        self.assertEqual(
            self.client.post("/certs/issue", headers=self.headers["auditor"], json={"csr_pem": csr_pem.decode()}).status_code,
            403,
        )
        self.assertEqual(self.client.get("/audit", headers=self.headers["operator"]).status_code, 403)

        unavailable = TestClient(
            create_app(
                Settings(
                    database_url=f"sqlite:///{(self.runtime_path / 'unavailable.db').resolve()}",
                    ca_cert_path=self.runtime_path / "unavailable.crt",
                    ca_key_path=self.runtime_path / "unavailable.key",
                )
            )
        )
        with unavailable:
            response = unavailable.post("/ca/init", headers={"X-API-Key": "any-token"})
        self.assertEqual(response.status_code, 503)

        legacy_settings = Settings(
            database_url=f"sqlite:///{(self.runtime_path / 'legacy.db').resolve()}",
            ca_cert_path=self.runtime_path / "legacy.crt",
            ca_key_path=self.runtime_path / "legacy.key",
            legacy_api_key="legacy-test-token",
        )
        with TestClient(create_app(legacy_settings)) as legacy_client:
            self.assertEqual(
                legacy_client.post("/ca/init", headers={"X-API-Key": "legacy-test-token"}).status_code,
                200,
            )
            legacy_issue = legacy_client.post(
                "/certs/issue",
                headers={"X-API-Key": "legacy-test-token"},
                json={"csr_pem": csr_pem.decode()},
            )
            self.assertEqual(legacy_issue.status_code, 200, legacy_issue.text)

    def test_persistence_revocation_crl_and_audit_survive_restart(self):
        self.initialize_ca()
        _, csr_pem = self.make_csr()
        issued = self.issue_certificate(csr_pem)

        self.client.__exit__(None, None, None)
        self.client = None
        with TestClient(create_app(self.settings)) as restarted_client:
            listed = restarted_client.get("/certs", headers=self.headers["auditor"])
            self.assertEqual(listed.status_code, 200, listed.text)
            self.assertEqual([record["serial"] for record in listed.json()], [issued["serial"]])

            revoked = restarted_client.post(
                f"/certs/{issued['serial']}/revoke",
                headers=self.headers["operator"],
            )
            self.assertEqual(revoked.status_code, 200, revoked.text)
            self.assertTrue(revoked.json()["newly_revoked"])
            self.assertEqual(revoked.json()["status"], "revoked")
            self.assertIsNotNone(revoked.json()["revoked_at"])

            crl_response = restarted_client.get("/crl", headers=self.headers["auditor"])
            self.assertEqual(crl_response.status_code, 200, crl_response.text)
            crl = x509.load_pem_x509_crl(crl_response.json()["crl_pem"].encode())
            self.assertIn(int(issued["serial"], 16), [entry.serial_number for entry in crl])

            audit_response = restarted_client.get("/audit", headers=self.headers["auditor"])
            self.assertEqual(audit_response.status_code, 200, audit_response.text)
            actions = [event["action"] for event in audit_response.json()]
            self.assertIn("ca.initialized", actions)
            self.assertIn("certificate.issued", actions)
            self.assertIn("certificate.revoked", actions)
            revocation_event = next(event for event in audit_response.json() if event["action"] == "certificate.revoked")
            self.assertEqual(revocation_event["actor_identity"], "operator")
            self.assertEqual(revocation_event["actor_role"], "operator")


if __name__ == "__main__":
    unittest.main()
