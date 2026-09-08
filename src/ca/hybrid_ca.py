"""
Hybrid Post-Quantum PKI Certificate Authority.

Issues X.509 certificates signed with a classical algorithm (ECDSA/RSA) today,
with hooks to add a post-quantum signature (ML-DSA / Dilithium via liboqs)
as a companion certificate once your target clients support it.

Why "hybrid" instead of pure-PQC:
  X.509 has no standardized way to carry two signatures in one certificate yet
  (IETF drafts exist but aren't finalized). The pragmatic approach used by
  real deployments today is dual-certificates: issue a classical cert AND a
  PQC cert from the same key material / identity, and let the peer pick
  whichever it supports during TLS negotiation (see draft-ietf-lamps-*).

Optional PQC support:
  pip install liboqs-python
  (requires the liboqs C library — see https://github.com/open-quantum-safe/liboqs)
  If not installed, the CA still works in classical-only mode.
"""

from __future__ import annotations

import datetime
import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

try:
    import oqs  # liboqs-python — optional, for real PQC signatures
    PQC_AVAILABLE = True
except ImportError:
    PQC_AVAILABLE = False

# Recommended NIST PQC signature algorithm (FIPS 204)
DEFAULT_PQC_SIG_ALG = "ML-DSA-65"


@dataclass
class IssuedCertBundle:
    """Everything produced by one issuance: classical cert, and optionally a PQC companion."""
    classical_cert_pem: bytes
    classical_key_pem: bytes
    pqc_cert_pem: Optional[bytes] = None
    pqc_public_key: Optional[bytes] = None
    pqc_algorithm: Optional[str] = None


class HybridCA:
    """
    A minimal CA that can act as root or intermediate.

    Usage:
        ca = HybridCA.create_root(common_name="My Root CA")
        ca.save("certs/root")

        bundle = ca.issue_leaf_cert(
            common_name="api.example.com",
            sans=["api.example.com"],
            enable_pqc=True,
        )
    """

    def __init__(self, cert: x509.Certificate, private_key, cert_pem: bytes, key_pem: bytes):
        self.cert = cert
        self.private_key = private_key
        self.cert_pem = cert_pem
        self.key_pem = key_pem

    # ------------------------------------------------------------------ #
    # Construction
    # ------------------------------------------------------------------ #

    @classmethod
    def create_root(
        cls,
        common_name: str,
        org_name: str = "Example Hybrid PQC CA",
        valid_days: int = 3650,
        key_size: int = 4096,
    ) -> "HybridCA":
        """Create a self-signed root CA (classical RSA today; PQC self-signed
        roots are possible once your trust stores accept them)."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        now = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=valid_days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False, key_cert_sign=True,
                    crl_sign=True, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .sign(private_key, hashes.SHA384())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return cls(cert, private_key, cert_pem, key_pem)

    @classmethod
    def load(cls, cert_path: str, key_path: str) -> "HybridCA":
        cert_pem = Path(cert_path).read_bytes()
        key_pem = Path(key_path).read_bytes()
        cert = x509.load_pem_x509_certificate(cert_pem)
        private_key = serialization.load_pem_private_key(key_pem, password=None)
        return cls(cert, private_key, cert_pem, key_pem)

    def save(self, path_prefix: str) -> None:
        os.makedirs(os.path.dirname(path_prefix) or ".", exist_ok=True)
        Path(f"{path_prefix}.crt").write_bytes(self.cert_pem)
        Path(f"{path_prefix}.key").write_bytes(self.key_pem)

    # ------------------------------------------------------------------ #
    # Issuance
    # ------------------------------------------------------------------ #

    def issue_leaf_cert(
        self,
        common_name: str,
        sans: list[str],
        valid_days: int = 397,  # CA/B Forum max for public TLS certs
        enable_pqc: bool = False,
        pqc_algorithm: str = DEFAULT_PQC_SIG_ALG,
    ) -> IssuedCertBundle:
        """Issue a leaf (end-entity) certificate signed by this CA, with an
        optional companion PQC certificate for hybrid trust."""

        # --- classical leaf ---
        leaf_key = ec.generate_private_key(ec.SECP384R1())

        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        san_entries = [self._san_entry(s) for s in sans]

        now = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=valid_days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False, key_encipherment=True,
                    data_encipherment=False, key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(self.private_key, hashes.SHA384())
        )

        bundle = IssuedCertBundle(
            classical_cert_pem=cert.public_bytes(serialization.Encoding.PEM),
            classical_key_pem=leaf_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )

        # --- optional PQC companion ---
        if enable_pqc:
            if not PQC_AVAILABLE:
                raise RuntimeError(
                    "PQC requested but liboqs-python is not installed. "
                    "Run `pip install liboqs-python` (requires the liboqs C library)."
                )
            with oqs.Signature(pqc_algorithm) as signer:
                pqc_public_key = signer.generate_keypair()
                # In production, wrap this in a proper cert-like structure
                # (e.g., a CBOR/CMS envelope) since x509 can't natively hold
                # a Dilithium public key/signature without a PQC-aware ASN.1
                # OID mapping. This demo signs a canonical identity blob.
                message = f"{common_name}|{','.join(sans)}|{now.isoformat()}".encode()
                signature = signer.sign(message)

                bundle.pqc_public_key = pqc_public_key
                bundle.pqc_algorithm = pqc_algorithm
                bundle.pqc_cert_pem = self._pack_pqc_envelope(
                    common_name, sans, pqc_public_key, signature, pqc_algorithm, now
                )

        return bundle

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _san_entry(value: str):
        try:
            return x509.IPAddress(ipaddress.ip_address(value))
        except ValueError:
            return x509.DNSName(value)

    @staticmethod
    def verify_pqc_envelope(envelope_pem: bytes) -> bool:
        """Verify a PQC identity envelope produced by `_pack_pqc_envelope`.
        Reconstructs the signed message and checks the signature with the
        embedded public key using the same algorithm it was signed with."""
        import base64
        import json

        if not PQC_AVAILABLE:
            raise RuntimeError("liboqs-python not installed; cannot verify PQC envelope.")

        text = envelope_pem.decode()
        body = "".join(
            line.strip() for line in text.splitlines()
            if line and "-----" not in line
        )
        payload = json.loads(base64.b64decode(body))

        pub_key = base64.b64decode(payload["public_key_b64"])
        signature = base64.b64decode(payload["signature_b64"])
        message = f"{payload['common_name']}|{','.join(payload['sans'])}|{payload['issued_at']}".encode()

        with oqs.Signature(payload["algorithm"]) as verifier:
            return verifier.verify(message, signature, pub_key)

    @staticmethod
    def _pack_pqc_envelope(cn, sans, pub_key, signature, alg, issued_at) -> bytes:
        """Simple PEM-like envelope for the PQC identity until a standard
        ASN.1/X.509 OID mapping for your chosen algorithm is finalized in
        your target ecosystem. Swap this for CMS/CBOR in production."""
        import base64
        import json

        payload = {
            "common_name": cn,
            "sans": sans,
            "algorithm": alg,
            "public_key_b64": base64.b64encode(pub_key).decode(),
            "signature_b64": base64.b64encode(signature).decode(),
            "issued_at": issued_at.isoformat(),
        }
        body = base64.b64encode(json.dumps(payload).encode()).decode()
        wrapped = "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
        return f"-----BEGIN PQC IDENTITY-----\n{wrapped}\n-----END PQC IDENTITY-----\n".encode()
