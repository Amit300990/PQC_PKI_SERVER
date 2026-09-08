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
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
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
    common_name: str
    sans: list[str]
    pqc_identity_pem: Optional[bytes] = None
    pqc_public_key: Optional[bytes] = None
    pqc_algorithm: Optional[str] = None


class HybridCA:
    """
    A minimal CA that can act as root or intermediate.

    Usage:
        ca = HybridCA.create_root(common_name="My Root CA")
        ca.save("certs/root")

        bundle = ca.issue_from_csr(csr_pem, enable_pqc=True)
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

        now = datetime.datetime.now(datetime.timezone.utc)
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
        if private_key.public_key().public_numbers() != cert.public_key().public_numbers():
            raise ValueError("CA private key does not match the CA certificate.")
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if not constraints.ca:
            raise ValueError("CA certificate does not have CA basic constraints.")
        return cls(cert, private_key, cert_pem, key_pem)

    def save(self, cert_path_or_prefix: str, key_path: Optional[str] = None) -> None:
        """Persist CA material with a private-key mode of 0600.

        Passing a prefix retains the original ``<prefix>.crt/.key`` behavior;
        passing both paths permits explicit production storage configuration.
        """
        cert_path = Path(f"{cert_path_or_prefix}.crt") if key_path is None else Path(cert_path_or_prefix)
        key_path = Path(f"{cert_path_or_prefix}.key") if key_path is None else Path(key_path)
        os.makedirs(cert_path.parent, mode=0o700, exist_ok=True)
        os.makedirs(key_path.parent, mode=0o700, exist_ok=True)
        cert_path.write_bytes(self.cert_pem)
        if key_path.exists():
            os.chmod(key_path, 0o600)
        key_descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(key_descriptor, "wb") as key_file:
                key_file.write(self.key_pem)
        finally:
            os.chmod(key_path, 0o600)

    # ------------------------------------------------------------------ #
    # Issuance
    # ------------------------------------------------------------------ #

    def issue_from_csr(
        self,
        csr_pem: bytes,
        valid_days: int = 397,  # CA/B Forum max for public TLS certs
        enable_pqc: bool = False,
        pqc_algorithm: str = DEFAULT_PQC_SIG_ALG,
    ) -> IssuedCertBundle:
        """Issue a certificate for a verified CSR without handling its private key.

        Only a conservative subject whitelist and DNS/IP SAN values from the CSR
        are copied.  All certificate capability extensions remain CA controlled.
        """
        try:
            csr = x509.load_pem_x509_csr(csr_pem)
        except ValueError as error:
            raise ValueError("CSR must be a valid PEM-encoded certificate signing request.") from error
        if not csr.is_signature_valid:
            raise ValueError("CSR signature validation failed.")

        subject, common_name = self._controlled_subject(csr.subject)
        sans = self._controlled_sans(csr)
        public_key = csr.public_key()

        now = datetime.datetime.now(datetime.timezone.utc)
        cert_not_after = min(
            now + datetime.timedelta(days=valid_days),
            self.cert.not_valid_after_utc,
        )
        if cert_not_after <= now:
            raise ValueError("CA certificate has expired and cannot issue leaf certificates.")
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(cert_not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=isinstance(public_key, rsa.RSAPublicKey),
                    data_encipherment=False, key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
        )
        if sans:
            cert = cert.add_extension(
                x509.SubjectAlternativeName([self._san_entry(value) for value in sans]),
                critical=False,
            )
        cert = cert.sign(self.private_key, hashes.SHA384())

        bundle = IssuedCertBundle(
            classical_cert_pem=cert.public_bytes(serialization.Encoding.PEM),
            common_name=common_name,
            sans=sans,
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
                bundle.pqc_identity_pem = self._pack_pqc_envelope(
                    common_name, sans, pqc_public_key, signature, pqc_algorithm, now
                )

        return bundle

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _controlled_subject(subject: x509.Name) -> tuple[x509.Name, str]:
        allowed_oids = {
            NameOID.COUNTRY_NAME,
            NameOID.STATE_OR_PROVINCE_NAME,
            NameOID.LOCALITY_NAME,
            NameOID.ORGANIZATION_NAME,
            NameOID.ORGANIZATIONAL_UNIT_NAME,
            NameOID.COMMON_NAME,
            NameOID.EMAIL_ADDRESS,
        }
        attributes = list(subject)
        if not attributes:
            raise ValueError("CSR subject must contain a common name.")
        if any(attribute.oid not in allowed_oids for attribute in attributes):
            raise ValueError("CSR subject contains an unsupported name attribute.")

        common_names = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(common_names) != 1:
            raise ValueError("CSR subject must contain exactly one common name.")
        common_name = common_names[0].value
        if not HybridCA._valid_subject_value(common_name, maximum_length=64):
            raise ValueError("CSR common name must be 1-64 printable characters.")

        for attribute in attributes:
            maximum_length = 128 if attribute.oid != NameOID.COUNTRY_NAME else 2
            if not HybridCA._valid_subject_value(attribute.value, maximum_length=maximum_length):
                raise ValueError(f"CSR subject value for {attribute.oid.dotted_string} is invalid.")
        return x509.Name(attributes), common_name

    @staticmethod
    def _valid_subject_value(value: str, maximum_length: int) -> bool:
        return bool(
            value
            and value == value.strip()
            and len(value) <= maximum_length
            and "\x00" not in value
            and all(character.isprintable() for character in value)
        )

    @staticmethod
    def _controlled_sans(csr: x509.CertificateSigningRequest) -> list[str]:
        try:
            requested_sans = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        except x509.ExtensionNotFound:
            return []

        if len(requested_sans) > 100:
            raise ValueError("CSR contains too many subject alternative names.")
        sans: list[str] = []
        for entry in requested_sans:
            if isinstance(entry, x509.DNSName):
                value = HybridCA._validated_dns_name(entry.value)
            elif isinstance(entry, x509.IPAddress):
                value = str(entry.value)
            else:
                raise ValueError("Only DNS and IP address subject alternative names are allowed.")
            if value in sans:
                raise ValueError("CSR contains duplicate subject alternative names.")
            sans.append(value)
        return sans

    @staticmethod
    def _validated_dns_name(value: str) -> str:
        if not value or len(value) > 253 or "\x00" in value:
            raise ValueError("CSR contains an invalid DNS subject alternative name.")
        try:
            value.encode("ascii")
        except UnicodeEncodeError as error:
            raise ValueError("DNS subject alternative names must use ASCII or punycode.") from error

        hostname = value[2:] if value.startswith("*.") else value
        label_pattern = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
        if not hostname or any(not label_pattern.fullmatch(label) for label in hostname.split(".")):
            raise ValueError("CSR contains an invalid DNS subject alternative name.")
        return value.lower()

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
