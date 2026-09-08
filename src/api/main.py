"""
REST API for the Hybrid PQC PKI server.

Run:
    uvicorn src.api.main:app --reload --port 8443

Endpoints:
    POST /ca/init                 -> create a new root CA (dev/demo only)
    POST /certs/issue             -> issue a leaf cert (classical + optional PQC)
    GET  /certs/{serial}          -> fetch an issued cert
    POST /certs/{serial}/revoke   -> revoke a cert
    GET  /crl                     -> current classical CRL (PEM)
"""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from src.ca.hybrid_ca import HybridCA, PQC_AVAILABLE

app = FastAPI(title="Hybrid PQC PKI Server", version="0.1.0")

CA_CERT_PATH = "certs/root.crt"
CA_KEY_PATH = "certs/root.key"

_ca: Optional[HybridCA] = None
_issued: dict[int, dict] = {}       # serial -> {cert_pem, status, common_name}
_revoked_serials: set[int] = set()


class IssueRequest(BaseModel):
    common_name: str = Field(..., examples=["api.example.com"])
    sans: list[str] = Field(default_factory=list)
    valid_days: int = 397
    enable_pqc: bool = False
    pqc_algorithm: str = "ML-DSA-65"


def get_ca() -> HybridCA:
    global _ca
    if _ca is None:
        if Path(CA_CERT_PATH).exists() and Path(CA_KEY_PATH).exists():
            _ca = HybridCA.load(CA_CERT_PATH, CA_KEY_PATH)
        else:
            raise HTTPException(400, "CA not initialized. Call POST /ca/init first.")
    return _ca


@app.post("/ca/init")
def init_ca(common_name: str = "Hybrid PQC Root CA"):
    global _ca
    _ca = HybridCA.create_root(common_name=common_name)
    _ca.save("certs/root")
    return {"status": "created", "common_name": common_name, "pqc_available": PQC_AVAILABLE}


@app.post("/certs/issue")
def issue_cert(req: IssueRequest):
    ca = get_ca()
    if req.enable_pqc and not PQC_AVAILABLE:
        raise HTTPException(
            400,
            "PQC requested but liboqs-python isn't installed on this server. "
            "Install it or set enable_pqc=false.",
        )

    bundle = ca.issue_leaf_cert(
        common_name=req.common_name,
        sans=req.sans or [req.common_name],
        valid_days=req.valid_days,
        enable_pqc=req.enable_pqc,
        pqc_algorithm=req.pqc_algorithm,
    )

    cert = x509.load_pem_x509_certificate(bundle.classical_cert_pem)
    serial = cert.serial_number
    _issued[serial] = {
        "common_name": req.common_name,
        "status": "valid",
        "classical_cert_pem": bundle.classical_cert_pem.decode(),
        "pqc_cert_pem": bundle.pqc_cert_pem.decode() if bundle.pqc_cert_pem else None,
    }

    return {
        "serial": serial,
        "classical_cert_pem": bundle.classical_cert_pem.decode(),
        "classical_key_pem": bundle.classical_key_pem.decode(),
        "pqc_cert_pem": bundle.pqc_cert_pem.decode() if bundle.pqc_cert_pem else None,
        "pqc_algorithm": bundle.pqc_algorithm,
    }


@app.get("/certs/{serial}")
def get_cert(serial: int):
    record = _issued.get(serial)
    if not record:
        raise HTTPException(404, "Certificate not found")
    return record


@app.post("/certs/{serial}/revoke")
def revoke_cert(serial: int):
    if serial not in _issued:
        raise HTTPException(404, "Certificate not found")
    _revoked_serials.add(serial)
    _issued[serial]["status"] = "revoked"
    return {"serial": serial, "status": "revoked"}


@app.get("/crl")
def get_crl():
    ca = get_ca()
    now = datetime.datetime.utcnow()
    builder = x509.CertificateRevocationListBuilder().issuer_name(ca.cert.subject)
    builder = builder.last_update(now).next_update(now + datetime.timedelta(days=7))

    for serial in _revoked_serials:
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(now)
            .build()
        )
        builder = builder.add_revoked_certificate(revoked)

    crl = builder.sign(private_key=ca.private_key, algorithm=hashes.SHA384())
    return {"crl_pem": crl.public_bytes(serialization.Encoding.PEM).decode()}


@app.post("/certs/{serial}/verify-pqc")
def verify_pqc(serial: int):
    """Verify the PQC companion identity for an issued certificate."""
    record = _issued.get(serial)
    if not record or not record.get("pqc_cert_pem"):
        raise HTTPException(404, "No PQC identity found for this certificate")
    valid = HybridCA.verify_pqc_envelope(record["pqc_cert_pem"].encode())
    return {"serial": serial, "pqc_signature_valid": valid}


@app.get("/health")
def health():
    return {"status": "ok", "pqc_available": PQC_AVAILABLE}
