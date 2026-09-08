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
import json
import os
import secrets
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Annotated, Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from src.ca.hybrid_ca import HybridCA, PQC_AVAILABLE

app = FastAPI(title="Hybrid PQC PKI Server", version="0.1.0")

CA_CERT_PATH = "certs/root.crt"
CA_KEY_PATH = "certs/root.key"
ISSUED_STATE_PATH = "certs/issued.json"
STATIC_DIR = Path(__file__).parent / "static"

_ca: Optional[HybridCA] = None
_issued: Optional[dict[int, dict[str, Any]]] = None


class IssueRequest(BaseModel):
    common_name: str = Field(..., min_length=1, max_length=64, examples=["api.example.com"])
    sans: list[str] = Field(default_factory=list)
    valid_days: int = Field(default=397, ge=1, le=397)
    enable_pqc: bool = False
    pqc_algorithm: str = "ML-DSA-65"


def require_api_key(x_api_key: Annotated[Optional[str], Header()] = None) -> None:
    configured_key = os.getenv("PKI_API_KEY")
    if not configured_key:
        raise HTTPException(503, "PKI_API_KEY must be configured before using the CA API.")
    if not x_api_key or not secrets.compare_digest(x_api_key, configured_key):
        raise HTTPException(401, "A valid X-API-Key header is required.")


def get_issued() -> dict[int, dict[str, Any]]:
    global _issued
    if _issued is None:
        state_path = Path(ISSUED_STATE_PATH)
        if not state_path.exists():
            _issued = {}
        else:
            try:
                persisted_records = json.loads(state_path.read_text())
                if not isinstance(persisted_records, dict):
                    raise ValueError("certificate records must be a JSON object")
                _issued = {int(serial): record for serial, record in persisted_records.items()}
            except (OSError, ValueError, json.JSONDecodeError) as error:
                raise RuntimeError(f"Unable to load issued certificate state: {error}") from error
    return _issued


def save_issued(records: dict[int, dict[str, Any]]) -> None:
    state_path = Path(ISSUED_STATE_PATH)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=state_path.parent,
        prefix=f".{state_path.name}.",
        delete=False,
    ) as temporary_file:
        json.dump({str(serial): record for serial, record in records.items()}, temporary_file)
        temporary_file.flush()
        os.fsync(temporary_file.fileno())
        temporary_path = Path(temporary_file.name)
    os.chmod(temporary_path, 0o600)
    temporary_path.replace(state_path)


def get_ca() -> HybridCA:
    global _ca
    if _ca is None:
        if Path(CA_CERT_PATH).exists() and Path(CA_KEY_PATH).exists():
            _ca = HybridCA.load(CA_CERT_PATH, CA_KEY_PATH)
        else:
            raise HTTPException(400, "CA not initialized. Call POST /ca/init first.")
    return _ca


@app.post("/ca/init", dependencies=[Depends(require_api_key)])
def init_ca(common_name: str = "Hybrid PQC Root CA", force: bool = False):
    global _ca
    if not force and (Path(CA_CERT_PATH).exists() or Path(CA_KEY_PATH).exists()):
        raise HTTPException(
            409,
            "CA already initialized. Pass force=true only when intentionally replacing the CA.",
        )
    _ca = HybridCA.create_root(common_name=common_name)
    _ca.save(str(Path(CA_CERT_PATH).with_suffix("")))
    if force:
        records = get_issued()
        records.clear()
        save_issued(records)
    return {"status": "created", "common_name": common_name, "pqc_available": PQC_AVAILABLE}


@app.post("/certs/issue", dependencies=[Depends(require_api_key)])
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
    issued = get_issued()
    issued[serial] = {
        "common_name": req.common_name,
        "status": "valid",
        "revoked_at": None,
        "classical_cert_pem": bundle.classical_cert_pem.decode(),
        "pqc_identity_pem": bundle.pqc_identity_pem.decode() if bundle.pqc_identity_pem else None,
    }
    save_issued(issued)

    return {
        "serial": serial,
        "classical_cert_pem": bundle.classical_cert_pem.decode(),
        "classical_key_pem": bundle.classical_key_pem.decode(),
        "pqc_identity_pem": bundle.pqc_identity_pem.decode() if bundle.pqc_identity_pem else None,
        "pqc_algorithm": bundle.pqc_algorithm,
    }


@app.get("/certs/{serial}", dependencies=[Depends(require_api_key)])
def get_cert(serial: int):
    record = get_issued().get(serial)
    if not record:
        raise HTTPException(404, "Certificate not found")
    return record


@app.get("/certs", dependencies=[Depends(require_api_key)])
def list_certs():
    return [
        {
            "serial": serial,
            "common_name": record["common_name"],
            "status": record["status"],
            "revoked_at": record["revoked_at"],
            "has_pqc_identity": bool(record.get("pqc_identity_pem")),
        }
        for serial, record in get_issued().items()
    ]


@app.post("/certs/{serial}/revoke", dependencies=[Depends(require_api_key)])
def revoke_cert(serial: int):
    issued = get_issued()
    if serial not in issued:
        raise HTTPException(404, "Certificate not found")
    issued[serial]["status"] = "revoked"
    issued[serial]["revoked_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    save_issued(issued)
    return {"serial": serial, "status": "revoked"}


@app.get("/crl", dependencies=[Depends(require_api_key)])
def get_crl():
    ca = get_ca()
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = x509.CertificateRevocationListBuilder().issuer_name(ca.cert.subject)
    builder = builder.last_update(now).next_update(now + datetime.timedelta(days=7))

    for serial, record in get_issued().items():
        if record["status"] != "revoked":
            continue
        revoked_at = datetime.datetime.fromisoformat(record["revoked_at"])
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(revoked_at)
            .build()
        )
        builder = builder.add_revoked_certificate(revoked)

    crl = builder.sign(private_key=ca.private_key, algorithm=hashes.SHA384())
    return {"crl_pem": crl.public_bytes(serialization.Encoding.PEM).decode()}


@app.post("/certs/{serial}/verify-pqc", dependencies=[Depends(require_api_key)])
def verify_pqc(serial: int):
    """Verify the PQC companion identity envelope for an issued certificate."""
    if not PQC_AVAILABLE:
        raise HTTPException(503, "PQC verification is unavailable because liboqs-python is not installed.")
    record = get_issued().get(serial)
    if not record or not record.get("pqc_identity_pem"):
        raise HTTPException(404, "No PQC identity found for this certificate")
    valid = HybridCA.verify_pqc_envelope(record["pqc_identity_pem"].encode())
    return {"serial": serial, "pqc_signature_valid": valid}


@app.get("/health")
def health():
    return {
        "status": "ok",
        "pqc_available": PQC_AVAILABLE,
        "ca_initialized": Path(CA_CERT_PATH).exists() and Path(CA_KEY_PATH).exists(),
    }


@app.get("/", include_in_schema=False)
def customer_console():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
