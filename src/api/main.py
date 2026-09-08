"""REST API for the Hybrid PQC PKI server."""

from __future__ import annotations

import datetime
import hashlib
import os
import secrets
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy.exc import SQLAlchemyError

from src.ca.hybrid_ca import DEFAULT_PQC_SIG_ALG, HybridCA, PQC_AVAILABLE
from src.persistence import (
    AuditEvent,
    CertificateConflictError,
    CertificateRepository,
    Database,
    IssuedCertificate,
)


DEFAULT_DATABASE_URL = "sqlite:///certs/pki.db"
DEFAULT_CA_CERT_PATH = "certs/root.crt"
DEFAULT_CA_KEY_PATH = "certs/root.key"
STATIC_DIR = Path(__file__).parent / "static"


@dataclass(frozen=True)
class Settings:
    database_url: str
    ca_cert_path: Path
    ca_key_path: Path
    admin_token: Optional[str] = None
    operator_token: Optional[str] = None
    auditor_token: Optional[str] = None
    legacy_api_key: Optional[str] = None

    @classmethod
    def from_environment(cls) -> "Settings":
        return cls(
            database_url=os.getenv("PKI_DATABASE_URL")
            or os.getenv("DATABASE_URL")
            or DEFAULT_DATABASE_URL,
            ca_cert_path=Path(os.getenv("PKI_CA_CERT_PATH", DEFAULT_CA_CERT_PATH)),
            ca_key_path=Path(os.getenv("PKI_CA_KEY_PATH", DEFAULT_CA_KEY_PATH)),
            admin_token=os.getenv("PKI_ADMIN_API_TOKEN"),
            operator_token=os.getenv("PKI_OPERATOR_API_TOKEN"),
            auditor_token=os.getenv("PKI_AUDITOR_API_TOKEN"),
            legacy_api_key=os.getenv("PKI_API_KEY"),
        )


@dataclass(frozen=True)
class Principal:
    identity: str
    role: str


class IssueRequest(BaseModel):
    csr_pem: str = Field(..., min_length=1, max_length=65536, examples=["-----BEGIN CERTIFICATE REQUEST-----\n..."])
    valid_days: int = Field(default=397, ge=1, le=397)
    enable_pqc: bool = False


def configured_principals(settings: Settings) -> list[tuple[str, Principal]]:
    """Build the scoped token set, failing closed for partial role configuration."""
    scoped_tokens = {
        "admin": settings.admin_token,
        "operator": settings.operator_token,
        "auditor": settings.auditor_token,
    }
    if any(scoped_tokens.values()):
        missing = [role for role, token in scoped_tokens.items() if not token]
        if missing:
            raise HTTPException(
                status_code=503,
                detail=f"Missing required scoped PKI API token configuration: {', '.join(missing)}.",
            )
        token_values = list(scoped_tokens.values())
        if len(set(token_values)) != len(token_values):
            raise HTTPException(
                status_code=503,
                detail="PKI_ADMIN_API_TOKEN, PKI_OPERATOR_API_TOKEN, and PKI_AUDITOR_API_TOKEN must be distinct.",
            )
        return [
            (scoped_tokens["admin"], Principal(identity="admin", role="admin")),
            (scoped_tokens["operator"], Principal(identity="operator", role="operator")),
            (scoped_tokens["auditor"], Principal(identity="auditor", role="auditor")),
        ]
    if settings.legacy_api_key:
        return [(settings.legacy_api_key, Principal(identity="legacy-api-key", role="admin"))]
    raise HTTPException(
        status_code=503,
        detail=(
            "Scoped PKI API tokens are not configured. Set PKI_ADMIN_API_TOKEN, "
            "PKI_OPERATOR_API_TOKEN, and PKI_AUDITOR_API_TOKEN."
        ),
    )


def authenticate(settings: Settings, x_api_key: Optional[str]) -> Principal:
    principals = configured_principals(settings)
    if not x_api_key:
        raise HTTPException(status_code=401, detail="An X-API-Key header is required.")
    for token, principal in principals:
        if secrets.compare_digest(x_api_key, token):
            return principal
    raise HTTPException(status_code=401, detail="A valid X-API-Key header is required.")


def require_roles(settings: Settings, *allowed_roles: str):
    def dependency(x_api_key: Annotated[Optional[str], Header()] = None) -> Principal:
        principal = authenticate(settings, x_api_key)
        if principal.role not in allowed_roles and principal.identity != "legacy-api-key":
            raise HTTPException(
                status_code=403,
                detail=f"The {principal.role} role cannot perform this operation.",
            )
        return principal

    return dependency


def load_ca(settings: Settings) -> HybridCA:
    if not settings.ca_cert_path.exists() or not settings.ca_key_path.exists():
        raise HTTPException(status_code=503, detail="CA is not initialized.")
    try:
        return HybridCA.load(str(settings.ca_cert_path), str(settings.ca_key_path))
    except (OSError, ValueError) as error:
        raise HTTPException(status_code=503, detail=f"CA material is unavailable: {error}") from error


def timestamp(value: Optional[datetime.datetime]) -> Optional[str]:
    return value.isoformat() if value else None


def certificate_response(record: IssuedCertificate, include_artifacts: bool = False) -> dict:
    response = {
        "serial": record.serial,
        "common_name": record.common_name,
        "subject_dn": record.subject_dn,
        "sans": record.sans,
        "status": record.status,
        "issued_at": timestamp(record.issued_at),
        "not_before": timestamp(record.not_before),
        "not_after": timestamp(record.not_after),
        "revoked_at": timestamp(record.revoked_at),
        "public_key_sha256": record.public_key_sha256,
        "has_pqc_identity": bool(record.pqc_identity_pem),
    }
    if include_artifacts:
        response["classical_cert_pem"] = record.classical_cert_pem
        response["pqc_identity_pem"] = record.pqc_identity_pem
        response["pqc_algorithm"] = record.pqc_algorithm
    return response


def audit_response(event: AuditEvent) -> dict:
    return {
        "id": event.id,
        "occurred_at": timestamp(event.occurred_at),
        "actor_identity": event.actor_identity,
        "actor_role": event.actor_role,
        "action": event.action,
        "certificate_serial": event.certificate_serial,
        "details": event.details,
    }


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    settings = settings or Settings.from_environment()
    database = Database(settings.database_url)
    repository = CertificateRepository(database)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        database.create_schema()
        try:
            yield
        finally:
            database.dispose()

    app = FastAPI(title="Hybrid PQC PKI Server", version="0.2.0", lifespan=lifespan)
    admin_only = require_roles(settings, "admin")
    operator_only = require_roles(settings, "operator")
    read_roles = require_roles(settings, "admin", "operator", "auditor")
    audit_roles = require_roles(settings, "admin", "auditor")

    @app.exception_handler(SQLAlchemyError)
    async def database_unavailable(_, __):
        return JSONResponse(status_code=503, content={"detail": "Certificate persistence is unavailable."})

    @app.post("/ca/init")
    def init_ca(
        common_name: str = Query(default="Hybrid PQC Root CA", min_length=1, max_length=64),
        force: bool = False,
        actor: Principal = Depends(admin_only),
    ):
        existing_material = settings.ca_cert_path.exists() or settings.ca_key_path.exists()
        if existing_material and not force:
            raise HTTPException(
                status_code=409,
                detail="CA already initialized. Pass force=true only when intentionally replacing the CA.",
            )
        ca = HybridCA.create_root(common_name=common_name)
        ca.save(str(settings.ca_cert_path), str(settings.ca_key_path))
        if force:
            deleted_count = repository.clear_certificates(
                actor_identity=actor.identity,
                actor_role=actor.role,
            )
            repository.record_audit(
                actor_identity=actor.identity,
                actor_role=actor.role,
                action="ca.reinitialized",
                details={"common_name": common_name, "cleared_certificate_count": deleted_count},
            )
        else:
            repository.record_audit(
                actor_identity=actor.identity,
                actor_role=actor.role,
                action="ca.initialized",
                details={"common_name": common_name},
            )
        return {"status": "created", "common_name": common_name, "pqc_available": PQC_AVAILABLE}

    @app.post("/certs/issue")
    def issue_cert(req: IssueRequest, actor: Principal = Depends(operator_only)):
        if req.enable_pqc and not PQC_AVAILABLE:
            raise HTTPException(
                status_code=503,
                detail="PQC issuance is unavailable because liboqs-python is not installed on this server.",
            )
        try:
            bundle = load_ca(settings).issue_from_csr(
                csr_pem=req.csr_pem.encode(),
                valid_days=req.valid_days,
                enable_pqc=req.enable_pqc,
                pqc_algorithm=DEFAULT_PQC_SIG_ALG,
            )
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        except RuntimeError as error:
            raise HTTPException(status_code=503, detail=str(error)) from error

        certificate = x509.load_pem_x509_certificate(bundle.classical_cert_pem)
        serial = format(certificate.serial_number, "X")
        public_key_der = certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        try:
            record = repository.create_certificate(
                serial=serial,
                common_name=bundle.common_name,
                subject_dn=certificate.subject.rfc4514_string(),
                sans=bundle.sans,
                issued_at=datetime.datetime.now(datetime.timezone.utc),
                not_before=certificate.not_valid_before_utc,
                not_after=certificate.not_valid_after_utc,
                classical_cert_pem=bundle.classical_cert_pem.decode(),
                csr_pem=req.csr_pem,
                public_key_sha256=hashlib.sha256(public_key_der).hexdigest(),
                pqc_identity_pem=bundle.pqc_identity_pem.decode() if bundle.pqc_identity_pem else None,
                pqc_algorithm=bundle.pqc_algorithm,
                actor_identity=actor.identity,
                actor_role=actor.role,
            )
        except CertificateConflictError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        return certificate_response(record, include_artifacts=True)

    @app.get("/certs/{serial}")
    def get_cert(serial: str, _: Principal = Depends(read_roles)):
        record = repository.get_certificate(serial)
        if not record:
            raise HTTPException(status_code=404, detail="Certificate not found")
        return certificate_response(record, include_artifacts=True)

    @app.get("/certs")
    def list_certs(_: Principal = Depends(read_roles)):
        return [certificate_response(record) for record in repository.list_certificates()]

    @app.post("/certs/{serial}/revoke")
    def revoke_cert(serial: str, actor: Principal = Depends(operator_only)):
        result = repository.revoke_certificate(
            serial,
            actor_identity=actor.identity,
            actor_role=actor.role,
        )
        if result.certificate is None:
            raise HTTPException(status_code=404, detail="Certificate not found")
        response = certificate_response(result.certificate)
        response["newly_revoked"] = result.newly_revoked
        return response

    @app.get("/crl")
    def get_crl(_: Principal = Depends(read_roles)):
        ca = load_ca(settings)
        now = datetime.datetime.now(datetime.timezone.utc)
        builder = x509.CertificateRevocationListBuilder().issuer_name(ca.cert.subject)
        builder = builder.last_update(now).next_update(now + datetime.timedelta(days=7))

        for record in repository.list_revoked_certificates():
            if not record.revoked_at:
                continue
            revoked_at = record.revoked_at
            if revoked_at.tzinfo is None:
                revoked_at = revoked_at.replace(tzinfo=datetime.timezone.utc)
            revoked = (
                x509.RevokedCertificateBuilder()
                .serial_number(int(record.serial, 16))
                .revocation_date(revoked_at)
                .build()
            )
            builder = builder.add_revoked_certificate(revoked)

        crl = builder.sign(private_key=ca.private_key, algorithm=hashes.SHA384())
        return {"crl_pem": crl.public_bytes(serialization.Encoding.PEM).decode()}

    @app.post("/certs/{serial}/verify-pqc")
    def verify_pqc(serial: str, _: Principal = Depends(read_roles)):
        if not PQC_AVAILABLE:
            raise HTTPException(
                status_code=503,
                detail="PQC verification is unavailable because liboqs-python is not installed.",
            )
        record = repository.get_certificate(serial)
        if not record or not record.pqc_identity_pem:
            raise HTTPException(status_code=404, detail="No PQC identity found for this certificate")
        valid = HybridCA.verify_pqc_envelope(record.pqc_identity_pem.encode())
        return {"serial": serial, "pqc_signature_valid": valid}

    @app.get("/audit")
    def get_audit_events(
        limit: int = Query(default=100, ge=1, le=500),
        _: Principal = Depends(audit_roles),
    ):
        return [audit_response(event) for event in repository.list_audit_events(limit)]

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "pqc_available": PQC_AVAILABLE,
            "ca_initialized": settings.ca_cert_path.exists() and settings.ca_key_path.exists(),
        }

    @app.get("/", include_in_schema=False)
    def customer_console():
        return FileResponse(STATIC_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app


app = create_app()
