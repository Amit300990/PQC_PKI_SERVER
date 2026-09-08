"""Durable certificate and audit persistence for the PKI API.

The repository owns database transactions so API handlers never maintain
certificate state in process memory.  SQLAlchemy's URL handling keeps SQLite
useful for a single-node deployment and permits the same models to run on
PostgreSQL.
"""

from __future__ import annotations

import datetime
import os
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Optional

from sqlalchemy import JSON, DateTime, Integer, String, Text, create_engine, delete, desc, select, update
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


def utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def normalize_database_url(database_url: str) -> str:
    """Use psycopg for conventional PostgreSQL URLs when no driver is named."""
    if database_url.startswith("postgres://"):
        return f"postgresql+psycopg://{database_url.removeprefix('postgres://')}"
    if database_url.startswith("postgresql://"):
        return f"postgresql+psycopg://{database_url.removeprefix('postgresql://')}"
    return database_url


class Base(DeclarativeBase):
    pass


class IssuedCertificate(Base):
    __tablename__ = "issued_certificates"

    serial: Mapped[str] = mapped_column(String(64), primary_key=True)
    common_name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    subject_dn: Mapped[str] = mapped_column(Text, nullable=False)
    sans: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="valid", index=True)
    issued_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    not_before: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    not_after: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    classical_cert_pem: Mapped[str] = mapped_column(Text, nullable=False)
    csr_pem: Mapped[str] = mapped_column(Text, nullable=False)
    public_key_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    pqc_identity_pem: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    pqc_algorithm: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    occurred_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, index=True
    )
    actor_identity: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor_role: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    certificate_serial: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class Database:
    """Small SQLAlchemy 2 database wrapper with per-operation sessions."""

    def __init__(self, database_url: str):
        self.database_url = normalize_database_url(database_url)
        self._prepare_sqlite_directory()
        url = make_url(self.database_url)
        connect_args = {"check_same_thread": False} if url.get_backend_name() == "sqlite" else {}
        self.engine: Engine = create_engine(
            self.database_url,
            future=True,
            pool_pre_ping=True,
            connect_args=connect_args,
        )
        self.session_factory = sessionmaker(self.engine, expire_on_commit=False)

    def _prepare_sqlite_directory(self) -> None:
        url = make_url(self.database_url)
        if url.get_backend_name() != "sqlite" or not url.database or url.database == ":memory:":
            return
        database_path = Path(url.database)
        if not database_path.is_absolute():
            database_path = Path.cwd() / database_path
        database_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    def create_schema(self) -> None:
        Base.metadata.create_all(self.engine)

    def dispose(self) -> None:
        self.engine.dispose()

    @contextmanager
    def session(self) -> Iterator[Session]:
        session = self.session_factory()
        try:
            yield session
        finally:
            session.close()


class CertificateConflictError(Exception):
    """The CA generated a serial number that already exists in persistence."""


@dataclass(frozen=True)
class RevocationResult:
    certificate: Optional[IssuedCertificate]
    newly_revoked: bool


class CertificateRepository:
    """Repository methods group state changes and their audit event atomically."""

    def __init__(self, database: Database):
        self.database = database

    @staticmethod
    def _add_audit(
        session: Session,
        *,
        actor_identity: str,
        actor_role: str,
        action: str,
        certificate_serial: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        session.add(
            AuditEvent(
                actor_identity=actor_identity,
                actor_role=actor_role,
                action=action,
                certificate_serial=certificate_serial,
                details=details or {},
            )
        )

    def record_audit(
        self,
        *,
        actor_identity: str,
        actor_role: str,
        action: str,
        certificate_serial: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        with self.database.session() as session:
            with session.begin():
                self._add_audit(
                    session,
                    actor_identity=actor_identity,
                    actor_role=actor_role,
                    action=action,
                    certificate_serial=certificate_serial,
                    details=details,
                )

    def create_certificate(
        self,
        *,
        serial: str,
        common_name: str,
        subject_dn: str,
        sans: list[str],
        issued_at: datetime.datetime,
        not_before: datetime.datetime,
        not_after: datetime.datetime,
        classical_cert_pem: str,
        csr_pem: str,
        public_key_sha256: str,
        pqc_identity_pem: Optional[str],
        pqc_algorithm: Optional[str],
        actor_identity: str,
        actor_role: str,
    ) -> IssuedCertificate:
        record = IssuedCertificate(
            serial=serial,
            common_name=common_name,
            subject_dn=subject_dn,
            sans=sans,
            status="valid",
            issued_at=issued_at,
            not_before=not_before,
            not_after=not_after,
            classical_cert_pem=classical_cert_pem,
            csr_pem=csr_pem,
            public_key_sha256=public_key_sha256,
            pqc_identity_pem=pqc_identity_pem,
            pqc_algorithm=pqc_algorithm,
        )
        try:
            with self.database.session() as session:
                with session.begin():
                    session.add(record)
                    self._add_audit(
                        session,
                        actor_identity=actor_identity,
                        actor_role=actor_role,
                        action="certificate.issued",
                        certificate_serial=serial,
                        details={
                            "common_name": common_name,
                            "sans": sans,
                            "pqc_enabled": bool(pqc_identity_pem),
                        },
                    )
        except IntegrityError as error:
            raise CertificateConflictError(f"certificate serial {serial} already exists") from error
        return record

    def get_certificate(self, serial: str) -> Optional[IssuedCertificate]:
        with self.database.session() as session:
            return session.get(IssuedCertificate, serial)

    def list_certificates(self) -> list[IssuedCertificate]:
        with self.database.session() as session:
            statement = select(IssuedCertificate).order_by(desc(IssuedCertificate.issued_at))
            return list(session.scalars(statement).all())

    def list_revoked_certificates(self) -> list[IssuedCertificate]:
        with self.database.session() as session:
            statement = (
                select(IssuedCertificate)
                .where(IssuedCertificate.status == "revoked")
                .order_by(IssuedCertificate.revoked_at)
            )
            return list(session.scalars(statement).all())

    def revoke_certificate(
        self,
        serial: str,
        *,
        actor_identity: str,
        actor_role: str,
    ) -> RevocationResult:
        now = utc_now()
        with self.database.session() as session:
            with session.begin():
                result = session.execute(
                    update(IssuedCertificate)
                    .where(
                        IssuedCertificate.serial == serial,
                        IssuedCertificate.status == "valid",
                    )
                    .values(status="revoked", revoked_at=now)
                )
                record = session.get(IssuedCertificate, serial)
                if record is None:
                    return RevocationResult(certificate=None, newly_revoked=False)
                if result.rowcount:
                    self._add_audit(
                        session,
                        actor_identity=actor_identity,
                        actor_role=actor_role,
                        action="certificate.revoked",
                        certificate_serial=serial,
                        details={"revoked_at": now.isoformat()},
                    )
                    return RevocationResult(certificate=record, newly_revoked=True)
                return RevocationResult(certificate=record, newly_revoked=False)

    def clear_certificates(
        self,
        *,
        actor_identity: str,
        actor_role: str,
    ) -> int:
        with self.database.session() as session:
            with session.begin():
                deleted = session.execute(delete(IssuedCertificate)).rowcount or 0
                self._add_audit(
                    session,
                    actor_identity=actor_identity,
                    actor_role=actor_role,
                    action="certificate_records.cleared",
                    details={"deleted_count": deleted},
                )
                return deleted

    def list_audit_events(self, limit: int) -> list[AuditEvent]:
        with self.database.session() as session:
            statement = select(AuditEvent).order_by(desc(AuditEvent.occurred_at), desc(AuditEvent.id)).limit(limit)
            return list(session.scalars(statement).all())
