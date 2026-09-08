# Hybrid PQC PKI Server

A FastAPI Certificate Authority that issues classical X.509 certificates from
client-generated CSRs, with an optional ML-DSA-65 signed identity envelope.
The X.509 certificate is suitable for conventional TLS clients; the PQC
envelope is application-specific and is **not** a TLS certificate.

## Why hybrid?

X.509 has no finalized standard for embedding both classical and PQC signatures
in one certificate. PQC migrations therefore commonly use dual certificates or
draft composite signatures. This project pairs a conventional X.509
certificate with an ML-DSA-65 / FIPS 204 signed identity envelope powered by
[liboqs](https://github.com/open-quantum-safe/liboqs). The envelope
demonstrates PQC signing but cannot itself be used for TLS negotiation.

## Production-safety foundation

- CSR-based issuance: the server validates the CSR signature and certifies its
  public key. It never creates, stores, or returns a leaf private key.
- Durable certificate, revocation, and audit persistence through SQLAlchemy 2.
  SQLite is the local default; PostgreSQL uses the same repository layer.
- Separate admin, operator, and auditor tokens with least-privilege endpoints.
- A non-root container process, a persistent CA/database mount, loopback-only
  default port exposure, dropped Linux capabilities, and no checked-in secrets.

This is still not a complete public CA. Production deployments need a reviewed
certificate policy, HSM/KMS-backed CA key handling, authenticated operator
identity rather than shared API tokens, OCSP, secure backups, monitoring, and
an independent security review.

## Roles and API authentication

Set three **different**, high-entropy tokens (for example,
`openssl rand -hex 32`) in the deployment environment:

| Role | Token | Permissions |
| --- | --- | --- |
| Admin | `PKI_ADMIN_API_TOKEN` | Initialize or replace the root CA; read certificates, CRL, and audit trail |
| Operator | `PKI_OPERATOR_API_TOKEN` | Issue from a CSR, revoke certificates; read certificates and CRL |
| Auditor | `PKI_AUDITOR_API_TOKEN` | Read certificates, CRL, and protected audit trail |

All protected endpoints expect `X-API-Key`. Missing/invalid credentials return
`401`; an authenticated role without permission receives `403`; incomplete or
unsafe token configuration returns `503`.

For a short migration window only, setting `PKI_API_KEY` with **no scoped
tokens** retains the broad access of the previous single-token API and records
the actor as `legacy-api-key` with the admin role. Do not use this compatibility
mode for new deployments. If any scoped token is configured, all three scoped
tokens are required and must be distinct.

## Run with Docker

The compose configuration persists the CA material and default SQLite database
under `./certs`, which is ignored by Git. On Linux, make the mount writable by
the image's unprivileged UID before starting:

```bash
mkdir -p certs
chmod 700 certs
sudo chown 10001:10001 certs  # Linux bind mounts; normally unnecessary on Docker Desktop

export PKI_ADMIN_API_TOKEN="$(openssl rand -hex 32)"
export PKI_OPERATOR_API_TOKEN="$(openssl rand -hex 32)"
export PKI_AUDITOR_API_TOKEN="$(openssl rand -hex 32)"
docker compose up --build
```

The default listener is `127.0.0.1:8443`. Terminate TLS at a hardened reverse
proxy or change the port binding only after adding network controls. Store
tokens in a secret manager or injected environment; do not commit them or put
them in an image.

### Database configuration and backups

`PKI_DATABASE_URL` takes precedence over `DATABASE_URL`. Its default is
`sqlite:///certs/pki.db` locally and
`sqlite:////app/certs/pki.db` in Docker Compose. Back up the SQLite file and
the CA key/certificate together, protect backups as key material, and test
restores.

For PostgreSQL, provide a standard URL; conventional `postgresql://` and
`postgres://` URLs are automatically routed through the bundled `psycopg`
driver:

```bash
export PKI_DATABASE_URL='postgresql+psycopg://pki_app:password@db.example/pki'
docker compose up --build
```

Use TLS, a narrowly privileged database account, and a secrets manager for the
PostgreSQL credentials. Configure `PKI_CA_CERT_PATH` and `PKI_CA_KEY_PATH`
together if CA material must reside outside the default `certs/root.crt` and
`certs/root.key` paths.

## Local development

Install the Python dependencies, set the three role tokens, then start Uvicorn:

```bash
pip install -r requirements.txt
export PKI_ADMIN_API_TOKEN="$(openssl rand -hex 32)"
export PKI_OPERATOR_API_TOKEN="$(openssl rand -hex 32)"
export PKI_AUDITOR_API_TOKEN="$(openssl rand -hex 32)"
uvicorn src.api.main:app --reload --port 8443
```

The optional PQC envelope requires `liboqs-python` and its `liboqs` shared
library. The Docker image builds the required minimal liboqs installation.
Without it, use `enable_pqc: false`; ordinary CSR issuance remains available.

## Issue from a CSR

Generate the leaf key pair and CSR on the client. The following OpenSSL example
keeps `service.key` solely on the client and requests a common name plus DNS/IP
SANs:

```bash
openssl req -new -newkey rsa:3072 -nodes \
  -keyout service.key -out service.csr \
  -subj '/CN=api.example.com' \
  -addext 'subjectAltName=DNS:api.example.com,DNS:www.example.com,IP:192.0.2.10'
```

Initialize the CA with the admin token once:

```bash
curl -X POST 'http://127.0.0.1:8443/ca/init' \
  -H "X-API-Key: $PKI_ADMIN_API_TOKEN"
```

Then issue with the operator token. This example uses `jq` to safely embed PEM
newlines in JSON:

```bash
curl -sS -X POST http://127.0.0.1:8443/certs/issue \
  -H "X-API-Key: $PKI_OPERATOR_API_TOKEN" \
  -H 'Content-Type: application/json' \
  --data "$(jq -n --rawfile csr service.csr \
    '{csr_pem: $csr, valid_days: 397, enable_pqc: false}')"
```

The result contains `classical_cert_pem` and, if requested and available,
`pqc_identity_pem`; it intentionally never contains a private key. CSR
subjects are limited to common certificate identity attributes, DNS/IP SANs
are validated, and all key-usage/extensions are CA controlled.

The browser console at `http://127.0.0.1:8443/` provides the same flow: paste
a PEM CSR, select validity/PQC options, and download public certificate
artifacts. Use the role token appropriate to the operation; unauthorized
controls report the server's permission error.

## API summary

| Endpoint | Role |
| --- | --- |
| `POST /ca/init` | Admin |
| `POST /certs/issue` | Operator |
| `POST /certs/{serial}/revoke` | Operator |
| `GET /certs`, `GET /certs/{serial}`, `GET /crl`, `POST /certs/{serial}/verify-pqc` | Admin, operator, or auditor |
| `GET /audit?limit=100` | Admin or auditor |
| `GET /health` | Public, readiness information only |

Certificate serials are canonical uppercase hexadecimal strings, preventing
JavaScript precision loss for X.509 serial numbers. Destructive CA replacement
requires `force=true`, clears issued-certificate records, and retains an audit
event documenting the action.

## Tests

The standard-library `unittest` suite covers CSR public-key matching, invalid
CSR rejection, role enforcement, durable restart behavior, revocation/CRL, and
auditable actions:

```bash
python -m unittest discover -s tests -v
```

## Benchmark: classical vs post-quantum

The preserved benchmark compares classical and PQC key/signature sizes and
timings on the local machine:

```bash
python3 benchmarks/compare_algorithms.py
```

PQC credentials are substantially larger on the wire, so measure the impact in
the target TLS/application protocol before planning a migration.

## Project layout

```text
src/
  ca/hybrid_ca.py       # Root CA creation, CSR validation, X.509/PQC issuance
  persistence.py        # SQLAlchemy models, sessions, repository, audit writes
  api/main.py           # FastAPI wiring, scoped RBAC, and console route
  api/static/           # Browser CSR issuance and certificate console
certs/                  # Runtime CA material and default SQLite database (ignored)
```

## License

MIT
