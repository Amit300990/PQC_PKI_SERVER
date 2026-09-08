# Hybrid PQC PKI Server

A minimal Certificate Authority + REST API that issues X.509 certificates
today (classical ECDSA/RSA) with real post-quantum signatures (ML-DSA-65 /
FIPS 204) as a companion identity, powered by
[liboqs](https://github.com/open-quantum-safe/liboqs) (Open Quantum Safe).

liboqs vendors [PQClean's](https://github.com/PQClean/PQClean) reference
implementations for most of its algorithms, so building against liboqs gets
you both projects' work in one library.

## Why hybrid?

X.509 doesn't yet have a finalized standard for embedding two signature
algorithms in one certificate. Real-world PQC migrations today use one of:

1. **Dual certificates** — issue a classical cert and a PQC cert for the same
   identity; peers negotiate which one they can verify. *(this repo's approach)*
2. **Composite signatures** — draft IETF schemes combining classical + PQC
   into one signature field (not yet standardized).

This project implements approach 1 so you can experiment safely without
waiting on standards to settle.

## Features

- [x] Self-signed root CA (RSA-4096, SHA-384)
- [x] Leaf certificate issuance (ECDSA P-384) with SAN support
- [x] Real PQC companion identity (ML-DSA-65, via liboqs/PQClean) per cert
- [x] PQC signature verification + tamper detection
- [x] REST API: init, issue, fetch, revoke, CRL, verify-pqc
- [x] Benchmark suite: classical vs PQC size/speed (see below)
- [ ] Intermediate CA chaining
- [ ] OCSP responder
- [ ] mTLS demo (two services authenticating with issued certs)

## Setup

### Option A — Docker (recommended, builds liboqs automatically)

```bash
docker compose up --build
```

### Option B — Local build

liboqs is a C library, so it needs to be compiled once:

```bash
# 1. Build liboqs (only the algorithms this project uses)
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cmake -GNinja -S liboqs -B liboqs/build \
  -DCMAKE_INSTALL_PREFIX=$HOME/liboqs-install \
  -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON \
  -DOQS_MINIMAL_BUILD="SIG_ml_dsa_65;SIG_sphincs_sha2_128f_simple;KEM_ml_kem_768"
ninja -C liboqs/build install

# 2. Install liboqs-python against that build
pip install git+https://github.com/open-quantum-safe/liboqs-python.git

# 3. Install the rest and run
pip install -r requirements.txt
export LD_LIBRARY_PATH=$HOME/liboqs-install/lib
uvicorn src.api.main:app --reload --port 8443
```

Without liboqs, the server still runs fine — just set `"enable_pqc": false`
when issuing certs and everything works in classical-only mode.

## Quick start

```bash
# 1. Initialize the root CA
curl -X POST localhost:8443/ca/init

# 2. Issue a hybrid certificate
curl -X POST localhost:8443/certs/issue -H "Content-Type: application/json" -d '{
  "common_name": "api.example.com",
  "sans": ["api.example.com"],
  "enable_pqc": true
}'

# 3. Verify the PQC identity for an issued cert
curl -X POST localhost:8443/certs/<serial>/verify-pqc

# 4. Check the CRL
curl localhost:8443/crl
```

## Benchmark: classical vs post-quantum

```bash
python3 benchmarks/compare_algorithms.py
```

Measured on this dev machine (200 iterations, your numbers will vary):

| Algorithm | Public key | Signature | Sign | Verify |
|---|---|---|---|---|
| ECDSA P-384 (classical) | 120 B | 104 B | 0.23 ms | 0.43 ms |
| ML-DSA-65 (post-quantum) | 1952 B | 3309 B | 0.12 ms | 0.04 ms |

Takeaway: ML-DSA keys/signatures are ~16-32x larger, but signing and
verifying are actually *faster* than ECDSA here — the classical bottleneck
is elliptic-curve math, not PQC's lattice math. The real cost of going PQC
is on-the-wire size (TLS handshake bytes, cert chain size), not CPU time.

## Project layout

```
src/
  ca/hybrid_ca.py    # core CA logic: root creation, leaf issuance, PQC hooks
  api/main.py         # FastAPI REST layer
certs/                # generated root cert/key (gitignored)
```

## Security note

This is a **learning/demo project**, not a production CA. Before using
anything like this for real traffic: move key storage to an HSM or KMS,
add auth to the API, add proper OCSP, and get the design reviewed.

## License

MIT
