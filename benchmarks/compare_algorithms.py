"""
Benchmark: classical (ECDSA P-384) vs post-quantum (ML-DSA-65) signing.

Run:
    LD_LIBRARY_PATH=/path/to/liboqs/lib python3 benchmarks/compare_algorithms.py

If liboqs-python / liboqs aren't installed, the PQC rows are skipped and
only classical numbers are printed.
"""

import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

try:
    import oqs
    PQC_AVAILABLE = True
except ImportError:
    PQC_AVAILABLE = False

N_ITERATIONS = 200
MESSAGE = b"benchmark message: the quick brown fox jumps over the lazy dog"


def bench_classical():
    key = ec.generate_private_key(ec.SECP384R1())
    pub_bytes = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    t0 = time.perf_counter()
    sigs = [key.sign(MESSAGE, ec.ECDSA(hashes.SHA384())) for _ in range(N_ITERATIONS)]
    sign_time = (time.perf_counter() - t0) / N_ITERATIONS

    pub_key = key.public_key()
    t0 = time.perf_counter()
    for sig in sigs:
        pub_key.verify(sig, MESSAGE, ec.ECDSA(hashes.SHA384()))
    verify_time = (time.perf_counter() - t0) / N_ITERATIONS

    return {
        "algorithm": "ECDSA P-384 (classical)",
        "pubkey_bytes": len(pub_bytes),
        "sig_bytes": len(sigs[0]),
        "sign_ms": sign_time * 1000,
        "verify_ms": verify_time * 1000,
    }


def bench_pqc(alg_name: str):
    with oqs.Signature(alg_name) as signer:
        pub_key = signer.generate_keypair()

        t0 = time.perf_counter()
        sigs = [signer.sign(MESSAGE) for _ in range(N_ITERATIONS)]
        sign_time = (time.perf_counter() - t0) / N_ITERATIONS

    with oqs.Signature(alg_name) as verifier:
        t0 = time.perf_counter()
        for sig in sigs:
            verifier.verify(MESSAGE, sig, pub_key)
        verify_time = (time.perf_counter() - t0) / N_ITERATIONS

    return {
        "algorithm": f"{alg_name} (post-quantum)",
        "pubkey_bytes": len(pub_key),
        "sig_bytes": len(sigs[0]),
        "sign_ms": sign_time * 1000,
        "verify_ms": verify_time * 1000,
    }


def print_row(r):
    print(
        f"{r['algorithm']:<32} "
        f"pubkey={r['pubkey_bytes']:>5}B  "
        f"sig={r['sig_bytes']:>5}B  "
        f"sign={r['sign_ms']:>6.3f}ms  "
        f"verify={r['verify_ms']:>6.3f}ms"
    )


if __name__ == "__main__":
    print(f"Benchmarking with {N_ITERATIONS} iterations each\n")

    print_row(bench_classical())

    if PQC_AVAILABLE:
        for alg in ["ML-DSA-65"]:
            try:
                print_row(bench_pqc(alg))
            except Exception as e:
                print(f"{alg}: skipped ({e})")
    else:
        print("liboqs-python not installed — skipping PQC benchmarks.")
        print("Install with: pip install git+https://github.com/open-quantum-safe/liboqs-python.git")
