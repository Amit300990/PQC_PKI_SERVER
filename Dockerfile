# --- Stage 1: build liboqs (Open Quantum Safe), which vendors PQClean's
#     reference implementations of NIST-standardized PQC algorithms ---
FROM debian:bookworm-slim AS liboqs-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    git build-essential cmake ninja-build libssl-dev python3 \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git /liboqs

# Build only the algorithms this project uses, to keep the image lean.
# Swap OQS_USE_OPENSSL=ON if you have libssl-dev (used above) for hardware-
# accelerated primitives; set OFF to use liboqs's portable internal crypto.
RUN cmake -GNinja -S /liboqs -B /liboqs/build \
      -DCMAKE_INSTALL_PREFIX=/opt/liboqs \
      -DBUILD_SHARED_LIBS=ON \
      -DOQS_BUILD_ONLY_LIB=ON \
      -DOQS_MINIMAL_BUILD="SIG_ml_dsa_65;SIG_sphincs_sha2_128f_simple;KEM_ml_kem_768" \
      -DOQS_USE_OPENSSL=ON \
    && ninja -C /liboqs/build install

# --- Stage 2: the actual app, using the liboqs build from stage 1 ---
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=liboqs-builder /opt/liboqs /opt/liboqs
ENV LD_LIBRARY_PATH=/opt/liboqs/lib
ENV OQS_INSTALL_PATH=/opt/liboqs

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# liboqs-python is a thin ctypes wrapper — point it at our prebuilt liboqs
# instead of letting it fetch/build its own copy at runtime.
RUN pip install --no-cache-dir git+https://github.com/open-quantum-safe/liboqs-python.git

COPY . .
EXPOSE 8443
CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8443"]
