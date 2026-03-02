# wolfCOSE

A lightweight, zero-allocation C library implementing [CBOR (RFC 8949)](https://www.rfc-editor.org/rfc/rfc8949) and [COSE (RFC 9052)](https://www.rfc-editor.org/rfc/rfc9052) with [wolfSSL](https://www.wolfssl.com/) as the crypto backend.

Built for constrained IoT devices, FIPS-bounded deployments, and anywhere you need authenticated CBOR payloads in minimal RAM.

## Key Features

- **Zero dynamic allocation** -- all operations use caller-provided buffers, no `malloc`
- **Zero-copy CBOR decoder** -- single-pass, data pointers reference input buffer directly
- **Tiny footprint** -- core library is ~11KB `.text`, zero `.data`/`.bss`
- **Full COSE lifecycle in <1KB RAM** (excluding wolfCrypt math internals)
- **C99 / MISRA-C:2023** -- single-exit pattern, no recursion, deviation-logged
- **wolfCrypt integration** -- ECC (P-256/P-384/P-521), Ed25519, AES-GCM, FIPS-ready
- **PQC-ready** -- reserved algorithm IDs and extensible key union for ML-DSA (Dilithium)
- **Pointer-based key struct** -- `WOLFCOSE_KEY` holds pointers to caller-owned wolfCrypt keys (~48 bytes, not kilobytes)
- **Compile-time algorithm dispatch** -- `#ifdef` ladder, zero overhead, no function pointers
- **Sensitive data scrubbing** -- `wc_ForceZero()` on all stack crypto material

## Supported Algorithms

| Type | Algorithms |
|------|-----------|
| Signing | ES256, ES384, ES512, EdDSA (Ed25519) |
| Encryption | A128GCM, A192GCM, A256GCM |
| Key Types | EC2 (NIST curves), OKP (Ed25519), Symmetric |

## Prerequisites

wolfSSL 5.x with the required algorithms enabled:

```bash
cd wolfssl
./configure --enable-ecc --enable-ed25519 --enable-curve25519 \
            --enable-aesgcm --enable-sha384 --enable-sha512 --enable-keygen
make && sudo make install
sudo ldconfig
```

## Build

```bash
# Core library (libwolfcose.a)
make

# Run tests
make test

# Build CLI tool
make tool

# Run lifecycle demo
make demo
```

### Build Targets

| Target | Description |
|--------|-------------|
| `make all` | Build `libwolfcose.a` (core library only) |
| `make shared` | Build `libwolfcose.so` |
| `make test` | Build + run CBOR and COSE unit tests |
| `make tool` | Build CLI tool (`tools/wolfcose_tool`) |
| `make tool-test` | Automated round-trip: keygen -> sign -> verify |
| `make demo` | Build + run edge-to-cloud lifecycle demo |
| `make clean` | Remove all build artifacts |

## Project Structure

```
include/wolfcose/
  wolfcose.h            Public API (types, constants, all functions)
  visibility.h          WOLFCOSE_API export macros
src/
  wolfcose_cbor.c       CBOR encoder/decoder (RFC 8949, no wolfCrypt dep)
  wolfcose.c            COSE Sign1/Encrypt0/Key (RFC 9052, wolfCrypt)
  wolfcose_internal.h   Internal helpers (BE macros, header codec, ECC wrappers)
tests/
  test_cbor.c           CBOR vectors (RFC 8949 Appendix A) + round-trip
  test_cose.c           COSE Sign1/Encrypt0/Key tests + RFC 9052 vectors
  test_main.c           Test harness (CI exit codes)
tools/
  wolfcose_tool.c       CLI: keygen, sign, verify, encrypt, decrypt, info
examples/
  lifecycle_demo.c      Edge-to-cloud producer/consumer demo
```

The core library is two object files. CBOR-only projects can link just `wolfcose_cbor.o`.

## Quick Start

### Sign and Verify (C API)

```c
#include <wolfcose/wolfcose.h>

/* Caller owns all buffers and key lifecycle */
ecc_key eccKey;
WOLFCOSE_KEY coseKey;
uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
uint8_t out[256];
size_t outLen;
WC_RNG rng;

/* Setup */
wc_ecc_init(&eccKey);
wc_ecc_make_key(&rng, 32, &eccKey);
wc_CoseKey_Init(&coseKey);
wc_CoseKey_SetEcc(&coseKey, WOLFCOSE_CRV_P256, &eccKey);

/* Sign */
wc_CoseSign1_Sign(&coseKey, WOLFCOSE_ALG_ES256,
    kid, kidLen, payload, payloadLen, NULL, 0,
    scratch, sizeof(scratch), out, sizeof(out), &outLen, &rng);

/* Verify */
WOLFCOSE_HDR hdr;
const uint8_t* decoded;
size_t decodedLen;
wc_CoseSign1_Verify(&coseKey, out, outLen, NULL, 0,
    scratch, sizeof(scratch), &hdr, &decoded, &decodedLen);

/* Cleanup -- caller frees wolfCrypt key, not wolfCOSE */
wc_ecc_free(&eccKey);
```

### CLI Tool

```bash
# Generate a COSE key
./tools/wolfcose_tool keygen -a ES256 -o my.key

# Sign a file
./tools/wolfcose_tool sign -k my.key -a ES256 -i data.bin -o data.cose

# Verify
./tools/wolfcose_tool verify -k my.key -i data.cose

# Encrypt / Decrypt (AES-GCM)
./tools/wolfcose_tool keygen -a A128GCM -o sym.key
./tools/wolfcose_tool enc -k sym.key -a A128GCM -i secret.bin -o secret.cose
./tools/wolfcose_tool dec -k sym.key -i secret.cose -o recovered.bin

# Inspect COSE structure
./tools/wolfcose_tool info -i data.cose
```

## Deploying on Real Hardware

### Cross-Compilation

```bash
# Example: ARM Cortex-M with arm-none-eabi-gcc
make CC=arm-none-eabi-gcc \
     CFLAGS="-std=c99 -Os -mcpu=cortex-m4 -mthumb \
             -I./include -I/path/to/wolfssl/include \
             -DWOLFSSL_USER_SETTINGS"
```

Provide a `user_settings.h` with your wolfSSL configuration instead of `wolfssl/options.h`. See the [wolfSSL manual](https://www.wolfssl.com/documentation/manuals/wolfssl/chapter02.html) for embedded build options.

### Tuning for Constrained Targets

```c
/* In your user_settings.h or build flags: */

/* Reduce scratch buffer (default 512, minimum depends on payload size) */
#define WOLFCOSE_MAX_SCRATCH_SZ   256

/* Reduce protected header buffer */
#define WOLFCOSE_PROTECTED_HDR_MAX  32

/* Reduce CBOR nesting depth (default 8) */
#define WOLFCOSE_CBOR_MAX_DEPTH     4

/* For PQC (ML-DSA), increase scratch buffer */
/* #define WOLFCOSE_MAX_SCRATCH_SZ  8192 */
```

### Integration Checklist

1. Build wolfSSL for your target with only the algorithms you need
2. Link `libwolfcose.a` (or compile `src/wolfcose_cbor.c` + `src/wolfcose.c` directly)
3. Do **not** include `tools/` or `examples/` in production firmware
4. Pre-provision keys in secure storage -- see `lifecycle_demo.c` for the pattern
5. Caller owns all `WC_RNG`, `ecc_key`, buffer lifecycle -- wolfCOSE never allocates

### Stack Budget

Per-function stack usage (from `-fstack-usage`, GCC, `-Os`, aarch64):

| Function | Stack (bytes) |
|----------|--------------|
| `wc_CoseSign1_Sign` | 480 |
| `wc_CoseSign1_Verify` | 288 |
| `wc_CoseEncrypt0_Encrypt` | 1088 |
| `wc_CoseEncrypt0_Decrypt` | 1056 |
| `wc_CoseKey_Encode` | 352 |
| `wc_CoseKey_Decode` | 224 |
| `wc_CBOR_Skip` | 112 |
| CBOR encode/decode | 0-48 |

## License

wolfCOSE is free software licensed under the [GPLv3](https://www.gnu.org/licenses/gpl-3.0.html).

Copyright (C) 2026 wolfSSL Inc.

## Support

For commercial licensing, support, and FIPS-validated builds, contact [wolfSSL](https://www.wolfssl.com/contact/).
