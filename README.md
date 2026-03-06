# wolfCOSE

A lightweight, zero-allocation C library implementing [CBOR (RFC 8949)](https://www.rfc-editor.org/rfc/rfc8949) and [COSE (RFC 9052/9053)](https://www.rfc-editor.org/rfc/rfc9052) with [wolfSSL](https://www.wolfssl.com/) as the crypto backend.

Built for constrained IoT devices, FIPS-bounded deployments, and anywhere you need authenticated CBOR payloads in minimal RAM.

## Highlights

- **First C COSE library with post-quantum signing** -- ML-DSA (FIPS 204 / Dilithium) at all three security levels
- **26 algorithms** across signing, encryption, and MAC -- from classical ECC to post-quantum
- **CNSA 2.0 ready** -- ML-DSA-44/65/87 for quantum-resistant digital signatures
- **Zero dynamic allocation** -- all operations use caller-provided buffers, no `malloc`
- **Tiny footprint** -- core library is ~15KB `.text`, zero `.data`/`.bss`
- **Full COSE lifecycle in <1KB RAM** (excluding wolfCrypt math internals)

## Key Features

- **Zero-copy CBOR decoder** -- single-pass, data pointers reference input buffer directly
- **C99 / MISRA-C:2023** -- single-exit pattern, no recursion, deviation-logged
- **wolfCrypt integration** -- leverages wolfSSL's FIPS 140-3 validated crypto engine
- **Pointer-based key struct** -- `WOLFCOSE_KEY` holds pointers to caller-owned wolfCrypt keys (~48 bytes, not kilobytes)
- **Compile-time algorithm dispatch** -- `#ifdef` ladder, zero overhead, no function pointers
- **Sensitive data scrubbing** -- `wc_ForceZero()` on all stack crypto material

## Supported Algorithms

### COSE_Sign1 (Digital Signatures)

| Algorithm | COSE ID | wolfCrypt Guard | Notes |
|-----------|---------|-----------------|-------|
| ES256 | -7 | `HAVE_ECC` | ECDSA with P-256 / SHA-256 |
| ES384 | -35 | `HAVE_ECC` | ECDSA with P-384 / SHA-384 |
| ES512 | -36 | `HAVE_ECC` | ECDSA with P-521 / SHA-512 |
| EdDSA (Ed25519) | -8 | `HAVE_ED25519` | Curve25519 |
| EdDSA (Ed448) | -8 | `HAVE_ED448` | Curve448 (Goldilocks) |
| PS256 | -37 | `WC_RSA_PSS` | RSA-PSS with SHA-256 |
| PS384 | -38 | `WC_RSA_PSS` | RSA-PSS with SHA-384 |
| PS512 | -39 | `WC_RSA_PSS` | RSA-PSS with SHA-512 |
| ML-DSA-44 | -48 | `HAVE_DILITHIUM` | Post-quantum, FIPS 204 Level 2 |
| ML-DSA-65 | -49 | `HAVE_DILITHIUM` | Post-quantum, FIPS 204 Level 3 |
| ML-DSA-87 | -50 | `HAVE_DILITHIUM` | Post-quantum, FIPS 204 Level 5 |

### COSE_Encrypt0 (Authenticated Encryption)

| Algorithm | COSE ID | wolfCrypt Guard | Notes |
|-----------|---------|-----------------|-------|
| A128GCM | 1 | `HAVE_AESGCM` | AES-GCM 128-bit |
| A192GCM | 2 | `HAVE_AESGCM` | AES-GCM 192-bit |
| A256GCM | 3 | `HAVE_AESGCM` | AES-GCM 256-bit |
| ChaCha20/Poly1305 | 24 | `HAVE_CHACHA && HAVE_POLY1305` | 256-bit, software-friendly |
| AES-CCM-16-64-128 | 10 | `HAVE_AESCCM` | 128-bit key, 8-byte tag |
| AES-CCM-16-64-256 | 11 | `HAVE_AESCCM` | 256-bit key, 8-byte tag |
| AES-CCM-64-64-128 | 12 | `HAVE_AESCCM` | 128-bit key, 8-byte tag, short nonce |
| AES-CCM-64-64-256 | 13 | `HAVE_AESCCM` | 256-bit key, 8-byte tag, short nonce |
| AES-CCM-16-128-128 | 30 | `HAVE_AESCCM` | 128-bit key, 16-byte tag |
| AES-CCM-16-128-256 | 31 | `HAVE_AESCCM` | 256-bit key, 16-byte tag |
| AES-CCM-64-128-128 | 32 | `HAVE_AESCCM` | 128-bit key, 16-byte tag, short nonce |
| AES-CCM-64-128-256 | 33 | `HAVE_AESCCM` | 256-bit key, 16-byte tag, short nonce |

### COSE_Mac0 (Message Authentication)

| Algorithm | COSE ID | wolfCrypt Guard | Notes |
|-----------|---------|-----------------|-------|
| HMAC 256/256 | 5 | `!NO_HMAC` | SHA-256, 32-byte tag |
| HMAC 384/384 | 6 | `WOLFSSL_SHA384` | SHA-384, 48-byte tag |
| HMAC 512/512 | 7 | `WOLFSSL_SHA512` | SHA-512, 64-byte tag |
| AES-MAC-128/64 | 14 | `HAVE_AES_CBC` | 128-bit key, 8-byte tag |
| AES-MAC-256/64 | 15 | `HAVE_AES_CBC` | 256-bit key, 8-byte tag |
| AES-MAC-128/128 | 25 | `HAVE_AES_CBC` | 128-bit key, 16-byte tag |
| AES-MAC-256/128 | 26 | `HAVE_AES_CBC` | 256-bit key, 16-byte tag |

### Key Distribution (COSE_Encrypt / COSE_Mac Multi-Recipient)

| Algorithm | COSE ID | wolfCrypt Guard | Notes |
|-----------|---------|-----------------|-------|
| Direct | -6 | always | Pre-shared symmetric key |
| A128KW | -3 | `HAVE_AES_KEYWRAP` | AES Key Wrap 128-bit |
| A192KW | -4 | `HAVE_AES_KEYWRAP` | AES Key Wrap 192-bit |
| A256KW | -5 | `HAVE_AES_KEYWRAP` | AES Key Wrap 256-bit |
| ECDH-ES+HKDF-256 | -25 | `HAVE_ECC && HAVE_HKDF` | Ephemeral-Static ECDH |
| ECDH-ES+HKDF-512 | -26 | `HAVE_ECC && HAVE_HKDF` | Ephemeral-Static ECDH |

### Multi-Party Messages

wolfCOSE supports full RFC 9052 multi-party COSE messages:

| Message Type | API | Notes |
|--------------|-----|-------|
| COSE_Sign | `wc_CoseSign_Sign()` / `wc_CoseSign_Verify()` | Multiple signers, mixed algorithms |
| COSE_Encrypt | `wc_CoseEncrypt_Encrypt()` / `wc_CoseEncrypt_Decrypt()` | Multiple recipients, key wrap or ECDH-ES |
| COSE_Mac | `wc_CoseMac_Create()` / `wc_CoseMac_Verify()` | Multiple recipients |

### Payload Modes

All message types support:

- **Inline payload** -- payload embedded in COSE message
- **Detached payload** -- payload transmitted separately, not in COSE structure

### External AAD

All message types support external Additional Authenticated Data (AAD) that is authenticated but not included in the COSE message.

### Key Types

| COSE kty | Guard | Algorithms |
|----------|-------|------------|
| EC2 (2) | `HAVE_ECC` | ES256, ES384, ES512 |
| OKP (1) | `HAVE_ED25519` / `HAVE_ED448` / `HAVE_DILITHIUM` | EdDSA, ML-DSA |
| RSA (3) | `WC_RSA_PSS` | PS256, PS384, PS512 |
| Symmetric (4) | always | AES-GCM, AES-CCM, ChaCha20, HMAC |

### Roadmap

Future algorithm support planned:

- **ML-KEM** (FIPS 203 / Kyber) -- post-quantum key encapsulation for COSE_Encrypt
- **XMSS / LMS** -- hash-based stateful signatures (NIST SP 800-208)
- **SLH-DSA** (SPHINCS+) -- stateless hash-based signatures

## Prerequisites

wolfSSL 5.x with the required algorithms enabled:

```bash
cd wolfssl
./autogen.sh
./configure --enable-ecc --enable-ed25519 --enable-ed448 \
            --enable-curve25519 --enable-aesgcm --enable-aesccm \
            --enable-sha384 --enable-sha512 --enable-keygen \
            --enable-rsapss --enable-chacha --enable-poly1305 \
            --enable-dilithium --enable-hkdf --enable-aeskeywrap
make && sudo make install
sudo ldconfig
```

### Feature-Specific Builds

| Feature | wolfSSL Configure Flags |
|---------|------------------------|
| ECC signing (ES256/384/512) | `--enable-ecc --enable-keygen` |
| EdDSA (Ed25519) | `--enable-ed25519 --enable-curve25519` |
| EdDSA (Ed448) | `--enable-ed448` |
| AES-GCM encryption | `--enable-aesgcm` |
| AES-CCM encryption | `--enable-aesccm` |
| ChaCha20-Poly1305 | `--enable-chacha --enable-poly1305` |
| ECDH-ES key agreement | `--enable-ecc --enable-hkdf` |
| AES Key Wrap | `--enable-aeskeywrap` |
| RSA-PSS signing | `--enable-rsapss --enable-keygen` |
| ML-DSA (post-quantum) | `--enable-dilithium` |
| HMAC (all sizes) | (enabled by default) |
| AES-MAC | `--enable-aescbc` |

**Minimal build (ECC + AES-GCM only):**
```bash
./configure --enable-ecc --enable-aesgcm --enable-sha384 \
            --enable-sha512 --enable-keygen
```

**ECDH-ES + Key Wrap (multi-recipient encryption):**
```bash
./configure --enable-ecc --enable-aesgcm --enable-sha384 \
            --enable-sha512 --enable-keygen --enable-hkdf --enable-aeskeywrap
```

**Post-quantum only (ML-DSA):**
```bash
./configure --enable-dilithium --enable-sha512
```

## Build

```bash
# Core library (libwolfcose.a)
make

# Run unit tests
make test

# Build and run CLI tool round-trip tests (all algorithms)
make tool-test

# Run lifecycle demo (11 algorithms)
make demo
```

### Build Targets

| Target | Description |
|--------|-------------|
| `make all` | Build `libwolfcose.a` (core library only) |
| `make shared` | Build `libwolfcose.so` |
| `make test` | Build + run CBOR and COSE unit tests |
| `make tool` | Build CLI tool (`tools/wolfcose_tool`) |
| `make tool-test` | Round-trip self-test for all 17 algorithms |
| `make demo` | Build + run lifecycle demo (11 algorithms) |
| `make demos` | Build + run all basic demos |
| `make comprehensive` | Build + run comprehensive algorithm tests (~240 tests) |
| `make scenarios` | Build + run real-world scenario examples |
| `make clean` | Remove all build artifacts |

## Project Structure

```
include/wolfcose/
  wolfcose.h            Public API (types, constants, all functions)
  visibility.h          WOLFCOSE_API export macros
src/
  wolfcose_cbor.c       CBOR encoder/decoder (RFC 8949, no wolfCrypt dep)
  wolfcose.c            COSE messages + key management (RFC 9052/9053, wolfCrypt)
  wolfcose_internal.h   Internal helpers (BE macros, header codec, AEAD dispatch)
tests/
  test_cbor.c           CBOR vectors (RFC 8949 Appendix A) + round-trip
  test_cose.c           COSE Sign1/Encrypt0/Mac0/Sign/Encrypt/Mac tests
  test_interop.c        Interoperability tests with RFC vectors
  test_main.c           Test harness (CI exit codes)
  vectors/              Test vectors from COSE Working Group
tools/
  wolfcose_tool.c       CLI: keygen, sign, verify, encrypt, decrypt, mac, info, test
examples/
  lifecycle_demo.c      Edge-to-cloud producer/consumer demo
  sign1_demo.c          COSE_Sign1 all algorithm combinations
  encrypt0_demo.c       COSE_Encrypt0 all algorithm combinations
  mac0_demo.c           COSE_Mac0 all algorithm combinations
  comprehensive/        Comprehensive algorithm matrix tests (CI)
    sign_all.c          Sign1 + multi-signer tests (~61 tests)
    encrypt_all.c       Encrypt0 + multi-recipient tests (~23 tests)
    mac_all.c           Mac0 + multi-recipient tests (~32 tests)
    errors_all.c        Error handling and edge cases (~19 tests)
  scenarios/            Real-world scenario examples
    firmware_update.c   Post-quantum firmware signing with ML-DSA
    multi_party_approval.c  Dual-signer firmware approval
    iot_fleet_config.c  Multi-recipient encrypted config push
    sensor_attestation.c   EAT-style attestation with AAD
    group_broadcast_mac.c  Multi-recipient MAC broadcast
docs/
  API-REFERENCE.md      Complete API documentation
  MACRO-REFERENCE.md    Configuration macros reference
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

### Post-Quantum Signing (ML-DSA)

```c
#include <wolfcose/wolfcose.h>

dilithium_key dlKey;
WOLFCOSE_KEY coseKey;
uint8_t scratch[8192];  /* PQC needs larger scratch */
uint8_t out[8192];
size_t outLen;

wc_dilithium_init(&dlKey);
wc_dilithium_set_level(&dlKey, 2);  /* Level 2 = ML-DSA-44 */
wc_dilithium_make_key(&dlKey, &rng);

wc_CoseKey_Init(&coseKey);
wc_CoseKey_SetDilithium(&coseKey, WOLFCOSE_ALG_ML_DSA_44, &dlKey);

wc_CoseSign1_Sign(&coseKey, WOLFCOSE_ALG_ML_DSA_44,
    NULL, 0, payload, payloadLen, NULL, 0,
    scratch, sizeof(scratch), out, sizeof(out), &outLen, &rng);
```

### More Examples

See the `examples/` directory for complete working examples:
- `sign1_demo.c` -- All COSE_Sign1 algorithms (ES256, ES384, ES512, EdDSA)
- `encrypt0_demo.c` -- All COSE_Encrypt0 algorithms (AES-GCM, ChaCha20, AES-CCM)
- `mac0_demo.c` -- All COSE_Mac0 algorithms (HMAC, AES-MAC)
- `lifecycle_demo.c` -- Full edge-to-cloud workflow

**Comprehensive Tests** (`examples/comprehensive/`):
- `sign_all.c` -- Sign1 and multi-signer matrix tests
- `encrypt_all.c` -- Encrypt0 and multi-recipient matrix tests
- `mac_all.c` -- Mac0 and multi-recipient matrix tests
- `errors_all.c` -- Error handling, tamper detection, edge cases

**Real-World Scenarios** (`examples/scenarios/`):
- `firmware_update.c` -- Post-quantum ML-DSA firmware signing with detached payload
- `multi_party_approval.c` -- Dual-control firmware approval (ES256 + ES384)
- `iot_fleet_config.c` -- Encrypted config push to IoT device fleet
- `sensor_attestation.c` -- EAT-style attestation with replay protection via AAD
- `group_broadcast_mac.c` -- Authenticated broadcast to multiple subscribers

See `docs/API-REFERENCE.md` for complete API documentation including multi-recipient encryption with ECDH-ES and AES Key Wrap.

### CLI Tool

```bash
# Generate keys for various algorithms
./tools/wolfcose_tool keygen -a ES256 -o ec.key
./tools/wolfcose_tool keygen -a PS256 -o rsa.key
./tools/wolfcose_tool keygen -a ML-DSA-44 -o pqc.key

# Sign and verify
./tools/wolfcose_tool sign -k ec.key -a ES256 -i data.bin -o data.cose
./tools/wolfcose_tool verify -k ec.key -i data.cose

# Encrypt and decrypt
./tools/wolfcose_tool keygen -a A128GCM -o sym.key
./tools/wolfcose_tool enc -k sym.key -a A128GCM -i secret.bin -o secret.cose
./tools/wolfcose_tool dec -k sym.key -i secret.cose -o recovered.bin

# MAC and verify
./tools/wolfcose_tool keygen -a HMAC256 -o hmac.key
./tools/wolfcose_tool mac -k hmac.key -a HMAC256 -i data.bin -o data.mac
./tools/wolfcose_tool macverify -k hmac.key -i data.mac

# Inspect COSE structure
./tools/wolfcose_tool info -i data.cose

# Run all round-trip self-tests
./tools/wolfcose_tool test --all

# Test a single algorithm
./tools/wolfcose_tool test -a ML-DSA-87
```

### Supported CLI Algorithms

```
ES256, EdDSA, Ed448, PS256, PS384, PS512,
ML-DSA-44, ML-DSA-65, ML-DSA-87,
A128GCM, A192GCM, A256GCM, ChaCha20, AES-CCM,
HMAC256, HMAC384, HMAC512
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

/* For PQC (ML-DSA), increase scratch and signature buffers */
/* #define WOLFCOSE_MAX_SCRATCH_SZ  8192 */
/* #define WOLFCOSE_MAX_SIG_SZ      4627 */
```

### Integration Checklist

1. Build wolfSSL for your target with only the algorithms you need
2. Link `libwolfcose.a` (or compile `src/wolfcose_cbor.c` + `src/wolfcose.c` directly)
3. Do **not** include `tools/` or `examples/` in production firmware
4. Pre-provision keys in secure storage -- see `lifecycle_demo.c` for the pattern
5. Caller owns all `WC_RNG`, key, buffer lifecycle -- wolfCOSE never allocates

### Stack Budget

Per-function stack usage (from `-fstack-usage`, GCC, `-Os`, aarch64):

| Function | Stack (bytes) |
|----------|--------------|
| `wc_CoseSign1_Sign` | 464 |
| `wc_CoseSign1_Verify` | 288 |
| `wc_CoseEncrypt0_Encrypt` | 1120 |
| `wc_CoseEncrypt0_Decrypt` | 1072 |
| `wc_CoseMac0_Create` | 1104 |
| `wc_CoseMac0_Verify` | 1072 |
| `wc_CoseKey_Encode` | 352 |
| `wc_CoseKey_Decode` | 224 |
| `wc_CBOR_Skip` | 112 |
| CBOR encode/decode | 0-48 |

## CI / Testing

wolfCOSE runs the following CI checks on every push and pull request:

- **Build and Test** -- Ubuntu (latest + 22.04), macOS, with full unit test suite
- **Multi-Compiler** -- GCC 10/11/12/13/14 and Clang 14/15/16/17/18
- **Comprehensive Tests** -- ~240 algorithm combination tests (sign/encrypt/mac matrix)
- **Scenario Examples** -- Real-world workflows (firmware update, attestation, fleet config)
- **Examples** -- Lifecycle demo (11 algorithms) and tool round-trip (17 algorithms)
- **Static Analysis** -- cppcheck, Clang analyzer, GCC `-fanalyzer`
- **Coverity Scan** -- nightly defect analysis

<a href="https://scan.coverity.com/projects/wolfcose">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/32918/badge.svg"/>
</a>

## License

wolfCOSE is free software licensed under the [GPLv3](https://www.gnu.org/licenses/gpl-3.0.html).

Copyright (C) 2026 wolfSSL Inc.

## Support

For commercial licensing, support, and FIPS-validated builds, contact [wolfSSL](https://www.wolfssl.com/contact/).
