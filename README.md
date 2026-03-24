# wolfCOSE

wolfCOSE is a lightweight C library implementing [CBOR (RFC 8949)](https://www.rfc-editor.org/rfc/rfc8949) and [COSE (RFC 9052/9053)](https://www.rfc-editor.org/rfc/rfc9052) using [wolfSSL](https://www.wolfssl.com/) as the crypto backend.

## Main Features

- **Post-quantum signing**: ML-DSA (Dilithium) at all three security levels
- **26 algorithms** across signing, encryption, and MAC
- **Zero dynamic allocation**: all operations use caller-provided buffers
- **Tiny footprint**: core library is ~15KB `.text`, zero `.data`/`.bss`
- **Full COSE lifecycle in <1KB RAM** (excluding wolfCrypt internals)

## Supported Algorithms

**Signing:** ES256, ES384, ES512, EdDSA (Ed25519/Ed448), PS256/384/512, ML-DSA-44/65/87

**Encryption:** AES-GCM (128/192/256), ChaCha20-Poly1305, AES-CCM variants

**MAC:** HMAC-SHA256/384/512, AES-MAC

**Key Distribution:** Direct, AES Key Wrap, ECDH-ES+HKDF

## Prerequisites (wolfSSL)

wolfCOSE requires [wolfSSL](https://www.wolfssl.com/) 5.x as its crypto backend. Choose between a minimal build (ECC + AES-GCM only) or a full build that enables all 26 algorithms wolfCOSE supports.

### Minimal Build (ECC + AES-GCM)

This gives you COSE Sign1 (ES256/384/512) and Encrypt0 (AES-GCM) — the most common COSE operations for IoT:

```bash
cd wolfssl
./autogen.sh
./configure --enable-ecc --enable-aesgcm \
            --enable-sha384 --enable-sha512 --enable-keygen
make && sudo make install
sudo ldconfig
```

**Algorithms enabled:** ES256, ES384, ES512, AES-GCM-128/192/256

### Full Build (All Algorithms)

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
| `make clean` | Remove all build artifacts |

## Quick Start

### Examples

See `examples/` for complete working code:
- `sign1_demo.c`, `encrypt0_demo.c`, `mac0_demo.c`: algorithm demos
- `lifecycle_demo.c`: full edge-to-cloud workflow
- `comprehensive/`: algorithm matrix tests
- `scenarios/`: firmware signing, attestation, fleet config

## CLI Tool

```bash
# Generate keys
./tools/wolfcose_tool keygen -a ES256 -o ec.key
./tools/wolfcose_tool keygen -a ML-DSA-44 -o pqc.key

# Sign and verify
./tools/wolfcose_tool sign -k ec.key -a ES256 -i data.bin -o data.cose
./tools/wolfcose_tool verify -k ec.key -i data.cose

# Encrypt and decrypt
./tools/wolfcose_tool keygen -a A128GCM -o sym.key
./tools/wolfcose_tool enc -k sym.key -a A128GCM -i secret.bin -o secret.cose
./tools/wolfcose_tool dec -k sym.key -i secret.cose -o recovered.bin

# MAC
./tools/wolfcose_tool keygen -a HMAC256 -o hmac.key
./tools/wolfcose_tool mac -k hmac.key -a HMAC256 -i data.bin -o data.mac
./tools/wolfcose_tool macverify -k hmac.key -i data.mac

# Inspect structure
./tools/wolfcose_tool info -i data.cose

# Self-test all algorithms
./tools/wolfcose_tool test --all
```

## CI / Testing

Runs on every push and PR:

- **Build + Test**: Ubuntu, macOS, GCC 10-14, Clang 14-18
- **Comprehensive Tests**: ~240 algorithm combination tests
- **Static Analysis**: cppcheck, Clang analyzer, GCC `-fanalyzer`
- **MISRA C 2012**: cppcheck `--addon=misra` checking all wolfCOSE code paths
- **MISRA C 2023**: strict GCC warnings and clang-tidy (`bugprone-*`, `cert-*`, `clang-analyzer-*`, `misc-*`)
- **Coverity Scan**: nightly defect analysis
- **Code Coverage**: 99.3% for wolfcose.c, 100% for wolfcose_cbor.c

```bash
make coverage                  # Run tests with gcov
make coverage-force-failure    # Include crypto failure path testing
```

<a href="https://scan.coverity.com/projects/wolfcose">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/32918/badge.svg"/>
</a>

## Documentation

Full documentation is available in the [Wiki](https://github.com/aidangarske/wolfCOSE/wiki):

- [Getting Started](https://github.com/aidangarske/wolfCOSE/wiki/Getting-Started): Build instructions and first steps
- [Algorithms](https://github.com/aidangarske/wolfCOSE/wiki/Algorithms): Complete list of 26 supported algorithms with COSE IDs
- [API Reference](https://github.com/aidangarske/wolfCOSE/wiki/API-Reference): Function signatures, data structures, error codes
- [Macros](https://github.com/aidangarske/wolfCOSE/wiki/Macros): Compile-time configuration options
- [Testing](https://github.com/aidangarske/wolfCOSE/wiki/Testing): Test infrastructure, coverage, and failure injection
- [Project Structure](https://github.com/aidangarske/wolfCOSE/wiki/Project-Structure): Source file layout

## License

wolfCOSE is free software licensed under the [GPLv3](https://www.gnu.org/licenses/gpl-3.0.html).

Copyright (C) 2026 wolfSSL Inc.

## Support

For commercial licensing and support, contact [wolfSSL](https://www.wolfssl.com/contact/). wolfSSL offers FIPS 140-3 validated crypto modules.
