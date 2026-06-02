# wolfCOSE Documentation

Welcome to the wolfCOSE wiki. This is the complete documentation for wolfCOSE, a lightweight CBOR and COSE library for embedded systems.

## What is wolfCOSE?

wolfCOSE is a C library implementing:
- **CBOR** (RFC 8949): Concise Binary Object Representation
- **COSE** (RFC 9052/9053): CBOR Object Signing and Encryption

It uses [wolfSSL](https://www.wolfssl.com/) as the cryptographic backend and is designed for constrained IoT devices, FIPS-bounded deployments, and anywhere you need authenticated CBOR payloads in minimal RAM.

## Key Features

| Feature | Description |
|---------|-------------|
| Complete RFC 9052 | All six COSE message types — Sign1, Sign, Encrypt0, Encrypt, Mac0, Mac |
| Multi-signer / multi-recipient | Full `COSE_Sign`, `COSE_Encrypt`, and `COSE_Mac` support |
| Post-quantum signing | ML-DSA (FIPS 204) at all three security levels — first COSE library to ship native PQC |
| Zero allocation | All operations use caller-provided buffers, no malloc |
| Tiny footprint | 7.5 KB minimal `.text` (Sign1+ECC), 25.6 KB full (40 algorithms), zero `.data`/`.bss` |
| 40 algorithms | Signing, encryption, MAC, and key distribution — classical and post-quantum |
| FIPS 140-3 path | Sole crypto dependency is wolfCrypt FIPS Certificate #4718 |
| CNSA 2.0 ready | ML-DSA-44/65/87 for quantum-resistant signatures |
| MISRA-C:2023 | compliance striving, Single-exit pattern, no recursion, deviation-logged |

## Documentation

| Page | Description |
|------|-------------|
| [[Getting Started]] | Prerequisites, building, and quick start examples |
| [[Message Types]] | All six RFC 9052 messages (Sign1/Sign, Encrypt0/Encrypt, Mac0/Mac) with code samples |
| [[Algorithms]] | Complete list of supported algorithms with COSE IDs |
| [[API Reference]] | Full API documentation for all functions |
| [[Macros]] | Configuration macros and compile-time options |
| [[Testing]] | Unit tests, coverage, and failure injection |
| [[Project Structure]] | Source code layout and file descriptions |

## Supported Message Types

wolfCOSE implements all six COSE message types from RFC 9052:

| Message Type | Tag | Description |
|--------------|-----|-------------|
| COSE_Sign1 | 18 | Single signer digital signature |
| COSE_Sign | 98 | Multiple signers |
| COSE_Encrypt0 | 16 | Symmetric encryption (single key) |
| COSE_Encrypt | 96 | Multi-recipient encryption |
| COSE_Mac0 | 17 | Symmetric MAC (single key) |
| COSE_Mac | 97 | Multi-recipient MAC |

## Quick Links

- [GitHub Repository](https://github.com/aidangarske/wolfCOSE)
- [wolfSSL Website](https://www.wolfssl.com/)
- [RFC 8949 (CBOR)](https://www.rfc-editor.org/rfc/rfc8949)
- [RFC 9052 (COSE Structures)](https://www.rfc-editor.org/rfc/rfc9052)
- [RFC 9053 (COSE Algorithms)](https://www.rfc-editor.org/rfc/rfc9053)

## License

wolfCOSE is free software licensed under GPLv3. For commercial licensing and support, contact [wolfSSL](https://www.wolfssl.com/contact/).
