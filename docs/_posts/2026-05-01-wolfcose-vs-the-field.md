---
layout: post
title: "wolfCOSE vs The Field: The Smallest, Most Complete COSE Implementation"
date: 2026-05-01 10:00:00
---

*The Smallest, Most Complete COSE Implementation*

wolfCOSE delivers 40 algorithms including post-quantum ML-DSA, all 6 COSE message types (`Sign1`, `Encrypt0`, `Mac0`, `Sign`, `Encrypt`, `Mac`), a built-in CBOR engine, zero heap allocation, and a path to FIPS 140-3 compliance via wolfCrypt. All in under 5,500 lines of C99.

## Measurement Methodology

All measurements were taken in March 2026 on identical hardware and toolchain.

* Platform: Raspberry Pi 5 (aarch64), Debian, 8 GB RAM
* Compiler: GCC 14.2.0
* Optimization: `-Os` (optimize for size)
* NCSL tool: `cloc` v2.04
* Binary tool: `size` (Berkeley format)
* Every library was built from source `master`

## Compiled Binary Size

### COSE + CBOR Combined (.text, -Os, aarch64, GCC 14.2.0)

Every COSE library needs a CBOR engine. Most depend on an external one. wolfCOSE includes its own. This allows for an insanely lightweight CBOR engine out of the box, with just 2.7 KB used for CBOR. A fair comparison should count both.

| Library | COSE .text | CBOR .text | Total .text | .data | .bss | Algos |
|---|---|---|---|---|---|---|
| **wolfCOSE (min)** | 4.8 KB | 2.7 KB | **7.5 KB** | 0 | 0 | ES256 |
| **wolfCOSE (full)** | 22.9 KB | 2.7 KB | **25.6 KB** | 0 | 0 | 40 |
| libcose+NanoCBOR | 11.9 KB | 6.9 KB | 18.8 KB | 0 | 16 | ~2 |
| t_cose+QCBOR | 5.1 KB | 25.5 KB | 30.6 KB | 0 | 16 | 7 |
| COSE-C+cn-cbor | 68.5 KB | 8.7 KB | 77.3 KB | 96 | 88 | ~30 |

```
wolfCOSE (min)       ███                              7.5 KB (ES256 Sign1)
libcose+NanoCBOR     ███████                         18.8 KB (~2 algos)
wolfCOSE (full)      ██████████                      25.6 KB (40 algos)
t_cose+QCBOR         ████████████                    30.6 KB (7 algos)
COSE-C+cn-cbor       ██████████████████████████████  77.3 KB (~30 algos)
```

Key takeaways:

* wolfCOSE minimal (`Sign1`-sign-only, ECC) is 7.5 KB. That is smaller than any other implementation.
* wolfCOSE full is smaller than `t_cose+QCBOR` while supporting 5.7x more algorithms.
* wolfCOSE is 3x smaller than `COSE-C` while being pure C99 (`COSE-C` is C++).
* `t_cose`'s README claims 3.5 to 4.8 KB of `.text`. That is `t_cose` itself. QCBOR adds approximately 25.5 KB of `.text` (`qcbor_decode.o` alone is 21.7 KB). The real footprint is around 30.6 KB.
* wolfCOSE's built-in CBOR engine is 2.7 KB. QCBOR is 25.5 KB (9.4x larger). NanoCBOR is 6.9 KB (2.6x larger).
* `libcose` is small but only implements approximately 2 algorithms with its libsodium backend (EdDSA + ChaCha20-Poly1305).

## Why wolfCOSE Is the Smallest

The size advantage is the result of four deliberate design choices, not a single trick.

1. **A CBOR engine purpose-built for COSE.** General-purpose CBOR libraries like QCBOR handle every CBOR type, indefinite-length encoding, tagged values, floating point, and deeply nested structures. wolfCOSE's CBOR engine handles exactly what COSE needs and nothing more. The result is 2.7 KB of `.text` versus 25.5 KB for QCBOR.
2. **238 compile-time guards.** Every message type and algorithm family can be conditionally compiled out via `WOLFCOSE_NO_*` macros. The minimum build strips down to 7.5 KB. You only pay flash for what you use.
3. **Zero dynamic allocation.** No `malloc`, no `calloc`, no `free`, and no heap bookkeeping pulled in by the standard library. Every API takes caller-provided buffers and returns a length.
4. **Single dependency.** wolfCOSE depends on wolfCrypt and nothing else. There is no second CBOR library, no separate crypto backend, and no glue layer linking them together.

## Compile-Time Stripping: Pay Only for What You Use

| Config | COSE .text | CBOR .text | Total | Included |
|---|---|---|---|---|
| Full (all 40 algos, all 6 types) | 22.9 KB | 2.7 KB | 25.6 KB | Everything |
| Minimal (`Sign1`-sign, ECC-only) | 4.8 KB | 2.7 KB | 7.5 KB | ES256 Sign1 + CBOR + Key |

## Per-Algorithm Efficiency

| Library | Total .text | Algorithms | KB per Algorithm |
|---|---|---|---|
| **wolfCOSE (full)** | 25.6 KB | 40 | **0.64 KB** |
| libcose+NanoCBOR | 18.8 KB | ~2 | 9.40 KB |
| COSE-C+cn-cbor | 77.3 KB | ~30 | 2.58 KB |
| t_cose+QCBOR | 30.6 KB | 7 | 4.37 KB |

wolfCOSE delivers 0.64 KB per algorithm. That is 6.8x more efficient than `t_cose+QCBOR`.

## Source Code Size (NCSL via cloc)

### COSE + CBOR Combined

| Library | Lang | COSE | CBOR | Total NCSL | Ratio | Algos |
|---|---|---|---|---|---|---|
| **wolfCOSE** | C99 | 4,959 | 502 | **5,461** | 1.0x | 40 |
| t_cose+QCBOR | C99 | 1,617 | 4,908 | 6,525 | 1.2x | 7 |
| libcose+NanoCBOR | C99 | 1,678 | 889 | 2,567 | 0.5x | ~2 |
| COSE-C+cn-cbor | C++ | 10,579 | 1,288 | 11,867 | 2.2x | ~30 |
| go-cose+fxcbor | Go | 2,637 | 5,973 | 8,610 | 1.6x | 7 |
| pycose | Py | 3,495 | (ext) | 3,495+ | 0.6x+ | ~12 |
| COSE-JAVA | Java | 3,478 | (ext) | 3,478+ | 0.6x+ | ~8 |

```
libcose+NanoCBOR     ██████                          2,567 (~2 algos)
wolfCOSE             ██████████████                  5,461 (40 algos)
t_cose+QCBOR         ████████████████                6,525 (7 algos)
go-cose+fxcbor       ██████████████████████          8,610 (7 algos)
COSE-C+cn-cbor       ██████████████████████████████ 11,867 (~30 algos)
```

### Algorithm Density (Algos per 1,000 NCSL)

| Library | Total NCSL | Algorithms | Algos / 1K Lines |
|---|---|---|---|
| **wolfCOSE** | 5,461 | 40 | **7.3** |
| pycose | 3,495+ | ~12 | ~3.4 |
| COSE-C+cn-cbor | 11,867 | ~30 | 2.5 |
| COSE-JAVA | 3,478+ | ~8 | ~2.3 |
| t_cose+QCBOR | 6,525 | 7 | 1.1 |
| go-cose+fxcbor | 8,610 | 7 | 0.8 |

wolfCOSE delivers 7.3 algorithms per 1,000 lines. That is 6.6x denser than `t_cose+QCBOR`.

### COSE Logic Only (No CBOR)

| Library | COSE-Only | CBOR Dep | Algorithms | COSE Algos/KLOC |
|---|---|---|---|---|
| **wolfCOSE** | 4,959 | 502 (built-in) | 40 | **8.1** |
| t_cose | 1,617 | 4,908 (QCBOR) | 7 | 4.3 |
| libcose | 1,678 | 889 (NanoCBOR) | ~2 | 1.2 |
| COSE-C | 10,579 | 1,288 (cn-cbor) | ~30 | 2.8 |

`t_cose` is smaller in COSE-only lines but it only supports 7 signing algorithms with no encryption or MAC. wolfCOSE packs 40 algorithms across all 6 COSE message types into 3,342 more lines.

## Algorithm Support

### At a Glance

| Library | Lang | Sign | Enc | MAC | Key Mgmt | Total | PQ | FIPS Path |
|---|---|---|---|---|---|---|---|---|
| **wolfCOSE** | C99 | 11 | 12 | 7 | 10 | **40** | ML-DSA | Via wolfCrypt #4718 |
| COSE-C | C++ | ~4 | ~12 | ~7 | ~7 | ~30 | No | Via OpenSSL FIPS |
| pycose | Py | ~7 | ~3 | ~2 | | ~12 | No | No |
| COSE-JAVA | Java | ~4 | ~2 | ~2 | | ~8 | No | No |
| t_cose | C99 | 7 | 0 | 0 | 0 | 7 | No | Via OpenSSL FIPS |
| go-cose | Go | 7 | 0 | 0 | 0 | 7 | No | No |
| libcose | C99 | 1 | 1 | 0 | 0 | ~2 | No | No |

### Signing Algorithms (COSE_Sign1 / COSE_Sign)

| Algorithm | wolfCOSE | t_cose | COSE-C | go-cose | libcose |
|---|---|---|---|---|---|
| ES256 (P-256) | Yes | Yes | Yes | Yes | No |
| ES384 (P-384) | Yes | Yes | Yes | Yes | No |
| ES512 (P-521) | Yes | Yes | Yes | Yes | No |
| EdDSA (Ed25519) | Yes | Yes | Yes | Yes | Yes |
| EdDSA (Ed448) | Yes | No | No | No | No |
| PS256 (RSA-PSS) | Yes | Yes | No | Yes | No |
| PS384 (RSA-PSS) | Yes | Yes | No | Yes | No |
| PS512 (RSA-PSS) | Yes | Yes | No | Yes | No |
| ML-DSA-44 | Yes | No | No | No | No |
| ML-DSA-65 | Yes | No | No | No | No |
| ML-DSA-87 | Yes | No | No | No | No |
| **Total** | **11** | 7 | ~4 | 7 | 1 |

wolfCOSE is the only COSE implementation with ML-DSA (FIPS 204) post-quantum signatures and the only one supporting Ed448.

### Encryption Algorithms (COSE_Encrypt0 / COSE_Encrypt)

| Algorithm | wolfCOSE | COSE-C | libcose |
|---|---|---|---|
| A128GCM | Yes | Yes | No |
| A192GCM | Yes | Yes | No |
| A256GCM | Yes | Yes | No |
| ChaCha20-Poly1305 | Yes | No | Yes |
| AES-CCM (8 variants) | Yes (all 8) | Yes (all 8) | No |
| **Total** | **12** | ~12 | 1 |

`t_cose` and `go-cose` have zero encryption support.

### MAC Algorithms (COSE_Mac0 / COSE_Mac)

| Algorithm | wolfCOSE | COSE-C | libcose |
|---|---|---|---|
| HMAC-256/256 | Yes | Yes | No |
| HMAC-384/384 | Yes | Yes | No |
| HMAC-512/512 | Yes | Yes | No |
| AES-MAC-128-64 | Yes | Yes | No |
| AES-MAC-256-64 | Yes | Yes | No |
| AES-MAC-128-128 | Yes | Yes | No |
| AES-MAC-256-128 | Yes | Yes | No |
| **Total** | **7** | ~7 | 0 |

`t_cose`, `go-cose`, and `libcose` have zero MAC support.

### Key Management Algorithms

| Algorithm | wolfCOSE | COSE-C |
|---|---|---|
| Direct | Yes | Yes |
| A128KW / A192KW / A256KW | Yes | Yes |
| ECDH-ES + HKDF-256/512 | Yes | Yes |
| ECDH-SS + HKDF-256/512 | Yes | Yes |
| ECDH-ES + A128KW / A192KW / A256KW | Yes | Partial |
| **Total** | **10** | ~7 |

`t_cose`, `go-cose`, and `libcose` have zero key management support.

### COSE Message Types

| Type | wolfCOSE | t_cose | COSE-C | libcose | go-cose |
|---|---|---|---|---|---|
| Sign1 | Yes | Yes | Yes | Yes | Yes |
| Encrypt0 | Yes | No | Yes | Yes | No |
| Mac0 | Yes | No | Yes | No | No |
| Sign (multi-signer) | Yes | No | Yes | Yes | No |
| Encrypt (multi-recipient) | Yes | No | Yes | Yes | No |
| Mac (multi-recipient) | Yes | No | Yes | No | No |
| **Total** | **6/6** | 1/6 | 6/6 | 4/6 | 1/6 |

## What Only wolfCOSE Has

| Capability | wolfCOSE | t_cose | COSE-C | libcose | go-cose |
|---|---|---|---|---|---|
| Post-Quantum (ML-DSA) | Yes | No | No | No | No |
| Path to FIPS 140-3 | Yes | No | No | No | No |
| DO-178C path with wolfTPM | Yes | No | No | No | No |
| Secure boot path with wolfBoot | Yes | No | No | No | No |
| Zero heap allocation | Yes | Yes | No | Yes | No |
| Built-in CBOR | Yes | No | No | No | No |
| MISRA-C compliance (striving) | Yes | No | No | No | N/A |
| Ed448 support | Yes | No | No | No | No |
| All 6 COSE types | Yes | No | Yes | No | No |
| CLI tool | Yes | No | No | No | No |
| 15 CI workflows | Yes | No | No | No | No |
| Coverity + ASan CI | Yes | No | No | No | No |
| COSE_Key all types | Yes | No | Partial | No | No |

## Zero Dynamic Allocation

| Library | Heap Alloc | Notes |
|---|---|---|
| **wolfCOSE** | Zero | Safety-critical: automotive, aerospace, medical |
| t_cose | Zero | Similar embedded design |
| libcose | Zero | Minimal allocation model |
| COSE-C | malloc/calloc | OpenSSL heap dependency, cn-cbor uses calloc |
| go-cose | GC-managed | Go runtime + garbage collector |
| pycose | GC-managed | Python interpreter + GC |
| COSE-JAVA | GC-managed | JVM + garbage collector |

Zero allocation means: no heap fragmentation, no use-after-free, no double-free, no allocation latency, no OOM crashes. This is a hard requirement for safety-critical embedded systems where `malloc` is prohibited.

## FIPS 140-3 and Certifications

wolfCOSE itself is not FIPS validated. wolfCOSE's sole cryptographic dependency is wolfCrypt, which holds [FIPS 140-3 Certificate #4718](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4718). Since wolfCrypt is the only dependency, there is a direct, clean path to FIPS compliance when required.

| Certification | wolfCOSE (via wolfCrypt) | All Others |
|---|---|---|
| FIPS 140-3 | Path via wolfCrypt #4718 | Via OpenSSL FIPS |
| DO-178C | Path via wolfCrypt and wolfTPM | None |
| Common Criteria | Path via wolfCrypt EAL4+ | None |

Other libraries that use OpenSSL as a backend (`COSE-C`, `t_cose`) can also achieve FIPS compliance through OpenSSL's FIPS module, but this requires a separate FIPS-specific OpenSSL build and adds significant binary size and complexity. wolfCrypt is purpose-built for embedded and constrained environments.

## MISRA C Compliance

wolfCOSE strives for MISRA C compliance and is checked in CI on every pull request via three complementary checkers (PR #16). Although wolfCOSE is not fully MISRA C compliant, it adheres to as many rules as it can while documenting deviations from the 2023 standard.

### Coverage Summary

| Area | cppcheck (2012) | Compiler + clang-tidy (2023) | Commercial |
|---|---|---|---|
| Syntax Rules | High (~90%) | High (~95%) | 100% |
| Essential Types | Medium (~50%) | High (~80%) | 100% |
| Data Flow | Low (~30%) | Medium (~50%) | 100% |
| Std Lib Safety | Low (~20%) | Medium (~60%) | 100% |

MISRA C:2012 is fully tested via cppcheck's MISRA addon. MISRA C:2023 achieves approximately 80% coverage via compiler warnings and clang-tidy checks. Full 2023 verification requires commercial tooling (LDRA, Polyspace).

## Post-Quantum Cryptography

wolfCOSE is the only COSE implementation, in any language, with native post-quantum digital signatures.

| PQ Algorithm | wolfCOSE | All Others |
|---|---|---|
| ML-DSA-44 (FIPS 204, Level 2) | Native | None |
| ML-DSA-65 (FIPS 204, Level 3) | Native | None |
| ML-DSA-87 (FIPS 204, Level 5) | Native | None |

Roadmap: XMSS, LMS/HSS (FIPS 205), ML-KEM (FIPS 203), SLH-DSA (SPHINCS+).

## Testing and CI

### Test Suite

| Metric | wolfCOSE | t_cose | COSE-C | libcose |
|---|---|---|---|---|
| Test functions | 176 | ~15 | ~20 | ~10 |
| Test NCSL | 15,173 | | | |
| Test tiers | 3 (unit, comp, scenario) | 1 | 1 | 1 |
| Round-trip all algos | `wolfcose_tool test --all` | No | No | No |
| Interop tests | Yes (RFC vectors) | Partial | Yes | No |
| Error path injection | Yes (`force_failure.c`) | No | No | No |
| Real-world scenarios | 5 | No | No | No |

### Code Coverage

| File | Line Coverage | Branch Coverage |
|---|---|---|
| `wolfcose.c` | 99.3% | High |
| `wolfcose_cbor.c` | 100% | 100% |

### CI Pipeline (15 Workflows)

wolfCOSE has 15 GitHub Actions workflows covering the full development lifecycle. 13 trigger on every pull request, plus a nightly orchestrator and a wolfSSL-versions matrix that run on a schedule overnight.

| CI Workflow | wolfCOSE | t_cose | COSE-C | libcose |
|---|---|---|---|---|
| `build-test.yml` (Ubuntu latest + 22.04, macOS) | Yes | Yes | Yes | Yes |
| `multi-compiler.yml` (GCC 10 to 14, Clang 14 to 18) | Yes | | | |
| `static-analysis.yml` (cppcheck, scan-build, `-fanalyzer`) | Yes | | | |
| `coverity.yml` (nightly Coverity defect analysis) | Yes | | | |
| `sanitizer.yml` (ASan + UBSan) | Yes | | | |
| `coverage.yml` (gcov + lcov, threshold enforced) | Yes | | | |
| `minimal-build.yml` (minimal wolfSSL configuration) | Yes | | | |
| `misra-2012.yml` (cppcheck addon) | Yes | | | |
| `misra-2023.yml` (compiler strict + clang-tidy) | Yes | | | |
| `comprehensive-tests.yml` (~240 algorithm combinations) | Yes | | | |
| `examples.yml` (lifecycle demo + tool round-trip) | Yes | | | |
| `scenarios.yml` (real-world scenario examples) | Yes | | | |
| `codespell.yml` (spell checking) | Yes | | | |
| `nightly.yml` (nightly orchestrator on master) | Yes | | | |
| `wolfssl-versions.yml` (every wolfSSL 5.x release, nightly) | Yes | | | |

The `nightly.yml` orchestrator re-runs the full CI suite on `master` each night. This catches breakage from upstream changes between PRs. The `wolfssl-versions.yml` matrix runs nightly against every wolfSSL 5.x release to verify ongoing compatibility with the crypto backend.

## Embedded Suitability

| Requirement | wolfCOSE | t_cose | COSE-C | libcose |
|---|---|---|---|---|
| No malloc | Yes | Yes | No | Yes |
| No floating point | Yes | Yes | No | Yes |
| No external CBOR | Yes | No (QCBOR) | No (cn-cbor) | No (NanoCBOR) |
| Fixed-size buffers | Yes | Yes | No | Yes |
| C99, no C++ | Yes | Yes | No (C++) | Yes |
| Bare-metal compatible | Yes | Yes | No | Yes |
| RTOS compatible | Yes | Yes | Partial | Yes |
| `#ifdef` configurability | 238 guards | Minimal | Minimal | Minimal |
| Stack usage (`.su`) | Yes | No | No | No |

## Architecture

| Property | wolfCOSE | t_cose | COSE-C | libcose |
|---|---|---|---|---|
| Language | C99 | C99 | C++ (C API) | C99 |
| Source files | 2 (.c) | 5 (.c)+adapter | 14 (.cpp) | 11 (.c) |
| MISRA-C | Striving (2012+2023) | No | No | No |
| Dependencies | wolfCrypt only | QCBOR+OpenSSL | cn-cbor+OpenSSL | NanoCBOR+libsodium |
| Crypto backend | wolfCrypt (FIPS path) | OpenSSL/PSA | OpenSSL | libsodium |
| COSE_Key support | All types | No | Partial | Minimal |
| All 6 COSE types | Yes | No (Sign1 only) | Yes | Partial |

## Tooling: wolfcose_tool

wolfCOSE ships with `wolfcose_tool`, a full CLI for key generation, signing, verification, encryption, decryption, and automated round-trip testing. No other C COSE library ships a CLI tool.

| Capability | wolfCOSE | Others |
|---|---|---|
| Keygen (ECC, EdDSA, RSA, ML-DSA) | Yes | None |
| `COSE_Sign1` sign/verify | Yes | None |
| `COSE_Encrypt0` encrypt/decrypt | Yes | None |
| `COSE_Mac0` create/verify | Yes | None |
| Round-trip test all algorithms | `test --all` | None |
| Single algorithm test | `test -a ES256` | None |

## A Fair Comparison

wolfCOSE implements all 6 COSE message types (`Sign1`, `Encrypt0`, `Mac0`, `Sign`, `Encrypt`, `Mac`) with 40 algorithms. This comparison measures every library the same way: COSE source plus required CBOR dependency, NCSL via `cloc`, `.text` via `size`, excluding tests and examples.

Libraries like `COSE-C` also support all 6 COSE types plus CounterSign. `t_cose`, `go-cose`, and `libcose` are more limited in scope. The comparison reports exactly what each library does and does not support, and all numbers are from actual builds on the same system.

## Summary

| Claim | Evidence |
|---|---|
| Smallest minimal `.text` | 7.5 KB (Sign1-sign-only, ECC) vs 18.8 KB (libcose), 30.6 KB (t_cose+QCBOR) |
| Smallest full `.text` | 25.6 KB / 40 algos vs 30.6 KB / 7 (t_cose+QCBOR), 77.3 KB / ~30 (COSE-C) |
| Most algorithms | 40 vs next-best ~30 (COSE-C) |
| Best per-algo efficiency | 0.64 KB/algo vs 4.37 (t_cose+QCBOR), 2.58 (COSE-C) |
| Only PQ-native COSE | ML-DSA-44/65/87 built in. No other has any. |
| Path to FIPS 140-3 | Via wolfCrypt Certificate #4718 (sole dependency) |
| Zero heap allocation | No `malloc` in any code path |
| Built-in CBOR | 502-line / 2.7 KB engine vs 4,908 / 25.5 KB (QCBOR) |
| All 6 COSE types | Sign1, Encrypt0, Mac0, Sign, Encrypt, Mac |
| Most comprehensive CI | 15 workflows: Coverity, ASan, UBSan, multi-compiler, MISRA, nightly orchestrator, wolfSSL-versions matrix |
| Highest code coverage | `wolfcose.c` >= 99.3%, `wolfcose_cbor.c` = 100% |
| Only full CLI tool | keygen, sign, verify, encrypt, decrypt, round-trip all algos |
| Highest algo density | 7.3 algos/KLOC vs next-best ~3.4 (pycose) |
| MISRA-C striving | 2012 fully checked, 2023 ~80% via 3 free checkers |

## Learn More

* All wolfCOSE blog posts: <https://aidangarske.github.io/wolfCOSE/>
* wolfCOSE wiki and documentation: <https://github.com/aidangarske/wolfCOSE/wiki>
* Contact wolfSSL for commercial licensing or production support: <https://www.wolfssl.com/contact/>

Measurements taken March 2026. NCSL via `cloc` v2.04, excluding tests. Binary sizes on ARM aarch64 (RPi 5), GCC 14.2.0, `-Os`. Verified by building each project from source.
