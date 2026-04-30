---
layout: post
title: "The Smallest Complete COSE Library for Embedded"
date: 2026-04-30 10:00:00
---

*Single-Actor and Multi-Actor Sign, Encrypt, and MAC in One Library*

wolfCOSE now has full multi-signer and multi-recipient support, making it the smallest C COSE library to implement the entire RFC 9052 message set: `COSE_Sign1`, `COSE_Sign`, `COSE_Encrypt0`, `COSE_Encrypt`, `COSE_Mac0`, `COSE_Mac`. No malloc, no external CBOR dependency, no caveats.

If you have worked with COSE on a constrained device, you know the landscape. Most embedded C libraries either implement only `COSE_Sign1` (`t_cose`, `go-cose`, `libcose`) or implement everything but require a heap allocator and several thousand lines of dependencies (`COSE-C`). wolfCOSE fills the gap: a complete RFC 9052 implementation without dragging in OpenSSL or `cn-cbor`.

A note on the project: wolfCOSE was developed by Aidan Garske, a wolfSSL developer, with support from wolfSSL engineering. It is currently an experimental project built on wolfCrypt, not an officially adopted wolfSSL product. If you are interested in production use or would like wolfSSL to formally support wolfCOSE, contact <facts@wolfssl.com>.

## Why Multi-Actor Messages Matter

`COSE_Sign1` is great when one entity signs one payload. It is not enough when:

- You are shipping firmware that requires dual-control approval (silicon vendor + OEM both sign).
- You are rolling out a hybrid classical/PQC signature during the post-quantum migration: one ML-DSA signature, one ECDSA signature, both attached to the same artifact.
- You are broadcasting an encrypted config to a fleet of devices, each with its own KEK or ECDH keypair, and you do not want to encrypt the payload N times.
- You are sending a MAC'd message to a multicast group where each subscriber has a different shared secret with the broadcaster.

These are exactly the scenarios `COSE_Sign`, `COSE_Encrypt`, and `COSE_Mac` were designed for, and they are the ones that disappeared from "alpha" or "experimental" status in most other C COSE libraries.

## Dual-Signing a Firmware Manifest

```c
/* vendorKey and oemKey are WOLFCOSE_KEY*, prepared earlier via
   wc_CoseKey_SetEcc() and wc_CoseKey_SetDilithium() respectively. */
WOLFCOSE_SIGNATURE signers[2] = {
    { .algId = WOLFCOSE_ALG_ES256,
      .key   = &vendorKey,
      .kid   = (const uint8_t*)"vendor-2026", .kidLen = 11 },
    { .algId = WOLFCOSE_ALG_ML_DSA_65,
      .key   = &oemKey,
      .kid   = (const uint8_t*)"oem-pqc-1",   .kidLen = 9 },
};

ret = wc_CoseSign_Sign(signers, 2,
                       firmware, firmwareLen,
                       NULL, 0, NULL, 0,
                       scratch, sizeof(scratch),
                       out, sizeof(out), &outLen, &rng);
```

Two signers, two algorithms, one COSE structure. The verifier picks an index and a public key. Multi-recipient encryption follows the same shape: you hand wolfCOSE an array of `WOLFCOSE_RECIPIENT` describing how each recipient learns the content key (Direct, AES Key Wrap, ECDH-ES, ECDH-ES+KW), and you get one ciphertext addressable by every recipient.

## Honest Comparison

wolfCOSE was benchmarked against the four most-used C / C++ / Go COSE libraries on a Raspberry Pi 5 (aarch64, GCC 14.2, `-Os`), measuring `.text` size with `size`, source lines with `cloc`. Every library was built from master.

```
wolfCOSE (min)       ███                              7.5 KB (ES256 Sign1)
libcose+NanoCBOR     ███████                         18.8 KB (~2 algos)
wolfCOSE (full)      ██████████                      25.6 KB (40 algos)
t_cose+QCBOR         ████████████                    30.6 KB (7 algos)
COSE-C+cn-cbor       ██████████████████████████████  77.3 KB (~30 algos)
```

`t_cose`'s README claims 3.5 to 4.8 KB of `.text`. That is `t_cose` itself. QCBOR, which `t_cose` requires and ships separately, adds ~25.5 KB of `.text` on its own (`qcbor_decode.o` is 21.7 KB). The full footprint is ~30.6 KB once you include the CBOR engine you actually need to parse a COSE message. wolfCOSE's built-in CBOR engine is 2.7 KB.

`libcose` is genuinely small (~18.8 KB combined with NanoCBOR), but its libsodium backend implements two algorithms: EdDSA and ChaCha20-Poly1305. If you need ES256, RSA-PSS, AES-GCM, or HMAC-SHA256, you are not comparing the same thing.

`COSE-C` is the only other library with all six message types, but it is C++ with a C façade, depends on `cn-cbor` (heap-allocated) and OpenSSL, and clocks in at ~77 KB.

## Per-Algorithm Efficiency

| Library | Total .text | Algorithms | KB / Algorithm |
|---|---|---|---|
| **wolfCOSE (full)** | 25.6 KB | 40 | **0.64 KB** |
| COSE-C+cn-cbor | 77.3 KB | ~30 | 2.58 KB |
| t_cose+QCBOR | 30.6 KB | 7 | 4.37 KB |
| libcose+NanoCBOR | 18.8 KB | ~2 | 9.40 KB |

wolfCOSE delivers ~6.8x more algorithms per KB of code than `t_cose+QCBOR`.

## A Purpose-Built CBOR Engine

wolfCOSE includes its own CBOR encoder/decoder in a single file (`wolfcose_cbor.c`, 502 NCSL, 2.7 KB `.text`). This was a deliberate design choice for embedded targets, not an oversight. General-purpose CBOR libraries like QCBOR (4,908 NCSL, 25.5 KB `.text`) are full-featured implementations that handle every CBOR type, indefinite-length encoding, tagged values, floating point, and deeply nested structures. wolfCOSE's CBOR engine handles exactly what COSE needs: definite-length maps, byte strings, text strings, integers, arrays, and CBOR tags. Nothing more.

The tradeoff is clear: wolfCOSE's CBOR engine is not a general-purpose CBOR library. It does not parse arbitrary CBOR documents, and it is not intended for applications that need full CBOR flexibility. What it does is keep the total COSE + CBOR footprint under 8 KB for a minimal build, which is the difference between fitting on a Cortex-M0 with 64 KB of flash and not fitting at all.

For teams that need wolfCOSE on an embedded target, this is the right tradeoff. The CBOR engine is small because the use case is small: encode and decode COSE messages, nothing else.

## Compile-Time Stripping Is the Design

The full library is 22.9 KB of `.text` for the COSE layer; combined with the 2.7 KB CBOR engine, that is the 25.6 KB full-build total quoted in the comparison above. The "I just need ES256 Sign1 and nothing else" build is 4.8 KB of COSE + 2.7 KB of CBOR = 7.5 KB total. You opt out of features you do not need:

```
-DWOLFCOSE_NO_SIGN     -DWOLFCOSE_NO_ENCRYPT  -DWOLFCOSE_NO_MAC
-DWOLFCOSE_NO_ENCRYPT0 -DWOLFCOSE_NO_MAC0
-DWOLFCOSE_NO_SIGN1_SIGN
```

This matters because the people who care most about COSE are the people who care most about flash. 238 compile-time guards across the library ensure you only pay for what you use.

## Zero Allocation, MISRA-Striving, FIPS Path

**No `malloc` anywhere in wolfCOSE.** Every API takes caller-provided buffers, returns a length, and zeroizes its own stack with `wc_ForceZero` before returning. Safety-critical embedded teams that ban heap allocation can use this on bare metal.

**MISRA-C:2023 striving.** Single-exit functions, no recursion, no function pointers in the hot path, three CI checkers (`cppcheck --addon=misra` for 2012, GCC strict + clang-tidy for ~80% of 2023). Deviations are documented rather than hidden.

**A real path to FIPS 140-3.** wolfCrypt holds [Certificate #4718](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4718). wolfCOSE's crypto goes through one dependency that is FIPS-validated. wolfCOSE is not validated itself, but the path is clean.

## CI

wolfCOSE has 15 GitHub Actions workflows: 13 trigger on every PR, plus a nightly orchestrator and a wolfSSL-versions matrix that run on a schedule. Together they cover the full development lifecycle:

- **Build + Test:** multi-platform (Ubuntu / macOS), multi-compiler (GCC 10 to 14, Clang 14 to 18)
- **Static analysis:** cppcheck + Clang scan-build + GCC `-fanalyzer`
- **Coverity:** nightly scan
- **Sanitizers:** AddressSanitizer + UndefinedBehaviorSanitizer
- **Code coverage:** threshold enforced (>=97% on `wolfcose.c`, 100% on `wolfcose_cbor.c`)
- **MISRA-C:2012:** `cppcheck --addon=misra` with all wolfCOSE macros defined
- **MISRA-C:2023:** GCC strict warnings + clang-tidy (`bugprone-*`, `cert-*`, `clang-analyzer-*`, `misc-*`)
- **Minimal build matrix:** 6 configurations testing different `WOLFCOSE_NO_*` combinations
- **Comprehensive algorithm tests:** ~240 algorithm-combination round-trips
- **Real-world scenarios:** firmware signing, attestation, fleet config, group broadcast, multi-party approval
- **Examples build:** all example programs compile and link cleanly
- **wolfSSL integration:** builds against wolfSSL to verify crypto backend compatibility
- **Codespell:** typo checking across the codebase
- **Nightly orchestrator:** re-runs the full CI suite on master each night (catches breakage from upstream changes between PRs)
- **wolfSSL-versions matrix:** nightly compatibility check against every wolfSSL 5.x release

The `wolfcose_tool` CLI ships with the project and round-trip tests every algorithm with `wolfcose_tool test --all`.

## Why We Built This

A key driver for wolfCOSE was enabling SUIT manifest verification in **wolfBoot**, wolfSSL's secure bootloader. The existing path for COSE in the embedded boot chain required `t_cose`, which depends on OpenSSL or mbedTLS for its crypto backend. That dependency is a non-starter for a bootloader that already uses wolfCrypt: it doubles the crypto footprint and introduces a second trust boundary.

wolfCOSE eliminates that dependency entirely. wolfBoot can verify `COSE_Sign1` firmware manifests using the same wolfCrypt it already links for secure boot, with no additional crypto library on the flash. The same library also covers the multi-signer and encryption use cases that SUIT profiles are evolving toward.

`t_cose` is a well-engineered library with strong `COSE_Sign1` support, and `COSE-C` covers the full message set. wolfCOSE is built for teams that are already in the wolfSSL ecosystem and need COSE without adding OpenSSL, cn-cbor, or a heap allocator to their build.

## Try It

```bash
git clone https://github.com/aidangarske/wolfCOSE
cd wolfCOSE
make && make test
make tool && ./tools/wolfcose_tool test --all
```

Repo: <https://github.com/aidangarske/wolfCOSE>
Wiki: <https://github.com/aidangarske/wolfCOSE/wiki>

GPLv3, with commercial licensing available from wolfSSL upon adoption. For interest in production support, contact <facts@wolfssl.com>.

`github.com/aidangarske/wolfCOSE | facts@wolfssl.com`

Numbers measured March 2026 on a Raspberry Pi 5 (aarch64, GCC 14.2, `-Os`); every library was built from master with its default release flags. File an issue if you spot a build flag we got wrong on your favorite library and we will re-run.
