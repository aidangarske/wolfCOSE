---
layout: post
title: "wolfCOSE: zero alloc C COSE for embedded"
date: 2026-04-30 12:00:00
---

*An experimental project from a wolfSSL developer*

Most C COSE libraries make you choose. You either get a small footprint with one message type (`t_cose` does `Sign1` only, and depends on QCBOR plus OpenSSL or mbedTLS), or every message type with `malloc` and OpenSSL (`COSE-C` does all six but ships at ~77 KB). For embedded teams already in the wolfSSL ecosystem, neither fits without doubling the crypto footprint.

wolfCOSE is the missing third option. It implements the full RFC 9052 message set (`Sign1`, `Sign`, `Encrypt0`, `Encrypt`, `Mac0`, `Mac`) in **7.5 KB minimum `.text`** (25.6 KB full build), with **zero dynamic allocation** and **40 algorithms** including native ML-DSA-44/65/87. As far as we can tell, this is also the first COSE implementation in any language with production-tested post-quantum signatures.

## A Note on the Project

wolfCOSE was developed by a wolfSSL developer, with support from wolfSSL engineering. It is currently an **experimental project** built on wolfCrypt, not an officially adopted wolfSSL product. If you are interested in production use or would like wolfSSL to formally support wolfCOSE, contact <facts@wolfssl.com>.

What that means concretely:

- The API surface is not frozen. Function signatures may change before 1.0, and the multi-signer / multi-recipient APIs are particularly likely to evolve based on early adopter feedback.
- Test coverage is high (99.3% measured on `wolfcose.c`, 100% on `wolfcose_cbor.c`, with a CI-enforced minimum of 97%) but we are still expanding edge-case coverage.
- COSE algorithm IDs for ML-DSA (`-48`, `-49`, `-50`) come from an IETF draft. The cryptographic primitive (FIPS 204 ML-DSA) is final; the integer code points could shift.
- Production deployments should pin a specific commit, review every upgrade, or wait for adoption / 1.0.

If any of that is a blocker, get in touch. Formal support and stability commitments are exactly the conversation I want to have.

## Why I Built It

I wrote this project mostly as a challenge, to see how well I could build a library from scratch compared to the other COSE libraries out there. I also noticed that of course there was no wolfcrypt use cases and thought that the world needed blessed with a little wolfcrypt magic! A more practical reason is that **wolfBoot**, wolfSSL's secure bootloader, may eventually need a COSE library for SUIT manifest verification. The existing path for COSE in the embedded boot chain requires `t_cose`, which depends on OpenSSL or mbedTLS for its crypto backend. That dependency is a non-starter for a bootloader that already uses wolfCrypt: it doubles the crypto footprint and introduces a second trust boundary.

wolfCOSE eliminates that dependency entirely. wolfBoot can verify `COSE_Sign1` firmware manifests using the same wolfCrypt it already links for secure boot, with no additional crypto library on the flash. The same library also covers the multi-signer and encryption use cases that SUIT profiles are evolving toward.

## What Is in It Today

- **Full RFC 9052 message set:** `Sign1`, `Sign`, `Encrypt0`, `Encrypt`, `Mac0`, `Mac`. Multi-signer and multi-recipient supported, not stubbed.
- **40 algorithms:** ECDSA (P-256/384/521), EdDSA, RSA-PSS, AES-GCM, AES-CCM, ChaCha20-Poly1305, AES Key Wrap, HMAC-SHA-256/384/512, ECDH-ES, and **ML-DSA-44/65/87**. (The CLI tool's `test --all` exercises a 17-algorithm round-trip subset of those for quick smoke testing; the 40 figure counts every distinct COSE algorithm ID across signing, encryption, MAC, and key distribution.)
- **Zero dynamic allocation.** Every API takes caller-provided buffers. Stack crypto material zeroized with `wc_ForceZero` on every exit.
- **Compile-time stripping:** 238 `#ifdef` guards. Minimum build is 7.5 KB; full build is 25.6 KB.
- **MISRA-C:2023 striving** with three CI checkers.
- **Path to FIPS 140-3** via wolfCrypt's [Certificate #4718](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4718).
- **15 GitHub Actions workflows** (13 on every PR, plus a nightly orchestrator and a wolfSSL-versions matrix), **~240 algorithm-combination tests**, AddressSanitizer + UndefinedBehaviorSanitizer in CI, Coverity nightly scan.

## What I Would Love from Early Adopters

- **Build it on your toolchain.** We test on Linux/macOS with GCC 10–14 and Clang 14–18. If you build on something else (IAR, ARMCC, TI CCS, Renesas, embedded Clang variants) and it fails, file an issue.
- **Run the lifecycle demo on your target.** `make demo` exercises keygen, sign, verify, and key serialization end to end across ECC, EdDSA, AEAD, HMAC, and ML-DSA-44. For ML-DSA-65 and ML-DSA-87 round-trips, use `./tools/wolfcose_tool test -a ML-DSA-65`.
- **Tell us if you want production support.** If wolfCOSE is on a critical path for you, that is the signal that turns this from an experimental project into a supported one.

## Read More

- [What is COSE? A short introduction]({{ "/blog/what-is-cose/" | relative_url }}). Background on COSE itself for readers who want context before the technical posts.
- [The Smallest Complete COSE Library for Embedded]({{ "/blog/wolfcose-full-rfc9052/" | relative_url }}). The size benchmark versus `t_cose`, `libcose`, and `COSE-C`, plus the multi-signer and multi-recipient design and the purpose-built CBOR engine.
- [The First COSE Implementation with ML-DSA]({{ "/blog/wolfcose-pqc-cose/" | relative_url }}). How FIPS 204 ML-DSA drops into `COSE_Sign1` and `COSE_Sign`, the hybrid classical-PQC migration story, and the wire-size honesty section.

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
