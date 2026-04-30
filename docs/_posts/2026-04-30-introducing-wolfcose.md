---
layout: post
title: "Introducing wolfCOSE: zero-allocation C COSE for embedded, FIPS, and PQC"
date: 2026-04-30 12:00:00
---

*An experimental project from a wolfSSL developer*

Most C COSE libraries make you choose. You either get a small footprint with one message type (`t_cose` does `Sign1` only, and depends on QCBOR plus OpenSSL or mbedTLS), or every message type with `malloc` and OpenSSL (`COSE-C` does all six but ships at ~77 KB). For embedded teams already in the wolfSSL ecosystem, neither fits without doubling the crypto footprint.

wolfCOSE is the missing third option: the full RFC 9052 message set — `Sign1`, `Sign`, `Encrypt0`, `Encrypt`, `Mac0`, `Mac` — in **5,500 lines of C99 with zero dynamic allocation**, **40 algorithms** including native ML-DSA-44/65/87, and a **7.5 KB minimum `.text`** when you only need `Sign1` with ECC. It is also, as far as we can tell, the first COSE implementation in any language with production-tested post-quantum signatures.

## A Note on the Project

wolfCOSE was developed by Aidan Garske, a wolfSSL developer, with support from wolfSSL engineering. It is currently an **experimental project** built on wolfCrypt, not an officially adopted wolfSSL product. If you are interested in production use or would like wolfSSL to formally support wolfCOSE, contact <facts@wolfssl.com>.

What that means concretely:

- The API surface is not frozen. Function signatures may change before 1.0, and the multi-signer / multi-recipient APIs are particularly likely to evolve based on early adopter feedback.
- Test coverage is high (>=97% on `wolfcose.c`, 100% on `wolfcose_cbor.c`) but we are still expanding edge-case coverage.
- COSE algorithm IDs for ML-DSA (`-48`, `-49`, `-50`) come from an IETF draft. The cryptographic primitive (FIPS 204 ML-DSA) is final; the integer code points could shift.
- Production deployments should pin a specific commit, review every upgrade, or wait for adoption / 1.0.

If any of that is a blocker, get in touch — formal support and stability commitments are exactly the conversation we want to have.

## Why I Built It

A key driver for wolfCOSE was enabling SUIT manifest verification in **wolfBoot**, wolfSSL's secure bootloader. The existing path for COSE in the embedded boot chain required `t_cose`, which depends on OpenSSL or mbedTLS for its crypto backend. That dependency is a non-starter for a bootloader that already uses wolfCrypt: it doubles the crypto footprint and introduces a second trust boundary.

wolfCOSE eliminates that dependency entirely. wolfBoot can verify `COSE_Sign1` firmware manifests using the same wolfCrypt it already links for secure boot, with no additional crypto library on the flash. The same library also covers the multi-signer and encryption use cases that SUIT profiles are evolving toward.

`t_cose` is a well-engineered library with strong `COSE_Sign1` support, and `COSE-C` covers the full message set. wolfCOSE is built for teams that are already in the wolfSSL ecosystem and need COSE without adding OpenSSL, cn-cbor, or a heap allocator to their build.

## What Is in It Today

- **Full RFC 9052 message set:** `Sign1`, `Sign`, `Encrypt0`, `Encrypt`, `Mac0`, `Mac`. Multi-signer and multi-recipient supported, not stubbed.
- **40 algorithms:** ECDSA (P-256/384/521), EdDSA, RSA-PSS, AES-GCM, AES-CCM, ChaCha20-Poly1305, AES Key Wrap, HMAC-SHA-256/384/512, ECDH-ES, and **ML-DSA-44/65/87**.
- **Zero dynamic allocation.** Every API takes caller-provided buffers. Stack crypto material zeroized with `wc_ForceZero` on every exit.
- **Compile-time stripping:** 238 `#ifdef` guards. Minimum build is 7.5 KB; full build is 25.6 KB.
- **MISRA-C:2023 striving** with three CI checkers.
- **Path to FIPS 140-3** via wolfCrypt's [Certificate #4718](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4718).
- **11 GitHub Actions workflows, ~240 algorithm-combination tests, AddressSanitizer + UndefinedBehaviorSanitizer in CI, Coverity nightly scan.**

## What I Would Love from Early Adopters

- **Build it on your toolchain.** We test on Linux/macOS with GCC 10–14 and Clang 14–18. If you build on something else (IAR, ARMCC, TI CCS, Renesas, embedded Clang variants) and it fails, file an issue.
- **Try the API and tell us what is awkward.** The pre-1.0 window is when API feedback is cheapest to act on.
- **Run the lifecycle demo on your target.** `make demo DEMO_ALG=ML-DSA-65` exercises keygen, sign, verify, and key serialization end to end.
- **Tell us if you want production support.** If wolfCOSE is on a critical path for you, that is the signal that turns this from an experimental project into a supported one.

## Read More

- [What is COSE? A short introduction]({{ "/blog/what-is-cose/" | relative_url }}) — for readers who want the background on COSE itself before reading the technical posts.
- [The Smallest Complete COSE Library for Embedded]({{ "/blog/wolfcose-full-rfc9052/" | relative_url }}) — the size benchmark vs. `t_cose`, `libcose`, and `COSE-C`, plus the multi-signer / multi-recipient design and the purpose-built CBOR engine.
- [The First COSE Implementation with ML-DSA]({{ "/blog/wolfcose-pqc-cose/" | relative_url }}) — how FIPS 204 ML-DSA drops into `COSE_Sign1` and `COSE_Sign`, the hybrid classical-PQC migration story, and the wire-size honesty section.

## Try It

```bash
git clone https://github.com/aidangarske/wolfCOSE
cd wolfCOSE
make && make test
./tools/wolfcose_tool test --all
```

Repo: <https://github.com/aidangarske/wolfCOSE>
Wiki: <https://github.com/aidangarske/wolfCOSE/wiki>

GPLv3, with commercial licensing available from wolfSSL upon adoption. For interest in production support, contact <facts@wolfssl.com>.

`github.com/aidangarske/wolfCOSE | facts@wolfssl.com`
