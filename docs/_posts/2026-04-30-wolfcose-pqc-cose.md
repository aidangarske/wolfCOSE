---
layout: post
title: "The First COSE Implementation with ML-DSA"
date: 2026-04-30 11:00:00
---

*Production-Tested Post-Quantum Signatures in wolfCOSE*

If you are signing CBOR payloads on an embedded device and you have started worrying about "harvest now, decrypt later," that worry now extends to signatures too. Long-lived firmware artifacts, attestation reports, supply-chain manifests: anything signed today with ECDSA or RSA can be retroactively forged by an adversary with a cryptographically relevant quantum computer.

wolfCOSE now has native ML-DSA-44, ML-DSA-65, and ML-DSA-87 support. As far as we can tell, this is the first COSE implementation, in any language, with production-tested post-quantum digital signatures.

A note on the project: wolfCOSE was developed by Aidan Garske, a wolfSSL developer, with support from wolfSSL engineering. It is not currently an officially adopted wolfSSL product. It is an experimental project built on wolfCrypt and the wolfSSL ecosystem. If you are interested in using wolfCOSE in production or would like wolfSSL to formally support it, reach out to <facts@wolfssl.com> and we are happy to discuss adoption and commercial support.

## The COSE PQC Landscape

| Library | PQC Support |
|---|---|
| **wolfCOSE** | **ML-DSA-44 / 65 / 87** |
| t_cose | None |
| COSE-C | None |
| pycose | None |
| go-cose | None |
| libcose | None |
| COSE-JAVA | None |

## What Is Actually in the Box

The cleanest way to describe wolfCOSE's ML-DSA implementation is to be precise about which spec each layer comes from:

- **The cryptographic primitive** is ML-DSA from [FIPS 204 final](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf) (published August 2024). We get it from wolfCrypt, which holds [FIPS 140-3 Certificate #4718](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4718). We use the context-aware API (`wc_dilithium_sign_ctx_msg`), which is what FIPS 204 final requires.
- **The COSE algorithm registration** comes from [`draft-ietf-cose-dilithium`](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/) (consolidating into `draft-ietf-cose-pqc-algs`). That draft assigns COSE algorithm IDs `-48`, `-49`, `-50` to ML-DSA-44 / 65 / 87 and defines the COSE_Key encoding (`kty=OKP`, `crv=ML-DSA-*`).
- **The COSE message envelope** is RFC 9052. Once you have a signature primitive and an algorithm ID, ML-DSA drops into `COSE_Sign1` and `COSE_Sign` exactly the way ES256 does.

The honest framing: the cryptography is final and FIPS-validated; the COSE algorithm IDs are still in IETF draft, which means the integer values could shift before the RFC is published. We track the latest draft and will update if IANA assigns different code points. The actual signatures you produce today are FIPS 204 ML-DSA. The integers we wrap them in are the only thing that is draft.

## Signing with ML-DSA in COSE_Sign1

Once your wolfSSL is built with `--enable-dilithium`, signing a CBOR payload with a 2,420-byte ML-DSA-44 signature looks identical to signing it with ES256:

```c
#include <wolfcose/wolfcose.h>
#include <wolfssl/wolfcrypt/dilithium.h>

dilithium_key  dlKey;
WOLFCOSE_KEY   coseKey;
WC_RNG         rng;

wc_InitRng(&rng);
wc_dilithium_init(&dlKey);
wc_dilithium_set_level(&dlKey, WC_ML_DSA_44);
wc_dilithium_make_key(&dlKey, &rng);

wc_CoseKey_Init(&coseKey);
wc_CoseKey_SetDilithium(&coseKey, WOLFCOSE_ALG_ML_DSA_44, &dlKey);

uint8_t scratch[8192];
int ret = wc_CoseSign1_Sign(&coseKey, WOLFCOSE_ALG_ML_DSA_44,
                            NULL, 0,                    /* kid, kidLen */
                            payload, payloadLen,
                            NULL, 0, NULL, 0,           /* detached payload, ext-AAD */
                            scratch, sizeof(scratch),
                            out, sizeof(out), &outLen, &rng);
```

That is the entire integration surface. The verifier side uses `wc_CoseSign1_Verify` with a public-only `dilithium_key`, and the COSE_Key serialization works for ML-DSA the same way it works for Ed25519: `kty=OKP`, with `crv` set to the ML-DSA level.

## Hybrid Signatures with COSE_Sign

The reason wolfCOSE has full `COSE_Sign` support (not just `Sign1`) is that the most likely deployment path for ML-DSA over the next several years is alongside a classical signature, not as a replacement. Standards bodies are explicit that hybrid is the recommended migration approach, and `COSE_Sign` is the COSE structure for it.

Here is a firmware manifest signed by both ES256 (today's verifier) and ML-DSA-65 (tomorrow's verifier), in one COSE structure:

```c
/* eccKey and mlDsaKey are WOLFCOSE_KEY*, set up earlier via
   wc_CoseKey_SetEcc() and wc_CoseKey_SetDilithium() respectively. */
WOLFCOSE_SIGNATURE signers[2] = {
    { .algId  = WOLFCOSE_ALG_ES256,
      .key    = &eccKey,
      .kid    = (const uint8_t*)"vendor-classic", .kidLen = 14 },
    { .algId  = WOLFCOSE_ALG_ML_DSA_65,
      .key    = &mlDsaKey,
      .kid    = (const uint8_t*)"vendor-pqc",     .kidLen = 10 },
};

ret = wc_CoseSign_Sign(signers, 2,
                       firmware, firmwareLen,
                       NULL, 0, NULL, 0,
                       scratch, sizeof(scratch),
                       out, sizeof(out), &outLen, &rng);
```

Per RFC 9052 §4.1, the verifier walks the `COSE_Signature` array and selects the signer to validate by matching the `alg` and `kid` headers it knows about — not by array position. Devices in the field that still only know ES256 select the `vendor-classic` signer and skip the ML-DSA one. Newer devices select the `vendor-pqc` signer and skip the ECC one. When everyone has migrated, you drop the classical signer and your code path is one line shorter. No re-signing campaigns, no flag-day cutovers.

## The Wire-Size Impact

Post-quantum signatures are not a free lunch. The wire-size impact is real and worth knowing before you architect a system around it.

| Algorithm | Public Key | Signature | NIST Level |
|---|---|---|---|
| ES256 (P-256) | 64 B | 64 B | (classical 128) |
| Ed25519 | 32 B | 64 B | (classical 128) |
| ML-DSA-44 | 1,312 B | 2,420 B | 2 |
| ML-DSA-65 | 1,952 B | 3,293 B | 3 |
| ML-DSA-87 | 2,592 B | 4,595 B | 5 |

A `COSE_Sign1` with ML-DSA-44 is about **40x larger** than the same message with Ed25519. If you are shipping firmware over LoRaWAN, that matters. If you are storing attestation reports in a database, it matters less. Plan accordingly.

What ML-DSA does not cost you, surprisingly, is verification time. ML-DSA verification is faster than ECDSA P-256 verification on a Cortex-M4, because there is no point multiplication. It is all small-integer arithmetic over polynomial rings. The expensive operation is signing, and even that is manageable. The real cost is the bytes on the wire.

## Why We Did This in COSE Now

There is a fair question: why bother integrating ML-DSA into COSE now, before the IETF draft is final? Three reasons:

1. **CNSA 2.0 timelines.** The NSA's [CNSA 2.0](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSI_CNSA_2.0_ALGORITHMS_.PDF) guidance requires PQC algorithms in software/firmware signing by **2025**, full PQC-only by **2030**. Devices being designed today will outlive the deadline. Shipping the COSE integration now means people who need to start prototyping have something to build against.
2. **The crypto is final, the wire format is the easy part.** FIPS 204 is not moving. Whatever IANA assigns as final COSE alg IDs, swapping `-48`/`-49`/`-50` for the final values is a one-line change on our side and a recompile on yours.
3. **Constrained-device PQC needs a real home.** Most PQC-in-protocol work has happened in TLS 1.3 and CMS. COSE is what you actually use on a microcontroller that does not have room for an X.509 stack: IoT firmware signing, attestation tokens, sensor authentication. If COSE does not get PQC, the embedded story has a hole in it.

## Try It

Build wolfSSL with `--enable-dilithium` (or `--enable-cryptonly --enable-dilithium` for a PQC-only build), then:

```bash
git clone https://github.com/aidangarske/wolfCOSE
cd wolfCOSE
make tool
./tools/wolfcose_tool keygen -a ML-DSA-44 -o pqc.key
./tools/wolfcose_tool sign -k pqc.key -a ML-DSA-44 -i data.bin -o data.cose
./tools/wolfcose_tool verify -k pqc.key -i data.cose
./tools/wolfcose_tool test -a ML-DSA-87
```

A complete keygen / sign / verify lifecycle for ML-DSA-44 lives in `examples/lifecycle_demo.c` and runs via `make demo`. ML-DSA-65 and ML-DSA-87 round-trips go through the CLI: `./tools/wolfcose_tool test -a ML-DSA-65`.

## What Is Next

ML-DSA is the first PQC algorithm in wolfCOSE. The roadmap from here:

- **SLH-DSA (FIPS 205, SPHINCS+):** Stateless hash-based signatures. Slower than ML-DSA but with a different security assumption (hash functions vs. lattices). Useful for certificate roots where signing speed does not matter.
- **LMS / XMSS (NIST SP 800-208):** Stateful hash-based signatures. The right tool for firmware signing where you can manage the state.
- **ML-KEM (FIPS 203, Kyber):** For `COSE_Encrypt` recipient algorithms, replacing ECDH-ES.

If you have a deployment where one of these is on a critical path, get in touch. That is how we prioritize.

## Resources

- Repo: <https://github.com/aidangarske/wolfCOSE>
- Wiki: <https://github.com/aidangarske/wolfCOSE/wiki>
- FIPS 204 (ML-DSA): <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf>
- IETF draft (COSE algorithm IDs): <https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/>
- wolfCrypt FIPS 140-3 cert #4718: <https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4718>

GPLv3, with commercial licensing available from wolfSSL. We do support engagements for teams that need help wiring this into a specific platform, particularly if you are racing a CNSA 2.0 deadline.

`github.com/aidangarske/wolfCOSE | facts@wolfssl.com`
