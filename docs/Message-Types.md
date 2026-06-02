# COSE Message Types

wolfCOSE implements the complete RFC 9052 message set — all six COSE structures, including the multi-actor variants (`COSE_Sign`, `COSE_Encrypt`, `COSE_Mac`) that most embedded C COSE libraries omit.

| Message | RFC 9052 | Tag | API |
|---|---|---|---|
| `COSE_Sign1` | Sec. 4.2 | 18 | `wc_CoseSign1_Sign` / `wc_CoseSign1_Verify` |
| `COSE_Sign` | Sec. 4.1 | 98 | `wc_CoseSign_Sign` / `wc_CoseSign_Verify` |
| `COSE_Encrypt0` | Sec. 5.2 | 16 | `wc_CoseEncrypt0_Encrypt` / `wc_CoseEncrypt0_Decrypt` |
| `COSE_Encrypt` | Sec. 5.1 | 96 | `wc_CoseEncrypt_Encrypt` / `wc_CoseEncrypt_Decrypt` |
| `COSE_Mac0` | Sec. 6.2 | 17 | `wc_CoseMac0_Create` / `wc_CoseMac0_Verify` |
| `COSE_Mac` | Sec. 6.1 | 97 | `wc_CoseMac_Create` / `wc_CoseMac_Verify` |
| `COSE_Key` / `COSE_KeySet` | Sec. 7 | (none) | `wc_CoseKey_Encode` / `wc_CoseKey_Decode` |

Every message can be built attached or detached, with optional external AAD, and every algorithm in [[Algorithms]] is available to every message type that accepts it.

## COSE_Sign1 — single-signer signature (RFC 9052 Sec. 4.2)

`COSE_Sign1` is the most common COSE message: one signer, one signature.

```c
WOLFCOSE_KEY key;
uint8_t out[1024];
size_t outLen;
WC_RNG rng;

wc_InitRng(&rng);
wc_CoseKey_Init(&key);
wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &eccPriv);

int ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256,
                            payload, payloadLen,
                            NULL, 0,            /* no detached payload */
                            NULL, 0,            /* no external AAD */
                            scratch, sizeof(scratch),
                            out, sizeof(out), &outLen,
                            &rng);
```

## COSE_Sign — multi-signer signature (RFC 9052 Sec. 4.1)

`COSE_Sign` carries N independent signatures over the same payload. Use it for dual-control approval, certificate chains where multiple parties attest, or hybrid classical/PQC signatures during migration. Each signer has its own algorithm and `kid`.

```c
WOLFCOSE_SIGNATURE signers[2] = {
    { .algId = WOLFCOSE_ALG_ES256,
      .key   = &vendorKey,
      .kid   = (const uint8_t*)"vendor-2026", .kidLen = 11 },
    { .algId = WOLFCOSE_ALG_ML_DSA_65,        /* hybrid: classical + PQC */
      .key   = &oemKey,
      .kid   = (const uint8_t*)"oem-pqc-1",   .kidLen = 9 },
};

ret = wc_CoseSign_Sign(signers, 2,
                       firmware, firmwareLen,
                       NULL, 0,                   /* attached payload */
                       NULL, 0,                   /* no external AAD */
                       scratch, sizeof(scratch),
                       out, sizeof(out), &outLen,
                       &rng);
```

Verifiers select which signature to check by index:

```c
ret = wc_CoseSign_Verify(&vendorPubKey, /*signerIndex=*/0,
                         in, inLen,
                         NULL, 0, NULL, 0,
                         scratch, sizeof(scratch),
                         &hdr, &payload, &payloadLen);
```

## COSE_Encrypt0 — single-recipient AEAD (RFC 9052 Sec. 5.2)

Direct symmetric AEAD. The caller already has the content encryption key (CEK).

```c
ret = wc_CoseEncrypt0_Encrypt(&aesKey, WOLFCOSE_ALG_A128GCM,
                              iv, sizeof(iv),
                              plaintext, plaintextLen,
                              NULL, 0, NULL, 0,
                              scratch, sizeof(scratch),
                              out, sizeof(out), &outLen,
                              &rng);
```

## COSE_Encrypt — multi-recipient AEAD (RFC 9052 Sec. 5.1)

`COSE_Encrypt` produces one ciphertext addressable by any of N recipients. Each recipient entry describes how that recipient learns the CEK: pre-shared (Direct), wrapped under a recipient KEK (`A128KW` / `A192KW` / `A256KW`), or derived via ECDH.

```c
WOLFCOSE_RECIPIENT recipients[3] = {
    { .algId = WOLFCOSE_ALG_DIRECT,
      .key   = &fleetSharedKey,
      .kid   = (const uint8_t*)"fleet-2026", .kidLen = 10 },
    { .algId = WOLFCOSE_ALG_A256KW,
      .key   = &device42Kek,
      .kid   = (const uint8_t*)"dev-42",     .kidLen = 6 },
    { .algId = WOLFCOSE_ALG_ECDH_ES_HKDF_256,
      .key   = &device43Pub,
      .kid   = (const uint8_t*)"dev-43",     .kidLen = 6 },
};

ret = wc_CoseEncrypt_Encrypt(recipients, 3,
                             WOLFCOSE_ALG_A128GCM,         /* content alg */
                             iv, sizeof(iv),
                             config, configLen,
                             NULL, 0, NULL, 0,
                             scratch, sizeof(scratch),
                             out, sizeof(out), &outLen,
                             &rng);
```

A receiving device decrypts by selecting its own recipient index:

```c
ret = wc_CoseEncrypt_Decrypt(&myRecipient, /*recipientIndex=*/1,
                             in, inLen,
                             NULL, 0, NULL, 0,
                             scratch, sizeof(scratch),
                             &hdr, plaintext, sizeof(plaintext), &plaintextLen);
```

## COSE_Mac0 — single-recipient MAC (RFC 9052 Sec. 6.2)

Direct MAC over a payload using a pre-shared key.

```c
ret = wc_CoseMac0_Create(&hmacKey, WOLFCOSE_ALG_HMAC_256_256,
                         payload, payloadLen,
                         NULL, 0, NULL, 0,
                         scratch, sizeof(scratch),
                         out, sizeof(out), &outLen);
```

## COSE_Mac — multi-recipient MAC (RFC 9052 Sec. 6.1)

`COSE_Mac` carries one MAC tag plus per-recipient envelopes describing how each recipient learns the MAC key. Useful for group broadcast scenarios where every subscriber needs to authenticate the same payload but holds a different KEK.

```c
WOLFCOSE_RECIPIENT subscribers[N] = { /* one entry per group member */ };

ret = wc_CoseMac_Create(subscribers, N,
                        WOLFCOSE_ALG_HMAC_256_256,
                        payload, payloadLen,
                        NULL, 0, NULL, 0,
                        scratch, sizeof(scratch),
                        out, sizeof(out), &outLen);
```

## Detached payloads

Every `Sign*`, `Encrypt*`, and `Mac*` API accepts a detached payload — the COSE message stores only the signature/MAC/ciphertext and a `nil` payload field, while the actual bytes live elsewhere. This is essential when signing large objects (firmware, OTA images) where you don't want to copy the payload through the COSE buffer. Pass the payload via the `detachedPayload` / `detachedLen` arguments instead of `payload` / `payloadLen`, and the same on verify.

## Compile-time stripping

You only pay for the message types you use. Define the appropriate `WOLFCOSE_NO_*` macros to strip unused code paths:

```c
-DWOLFCOSE_NO_SIGN     -DWOLFCOSE_NO_ENCRYPT  -DWOLFCOSE_NO_MAC   /* multi-actor only */
-DWOLFCOSE_NO_ENCRYPT0 -DWOLFCOSE_NO_MAC0                          /* sign-only build */
-DWOLFCOSE_NO_SIGN1_SIGN -DWOLFCOSE_NO_CBOR_ENCODE                 /* verify-only build */
```

A minimal Sign1-verify-only build is around **7.5 KB of `.text`**, including the built-in CBOR engine.

## See also

- [[Algorithms]] — full algorithm list with COSE IDs and wolfCrypt guards
- [[API Reference]] — function signatures, structures, and error codes
- [[Macros]] — every `WOLFCOSE_*` and `WOLFCOSE_NO_*` compile-time toggle
- [`examples/scenarios/`](https://github.com/aidangarske/wolfCOSE/tree/master/examples/scenarios) — `multi_party_approval.c`, `iot_fleet_config.c`, `group_broadcast_mac.c` show real multi-actor flows
