/* test_cose.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfCOSE.
 *
 * wolfCOSE is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfCOSE is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/**
 * COSE Sign1/Encrypt0/Key tests. Covers:
 * - COSE_Key init/free/set for ECC, Ed25519, symmetric
 * - COSE_Key encode/decode round-trip
 * - COSE_Sign1 sign/verify round-trip (ES256, EdDSA)
 * - COSE_Sign1 wrong key fails, tampered payload fails
 * - COSE_Encrypt0 encrypt/decrypt round-trip (A128GCM, A256GCM)
 * - COSE_Encrypt0 tampered ciphertext fails
 * - Header parsing: alg, kid, IV extracted correctly
 * - Error paths: null args, wrong key type, bad alg
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfcose/wolfcose.h>
#include <wolfssl/wolfcrypt/random.h>
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifdef HAVE_ED25519
    #include <wolfssl/wolfcrypt/ed25519.h>
#endif
#ifdef HAVE_AESGCM
    #include <wolfssl/wolfcrypt/aes.h>
#endif
#include <stdio.h>
#include <string.h>

static int g_failures = 0;

#define TEST_ASSERT(cond, name) do {                           \
    if (!(cond)) {                                             \
        printf("  FAIL: %s (line %d)\n", (name), __LINE__);   \
        g_failures++;                                          \
    } else {                                                   \
        printf("  PASS: %s\n", (name));                        \
    }                                                          \
} while (0)

/* ---------------------------------------------------------------------------
 * COSE Key API tests
 * --------------------------------------------------------------------------- */
static void test_cose_key_init(void)
{
    WOLFCOSE_KEY key;
    int ret;

    printf("  [Key Init/Free]\n");

    ret = wc_CoseKey_Init(&key);
    TEST_ASSERT(ret == 0 && key.kty == 0 && key.alg == 0 &&
                key.hasPrivate == 0, "key init zeroed");

    ret = wc_CoseKey_Init(NULL);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "key init null");

    wc_CoseKey_Free(&key);
    TEST_ASSERT(key.kty == 0, "key free zeroes");

    wc_CoseKey_Free(NULL); /* should not crash */
    TEST_ASSERT(1, "key free null safe");
}

#ifdef HAVE_ECC
static void test_cose_key_ecc(void)
{
    WOLFCOSE_KEY key;
    ecc_key eccKey;
    WC_RNG rng;
    int ret;

    printf("  [Key ECC]\n");

    ret = wc_InitRng(&rng);
    TEST_ASSERT(ret == 0, "rng init");
    if (ret != 0) return;

    ret = wc_ecc_init(&eccKey);
    TEST_ASSERT(ret == 0, "ecc init");
    if (ret != 0) { wc_FreeRng(&rng); return; }

    ret = wc_ecc_make_key(&rng, 32, &eccKey);
    TEST_ASSERT(ret == 0, "ecc keygen P-256");
    if (ret != 0) { wc_ecc_free(&eccKey); wc_FreeRng(&rng); return; }

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &eccKey);
    TEST_ASSERT(ret == 0 && key.kty == WOLFCOSE_KTY_EC2 &&
                key.crv == WOLFCOSE_CRV_P256 && key.hasPrivate == 1,
                "key set ecc");

    ret = wc_CoseKey_SetEcc(NULL, WOLFCOSE_CRV_P256, &eccKey);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "key set ecc null key");

    ret = wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, NULL);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "key set ecc null ecckey");

    /* Encode/decode round-trip */
    {
        uint8_t cbuf[256];
        size_t cLen = 0;
        WOLFCOSE_KEY key2;
        ecc_key eccKey2;

        ret = wc_CoseKey_Encode(&key, cbuf, sizeof(cbuf), &cLen);
        TEST_ASSERT(ret == 0 && cLen > 0, "key ecc encode");

        wc_ecc_init(&eccKey2);
        wc_CoseKey_Init(&key2);
        key2.key.ecc = &eccKey2;
        ret = wc_CoseKey_Decode(&key2, cbuf, cLen);
        TEST_ASSERT(ret == 0 && key2.kty == WOLFCOSE_KTY_EC2 &&
                    key2.crv == WOLFCOSE_CRV_P256 && key2.hasPrivate == 1,
                    "key ecc decode");
        wc_ecc_free(&eccKey2);
    }

    wc_CoseKey_Free(&key);
    wc_ecc_free(&eccKey);
    wc_FreeRng(&rng);
}
#endif /* HAVE_ECC */

#ifdef HAVE_ED25519
static void test_cose_key_ed25519(void)
{
    WOLFCOSE_KEY key;
    ed25519_key edKey;
    WC_RNG rng;
    int ret;

    printf("  [Key Ed25519]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) { TEST_ASSERT(0, "rng init"); return; }

    ret = wc_ed25519_init(&edKey);
    if (ret != 0) { TEST_ASSERT(0, "ed init"); wc_FreeRng(&rng); return; }

    ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &edKey);
    TEST_ASSERT(ret == 0, "ed keygen");
    if (ret != 0) { wc_ed25519_free(&edKey); wc_FreeRng(&rng); return; }

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetEd25519(&key, &edKey);
    TEST_ASSERT(ret == 0 && key.kty == WOLFCOSE_KTY_OKP &&
                key.crv == WOLFCOSE_CRV_ED25519 && key.hasPrivate == 1,
                "key set ed25519");

    /* Encode/decode round-trip */
    {
        uint8_t cbuf[256];
        size_t cLen = 0;
        WOLFCOSE_KEY key2;
        ed25519_key edKey2;

        ret = wc_CoseKey_Encode(&key, cbuf, sizeof(cbuf), &cLen);
        TEST_ASSERT(ret == 0 && cLen > 0, "key ed encode");

        wc_ed25519_init(&edKey2);
        wc_CoseKey_Init(&key2);
        key2.key.ed25519 = &edKey2;
        ret = wc_CoseKey_Decode(&key2, cbuf, cLen);
        TEST_ASSERT(ret == 0 && key2.kty == WOLFCOSE_KTY_OKP &&
                    key2.hasPrivate == 1,
                    "key ed decode");
        wc_ed25519_free(&edKey2);
    }

    wc_CoseKey_Free(&key);
    wc_ed25519_free(&edKey);
    wc_FreeRng(&rng);
}
#endif /* HAVE_ED25519 */

static void test_cose_key_symmetric(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    int ret;

    printf("  [Key Symmetric]\n");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));
    TEST_ASSERT(ret == 0 && key.kty == WOLFCOSE_KTY_SYMMETRIC &&
                key.hasPrivate == 1, "key set symmetric");

    ret = wc_CoseKey_SetSymmetric(NULL, keyData, sizeof(keyData));
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "key set symm null");

    ret = wc_CoseKey_SetSymmetric(&key, NULL, 16);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "key set symm null data");

    ret = wc_CoseKey_SetSymmetric(&key, keyData, 0);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "key set symm zero len");

    /* Encode/decode round-trip */
    {
        uint8_t cbuf[64];
        size_t cLen = 0;
        WOLFCOSE_KEY key2;

        wc_CoseKey_Init(&key);
        wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));

        ret = wc_CoseKey_Encode(&key, cbuf, sizeof(cbuf), &cLen);
        TEST_ASSERT(ret == 0 && cLen > 0, "key symm encode");

        wc_CoseKey_Init(&key2);
        key2.kty = WOLFCOSE_KTY_SYMMETRIC; /* hint for decoder */
        ret = wc_CoseKey_Decode(&key2, cbuf, cLen);
        TEST_ASSERT(ret == 0 && key2.kty == WOLFCOSE_KTY_SYMMETRIC &&
                    key2.key.symm.keyLen == 16 &&
                    memcmp(key2.key.symm.key, keyData, 16) == 0,
                    "key symm decode");
    }

    wc_CoseKey_Free(&key);
}

/* ---------------------------------------------------------------------------
 * COSE_Sign1 tests
 * --------------------------------------------------------------------------- */
#ifdef HAVE_ECC
static void test_cose_sign1_es256(void)
{
    WOLFCOSE_KEY signKey, verifyKey;
    ecc_key eccSign;
    WC_RNG rng;
    int ret;
    uint8_t payload[] = "Hello wolfCOSE!";
    uint8_t kid[] = "key-1";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Sign1 ES256]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) { TEST_ASSERT(0, "rng init"); return; }

    /* Generate signing key */
    wc_ecc_init(&eccSign);
    ret = wc_ecc_make_key(&rng, 32, &eccSign);
    if (ret != 0) { TEST_ASSERT(0, "sign keygen"); goto done_es256; }

    wc_CoseKey_Init(&signKey);
    wc_CoseKey_SetEcc(&signKey, WOLFCOSE_CRV_P256, &eccSign);

    /* Sign */
    ret = wc_CoseSign1_Sign(&signKey, WOLFCOSE_ALG_ES256,
        kid, sizeof(kid) - 1,
        payload, sizeof(payload) - 1,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret == 0 && outLen > 0, "sign1 es256 sign");

    /* Verify with same key */
    wc_CoseKey_Init(&verifyKey);
    wc_CoseKey_SetEcc(&verifyKey, WOLFCOSE_CRV_P256, &eccSign);

    ret = wc_CoseSign1_Verify(&verifyKey, out, outLen,
        NULL, 0, scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "sign1 es256 verify");
    TEST_ASSERT(decPayloadLen == sizeof(payload) - 1 &&
                memcmp(decPayload, payload, decPayloadLen) == 0,
                "sign1 es256 payload match");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_ES256, "sign1 es256 hdr alg");
    TEST_ASSERT(hdr.kidLen == sizeof(kid) - 1 &&
                memcmp(hdr.kid, kid, hdr.kidLen) == 0,
                "sign1 es256 hdr kid");

    /* Verify with wrong key should fail */
    {
        ecc_key eccWrong;
        WOLFCOSE_KEY wrongKey;
        wc_ecc_init(&eccWrong);
        ret = wc_ecc_make_key(&rng, 32, &eccWrong);
        if (ret == 0) {
            wc_CoseKey_Init(&wrongKey);
            wc_CoseKey_SetEcc(&wrongKey, WOLFCOSE_CRV_P256, &eccWrong);
            ret = wc_CoseSign1_Verify(&wrongKey, out, outLen,
                NULL, 0, scratch, sizeof(scratch),
                &hdr, &decPayload, &decPayloadLen);
            TEST_ASSERT(ret == WOLFCOSE_E_COSE_SIG_FAIL,
                        "sign1 es256 wrong key fails");
        }
        wc_ecc_free(&eccWrong);
    }

    /* Tamper with payload byte, verify should fail */
    {
        uint8_t tampered[512];
        memcpy(tampered, out, outLen);
        /* Find the payload inside the COSE message and flip a byte.
         * The payload is after protected+unprotected headers. Flip a byte
         * near the middle of the message. */
        if (outLen > 20) {
            tampered[outLen / 2] ^= 0xFF;
        }
        ret = wc_CoseSign1_Verify(&verifyKey, tampered, outLen,
            NULL, 0, scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret != 0, "sign1 es256 tampered fails");
    }

    /* Error: null args */
    ret = wc_CoseSign1_Sign(NULL, WOLFCOSE_ALG_ES256, NULL, 0,
        payload, sizeof(payload), NULL, 0,
        scratch, sizeof(scratch), out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "sign1 null key");

    ret = wc_CoseSign1_Verify(NULL, out, outLen, NULL, 0,
        scratch, sizeof(scratch), &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "verify null key");

    /* Error: no private key */
    {
        WOLFCOSE_KEY pubOnly;
        wc_CoseKey_Init(&pubOnly);
        pubOnly.kty = WOLFCOSE_KTY_EC2;
        pubOnly.hasPrivate = 0;
        pubOnly.key.ecc = &eccSign;
        ret = wc_CoseSign1_Sign(&pubOnly, WOLFCOSE_ALG_ES256, NULL, 0,
            payload, sizeof(payload), NULL, 0,
            scratch, sizeof(scratch), out, sizeof(out), &outLen, &rng);
        TEST_ASSERT(ret == WOLFCOSE_E_COSE_KEY_TYPE, "sign1 no privkey");
    }

done_es256:
    wc_ecc_free(&eccSign);
    wc_FreeRng(&rng);
}
#endif /* HAVE_ECC */

#ifdef HAVE_ED25519
static void test_cose_sign1_eddsa(void)
{
    WOLFCOSE_KEY signKey;
    ed25519_key edKey;
    WC_RNG rng;
    int ret;
    uint8_t payload[] = "EdDSA payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Sign1 EdDSA]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) { TEST_ASSERT(0, "rng init"); return; }

    wc_ed25519_init(&edKey);
    ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &edKey);
    if (ret != 0) { TEST_ASSERT(0, "ed keygen"); goto done_eddsa; }

    wc_CoseKey_Init(&signKey);
    wc_CoseKey_SetEd25519(&signKey, &edKey);

    /* Sign */
    ret = wc_CoseSign1_Sign(&signKey, WOLFCOSE_ALG_EDDSA,
        NULL, 0,
        payload, sizeof(payload) - 1,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret == 0 && outLen > 0, "sign1 eddsa sign");

    /* Verify */
    ret = wc_CoseSign1_Verify(&signKey, out, outLen,
        NULL, 0, scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "sign1 eddsa verify");
    TEST_ASSERT(decPayloadLen == sizeof(payload) - 1 &&
                memcmp(decPayload, payload, decPayloadLen) == 0,
                "sign1 eddsa payload match");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_EDDSA, "sign1 eddsa hdr alg");

    /* Wrong key should fail */
    {
        ed25519_key edWrong;
        WOLFCOSE_KEY wrongKey;
        wc_ed25519_init(&edWrong);
        ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &edWrong);
        if (ret == 0) {
            wc_CoseKey_Init(&wrongKey);
            wc_CoseKey_SetEd25519(&wrongKey, &edWrong);
            ret = wc_CoseSign1_Verify(&wrongKey, out, outLen,
                NULL, 0, scratch, sizeof(scratch),
                &hdr, &decPayload, &decPayloadLen);
            TEST_ASSERT(ret != 0, "sign1 eddsa wrong key fails");
        }
        wc_ed25519_free(&edWrong);
    }

done_eddsa:
    wc_ed25519_free(&edKey);
    wc_FreeRng(&rng);
}
#endif /* HAVE_ED25519 */

/* ---------------------------------------------------------------------------
 * COSE_Encrypt0 tests
 * --------------------------------------------------------------------------- */
#ifdef HAVE_AESGCM
static void test_cose_encrypt0_a128gcm(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[16] = {
        0x84, 0x9B, 0x57, 0x21, 0x9D, 0xAE, 0x48, 0xDE,
        0x64, 0x6D, 0x07, 0xDB, 0xB5, 0x33, 0x56, 0x6E
    };
    uint8_t iv[12] = {
        0x02, 0xD1, 0xF7, 0xE6, 0xF2, 0x6C, 0x43, 0xD4,
        0x86, 0x8D, 0x87, 0xCE
    };
    uint8_t payload[] = "Encrypt0 test payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Encrypt0 A128GCM]\n");

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));

    /* Encrypt */
    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A128GCM,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "enc0 a128gcm encrypt");

    /* Decrypt */
    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "enc0 a128gcm decrypt");
    TEST_ASSERT(plaintextLen == sizeof(payload) - 1 &&
                memcmp(plaintext, payload, plaintextLen) == 0,
                "enc0 a128gcm payload match");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_A128GCM, "enc0 a128gcm hdr alg");
    TEST_ASSERT(hdr.ivLen == sizeof(iv), "enc0 a128gcm hdr iv");

    /* Tampered ciphertext should fail */
    {
        uint8_t tampered[512];
        memcpy(tampered, out, outLen);
        if (outLen > 20) {
            tampered[outLen - 5] ^= 0xFF; /* flip byte near end (in tag) */
        }
        ret = wc_CoseEncrypt0_Decrypt(&key, tampered, outLen,
            NULL, 0, scratch, sizeof(scratch), &hdr,
            plaintext, sizeof(plaintext), &plaintextLen);
        TEST_ASSERT(ret != 0, "enc0 a128gcm tampered fails");
    }

    /* Error: null args */
    ret = wc_CoseEncrypt0_Encrypt(NULL, WOLFCOSE_ALG_A128GCM,
        iv, sizeof(iv), payload, sizeof(payload), NULL, 0,
        scratch, sizeof(scratch), out, sizeof(out), &outLen);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "enc0 null key");

    /* Error: wrong key type */
    {
        WOLFCOSE_KEY badKey;
        wc_CoseKey_Init(&badKey);
        badKey.kty = WOLFCOSE_KTY_EC2;
        ret = wc_CoseEncrypt0_Encrypt(&badKey, WOLFCOSE_ALG_A128GCM,
            iv, sizeof(iv), payload, sizeof(payload), NULL, 0,
            scratch, sizeof(scratch), out, sizeof(out), &outLen);
        TEST_ASSERT(ret == WOLFCOSE_E_COSE_KEY_TYPE, "enc0 wrong key type");
    }

    /* Error: wrong key length */
    {
        WOLFCOSE_KEY shortKey;
        uint8_t shortData[8] = {0};
        wc_CoseKey_Init(&shortKey);
        wc_CoseKey_SetSymmetric(&shortKey, shortData, sizeof(shortData));
        ret = wc_CoseEncrypt0_Encrypt(&shortKey, WOLFCOSE_ALG_A128GCM,
            iv, sizeof(iv), payload, sizeof(payload), NULL, 0,
            scratch, sizeof(scratch), out, sizeof(out), &outLen);
        TEST_ASSERT(ret == WOLFCOSE_E_COSE_KEY_TYPE, "enc0 wrong key len");
    }
}

static void test_cose_encrypt0_a256gcm(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    uint8_t iv[12] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66
    };
    uint8_t payload[] = "A256GCM test data with more bytes";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Encrypt0 A256GCM]\n");

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));

    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A256GCM,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "enc0 a256gcm encrypt");

    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "enc0 a256gcm decrypt");
    TEST_ASSERT(plaintextLen == sizeof(payload) - 1 &&
                memcmp(plaintext, payload, plaintextLen) == 0,
                "enc0 a256gcm payload match");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_A256GCM, "enc0 a256gcm hdr alg");
}

static void test_cose_encrypt0_with_aad(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[16] = {
        0x84, 0x9B, 0x57, 0x21, 0x9D, 0xAE, 0x48, 0xDE,
        0x64, 0x6D, 0x07, 0xDB, 0xB5, 0x33, 0x56, 0x6E
    };
    uint8_t iv[12] = {
        0x02, 0xD1, 0xF7, 0xE6, 0xF2, 0x6C, 0x43, 0xD4,
        0x86, 0x8D, 0x87, 0xCE
    };
    uint8_t payload[] = "AAD test payload";
    uint8_t extAad[] = "external-aad-data";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Encrypt0 with external AAD]\n");

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));

    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A128GCM,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,
        extAad, sizeof(extAad) - 1,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "enc0 aad encrypt");

    /* Decrypt with correct AAD */
    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        extAad, sizeof(extAad) - 1,
        scratch, sizeof(scratch), &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0 && plaintextLen == sizeof(payload) - 1,
                "enc0 aad decrypt ok");

    /* Decrypt with wrong AAD should fail */
    {
        uint8_t wrongAad[] = "wrong-aad";
        ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
            wrongAad, sizeof(wrongAad) - 1,
            scratch, sizeof(scratch), &hdr,
            plaintext, sizeof(plaintext), &plaintextLen);
        TEST_ASSERT(ret != 0, "enc0 wrong aad fails");
    }

    /* Decrypt with no AAD should fail */
    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0,
        scratch, sizeof(scratch), &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret != 0, "enc0 missing aad fails");
}
#endif /* HAVE_AESGCM */

/* ---------------------------------------------------------------------------
 * COSE_Sign1 with external AAD
 * --------------------------------------------------------------------------- */
#ifdef HAVE_ECC
static void test_cose_sign1_with_aad(void)
{
    WOLFCOSE_KEY key;
    ecc_key eccKey;
    WC_RNG rng;
    int ret;
    uint8_t payload[] = "AAD sign test";
    uint8_t extAad[] = "sign-external-aad";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Sign1 with external AAD]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) { TEST_ASSERT(0, "rng init"); return; }

    wc_ecc_init(&eccKey);
    ret = wc_ecc_make_key(&rng, 32, &eccKey);
    if (ret != 0) { TEST_ASSERT(0, "keygen"); goto done_aad; }

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &eccKey);

    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256,
        NULL, 0,
        payload, sizeof(payload) - 1,
        extAad, sizeof(extAad) - 1,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret == 0, "sign1 aad sign");

    /* Verify with correct AAD */
    ret = wc_CoseSign1_Verify(&key, out, outLen,
        extAad, sizeof(extAad) - 1,
        scratch, sizeof(scratch), &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "sign1 aad verify ok");

    /* Verify with wrong AAD should fail */
    {
        uint8_t wrongAad[] = "wrong";
        ret = wc_CoseSign1_Verify(&key, out, outLen,
            wrongAad, sizeof(wrongAad) - 1,
            scratch, sizeof(scratch), &hdr,
            &decPayload, &decPayloadLen);
        TEST_ASSERT(ret != 0, "sign1 wrong aad fails");
    }

done_aad:
    wc_ecc_free(&eccKey);
    wc_FreeRng(&rng);
}
#endif

/* ---------------------------------------------------------------------------
 * Entry point
 * --------------------------------------------------------------------------- */
int test_cose(void)
{
    g_failures = 0;

    test_cose_key_init();
#ifdef HAVE_ECC
    test_cose_key_ecc();
#endif
#ifdef HAVE_ED25519
    test_cose_key_ed25519();
#endif
    test_cose_key_symmetric();

#ifdef HAVE_ECC
    test_cose_sign1_es256();
    test_cose_sign1_with_aad();
#endif
#ifdef HAVE_ED25519
    test_cose_sign1_eddsa();
#endif

#ifdef HAVE_AESGCM
    test_cose_encrypt0_a128gcm();
    test_cose_encrypt0_a256gcm();
    test_cose_encrypt0_with_aad();
#endif

    printf("  COSE: %d failure(s)\n", g_failures);
    return g_failures;
}
