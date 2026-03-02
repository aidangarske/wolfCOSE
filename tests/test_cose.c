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
#ifdef HAVE_ED448
    #include <wolfssl/wolfcrypt/ed448.h>
#endif
#ifdef HAVE_DILITHIUM
    #include <wolfssl/wolfcrypt/dilithium.h>
#endif
#ifdef WC_RSA_PSS
    #include <wolfssl/wolfcrypt/rsa.h>
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

#ifdef HAVE_ED448
static void test_cose_sign1_ed448(void)
{
    WOLFCOSE_KEY signKey;
    ed448_key edKey;
    WC_RNG rng;
    int ret;
    uint8_t payload[] = "Ed448 payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Sign1 Ed448]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) { TEST_ASSERT(0, "rng init"); return; }

    wc_ed448_init(&edKey);
    ret = wc_ed448_make_key(&rng, ED448_KEY_SIZE, &edKey);
    if (ret != 0) { TEST_ASSERT(0, "ed448 keygen"); goto done_ed448; }

    wc_CoseKey_Init(&signKey);
    wc_CoseKey_SetEd448(&signKey, &edKey);

    /* Sign */
    ret = wc_CoseSign1_Sign(&signKey, WOLFCOSE_ALG_EDDSA,
        NULL, 0,
        payload, sizeof(payload) - 1,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret == 0 && outLen > 0, "sign1 ed448 sign");

    /* Verify */
    ret = wc_CoseSign1_Verify(&signKey, out, outLen,
        NULL, 0, scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "sign1 ed448 verify");
    TEST_ASSERT(decPayloadLen == sizeof(payload) - 1 &&
                memcmp(decPayload, payload, decPayloadLen) == 0,
                "sign1 ed448 payload match");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_EDDSA, "sign1 ed448 hdr alg");

    /* Wrong key should fail */
    {
        ed448_key edWrong;
        WOLFCOSE_KEY wrongKey;
        wc_ed448_init(&edWrong);
        ret = wc_ed448_make_key(&rng, ED448_KEY_SIZE, &edWrong);
        if (ret == 0) {
            wc_CoseKey_Init(&wrongKey);
            wc_CoseKey_SetEd448(&wrongKey, &edWrong);
            ret = wc_CoseSign1_Verify(&wrongKey, out, outLen,
                NULL, 0, scratch, sizeof(scratch),
                &hdr, &decPayload, &decPayloadLen);
            TEST_ASSERT(ret != 0, "sign1 ed448 wrong key fails");
        }
        wc_ed448_free(&edWrong);
    }

    /* Key encode/decode round-trip */
    {
        uint8_t keyBuf[256];
        size_t keyLen = 0;
        WOLFCOSE_KEY decKey;
        ed448_key decEdKey;

        ret = wc_CoseKey_Encode(&signKey, keyBuf, sizeof(keyBuf), &keyLen);
        TEST_ASSERT(ret == 0 && keyLen > 0, "key ed448 encode");

        wc_ed448_init(&decEdKey);
        wc_CoseKey_Init(&decKey);
        decKey.key.ed448 = &decEdKey;
        ret = wc_CoseKey_Decode(&decKey, keyBuf, keyLen);
        TEST_ASSERT(ret == 0 && decKey.kty == WOLFCOSE_KTY_OKP &&
                    decKey.crv == WOLFCOSE_CRV_ED448, "key ed448 decode");
        wc_ed448_free(&decEdKey);
    }

done_ed448:
    wc_ed448_free(&edKey);
    wc_FreeRng(&rng);
}
#endif /* HAVE_ED448 */

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
 * COSE_Encrypt0 ChaCha20-Poly1305 tests
 * --------------------------------------------------------------------------- */
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
static void test_cose_encrypt0_chacha20(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[WOLFCOSE_CHACHA_KEY_SZ] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    uint8_t iv[WOLFCOSE_CHACHA_NONCE_SZ] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66
    };
    uint8_t payload[] = "ChaCha20-Poly1305 test payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Encrypt0 ChaCha20-Poly1305]\n");

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));

    /* Encrypt */
    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_CHACHA20_POLY1305,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "enc0 chacha20 encrypt");

    /* Decrypt */
    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "enc0 chacha20 decrypt");
    TEST_ASSERT(plaintextLen == sizeof(payload) - 1 &&
                memcmp(plaintext, payload, plaintextLen) == 0,
                "enc0 chacha20 payload match");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_CHACHA20_POLY1305,
                "enc0 chacha20 hdr alg");

    /* Tampered ciphertext should fail */
    {
        uint8_t tampered[512];
        memcpy(tampered, out, outLen);
        if (outLen > 20) {
            tampered[outLen - 5] ^= 0xFF;
        }
        ret = wc_CoseEncrypt0_Decrypt(&key, tampered, outLen,
            NULL, 0, scratch, sizeof(scratch), &hdr,
            plaintext, sizeof(plaintext), &plaintextLen);
        TEST_ASSERT(ret != 0, "enc0 chacha20 tampered fails");
    }

    /* Wrong key length should fail */
    {
        WOLFCOSE_KEY shortKey;
        uint8_t shortData[16] = {0};
        wc_CoseKey_Init(&shortKey);
        wc_CoseKey_SetSymmetric(&shortKey, shortData, sizeof(shortData));
        ret = wc_CoseEncrypt0_Encrypt(&shortKey,
            WOLFCOSE_ALG_CHACHA20_POLY1305,
            iv, sizeof(iv), payload, sizeof(payload), NULL, 0,
            scratch, sizeof(scratch), out, sizeof(out), &outLen);
        TEST_ASSERT(ret == WOLFCOSE_E_COSE_KEY_TYPE,
                    "enc0 chacha20 wrong key len");
    }
}
#endif /* HAVE_CHACHA && HAVE_POLY1305 */

/* ---------------------------------------------------------------------------
 * COSE_Encrypt0 AES-CCM tests
 * --------------------------------------------------------------------------- */
#ifdef HAVE_AESCCM
static void test_cose_encrypt0_aes_ccm(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData16[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    uint8_t nonce13[13] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66, 0x77
    };
    uint8_t nonce7[7] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11
    };
    uint8_t payload[] = "AES-CCM test payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Encrypt0 AES-CCM]\n");

    /* --- AES-CCM-16-128-128: key=16, nonce=13, tag=16 --- */
    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, keyData16, sizeof(keyData16));

    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_AES_CCM_16_128_128,
        nonce13, sizeof(nonce13),
        payload, sizeof(payload) - 1,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "enc0 ccm-16-128-128 encrypt");

    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "enc0 ccm-16-128-128 decrypt");
    TEST_ASSERT(plaintextLen == sizeof(payload) - 1 &&
                memcmp(plaintext, payload, plaintextLen) == 0,
                "enc0 ccm-16-128-128 payload match");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_AES_CCM_16_128_128,
                "enc0 ccm-16-128-128 hdr alg");

    /* Tampered ciphertext should fail */
    {
        uint8_t tampered[512];
        memcpy(tampered, out, outLen);
        if (outLen > 20) {
            tampered[outLen - 5] ^= 0xFF;
        }
        ret = wc_CoseEncrypt0_Decrypt(&key, tampered, outLen,
            NULL, 0, scratch, sizeof(scratch), &hdr,
            plaintext, sizeof(plaintext), &plaintextLen);
        TEST_ASSERT(ret != 0, "enc0 ccm-16-128-128 tampered fails");
    }

    /* --- AES-CCM-16-64-128: key=16, nonce=13, tag=8 --- */
    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_AES_CCM_16_64_128,
        nonce13, sizeof(nonce13),
        payload, sizeof(payload) - 1,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "enc0 ccm-16-64-128 encrypt");

    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "enc0 ccm-16-64-128 decrypt");
    TEST_ASSERT(plaintextLen == sizeof(payload) - 1 &&
                memcmp(plaintext, payload, plaintextLen) == 0,
                "enc0 ccm-16-64-128 payload match");

    /* --- AES-CCM-64-128-128: key=16, nonce=7, tag=16 --- */
    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_AES_CCM_64_128_128,
        nonce7, sizeof(nonce7),
        payload, sizeof(payload) - 1,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "enc0 ccm-64-128-128 encrypt");

    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "enc0 ccm-64-128-128 decrypt");
    TEST_ASSERT(plaintextLen == sizeof(payload) - 1 &&
                memcmp(plaintext, payload, plaintextLen) == 0,
                "enc0 ccm-64-128-128 payload match");
}
#endif /* HAVE_AESCCM */

/* ---------------------------------------------------------------------------
 * COSE_Sign1 RSA-PSS tests
 * --------------------------------------------------------------------------- */
#ifdef WC_RSA_PSS
static void test_cose_sign1_pss(const char* label, int32_t alg)
{
    WOLFCOSE_KEY signKey;
    RsaKey rsaKey;
    WC_RNG rng;
    int ret;
    uint8_t payload[] = "RSA-PSS payload";
    uint8_t scratch[1024];
    uint8_t out[1024];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Sign1 %s]\n", label);

    ret = wc_InitRng(&rng);
    if (ret != 0) { TEST_ASSERT(0, "rng init"); return; }

    ret = wc_InitRsaKey(&rsaKey, NULL);
    if (ret != 0) { TEST_ASSERT(0, "rsa init"); wc_FreeRng(&rng); return; }

    ret = wc_MakeRsaKey(&rsaKey, 2048, WC_RSA_EXPONENT, &rng);
    if (ret != 0) { TEST_ASSERT(0, "rsa keygen"); goto done_pss; }

    wc_CoseKey_Init(&signKey);
    wc_CoseKey_SetRsa(&signKey, &rsaKey);

    /* Sign */
    ret = wc_CoseSign1_Sign(&signKey, alg,
        NULL, 0,
        payload, sizeof(payload) - 1,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret == 0 && outLen > 0, "sign1 pss sign");

    /* Verify */
    ret = wc_CoseSign1_Verify(&signKey, out, outLen,
        NULL, 0, scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "sign1 pss verify");
    TEST_ASSERT(decPayloadLen == sizeof(payload) - 1 &&
                memcmp(decPayload, payload, decPayloadLen) == 0,
                "sign1 pss payload match");
    TEST_ASSERT(hdr.alg == alg, "sign1 pss hdr alg");

    /* Wrong key should fail */
    {
        RsaKey rsaWrong;
        WOLFCOSE_KEY wrongKey;
        wc_InitRsaKey(&rsaWrong, NULL);
        ret = wc_MakeRsaKey(&rsaWrong, 2048, WC_RSA_EXPONENT, &rng);
        if (ret == 0) {
            wc_CoseKey_Init(&wrongKey);
            wc_CoseKey_SetRsa(&wrongKey, &rsaWrong);
            ret = wc_CoseSign1_Verify(&wrongKey, out, outLen,
                NULL, 0, scratch, sizeof(scratch),
                &hdr, &decPayload, &decPayloadLen);
            TEST_ASSERT(ret != 0, "sign1 pss wrong key fails");
        }
        wc_FreeRsaKey(&rsaWrong);
    }

done_pss:
    wc_FreeRsaKey(&rsaKey);
    wc_FreeRng(&rng);
}
#endif /* WC_RSA_PSS */

/* ---------------------------------------------------------------------------
 * COSE_Sign1 ML-DSA (Dilithium) tests
 * --------------------------------------------------------------------------- */
#ifdef HAVE_DILITHIUM
static void test_cose_sign1_ml_dsa(const char* label, int32_t alg, byte level)
{
    WOLFCOSE_KEY signKey;
    dilithium_key dlKey;
    WC_RNG rng;
    int ret;
    uint8_t payload[] = "ML-DSA payload";
    uint8_t scratch[8192];
    uint8_t out[8192];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Sign1 %s]\n", label);

    ret = wc_InitRng(&rng);
    if (ret != 0) { TEST_ASSERT(0, "rng init"); return; }

    ret = wc_dilithium_init(&dlKey);
    if (ret != 0) { TEST_ASSERT(0, "dl init"); wc_FreeRng(&rng); return; }

    ret = wc_dilithium_set_level(&dlKey, level);
    if (ret != 0) { TEST_ASSERT(0, "dl set level"); goto done_mldsa; }

    ret = wc_dilithium_make_key(&dlKey, &rng);
    if (ret != 0) { TEST_ASSERT(0, "dl keygen"); goto done_mldsa; }

    wc_CoseKey_Init(&signKey);
    wc_CoseKey_SetDilithium(&signKey, alg, &dlKey);

    /* Sign */
    ret = wc_CoseSign1_Sign(&signKey, alg,
        NULL, 0,
        payload, sizeof(payload) - 1,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret == 0 && outLen > 0, "sign1 ml-dsa sign");

    /* Verify */
    ret = wc_CoseSign1_Verify(&signKey, out, outLen,
        NULL, 0, scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "sign1 ml-dsa verify");
    TEST_ASSERT(decPayloadLen == sizeof(payload) - 1 &&
                memcmp(decPayload, payload, decPayloadLen) == 0,
                "sign1 ml-dsa payload match");
    TEST_ASSERT(hdr.alg == alg, "sign1 ml-dsa hdr alg");

    /* Wrong key should fail */
    {
        dilithium_key dlWrong;
        WOLFCOSE_KEY wrongKey;
        wc_dilithium_init(&dlWrong);
        wc_dilithium_set_level(&dlWrong, level);
        ret = wc_dilithium_make_key(&dlWrong, &rng);
        if (ret == 0) {
            wc_CoseKey_Init(&wrongKey);
            wc_CoseKey_SetDilithium(&wrongKey, alg, &dlWrong);
            ret = wc_CoseSign1_Verify(&wrongKey, out, outLen,
                NULL, 0, scratch, sizeof(scratch),
                &hdr, &decPayload, &decPayloadLen);
            TEST_ASSERT(ret != 0, "sign1 ml-dsa wrong key fails");
        }
        wc_dilithium_free(&dlWrong);
    }

done_mldsa:
    wc_dilithium_free(&dlKey);
    wc_FreeRng(&rng);
}
#endif /* HAVE_DILITHIUM */

/* ---------------------------------------------------------------------------
 * COSE_Mac0 tests
 * --------------------------------------------------------------------------- */
#if !defined(NO_HMAC)
static void test_cose_mac0_hmac256(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    uint8_t payload[] = "Mac0 HMAC-256 test";
    uint8_t kid[] = "hmac-key-1";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Mac0 HMAC-256]\n");

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));

    /* Create */
    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC256,
        kid, sizeof(kid) - 1,
        payload, sizeof(payload) - 1,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "mac0 hmac256 create");

    /* Verify */
    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0, scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "mac0 hmac256 verify");
    TEST_ASSERT(decPayloadLen == sizeof(payload) - 1 &&
                memcmp(decPayload, payload, decPayloadLen) == 0,
                "mac0 hmac256 payload match");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_HMAC256, "mac0 hmac256 hdr alg");
    TEST_ASSERT(hdr.kidLen == sizeof(kid) - 1 &&
                memcmp(hdr.kid, kid, hdr.kidLen) == 0,
                "mac0 hmac256 hdr kid");

    /* Wrong key should fail */
    {
        WOLFCOSE_KEY wrongKey;
        uint8_t wrongData[32] = {0xFF};
        wc_CoseKey_Init(&wrongKey);
        wc_CoseKey_SetSymmetric(&wrongKey, wrongData, sizeof(wrongData));
        ret = wc_CoseMac0_Verify(&wrongKey, out, outLen,
            NULL, 0, scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == WOLFCOSE_E_COSE_MAC_FAIL,
                    "mac0 hmac256 wrong key fails");
    }

    /* Tampered payload should fail */
    {
        uint8_t tampered[512];
        memcpy(tampered, out, outLen);
        if (outLen > 20) {
            tampered[outLen / 2] ^= 0xFF;
        }
        ret = wc_CoseMac0_Verify(&key, tampered, outLen,
            NULL, 0, scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret != 0, "mac0 hmac256 tampered fails");
    }

    /* Error: null args */
    ret = wc_CoseMac0_Create(NULL, WOLFCOSE_ALG_HMAC256, NULL, 0,
        payload, sizeof(payload), NULL, 0,
        scratch, sizeof(scratch), out, sizeof(out), &outLen);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "mac0 null key");
}

#ifdef WOLFSSL_SHA384
static void test_cose_mac0_hmac384(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[48];
    uint8_t payload[] = "Mac0 HMAC-384 test";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Mac0 HMAC-384]\n");

    memset(keyData, 0xAB, sizeof(keyData));
    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));

    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC384,
        NULL, 0,
        payload, sizeof(payload) - 1,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "mac0 hmac384 create");

    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0, scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "mac0 hmac384 verify");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_HMAC384, "mac0 hmac384 hdr alg");
}
#endif /* WOLFSSL_SHA384 */

#ifdef WOLFSSL_SHA512
static void test_cose_mac0_hmac512(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[64];
    uint8_t payload[] = "Mac0 HMAC-512 test";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Mac0 HMAC-512]\n");

    memset(keyData, 0xCD, sizeof(keyData));
    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));

    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC512,
        NULL, 0,
        payload, sizeof(payload) - 1,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "mac0 hmac512 create");

    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0, scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "mac0 hmac512 verify");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_HMAC512, "mac0 hmac512 hdr alg");
}
#endif /* WOLFSSL_SHA512 */
#endif /* !NO_HMAC */

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
#ifdef HAVE_ED448
    test_cose_sign1_ed448();
#endif

#ifdef HAVE_AESGCM
    test_cose_encrypt0_a128gcm();
    test_cose_encrypt0_a256gcm();
    test_cose_encrypt0_with_aad();
#endif

#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    test_cose_encrypt0_chacha20();
#endif

#ifdef HAVE_AESCCM
    test_cose_encrypt0_aes_ccm();
#endif

#ifdef WC_RSA_PSS
    test_cose_sign1_pss("PS256", WOLFCOSE_ALG_PS256);
    test_cose_sign1_pss("PS384", WOLFCOSE_ALG_PS384);
    test_cose_sign1_pss("PS512", WOLFCOSE_ALG_PS512);
#endif

#ifdef HAVE_DILITHIUM
    test_cose_sign1_ml_dsa("ML-DSA-44", WOLFCOSE_ALG_ML_DSA_44, 2);
    test_cose_sign1_ml_dsa("ML-DSA-65", WOLFCOSE_ALG_ML_DSA_65, 3);
    test_cose_sign1_ml_dsa("ML-DSA-87", WOLFCOSE_ALG_ML_DSA_87, 5);
#endif

#if !defined(NO_HMAC)
    test_cose_mac0_hmac256();
#ifdef WOLFSSL_SHA384
    test_cose_mac0_hmac384();
#endif
#ifdef WOLFSSL_SHA512
    test_cose_mac0_hmac512();
#endif
#endif /* !NO_HMAC */

    printf("  COSE: %d failure(s)\n", g_failures);
    return g_failures;
}
