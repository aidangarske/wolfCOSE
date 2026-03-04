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
static void test_cose_sign1_ecc(const char* label, int32_t alg, int32_t crv,
                                 int keySz)
{
    WOLFCOSE_KEY signKey;
    ecc_key eccKey;
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

    printf("  [Sign1 %s]\n", label);

    ret = wc_InitRng(&rng);
    if (ret != 0) { TEST_ASSERT(0, "rng init"); return; }

    wc_ecc_init(&eccKey);
    ret = wc_ecc_make_key(&rng, keySz, &eccKey);
    if (ret != 0) { TEST_ASSERT(0, "ecc keygen"); goto done_ecc; }

    wc_CoseKey_Init(&signKey);
    wc_CoseKey_SetEcc(&signKey, crv, &eccKey);

    /* Sign */
    ret = wc_CoseSign1_Sign(&signKey, alg,
        kid, sizeof(kid) - 1,
        payload, sizeof(payload) - 1,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret == 0 && outLen > 0, "sign1 ecc sign");

    /* Verify */
    ret = wc_CoseSign1_Verify(&signKey, out, outLen,
        NULL, 0, scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "sign1 ecc verify");
    TEST_ASSERT(decPayloadLen == sizeof(payload) - 1 &&
                memcmp(decPayload, payload, decPayloadLen) == 0,
                "sign1 ecc payload match");
    TEST_ASSERT(hdr.alg == alg, "sign1 ecc hdr alg");
    TEST_ASSERT(hdr.kidLen == sizeof(kid) - 1 &&
                memcmp(hdr.kid, kid, hdr.kidLen) == 0,
                "sign1 ecc hdr kid");

    /* Wrong key should fail */
    {
        ecc_key eccWrong;
        WOLFCOSE_KEY wrongKey;
        wc_ecc_init(&eccWrong);
        ret = wc_ecc_make_key(&rng, keySz, &eccWrong);
        if (ret == 0) {
            wc_CoseKey_Init(&wrongKey);
            wc_CoseKey_SetEcc(&wrongKey, crv, &eccWrong);
            ret = wc_CoseSign1_Verify(&wrongKey, out, outLen,
                NULL, 0, scratch, sizeof(scratch),
                &hdr, &decPayload, &decPayloadLen);
            TEST_ASSERT(ret != 0, "sign1 ecc wrong key fails");
        }
        wc_ecc_free(&eccWrong);
    }

    /* Tampered ciphertext should fail */
    {
        uint8_t tampered[512];
        memcpy(tampered, out, outLen);
        if (outLen > 20) {
            tampered[outLen / 2] ^= 0xFF;
        }
        ret = wc_CoseSign1_Verify(&signKey, tampered, outLen,
            NULL, 0, scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret != 0, "sign1 ecc tampered fails");
    }

    /* Error tests (only run once, for ES256) */
    if (alg == WOLFCOSE_ALG_ES256) {
        ret = wc_CoseSign1_Sign(NULL, WOLFCOSE_ALG_ES256, NULL, 0,
            payload, sizeof(payload), NULL, 0,
            scratch, sizeof(scratch), out, sizeof(out), &outLen, &rng);
        TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "sign1 null key");

        ret = wc_CoseSign1_Verify(NULL, out, outLen, NULL, 0,
            scratch, sizeof(scratch), &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "verify null key");

        {
            WOLFCOSE_KEY pubOnly;
            wc_CoseKey_Init(&pubOnly);
            pubOnly.kty = WOLFCOSE_KTY_EC2;
            pubOnly.hasPrivate = 0;
            pubOnly.key.ecc = &eccKey;
            ret = wc_CoseSign1_Sign(&pubOnly, WOLFCOSE_ALG_ES256, NULL, 0,
                payload, sizeof(payload), NULL, 0,
                scratch, sizeof(scratch), out, sizeof(out), &outLen, &rng);
            TEST_ASSERT(ret == WOLFCOSE_E_COSE_KEY_TYPE, "sign1 no privkey");
        }
    }

done_ecc:
    wc_ecc_free(&eccKey);
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
#if defined(WC_RSA_PSS) && defined(WOLFSSL_KEY_GEN)
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
#endif /* WC_RSA_PSS && WOLFSSL_KEY_GEN */

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
 * COSE_Key RSA encode/decode round-trip
 * --------------------------------------------------------------------------- */
#if defined(WC_RSA_PSS) && defined(WOLFSSL_KEY_GEN)
static void test_cose_key_rsa(void)
{
    WOLFCOSE_KEY key;
    RsaKey rsaKey;
    WC_RNG rng;
    int ret;

    printf("  [Key RSA]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) { TEST_ASSERT(0, "rng init"); return; }

    ret = wc_InitRsaKey(&rsaKey, NULL);
    if (ret != 0) { TEST_ASSERT(0, "rsa init"); wc_FreeRng(&rng); return; }

    ret = wc_MakeRsaKey(&rsaKey, 2048, 65537, &rng);
    TEST_ASSERT(ret == 0, "rsa keygen 2048");
    if (ret != 0) { wc_FreeRsaKey(&rsaKey); wc_FreeRng(&rng); return; }

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetRsa(&key, &rsaKey);
    TEST_ASSERT(ret == 0 && key.kty == WOLFCOSE_KTY_RSA &&
                key.hasPrivate == 1, "key set rsa");

    /* Encode/decode round-trip.
     * Buffer must be large enough for private key encoding scratch:
     * CBOR overhead + n + e + d + temporary p/q workspace. */
    {
        uint8_t cbuf[2048];
        size_t cLen = 0;
        WOLFCOSE_KEY key2;
        RsaKey rsaKey2;

        ret = wc_CoseKey_Encode(&key, cbuf, sizeof(cbuf), &cLen);
        TEST_ASSERT(ret == 0 && cLen > 0, "key rsa encode");

        wc_InitRsaKey(&rsaKey2, NULL);
        wc_CoseKey_Init(&key2);
        key2.key.rsa = &rsaKey2;
        ret = wc_CoseKey_Decode(&key2, cbuf, cLen);
        TEST_ASSERT(ret == 0 && key2.kty == WOLFCOSE_KTY_RSA,
                    "key rsa decode");

        /* Verify decoded key can sign/verify */
        {
            uint8_t payload[] = "RSA key round-trip";
            uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
            uint8_t out[512];
            size_t outLen = 0;
            const uint8_t* decPayload = NULL;
            size_t decPayloadLen = 0;
            WOLFCOSE_HDR hdr;

            /* Sign with original key */
            ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_PS256,
                NULL, 0, payload, sizeof(payload) - 1, NULL, 0,
                scratch, sizeof(scratch),
                out, sizeof(out), &outLen, &rng);
            TEST_ASSERT(ret == 0, "key rsa rt sign");

            /* Verify with decoded key (public only) */
            ret = wc_CoseSign1_Verify(&key2, out, outLen,
                NULL, 0, scratch, sizeof(scratch),
                &hdr, &decPayload, &decPayloadLen);
            TEST_ASSERT(ret == 0, "key rsa rt verify");
        }

        wc_FreeRsaKey(&rsaKey2);
    }

    wc_CoseKey_Free(&key);
    wc_FreeRsaKey(&rsaKey);
    wc_FreeRng(&rng);
}
#endif /* WC_RSA_PSS && WOLFSSL_KEY_GEN */

/* ---------------------------------------------------------------------------
 * COSE_Key Dilithium encode/decode round-trip
 * --------------------------------------------------------------------------- */
#ifdef HAVE_DILITHIUM
static void test_cose_key_dilithium(const char* label, int32_t alg,
                                      int level)
{
    WOLFCOSE_KEY key;
    dilithium_key dlKey;
    WC_RNG rng;
    int ret;

    printf("  [Key %s]\n", label);

    ret = wc_InitRng(&rng);
    if (ret != 0) { TEST_ASSERT(0, "rng init"); return; }

    ret = wc_dilithium_init(&dlKey);
    if (ret != 0) { TEST_ASSERT(0, "dl init"); wc_FreeRng(&rng); return; }

    ret = wc_dilithium_set_level(&dlKey, (byte)level);
    if (ret != 0) {
        TEST_ASSERT(0, "dl set level");
        wc_dilithium_free(&dlKey); wc_FreeRng(&rng); return;
    }

    ret = wc_dilithium_make_key(&dlKey, &rng);
    TEST_ASSERT(ret == 0, "dl keygen");
    if (ret != 0) { wc_dilithium_free(&dlKey); wc_FreeRng(&rng); return; }

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetDilithium(&key, alg, &dlKey);
    TEST_ASSERT(ret == 0 && key.kty == WOLFCOSE_KTY_OKP, "key set dl");

    /* Encode/decode round-trip */
    {
        uint8_t cbuf[8192];
        size_t cLen = 0;
        WOLFCOSE_KEY key2;
        dilithium_key dlKey2;

        ret = wc_CoseKey_Encode(&key, cbuf, sizeof(cbuf), &cLen);
        TEST_ASSERT(ret == 0 && cLen > 0, "key dl encode");

        wc_dilithium_init(&dlKey2);
        wc_CoseKey_Init(&key2);
        key2.key.dilithium = &dlKey2;
        ret = wc_CoseKey_Decode(&key2, cbuf, cLen);
        TEST_ASSERT(ret == 0 && key2.kty == WOLFCOSE_KTY_OKP &&
                    key2.crv == key.crv && key2.hasPrivate == 1,
                    "key dl decode");

        /* Verify decoded key can sign/verify */
        {
            uint8_t payload[] = "Dilithium key round-trip";
            uint8_t scratch[8192];
            uint8_t out[8192];
            size_t outLen = 0;
            const uint8_t* decPayload = NULL;
            size_t decPayloadLen = 0;
            WOLFCOSE_HDR hdr;

            /* Sign with original key */
            ret = wc_CoseSign1_Sign(&key, alg,
                NULL, 0, payload, sizeof(payload) - 1, NULL, 0,
                scratch, sizeof(scratch),
                out, sizeof(out), &outLen, &rng);
            TEST_ASSERT(ret == 0, "key dl rt sign");

            /* Verify with decoded key */
            ret = wc_CoseSign1_Verify(&key2, out, outLen,
                NULL, 0, scratch, sizeof(scratch),
                &hdr, &decPayload, &decPayloadLen);
            TEST_ASSERT(ret == 0, "key dl rt verify");
        }

        wc_dilithium_free(&dlKey2);
    }

    wc_CoseKey_Free(&key);
    wc_dilithium_free(&dlKey);
    wc_FreeRng(&rng);
}
#endif /* HAVE_DILITHIUM */

/* ---------------------------------------------------------------------------
 * Hardened / error-path / boundary tests
 * --------------------------------------------------------------------------- */

#ifdef HAVE_ECC
static void test_cose_sign1_buffer_too_small(void)
{
    WOLFCOSE_KEY key;
    ecc_key eccKey;
    WC_RNG rng;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen;
    const uint8_t payload[] = "test";
    int ret;

    printf("  [Sign1 Buffer Errors]\n");

    wc_InitRng(&rng);
    wc_ecc_init(&eccKey);
    wc_ecc_make_key(&rng, 32, &eccKey);
    wc_CoseKey_Init(&key);
    wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &eccKey);

    /* scratch too small */
    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256, NULL, 0,
        payload, sizeof(payload), NULL, 0,
        scratch, 10, out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret != 0, "sign1 scratch too small");

    /* output too small */
    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256, NULL, 0,
        payload, sizeof(payload), NULL, 0,
        scratch, sizeof(scratch), out, 5, &outLen, &rng);
    TEST_ASSERT(ret != 0, "sign1 out too small");

    /* NULL scratch */
    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256, NULL, 0,
        payload, sizeof(payload), NULL, 0,
        NULL, 0, out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret != 0, "sign1 null scratch");

    /* NULL output */
    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256, NULL, 0,
        payload, sizeof(payload), NULL, 0,
        scratch, sizeof(scratch), NULL, 0, &outLen, &rng);
    TEST_ASSERT(ret != 0, "sign1 null out");

    /* NULL outLen */
    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256, NULL, 0,
        payload, sizeof(payload), NULL, 0,
        scratch, sizeof(scratch), out, sizeof(out), NULL, &rng);
    TEST_ASSERT(ret != 0, "sign1 null outLen");

    /* bad algorithm */
    ret = wc_CoseSign1_Sign(&key, 999, NULL, 0,
        payload, sizeof(payload), NULL, 0,
        scratch, sizeof(scratch), out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret != 0, "sign1 bad alg");

    /* verify with truncated input */
    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256, NULL, 0,
        payload, sizeof(payload), NULL, 0,
        scratch, sizeof(scratch), out, sizeof(out), &outLen, &rng);
    if (ret == 0) {
        WOLFCOSE_HDR hdr;
        const uint8_t* dec;
        size_t decLen;
        ret = wc_CoseSign1_Verify(&key, out, 3, NULL, 0,
            scratch, sizeof(scratch), &hdr, &dec, &decLen);
        TEST_ASSERT(ret != 0, "verify truncated input");

        /* verify with scratch too small */
        ret = wc_CoseSign1_Verify(&key, out, outLen, NULL, 0,
            scratch, 10, &hdr, &dec, &decLen);
        TEST_ASSERT(ret != 0, "verify scratch too small");
    }

    wc_CoseKey_Free(&key);
    wc_ecc_free(&eccKey);
    wc_FreeRng(&rng);
}
#endif /* HAVE_ECC */

#ifdef HAVE_AESGCM
static void test_cose_encrypt0_buffer_errors(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[16];
    uint8_t nonce[12];
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen;
    const uint8_t payload[] = "test";
    int ret;

    printf("  [Encrypt0 Buffer Errors]\n");

    memset(keyData, 0xAA, sizeof(keyData));
    memset(nonce, 0xBB, sizeof(nonce));
    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));

    /* scratch too small */
    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A128GCM,
        nonce, sizeof(nonce), payload, sizeof(payload), NULL, 0,
        scratch, 5, out, sizeof(out), &outLen);
    TEST_ASSERT(ret != 0, "enc0 scratch too small");

    /* output too small */
    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A128GCM,
        nonce, sizeof(nonce), payload, sizeof(payload), NULL, 0,
        scratch, sizeof(scratch), out, 5, &outLen);
    TEST_ASSERT(ret != 0, "enc0 out too small");

    /* NULL key */
    ret = wc_CoseEncrypt0_Encrypt(NULL, WOLFCOSE_ALG_A128GCM,
        nonce, sizeof(nonce), payload, sizeof(payload), NULL, 0,
        scratch, sizeof(scratch), out, sizeof(out), &outLen);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "enc0 null key");

    /* bad alg */
    ret = wc_CoseEncrypt0_Encrypt(&key, 999,
        nonce, sizeof(nonce), payload, sizeof(payload), NULL, 0,
        scratch, sizeof(scratch), out, sizeof(out), &outLen);
    TEST_ASSERT(ret != 0, "enc0 bad alg");

    /* decrypt truncated */
    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A128GCM,
        nonce, sizeof(nonce), payload, sizeof(payload), NULL, 0,
        scratch, sizeof(scratch), out, sizeof(out), &outLen);
    if (ret == 0) {
        WOLFCOSE_HDR hdr;
        uint8_t ptBuf[64];
        size_t ptLen;
        ret = wc_CoseEncrypt0_Decrypt(&key, out, 3, NULL, 0,
            scratch, sizeof(scratch), &hdr,
            ptBuf, sizeof(ptBuf), &ptLen);
        TEST_ASSERT(ret != 0, "dec0 truncated input");
    }

    wc_CoseKey_Free(&key);
}
#endif /* HAVE_AESGCM */

#if !defined(NO_HMAC)
static void test_cose_mac0_buffer_errors(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[32];
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen;
    const uint8_t payload[] = "test";
    int ret;

    printf("  [Mac0 Buffer Errors]\n");

    memset(keyData, 0xCC, sizeof(keyData));
    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));

    /* scratch too small */
    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC256, NULL, 0,
        payload, sizeof(payload), NULL, 0,
        scratch, 5, out, sizeof(out), &outLen);
    TEST_ASSERT(ret != 0, "mac0 scratch too small");

    /* output too small */
    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC256, NULL, 0,
        payload, sizeof(payload), NULL, 0,
        scratch, sizeof(scratch), out, 5, &outLen);
    TEST_ASSERT(ret != 0, "mac0 out too small");

    /* bad alg */
    ret = wc_CoseMac0_Create(&key, 999, NULL, 0,
        payload, sizeof(payload), NULL, 0,
        scratch, sizeof(scratch), out, sizeof(out), &outLen);
    TEST_ASSERT(ret != 0, "mac0 bad alg");

    /* verify truncated */
    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC256, NULL, 0,
        payload, sizeof(payload), NULL, 0,
        scratch, sizeof(scratch), out, sizeof(out), &outLen);
    if (ret == 0) {
        WOLFCOSE_HDR hdr;
        const uint8_t* dec;
        size_t decLen;
        ret = wc_CoseMac0_Verify(&key, out, 3, NULL, 0,
            scratch, sizeof(scratch), &hdr, &dec, &decLen);
        TEST_ASSERT(ret != 0, "mac0 verify truncated");
    }

    wc_CoseKey_Free(&key);
}
#endif /* !NO_HMAC */

static void test_cose_key_encode_errors(void)
{
    WOLFCOSE_KEY key;
    uint8_t buf[512];
    size_t len;
    int ret;

    printf("  [Key Encode/Decode Errors]\n");

    /* encode uninitialized key (kty=0) */
    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_Encode(&key, buf, sizeof(buf), &len);
    TEST_ASSERT(ret != 0, "encode unknown kty");

    /* encode with buffer too small */
    key.kty = WOLFCOSE_KTY_SYMMETRIC;
    key.key.symm.key = (const uint8_t*)"\x01\x02\x03\x04";
    key.key.symm.keyLen = 4;
    ret = wc_CoseKey_Encode(&key, buf, 3, &len);
    TEST_ASSERT(ret != 0, "encode buf too small");

    /* decode empty buffer */
    ret = wc_CoseKey_Decode(&key, buf, 0);
    TEST_ASSERT(ret != 0, "decode empty buf");

    /* decode truncated CBOR */
    buf[0] = 0xA1; /* map(1) but nothing follows */
    ret = wc_CoseKey_Decode(&key, buf, 1);
    TEST_ASSERT(ret != 0, "decode truncated cbor");

    /* NULL args */
    ret = wc_CoseKey_Encode(NULL, buf, sizeof(buf), &len);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "encode null key");
    ret = wc_CoseKey_Encode(&key, NULL, sizeof(buf), &len);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "encode null buf");
    ret = wc_CoseKey_Encode(&key, buf, sizeof(buf), NULL);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "encode null len");
    ret = wc_CoseKey_Decode(NULL, buf, sizeof(buf));
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "decode null key");
    ret = wc_CoseKey_Decode(&key, NULL, sizeof(buf));
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "decode null buf");
}

#ifdef HAVE_DILITHIUM
static void test_cose_key_set_dilithium_errors(void)
{
    WOLFCOSE_KEY key;
    dilithium_key dlKey;
    int ret;

    printf("  [SetDilithium Errors]\n");

    wc_CoseKey_Init(&key);
    wc_dilithium_init(&dlKey);

    /* NULL args */
    ret = wc_CoseKey_SetDilithium(NULL, WOLFCOSE_ALG_ML_DSA_44, &dlKey);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "set dl null key");
    ret = wc_CoseKey_SetDilithium(&key, WOLFCOSE_ALG_ML_DSA_44, NULL);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "set dl null dlkey");

    /* invalid alg */
    ret = wc_CoseKey_SetDilithium(&key, -99, &dlKey);
    TEST_ASSERT(ret == WOLFCOSE_E_COSE_BAD_ALG, "set dl bad alg");
    ret = wc_CoseKey_SetDilithium(&key, 0, &dlKey);
    TEST_ASSERT(ret == WOLFCOSE_E_COSE_BAD_ALG, "set dl zero alg");

    wc_dilithium_free(&dlKey);
}
#endif /* HAVE_DILITHIUM */

#ifdef HAVE_ED25519
static void test_cose_key_ed25519_public_only(void)
{
    WOLFCOSE_KEY key, key2;
    ed25519_key edKey, edKey2;
    WC_RNG rng;
    uint8_t buf[256];
    size_t len;
    int ret;

    printf("  [Key Ed25519 Public-Only]\n");

    wc_InitRng(&rng);
    wc_ed25519_init(&edKey);
    wc_ed25519_init(&edKey2);
    wc_ed25519_make_key(&rng, 32, &edKey);
    wc_CoseKey_Init(&key);
    wc_CoseKey_SetEd25519(&key, &edKey);

    /* Encode with private */
    ret = wc_CoseKey_Encode(&key, buf, sizeof(buf), &len);
    TEST_ASSERT(ret == 0, "ed pub encode");

    /* Decode into fresh key — should have private */
    wc_CoseKey_Init(&key2);
    key2.kty = WOLFCOSE_KTY_OKP;
    key2.key.ed25519 = &edKey2;
    ret = wc_CoseKey_Decode(&key2, buf, len);
    TEST_ASSERT(ret == 0, "ed pub decode");
    TEST_ASSERT(key2.hasPrivate == 1, "ed has priv");

    /* Now export public-only: make a CBOR map without d label */
    {
        /* Build a minimal OKP key with only x (public) */
        uint8_t pubBuf[256];
        WOLFCOSE_CBOR_CTX enc;
        uint8_t xBuf[32];
        word32 xSz = sizeof(xBuf);
        ed25519_key edKey3;

        wc_ed25519_init(&edKey3);
        wc_ed25519_export_public(&edKey, xBuf, &xSz);

        enc.buf = pubBuf; enc.bufSz = sizeof(pubBuf); enc.idx = 0;
        wc_CBOR_EncodeMapStart(&enc, 3);
        wc_CBOR_EncodeInt(&enc, WOLFCOSE_KEY_LABEL_KTY);
        wc_CBOR_EncodeUint(&enc, WOLFCOSE_KTY_OKP);
        wc_CBOR_EncodeInt(&enc, WOLFCOSE_KEY_LABEL_CRV);
        wc_CBOR_EncodeUint(&enc, WOLFCOSE_CRV_ED25519);
        wc_CBOR_EncodeInt(&enc, WOLFCOSE_KEY_LABEL_X);
        wc_CBOR_EncodeBstr(&enc, xBuf, xSz);

        wc_CoseKey_Init(&key2);
        key2.kty = WOLFCOSE_KTY_OKP;
        key2.key.ed25519 = &edKey3;
        ret = wc_CoseKey_Decode(&key2, pubBuf, enc.idx);
        TEST_ASSERT(ret == 0, "ed pub-only decode");
        TEST_ASSERT(key2.hasPrivate == 0, "ed pub-only no priv");

        wc_ed25519_free(&edKey3);
    }

    wc_CoseKey_Free(&key);
    wc_ed25519_free(&edKey);
    wc_ed25519_free(&edKey2);
    wc_FreeRng(&rng);
}
#endif /* HAVE_ED25519 */

#ifdef HAVE_ED448
static void test_cose_key_ed448_public_only(void)
{
    WOLFCOSE_KEY key;
    ed448_key edKey, edKey2;
    WC_RNG rng;
    uint8_t pubBuf[256];
    WOLFCOSE_CBOR_CTX enc;
    uint8_t xBuf[57];
    word32 xSz = sizeof(xBuf);
    int ret;

    printf("  [Key Ed448 Public-Only]\n");

    wc_InitRng(&rng);
    wc_ed448_init(&edKey);
    wc_ed448_init(&edKey2);
    wc_ed448_make_key(&rng, ED448_KEY_SIZE, &edKey);
    wc_ed448_export_public(&edKey, xBuf, &xSz);

    /* Build a public-only OKP key (no d label) */
    enc.buf = pubBuf; enc.bufSz = sizeof(pubBuf); enc.idx = 0;
    wc_CBOR_EncodeMapStart(&enc, 3);
    wc_CBOR_EncodeInt(&enc, WOLFCOSE_KEY_LABEL_KTY);
    wc_CBOR_EncodeUint(&enc, WOLFCOSE_KTY_OKP);
    wc_CBOR_EncodeInt(&enc, WOLFCOSE_KEY_LABEL_CRV);
    wc_CBOR_EncodeUint(&enc, WOLFCOSE_CRV_ED448);
    wc_CBOR_EncodeInt(&enc, WOLFCOSE_KEY_LABEL_X);
    wc_CBOR_EncodeBstr(&enc, xBuf, xSz);

    wc_CoseKey_Init(&key);
    key.kty = WOLFCOSE_KTY_OKP;
    key.key.ed448 = &edKey2;
    ret = wc_CoseKey_Decode(&key, pubBuf, enc.idx);
    TEST_ASSERT(ret == 0, "ed448 pub-only decode");
    TEST_ASSERT(key.hasPrivate == 0, "ed448 pub-only no priv");

    wc_ed448_free(&edKey);
    wc_ed448_free(&edKey2);
    wc_FreeRng(&rng);
}
#endif /* HAVE_ED448 */

#ifdef HAVE_DILITHIUM
static void test_cose_key_dilithium_public_only(void)
{
    WOLFCOSE_KEY key;
    dilithium_key dlKey, dlKey2;
    WC_RNG rng;
    uint8_t pubBuf[2048];
    WOLFCOSE_CBOR_CTX enc;
    uint8_t xBuf[1312]; /* ML-DSA-44 pub key size */
    word32 xSz = sizeof(xBuf);
    int ret;

    printf("  [Key ML-DSA-44 Public-Only]\n");

    wc_InitRng(&rng);
    wc_dilithium_init(&dlKey);
    wc_dilithium_init(&dlKey2);
    wc_dilithium_set_level(&dlKey, 2);
    wc_dilithium_make_key(&dlKey, &rng);
    wc_dilithium_export_public(&dlKey, xBuf, &xSz);

    /* Build a public-only OKP key (no d label) */
    enc.buf = pubBuf; enc.bufSz = sizeof(pubBuf); enc.idx = 0;
    wc_CBOR_EncodeMapStart(&enc, 3);
    wc_CBOR_EncodeInt(&enc, WOLFCOSE_KEY_LABEL_KTY);
    wc_CBOR_EncodeUint(&enc, WOLFCOSE_KTY_OKP);
    wc_CBOR_EncodeInt(&enc, WOLFCOSE_KEY_LABEL_CRV);
    wc_CBOR_EncodeInt(&enc, WOLFCOSE_CRV_ML_DSA_44);
    wc_CBOR_EncodeInt(&enc, WOLFCOSE_KEY_LABEL_X);
    wc_CBOR_EncodeBstr(&enc, xBuf, (size_t)xSz);

    wc_CoseKey_Init(&key);
    key.kty = WOLFCOSE_KTY_OKP;
    key.key.dilithium = &dlKey2;
    ret = wc_CoseKey_Decode(&key, pubBuf, enc.idx);
    TEST_ASSERT(ret == 0, "dl pub-only decode");
    TEST_ASSERT(key.hasPrivate == 0, "dl pub-only no priv");

    /* Verify with public-only key */
    {
        WOLFCOSE_KEY signKey;
        uint8_t scratch[8192];
        uint8_t out[8192];
        size_t outLen;
        const uint8_t payload[] = "pub-only verify";
        WOLFCOSE_HDR hdr;
        const uint8_t* dec;
        size_t decLen;

        wc_CoseKey_Init(&signKey);
        wc_CoseKey_SetDilithium(&signKey, WOLFCOSE_ALG_ML_DSA_44, &dlKey);

        ret = wc_CoseSign1_Sign(&signKey, WOLFCOSE_ALG_ML_DSA_44, NULL, 0,
            payload, sizeof(payload), NULL, 0,
            scratch, sizeof(scratch), out, sizeof(out), &outLen, &rng);
        TEST_ASSERT(ret == 0, "dl pub-only sign");

        ret = wc_CoseSign1_Verify(&key, out, outLen, NULL, 0,
            scratch, sizeof(scratch), &hdr, &dec, &decLen);
        TEST_ASSERT(ret == 0, "dl pub-only verify");

        wc_CoseKey_Free(&signKey);
    }

    wc_CoseKey_Free(&key);
    wc_dilithium_free(&dlKey);
    wc_dilithium_free(&dlKey2);
    wc_FreeRng(&rng);
}
#endif /* HAVE_DILITHIUM */

#ifdef HAVE_ECC
/* Test ECC public-only key decode (no d label) */
static void test_cose_key_ecc_public_only(void)
{
    WOLFCOSE_KEY key;
    ecc_key eccKey, eccKey2;
    WC_RNG rng;
    uint8_t pubBuf[256];
    WOLFCOSE_CBOR_CTX enc;
    uint8_t xBuf[32], yBuf[32];
    word32 xLen = sizeof(xBuf), yLen = sizeof(yBuf);
    int ret;

    printf("  [Key ECC Public-Only]\n");

    wc_InitRng(&rng);
    wc_ecc_init(&eccKey);
    wc_ecc_init(&eccKey2);
    wc_ecc_make_key(&rng, 32, &eccKey);
    wc_ecc_export_public_raw(&eccKey, xBuf, &xLen, yBuf, &yLen);

    /* Build a public-only EC2 key (no d label) */
    enc.buf = pubBuf; enc.bufSz = sizeof(pubBuf); enc.idx = 0;
    wc_CBOR_EncodeMapStart(&enc, 4);
    wc_CBOR_EncodeInt(&enc, WOLFCOSE_KEY_LABEL_KTY);
    wc_CBOR_EncodeUint(&enc, WOLFCOSE_KTY_EC2);
    wc_CBOR_EncodeInt(&enc, WOLFCOSE_KEY_LABEL_CRV);
    wc_CBOR_EncodeUint(&enc, WOLFCOSE_CRV_P256);
    wc_CBOR_EncodeInt(&enc, WOLFCOSE_KEY_LABEL_X);
    wc_CBOR_EncodeBstr(&enc, xBuf, (size_t)xLen);
    wc_CBOR_EncodeInt(&enc, WOLFCOSE_KEY_LABEL_Y);
    wc_CBOR_EncodeBstr(&enc, yBuf, (size_t)yLen);

    wc_CoseKey_Init(&key);
    key.key.ecc = &eccKey2;
    ret = wc_CoseKey_Decode(&key, pubBuf, enc.idx);
    TEST_ASSERT(ret == 0, "ecc pub-only decode");
    TEST_ASSERT(key.hasPrivate == 0, "ecc pub-only no priv");

    wc_ecc_free(&eccKey);
    wc_ecc_free(&eccKey2);
    wc_FreeRng(&rng);
}
#endif /* HAVE_ECC */

/* Test COSE_Key decode with kid and alg labels */
static void test_cose_key_decode_optional_labels(void)
{
    WOLFCOSE_KEY key;
    uint8_t buf[128];
    WOLFCOSE_CBOR_CTX enc;
    const uint8_t kidVal[] = "sensor-01";
    const uint8_t symmKey[] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    int ret;

    printf("  [Key Decode Optional Labels]\n");

    /* Build a symmetric key with kid(2), alg(3), and an unknown label(99) */
    enc.buf = buf; enc.bufSz = sizeof(buf); enc.idx = 0;
    wc_CBOR_EncodeMapStart(&enc, 5);

    /* kty = 4 (Symmetric) */
    wc_CBOR_EncodeInt(&enc, WOLFCOSE_KEY_LABEL_KTY);
    wc_CBOR_EncodeUint(&enc, WOLFCOSE_KTY_SYMMETRIC);

    /* kid = "sensor-01" */
    wc_CBOR_EncodeInt(&enc, WOLFCOSE_KEY_LABEL_KID);
    wc_CBOR_EncodeBstr(&enc, kidVal, sizeof(kidVal) - 1);

    /* alg = 5 (HMAC256) */
    wc_CBOR_EncodeInt(&enc, WOLFCOSE_KEY_LABEL_ALG);
    wc_CBOR_EncodeInt(&enc, WOLFCOSE_ALG_HMAC256);

    /* -1 = k (symmetric key bytes) */
    wc_CBOR_EncodeInt(&enc, WOLFCOSE_KEY_LABEL_K);
    wc_CBOR_EncodeBstr(&enc, symmKey, sizeof(symmKey));

    /* unknown label 99 = uint 42 (should be skipped) */
    wc_CBOR_EncodeInt(&enc, 99);
    wc_CBOR_EncodeUint(&enc, 42);

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_Decode(&key, buf, enc.idx);
    TEST_ASSERT(ret == 0, "key decode with labels");
    TEST_ASSERT(key.kty == WOLFCOSE_KTY_SYMMETRIC, "key decode kty");
    TEST_ASSERT(key.alg == WOLFCOSE_ALG_HMAC256, "key decode alg");
    TEST_ASSERT(key.kidLen == sizeof(kidVal) - 1, "key decode kid len");
    TEST_ASSERT(key.key.symm.keyLen == sizeof(symmKey), "key decode k len");
}

/* ---------------------------------------------------------------------------
 * RFC 9052 interop test vectors (cose-wg/Examples)
 * --------------------------------------------------------------------------- */

/* ECDSA-01: P-256 / ES256 Sign1 (ecdsa-sig-01.json) */
#ifdef HAVE_ECC
static void test_rfc_sign1_ecdsa_01(void)
{
    /* Known P-256 public key (x, y from test vector) */
    static const uint8_t tvKeyX[] = {
        0xBA, 0xC5, 0xB1, 0x1C, 0xAD, 0x8F, 0x99, 0xF9,
        0xC7, 0x2B, 0x05, 0xCF, 0x4B, 0x9E, 0x26, 0xD2,
        0x44, 0xDC, 0x18, 0x9F, 0x74, 0x52, 0x28, 0x25,
        0x5A, 0x21, 0x9A, 0x86, 0xD6, 0xA0, 0x9E, 0xFF
    };
    static const uint8_t tvKeyY[] = {
        0x20, 0x13, 0x8B, 0xF8, 0x2D, 0xC1, 0xB6, 0xD5,
        0x62, 0xBE, 0x0F, 0xA5, 0x4A, 0xB7, 0x80, 0x4A,
        0x3A, 0x64, 0xB6, 0xD7, 0x2C, 0xCF, 0xED, 0x6B,
        0x6F, 0xB6, 0xED, 0x28, 0xBB, 0xFC, 0x11, 0x7E
    };

    /* COSE_Sign1 output (100 bytes): Tag(18), protected={1:-7,3:0},
     * unprotected={4:h'3131'}, payload="This is the content.",
     * signature=64-byte r||s */
    static const uint8_t tvCbor[] = {
        0xD2, 0x84, 0x45, 0xA2, 0x01, 0x26, 0x03, 0x00,
        0xA1, 0x04, 0x42, 0x31, 0x31, 0x54, 0x54, 0x68,
        0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
        0x65, 0x20, 0x63, 0x6F, 0x6E, 0x74, 0x65, 0x6E,
        0x74, 0x2E, 0x58, 0x40, 0x65, 0x20, 0xBB, 0xAF,
        0x20, 0x81, 0xD7, 0xE0, 0xED, 0x0F, 0x95, 0xF7,
        0x6E, 0xB0, 0x73, 0x3D, 0x66, 0x70, 0x05, 0xF7,
        0x46, 0x7C, 0xEC, 0x4B, 0x87, 0xB9, 0x38, 0x1A,
        0x6B, 0xA1, 0xED, 0xE8, 0xE0, 0x0D, 0xF2, 0x9F,
        0x32, 0xA3, 0x72, 0x30, 0xF3, 0x9A, 0x84, 0x2A,
        0x54, 0x82, 0x1F, 0xDD, 0x22, 0x30, 0x92, 0x81,
        0x9D, 0x77, 0x28, 0xEF, 0xB9, 0xD3, 0xA0, 0x08,
        0x0B, 0x75, 0x38, 0x0B
    };

    WOLFCOSE_KEY key;
    ecc_key eccKey;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    WOLFCOSE_HDR hdr;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    int ret;

    printf("  [RFC ecdsa-sig-01 (ES256)]\n");

    /* Import known public key */
    wc_ecc_init(&eccKey);
    ret = wc_ecc_import_unsigned(&eccKey,
        (byte*)tvKeyX, (byte*)tvKeyY, NULL, ECC_SECP256R1);
    TEST_ASSERT(ret == 0, "rfc es256 key import");
    if (ret != 0) { wc_ecc_free(&eccKey); return; }

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &eccKey);
    key.hasPrivate = 0; /* public-only for verify */

    /* Verify the known test vector */
    ret = wc_CoseSign1_Verify(&key, tvCbor, sizeof(tvCbor),
        NULL, 0, scratch, sizeof(scratch), &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "rfc es256 verify");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_ES256, "rfc es256 alg");
    TEST_ASSERT(decPayloadLen == 20, "rfc es256 payload len");
    TEST_ASSERT(decPayload != NULL &&
                memcmp(decPayload, "This is the content.", 20) == 0,
                "rfc es256 payload match");

    wc_CoseKey_Free(&key);
    wc_ecc_free(&eccKey);
}
#endif /* HAVE_ECC */

/* HMAC-01: HMAC-SHA256 Mac0 (mac0-tests/HMac-01.json) */
#if !defined(NO_HMAC)
static void test_rfc_mac0_hmac_01(void)
{
    /* Known HMAC-SHA256 symmetric key (32 bytes) */
    static const uint8_t tvKey[] = {
        0x84, 0x9B, 0x57, 0x21, 0x9D, 0xAE, 0x48, 0xDE,
        0x64, 0x6D, 0x07, 0xDB, 0xB5, 0x33, 0x56, 0x6E,
        0x97, 0x66, 0x86, 0x45, 0x7C, 0x14, 0x91, 0xBE,
        0x3A, 0x76, 0xDC, 0xEA, 0x6C, 0x42, 0x71, 0x88
    };

    /* COSE_Mac0 output (62 bytes): Tag(17), protected={1:5},
     * unprotected={}, payload="This is the content.",
     * tag=32-byte HMAC */
    static const uint8_t tvCbor[] = {
        0xD1, 0x84, 0x43, 0xA1, 0x01, 0x05, 0xA0, 0x54,
        0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x63, 0x6F, 0x6E, 0x74,
        0x65, 0x6E, 0x74, 0x2E, 0x58, 0x20, 0xA1, 0xA8,
        0x48, 0xD3, 0x47, 0x1F, 0x9D, 0x61, 0xEE, 0x49,
        0x01, 0x8D, 0x24, 0x4C, 0x82, 0x47, 0x72, 0xF2,
        0x23, 0xAD, 0x4F, 0x93, 0x52, 0x93, 0xF1, 0x78,
        0x9F, 0xC3, 0xA0, 0x8D, 0x8C, 0x58
    };

    WOLFCOSE_KEY key;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    WOLFCOSE_HDR hdr;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    int ret;

    printf("  [RFC HMac-01 (HMAC-256)]\n");

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, tvKey, sizeof(tvKey));

    /* Verify the known test vector */
    ret = wc_CoseMac0_Verify(&key, tvCbor, sizeof(tvCbor),
        NULL, 0, scratch, sizeof(scratch), &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "rfc hmac01 verify");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_HMAC256, "rfc hmac01 alg");
    TEST_ASSERT(decPayloadLen == 20, "rfc hmac01 payload len");
    TEST_ASSERT(decPayload != NULL &&
                memcmp(decPayload, "This is the content.", 20) == 0,
                "rfc hmac01 payload match");

    wc_CoseKey_Free(&key);
}
#endif /* !NO_HMAC */

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
#if defined(WC_RSA_PSS) && defined(WOLFSSL_KEY_GEN)
    test_cose_key_rsa();
#endif
#ifdef HAVE_DILITHIUM
    test_cose_key_dilithium("ML-DSA-44", WOLFCOSE_ALG_ML_DSA_44, 2);
    test_cose_key_dilithium("ML-DSA-65", WOLFCOSE_ALG_ML_DSA_65, 3);
    test_cose_key_dilithium("ML-DSA-87", WOLFCOSE_ALG_ML_DSA_87, 5);
#endif

#ifdef HAVE_ECC
    test_cose_sign1_ecc("ES256", WOLFCOSE_ALG_ES256, WOLFCOSE_CRV_P256, 32);
    test_cose_sign1_with_aad();
#ifdef WOLFSSL_SHA384
    test_cose_sign1_ecc("ES384", WOLFCOSE_ALG_ES384, WOLFCOSE_CRV_P384, 48);
#endif
#ifdef WOLFSSL_SHA512
    test_cose_sign1_ecc("ES512", WOLFCOSE_ALG_ES512, WOLFCOSE_CRV_P521, 66);
#endif
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

#if defined(WC_RSA_PSS) && defined(WOLFSSL_KEY_GEN)
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

    /* RFC 9052 interop test vectors */
#ifdef HAVE_ECC
    test_rfc_sign1_ecdsa_01();
#endif
#if !defined(NO_HMAC)
    test_rfc_mac0_hmac_01();
#endif

    /* Hardened / error-path tests */
#ifdef HAVE_ECC
    test_cose_sign1_buffer_too_small();
#endif
#ifdef HAVE_AESGCM
    test_cose_encrypt0_buffer_errors();
#endif
#if !defined(NO_HMAC)
    test_cose_mac0_buffer_errors();
#endif
    test_cose_key_encode_errors();
    test_cose_key_decode_optional_labels();
#ifdef HAVE_DILITHIUM
    test_cose_key_set_dilithium_errors();
#endif
#ifdef HAVE_ED25519
    test_cose_key_ed25519_public_only();
#endif
#ifdef HAVE_ED448
    test_cose_key_ed448_public_only();
#endif
#ifdef HAVE_DILITHIUM
    test_cose_key_dilithium_public_only();
#endif
#ifdef HAVE_ECC
    test_cose_key_ecc_public_only();
#endif

    printf("  COSE: %d failure(s)\n", g_failures);
    return g_failures;
}
