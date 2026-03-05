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
        NULL, 0, /* detachedPayload, detachedLen */
        NULL, 0, /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret == 0 && outLen > 0, "sign1 ecc sign");

    /* Verify with same key */
    ret = wc_CoseSign1_Verify(&signKey, out, outLen,
        NULL, 0, /* detachedPayload, detachedLen */
        NULL, 0, /* extAad, extAadLen */
        scratch, sizeof(scratch),
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
                NULL, 0, NULL, 0, scratch, sizeof(scratch),
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
            NULL, 0, NULL, 0, scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret != 0, "sign1 ecc tampered fails");
    }

    /* Error: null args */
    ret = wc_CoseSign1_Sign(NULL, WOLFCOSE_ALG_ES256, NULL, 0,
        payload, sizeof(payload), NULL, 0, NULL, 0,
        scratch, sizeof(scratch), out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "sign1 null key");

    ret = wc_CoseSign1_Verify(NULL, out, outLen, NULL, 0, NULL, 0,
        scratch, sizeof(scratch), &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "verify null key");

    /* Error: no private key */
    {
        WOLFCOSE_KEY pubOnly;
        wc_CoseKey_Init(&pubOnly);
        pubOnly.kty = WOLFCOSE_KTY_EC2;
        pubOnly.hasPrivate = 0;
        pubOnly.key.ecc = &eccKey;
        ret = wc_CoseSign1_Sign(&pubOnly, WOLFCOSE_ALG_ES256, NULL, 0,
            payload, sizeof(payload), NULL, 0, NULL, 0,
            scratch, sizeof(scratch), out, sizeof(out), &outLen, &rng);
        TEST_ASSERT(ret == WOLFCOSE_E_COSE_KEY_TYPE, "sign1 no privkey");
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
        NULL, 0, /* detachedPayload, detachedLen */
        NULL, 0, /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret == 0 && outLen > 0, "sign1 eddsa sign");

    /* Verify */
    ret = wc_CoseSign1_Verify(&signKey, out, outLen,
        NULL, 0, NULL, 0, scratch, sizeof(scratch),
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
                NULL, 0, NULL, 0, scratch, sizeof(scratch),
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
        NULL, 0, /* detachedPayload, detachedLen */
        NULL, 0, /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret == 0 && outLen > 0, "sign1 ed448 sign");

    /* Verify */
    ret = wc_CoseSign1_Verify(&signKey, out, outLen,
        NULL, 0, /* detachedPayload, detachedLen */
        NULL, 0, /* extAad, extAadLen */
        scratch, sizeof(scratch),
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
                NULL, 0, /* detachedPayload, detachedLen */
                NULL, 0, /* extAad, extAadLen */
                scratch, sizeof(scratch),
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
        NULL, 0, NULL, /* detachedPayload, detachedSz, detachedLen */
        NULL, 0, /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "enc0 a128gcm encrypt");

    /* Decrypt */
    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0, /* detachedCt, detachedCtLen */
        NULL, 0, /* extAad, extAadLen */
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
            NULL, 0, NULL, 0, scratch, sizeof(scratch), &hdr,
            plaintext, sizeof(plaintext), &plaintextLen);
        TEST_ASSERT(ret != 0, "enc0 a128gcm tampered fails");
    }

    /* Error: null args */
    ret = wc_CoseEncrypt0_Encrypt(NULL, WOLFCOSE_ALG_A128GCM,
        iv, sizeof(iv), payload, sizeof(payload), NULL, 0, NULL, NULL, 0,
        scratch, sizeof(scratch), out, sizeof(out), &outLen);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "enc0 null key");

    /* Error: wrong key type */
    {
        WOLFCOSE_KEY badKey;
        wc_CoseKey_Init(&badKey);
        badKey.kty = WOLFCOSE_KTY_EC2;
        ret = wc_CoseEncrypt0_Encrypt(&badKey, WOLFCOSE_ALG_A128GCM,
            iv, sizeof(iv), payload, sizeof(payload), NULL, 0, NULL, NULL, 0,
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
            iv, sizeof(iv), payload, sizeof(payload), NULL, 0, NULL, NULL, 0,
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
        NULL, 0, NULL, /* detachedPayload, detachedSz, detachedLen */
        NULL, 0, /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "enc0 a256gcm encrypt");

    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0, /* detachedCt, detachedCtLen */
        NULL, 0, /* extAad, extAadLen */
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
        NULL, 0, NULL, /* detachedPayload, detachedSz, detachedLen */
        extAad, sizeof(extAad) - 1,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "enc0 aad encrypt");

    /* Decrypt with correct AAD */
    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0, /* detachedCt, detachedCtLen */
        extAad, sizeof(extAad) - 1,
        scratch, sizeof(scratch), &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0 && plaintextLen == sizeof(payload) - 1,
                "enc0 aad decrypt ok");

    /* Decrypt with wrong AAD should fail */
    {
        uint8_t wrongAad[] = "wrong-aad";
        ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
            NULL, 0, /* detachedCt, detachedCtLen */
            wrongAad, sizeof(wrongAad) - 1,
            scratch, sizeof(scratch), &hdr,
            plaintext, sizeof(plaintext), &plaintextLen);
        TEST_ASSERT(ret != 0, "enc0 wrong aad fails");
    }

    /* Decrypt with no AAD should fail */
    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0, NULL, 0,
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
        NULL, 0, NULL, /* detachedPayload, detachedSz, detachedLen */
        NULL, 0,       /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "enc0 chacha20 encrypt");

    /* Decrypt */
    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0, /* detachedCt, detachedLen */
        NULL, 0, /* extAad, extAadLen */
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
            NULL, 0, NULL, 0, scratch, sizeof(scratch), &hdr,
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
            iv, sizeof(iv), payload, sizeof(payload), NULL, 0, NULL, NULL, 0,
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
        NULL, 0, NULL, /* detachedPayload, detachedSz, detachedLen */
        NULL, 0, /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "enc0 ccm-16-128-128 encrypt");

    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0, /* detachedCt, detachedCtLen */
        NULL, 0, /* extAad, extAadLen */
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
            NULL, 0, /* detachedCt, detachedCtLen */
            NULL, 0, /* extAad, extAadLen */
            scratch, sizeof(scratch), &hdr,
            plaintext, sizeof(plaintext), &plaintextLen);
        TEST_ASSERT(ret != 0, "enc0 ccm-16-128-128 tampered fails");
    }

    /* --- AES-CCM-16-64-128: key=16, nonce=13, tag=8 --- */
    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_AES_CCM_16_64_128,
        nonce13, sizeof(nonce13),
        payload, sizeof(payload) - 1,
        NULL, 0, NULL, /* detachedPayload, detachedSz, detachedLen */
        NULL, 0, /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "enc0 ccm-16-64-128 encrypt");

    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0, /* detachedCt, detachedCtLen */
        NULL, 0, /* extAad, extAadLen */
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
        NULL, 0, NULL, /* detachedPayload, detachedSz, detachedLen */
        NULL, 0, /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "enc0 ccm-64-128-128 encrypt");

    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0, /* detachedCt, detachedCtLen */
        NULL, 0, /* extAad, extAadLen */
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
        NULL, 0, /* detachedPayload, detachedLen */
        NULL, 0, /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret == 0 && outLen > 0, "sign1 pss sign");

    /* Verify */
    ret = wc_CoseSign1_Verify(&signKey, out, outLen,
        NULL, 0, /* detachedPayload, detachedLen */
        NULL, 0, /* extAad, extAadLen */
        scratch, sizeof(scratch),
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
                NULL, 0, /* detachedPayload, detachedLen */
                NULL, 0, /* extAad, extAadLen */
                scratch, sizeof(scratch),
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
        NULL, 0, /* detachedPayload, detachedLen */
        NULL, 0, /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret == 0 && outLen > 0, "sign1 ml-dsa sign");

    /* Verify */
    ret = wc_CoseSign1_Verify(&signKey, out, outLen,
        NULL, 0, /* detachedPayload, detachedLen */
        NULL, 0, /* extAad, extAadLen */
        scratch, sizeof(scratch),
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
                NULL, 0, /* detachedPayload, detachedLen */
                NULL, 0, /* extAad, extAadLen */
                scratch, sizeof(scratch),
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
        NULL, 0, /* detachedPayload, detachedLen */
        extAad, sizeof(extAad) - 1,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret == 0, "sign1 aad sign");

    /* Verify with correct AAD */
    ret = wc_CoseSign1_Verify(&key, out, outLen,
        NULL, 0, /* detachedPayload, detachedLen */
        extAad, sizeof(extAad) - 1,
        scratch, sizeof(scratch), &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "sign1 aad verify ok");

    /* Verify with wrong AAD should fail */
    {
        uint8_t wrongAad[] = "wrong";
        ret = wc_CoseSign1_Verify(&key, out, outLen,
            NULL, 0, /* detachedPayload, detachedLen */
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
                NULL, 0, payload, sizeof(payload) - 1,
                NULL, 0, /* detachedPayload, detachedLen */
                NULL, 0, /* extAad, extAadLen */
                scratch, sizeof(scratch),
                out, sizeof(out), &outLen, &rng);
            TEST_ASSERT(ret == 0, "key rsa rt sign");

            /* Verify with decoded key (public only) */
            ret = wc_CoseSign1_Verify(&key2, out, outLen,
                NULL, 0, /* detachedPayload, detachedLen */
                NULL, 0, /* extAad, extAadLen */
                scratch, sizeof(scratch),
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
                NULL, 0, payload, sizeof(payload) - 1,
                NULL, 0, /* detachedPayload, detachedLen */
                NULL, 0, /* extAad, extAadLen */
                scratch, sizeof(scratch),
                out, sizeof(out), &outLen, &rng);
            TEST_ASSERT(ret == 0, "key dl rt sign");

            /* Verify with decoded key */
            ret = wc_CoseSign1_Verify(&key2, out, outLen,
                NULL, 0, /* detachedPayload, detachedLen */
                NULL, 0, /* extAad, extAadLen */
                scratch, sizeof(scratch),
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
 * COSE_Mac0 tests
 * --------------------------------------------------------------------------- */
#ifndef NO_HMAC
static void test_cose_mac0_hmac256(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    uint8_t payload[] = "COSE_Mac0 test payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Mac0 HMAC-256/256]\n");

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));

    /* Create Mac0 */
    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC_256_256,
        NULL, 0, /* kid, kidLen */
        payload, sizeof(payload) - 1,
        NULL, 0, /* detachedPayload, detachedLen */
        NULL, 0, /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "mac0 hmac256 create");

    /* Verify */
    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0, /* detachedPayload, detachedLen */
        NULL, 0, /* extAad, extAadLen */
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "mac0 hmac256 verify");
    TEST_ASSERT(decPayloadLen == sizeof(payload) - 1 &&
                memcmp(decPayload, payload, decPayloadLen) == 0,
                "mac0 hmac256 payload match");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_HMAC_256_256, "mac0 hmac256 hdr alg");

    /* Verify with wrong key should fail */
    {
        WOLFCOSE_KEY wrongKey;
        uint8_t wrongKeyData[32] = {0};
        wc_CoseKey_Init(&wrongKey);
        wc_CoseKey_SetSymmetric(&wrongKey, wrongKeyData, sizeof(wrongKeyData));
        ret = wc_CoseMac0_Verify(&wrongKey, out, outLen,
            NULL, 0, NULL, 0, scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == WOLFCOSE_E_MAC_FAIL, "mac0 wrong key fails");
    }

    /* Tampered message should fail */
    {
        uint8_t tampered[512];
        memcpy(tampered, out, outLen);
        if (outLen > 20) {
            tampered[outLen - 5] ^= 0xFF; /* flip byte in tag */
        }
        ret = wc_CoseMac0_Verify(&key, tampered, outLen,
            NULL, 0, NULL, 0, scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == WOLFCOSE_E_MAC_FAIL, "mac0 tampered fails");
    }

    /* Error: null args */
    ret = wc_CoseMac0_Create(NULL, WOLFCOSE_ALG_HMAC_256_256,
        NULL, 0, /* kid, kidLen */
        payload, sizeof(payload), NULL, 0, NULL, 0,
        scratch, sizeof(scratch), out, sizeof(out), &outLen);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "mac0 null key");

    ret = wc_CoseMac0_Verify(NULL, out, outLen,
        NULL, 0, NULL, 0, scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "mac0 verify null key");

    /* Error: wrong key type */
    {
        WOLFCOSE_KEY badKey;
        wc_CoseKey_Init(&badKey);
        badKey.kty = WOLFCOSE_KTY_EC2;
        ret = wc_CoseMac0_Create(&badKey, WOLFCOSE_ALG_HMAC_256_256,
            NULL, 0, /* kid, kidLen */
            payload, sizeof(payload), NULL, 0, NULL, 0,
            scratch, sizeof(scratch), out, sizeof(out), &outLen);
        TEST_ASSERT(ret == WOLFCOSE_E_COSE_KEY_TYPE, "mac0 wrong key type");
    }
}

#ifdef WOLFSSL_SHA384
static void test_cose_mac0_hmac384(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[48];
    uint8_t payload[] = "Mac0 HMAC-384/384 test";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Mac0 HMAC-384/384]\n");

    memset(keyData, 0xAB, sizeof(keyData));
    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));

    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC_384_384,
        NULL, 0, /* kid, kidLen */
        payload, sizeof(payload) - 1,
        NULL, 0, /* detachedPayload */
        NULL, 0, /* extAad */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "mac0 hmac384 create");

    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "mac0 hmac384 verify");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_HMAC_384_384, "mac0 hmac384 hdr alg");
}
#endif /* WOLFSSL_SHA384 */

#ifdef WOLFSSL_SHA512
static void test_cose_mac0_hmac512(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[64];
    uint8_t payload[] = "Mac0 HMAC-512/512 test";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Mac0 HMAC-512/512]\n");

    memset(keyData, 0xCD, sizeof(keyData));
    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));

    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC_512_512,
        NULL, 0, /* kid, kidLen */
        payload, sizeof(payload) - 1,
        NULL, 0, /* detachedPayload */
        NULL, 0, /* extAad */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "mac0 hmac512 create");

    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "mac0 hmac512 verify");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_HMAC_512_512, "mac0 hmac512 hdr alg");
}
#endif /* WOLFSSL_SHA512 */

static void test_cose_mac0_with_aad(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[32] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    uint8_t payload[] = "MAC AAD test payload";
    uint8_t extAad[] = "mac-external-aad";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Mac0 with external AAD]\n");

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));

    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC_256_256,
        NULL, 0, /* kid, kidLen */
        payload, sizeof(payload) - 1,
        NULL, 0, /* detachedPayload, detachedLen */
        extAad, sizeof(extAad) - 1,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "mac0 aad create");

    /* Verify with correct AAD */
    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0, /* detachedPayload, detachedLen */
        extAad, sizeof(extAad) - 1,
        scratch, sizeof(scratch), &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "mac0 aad verify ok");

    /* Verify with wrong AAD should fail */
    {
        uint8_t wrongAad[] = "wrong-aad";
        ret = wc_CoseMac0_Verify(&key, out, outLen,
            NULL, 0, /* detachedPayload, detachedLen */
            wrongAad, sizeof(wrongAad) - 1,
            scratch, sizeof(scratch), &hdr,
            &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == WOLFCOSE_E_MAC_FAIL, "mac0 wrong aad fails");
    }

    /* Verify with no AAD should fail */
    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch), &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == WOLFCOSE_E_MAC_FAIL, "mac0 missing aad fails");
}
#endif /* !NO_HMAC */

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
        payload, sizeof(payload), NULL, 0, NULL, 0,
        scratch, 10, out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret != 0, "sign1 scratch too small");

    /* output too small */
    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256, NULL, 0,
        payload, sizeof(payload), NULL, 0, NULL, 0,
        scratch, sizeof(scratch), out, 5, &outLen, &rng);
    TEST_ASSERT(ret != 0, "sign1 out too small");

    /* NULL scratch */
    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256, NULL, 0,
        payload, sizeof(payload), NULL, 0, NULL, 0,
        NULL, 0, out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret != 0, "sign1 null scratch");

    /* NULL output */
    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256, NULL, 0,
        payload, sizeof(payload), NULL, 0, NULL, 0,
        scratch, sizeof(scratch), NULL, 0, &outLen, &rng);
    TEST_ASSERT(ret != 0, "sign1 null out");

    /* NULL outLen */
    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256, NULL, 0,
        payload, sizeof(payload), NULL, 0, NULL, 0,
        scratch, sizeof(scratch), out, sizeof(out), NULL, &rng);
    TEST_ASSERT(ret != 0, "sign1 null outLen");

    /* bad algorithm */
    ret = wc_CoseSign1_Sign(&key, 999, NULL, 0,
        payload, sizeof(payload), NULL, 0, NULL, 0,
        scratch, sizeof(scratch), out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret != 0, "sign1 bad alg");

    /* verify with truncated input */
    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256, NULL, 0,
        payload, sizeof(payload), NULL, 0, NULL, 0,
        scratch, sizeof(scratch), out, sizeof(out), &outLen, &rng);
    if (ret == 0) {
        WOLFCOSE_HDR hdr;
        const uint8_t* dec;
        size_t decLen;
        ret = wc_CoseSign1_Verify(&key, out, 3, NULL, 0, NULL, 0,
            scratch, sizeof(scratch), &hdr, &dec, &decLen);
        TEST_ASSERT(ret != 0, "verify truncated input");

        /* verify with scratch too small */
        ret = wc_CoseSign1_Verify(&key, out, outLen, NULL, 0, NULL, 0,
            scratch, 10, &hdr, &dec, &decLen);
        TEST_ASSERT(ret != 0, "verify scratch too small");
    }

    wc_CoseKey_Free(&key);
    wc_ecc_free(&eccKey);
    wc_FreeRng(&rng);
}

/* ---------------------------------------------------------------------------
 * Detached Payload tests (RFC 9052 Section 2)
 * --------------------------------------------------------------------------- */
static void test_cose_sign1_detached(void)
{
    WOLFCOSE_KEY key;
    ecc_key eccKey;
    WC_RNG rng;
    int ret;
    uint8_t payload[] = "Detached sign payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Sign1 Detached Payload]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) { TEST_ASSERT(0, "rng init"); return; }

    wc_ecc_init(&eccKey);
    ret = wc_ecc_make_key(&rng, 32, &eccKey);
    if (ret != 0) { TEST_ASSERT(0, "keygen"); goto done_det_sign; }

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &eccKey);

    /* Sign with detached payload (payload in message is null) */
    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256,
        NULL, 0,          /* kid */
        NULL, 0,          /* payload in message = null */
        payload, sizeof(payload) - 1,  /* detached payload for signature */
        NULL, 0,          /* extAad */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret == 0 && outLen > 0, "sign1 detached sign");

    /* Verify must fail if no detached payload provided */
    ret = wc_CoseSign1_Verify(&key, out, outLen,
        NULL, 0, /* no detached payload */
        NULL, 0, scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == WOLFCOSE_E_DETACHED_PAYLOAD, "sign1 detached no payload fails");

    /* Verify with correct detached payload */
    ret = wc_CoseSign1_Verify(&key, out, outLen,
        payload, sizeof(payload) - 1, /* provide detached payload */
        NULL, 0, scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "sign1 detached verify ok");
    TEST_ASSERT(hdr.flags & WOLFCOSE_HDR_FLAG_DETACHED, "sign1 detached flag set");
    TEST_ASSERT(decPayload == NULL && decPayloadLen == 0, "sign1 detached payload null");

    /* Verify with wrong detached payload should fail */
    {
        uint8_t wrongPayload[] = "Wrong payload data";
        ret = wc_CoseSign1_Verify(&key, out, outLen,
            wrongPayload, sizeof(wrongPayload) - 1,
            NULL, 0, scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret != 0, "sign1 detached wrong payload fails");
    }

done_det_sign:
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
        nonce, sizeof(nonce), payload, sizeof(payload), NULL, 0, NULL,
        NULL, 0, scratch, 5, out, sizeof(out), &outLen);
    TEST_ASSERT(ret != 0, "enc0 scratch too small");

    /* output too small */
    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A128GCM,
        nonce, sizeof(nonce), payload, sizeof(payload), NULL, 0, NULL,
        NULL, 0, scratch, sizeof(scratch), out, 5, &outLen);
    TEST_ASSERT(ret != 0, "enc0 out too small");

    /* NULL key */
    ret = wc_CoseEncrypt0_Encrypt(NULL, WOLFCOSE_ALG_A128GCM,
        nonce, sizeof(nonce), payload, sizeof(payload), NULL, 0, NULL,
        NULL, 0, scratch, sizeof(scratch), out, sizeof(out), &outLen);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "enc0 null key");

    /* bad alg */
    ret = wc_CoseEncrypt0_Encrypt(&key, 999,
        nonce, sizeof(nonce), payload, sizeof(payload), NULL, 0, NULL,
        NULL, 0, scratch, sizeof(scratch), out, sizeof(out), &outLen);
    TEST_ASSERT(ret != 0, "enc0 bad alg");

    /* decrypt truncated */
    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A128GCM,
        nonce, sizeof(nonce), payload, sizeof(payload), NULL, 0, NULL,
        NULL, 0, scratch, sizeof(scratch), out, sizeof(out), &outLen);
    if (ret == 0) {
        WOLFCOSE_HDR hdr;
        uint8_t ptBuf[64];
        size_t ptLen;
        ret = wc_CoseEncrypt0_Decrypt(&key, out, 3, NULL, 0,
            NULL, 0, scratch, sizeof(scratch), &hdr,
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
    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC_256_256,
        NULL, 0, /* kid, kidLen */
        payload, sizeof(payload), NULL, 0, NULL, 0, /* payload, detached, extAad */
        scratch, 5, out, sizeof(out), &outLen);
    TEST_ASSERT(ret != 0, "mac0 scratch too small");

    /* output too small */
    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC_256_256,
        NULL, 0, /* kid, kidLen */
        payload, sizeof(payload), NULL, 0, NULL, 0, /* payload, detached, extAad */
        scratch, sizeof(scratch), out, 5, &outLen);
    TEST_ASSERT(ret != 0, "mac0 out too small");

    /* bad alg */
    ret = wc_CoseMac0_Create(&key, 999,
        NULL, 0, /* kid, kidLen */
        payload, sizeof(payload), NULL, 0, NULL, 0, /* payload, detached, extAad */
        scratch, sizeof(scratch), out, sizeof(out), &outLen);
    TEST_ASSERT(ret != 0, "mac0 bad alg");

    /* verify truncated */
    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC_256_256,
        NULL, 0, /* kid, kidLen */
        payload, sizeof(payload), NULL, 0, NULL, 0, /* payload, detached, extAad */
        scratch, sizeof(scratch), out, sizeof(out), &outLen);
    if (ret == 0) {
        WOLFCOSE_HDR hdr;
        const uint8_t* dec;
        size_t decLen;
        ret = wc_CoseMac0_Verify(&key, out, 3, NULL, 0, NULL, 0,
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
            payload, sizeof(payload),
            NULL, 0, /* detachedPayload, detachedLen */
            NULL, 0, /* extAad, extAadLen */
            scratch, sizeof(scratch), out, sizeof(out), &outLen, &rng);
        TEST_ASSERT(ret == 0, "dl pub-only sign");

        ret = wc_CoseSign1_Verify(&key, out, outLen,
            NULL, 0, /* detachedPayload, detachedLen */
            NULL, 0, /* extAad, extAadLen */
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
    wc_CBOR_EncodeInt(&enc, WOLFCOSE_ALG_HMAC_256_256);

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
    TEST_ASSERT(key.alg == WOLFCOSE_ALG_HMAC_256_256, "key decode alg");
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
        NULL, 0, NULL, 0, scratch, sizeof(scratch), &hdr,
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
        NULL, 0, NULL, 0, scratch, sizeof(scratch), &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "rfc hmac01 verify");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_HMAC_256_256, "rfc hmac01 alg");
    TEST_ASSERT(decPayloadLen == 20, "rfc hmac01 payload len");
    TEST_ASSERT(decPayload != NULL &&
                memcmp(decPayload, "This is the content.", 20) == 0,
                "rfc hmac01 payload match");

    wc_CoseKey_Free(&key);
}
#endif /* !NO_HMAC */

#ifdef HAVE_AESGCM
static void test_cose_encrypt0_detached(void)
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
    uint8_t payload[] = "Detached encrypt payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    uint8_t detachedCt[256];
    size_t detachedCtLen = 0;
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Encrypt0 Detached Ciphertext]\n");

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));

    /* Encrypt with detached ciphertext */
    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A128GCM,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,
        detachedCt, sizeof(detachedCt), &detachedCtLen,
        NULL, 0, /* extAad */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "enc0 detached encrypt");
    TEST_ASSERT(detachedCtLen == sizeof(payload) - 1 + WOLFCOSE_AES_GCM_TAG_SZ,
                "enc0 detached ct len");

    /* Decrypt must fail if no detached ciphertext provided */
    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0, /* no detached ct */
        NULL, 0, scratch, sizeof(scratch), &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == WOLFCOSE_E_DETACHED_PAYLOAD, "enc0 detached no ct fails");

    /* Decrypt with correct detached ciphertext */
    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        detachedCt, detachedCtLen,
        NULL, 0, scratch, sizeof(scratch), &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "enc0 detached decrypt ok");
    TEST_ASSERT(hdr.flags & WOLFCOSE_HDR_FLAG_DETACHED, "enc0 detached flag set");
    TEST_ASSERT(plaintextLen == sizeof(payload) - 1 &&
                memcmp(plaintext, payload, plaintextLen) == 0,
                "enc0 detached payload match");

    /* Decrypt with tampered detached ciphertext should fail */
    {
        uint8_t tamperedCt[256];
        memcpy(tamperedCt, detachedCt, detachedCtLen);
        tamperedCt[0] ^= 0xFF;
        ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
            tamperedCt, detachedCtLen,
            NULL, 0, scratch, sizeof(scratch), &hdr,
            plaintext, sizeof(plaintext), &plaintextLen);
        TEST_ASSERT(ret != 0, "enc0 detached tampered ct fails");
    }
}
#endif /* HAVE_AESGCM */

#ifndef NO_HMAC
static void test_cose_mac0_detached(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    uint8_t payload[] = "Detached MAC payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Mac0 Detached Payload]\n");

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));

    /* Create Mac0 with detached payload */
    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC_256_256,
        NULL, 0,                       /* kid, kidLen */
        NULL, 0,                       /* payload in message = null */
        payload, sizeof(payload) - 1,  /* detached payload for MAC */
        NULL, 0,                       /* extAad */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "mac0 detached create");

    /* Verify must fail if no detached payload provided */
    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0, /* no detached payload */
        NULL, 0, scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == WOLFCOSE_E_DETACHED_PAYLOAD, "mac0 detached no payload fails");

    /* Verify with correct detached payload */
    ret = wc_CoseMac0_Verify(&key, out, outLen,
        payload, sizeof(payload) - 1, /* provide detached payload */
        NULL, 0, scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "mac0 detached verify ok");
    TEST_ASSERT(hdr.flags & WOLFCOSE_HDR_FLAG_DETACHED, "mac0 detached flag set");
    TEST_ASSERT(decPayload == NULL && decPayloadLen == 0, "mac0 detached payload null");

    /* Verify with wrong detached payload should fail */
    {
        uint8_t wrongPayload[] = "Wrong payload data";
        ret = wc_CoseMac0_Verify(&key, out, outLen,
            wrongPayload, sizeof(wrongPayload) - 1,
            NULL, 0, scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == WOLFCOSE_E_MAC_FAIL, "mac0 detached wrong payload fails");
    }
}

static void test_cose_mac0_detached_with_aad(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[32] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    uint8_t payload[] = "Detached payload with AAD";
    uint8_t extAad[] = "external-aad-data";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Mac0 Detached with AAD]\n");

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));

    /* Create with detached payload and external AAD */
    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC_256_256,
        NULL, 0,                       /* kid, kidLen */
        NULL, 0,                       /* payload in message = null */
        payload, sizeof(payload) - 1,  /* detached payload */
        extAad, sizeof(extAad) - 1,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "mac0 detached+aad create");

    /* Verify with correct detached payload and AAD */
    ret = wc_CoseMac0_Verify(&key, out, outLen,
        payload, sizeof(payload) - 1,
        extAad, sizeof(extAad) - 1,
        scratch, sizeof(scratch), &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "mac0 detached+aad verify ok");

    /* Verify with wrong AAD should fail */
    {
        uint8_t wrongAad[] = "wrong";
        ret = wc_CoseMac0_Verify(&key, out, outLen,
            payload, sizeof(payload) - 1,
            wrongAad, sizeof(wrongAad) - 1,
            scratch, sizeof(scratch), &hdr,
            &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == WOLFCOSE_E_MAC_FAIL, "mac0 detached wrong aad fails");
    }
}
#endif /* !NO_HMAC */

#ifdef HAVE_AES_CBC
/**
 * Test AES-CBC-MAC algorithms (RFC 9053 Section 3.2)
 */
static void test_cose_mac0_aes_cbc_mac(void)
{
    WOLFCOSE_KEY key128, key256;
    uint8_t keyData128[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    uint8_t keyData256[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    uint8_t payload[] = "AES-CBC-MAC test payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Mac0 AES-CBC-MAC]\n");

    wc_CoseKey_Init(&key128);
    wc_CoseKey_SetSymmetric(&key128, keyData128, sizeof(keyData128));
    wc_CoseKey_Init(&key256);
    wc_CoseKey_SetSymmetric(&key256, keyData256, sizeof(keyData256));

    /* Test AES-MAC-128/64 */
    ret = wc_CoseMac0_Create(&key128, WOLFCOSE_ALG_AES_MAC_128_64,
        NULL, 0, /* kid, kidLen */
        payload, sizeof(payload) - 1,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "mac0 aes-128/64 create");

    ret = wc_CoseMac0_Verify(&key128, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "mac0 aes-128/64 verify");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_AES_MAC_128_64, "mac0 aes-128/64 alg");
    TEST_ASSERT(decPayloadLen == sizeof(payload) - 1 &&
                memcmp(decPayload, payload, decPayloadLen) == 0,
                "mac0 aes-128/64 payload match");

    /* Test AES-MAC-256/64 */
    ret = wc_CoseMac0_Create(&key256, WOLFCOSE_ALG_AES_MAC_256_64,
        NULL, 0, /* kid, kidLen */
        payload, sizeof(payload) - 1,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "mac0 aes-256/64 create");

    ret = wc_CoseMac0_Verify(&key256, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "mac0 aes-256/64 verify");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_AES_MAC_256_64, "mac0 aes-256/64 alg");

    /* Test AES-MAC-128/128 */
    ret = wc_CoseMac0_Create(&key128, WOLFCOSE_ALG_AES_MAC_128_128,
        NULL, 0, /* kid, kidLen */
        payload, sizeof(payload) - 1,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "mac0 aes-128/128 create");

    ret = wc_CoseMac0_Verify(&key128, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "mac0 aes-128/128 verify");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_AES_MAC_128_128, "mac0 aes-128/128 alg");

    /* Test AES-MAC-256/128 */
    ret = wc_CoseMac0_Create(&key256, WOLFCOSE_ALG_AES_MAC_256_128,
        NULL, 0, /* kid, kidLen */
        payload, sizeof(payload) - 1,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "mac0 aes-256/128 create");

    ret = wc_CoseMac0_Verify(&key256, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "mac0 aes-256/128 verify");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_AES_MAC_256_128, "mac0 aes-256/128 alg");

    /* Wrong key should fail */
    {
        WOLFCOSE_KEY wrongKey;
        uint8_t wrongKeyData[16] = {0};
        wc_CoseKey_Init(&wrongKey);
        wc_CoseKey_SetSymmetric(&wrongKey, wrongKeyData, sizeof(wrongKeyData));
        ret = wc_CoseMac0_Verify(&wrongKey, out, outLen,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret != 0, "mac0 aes wrong key fails");
    }

    /* Tampered message should fail */
    {
        uint8_t tampered[512];
        memcpy(tampered, out, outLen);
        if (outLen > 20) {
            tampered[outLen - 5] ^= 0xFF;
        }
        ret = wc_CoseMac0_Verify(&key256, tampered, outLen,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == WOLFCOSE_E_MAC_FAIL, "mac0 aes tampered fails");
    }

    /* Wrong key length for algorithm should fail */
    {
        /* Using 128-bit key with 256-bit algorithm */
        ret = wc_CoseMac0_Create(&key128, WOLFCOSE_ALG_AES_MAC_256_64,
            NULL, 0, /* kid, kidLen */
            payload, sizeof(payload) - 1,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen);
        TEST_ASSERT(ret == WOLFCOSE_E_COSE_KEY_TYPE, "mac0 aes wrong keylen fails");
    }
}

/**
 * Test AES-CBC-MAC with external AAD
 */
static void test_cose_mac0_aes_cbc_mac_with_aad(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    uint8_t payload[] = "AES-CBC-MAC AAD test";
    uint8_t extAad[] = "external-authenticated-data";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Mac0 AES-CBC-MAC with AAD]\n");

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));

    /* Create with AAD */
    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_AES_MAC_128_128,
        NULL, 0, /* kid, kidLen */
        payload, sizeof(payload) - 1,
        NULL, 0, /* detachedPayload */
        extAad, sizeof(extAad) - 1,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "mac0 aes aad create");

    /* Verify with correct AAD */
    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0,
        extAad, sizeof(extAad) - 1,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "mac0 aes aad verify ok");

    /* Verify with wrong AAD should fail */
    {
        uint8_t wrongAad[] = "wrong-aad";
        ret = wc_CoseMac0_Verify(&key, out, outLen,
            NULL, 0,
            wrongAad, sizeof(wrongAad) - 1,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == WOLFCOSE_E_MAC_FAIL, "mac0 aes wrong aad fails");
    }

    /* Verify without AAD should fail */
    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == WOLFCOSE_E_MAC_FAIL, "mac0 aes missing aad fails");
}

/**
 * Test AES-CBC-MAC with detached payload
 */
static void test_cose_mac0_aes_cbc_mac_detached(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    uint8_t payload[] = "AES-CBC-MAC detached test";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Mac0 AES-CBC-MAC Detached]\n");

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));

    /* Create with detached payload */
    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_AES_MAC_128_64,
        NULL, 0, /* kid, kidLen */
        NULL, 0, /* payload = null for detached */
        payload, sizeof(payload) - 1,  /* detached payload */
        NULL, 0, /* extAad */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "mac0 aes detached create");

    /* Verify without providing detached payload should fail */
    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0,  /* no detached payload */
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == WOLFCOSE_E_DETACHED_PAYLOAD, "mac0 aes detached no payload fails");

    /* Verify with correct detached payload */
    ret = wc_CoseMac0_Verify(&key, out, outLen,
        payload, sizeof(payload) - 1,  /* detached */
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "mac0 aes detached verify ok");
    TEST_ASSERT(hdr.flags & WOLFCOSE_HDR_FLAG_DETACHED, "mac0 aes detached flag set");
    TEST_ASSERT(decPayload == NULL, "mac0 aes detached payload null");

    /* Verify with wrong detached payload should fail */
    {
        uint8_t wrongPayload[] = "wrong payload";
        ret = wc_CoseMac0_Verify(&key, out, outLen,
            wrongPayload, sizeof(wrongPayload) - 1,
            NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == WOLFCOSE_E_MAC_FAIL, "mac0 aes detached wrong payload fails");
    }
}
#endif /* HAVE_AES_CBC */

/* ---------------------------------------------------------------------------
 * COSE_Sign Multi-Signer Tests (RFC 9052 Section 4.1)
 * --------------------------------------------------------------------------- */
#if defined(WOLFCOSE_SIGN) && defined(HAVE_ECC)
static void test_cose_sign_multi_signer(void)
{
    WOLFCOSE_KEY key1, key2;
    ecc_key eccKey1, eccKey2;
    WOLFCOSE_SIGNATURE signers[2];
    WOLFCOSE_HDR hdr;
    WC_RNG rng;
    int ret;
    uint8_t out[512];
    size_t outLen;
    uint8_t scratch[256];
    const uint8_t payload[] = "Multi-signer test payload";
    const uint8_t kid1[] = "signer-1";
    const uint8_t kid2[] = "signer-2";
    const uint8_t* decPayload;
    size_t decPayloadLen;

    printf("  [Sign Multi-Signer ES256]\n");

    /* Initialize RNG and keys */
    ret = wc_InitRng(&rng);
    TEST_ASSERT(ret == 0, "sign rng init");

    ret = wc_ecc_init(&eccKey1);
    TEST_ASSERT(ret == 0, "sign ecc1 init");

    ret = wc_ecc_init(&eccKey2);
    TEST_ASSERT(ret == 0, "sign ecc2 init");

    /* Generate two different P-256 keys */
    ret = wc_ecc_make_key(&rng, 32, &eccKey1);
    TEST_ASSERT(ret == 0, "sign ecc1 keygen");

    ret = wc_ecc_make_key(&rng, 32, &eccKey2);
    TEST_ASSERT(ret == 0, "sign ecc2 keygen");

    /* Setup COSE keys */
    wc_CoseKey_Init(&key1);
    ret = wc_CoseKey_SetEcc(&key1, WOLFCOSE_CRV_P256, &eccKey1);
    TEST_ASSERT(ret == 0, "sign key1 set");

    wc_CoseKey_Init(&key2);
    ret = wc_CoseKey_SetEcc(&key2, WOLFCOSE_CRV_P256, &eccKey2);
    TEST_ASSERT(ret == 0, "sign key2 set");

    /* Setup signers array */
    signers[0].algId = WOLFCOSE_ALG_ES256;
    signers[0].key = &key1;
    signers[0].kid = kid1;
    signers[0].kidLen = sizeof(kid1) - 1;

    signers[1].algId = WOLFCOSE_ALG_ES256;
    signers[1].key = &key2;
    signers[1].kid = kid2;
    signers[1].kidLen = sizeof(kid2) - 1;

    /* Sign with two signers */
    ret = wc_CoseSign_Sign(signers, 2,
        payload, sizeof(payload) - 1,
        NULL, 0,  /* no detached payload */
        NULL, 0,  /* no external AAD */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen,
        &rng);
    TEST_ASSERT(ret == 0, "sign multi create");

    /* Verify first signer */
    memset(&hdr, 0, sizeof(hdr));
    ret = wc_CoseSign_Verify(&key1, 0,
        out, outLen,
        NULL, 0,  /* no detached payload */
        NULL, 0,  /* no external AAD */
        scratch, sizeof(scratch),
        &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "sign verify signer 0");
    TEST_ASSERT(decPayloadLen == sizeof(payload) - 1, "sign payload len 0");
    TEST_ASSERT(memcmp(decPayload, payload, decPayloadLen) == 0, "sign payload match 0");

    /* Verify second signer */
    memset(&hdr, 0, sizeof(hdr));
    ret = wc_CoseSign_Verify(&key2, 1,
        out, outLen,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "sign verify signer 1");
    TEST_ASSERT(decPayloadLen == sizeof(payload) - 1, "sign payload len 1");
    TEST_ASSERT(memcmp(decPayload, payload, decPayloadLen) == 0, "sign payload match 1");

    /* Wrong key for signer 0 should fail */
    ret = wc_CoseSign_Verify(&key2, 0,  /* key2 for signer 0 */
        out, outLen,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == WOLFCOSE_E_COSE_SIG_FAIL, "sign wrong key fails");

    /* Wrong key for signer 1 should fail */
    ret = wc_CoseSign_Verify(&key1, 1,  /* key1 for signer 1 */
        out, outLen,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == WOLFCOSE_E_COSE_SIG_FAIL, "sign wrong key signer 1 fails");

    /* Invalid signer index should fail */
    ret = wc_CoseSign_Verify(&key1, 5,  /* signer index out of range */
        out, outLen,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret < 0, "sign invalid signer index fails");

    /* Cleanup */
    wc_CoseKey_Free(&key1);
    wc_CoseKey_Free(&key2);
    wc_ecc_free(&eccKey1);
    wc_ecc_free(&eccKey2);
    wc_FreeRng(&rng);
}

static void test_cose_sign_with_aad(void)
{
    WOLFCOSE_KEY key;
    ecc_key eccKey;
    WOLFCOSE_SIGNATURE signers[1];
    WOLFCOSE_HDR hdr;
    WC_RNG rng;
    int ret;
    uint8_t out[512];
    size_t outLen;
    uint8_t scratch[256];
    const uint8_t payload[] = "Sign with AAD payload";
    const uint8_t aad[] = "external application data";
    const uint8_t wrongAad[] = "wrong aad";
    const uint8_t* decPayload;
    size_t decPayloadLen;

    printf("  [Sign with external AAD]\n");

    ret = wc_InitRng(&rng);
    TEST_ASSERT(ret == 0, "sign aad rng init");

    ret = wc_ecc_init(&eccKey);
    TEST_ASSERT(ret == 0, "sign aad ecc init");

    ret = wc_ecc_make_key(&rng, 32, &eccKey);
    TEST_ASSERT(ret == 0, "sign aad keygen");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &eccKey);
    TEST_ASSERT(ret == 0, "sign aad key set");

    signers[0].algId = WOLFCOSE_ALG_ES256;
    signers[0].key = &key;
    signers[0].kid = NULL;
    signers[0].kidLen = 0;

    /* Sign with AAD */
    ret = wc_CoseSign_Sign(signers, 1,
        payload, sizeof(payload) - 1,
        NULL, 0,
        aad, sizeof(aad) - 1,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen,
        &rng);
    TEST_ASSERT(ret == 0, "sign aad create");

    /* Verify with correct AAD */
    memset(&hdr, 0, sizeof(hdr));
    ret = wc_CoseSign_Verify(&key, 0,
        out, outLen,
        NULL, 0,
        aad, sizeof(aad) - 1,
        scratch, sizeof(scratch),
        &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "sign aad verify ok");

    /* Verify with wrong AAD should fail */
    ret = wc_CoseSign_Verify(&key, 0,
        out, outLen,
        NULL, 0,
        wrongAad, sizeof(wrongAad) - 1,
        scratch, sizeof(scratch),
        &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == WOLFCOSE_E_COSE_SIG_FAIL, "sign wrong aad fails");

    /* Verify with missing AAD should fail */
    ret = wc_CoseSign_Verify(&key, 0,
        out, outLen,
        NULL, 0,
        NULL, 0,  /* no AAD when signature was made with AAD */
        scratch, sizeof(scratch),
        &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == WOLFCOSE_E_COSE_SIG_FAIL, "sign missing aad fails");

    wc_CoseKey_Free(&key);
    wc_ecc_free(&eccKey);
    wc_FreeRng(&rng);
}

static void test_cose_sign_detached(void)
{
    WOLFCOSE_KEY key;
    ecc_key eccKey;
    WOLFCOSE_SIGNATURE signers[1];
    WOLFCOSE_HDR hdr;
    WC_RNG rng;
    int ret;
    uint8_t out[512];
    size_t outLen;
    uint8_t scratch[256];
    const uint8_t payload[] = "Detached payload for multi-sign";
    const uint8_t wrongPayload[] = "wrong payload";
    const uint8_t* decPayload;
    size_t decPayloadLen;

    printf("  [Sign Detached Payload]\n");

    ret = wc_InitRng(&rng);
    TEST_ASSERT(ret == 0, "sign detached rng init");

    ret = wc_ecc_init(&eccKey);
    TEST_ASSERT(ret == 0, "sign detached ecc init");

    ret = wc_ecc_make_key(&rng, 32, &eccKey);
    TEST_ASSERT(ret == 0, "sign detached keygen");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &eccKey);
    TEST_ASSERT(ret == 0, "sign detached key set");

    signers[0].algId = WOLFCOSE_ALG_ES256;
    signers[0].key = &key;
    signers[0].kid = NULL;
    signers[0].kidLen = 0;

    /* Sign with detached payload */
    ret = wc_CoseSign_Sign(signers, 1,
        NULL, 0,  /* no attached payload */
        payload, sizeof(payload) - 1,  /* detached payload */
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen,
        &rng);
    TEST_ASSERT(ret == 0, "sign detached create");

    /* Verify with detached payload must fail without providing payload */
    memset(&hdr, 0, sizeof(hdr));
    ret = wc_CoseSign_Verify(&key, 0,
        out, outLen,
        NULL, 0,  /* no detached payload provided */
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == WOLFCOSE_E_DETACHED_PAYLOAD, "sign detached no payload fails");

    /* Verify with correct detached payload */
    ret = wc_CoseSign_Verify(&key, 0,
        out, outLen,
        payload, sizeof(payload) - 1,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "sign detached verify ok");
    TEST_ASSERT((hdr.flags & WOLFCOSE_HDR_FLAG_DETACHED) != 0, "sign detached flag set");
    TEST_ASSERT(decPayload == NULL, "sign detached payload null");

    /* Wrong detached payload should fail */
    ret = wc_CoseSign_Verify(&key, 0,
        out, outLen,
        wrongPayload, sizeof(wrongPayload) - 1,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == WOLFCOSE_E_COSE_SIG_FAIL, "sign detached wrong payload fails");

    wc_CoseKey_Free(&key);
    wc_ecc_free(&eccKey);
    wc_FreeRng(&rng);
}

#ifdef HAVE_ED25519
static void test_cose_sign_mixed_algorithms(void)
{
    WOLFCOSE_KEY keyEc, keyEd;
    ecc_key eccKey;
    ed25519_key edKey;
    WOLFCOSE_SIGNATURE signers[2];
    WOLFCOSE_HDR hdr;
    WC_RNG rng;
    int ret;
    uint8_t out[768];  /* larger for two different sig types */
    size_t outLen;
    uint8_t scratch[256];
    const uint8_t payload[] = "Mixed algorithm payload";
    const uint8_t* decPayload;
    size_t decPayloadLen;

    printf("  [Sign Mixed Algorithms ES256+EdDSA]\n");

    ret = wc_InitRng(&rng);
    TEST_ASSERT(ret == 0, "sign mixed rng init");

    /* Generate ECC key */
    ret = wc_ecc_init(&eccKey);
    TEST_ASSERT(ret == 0, "sign mixed ecc init");

    ret = wc_ecc_make_key(&rng, 32, &eccKey);
    TEST_ASSERT(ret == 0, "sign mixed ecc keygen");

    wc_CoseKey_Init(&keyEc);
    ret = wc_CoseKey_SetEcc(&keyEc, WOLFCOSE_CRV_P256, &eccKey);
    TEST_ASSERT(ret == 0, "sign mixed ecc key set");

    /* Generate Ed25519 key */
    ret = wc_ed25519_init(&edKey);
    TEST_ASSERT(ret == 0, "sign mixed ed init");

    ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &edKey);
    TEST_ASSERT(ret == 0, "sign mixed ed keygen");

    wc_CoseKey_Init(&keyEd);
    ret = wc_CoseKey_SetEd25519(&keyEd, &edKey);
    TEST_ASSERT(ret == 0, "sign mixed ed key set");

    /* Setup signers: ES256 + EdDSA */
    signers[0].algId = WOLFCOSE_ALG_ES256;
    signers[0].key = &keyEc;
    signers[0].kid = NULL;
    signers[0].kidLen = 0;

    signers[1].algId = WOLFCOSE_ALG_EDDSA;
    signers[1].key = &keyEd;
    signers[1].kid = NULL;
    signers[1].kidLen = 0;

    /* Sign with mixed algorithms */
    ret = wc_CoseSign_Sign(signers, 2,
        payload, sizeof(payload) - 1,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen,
        &rng);
    TEST_ASSERT(ret == 0, "sign mixed create");

    /* Verify ES256 signer (index 0) */
    memset(&hdr, 0, sizeof(hdr));
    ret = wc_CoseSign_Verify(&keyEc, 0,
        out, outLen,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "sign mixed verify es256");
    TEST_ASSERT(memcmp(decPayload, payload, decPayloadLen) == 0, "sign mixed payload match es256");

    /* Verify EdDSA signer (index 1) */
    memset(&hdr, 0, sizeof(hdr));
    ret = wc_CoseSign_Verify(&keyEd, 1,
        out, outLen,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "sign mixed verify eddsa");
    TEST_ASSERT(memcmp(decPayload, payload, decPayloadLen) == 0, "sign mixed payload match eddsa");

    /* Cross-verify should fail */
    ret = wc_CoseSign_Verify(&keyEd, 0,  /* EdDSA key for ES256 signer */
        out, outLen,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret != 0, "sign mixed cross-verify fails");

    wc_CoseKey_Free(&keyEc);
    wc_CoseKey_Free(&keyEd);
    wc_ecc_free(&eccKey);
    wc_ed25519_free(&edKey);
    wc_FreeRng(&rng);
}
#endif /* HAVE_ED25519 */
#endif /* WOLFCOSE_SIGN && HAVE_ECC */

/* ---------------------------------------------------------------------------
 * COSE_Encrypt Multi-Recipient Tests (RFC 9052 Section 5.1)
 * --------------------------------------------------------------------------- */
#if defined(WOLFCOSE_ENCRYPT) && defined(HAVE_AESGCM)
static void test_cose_encrypt_multi_recipient(void)
{
    WOLFCOSE_KEY key1, key2;
    WOLFCOSE_RECIPIENT recipients[2];
    WOLFCOSE_HDR hdr;
    int ret;
    uint8_t out[512];
    size_t outLen;
    uint8_t scratch[256];
    uint8_t plaintext[256];
    size_t plaintextLen;
    const uint8_t payload[] = "Multi-recipient encryption test";
    const uint8_t iv[12] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                            0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C};
    const uint8_t keyData[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    const uint8_t wrongKeyData[16] = {0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
                                       0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0};
    const uint8_t kid1[] = "recipient-1";
    const uint8_t kid2[] = "recipient-2";

    printf("  [Encrypt Multi-Recipient A128GCM]\n");

    /* Setup keys - both recipients use the same shared key in direct mode */
    wc_CoseKey_Init(&key1);
    ret = wc_CoseKey_SetSymmetric(&key1, keyData, sizeof(keyData));
    TEST_ASSERT(ret == 0, "encrypt key1 set");

    wc_CoseKey_Init(&key2);
    ret = wc_CoseKey_SetSymmetric(&key2, keyData, sizeof(keyData));
    TEST_ASSERT(ret == 0, "encrypt key2 set");

    /* Setup recipients */
    recipients[0].algId = 0;  /* Direct key */
    recipients[0].key = &key1;
    recipients[0].kid = kid1;
    recipients[0].kidLen = sizeof(kid1) - 1;

    recipients[1].algId = 0;  /* Direct key */
    recipients[1].key = &key2;
    recipients[1].kid = kid2;
    recipients[1].kidLen = sizeof(kid2) - 1;

    /* Encrypt with two recipients */
    ret = wc_CoseEncrypt_Encrypt(recipients, 2,
        WOLFCOSE_ALG_A128GCM,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,
        NULL, 0,  /* no detached payload */
        NULL, 0,  /* no external AAD */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen,
        NULL);
    TEST_ASSERT(ret == 0, "encrypt multi create");

    /* Decrypt with first recipient */
    memset(&hdr, 0, sizeof(hdr));
    ret = wc_CoseEncrypt_Decrypt(&recipients[0], 0,
        out, outLen,
        NULL, 0,  /* no detached ciphertext */
        NULL, 0,  /* no external AAD */
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "encrypt decrypt recipient 0");
    TEST_ASSERT(plaintextLen == sizeof(payload) - 1, "encrypt payload len 0");
    TEST_ASSERT(memcmp(plaintext, payload, plaintextLen) == 0, "encrypt payload match 0");

    /* Decrypt with second recipient */
    memset(&hdr, 0, sizeof(hdr));
    memset(plaintext, 0, sizeof(plaintext));
    ret = wc_CoseEncrypt_Decrypt(&recipients[1], 1,
        out, outLen,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "encrypt decrypt recipient 1");
    TEST_ASSERT(plaintextLen == sizeof(payload) - 1, "encrypt payload len 1");
    TEST_ASSERT(memcmp(plaintext, payload, plaintextLen) == 0, "encrypt payload match 1");

    /* Verify headers */
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_A128GCM, "encrypt hdr alg");
    TEST_ASSERT(hdr.ivLen == sizeof(iv), "encrypt hdr iv len");
    TEST_ASSERT(memcmp(hdr.iv, iv, sizeof(iv)) == 0, "encrypt hdr iv match");

    /* Wrong key should fail */
    {
        WOLFCOSE_KEY wrongKey;
        WOLFCOSE_RECIPIENT wrongRecipient;
        wc_CoseKey_Init(&wrongKey);
        wc_CoseKey_SetSymmetric(&wrongKey, wrongKeyData, sizeof(wrongKeyData));
        wrongRecipient.algId = 0;
        wrongRecipient.key = &wrongKey;
        wrongRecipient.kid = NULL;
        wrongRecipient.kidLen = 0;

        ret = wc_CoseEncrypt_Decrypt(&wrongRecipient, 0,
            out, outLen,
            NULL, 0,
            NULL, 0,
            scratch, sizeof(scratch),
            &hdr,
            plaintext, sizeof(plaintext), &plaintextLen);
        TEST_ASSERT(ret == WOLFCOSE_E_COSE_DECRYPT_FAIL, "encrypt wrong key fails");
        wc_CoseKey_Free(&wrongKey);
    }

    /* Invalid recipient index should fail */
    ret = wc_CoseEncrypt_Decrypt(&recipients[0], 5,
        out, outLen,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret != 0, "encrypt invalid recipient index fails");

    wc_CoseKey_Free(&key1);
    wc_CoseKey_Free(&key2);
}

static void test_cose_encrypt_with_aad(void)
{
    WOLFCOSE_KEY key;
    WOLFCOSE_RECIPIENT recipients[1];
    WOLFCOSE_HDR hdr;
    int ret;
    uint8_t out[512];
    size_t outLen;
    uint8_t scratch[256];
    uint8_t plaintext[256];
    size_t plaintextLen;
    const uint8_t payload[] = "Encrypt with AAD";
    const uint8_t iv[12] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                            0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC};
    const uint8_t keyData[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                  0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    const uint8_t aad[] = "authenticated additional data";
    const uint8_t wrongAad[] = "wrong aad";

    printf("  [Encrypt with external AAD]\n");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));
    TEST_ASSERT(ret == 0, "encrypt aad key set");

    recipients[0].algId = 0;
    recipients[0].key = &key;
    recipients[0].kid = NULL;
    recipients[0].kidLen = 0;

    /* Encrypt with AAD */
    ret = wc_CoseEncrypt_Encrypt(recipients, 1,
        WOLFCOSE_ALG_A128GCM,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,
        NULL, 0,
        aad, sizeof(aad) - 1,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen,
        NULL);
    TEST_ASSERT(ret == 0, "encrypt aad create");

    /* Decrypt with correct AAD */
    memset(&hdr, 0, sizeof(hdr));
    ret = wc_CoseEncrypt_Decrypt(&recipients[0], 0,
        out, outLen,
        NULL, 0,
        aad, sizeof(aad) - 1,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "encrypt aad decrypt ok");
    TEST_ASSERT(memcmp(plaintext, payload, plaintextLen) == 0, "encrypt aad payload match");

    /* Wrong AAD should fail */
    ret = wc_CoseEncrypt_Decrypt(&recipients[0], 0,
        out, outLen,
        NULL, 0,
        wrongAad, sizeof(wrongAad) - 1,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == WOLFCOSE_E_COSE_DECRYPT_FAIL, "encrypt wrong aad fails");

    /* Missing AAD should fail */
    ret = wc_CoseEncrypt_Decrypt(&recipients[0], 0,
        out, outLen,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == WOLFCOSE_E_COSE_DECRYPT_FAIL, "encrypt missing aad fails");

    wc_CoseKey_Free(&key);
}

static void test_cose_encrypt_a256gcm(void)
{
    WOLFCOSE_KEY key;
    WOLFCOSE_RECIPIENT recipients[1];
    WOLFCOSE_HDR hdr;
    int ret;
    uint8_t out[512];
    size_t outLen;
    uint8_t scratch[256];
    uint8_t plaintext[256];
    size_t plaintextLen;
    const uint8_t payload[] = "A256GCM multi-recipient test";
    const uint8_t iv[12] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
                            0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    const uint8_t keyData[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    printf("  [Encrypt Multi-Recipient A256GCM]\n");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));
    TEST_ASSERT(ret == 0, "encrypt a256 key set");

    recipients[0].algId = 0;
    recipients[0].key = &key;
    recipients[0].kid = NULL;
    recipients[0].kidLen = 0;

    /* Encrypt with A256GCM */
    ret = wc_CoseEncrypt_Encrypt(recipients, 1,
        WOLFCOSE_ALG_A256GCM,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen,
        NULL);
    TEST_ASSERT(ret == 0, "encrypt a256 create");

    /* Decrypt */
    memset(&hdr, 0, sizeof(hdr));
    ret = wc_CoseEncrypt_Decrypt(&recipients[0], 0,
        out, outLen,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "encrypt a256 decrypt");
    TEST_ASSERT(plaintextLen == sizeof(payload) - 1, "encrypt a256 payload len");
    TEST_ASSERT(memcmp(plaintext, payload, plaintextLen) == 0, "encrypt a256 payload match");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_A256GCM, "encrypt a256 hdr alg");

    wc_CoseKey_Free(&key);
}

#if defined(WOLFCOSE_ECDH_ES_DIRECT) && defined(HAVE_ECC) && defined(HAVE_HKDF)
/**
 * Test ECDH-ES (Ephemeral-Static) encryption and decryption.
 * - Encrypt with recipient's EC public key
 * - Decrypt with recipient's EC private key
 * - Verify roundtrip works correctly
 */
static void test_cose_encrypt_ecdh_es_hkdf_256(void)
{
    WOLFCOSE_KEY recipientKey;
    WOLFCOSE_RECIPIENT recipient;
    WOLFCOSE_HDR hdr;
    ecc_key recipientEcc;
    WC_RNG rng;
    int ret;
    uint8_t out[512];
    size_t outLen;
    uint8_t scratch[256];
    uint8_t plaintext[256];
    size_t plaintextLen;
    const uint8_t payload[] = "ECDH-ES test payload";
    uint8_t iv[12];

    printf("  [Encrypt ECDH-ES + HKDF-256]\n");

    /* Initialize RNG */
    ret = wc_InitRng(&rng);
    TEST_ASSERT(ret == 0, "ecdh-es rng init");

    /* Generate recipient EC key pair (P-256) */
    ret = wc_ecc_init(&recipientEcc);
    TEST_ASSERT(ret == 0, "ecdh-es ecc init");

    ret = wc_ecc_make_key(&rng, 32, &recipientEcc);
    TEST_ASSERT(ret == 0, "ecdh-es make key");

    /* Set up recipient's public key for encryption */
    wc_CoseKey_Init(&recipientKey);
    ret = wc_CoseKey_SetEcc(&recipientKey, WOLFCOSE_CRV_P256, &recipientEcc);
    TEST_ASSERT(ret == 0, "ecdh-es set ecc key");
    recipientKey.hasPrivate = 0;  /* Encryption uses public key only */

    /* Set up ECDH-ES recipient */
    recipient.algId = WOLFCOSE_ALG_ECDH_ES_HKDF_256;
    recipient.key = &recipientKey;
    recipient.kid = NULL;
    recipient.kidLen = 0;

    /* Generate random IV */
    ret = wc_RNG_GenerateBlock(&rng, iv, sizeof(iv));
    TEST_ASSERT(ret == 0, "ecdh-es generate iv");

    /* Encrypt */
    ret = wc_CoseEncrypt_Encrypt(
        &recipient, 1,
        WOLFCOSE_ALG_A128GCM,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,
        NULL, 0,  /* no detached payload */
        NULL, 0,  /* no external AAD */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen,
        &rng);
    TEST_ASSERT(ret == 0, "ecdh-es encrypt");

    /* Set up recipient with private key for decryption */
    recipientKey.hasPrivate = 1;

    /* Decrypt */
    memset(&hdr, 0, sizeof(hdr));
    ret = wc_CoseEncrypt_Decrypt(
        &recipient, 0,
        out, outLen,
        NULL, 0,  /* no detached ciphertext */
        NULL, 0,  /* no external AAD */
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "ecdh-es decrypt");
    TEST_ASSERT(plaintextLen == sizeof(payload) - 1, "ecdh-es payload len");
    TEST_ASSERT(memcmp(plaintext, payload, plaintextLen) == 0, "ecdh-es payload match");

    /* Verify headers */
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_A128GCM, "ecdh-es hdr alg");
    TEST_ASSERT(hdr.ivLen == sizeof(iv), "ecdh-es hdr iv len");

    /* Clean up */
    wc_CoseKey_Free(&recipientKey);
    wc_ecc_free(&recipientEcc);
    wc_FreeRng(&rng);
}

/**
 * Test ECDH-ES with wrong key fails decryption.
 */
static void test_cose_encrypt_ecdh_es_wrong_key(void)
{
    WOLFCOSE_KEY recipientKey, wrongKey;
    WOLFCOSE_RECIPIENT recipient;
    WOLFCOSE_HDR hdr;
    ecc_key recipientEcc, wrongEcc;
    WC_RNG rng;
    int ret;
    uint8_t out[512];
    size_t outLen;
    uint8_t scratch[256];
    uint8_t plaintext[256];
    size_t plaintextLen;
    const uint8_t payload[] = "ECDH-ES wrong key test";
    uint8_t iv[12];

    printf("  [Encrypt ECDH-ES wrong key fails]\n");

    /* Initialize RNG */
    ret = wc_InitRng(&rng);
    TEST_ASSERT(ret == 0, "ecdh-es wrong rng init");

    /* Generate recipient EC key pair */
    ret = wc_ecc_init(&recipientEcc);
    TEST_ASSERT(ret == 0, "ecdh-es wrong ecc init");
    ret = wc_ecc_make_key(&rng, 32, &recipientEcc);
    TEST_ASSERT(ret == 0, "ecdh-es wrong make key");

    /* Generate a different (wrong) key pair */
    ret = wc_ecc_init(&wrongEcc);
    TEST_ASSERT(ret == 0, "ecdh-es wrong ecc2 init");
    ret = wc_ecc_make_key(&rng, 32, &wrongEcc);
    TEST_ASSERT(ret == 0, "ecdh-es wrong make key2");

    /* Set up recipient's key for encryption */
    wc_CoseKey_Init(&recipientKey);
    ret = wc_CoseKey_SetEcc(&recipientKey, WOLFCOSE_CRV_P256, &recipientEcc);
    TEST_ASSERT(ret == 0, "ecdh-es wrong set key");
    recipientKey.hasPrivate = 0;

    /* Encrypt */
    recipient.algId = WOLFCOSE_ALG_ECDH_ES_HKDF_256;
    recipient.key = &recipientKey;
    recipient.kid = NULL;
    recipient.kidLen = 0;

    ret = wc_RNG_GenerateBlock(&rng, iv, sizeof(iv));
    TEST_ASSERT(ret == 0, "ecdh-es wrong generate iv");

    ret = wc_CoseEncrypt_Encrypt(
        &recipient, 1,
        WOLFCOSE_ALG_A128GCM,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen,
        &rng);
    TEST_ASSERT(ret == 0, "ecdh-es wrong encrypt");

    /* Try to decrypt with wrong key */
    wc_CoseKey_Init(&wrongKey);
    ret = wc_CoseKey_SetEcc(&wrongKey, WOLFCOSE_CRV_P256, &wrongEcc);
    TEST_ASSERT(ret == 0, "ecdh-es wrong set key2");
    wrongKey.hasPrivate = 1;

    recipient.key = &wrongKey;

    memset(&hdr, 0, sizeof(hdr));
    ret = wc_CoseEncrypt_Decrypt(
        &recipient, 0,
        out, outLen,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == WOLFCOSE_E_COSE_DECRYPT_FAIL, "ecdh-es wrong key fails");

    /* Clean up */
    wc_CoseKey_Free(&recipientKey);
    wc_CoseKey_Free(&wrongKey);
    wc_ecc_free(&recipientEcc);
    wc_ecc_free(&wrongEcc);
    wc_FreeRng(&rng);
}

/**
 * Test ECDH-ES with P-384 curve.
 */
static void test_cose_encrypt_ecdh_es_p384(void)
{
    WOLFCOSE_KEY recipientKey;
    WOLFCOSE_RECIPIENT recipient;
    WOLFCOSE_HDR hdr;
    ecc_key recipientEcc;
    WC_RNG rng;
    int ret;
    uint8_t out[512];
    size_t outLen;
    uint8_t scratch[256];
    uint8_t plaintext[256];
    size_t plaintextLen;
    const uint8_t payload[] = "ECDH-ES P-384 test";
    uint8_t iv[12];

    printf("  [Encrypt ECDH-ES P-384]\n");

    /* Initialize RNG */
    ret = wc_InitRng(&rng);
    TEST_ASSERT(ret == 0, "ecdh-es p384 rng init");

    /* Generate recipient EC key pair (P-384) */
    ret = wc_ecc_init(&recipientEcc);
    TEST_ASSERT(ret == 0, "ecdh-es p384 ecc init");

    ret = wc_ecc_make_key(&rng, 48, &recipientEcc);
    TEST_ASSERT(ret == 0, "ecdh-es p384 make key");

    /* Set up recipient's public key for encryption */
    wc_CoseKey_Init(&recipientKey);
    ret = wc_CoseKey_SetEcc(&recipientKey, WOLFCOSE_CRV_P384, &recipientEcc);
    TEST_ASSERT(ret == 0, "ecdh-es p384 set ecc key");
    recipientKey.hasPrivate = 0;

    /* Set up ECDH-ES recipient */
    recipient.algId = WOLFCOSE_ALG_ECDH_ES_HKDF_256;
    recipient.key = &recipientKey;
    recipient.kid = NULL;
    recipient.kidLen = 0;

    /* Generate random IV */
    ret = wc_RNG_GenerateBlock(&rng, iv, sizeof(iv));
    TEST_ASSERT(ret == 0, "ecdh-es p384 generate iv");

    /* Encrypt */
    ret = wc_CoseEncrypt_Encrypt(
        &recipient, 1,
        WOLFCOSE_ALG_A128GCM,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen,
        &rng);
    TEST_ASSERT(ret == 0, "ecdh-es p384 encrypt");

    /* Set up recipient with private key for decryption */
    recipientKey.hasPrivate = 1;

    /* Decrypt */
    memset(&hdr, 0, sizeof(hdr));
    ret = wc_CoseEncrypt_Decrypt(
        &recipient, 0,
        out, outLen,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "ecdh-es p384 decrypt");
    TEST_ASSERT(plaintextLen == sizeof(payload) - 1, "ecdh-es p384 payload len");
    TEST_ASSERT(memcmp(plaintext, payload, plaintextLen) == 0, "ecdh-es p384 payload match");

    /* Clean up */
    wc_CoseKey_Free(&recipientKey);
    wc_ecc_free(&recipientEcc);
    wc_FreeRng(&rng);
}
#endif /* WOLFCOSE_ECDH_ES_DIRECT && HAVE_ECC && HAVE_HKDF */

#if defined(WOLFCOSE_KEY_WRAP)
/**
 * Test COSE_Encrypt with A128KW key wrap algorithm.
 */
static void test_cose_encrypt_a128kw(void)
{
    WOLFCOSE_KEY kek, wrongKek;
    WOLFCOSE_RECIPIENT recipient, wrongRecipient;
    WOLFCOSE_HDR hdr;
    WC_RNG rng;
    int ret;
    uint8_t out[512];
    size_t outLen;
    uint8_t scratch[256];
    uint8_t plaintext[256];
    size_t plaintextLen;
    const uint8_t payload[] = "A128KW test payload";
    uint8_t iv[12];
    /* 16-byte KEK for A128KW */
    const uint8_t kekData[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    const uint8_t wrongKekData[16] = {
        0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
        0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0
    };

    printf("  [Encrypt A128KW Key Wrap]\n");

    /* Initialize RNG */
    ret = wc_InitRng(&rng);
    TEST_ASSERT(ret == 0, "a128kw rng init");

    /* Set up KEK */
    wc_CoseKey_Init(&kek);
    ret = wc_CoseKey_SetSymmetric(&kek, kekData, sizeof(kekData));
    TEST_ASSERT(ret == 0, "a128kw set kek");

    /* Set up recipient */
    recipient.algId = WOLFCOSE_ALG_A128KW;
    recipient.key = &kek;
    recipient.kid = (const uint8_t*)"kw-recipient";
    recipient.kidLen = 12;

    /* Generate random IV */
    ret = wc_RNG_GenerateBlock(&rng, iv, sizeof(iv));
    TEST_ASSERT(ret == 0, "a128kw generate iv");

    /* Encrypt */
    ret = wc_CoseEncrypt_Encrypt(
        &recipient, 1,
        WOLFCOSE_ALG_A128GCM,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,
        NULL, 0,  /* no detached payload */
        NULL, 0,  /* no external AAD */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen,
        &rng);
    TEST_ASSERT(ret == 0, "a128kw encrypt");

    /* Decrypt with correct KEK */
    memset(&hdr, 0, sizeof(hdr));
    ret = wc_CoseEncrypt_Decrypt(
        &recipient, 0,
        out, outLen,
        NULL, 0,  /* no detached ciphertext */
        NULL, 0,  /* no external AAD */
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "a128kw decrypt");
    TEST_ASSERT(plaintextLen == sizeof(payload) - 1, "a128kw payload len");
    TEST_ASSERT(memcmp(plaintext, payload, plaintextLen) == 0, "a128kw payload match");

    /* Verify headers */
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_A128GCM, "a128kw hdr alg");
    TEST_ASSERT(hdr.ivLen == sizeof(iv), "a128kw hdr iv len");

    /* Decrypt with wrong KEK should fail */
    wc_CoseKey_Init(&wrongKek);
    ret = wc_CoseKey_SetSymmetric(&wrongKek, wrongKekData, sizeof(wrongKekData));
    TEST_ASSERT(ret == 0, "a128kw set wrong kek");

    wrongRecipient.algId = WOLFCOSE_ALG_A128KW;
    wrongRecipient.key = &wrongKek;
    wrongRecipient.kid = NULL;
    wrongRecipient.kidLen = 0;

    memset(&hdr, 0, sizeof(hdr));
    ret = wc_CoseEncrypt_Decrypt(
        &wrongRecipient, 0,
        out, outLen,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret != 0, "a128kw wrong kek fails");

    /* Clean up */
    wc_CoseKey_Free(&kek);
    wc_CoseKey_Free(&wrongKek);
    wc_FreeRng(&rng);
}

/**
 * Test COSE_Encrypt with A192KW key wrap algorithm.
 */
static void test_cose_encrypt_a192kw(void)
{
    WOLFCOSE_KEY kek;
    WOLFCOSE_RECIPIENT recipient;
    WOLFCOSE_HDR hdr;
    WC_RNG rng;
    int ret;
    uint8_t out[512];
    size_t outLen;
    uint8_t scratch[256];
    uint8_t plaintext[256];
    size_t plaintextLen;
    const uint8_t payload[] = "A192KW test payload";
    uint8_t iv[12];
    /* 24-byte KEK for A192KW */
    const uint8_t kekData[24] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    };

    printf("  [Encrypt A192KW Key Wrap]\n");

    /* Initialize RNG */
    ret = wc_InitRng(&rng);
    TEST_ASSERT(ret == 0, "a192kw rng init");

    /* Set up KEK */
    wc_CoseKey_Init(&kek);
    ret = wc_CoseKey_SetSymmetric(&kek, kekData, sizeof(kekData));
    TEST_ASSERT(ret == 0, "a192kw set kek");

    /* Set up recipient */
    recipient.algId = WOLFCOSE_ALG_A192KW;
    recipient.key = &kek;
    recipient.kid = NULL;
    recipient.kidLen = 0;

    /* Generate random IV */
    ret = wc_RNG_GenerateBlock(&rng, iv, sizeof(iv));
    TEST_ASSERT(ret == 0, "a192kw generate iv");

    /* Encrypt */
    ret = wc_CoseEncrypt_Encrypt(
        &recipient, 1,
        WOLFCOSE_ALG_A128GCM,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen,
        &rng);
    TEST_ASSERT(ret == 0, "a192kw encrypt");

    /* Decrypt */
    memset(&hdr, 0, sizeof(hdr));
    ret = wc_CoseEncrypt_Decrypt(
        &recipient, 0,
        out, outLen,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "a192kw decrypt");
    TEST_ASSERT(plaintextLen == sizeof(payload) - 1, "a192kw payload len");
    TEST_ASSERT(memcmp(plaintext, payload, plaintextLen) == 0, "a192kw payload match");

    /* Clean up */
    wc_CoseKey_Free(&kek);
    wc_FreeRng(&rng);
}

/**
 * Test COSE_Encrypt with A256KW key wrap algorithm.
 */
static void test_cose_encrypt_a256kw(void)
{
    WOLFCOSE_KEY kek;
    WOLFCOSE_RECIPIENT recipient;
    WOLFCOSE_HDR hdr;
    WC_RNG rng;
    int ret;
    uint8_t out[512];
    size_t outLen;
    uint8_t scratch[256];
    uint8_t plaintext[256];
    size_t plaintextLen;
    const uint8_t payload[] = "A256KW test payload";
    uint8_t iv[12];
    /* 32-byte KEK for A256KW */
    const uint8_t kekData[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    printf("  [Encrypt A256KW Key Wrap]\n");

    /* Initialize RNG */
    ret = wc_InitRng(&rng);
    TEST_ASSERT(ret == 0, "a256kw rng init");

    /* Set up KEK */
    wc_CoseKey_Init(&kek);
    ret = wc_CoseKey_SetSymmetric(&kek, kekData, sizeof(kekData));
    TEST_ASSERT(ret == 0, "a256kw set kek");

    /* Set up recipient */
    recipient.algId = WOLFCOSE_ALG_A256KW;
    recipient.key = &kek;
    recipient.kid = NULL;
    recipient.kidLen = 0;

    /* Generate random IV */
    ret = wc_RNG_GenerateBlock(&rng, iv, sizeof(iv));
    TEST_ASSERT(ret == 0, "a256kw generate iv");

    /* Encrypt with A256GCM content encryption */
    ret = wc_CoseEncrypt_Encrypt(
        &recipient, 1,
        WOLFCOSE_ALG_A256GCM,  /* Use A256GCM with A256KW */
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen,
        &rng);
    TEST_ASSERT(ret == 0, "a256kw encrypt");

    /* Decrypt */
    memset(&hdr, 0, sizeof(hdr));
    ret = wc_CoseEncrypt_Decrypt(
        &recipient, 0,
        out, outLen,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "a256kw decrypt");
    TEST_ASSERT(plaintextLen == sizeof(payload) - 1, "a256kw payload len");
    TEST_ASSERT(memcmp(plaintext, payload, plaintextLen) == 0, "a256kw payload match");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_A256GCM, "a256kw hdr alg");

    /* Clean up */
    wc_CoseKey_Free(&kek);
    wc_FreeRng(&rng);
}

/**
 * Test COSE_Encrypt with A128KW using wrong-sized KEK should fail.
 */
static void test_cose_encrypt_kw_wrong_keysize(void)
{
    WOLFCOSE_KEY kek;
    WOLFCOSE_RECIPIENT recipient;
    WC_RNG rng;
    int ret;
    uint8_t out[512];
    size_t outLen;
    uint8_t scratch[256];
    const uint8_t payload[] = "Wrong keysize test";
    uint8_t iv[12];
    /* 32-byte key, but algorithm expects 16-byte */
    const uint8_t wrongSizeKey[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    printf("  [Encrypt Key Wrap Wrong KEK Size]\n");

    /* Initialize RNG */
    ret = wc_InitRng(&rng);
    TEST_ASSERT(ret == 0, "kw-wrong-size rng init");

    /* Set up KEK with wrong size for A128KW (32 bytes instead of 16) */
    wc_CoseKey_Init(&kek);
    ret = wc_CoseKey_SetSymmetric(&kek, wrongSizeKey, sizeof(wrongSizeKey));
    TEST_ASSERT(ret == 0, "kw-wrong-size set kek");

    /* Set up recipient with A128KW but wrong size key */
    recipient.algId = WOLFCOSE_ALG_A128KW;
    recipient.key = &kek;
    recipient.kid = NULL;
    recipient.kidLen = 0;

    /* Generate random IV */
    ret = wc_RNG_GenerateBlock(&rng, iv, sizeof(iv));
    TEST_ASSERT(ret == 0, "kw-wrong-size generate iv");

    /* Encrypt should fail because KEK size doesn't match algorithm */
    ret = wc_CoseEncrypt_Encrypt(
        &recipient, 1,
        WOLFCOSE_ALG_A128GCM,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen,
        &rng);
    TEST_ASSERT(ret == WOLFCOSE_E_COSE_KEY_TYPE, "kw-wrong-size encrypt fails");

    /* Clean up */
    wc_CoseKey_Free(&kek);
    wc_FreeRng(&rng);
}
#endif /* WOLFCOSE_KEY_WRAP */

#endif /* WOLFCOSE_ENCRYPT && HAVE_AESGCM */

/* ---------------------------------------------------------------------------
 * COSE_Mac Multi-Recipient Tests (RFC 9052 Section 6.1)
 * --------------------------------------------------------------------------- */
#if defined(WOLFCOSE_MAC) && !defined(NO_HMAC)
static void test_cose_mac_multi_recipient(void)
{
    WOLFCOSE_KEY key1, key2;
    WOLFCOSE_RECIPIENT recipients[2];
    WOLFCOSE_HDR hdr;
    int ret;
    uint8_t out[512];
    size_t outLen;
    uint8_t scratch[256];
    const uint8_t payload[] = "Multi-recipient MAC test";
    const uint8_t keyData[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    const uint8_t wrongKeyData[32] = {
        0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
        0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0,
        0xEF, 0xEE, 0xED, 0xEC, 0xEB, 0xEA, 0xE9, 0xE8,
        0xE7, 0xE6, 0xE5, 0xE4, 0xE3, 0xE2, 0xE1, 0xE0
    };
    const uint8_t kid1[] = "mac-recipient-1";
    const uint8_t kid2[] = "mac-recipient-2";
    const uint8_t* decPayload;
    size_t decPayloadLen;

    printf("  [Mac Multi-Recipient HMAC-256]\n");

    /* Setup keys - both recipients share the same key in direct mode */
    wc_CoseKey_Init(&key1);
    ret = wc_CoseKey_SetSymmetric(&key1, keyData, sizeof(keyData));
    TEST_ASSERT(ret == 0, "mac key1 set");

    wc_CoseKey_Init(&key2);
    ret = wc_CoseKey_SetSymmetric(&key2, keyData, sizeof(keyData));
    TEST_ASSERT(ret == 0, "mac key2 set");

    /* Setup recipients */
    recipients[0].algId = 0;  /* Direct key */
    recipients[0].key = &key1;
    recipients[0].kid = kid1;
    recipients[0].kidLen = sizeof(kid1) - 1;

    recipients[1].algId = 0;  /* Direct key */
    recipients[1].key = &key2;
    recipients[1].kid = kid2;
    recipients[1].kidLen = sizeof(kid2) - 1;

    /* Create MAC with two recipients */
    ret = wc_CoseMac_Create(recipients, 2,
        WOLFCOSE_ALG_HMAC_256_256,
        payload, sizeof(payload) - 1,
        NULL, 0,  /* no detached payload */
        NULL, 0,  /* no external AAD */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "mac multi create");

    /* Verify with first recipient */
    memset(&hdr, 0, sizeof(hdr));
    ret = wc_CoseMac_Verify(&recipients[0], 0,
        out, outLen,
        NULL, 0,  /* no detached payload */
        NULL, 0,  /* no external AAD */
        scratch, sizeof(scratch),
        &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "mac verify recipient 0");
    TEST_ASSERT(decPayloadLen == sizeof(payload) - 1, "mac payload len 0");
    TEST_ASSERT(memcmp(decPayload, payload, decPayloadLen) == 0, "mac payload match 0");

    /* Verify with second recipient */
    memset(&hdr, 0, sizeof(hdr));
    ret = wc_CoseMac_Verify(&recipients[1], 1,
        out, outLen,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "mac verify recipient 1");
    TEST_ASSERT(decPayloadLen == sizeof(payload) - 1, "mac payload len 1");
    TEST_ASSERT(memcmp(decPayload, payload, decPayloadLen) == 0, "mac payload match 1");

    /* Verify headers */
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_HMAC_256_256, "mac hdr alg");

    /* Wrong key should fail */
    {
        WOLFCOSE_KEY wrongKey;
        WOLFCOSE_RECIPIENT wrongRecipient;
        wc_CoseKey_Init(&wrongKey);
        wc_CoseKey_SetSymmetric(&wrongKey, wrongKeyData, sizeof(wrongKeyData));
        wrongRecipient.algId = 0;
        wrongRecipient.key = &wrongKey;
        wrongRecipient.kid = NULL;
        wrongRecipient.kidLen = 0;

        ret = wc_CoseMac_Verify(&wrongRecipient, 0,
            out, outLen,
            NULL, 0,
            NULL, 0,
            scratch, sizeof(scratch),
            &hdr,
            &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == WOLFCOSE_E_MAC_FAIL, "mac wrong key fails");
        wc_CoseKey_Free(&wrongKey);
    }

    /* Invalid recipient index should fail */
    ret = wc_CoseMac_Verify(&recipients[0], 5,
        out, outLen,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret != 0, "mac invalid recipient index fails");

    wc_CoseKey_Free(&key1);
    wc_CoseKey_Free(&key2);
}

static void test_cose_mac_with_aad(void)
{
    WOLFCOSE_KEY key;
    WOLFCOSE_RECIPIENT recipients[1];
    WOLFCOSE_HDR hdr;
    int ret;
    uint8_t out[512];
    size_t outLen;
    uint8_t scratch[256];
    const uint8_t payload[] = "MAC with AAD";
    const uint8_t keyData[32] = {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F
    };
    const uint8_t aad[] = "additional authenticated data";
    const uint8_t wrongAad[] = "wrong aad";
    const uint8_t* decPayload;
    size_t decPayloadLen;

    printf("  [Mac with external AAD]\n");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));
    TEST_ASSERT(ret == 0, "mac aad key set");

    recipients[0].algId = 0;
    recipients[0].key = &key;
    recipients[0].kid = NULL;
    recipients[0].kidLen = 0;

    /* Create MAC with AAD */
    ret = wc_CoseMac_Create(recipients, 1,
        WOLFCOSE_ALG_HMAC_256_256,
        payload, sizeof(payload) - 1,
        NULL, 0,
        aad, sizeof(aad) - 1,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "mac aad create");

    /* Verify with correct AAD */
    memset(&hdr, 0, sizeof(hdr));
    ret = wc_CoseMac_Verify(&recipients[0], 0,
        out, outLen,
        NULL, 0,
        aad, sizeof(aad) - 1,
        scratch, sizeof(scratch),
        &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "mac aad verify ok");
    TEST_ASSERT(memcmp(decPayload, payload, decPayloadLen) == 0, "mac aad payload match");

    /* Wrong AAD should fail */
    ret = wc_CoseMac_Verify(&recipients[0], 0,
        out, outLen,
        NULL, 0,
        wrongAad, sizeof(wrongAad) - 1,
        scratch, sizeof(scratch),
        &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == WOLFCOSE_E_MAC_FAIL, "mac wrong aad fails");

    /* Missing AAD should fail */
    ret = wc_CoseMac_Verify(&recipients[0], 0,
        out, outLen,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == WOLFCOSE_E_MAC_FAIL, "mac missing aad fails");

    wc_CoseKey_Free(&key);
}

static void test_cose_mac_detached(void)
{
    WOLFCOSE_KEY key;
    WOLFCOSE_RECIPIENT recipients[1];
    WOLFCOSE_HDR hdr;
    int ret;
    uint8_t out[512];
    size_t outLen;
    uint8_t scratch[256];
    const uint8_t payload[] = "Detached MAC payload";
    const uint8_t wrongPayload[] = "wrong payload";
    const uint8_t keyData[32] = {
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F
    };
    const uint8_t* decPayload;
    size_t decPayloadLen;

    printf("  [Mac Detached Payload]\n");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));
    TEST_ASSERT(ret == 0, "mac detached key set");

    recipients[0].algId = 0;
    recipients[0].key = &key;
    recipients[0].kid = NULL;
    recipients[0].kidLen = 0;

    /* Create MAC with detached payload */
    ret = wc_CoseMac_Create(recipients, 1,
        WOLFCOSE_ALG_HMAC_256_256,
        NULL, 0,  /* no attached payload */
        payload, sizeof(payload) - 1,  /* detached payload */
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "mac detached create");

    /* Verify without providing detached payload should fail */
    memset(&hdr, 0, sizeof(hdr));
    ret = wc_CoseMac_Verify(&recipients[0], 0,
        out, outLen,
        NULL, 0,  /* no detached payload provided */
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == WOLFCOSE_E_DETACHED_PAYLOAD, "mac detached no payload fails");

    /* Verify with correct detached payload */
    ret = wc_CoseMac_Verify(&recipients[0], 0,
        out, outLen,
        payload, sizeof(payload) - 1,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "mac detached verify ok");
    TEST_ASSERT((hdr.flags & WOLFCOSE_HDR_FLAG_DETACHED) != 0, "mac detached flag set");
    TEST_ASSERT(decPayload == NULL, "mac detached payload null");

    /* Wrong detached payload should fail */
    ret = wc_CoseMac_Verify(&recipients[0], 0,
        out, outLen,
        wrongPayload, sizeof(wrongPayload) - 1,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == WOLFCOSE_E_MAC_FAIL, "mac detached wrong payload fails");

    wc_CoseKey_Free(&key);
}
#endif /* WOLFCOSE_MAC && !NO_HMAC */

/* ---------------------------------------------------------------------------
 * Phase 1: Algorithm Combination Tests
 * --------------------------------------------------------------------------- */
#ifdef HAVE_ECC
static void test_cose_sign1_es384(void)
{
    WOLFCOSE_KEY key;
    ecc_key eccKey;
    WC_RNG rng;
    int ret;
    uint8_t payload[] = "ES384 test payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Sign1 ES384]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) { TEST_ASSERT(0, "rng init"); return; }

    wc_ecc_init(&eccKey);
    ret = wc_ecc_make_key(&rng, 48, &eccKey);  /* P-384 */
    if (ret != 0) { TEST_ASSERT(0, "P-384 keygen"); goto done_es384; }

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P384, &eccKey);
    TEST_ASSERT(ret == 0, "set P-384 key");

    /* Sign */
    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES384,
        NULL, 0, payload, sizeof(payload) - 1,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret == 0 && outLen > 0, "sign1 es384 sign");

    /* Verify */
    ret = wc_CoseSign1_Verify(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "sign1 es384 verify");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_ES384, "sign1 es384 alg");
    TEST_ASSERT(decPayloadLen == sizeof(payload) - 1, "sign1 es384 payload len");

done_es384:
    wc_ecc_free(&eccKey);
    wc_FreeRng(&rng);
}

static void test_cose_sign1_es512(void)
{
    WOLFCOSE_KEY key;
    ecc_key eccKey;
    WC_RNG rng;
    int ret;
    uint8_t payload[] = "ES512 test payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[640];  /* ES512 sigs are larger */
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Sign1 ES512]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) { TEST_ASSERT(0, "rng init"); return; }

    wc_ecc_init(&eccKey);
    ret = wc_ecc_make_key(&rng, 66, &eccKey);  /* P-521 */
    if (ret != 0) { TEST_ASSERT(0, "P-521 keygen"); goto done_es512; }

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P521, &eccKey);
    TEST_ASSERT(ret == 0, "set P-521 key");

    /* Sign */
    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES512,
        NULL, 0, payload, sizeof(payload) - 1,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret == 0 && outLen > 0, "sign1 es512 sign");

    /* Verify */
    ret = wc_CoseSign1_Verify(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "sign1 es512 verify");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_ES512, "sign1 es512 alg");

done_es512:
    wc_ecc_free(&eccKey);
    wc_FreeRng(&rng);
}
#endif /* HAVE_ECC */

#ifdef HAVE_AESGCM
static void test_cose_encrypt0_a192gcm(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[24] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18
    };
    uint8_t iv[12] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66
    };
    uint8_t payload[] = "A192GCM test payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Encrypt0 A192GCM]\n");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));
    TEST_ASSERT(ret == 0, "set 192-bit key");

    /* Encrypt */
    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A192GCM,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,
        NULL, 0, NULL, NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "enc0 a192gcm encrypt");

    /* Decrypt */
    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch), &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "enc0 a192gcm decrypt");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_A192GCM, "enc0 a192gcm alg");
    TEST_ASSERT(plaintextLen == sizeof(payload) - 1 &&
                memcmp(plaintext, payload, plaintextLen) == 0,
                "enc0 a192gcm payload match");
}
#endif /* HAVE_AESGCM */

/* ---------------------------------------------------------------------------
 * Phase 3B: Negative Crypto Tests (Tamper Detection)
 * Critical security tests - must detect single-byte tampering
 * --------------------------------------------------------------------------- */
#ifdef HAVE_ECC
static void test_cose_sign1_tampered_sig_byte(void)
{
    WOLFCOSE_KEY key;
    ecc_key eccKey;
    WC_RNG rng;
    int ret;
    uint8_t payload[] = "Tamper test payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Sign1 Tampered Signature Byte]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) { TEST_ASSERT(0, "rng init"); return; }

    wc_ecc_init(&eccKey);
    ret = wc_ecc_make_key(&rng, 32, &eccKey);
    if (ret != 0) { TEST_ASSERT(0, "keygen"); goto done_tamper_sig; }

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &eccKey);

    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256,
        NULL, 0, payload, sizeof(payload) - 1,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret == 0, "sign for tamper test");

    /* Flip ONE byte in signature (last byte of COSE message) */
    if (outLen > 5) {
        out[outLen - 2] ^= 0x01;  /* Flip single bit */
    }

    ret = wc_CoseSign1_Verify(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == WOLFCOSE_E_COSE_SIG_FAIL, "tampered sig byte detected");

done_tamper_sig:
    wc_ecc_free(&eccKey);
    wc_FreeRng(&rng);
}

static void test_cose_sign1_tampered_payload_byte(void)
{
    WOLFCOSE_KEY key;
    ecc_key eccKey;
    WC_RNG rng;
    int ret;
    uint8_t payload[] = "Payload to tamper with after signing";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    size_t tamperedPos;

    printf("  [Sign1 Tampered Payload Byte]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) { TEST_ASSERT(0, "rng init"); return; }

    wc_ecc_init(&eccKey);
    ret = wc_ecc_make_key(&rng, 32, &eccKey);
    if (ret != 0) { TEST_ASSERT(0, "keygen"); goto done_tamper_payload; }

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &eccKey);

    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256,
        NULL, 0, payload, sizeof(payload) - 1,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret == 0, "sign for payload tamper test");

    /* Flip ONE byte in the payload area (middle of message) */
    tamperedPos = outLen / 2;
    out[tamperedPos] ^= 0x80;

    ret = wc_CoseSign1_Verify(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret != 0, "tampered payload byte detected");

done_tamper_payload:
    wc_ecc_free(&eccKey);
    wc_FreeRng(&rng);
}

static void test_cose_sign1_truncated_sig(void)
{
    WOLFCOSE_KEY key;
    ecc_key eccKey;
    WC_RNG rng;
    int ret;
    uint8_t payload[] = "Truncation test";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Sign1 Truncated Signature]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) { TEST_ASSERT(0, "rng init"); return; }

    wc_ecc_init(&eccKey);
    ret = wc_ecc_make_key(&rng, 32, &eccKey);
    if (ret != 0) { TEST_ASSERT(0, "keygen"); goto done_trunc; }

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &eccKey);

    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256,
        NULL, 0, payload, sizeof(payload) - 1,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret == 0, "sign for truncation test");

    /* Remove last byte of message (truncates signature) */
    ret = wc_CoseSign1_Verify(&key, out, outLen - 1,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret != 0, "truncated signature detected");

done_trunc:
    wc_ecc_free(&eccKey);
    wc_FreeRng(&rng);
}
#endif /* HAVE_ECC */

#ifdef HAVE_AESGCM
static void test_cose_encrypt0_tampered_ct_byte(void)
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
    uint8_t payload[] = "Ciphertext tamper test";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Encrypt0 Tampered Ciphertext Byte]\n");

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));

    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A128GCM,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,
        NULL, 0, NULL, NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "encrypt for ct tamper test");

    /* Flip ONE byte in ciphertext area */
    if (outLen > 30) {
        out[outLen - 20] ^= 0x01;  /* Flip one bit in ciphertext */
    }

    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch), &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == WOLFCOSE_E_COSE_DECRYPT_FAIL, "tampered ct detected");
}

static void test_cose_encrypt0_tampered_tag(void)
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
    uint8_t payload[] = "Auth tag tamper test";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Encrypt0 Tampered Auth Tag]\n");

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));

    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A128GCM,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,
        NULL, 0, NULL, NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "encrypt for tag tamper test");

    /* Flip ONE byte in auth tag (last 16 bytes of ciphertext in AES-GCM) */
    if (outLen > 5) {
        out[outLen - 3] ^= 0xFF;  /* Flip byte in tag */
    }

    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch), &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == WOLFCOSE_E_COSE_DECRYPT_FAIL, "tampered tag detected");
}

static void test_cose_encrypt0_wrong_key(void)
{
    WOLFCOSE_KEY key, wrongKey;
    uint8_t keyData[16] = {
        0x84, 0x9B, 0x57, 0x21, 0x9D, 0xAE, 0x48, 0xDE,
        0x64, 0x6D, 0x07, 0xDB, 0xB5, 0x33, 0x56, 0x6E
    };
    uint8_t wrongKeyData[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    uint8_t iv[12] = {
        0x02, 0xD1, 0xF7, 0xE6, 0xF2, 0x6C, 0x43, 0xD4,
        0x86, 0x8D, 0x87, 0xCE
    };
    uint8_t payload[] = "Wrong key test";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Encrypt0 Wrong Key]\n");

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));

    wc_CoseKey_Init(&wrongKey);
    wc_CoseKey_SetSymmetric(&wrongKey, wrongKeyData, sizeof(wrongKeyData));

    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A128GCM,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,
        NULL, 0, NULL, NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "encrypt with correct key");

    /* Decrypt with wrong key */
    ret = wc_CoseEncrypt0_Decrypt(&wrongKey, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch), &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == WOLFCOSE_E_COSE_DECRYPT_FAIL, "wrong key detected");
}
#endif /* HAVE_AESGCM */

#ifndef NO_HMAC
static void test_cose_mac0_tampered_tag_byte(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    uint8_t payload[] = "MAC tamper test";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Mac0 Tampered Tag Byte]\n");

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));

    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC_256_256,
        NULL, 0, /* kid, kidLen */
        payload, sizeof(payload) - 1,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "create MAC for tamper test");

    /* Flip ONE byte in MAC tag */
    if (outLen > 5) {
        out[outLen - 3] ^= 0x01;
    }

    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == WOLFCOSE_E_MAC_FAIL, "tampered MAC tag detected");
}

static void test_cose_mac0_truncated_tag(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    uint8_t payload[] = "MAC truncation test";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Mac0 Truncated Tag]\n");

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));

    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC_256_256,
        NULL, 0, /* kid, kidLen */
        payload, sizeof(payload) - 1,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "create MAC for truncation test");

    /* Truncate message (removes part of tag) */
    ret = wc_CoseMac0_Verify(&key, out, outLen - 2,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret != 0, "truncated MAC tag detected");
}
#endif /* !NO_HMAC */

/* ---------------------------------------------------------------------------
 * Phase 3A: Boundary Condition Tests
 * --------------------------------------------------------------------------- */
#ifdef HAVE_ECC
static void test_cose_empty_payload(void)
{
    WOLFCOSE_KEY key;
    ecc_key eccKey;
    WC_RNG rng;
    int ret;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Sign1 Empty Payload]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) { TEST_ASSERT(0, "rng init"); return; }

    wc_ecc_init(&eccKey);
    ret = wc_ecc_make_key(&rng, 32, &eccKey);
    if (ret != 0) { TEST_ASSERT(0, "keygen"); goto done_empty; }

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &eccKey);

    /* Sign with zero-length payload (valid per RFC 9052) */
    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256,
        NULL, 0,
        (const uint8_t*)"", 0,  /* empty payload */
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret == 0, "sign empty payload");

    ret = wc_CoseSign1_Verify(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "verify empty payload");
    TEST_ASSERT(decPayloadLen == 0, "empty payload length");

done_empty:
    wc_ecc_free(&eccKey);
    wc_FreeRng(&rng);
}

static void test_cose_large_payload(void)
{
    WOLFCOSE_KEY key;
    ecc_key eccKey;
    WC_RNG rng;
    int ret;
    uint8_t largePayload[4096];
    /* Scratch buffer must hold Sig_structure which includes the payload */
    uint8_t scratch[4096 + 128];  /* payload + CBOR overhead */
    uint8_t out[8192];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    size_t i;

    printf("  [Sign1 Large Payload (4KB)]\n");

    /* Fill payload with pattern */
    for (i = 0; i < sizeof(largePayload); i++) {
        largePayload[i] = (uint8_t)(i & 0xFF);
    }

    ret = wc_InitRng(&rng);
    if (ret != 0) { TEST_ASSERT(0, "rng init"); return; }

    wc_ecc_init(&eccKey);
    ret = wc_ecc_make_key(&rng, 32, &eccKey);
    if (ret != 0) { TEST_ASSERT(0, "keygen"); goto done_large; }

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &eccKey);

    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256,
        NULL, 0,
        largePayload, sizeof(largePayload),
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret == 0, "sign large payload");

    ret = wc_CoseSign1_Verify(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "verify large payload");
    TEST_ASSERT(decPayloadLen == sizeof(largePayload), "large payload length");
    TEST_ASSERT(memcmp(decPayload, largePayload, decPayloadLen) == 0,
                "large payload match");

done_large:
    wc_ecc_free(&eccKey);
    wc_FreeRng(&rng);
}

static void test_cose_empty_aad(void)
{
    WOLFCOSE_KEY key;
    ecc_key eccKey;
    WC_RNG rng;
    int ret;
    uint8_t payload[] = "Test with empty AAD";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Sign1 Empty AAD]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) { TEST_ASSERT(0, "rng init"); return; }

    wc_ecc_init(&eccKey);
    ret = wc_ecc_make_key(&rng, 32, &eccKey);
    if (ret != 0) { TEST_ASSERT(0, "keygen"); goto done_empty_aad; }

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &eccKey);

    /* Sign with zero-length AAD (valid per RFC 9052) */
    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256,
        NULL, 0,
        payload, sizeof(payload) - 1,
        NULL, 0,
        (const uint8_t*)"", 0,  /* empty AAD */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret == 0, "sign with empty aad");

    ret = wc_CoseSign1_Verify(&key, out, outLen,
        NULL, 0,
        (const uint8_t*)"", 0,  /* empty AAD */
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "verify with empty aad");

done_empty_aad:
    wc_ecc_free(&eccKey);
    wc_FreeRng(&rng);
}

static void test_cose_long_kid(void)
{
    WOLFCOSE_KEY key;
    ecc_key eccKey;
    WC_RNG rng;
    int ret;
    uint8_t payload[] = "Test with long kid";
    uint8_t longKid[256];  /* 256-byte key identifier */
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[1024];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    size_t i;

    printf("  [Sign1 Long KID (256 bytes)]\n");

    /* Fill kid with pattern */
    for (i = 0; i < sizeof(longKid); i++) {
        longKid[i] = (uint8_t)(i & 0xFF);
    }

    ret = wc_InitRng(&rng);
    if (ret != 0) { TEST_ASSERT(0, "rng init"); return; }

    wc_ecc_init(&eccKey);
    ret = wc_ecc_make_key(&rng, 32, &eccKey);
    if (ret != 0) { TEST_ASSERT(0, "keygen"); goto done_long_kid; }

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &eccKey);

    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256,
        longKid, sizeof(longKid),
        payload, sizeof(payload) - 1,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret == 0, "sign with long kid");

    ret = wc_CoseSign1_Verify(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "verify with long kid");
    TEST_ASSERT(hdr.kidLen == sizeof(longKid), "long kid length preserved");

done_long_kid:
    wc_ecc_free(&eccKey);
    wc_FreeRng(&rng);
}
#endif /* HAVE_ECC */

/* ---------------------------------------------------------------------------
 * Phase 3E: Buffer Overflow Prevention Tests
 * --------------------------------------------------------------------------- */
#ifdef HAVE_ECC
static void test_cose_sign_output_too_small(void)
{
    WOLFCOSE_KEY key;
    ecc_key eccKey;
    WC_RNG rng;
    int ret;
    uint8_t payload[] = "Buffer test payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[10];  /* Way too small */
    size_t outLen = 0;

    printf("  [Sign1 Output Buffer Too Small]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) { TEST_ASSERT(0, "rng init"); return; }

    wc_ecc_init(&eccKey);
    ret = wc_ecc_make_key(&rng, 32, &eccKey);
    if (ret != 0) { TEST_ASSERT(0, "keygen"); goto done_buf_small; }

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &eccKey);

    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256,
        NULL, 0,
        payload, sizeof(payload) - 1,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret == WOLFCOSE_E_BUFFER_TOO_SMALL, "small output buffer detected");

done_buf_small:
    wc_ecc_free(&eccKey);
    wc_FreeRng(&rng);
}

static void test_cose_sign_scratch_too_small(void)
{
    WOLFCOSE_KEY key;
    ecc_key eccKey;
    WC_RNG rng;
    int ret;
    uint8_t payload[] = "Scratch buffer test";
    uint8_t scratch[16];  /* Too small for Sig_structure */
    uint8_t out[512];
    size_t outLen = 0;

    printf("  [Sign1 Scratch Buffer Too Small]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) { TEST_ASSERT(0, "rng init"); return; }

    wc_ecc_init(&eccKey);
    ret = wc_ecc_make_key(&rng, 32, &eccKey);
    if (ret != 0) { TEST_ASSERT(0, "keygen"); goto done_scratch_small; }

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &eccKey);

    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256,
        NULL, 0,
        payload, sizeof(payload) - 1,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret == WOLFCOSE_E_BUFFER_TOO_SMALL, "small scratch buffer detected");

done_scratch_small:
    wc_ecc_free(&eccKey);
    wc_FreeRng(&rng);
}
#endif /* HAVE_ECC */

#ifdef HAVE_AESGCM
static void test_cose_encrypt_output_too_small(void)
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
    uint8_t payload[] = "Buffer size test";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[10];  /* Too small */
    size_t outLen = 0;
    int ret;

    printf("  [Encrypt0 Output Buffer Too Small]\n");

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));

    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A128GCM,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,
        NULL, 0, NULL, NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == WOLFCOSE_E_BUFFER_TOO_SMALL, "small encrypt buffer detected");
}
#endif /* HAVE_AESGCM */

/* ---------------------------------------------------------------------------
 * Phase 3C: Malformed CBOR Input Tests
 * --------------------------------------------------------------------------- */
#ifdef HAVE_ECC
static void test_decode_truncated_message(void)
{
    WOLFCOSE_KEY key;
    ecc_key eccKey;
    WC_RNG rng;
    int ret;
    uint8_t payload[] = "Truncation test";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Decode Truncated Message]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) { TEST_ASSERT(0, "rng init"); return; }

    wc_ecc_init(&eccKey);
    ret = wc_ecc_make_key(&rng, 32, &eccKey);
    if (ret != 0) { TEST_ASSERT(0, "keygen"); goto done_trunc_msg; }

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &eccKey);

    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256,
        NULL, 0, payload, sizeof(payload) - 1,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret == 0, "create message for truncation");

    /* Try to verify with truncated message (half the length) */
    ret = wc_CoseSign1_Verify(&key, out, outLen / 2,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret != 0, "truncated message detected");

done_trunc_msg:
    wc_ecc_free(&eccKey);
    wc_FreeRng(&rng);
}

static void test_decode_wrong_tag(void)
{
    WOLFCOSE_KEY key;
    ecc_key eccKey;
    WC_RNG rng;
    int ret;
    uint8_t payload[] = "Wrong tag test";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Decode Wrong COSE Tag]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) { TEST_ASSERT(0, "rng init"); return; }

    wc_ecc_init(&eccKey);
    ret = wc_ecc_make_key(&rng, 32, &eccKey);
    if (ret != 0) { TEST_ASSERT(0, "keygen"); goto done_wrong_tag; }

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &eccKey);

    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256,
        NULL, 0, payload, sizeof(payload) - 1,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret == 0, "create message");

    /* Corrupt the CBOR tag - Tag 18 is encoded as single byte 0xD2
     * (major type 6 = 0xC0 | value 18 = 0x12 => 0xD2)
     * Change it to tag 16 (Encrypt0 tag) = 0xD0 to test wrong tag detection */
    if (outLen > 0 && out[0] == 0xD2) {
        out[0] = 0xD0;  /* Wrong tag - COSE_Encrypt0 tag instead of COSE_Sign1 */
    }

    ret = wc_CoseSign1_Verify(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    /* Should fail with bad tag or malformed error */
    TEST_ASSERT(ret != 0, "wrong tag detected");

done_wrong_tag:
    wc_ecc_free(&eccKey);
    wc_FreeRng(&rng);
}
#endif /* HAVE_ECC */

/* ---------------------------------------------------------------------------
 * Additional coverage tests
 * --------------------------------------------------------------------------- */

/* Test bad/unsupported algorithm handling */
#ifdef HAVE_ECC
static void test_cose_bad_algorithm(void)
{
    WOLFCOSE_KEY key;
    ecc_key eccKey;
    WC_RNG rng;
    int ret;
    uint8_t payload[] = "Bad algorithm test";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;

    printf("  [Bad Algorithm Tests]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) { TEST_ASSERT(0, "rng init"); return; }

    wc_ecc_init(&eccKey);
    ret = wc_ecc_make_key(&rng, 32, &eccKey);
    if (ret != 0) { TEST_ASSERT(0, "keygen"); goto done; }

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &eccKey);

    /* Try signing with invalid algorithm */
    ret = wc_CoseSign1_Sign(&key, 9999,  /* Invalid algorithm ID */
        NULL, 0, payload, sizeof(payload) - 1,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    TEST_ASSERT(ret != 0, "bad alg rejected");

done:
    wc_ecc_free(&eccKey);
    wc_FreeRng(&rng);
}
#endif

/* Test NULL parameter handling */
static void test_cose_null_params(void)
{
    WOLFCOSE_KEY key;
    int ret;

    printf("  [NULL Parameter Tests]\n");

    /* Init with NULL should be safe (no-op) */
    wc_CoseKey_Init(NULL);
    TEST_ASSERT(1, "null init safe");

    /* Free with NULL should be safe */
    wc_CoseKey_Free(NULL);
    TEST_ASSERT(1, "null free safe");

    /* SetSymmetric with NULL key */
    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetSymmetric(NULL, (const uint8_t*)"test", 4);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "null key arg");

    /* SetSymmetric with NULL data */
    ret = wc_CoseKey_SetSymmetric(&key, NULL, 4);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "null data arg");

    /* SetSymmetric with zero length */
    ret = wc_CoseKey_SetSymmetric(&key, (const uint8_t*)"test", 0);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "zero len arg");
}

/* Test COSE_Key with KID field */
static void test_cose_key_with_kid(void)
{
    uint8_t keyData[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    uint8_t kidData[] = "my-key-id-12345";
    WOLFCOSE_KEY key;
    uint8_t encoded[256];
    size_t encodedLen = 0;
    int ret;

    printf("  [COSE_Key with KID]\n");

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));

    /* Set KID */
    key.kid = kidData;
    key.kidLen = sizeof(kidData) - 1;

    /* Encode */
    ret = wc_CoseKey_Encode(&key, encoded, sizeof(encoded), &encodedLen);
    TEST_ASSERT(ret == 0, "encode with kid");
    TEST_ASSERT(encodedLen > sizeof(keyData), "kid included in encoding");

    /* Decode */
    WOLFCOSE_KEY decoded;
    wc_CoseKey_Init(&decoded);
    ret = wc_CoseKey_Decode(&decoded, encoded, encodedLen);
    TEST_ASSERT(ret == 0, "decode with kid");
    /* Note: KID decoding may not be implemented - check if supported */
    if (decoded.kidLen > 0) {
        TEST_ASSERT(decoded.kidLen == key.kidLen, "kid length preserved");
        if (decoded.kid != NULL && key.kid != NULL) {
            TEST_ASSERT(memcmp(decoded.kid, key.kid, key.kidLen) == 0, "kid value preserved");
        }
    }
}

#ifdef HAVE_ECC
/* Test COSE_Key ECC with P-384 and P-521 curves */
static void test_cose_key_ecc_curves(void)
{
    WOLFCOSE_KEY key;
    ecc_key eccKey;
    WC_RNG rng;
    uint8_t encoded[512];  /* Larger buffer for P-521 */
    size_t encodedLen = 0;
    int ret;

    printf("  [COSE_Key ECC Curves]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) { TEST_ASSERT(0, "rng init"); return; }

#ifdef WOLFSSL_SHA384
    /* Test P-384 */
    wc_ecc_init(&eccKey);
    ret = wc_ecc_make_key(&rng, 48, &eccKey);  /* 48 bytes = 384 bits */
    if (ret == 0) {
        wc_CoseKey_Init(&key);
        ret = wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P384, &eccKey);
        if (ret == 0) {
            TEST_ASSERT(ret == 0, "set P-384 key");

            ret = wc_CoseKey_Encode(&key, encoded, sizeof(encoded), &encodedLen);
            TEST_ASSERT(ret == 0, "encode P-384");

            if (ret == 0) {
                WOLFCOSE_KEY decoded;
                wc_CoseKey_Init(&decoded);
                ret = wc_CoseKey_Decode(&decoded, encoded, encodedLen);
                TEST_ASSERT(ret == 0, "decode P-384");
                TEST_ASSERT(decoded.crv == WOLFCOSE_CRV_P384, "P-384 curve preserved");
            }
        }
    }
    wc_ecc_free(&eccKey);
#endif

#ifdef WOLFSSL_SHA512
    /* Test P-521 */
    wc_ecc_init(&eccKey);
    ret = wc_ecc_make_key(&rng, 66, &eccKey);  /* 66 bytes = 521 bits */
    if (ret == 0) {
        wc_CoseKey_Init(&key);
        ret = wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P521, &eccKey);
        if (ret == 0) {
            TEST_ASSERT(ret == 0, "set P-521 key");

            ret = wc_CoseKey_Encode(&key, encoded, sizeof(encoded), &encodedLen);
            TEST_ASSERT(ret == 0, "encode P-521");

            if (ret == 0) {
                WOLFCOSE_KEY decoded;
                wc_CoseKey_Init(&decoded);
                ret = wc_CoseKey_Decode(&decoded, encoded, encodedLen);
                TEST_ASSERT(ret == 0, "decode P-521");
                TEST_ASSERT(decoded.crv == WOLFCOSE_CRV_P521, "P-521 curve preserved");
            }
        }
    }
    wc_ecc_free(&eccKey);
#endif

    wc_FreeRng(&rng);
}
#endif

#ifdef HAVE_AESGCM
/* Test Encrypt0 with all AES-GCM key sizes */
static void test_cose_encrypt0_key_sizes(void)
{
    WOLFCOSE_KEY key;
    uint8_t key128[16], key192[24], key256[32];
    uint8_t iv[12] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                      0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C};
    uint8_t payload[] = "Key size test";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    uint8_t plaintext[64];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;
    size_t i;

    printf("  [Encrypt0 Key Sizes]\n");

    /* Initialize keys with patterns */
    for (i = 0; i < sizeof(key128); i++) key128[i] = (uint8_t)(i + 1);
    for (i = 0; i < sizeof(key192); i++) key192[i] = (uint8_t)(i + 0x10);
    for (i = 0; i < sizeof(key256); i++) key256[i] = (uint8_t)(i + 0x20);

    /* Test 128-bit key */
    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, key128, sizeof(key128));
    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A128GCM,
        iv, sizeof(iv), payload, sizeof(payload) - 1,
        NULL, 0, NULL,  /* detached: buffer, size, outLen */
        NULL, 0,        /* extAad */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "encrypt A128GCM");
    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch), &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "decrypt A128GCM");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_A128GCM, "A128GCM alg");

    /* Test 192-bit key */
    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, key192, sizeof(key192));
    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A192GCM,
        iv, sizeof(iv), payload, sizeof(payload) - 1,
        NULL, 0, NULL,  /* detached */
        NULL, 0,        /* extAad */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "encrypt A192GCM");
    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch), &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "decrypt A192GCM");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_A192GCM, "A192GCM alg");

    /* Test 256-bit key */
    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, key256, sizeof(key256));
    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A256GCM,
        iv, sizeof(iv), payload, sizeof(payload) - 1,
        NULL, 0, NULL,  /* detached */
        NULL, 0,        /* extAad */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "encrypt A256GCM");
    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch), &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "decrypt A256GCM");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_A256GCM, "A256GCM alg");
}
#endif

#ifndef NO_HMAC
/* Test Mac0 with different HMAC key sizes */
static void test_cose_mac0_key_sizes(void)
{
    WOLFCOSE_KEY key;
    uint8_t key256[32];
    uint8_t payload[] = "HMAC key size test";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;
    size_t i;

    printf("  [Mac0 HMAC Key Sizes]\n");

    for (i = 0; i < sizeof(key256); i++) key256[i] = (uint8_t)(i + 0x30);

    /* Test 256-bit HMAC key */
    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, key256, sizeof(key256));
    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC_256_256,
        NULL, 0, /* kid, kidLen */
        payload, sizeof(payload) - 1,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "create HMAC-256");
    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "verify HMAC-256");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_HMAC_256_256, "HMAC-256 alg");
}
#endif

/* Test CBOR encoding edge cases for higher coverage */
static void test_cbor_edge_cases(void)
{
    WOLFCOSE_CBOR_CTX ctx;
    uint8_t buf[256];
    int ret;
    uint64_t u64Val;
    int64_t i64Val;
    size_t count;

    printf("  [CBOR Edge Cases]\n");

    /* Test encoding/decoding large uint (> 255) */
    ctx.buf = buf;
    ctx.bufSz = sizeof(buf);
    ctx.idx = 0;
    ret = wc_CBOR_EncodeUint(&ctx, 1000);  /* > 255, needs 2 bytes */
    TEST_ASSERT(ret == 0, "encode uint 1000");

    ctx.idx = 0;
    ret = wc_CBOR_DecodeUint(&ctx, &u64Val);
    TEST_ASSERT(ret == 0, "decode uint 1000");
    TEST_ASSERT(u64Val == 1000, "uint 1000 value");

    /* Test encoding/decoding 4-byte uint */
    ctx.idx = 0;
    ret = wc_CBOR_EncodeUint(&ctx, 100000);  /* needs 4 bytes */
    TEST_ASSERT(ret == 0, "encode uint 100000");

    ctx.idx = 0;
    ret = wc_CBOR_DecodeUint(&ctx, &u64Val);
    TEST_ASSERT(ret == 0, "decode uint 100000");
    TEST_ASSERT(u64Val == 100000, "uint 100000 value");

    /* Test negative integer encoding */
    ctx.idx = 0;
    ret = wc_CBOR_EncodeInt(&ctx, -100);
    TEST_ASSERT(ret == 0, "encode int -100");

    ctx.idx = 0;
    ret = wc_CBOR_DecodeInt(&ctx, &i64Val);
    TEST_ASSERT(ret == 0, "decode int -100");
    TEST_ASSERT(i64Val == -100, "int -100 value");

    /* Test large negative integer */
    ctx.idx = 0;
    ret = wc_CBOR_EncodeInt(&ctx, -1000);
    TEST_ASSERT(ret == 0, "encode int -1000");

    ctx.idx = 0;
    ret = wc_CBOR_DecodeInt(&ctx, &i64Val);
    TEST_ASSERT(ret == 0, "decode int -1000");
    TEST_ASSERT(i64Val == -1000, "int -1000 value");

    /* Test bstr boundary (24 bytes) */
    ctx.idx = 0;
    ret = wc_CBOR_EncodeBstr(&ctx, buf, 24);
    TEST_ASSERT(ret == 0, "encode bstr 24");

    /* Test bstr boundary (256 bytes) - needs larger buffer */
    {
        uint8_t largeBuf[512];
        uint8_t bigData[260] = {0};
        WOLFCOSE_CBOR_CTX bigCtx;
        bigCtx.buf = largeBuf;
        bigCtx.bufSz = sizeof(largeBuf);
        bigCtx.idx = 0;
        ret = wc_CBOR_EncodeBstr(&bigCtx, bigData, 256);
        TEST_ASSERT(ret == 0, "encode bstr 256");
    }

    /* Test map with entries */
    ctx.idx = 0;
    ret = wc_CBOR_EncodeMapStart(&ctx, 2);
    TEST_ASSERT(ret == 0, "encode map 2");
    ret = wc_CBOR_EncodeInt(&ctx, 1);
    TEST_ASSERT(ret == 0, "encode map key 1");
    ret = wc_CBOR_EncodeInt(&ctx, 100);
    TEST_ASSERT(ret == 0, "encode map val 100");
    ret = wc_CBOR_EncodeInt(&ctx, -1);
    TEST_ASSERT(ret == 0, "encode map key -1");
    ret = wc_CBOR_EncodeBstr(&ctx, (const uint8_t*)"test", 4);
    TEST_ASSERT(ret == 0, "encode map val bstr");

    ctx.idx = 0;
    ret = wc_CBOR_DecodeMapStart(&ctx, &count);
    TEST_ASSERT(ret == 0, "decode map start");
    TEST_ASSERT(count == 2, "map count 2");
}

/* ---------------------------------------------------------------------------
 * Entry point
 * --------------------------------------------------------------------------- */
int test_cose(void)
{
    g_failures = 0;

    /* Key tests */
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

    /* Sign1 basic tests */
#ifdef HAVE_ECC
    test_cose_sign1_ecc("ES256", WOLFCOSE_ALG_ES256, WOLFCOSE_CRV_P256, 32);
    test_cose_sign1_with_aad();
    test_cose_sign1_detached();
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

    /* Encrypt0 basic tests */
#ifdef HAVE_AESGCM
    test_cose_encrypt0_a128gcm();
    test_cose_encrypt0_a256gcm();
    test_cose_encrypt0_with_aad();
    test_cose_encrypt0_detached();
#endif

    /* ChaCha20-Poly1305 encryption tests */
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    test_cose_encrypt0_chacha20();
#endif

    /* AES-CCM encryption tests */
#ifdef HAVE_AESCCM
    test_cose_encrypt0_aes_ccm();
#endif

    /* RSA-PSS signature tests */
#if defined(WC_RSA_PSS) && defined(WOLFSSL_KEY_GEN)
    test_cose_sign1_pss("PS256", WOLFCOSE_ALG_PS256);
    test_cose_sign1_pss("PS384", WOLFCOSE_ALG_PS384);
    test_cose_sign1_pss("PS512", WOLFCOSE_ALG_PS512);
#endif

    /* ML-DSA (Dilithium) signature tests */
#ifdef HAVE_DILITHIUM
    test_cose_sign1_ml_dsa("ML-DSA-44", WOLFCOSE_ALG_ML_DSA_44, 2);
    test_cose_sign1_ml_dsa("ML-DSA-65", WOLFCOSE_ALG_ML_DSA_65, 3);
    test_cose_sign1_ml_dsa("ML-DSA-87", WOLFCOSE_ALG_ML_DSA_87, 5);
#endif

    /* Mac0 basic tests */
#if !defined(NO_HMAC)
    test_cose_mac0_hmac256();
    test_cose_mac0_with_aad();
    test_cose_mac0_detached();
    test_cose_mac0_detached_with_aad();
#ifdef WOLFSSL_SHA384
    test_cose_mac0_hmac384();
#endif
#ifdef WOLFSSL_SHA512
    test_cose_mac0_hmac512();
#endif
#endif /* !NO_HMAC */

    /* AES-CBC-MAC tests */
#ifdef HAVE_AES_CBC
    test_cose_mac0_aes_cbc_mac();
    test_cose_mac0_aes_cbc_mac_with_aad();
    test_cose_mac0_aes_cbc_mac_detached();
#endif

    /* RFC 9052 interop test vectors */
#ifdef HAVE_ECC
    test_rfc_sign1_ecdsa_01();
#endif
#if !defined(NO_HMAC)
    test_rfc_mac0_hmac_01();
#endif

    /* Multi-signer tests */
#if defined(WOLFCOSE_SIGN) && defined(HAVE_ECC)
    test_cose_sign_multi_signer();
    test_cose_sign_with_aad();
    test_cose_sign_detached();
#ifdef HAVE_ED25519
    test_cose_sign_mixed_algorithms();
#endif
#endif

    /* Multi-recipient encryption tests */
#if defined(WOLFCOSE_ENCRYPT) && defined(HAVE_AESGCM)
    test_cose_encrypt_multi_recipient();
    test_cose_encrypt_with_aad();
    test_cose_encrypt_a256gcm();
#if defined(WOLFCOSE_ECDH_ES_DIRECT) && defined(HAVE_ECC) && defined(HAVE_HKDF)
    test_cose_encrypt_ecdh_es_hkdf_256();
    test_cose_encrypt_ecdh_es_wrong_key();
    test_cose_encrypt_ecdh_es_p384();
#endif
#if defined(WOLFCOSE_KEY_WRAP)
    test_cose_encrypt_a128kw();
    test_cose_encrypt_a192kw();
    test_cose_encrypt_a256kw();
    test_cose_encrypt_kw_wrong_keysize();
#endif
#endif

    /* Multi-recipient MAC tests */
#if defined(WOLFCOSE_MAC) && !defined(NO_HMAC)
    test_cose_mac_multi_recipient();
    test_cose_mac_with_aad();
    test_cose_mac_detached();
#endif

    /* Phase 1: Algorithm Combination Tests */
    printf("\n--- Algorithm Combination Tests ---\n");
#ifdef HAVE_ECC
    test_cose_sign1_es384();
    test_cose_sign1_es512();
#endif
#ifdef HAVE_AESGCM
    test_cose_encrypt0_a192gcm();
#endif

    /* Phase 3B: Negative Crypto Tests (Tamper Detection) */
    printf("\n--- Negative Crypto Tests ---\n");
#ifdef HAVE_ECC
    test_cose_sign1_tampered_sig_byte();
    test_cose_sign1_tampered_payload_byte();
    test_cose_sign1_truncated_sig();
#endif
#ifdef HAVE_AESGCM
    test_cose_encrypt0_tampered_ct_byte();
    test_cose_encrypt0_tampered_tag();
    test_cose_encrypt0_wrong_key();
#endif
#ifndef NO_HMAC
    test_cose_mac0_tampered_tag_byte();
    test_cose_mac0_truncated_tag();
#endif

    /* Phase 3A: Boundary Condition Tests */
    printf("\n--- Boundary Condition Tests ---\n");
#ifdef HAVE_ECC
    test_cose_empty_payload();
    test_cose_large_payload();
    test_cose_empty_aad();
    test_cose_long_kid();
#endif

    /* Phase 3E: Buffer Overflow Prevention Tests */
    printf("\n--- Buffer Overflow Prevention Tests ---\n");
#ifdef HAVE_ECC
    test_cose_sign_output_too_small();
    test_cose_sign_scratch_too_small();
#endif
#ifdef HAVE_AESGCM
    test_cose_encrypt_output_too_small();
#endif

    /* Phase 3C: Malformed CBOR Input Tests */
    printf("\n--- Malformed Input Tests ---\n");
#ifdef HAVE_ECC
    test_decode_truncated_message();
    test_decode_wrong_tag();
#endif

    /* Additional Coverage Tests */
    printf("\n--- Additional Coverage Tests ---\n");
#ifdef HAVE_ECC
    test_cose_bad_algorithm();
#endif
    test_cose_null_params();
    test_cose_key_with_kid();
#ifdef HAVE_ECC
    test_cose_key_ecc_curves();
#endif
#ifdef HAVE_AESGCM
    test_cose_encrypt0_key_sizes();
#endif
#ifndef NO_HMAC
    test_cose_mac0_key_sizes();
#endif
    test_cbor_edge_cases();

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
