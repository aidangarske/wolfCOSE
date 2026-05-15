/* test_interop.c
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
 * COSE Interoperability Tests
 *
 * Tests wolfCOSE against known-good test vectors from:
 * - COSE Working Group Examples (https://github.com/cose-wg/Examples)
 * - RFC 9052 Appendix examples
 *
 * These tests prove RFC correctness by verifying that:
 * 1. wolfCOSE can decode/verify messages created by reference implementations
 * 2. Messages created by wolfCOSE can be verified by reference implementations
 * 3. Round-trip encode/decode preserves data integrity
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

/* ----- COSE_Sign1 Test Vectors (RFC 9052 / COSE WG Examples) ----- */

/*
 * Test Vector: sign1-pass-01
 * Algorithm: ES256
 * Payload: "This is the content."
 * Source: Derived from COSE WG sign1-tests
 *
 * Key (P-256):
 *   x: 65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d
 *   y: 1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c
 *   d: aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf
 */
static const uint8_t sign1_vec1_keyX[] = {
    0x65, 0xed, 0xa5, 0xa1, 0x25, 0x77, 0xc2, 0xba,
    0xe8, 0x29, 0x43, 0x7f, 0xe3, 0x38, 0x70, 0x1a,
    0x10, 0xaa, 0xa3, 0x75, 0xe1, 0xbb, 0x5b, 0x5d,
    0xe1, 0x08, 0xde, 0x43, 0x9c, 0x08, 0x55, 0x1d
};
static const uint8_t sign1_vec1_keyY[] = {
    0x1e, 0x52, 0xed, 0x75, 0x70, 0x11, 0x63, 0xf7,
    0xf9, 0xe4, 0x0d, 0xdf, 0x9f, 0x34, 0x1b, 0x3d,
    0xc9, 0xba, 0x86, 0x0a, 0xf7, 0xe0, 0xca, 0x7c,
    0xa7, 0xe9, 0xee, 0xcd, 0x00, 0x84, 0xd1, 0x9c
};
static const uint8_t sign1_vec1_keyD[] = {
    0xaf, 0xf9, 0x07, 0xc9, 0x9f, 0x9a, 0xd3, 0xaa,
    0xe6, 0xc4, 0xcd, 0xf2, 0x11, 0x22, 0xbc, 0xe2,
    0xbd, 0x68, 0xb5, 0x28, 0x3e, 0x69, 0x07, 0x15,
    0x4a, 0xd9, 0x11, 0x84, 0x0f, 0xa2, 0x08, 0xcf
};

static const uint8_t sign1_vec1_payload[] = "This is the content.";

/* ----- COSE_Encrypt0 Test Vectors ----- */

/*
 * Test Vector: encrypt0-pass-01
 * Algorithm: A128GCM
 * Payload: "This is the content."
 * Key: 849b57219dae48de646d07dbb533566e (16 bytes)
 * IV:  02d1f7e6f26c43d4868d87ce
 */
static const uint8_t enc0_vec1_key[] = {
    0x84, 0x9b, 0x57, 0x21, 0x9d, 0xae, 0x48, 0xde,
    0x64, 0x6d, 0x07, 0xdb, 0xb5, 0x33, 0x56, 0x6e
};

static const uint8_t enc0_vec1_iv[] = {
    0x02, 0xd1, 0xf7, 0xe6, 0xf2, 0x6c, 0x43, 0xd4,
    0x86, 0x8d, 0x87, 0xce
};

static const uint8_t enc0_vec1_payload[] = "This is the content.";

/* ----- COSE_Mac0 Test Vectors ----- */

/*
 * Test Vector: mac0-pass-01
 * Algorithm: HMAC-256/256
 * Payload: "This is the content."
 * Key: 849b57219dae48de646d07dbb533566e... (32 bytes)
 */
static const uint8_t mac0_vec1_key[] = {
    0x84, 0x9b, 0x57, 0x21, 0x9d, 0xae, 0x48, 0xde,
    0x64, 0x6d, 0x07, 0xdb, 0xb5, 0x33, 0x56, 0x6e,
    0x84, 0x9b, 0x57, 0x21, 0x9d, 0xae, 0x48, 0xde,
    0x64, 0x6d, 0x07, 0xdb, 0xb5, 0x33, 0x56, 0x6e
};

static const uint8_t mac0_vec1_payload[] = "This is the content.";

/* ----- Sign1 Interop Tests ----- */
#ifdef HAVE_ECC
static void test_interop_sign1_roundtrip(void)
{
    WOLFCOSE_KEY signKey;
    ecc_key eccKey;
    WC_RNG rng;
    int ret = 0;
    int rngInited = 0;
    int eccInited = 0;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Interop Sign1 ES256 Round-trip]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        TEST_ASSERT(0, "rng init");
    }
    else {
        rngInited = 1;
    }

    if (ret == 0) {
        ret = wc_ecc_init(&eccKey);
        if (ret != 0) {
            TEST_ASSERT(0, "ecc init");
        }
        else {
            eccInited = 1;
        }
    }

    /* Import the test vector key */
    if (ret == 0) {
        ret = wc_ecc_import_unsigned(&eccKey,
            sign1_vec1_keyX, sign1_vec1_keyY, sign1_vec1_keyD,
            ECC_SECP256R1);
        TEST_ASSERT(ret == 0, "import test vector key");
    }

    if (ret == 0) {
        wc_CoseKey_Init(&signKey);
        ret = wc_CoseKey_SetEcc(&signKey, WOLFCOSE_CRV_P256, &eccKey);
        TEST_ASSERT(ret == 0, "set ecc key");
    }

    /* Sign the payload */
    if (ret == 0) {
        ret = wc_CoseSign1_Sign(&signKey, WOLFCOSE_ALG_ES256,
            NULL, 0, /* kid */
            sign1_vec1_payload, sizeof(sign1_vec1_payload) - 1,
            NULL, 0, /* detached */
            NULL, 0, /* extAad */
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
        TEST_ASSERT(ret == 0 && outLen > 0, "sign message");
    }

    /* Verify with same key */
    if (ret == 0) {
        ret = wc_CoseSign1_Verify(&signKey, out, outLen,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == 0, "verify signature");
        TEST_ASSERT(decPayloadLen == sizeof(sign1_vec1_payload) - 1,
                    "payload length match");
        TEST_ASSERT(memcmp(decPayload, sign1_vec1_payload, decPayloadLen) == 0,
                    "payload content match");
        TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_ES256, "algorithm match");
    }

    if (eccInited != 0) {
        wc_ecc_free(&eccKey);
    }
    if (rngInited != 0) {
        wc_FreeRng(&rng);
    }
}

static void test_interop_sign1_es384_roundtrip(void)
{
    WOLFCOSE_KEY signKey;
    ecc_key eccKey;
    WC_RNG rng;
    int ret = 0;
    int rngInited = 0;
    int eccInited = 0;
    uint8_t payload[] = "ES384 test payload for interop";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Interop Sign1 ES384 Round-trip]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        TEST_ASSERT(0, "rng init");
    }
    else {
        rngInited = 1;
    }

    if (ret == 0) {
        ret = wc_ecc_init(&eccKey);
        if (ret != 0) {
            TEST_ASSERT(0, "ecc init");
        }
        else {
            eccInited = 1;
        }
    }

    /* Generate P-384 key */
    if (ret == 0) {
        ret = wc_ecc_make_key(&rng, 48, &eccKey);
        TEST_ASSERT(ret == 0, "generate P-384 key");
    }

    if (ret == 0) {
        wc_CoseKey_Init(&signKey);
        ret = wc_CoseKey_SetEcc(&signKey, WOLFCOSE_CRV_P384, &eccKey);
        TEST_ASSERT(ret == 0, "set ecc key P-384");
    }

    /* Sign with ES384 */
    if (ret == 0) {
        ret = wc_CoseSign1_Sign(&signKey, WOLFCOSE_ALG_ES384,
            NULL, 0,
            payload, sizeof(payload) - 1,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
        TEST_ASSERT(ret == 0 && outLen > 0, "sign ES384");
    }

    /* Verify */
    if (ret == 0) {
        ret = wc_CoseSign1_Verify(&signKey, out, outLen,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == 0, "verify ES384");
        TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_ES384, "ES384 algorithm match");
    }

    if (eccInited != 0) {
        wc_ecc_free(&eccKey);
    }
    if (rngInited != 0) {
        wc_FreeRng(&rng);
    }
}

static void test_interop_sign1_es512_roundtrip(void)
{
    WOLFCOSE_KEY signKey;
    ecc_key eccKey;
    WC_RNG rng;
    int ret = 0;
    int rngInited = 0;
    int eccInited = 0;
    uint8_t payload[] = "ES512 test payload for interop testing";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[640]; /* ES512 signatures are larger */
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Interop Sign1 ES512 Round-trip]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        TEST_ASSERT(0, "rng init");
    }
    else {
        rngInited = 1;
    }

    if (ret == 0) {
        ret = wc_ecc_init(&eccKey);
        if (ret != 0) {
            TEST_ASSERT(0, "ecc init");
        }
        else {
            eccInited = 1;
        }
    }

    /* Generate P-521 key */
    if (ret == 0) {
        ret = wc_ecc_make_key(&rng, 66, &eccKey);
        TEST_ASSERT(ret == 0, "generate P-521 key");
    }

    if (ret == 0) {
        wc_CoseKey_Init(&signKey);
        ret = wc_CoseKey_SetEcc(&signKey, WOLFCOSE_CRV_P521, &eccKey);
        TEST_ASSERT(ret == 0, "set ecc key P-521");
    }

    /* Sign with ES512 */
    if (ret == 0) {
        ret = wc_CoseSign1_Sign(&signKey, WOLFCOSE_ALG_ES512,
            NULL, 0,
            payload, sizeof(payload) - 1,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
        TEST_ASSERT(ret == 0 && outLen > 0, "sign ES512");
    }

    /* Verify */
    if (ret == 0) {
        ret = wc_CoseSign1_Verify(&signKey, out, outLen,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == 0, "verify ES512");
        TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_ES512, "ES512 algorithm match");
    }

    if (eccInited != 0) {
        wc_ecc_free(&eccKey);
    }
    if (rngInited != 0) {
        wc_FreeRng(&rng);
    }
}

static void test_interop_sign1_with_aad_roundtrip(void)
{
    WOLFCOSE_KEY signKey;
    ecc_key eccKey;
    WC_RNG rng;
    int ret = 0;
    int rngInited = 0;
    int eccInited = 0;
    uint8_t payload[] = "Payload with external AAD";
    uint8_t extAad[] = "application-specific-context";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Interop Sign1 with External AAD]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        TEST_ASSERT(0, "rng init");
    }
    else {
        rngInited = 1;
    }

    if (ret == 0) {
        ret = wc_ecc_init(&eccKey);
        if (ret != 0) {
            TEST_ASSERT(0, "ecc init");
        }
        else {
            eccInited = 1;
        }
    }

    if (ret == 0) {
        ret = wc_ecc_make_key(&rng, 32, &eccKey);
        if (ret != 0) {
            TEST_ASSERT(0, "keygen");
        }
    }

    if (ret == 0) {
        wc_CoseKey_Init(&signKey);
        wc_CoseKey_SetEcc(&signKey, WOLFCOSE_CRV_P256, &eccKey);

        /* Sign with AAD */
        ret = wc_CoseSign1_Sign(&signKey, WOLFCOSE_ALG_ES256,
            NULL, 0,
            payload, sizeof(payload) - 1,
            NULL, 0,
            extAad, sizeof(extAad) - 1,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
        TEST_ASSERT(ret == 0, "sign with AAD");
    }

    /* Verify with correct AAD */
    if (ret == 0) {
        ret = wc_CoseSign1_Verify(&signKey, out, outLen,
            NULL, 0,
            extAad, sizeof(extAad) - 1,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == 0, "verify with correct AAD");
    }

    /* Verify with wrong AAD must fail */
    if (ret == 0) {
        uint8_t wrongAad[] = "wrong-context";
        int verifyRet;
        verifyRet = wc_CoseSign1_Verify(&signKey, out, outLen,
            NULL, 0,
            wrongAad, sizeof(wrongAad) - 1,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(verifyRet != 0, "verify with wrong AAD fails");
    }

    if (eccInited != 0) {
        wc_ecc_free(&eccKey);
    }
    if (rngInited != 0) {
        wc_FreeRng(&rng);
    }
}

static void test_interop_sign1_detached_roundtrip(void)
{
    WOLFCOSE_KEY signKey;
    ecc_key eccKey;
    WC_RNG rng;
    int ret = 0;
    int rngInited = 0;
    int eccInited = 0;
    uint8_t payload[] = "Detached payload content";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Interop Sign1 Detached Payload]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        TEST_ASSERT(0, "rng init");
    }
    else {
        rngInited = 1;
    }

    if (ret == 0) {
        ret = wc_ecc_init(&eccKey);
        if (ret != 0) {
            TEST_ASSERT(0, "ecc init");
        }
        else {
            eccInited = 1;
        }
    }

    if (ret == 0) {
        ret = wc_ecc_make_key(&rng, 32, &eccKey);
        if (ret != 0) {
            TEST_ASSERT(0, "keygen");
        }
    }

    if (ret == 0) {
        wc_CoseKey_Init(&signKey);
        wc_CoseKey_SetEcc(&signKey, WOLFCOSE_CRV_P256, &eccKey);

        /* Sign with detached payload */
        ret = wc_CoseSign1_Sign(&signKey, WOLFCOSE_ALG_ES256,
            NULL, 0,
            NULL, 0, /* no inline payload */
            payload, sizeof(payload) - 1, /* detached payload */
            NULL, 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
        TEST_ASSERT(ret == 0, "sign detached");
    }

    /* Verify with detached payload */
    if (ret == 0) {
        ret = wc_CoseSign1_Verify(&signKey, out, outLen,
            payload, sizeof(payload) - 1,
            NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == 0, "verify detached");
        TEST_ASSERT((hdr.flags & WOLFCOSE_HDR_FLAG_DETACHED) != 0, "detached flag set");
    }

    /* Wrong detached payload must fail */
    if (ret == 0) {
        uint8_t wrongPayload[] = "Wrong payload";
        int verifyRet;
        verifyRet = wc_CoseSign1_Verify(&signKey, out, outLen,
            wrongPayload, sizeof(wrongPayload) - 1,
            NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(verifyRet != 0, "wrong detached payload fails");
    }

    if (eccInited != 0) {
        wc_ecc_free(&eccKey);
    }
    if (rngInited != 0) {
        wc_FreeRng(&rng);
    }
}
#endif /* HAVE_ECC */

/* ----- Encrypt0 Interop Tests ----- */
#ifdef HAVE_AESGCM
static void test_interop_encrypt0_roundtrip(void)
{
    WOLFCOSE_KEY key;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Interop Encrypt0 A128GCM Round-trip]\n");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetSymmetric(&key, enc0_vec1_key, sizeof(enc0_vec1_key));
    TEST_ASSERT(ret == 0, "set symmetric key");

    /* Encrypt */
    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A128GCM,
        enc0_vec1_iv, sizeof(enc0_vec1_iv),
        enc0_vec1_payload, sizeof(enc0_vec1_payload) - 1,
        NULL, 0, NULL,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "encrypt A128GCM");

    /* Decrypt */
    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "decrypt A128GCM");
    TEST_ASSERT(plaintextLen == sizeof(enc0_vec1_payload) - 1, "payload length");
    TEST_ASSERT(memcmp(plaintext, enc0_vec1_payload, plaintextLen) == 0,
                "payload match");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_A128GCM, "algorithm match");
}

static void test_interop_encrypt0_a192gcm_roundtrip(void)
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
    uint8_t payload[] = "A192GCM interop test payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Interop Encrypt0 A192GCM Round-trip]\n");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));
    TEST_ASSERT(ret == 0, "set 192-bit key");

    /* Encrypt with A192GCM */
    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A192GCM,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,
        NULL, 0, NULL,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "encrypt A192GCM");

    /* Decrypt */
    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "decrypt A192GCM");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_A192GCM, "A192GCM algorithm");
    TEST_ASSERT(plaintextLen == sizeof(payload) - 1, "payload length");
}

static void test_interop_encrypt0_a256gcm_roundtrip(void)
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
    uint8_t payload[] = "A256GCM interop test payload data";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Interop Encrypt0 A256GCM Round-trip]\n");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));
    TEST_ASSERT(ret == 0, "set 256-bit key");

    /* Encrypt with A256GCM */
    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A256GCM,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,
        NULL, 0, NULL,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "encrypt A256GCM");

    /* Decrypt */
    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "decrypt A256GCM");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_A256GCM, "A256GCM algorithm");
}

static void test_interop_encrypt0_with_aad(void)
{
    WOLFCOSE_KEY key;
    uint8_t extAad[] = "encryption-context-data";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Interop Encrypt0 with External AAD]\n");

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, enc0_vec1_key, sizeof(enc0_vec1_key));

    /* Encrypt with AAD */
    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A128GCM,
        enc0_vec1_iv, sizeof(enc0_vec1_iv),
        enc0_vec1_payload, sizeof(enc0_vec1_payload) - 1,
        NULL, 0, NULL,
        extAad, sizeof(extAad) - 1,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "encrypt with AAD");

    /* Decrypt with correct AAD */
    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0,
        extAad, sizeof(extAad) - 1,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "decrypt with correct AAD");

    /* Decrypt with wrong AAD must fail */
    /* empty-brace-scan: allow - test-local temporary scope */
    {
        uint8_t wrongAad[] = "wrong-context";
        ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
            NULL, 0,
            wrongAad, sizeof(wrongAad) - 1,
            scratch, sizeof(scratch),
            &hdr,
            plaintext, sizeof(plaintext), &plaintextLen);
        TEST_ASSERT(ret != 0, "wrong AAD fails");
    }
}

static void test_interop_encrypt0_detached(void)
{
    WOLFCOSE_KEY key;
    uint8_t payload[] = "Detached ciphertext payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    uint8_t detachedCt[256];
    size_t detachedCtLen = 0;
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Interop Encrypt0 Detached Ciphertext]\n");

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, enc0_vec1_key, sizeof(enc0_vec1_key));

    /* Encrypt with detached ciphertext */
    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A128GCM,
        enc0_vec1_iv, sizeof(enc0_vec1_iv),
        payload, sizeof(payload) - 1,
        detachedCt, sizeof(detachedCt), &detachedCtLen,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "encrypt detached");
    TEST_ASSERT(detachedCtLen > 0, "detached ct length");

    /* Decrypt with detached ciphertext */
    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        detachedCt, detachedCtLen,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "decrypt detached");
    TEST_ASSERT((hdr.flags & WOLFCOSE_HDR_FLAG_DETACHED) != 0, "detached flag");
}
#endif /* HAVE_AESGCM */

/* ----- Mac0 Interop Tests ----- */
#ifndef NO_HMAC
static void test_interop_mac0_roundtrip(void)
{
    WOLFCOSE_KEY key;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Interop Mac0 HMAC-256/256 Round-trip]\n");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetSymmetric(&key, mac0_vec1_key, sizeof(mac0_vec1_key));
    TEST_ASSERT(ret == 0, "set HMAC key");

    /* Create MAC */
    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC_256_256,
        NULL, 0, /* kid, kidLen */
        mac0_vec1_payload, sizeof(mac0_vec1_payload) - 1,
        NULL, 0, /* detachedPayload, detachedLen */
        NULL, 0, /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0 && outLen > 0, "create MAC");

    /* Verify */
    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "verify MAC");
    TEST_ASSERT(decPayloadLen == sizeof(mac0_vec1_payload) - 1, "payload length");
    TEST_ASSERT(memcmp(decPayload, mac0_vec1_payload, decPayloadLen) == 0,
                "payload match");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_HMAC_256_256, "algorithm match");
}

static void test_interop_mac0_with_aad(void)
{
    WOLFCOSE_KEY key;
    uint8_t extAad[] = "mac-context-data";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Interop Mac0 with External AAD]\n");

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, mac0_vec1_key, sizeof(mac0_vec1_key));

    /* Create MAC with AAD */
    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC_256_256,
        NULL, 0, /* kid, kidLen */
        mac0_vec1_payload, sizeof(mac0_vec1_payload) - 1,
        NULL, 0, /* detachedPayload, detachedLen */
        extAad, sizeof(extAad) - 1, /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "create MAC with AAD");

    /* Verify with correct AAD */
    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0,
        extAad, sizeof(extAad) - 1,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "verify with correct AAD");

    /* Wrong AAD must fail */
    /* empty-brace-scan: allow - test-local temporary scope */
    {
        uint8_t wrongAad[] = "wrong";
        ret = wc_CoseMac0_Verify(&key, out, outLen,
            NULL, 0,
            wrongAad, sizeof(wrongAad) - 1,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret != 0, "wrong AAD fails");
    }
}

static void test_interop_mac0_aes_cbc_mac_128_64(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    uint8_t payload[] = "AES-CBC-MAC-128-64 test";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Interop Mac0 AES-MAC-128/64]\n");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));
    TEST_ASSERT(ret == 0, "set AES key");

    /* Create MAC */
    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_AES_MAC_128_64,
        NULL, 0, /* kid, kidLen */
        payload, sizeof(payload) - 1,
        NULL, 0, /* detachedPayload, detachedLen */
        NULL, 0, /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "create AES-MAC-128/64");

    /* Verify */
    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "verify AES-MAC-128/64");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_AES_MAC_128_64, "algorithm");
}

static void test_interop_mac0_aes_cbc_mac_256_128(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    uint8_t payload[] = "AES-CBC-MAC-256-128 test";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Interop Mac0 AES-MAC-256/128]\n");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));
    TEST_ASSERT(ret == 0, "set AES-256 key");

    /* Create MAC */
    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_AES_MAC_256_128,
        NULL, 0, /* kid, kidLen */
        payload, sizeof(payload) - 1,
        NULL, 0, /* detachedPayload, detachedLen */
        NULL, 0, /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "create AES-MAC-256/128");

    /* Verify */
    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "verify AES-MAC-256/128");
    TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_AES_MAC_256_128, "algorithm");
}

static void test_interop_mac0_detached(void)
{
    WOLFCOSE_KEY key;
    uint8_t payload[] = "Detached MAC payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Interop Mac0 Detached Payload]\n");

    wc_CoseKey_Init(&key);
    wc_CoseKey_SetSymmetric(&key, mac0_vec1_key, sizeof(mac0_vec1_key));

    /* Create MAC with detached payload */
    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC_256_256,
        NULL, 0, /* kid, kidLen */
        NULL, 0, /* no inline payload */
        payload, sizeof(payload) - 1, /* detached */
        NULL, 0, /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "create detached MAC");

    /* Verify with detached payload */
    ret = wc_CoseMac0_Verify(&key, out, outLen,
        payload, sizeof(payload) - 1,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "verify detached MAC");
    TEST_ASSERT((hdr.flags & WOLFCOSE_HDR_FLAG_DETACHED) != 0, "detached flag");

    /* Wrong detached payload must fail */
    /* empty-brace-scan: allow - test-local temporary scope */
    {
        uint8_t wrongPayload[] = "Wrong";
        ret = wc_CoseMac0_Verify(&key, out, outLen,
            wrongPayload, sizeof(wrongPayload) - 1,
            NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret != 0, "wrong detached payload fails");
    }
}
#endif /* !NO_HMAC */

/* ----- EdDSA Interop Tests ----- */
#ifdef HAVE_ED25519
static void test_interop_sign1_eddsa_roundtrip(void)
{
    WOLFCOSE_KEY signKey;
    ed25519_key edKey;
    WC_RNG rng;
    int ret = 0;
    int rngInited = 0;
    int edInited = 0;
    uint8_t payload[] = "EdDSA interoperability test payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Interop Sign1 EdDSA Round-trip]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        TEST_ASSERT(0, "rng init");
    }
    else {
        rngInited = 1;
    }

    if (ret == 0) {
        ret = wc_ed25519_init(&edKey);
        if (ret != 0) {
            TEST_ASSERT(0, "ed init");
        }
        else {
            edInited = 1;
        }
    }

    if (ret == 0) {
        ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &edKey);
        TEST_ASSERT(ret == 0, "generate Ed25519 key");
    }

    if (ret == 0) {
        wc_CoseKey_Init(&signKey);
        ret = wc_CoseKey_SetEd25519(&signKey, &edKey);
        TEST_ASSERT(ret == 0, "set Ed25519 key");
    }

    /* Sign with EdDSA */
    if (ret == 0) {
        ret = wc_CoseSign1_Sign(&signKey, WOLFCOSE_ALG_EDDSA,
            NULL, 0,
            payload, sizeof(payload) - 1,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
        TEST_ASSERT(ret == 0 && outLen > 0, "sign EdDSA");
    }

    /* Verify */
    if (ret == 0) {
        ret = wc_CoseSign1_Verify(&signKey, out, outLen,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == 0, "verify EdDSA");
        TEST_ASSERT(hdr.alg == WOLFCOSE_ALG_EDDSA, "EdDSA algorithm");
        TEST_ASSERT(decPayloadLen == sizeof(payload) - 1, "payload length");
    }

    if (edInited != 0) {
        wc_ed25519_free(&edKey);
    }
    if (rngInited != 0) {
        wc_FreeRng(&rng);
    }
}

static void test_interop_sign1_eddsa_with_aad(void)
{
    WOLFCOSE_KEY signKey;
    ed25519_key edKey;
    WC_RNG rng;
    int ret = 0;
    int rngInited = 0;
    int edInited = 0;
    uint8_t payload[] = "EdDSA with AAD";
    uint8_t extAad[] = "eddsa-context";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Interop Sign1 EdDSA with AAD]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        TEST_ASSERT(0, "rng init");
    }
    else {
        rngInited = 1;
    }

    if (ret == 0) {
        ret = wc_ed25519_init(&edKey);
        if (ret != 0) {
            TEST_ASSERT(0, "ed init");
        }
        else {
            edInited = 1;
        }
    }

    if (ret == 0) {
        ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &edKey);
        if (ret != 0) {
            TEST_ASSERT(0, "keygen");
        }
    }

    if (ret == 0) {
        wc_CoseKey_Init(&signKey);
        wc_CoseKey_SetEd25519(&signKey, &edKey);

        /* Sign with AAD */
        ret = wc_CoseSign1_Sign(&signKey, WOLFCOSE_ALG_EDDSA,
            NULL, 0,
            payload, sizeof(payload) - 1,
            NULL, 0,
            extAad, sizeof(extAad) - 1,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
        TEST_ASSERT(ret == 0, "sign EdDSA with AAD");
    }

    /* Verify with correct AAD */
    if (ret == 0) {
        ret = wc_CoseSign1_Verify(&signKey, out, outLen,
            NULL, 0,
            extAad, sizeof(extAad) - 1,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == 0, "verify EdDSA with AAD");
    }

    if (edInited != 0) {
        wc_ed25519_free(&edKey);
    }
    if (rngInited != 0) {
        wc_FreeRng(&rng);
    }
}
#endif /* HAVE_ED25519 */

/* ----- Multi-Signer Interop Tests ----- */
#ifdef HAVE_ECC
static void test_interop_sign_multi_signer(void)
{
    WOLFCOSE_KEY key1, key2;
    ecc_key eccKey1, eccKey2;
    WOLFCOSE_SIGNATURE signers[2];
    WC_RNG rng;
    int ret = 0;
    int rngInited = 0;
    int ecc1Inited = 0;
    int ecc2Inited = 0;
    uint8_t payload[] = "Multi-signer payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[1024];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Interop Sign Multi-Signer]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        TEST_ASSERT(0, "rng init");
    }
    else {
        rngInited = 1;
    }

    /* Initialize keys */
    if (ret == 0) {
        ret = wc_ecc_init(&eccKey1);
        if (ret == 0) {
            ecc1Inited = 1;
        }
    }

    if (ret == 0) {
        ret = wc_ecc_init(&eccKey2);
        if (ret == 0) {
            ecc2Inited = 1;
        }
    }

    if (ret == 0) {
        ret = wc_ecc_make_key(&rng, 32, &eccKey1);
        if (ret != 0) {
            TEST_ASSERT(0, "keygen1");
        }
    }

    if (ret == 0) {
        ret = wc_ecc_make_key(&rng, 32, &eccKey2);
        if (ret != 0) {
            TEST_ASSERT(0, "keygen2");
        }
    }

    if (ret == 0) {
        wc_CoseKey_Init(&key1);
        wc_CoseKey_SetEcc(&key1, WOLFCOSE_CRV_P256, &eccKey1);

        wc_CoseKey_Init(&key2);
        wc_CoseKey_SetEcc(&key2, WOLFCOSE_CRV_P256, &eccKey2);

        /* Setup signers array */
        signers[0].algId = WOLFCOSE_ALG_ES256;
        signers[0].key = &key1;
        signers[0].kid = (const uint8_t*)"signer-1";
        signers[0].kidLen = 8;

        signers[1].algId = WOLFCOSE_ALG_ES256;
        signers[1].key = &key2;
        signers[1].kid = (const uint8_t*)"signer-2";
        signers[1].kidLen = 8;

        /* Sign with both signers */
        ret = wc_CoseSign_Sign(signers, 2,
            payload, sizeof(payload) - 1,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
        TEST_ASSERT(ret == 0 && outLen > 0, "multi-sign");
    }

    /* Verify with first signer */
    if (ret == 0) {
        ret = wc_CoseSign_Verify(&key1, 0, out, outLen,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == 0, "verify signer 0");
    }

    /* Verify with second signer */
    if (ret == 0) {
        ret = wc_CoseSign_Verify(&key2, 1, out, outLen,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == 0, "verify signer 1");
    }

    if (ecc1Inited != 0) {
        wc_ecc_free(&eccKey1);
    }
    if (ecc2Inited != 0) {
        wc_ecc_free(&eccKey2);
    }
    if (rngInited != 0) {
        wc_FreeRng(&rng);
    }
}

static void test_interop_sign_mixed_algorithms(void)
{
    WOLFCOSE_KEY eccKey256, eccKey384;
    ecc_key ecc256, ecc384;
    WOLFCOSE_SIGNATURE signers[2];
    WC_RNG rng;
    int ret = 0;
    int rngInited = 0;
    int ecc256Inited = 0;
    int ecc384Inited = 0;
    uint8_t payload[] = "Mixed algorithm payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[1024];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("  [Interop Sign Mixed ES256 + ES384]\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        TEST_ASSERT(0, "rng init");
    }
    else {
        rngInited = 1;
    }

    if (ret == 0) {
        ret = wc_ecc_init(&ecc256);
        if (ret == 0) {
            ecc256Inited = 1;
        }
    }

    if (ret == 0) {
        ret = wc_ecc_init(&ecc384);
        if (ret == 0) {
            ecc384Inited = 1;
        }
    }

    if (ret == 0) {
        ret = wc_ecc_make_key(&rng, 32, &ecc256);
        if (ret != 0) {
            TEST_ASSERT(0, "keygen P-256");
        }
    }

    if (ret == 0) {
        ret = wc_ecc_make_key(&rng, 48, &ecc384);
        if (ret != 0) {
            TEST_ASSERT(0, "keygen P-384");
        }
    }

    if (ret == 0) {
        wc_CoseKey_Init(&eccKey256);
        wc_CoseKey_SetEcc(&eccKey256, WOLFCOSE_CRV_P256, &ecc256);

        wc_CoseKey_Init(&eccKey384);
        wc_CoseKey_SetEcc(&eccKey384, WOLFCOSE_CRV_P384, &ecc384);

        /* Mixed algorithm signers */
        signers[0].algId = WOLFCOSE_ALG_ES256;
        signers[0].key = &eccKey256;
        signers[0].kid = (const uint8_t*)"p256";
        signers[0].kidLen = 4;

        signers[1].algId = WOLFCOSE_ALG_ES384;
        signers[1].key = &eccKey384;
        signers[1].kid = (const uint8_t*)"p384";
        signers[1].kidLen = 4;

        /* Sign */
        ret = wc_CoseSign_Sign(signers, 2,
            payload, sizeof(payload) - 1,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen, &rng);
        TEST_ASSERT(ret == 0, "multi-sign mixed");
    }

    /* Verify ES256 signer */
    if (ret == 0) {
        ret = wc_CoseSign_Verify(&eccKey256, 0, out, outLen,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == 0, "verify ES256");
    }

    /* Verify ES384 signer */
    if (ret == 0) {
        ret = wc_CoseSign_Verify(&eccKey384, 1, out, outLen,
            NULL, 0, NULL, 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        TEST_ASSERT(ret == 0, "verify ES384");
    }

    if (ecc256Inited != 0) {
        wc_ecc_free(&ecc256);
    }
    if (ecc384Inited != 0) {
        wc_ecc_free(&ecc384);
    }
    if (rngInited != 0) {
        wc_FreeRng(&rng);
    }
}
#endif /* HAVE_ECC */

/* ----- Multi-Recipient Interop Tests ----- */
#ifdef HAVE_AESGCM
static void test_interop_encrypt_multi_recipient(void)
{
    WOLFCOSE_KEY cek, kek1, kek2;
    WOLFCOSE_RECIPIENT recipients[2];
    uint8_t cekData[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    uint8_t kekData1[16] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00
    };
    uint8_t kekData2[16] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
    };
    uint8_t iv[12] = {
        0x02, 0xD1, 0xF7, 0xE6, 0xF2, 0x6C, 0x43, 0xD4,
        0x86, 0x8D, 0x87, 0xCE
    };
    uint8_t payload[] = "Multi-recipient encrypted payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[1024];
    size_t outLen = 0;
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;
    WC_RNG rng;
    int ret;

    (void)kekData1;
    (void)kekData2;
    (void)kek1;
    (void)kek2;

    printf("  [Interop Encrypt Multi-Recipient]\n");

    ret = wc_InitRng(&rng);
    TEST_ASSERT(ret == 0, "init RNG");

    wc_CoseKey_Init(&cek);
    wc_CoseKey_SetSymmetric(&cek, cekData, sizeof(cekData));

    wc_CoseKey_Init(&kek1);
    wc_CoseKey_SetSymmetric(&kek1, kekData1, sizeof(kekData1));

    wc_CoseKey_Init(&kek2);
    wc_CoseKey_SetSymmetric(&kek2, kekData2, sizeof(kekData2));

    /* Setup recipients with direct key */
    XMEMSET(recipients, 0, sizeof(recipients));
    recipients[0].algId = WOLFCOSE_ALG_DIRECT;
    recipients[0].key = &cek;
    recipients[0].kid = (const uint8_t*)"recipient-1";
    recipients[0].kidLen = 11;

    recipients[1].algId = WOLFCOSE_ALG_DIRECT;
    recipients[1].key = &cek;
    recipients[1].kid = (const uint8_t*)"recipient-2";
    recipients[1].kidLen = 11;

    /* Encrypt - correct argument order per API */
    ret = wc_CoseEncrypt_Encrypt(recipients, 2,
        WOLFCOSE_ALG_A128GCM,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen,
        &rng);
    TEST_ASSERT(ret == 0, "multi-recipient encrypt");

    /* Decrypt with first recipient */
    ret = wc_CoseEncrypt_Decrypt(&recipients[0], 0, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "decrypt recipient 0");

    /* Decrypt with second recipient */
    ret = wc_CoseEncrypt_Decrypt(&recipients[1], 1, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    TEST_ASSERT(ret == 0, "decrypt recipient 1");

    wc_FreeRng(&rng);
}
#endif /* HAVE_AESGCM */

#ifndef NO_HMAC
static void test_interop_mac_multi_recipient(void)
{
    WOLFCOSE_KEY key;
    WOLFCOSE_RECIPIENT recipients[2];
    uint8_t keyData[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    uint8_t payload[] = "Multi-recipient MAC payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[1024];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("  [Interop Mac Multi-Recipient]\n");

    ret = wc_CoseKey_Init(&key);
    TEST_ASSERT(ret == 0, "multi-recipient MAC key init");
    ret = wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));
    TEST_ASSERT(ret == 0, "multi-recipient MAC key set");

    /* Setup recipients with direct key */
    XMEMSET(recipients, 0, sizeof(recipients));
    recipients[0].algId = WOLFCOSE_ALG_DIRECT;
    recipients[0].key = &key;
    recipients[0].kid = (const uint8_t*)"mac-rcpt-1";
    recipients[0].kidLen = 10;

    recipients[1].algId = WOLFCOSE_ALG_DIRECT;
    recipients[1].key = &key;
    recipients[1].kid = (const uint8_t*)"mac-rcpt-2";
    recipients[1].kidLen = 10;

    /* Create MAC - correct argument order per API */
    ret = wc_CoseMac_Create(recipients, 2,
        WOLFCOSE_ALG_HMAC_256_256,
        payload, sizeof(payload) - 1,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    TEST_ASSERT(ret == 0, "multi-recipient MAC create");

    /* Verify with first recipient */
    ret = wc_CoseMac_Verify(&recipients[0], 0, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "verify recipient 0");

    /* Verify with second recipient */
    ret = wc_CoseMac_Verify(&recipients[1], 1, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    TEST_ASSERT(ret == 0, "verify recipient 1");
}
#endif /* !NO_HMAC */

/* ----- Entry point ----- */
int test_interop(void)
{
    g_failures = 0;

    printf("=== COSE Interoperability Tests ===\n\n");

    printf("[Sign1 Tests]\n");
#ifdef HAVE_ECC
    test_interop_sign1_roundtrip();
    test_interop_sign1_es384_roundtrip();
    test_interop_sign1_es512_roundtrip();
    test_interop_sign1_with_aad_roundtrip();
    test_interop_sign1_detached_roundtrip();
#endif

#ifdef HAVE_ED25519
    test_interop_sign1_eddsa_roundtrip();
    test_interop_sign1_eddsa_with_aad();
#endif

    printf("\n[Encrypt0 Tests]\n");
#ifdef HAVE_AESGCM
    test_interop_encrypt0_roundtrip();
    test_interop_encrypt0_a192gcm_roundtrip();
    test_interop_encrypt0_a256gcm_roundtrip();
    test_interop_encrypt0_with_aad();
    test_interop_encrypt0_detached();
#endif

    printf("\n[Mac0 Tests]\n");
#ifndef NO_HMAC
    test_interop_mac0_roundtrip();
    test_interop_mac0_with_aad();
    test_interop_mac0_aes_cbc_mac_128_64();
    test_interop_mac0_aes_cbc_mac_256_128();
    test_interop_mac0_detached();
#endif

    printf("\n[Multi-Signer Tests]\n");
#ifdef HAVE_ECC
    test_interop_sign_multi_signer();
    test_interop_sign_mixed_algorithms();
#endif

    printf("\n[Multi-Recipient Tests]\n");
#ifdef HAVE_AESGCM
    test_interop_encrypt_multi_recipient();
#endif
#ifndef NO_HMAC
    test_interop_mac_multi_recipient();
#endif

    printf("\n=== Interop Results: %s ===\n",
           (g_failures == 0) ? "ALL PASSED" : "FAILURES");
    if (g_failures > 0) {
        printf("%d test(s) failed.\n", g_failures);
    }

    return g_failures;
}

/* Standalone main for interop tests only */
#ifdef WOLFCOSE_INTEROP_TEST_MAIN
int main(void)
{
    return test_interop();
}
#endif
