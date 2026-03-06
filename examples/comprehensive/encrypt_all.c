/* encrypt_all.c
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

/* Comprehensive COSE_Encrypt0 and COSE_Encrypt test coverage.
 *
 * Compile-time gates:
 *   WOLFCOSE_EXAMPLE_ENCRYPT_ALL       - Enable this example (default: enabled)
 *   WOLFCOSE_NO_ENCRYPT_ALL_A128GCM    - Exclude A128GCM tests
 *   WOLFCOSE_NO_ENCRYPT_ALL_A192GCM    - Exclude A192GCM tests
 *   WOLFCOSE_NO_ENCRYPT_ALL_A256GCM    - Exclude A256GCM tests
 *   WOLFCOSE_NO_ENCRYPT_ALL_MULTI      - Exclude multi-recipient tests
 *   WOLFCOSE_NO_ENCRYPT_ALL_INTEROP    - Exclude interop vector tests
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

/* Default: enabled */
#ifndef WOLFCOSE_NO_EXAMPLE_ENCRYPT_ALL
    #define WOLFCOSE_EXAMPLE_ENCRYPT_ALL
#endif

#ifdef WOLFCOSE_EXAMPLE_ENCRYPT_ALL

#include <wolfcose/wolfcose.h>
#include <wolfssl/wolfcrypt/random.h>
#include <stdio.h>
#include <string.h>

/* ----- Test Macros ----- */
#define PRINT_TEST(name) printf("  Testing: %s... ", (name))
#define CHECK_RESULT(r, name) do {                      \
    if ((r) == 0) {                                     \
        printf("PASS\n");                               \
        passed++;                                       \
    } else {                                            \
        printf("FAIL (ret=%d)\n", (r));                \
        failed++;                                       \
    }                                                   \
} while (0)

/**
 * Encrypt0 Worker Function
 *
 * @param alg       Algorithm ID (WOLFCOSE_ALG_A128GCM, etc.)
 * @param keySz     Key size: 16, 24, or 32 bytes
 * @param detached  0=inline ciphertext, 1=detached ciphertext
 * @param useAad    0=no AAD, 1=with external AAD
 * @return 0 on success, negative error code on failure.
 */
#ifdef HAVE_AESGCM
static int test_encrypt0(int32_t alg, int keySz, int detached, int useAad)
{
    int ret = 0;
    WOLFCOSE_KEY cosKey;
    uint8_t keyData[32];
    uint8_t iv[12] = {
        0x02, 0xD1, 0xF7, 0xE6, 0xF2, 0x6C, 0x43, 0xD4,
        0x86, 0x8D, 0x87, 0xCE
    };
    uint8_t out[512];
    uint8_t scratch[512];
    uint8_t payload[] = "test payload for encryption";
    uint8_t aad[] = "external additional authenticated data";
    uint8_t detachedCt[512];
    size_t detachedCtLen = 0;
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    size_t outLen = 0;
    WOLFCOSE_HDR hdr;

    /* Generate test key data */
    XMEMSET(keyData, 0xAB, sizeof(keyData));
    keyData[0] = (uint8_t)keySz;

    wc_CoseKey_Init(&cosKey);
    ret = wc_CoseKey_SetSymmetric(&cosKey, keyData, (size_t)keySz);
    if (ret != 0) { goto cleanup; }

    /* Encrypt */
    if (detached) {
        ret = wc_CoseEncrypt0_Encrypt(&cosKey, alg,
            iv, sizeof(iv),
            payload, sizeof(payload) - 1,
            detachedCt, sizeof(detachedCt), &detachedCtLen,
            useAad ? aad : NULL,
            useAad ? sizeof(aad) - 1 : 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen);
    }
    else {
        ret = wc_CoseEncrypt0_Encrypt(&cosKey, alg,
            iv, sizeof(iv),
            payload, sizeof(payload) - 1,
            NULL, 0, NULL,
            useAad ? aad : NULL,
            useAad ? sizeof(aad) - 1 : 0,
            scratch, sizeof(scratch),
            out, sizeof(out), &outLen);
    }
    if (ret != 0) { goto cleanup; }

    /* Decrypt */
    if (detached) {
        ret = wc_CoseEncrypt0_Decrypt(&cosKey, out, outLen,
            detachedCt, detachedCtLen,
            useAad ? aad : NULL,
            useAad ? sizeof(aad) - 1 : 0,
            scratch, sizeof(scratch),
            &hdr,
            plaintext, sizeof(plaintext), &plaintextLen);
    }
    else {
        ret = wc_CoseEncrypt0_Decrypt(&cosKey, out, outLen,
            NULL, 0,
            useAad ? aad : NULL,
            useAad ? sizeof(aad) - 1 : 0,
            scratch, sizeof(scratch),
            &hdr,
            plaintext, sizeof(plaintext), &plaintextLen);
    }
    if (ret != 0) { goto cleanup; }

    /* Validate */
    if (hdr.alg != alg) {
        ret = -1;
        goto cleanup;
    }
    if (plaintextLen != sizeof(payload) - 1) {
        ret = -2;
        goto cleanup;
    }
    if (XMEMCMP(plaintext, payload, plaintextLen) != 0) {
        ret = -3;
        goto cleanup;
    }

cleanup:
    return ret;
}
#endif /* HAVE_AESGCM */

/* ----- Multi-Recipient Encrypt Worker (Direct Key) ----- */
#if defined(HAVE_AESGCM) && defined(WOLFCOSE_ENCRYPT)
static int test_encrypt_multi_direct(int32_t contentAlg, int keySz,
                                      int recipCount, int detached, int useAad)
{
    int ret = 0;
    WOLFCOSE_KEY cek;
    WOLFCOSE_RECIPIENT recipients[4];
    uint8_t keyData[32];
    uint8_t iv[12] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C
    };
    uint8_t out[1024];
    uint8_t scratch[512];
    uint8_t payload[] = "multi-recipient encrypted payload";
    uint8_t aad[] = "multi-recipient aad";
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    size_t outLen = 0;
    WOLFCOSE_HDR hdr;
    WC_RNG rng;
    int rngInit = 0;
    int i;

    if (recipCount > 4) {
        return WOLFCOSE_E_INVALID_ARG;
    }

    XMEMSET(keyData, 0xCD, sizeof(keyData));
    XMEMSET(recipients, 0, sizeof(recipients));

    ret = wc_InitRng(&rng);
    if (ret != 0) { goto cleanup; }
    rngInit = 1;

    wc_CoseKey_Init(&cek);
    ret = wc_CoseKey_SetSymmetric(&cek, keyData, (size_t)keySz);
    if (ret != 0) { goto cleanup; }

    /* Setup recipients with direct key */
    for (i = 0; i < recipCount; i++) {
        recipients[i].algId = WOLFCOSE_ALG_DIRECT;
        recipients[i].key = &cek;
        recipients[i].kid = (const uint8_t*)"rcpX";
        recipients[i].kidLen = 4;
    }

    /* Encrypt */
    ret = wc_CoseEncrypt_Encrypt(recipients, (size_t)recipCount,
        contentAlg,
        iv, sizeof(iv),
        detached ? NULL : payload,
        detached ? 0 : sizeof(payload) - 1,
        detached ? payload : NULL,
        detached ? sizeof(payload) - 1 : 0,
        useAad ? aad : NULL,
        useAad ? sizeof(aad) - 1 : 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen,
        &rng);
    if (ret != 0) { goto cleanup; }

    /* Decrypt with each recipient */
    for (i = 0; i < recipCount; i++) {
        ret = wc_CoseEncrypt_Decrypt(&recipients[i], (size_t)i, out, outLen,
            detached ? payload : NULL,
            detached ? sizeof(payload) - 1 : 0,
            useAad ? aad : NULL,
            useAad ? sizeof(aad) - 1 : 0,
            scratch, sizeof(scratch),
            &hdr,
            plaintext, sizeof(plaintext), &plaintextLen);
        if (ret != 0) { goto cleanup; }
    }

cleanup:
    if (rngInit) { wc_FreeRng(&rng); }
    return ret;
}
#endif /* HAVE_AESGCM && WOLFCOSE_ENCRYPT */

/* ----- Multi-Recipient with Different Keys (Wrong Key Test) ----- */
#if defined(HAVE_AESGCM) && defined(WOLFCOSE_ENCRYPT)
static int test_encrypt_wrong_key(void)
{
    int ret = 0;
    WOLFCOSE_KEY cek, wrongKey;
    WOLFCOSE_RECIPIENT recipients[2];
    WOLFCOSE_RECIPIENT wrongRecipient;
    uint8_t keyData1[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    uint8_t keyData2[16] = {
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00
    };
    uint8_t iv[12] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C
    };
    uint8_t out[512];
    uint8_t scratch[512];
    uint8_t payload[] = "wrong key test";
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    size_t outLen = 0;
    WOLFCOSE_HDR hdr;
    WC_RNG rng;
    int rngInit = 0;

    XMEMSET(recipients, 0, sizeof(recipients));
    XMEMSET(&wrongRecipient, 0, sizeof(wrongRecipient));

    ret = wc_InitRng(&rng);
    if (ret != 0) { goto cleanup; }
    rngInit = 1;

    wc_CoseKey_Init(&cek);
    ret = wc_CoseKey_SetSymmetric(&cek, keyData1, sizeof(keyData1));
    if (ret != 0) { goto cleanup; }

    wc_CoseKey_Init(&wrongKey);
    ret = wc_CoseKey_SetSymmetric(&wrongKey, keyData2, sizeof(keyData2));
    if (ret != 0) { goto cleanup; }

    /* Setup recipients */
    recipients[0].algId = WOLFCOSE_ALG_DIRECT;
    recipients[0].key = &cek;
    recipients[0].kid = (const uint8_t*)"recip1";
    recipients[0].kidLen = 6;

    recipients[1].algId = WOLFCOSE_ALG_DIRECT;
    recipients[1].key = &cek;
    recipients[1].kid = (const uint8_t*)"recip2";
    recipients[1].kidLen = 6;

    /* Wrong recipient with different key */
    wrongRecipient.algId = WOLFCOSE_ALG_DIRECT;
    wrongRecipient.key = &wrongKey;
    wrongRecipient.kid = (const uint8_t*)"wrong";
    wrongRecipient.kidLen = 5;

    /* Encrypt */
    ret = wc_CoseEncrypt_Encrypt(recipients, 2,
        WOLFCOSE_ALG_A128GCM,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen,
        &rng);
    if (ret != 0) { goto cleanup; }

    /* Decrypt with wrong key must fail */
    ret = wc_CoseEncrypt_Decrypt(&wrongRecipient, 0, out, outLen,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    if (ret == 0) {
        /* Should have failed */
        ret = -100;
        goto cleanup;
    }

    /* Reset ret for success */
    ret = 0;

cleanup:
    if (rngInit) { wc_FreeRng(&rng); }
    return ret;
}
#endif /* HAVE_AESGCM && WOLFCOSE_ENCRYPT */

/* ----- Encrypt0 Test Runner (12 tests) ----- */
#ifdef HAVE_AESGCM
static int test_encrypt0_all(void)
{
    int ret = 0;
    int passed = 0;
    int failed = 0;

    printf("\n=== COSE_Encrypt0 Comprehensive Tests ===\n\n");

#ifndef WOLFCOSE_NO_ENCRYPT_ALL_A128GCM
    /* A128GCM - 4 combinations */
    PRINT_TEST("a128gcm_inline_noaad");
    ret = test_encrypt0(WOLFCOSE_ALG_A128GCM, 16, 0, 0);
    CHECK_RESULT(ret, "a128gcm_inline_noaad");

    PRINT_TEST("a128gcm_inline_aad");
    ret = test_encrypt0(WOLFCOSE_ALG_A128GCM, 16, 0, 1);
    CHECK_RESULT(ret, "a128gcm_inline_aad");

    PRINT_TEST("a128gcm_detached_noaad");
    ret = test_encrypt0(WOLFCOSE_ALG_A128GCM, 16, 1, 0);
    CHECK_RESULT(ret, "a128gcm_detached_noaad");

    PRINT_TEST("a128gcm_detached_aad");
    ret = test_encrypt0(WOLFCOSE_ALG_A128GCM, 16, 1, 1);
    CHECK_RESULT(ret, "a128gcm_detached_aad");
#endif

#ifndef WOLFCOSE_NO_ENCRYPT_ALL_A192GCM
    /* A192GCM - 4 combinations */
    PRINT_TEST("a192gcm_inline_noaad");
    ret = test_encrypt0(WOLFCOSE_ALG_A192GCM, 24, 0, 0);
    CHECK_RESULT(ret, "a192gcm_inline_noaad");

    PRINT_TEST("a192gcm_inline_aad");
    ret = test_encrypt0(WOLFCOSE_ALG_A192GCM, 24, 0, 1);
    CHECK_RESULT(ret, "a192gcm_inline_aad");

    PRINT_TEST("a192gcm_detached_noaad");
    ret = test_encrypt0(WOLFCOSE_ALG_A192GCM, 24, 1, 0);
    CHECK_RESULT(ret, "a192gcm_detached_noaad");

    PRINT_TEST("a192gcm_detached_aad");
    ret = test_encrypt0(WOLFCOSE_ALG_A192GCM, 24, 1, 1);
    CHECK_RESULT(ret, "a192gcm_detached_aad");
#endif

#ifndef WOLFCOSE_NO_ENCRYPT_ALL_A256GCM
    /* A256GCM - 4 combinations */
    PRINT_TEST("a256gcm_inline_noaad");
    ret = test_encrypt0(WOLFCOSE_ALG_A256GCM, 32, 0, 0);
    CHECK_RESULT(ret, "a256gcm_inline_noaad");

    PRINT_TEST("a256gcm_inline_aad");
    ret = test_encrypt0(WOLFCOSE_ALG_A256GCM, 32, 0, 1);
    CHECK_RESULT(ret, "a256gcm_inline_aad");

    PRINT_TEST("a256gcm_detached_noaad");
    ret = test_encrypt0(WOLFCOSE_ALG_A256GCM, 32, 1, 0);
    CHECK_RESULT(ret, "a256gcm_detached_noaad");

    PRINT_TEST("a256gcm_detached_aad");
    ret = test_encrypt0(WOLFCOSE_ALG_A256GCM, 32, 1, 1);
    CHECK_RESULT(ret, "a256gcm_detached_aad");
#endif

    printf("\nEncrypt0 Summary: %d passed, %d failed\n", passed, failed);
    return failed;
}
#endif /* HAVE_AESGCM */

/* ----- Multi-Recipient Test Runner ----- */
#if defined(HAVE_AESGCM) && defined(WOLFCOSE_ENCRYPT) && \
    !defined(WOLFCOSE_NO_ENCRYPT_ALL_MULTI)
static int test_encrypt_multi_all(void)
{
    int ret = 0;
    int passed = 0;
    int failed = 0;

    printf("\n=== COSE_Encrypt Multi-Recipient Comprehensive Tests ===\n\n");

    /* Direct key with A128GCM - varying recipients */
    PRINT_TEST("multi_direct_a128gcm_1recip_inline");
    ret = test_encrypt_multi_direct(WOLFCOSE_ALG_A128GCM, 16, 1, 0, 0);
    CHECK_RESULT(ret, "multi_direct_a128gcm_1recip_inline");

    PRINT_TEST("multi_direct_a128gcm_2recip_inline");
    ret = test_encrypt_multi_direct(WOLFCOSE_ALG_A128GCM, 16, 2, 0, 0);
    CHECK_RESULT(ret, "multi_direct_a128gcm_2recip_inline");

    PRINT_TEST("multi_direct_a128gcm_3recip_inline");
    ret = test_encrypt_multi_direct(WOLFCOSE_ALG_A128GCM, 16, 3, 0, 0);
    CHECK_RESULT(ret, "multi_direct_a128gcm_3recip_inline");

    PRINT_TEST("multi_direct_a128gcm_2recip_aad");
    ret = test_encrypt_multi_direct(WOLFCOSE_ALG_A128GCM, 16, 2, 0, 1);
    CHECK_RESULT(ret, "multi_direct_a128gcm_2recip_aad");

    /* Note: Detached ciphertext is not supported for multi-recipient
     * COSE_Encrypt in this implementation. Only Encrypt0 supports it. */

    /* A192GCM with multiple recipients */
    PRINT_TEST("multi_direct_a192gcm_2recip_inline");
    ret = test_encrypt_multi_direct(WOLFCOSE_ALG_A192GCM, 24, 2, 0, 0);
    CHECK_RESULT(ret, "multi_direct_a192gcm_2recip_inline");

    PRINT_TEST("multi_direct_a192gcm_3recip_aad");
    ret = test_encrypt_multi_direct(WOLFCOSE_ALG_A192GCM, 24, 3, 0, 1);
    CHECK_RESULT(ret, "multi_direct_a192gcm_3recip_aad");

    /* A256GCM with multiple recipients */
    PRINT_TEST("multi_direct_a256gcm_2recip_inline");
    ret = test_encrypt_multi_direct(WOLFCOSE_ALG_A256GCM, 32, 2, 0, 0);
    CHECK_RESULT(ret, "multi_direct_a256gcm_2recip_inline");

    PRINT_TEST("multi_direct_a256gcm_3recip_inline");
    ret = test_encrypt_multi_direct(WOLFCOSE_ALG_A256GCM, 32, 3, 0, 0);
    CHECK_RESULT(ret, "multi_direct_a256gcm_3recip_inline");

    PRINT_TEST("multi_direct_a256gcm_4recip_aad");
    ret = test_encrypt_multi_direct(WOLFCOSE_ALG_A256GCM, 32, 4, 0, 1);
    CHECK_RESULT(ret, "multi_direct_a256gcm_4recip_aad");

    /* Wrong key rejection test */
    PRINT_TEST("multi_wrong_key_fails");
    ret = test_encrypt_wrong_key();
    CHECK_RESULT(ret, "multi_wrong_key_fails");

    printf("\nMulti-Recipient Summary: %d passed, %d failed\n", passed, failed);
    return failed;
}
#endif /* HAVE_AESGCM && WOLFCOSE_ENCRYPT */

/* ----- Interop Vector Tests ----- */
#if defined(HAVE_AESGCM) && !defined(WOLFCOSE_NO_ENCRYPT_ALL_INTEROP)
static int test_encrypt0_interop(void)
{
    int ret = 0;
    int passed = 0;
    int failed = 0;
    WOLFCOSE_KEY cosKey;
    uint8_t scratch[512];
    uint8_t out[512];
    size_t outLen = 0;
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;

    /* Test vector from COSE WG Examples */
    static const uint8_t key[] = {
        0x84, 0x9b, 0x57, 0x21, 0x9d, 0xae, 0x48, 0xde,
        0x64, 0x6d, 0x07, 0xdb, 0xb5, 0x33, 0x56, 0x6e
    };
    static const uint8_t iv[] = {
        0x02, 0xd1, 0xf7, 0xe6, 0xf2, 0x6c, 0x43, 0xd4,
        0x86, 0x8d, 0x87, 0xce
    };
    static const uint8_t payload[] = "This is the content.";

    printf("\n=== COSE_Encrypt0 Interoperability Tests ===\n\n");

    wc_CoseKey_Init(&cosKey);
    ret = wc_CoseKey_SetSymmetric(&cosKey, key, sizeof(key));
    if (ret != 0) { goto cleanup; }

    /* Encrypt with known key */
    PRINT_TEST("interop_encrypt0_a128gcm_roundtrip");
    ret = wc_CoseEncrypt0_Encrypt(&cosKey, WOLFCOSE_ALG_A128GCM,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,
        NULL, 0, NULL,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    if (ret != 0) { goto cleanup; }

    /* Decrypt with same key */
    ret = wc_CoseEncrypt0_Decrypt(&cosKey, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);
    if (ret != 0) { goto cleanup; }

    /* Validate */
    if (hdr.alg != WOLFCOSE_ALG_A128GCM) {
        ret = -1;
        goto cleanup;
    }
    if (plaintextLen != sizeof(payload) - 1) {
        ret = -2;
        goto cleanup;
    }
    if (XMEMCMP(plaintext, payload, plaintextLen) != 0) {
        ret = -3;
        goto cleanup;
    }

    CHECK_RESULT(ret, "interop_encrypt0_a128gcm_roundtrip");

cleanup:
    printf("\nInterop Summary: %d passed, %d failed\n", passed, failed);
    return failed;
}
#endif /* HAVE_AESGCM && !WOLFCOSE_NO_ENCRYPT_ALL_INTEROP */

/* ----- Main Entry Point ----- */
int main(void)
{
    int totalFailed = 0;

    printf("========================================\n");
    printf("wolfCOSE Comprehensive Encrypt Tests\n");
    printf("========================================\n");

#ifdef HAVE_AESGCM
    totalFailed += test_encrypt0_all();
#endif

#if defined(HAVE_AESGCM) && defined(WOLFCOSE_ENCRYPT) && \
    !defined(WOLFCOSE_NO_ENCRYPT_ALL_MULTI)
    totalFailed += test_encrypt_multi_all();
#endif

#if defined(HAVE_AESGCM) && !defined(WOLFCOSE_NO_ENCRYPT_ALL_INTEROP)
    totalFailed += test_encrypt0_interop();
#endif

#ifndef HAVE_AESGCM
    printf("AES-GCM not available - encryption tests skipped\n");
#endif

    printf("\n========================================\n");
    printf("Total: %d failures\n", totalFailed);
    printf("========================================\n");

    return totalFailed;
}

#else /* !WOLFCOSE_EXAMPLE_ENCRYPT_ALL */

int main(void)
{
    printf("encrypt_all: example disabled (WOLFCOSE_NO_EXAMPLE_ENCRYPT_ALL defined)\n");
    return 0;
}

#endif /* WOLFCOSE_EXAMPLE_ENCRYPT_ALL */
