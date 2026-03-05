/* mac_all.c
 *
 * Comprehensive COSE_Mac0 and COSE_Mac test coverage.
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
 *
 * Compile-time gates:
 *   WOLFCOSE_EXAMPLE_MAC_ALL           - Enable this example (default: enabled)
 *   WOLFCOSE_NO_MAC_ALL_HMAC256        - Exclude HMAC-256/256 tests
 *   WOLFCOSE_NO_MAC_ALL_HMAC384        - Exclude HMAC-384/384 tests
 *   WOLFCOSE_NO_MAC_ALL_HMAC512        - Exclude HMAC-512/512 tests
 *   WOLFCOSE_NO_MAC_ALL_AES_MAC        - Exclude AES-CBC-MAC tests
 *   WOLFCOSE_NO_MAC_ALL_MULTI          - Exclude multi-recipient tests
 *   WOLFCOSE_NO_MAC_ALL_INTEROP        - Exclude interop vector tests
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

/* Default: enabled */
#ifndef WOLFCOSE_NO_EXAMPLE_MAC_ALL
    #define WOLFCOSE_EXAMPLE_MAC_ALL
#endif

#ifdef WOLFCOSE_EXAMPLE_MAC_ALL

#include <wolfcose/wolfcose.h>
#include <wolfssl/wolfcrypt/random.h>
#include <stdio.h>
#include <string.h>

/* ---------------------------------------------------------------------------
 * Test Macros
 * --------------------------------------------------------------------------- */
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

/* ---------------------------------------------------------------------------
 * Mac0 Worker Function
 *
 * Parameters:
 *   alg       - Algorithm ID (WOLFCOSE_ALG_HMAC_256_256, etc.)
 *   keySz     - Key size in bytes
 *   detached  - 0=inline payload, 1=detached payload
 *   useAad    - 0=no AAD, 1=with external AAD
 *
 * Returns 0 on success, negative error code on failure.
 * --------------------------------------------------------------------------- */
#ifndef NO_HMAC
static int test_mac0(int32_t alg, int keySz, int detached, int useAad)
{
    int ret = 0;
    WOLFCOSE_KEY cosKey;
    uint8_t keyData[64];
    uint8_t out[512];
    uint8_t scratch[512];
    uint8_t payload[] = "test payload for MAC operation";
    uint8_t aad[] = "external additional authenticated data";
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    /* Generate test key data */
    XMEMSET(keyData, 0xAB, sizeof(keyData));
    keyData[0] = (uint8_t)keySz;

    wc_CoseKey_Init(&cosKey);
    ret = wc_CoseKey_SetSymmetric(&cosKey, keyData, (size_t)keySz);
    if (ret != 0) { goto cleanup; }

    /* Create MAC */
    ret = wc_CoseMac0_Create(&cosKey, alg,
        NULL, 0,  /* kid */
        detached ? NULL : payload,
        detached ? 0 : sizeof(payload) - 1,
        detached ? payload : NULL,
        detached ? sizeof(payload) - 1 : 0,
        useAad ? aad : NULL,
        useAad ? sizeof(aad) - 1 : 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    if (ret != 0) { goto cleanup; }

    /* Verify */
    ret = wc_CoseMac0_Verify(&cosKey, out, outLen,
        detached ? payload : NULL,
        detached ? sizeof(payload) - 1 : 0,
        useAad ? aad : NULL,
        useAad ? sizeof(aad) - 1 : 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    if (ret != 0) { goto cleanup; }

    /* Validate algorithm */
    if (hdr.alg != alg) {
        ret = -1;
        goto cleanup;
    }

    /* Validate payload if inline */
    if (!detached) {
        if (decPayloadLen != sizeof(payload) - 1) {
            ret = -2;
            goto cleanup;
        }
        if (XMEMCMP(decPayload, payload, decPayloadLen) != 0) {
            ret = -3;
            goto cleanup;
        }
    }

cleanup:
    return ret;
}
#endif /* !NO_HMAC */

/* ---------------------------------------------------------------------------
 * Multi-Recipient Mac Worker (Direct Key)
 * --------------------------------------------------------------------------- */
#if !defined(NO_HMAC) && defined(WOLFCOSE_MAC)
static int test_mac_multi_direct(int32_t macAlg, int keySz,
                                  int recipCount, int detached, int useAad)
{
    int ret = 0;
    WOLFCOSE_KEY macKey;
    WOLFCOSE_RECIPIENT recipients[4];
    uint8_t keyData[64];
    uint8_t out[1024];
    uint8_t scratch[512];
    uint8_t payload[] = "multi-recipient MAC payload";
    uint8_t aad[] = "multi-recipient mac aad";
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    size_t outLen = 0;
    WOLFCOSE_HDR hdr;
    int i;

    if (recipCount > 4) {
        return WOLFCOSE_E_INVALID_ARG;
    }

    XMEMSET(keyData, 0xCD, sizeof(keyData));
    XMEMSET(recipients, 0, sizeof(recipients));

    wc_CoseKey_Init(&macKey);
    ret = wc_CoseKey_SetSymmetric(&macKey, keyData, (size_t)keySz);
    if (ret != 0) { goto cleanup; }

    /* Setup recipients with direct key */
    for (i = 0; i < recipCount; i++) {
        recipients[i].algId = WOLFCOSE_ALG_DIRECT;
        recipients[i].key = &macKey;
        recipients[i].kid = (const uint8_t*)"macX";
        recipients[i].kidLen = 4;
    }

    /* Create MAC */
    ret = wc_CoseMac_Create(recipients, (size_t)recipCount,
        macAlg,
        detached ? NULL : payload,
        detached ? 0 : sizeof(payload) - 1,
        detached ? payload : NULL,
        detached ? sizeof(payload) - 1 : 0,
        useAad ? aad : NULL,
        useAad ? sizeof(aad) - 1 : 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    if (ret != 0) { goto cleanup; }

    /* Verify with each recipient */
    for (i = 0; i < recipCount; i++) {
        ret = wc_CoseMac_Verify(&recipients[i], (size_t)i, out, outLen,
            detached ? payload : NULL,
            detached ? sizeof(payload) - 1 : 0,
            useAad ? aad : NULL,
            useAad ? sizeof(aad) - 1 : 0,
            scratch, sizeof(scratch),
            &hdr, &decPayload, &decPayloadLen);
        if (ret != 0) { goto cleanup; }
    }

cleanup:
    return ret;
}
#endif /* !NO_HMAC && WOLFCOSE_MAC */

/* ---------------------------------------------------------------------------
 * Multi-Recipient Wrong Key Test
 * --------------------------------------------------------------------------- */
#if !defined(NO_HMAC) && defined(WOLFCOSE_MAC)
static int test_mac_wrong_key(void)
{
    int ret = 0;
    WOLFCOSE_KEY macKey, wrongKey;
    WOLFCOSE_RECIPIENT recipients[2];
    WOLFCOSE_RECIPIENT wrongRecipient;
    uint8_t keyData1[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    uint8_t keyData2[32] = {
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
    };
    uint8_t out[512];
    uint8_t scratch[512];
    uint8_t payload[] = "wrong key test";
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    size_t outLen = 0;
    WOLFCOSE_HDR hdr;

    XMEMSET(recipients, 0, sizeof(recipients));
    XMEMSET(&wrongRecipient, 0, sizeof(wrongRecipient));

    wc_CoseKey_Init(&macKey);
    ret = wc_CoseKey_SetSymmetric(&macKey, keyData1, sizeof(keyData1));
    if (ret != 0) { goto cleanup; }

    wc_CoseKey_Init(&wrongKey);
    ret = wc_CoseKey_SetSymmetric(&wrongKey, keyData2, sizeof(keyData2));
    if (ret != 0) { goto cleanup; }

    /* Setup recipients */
    recipients[0].algId = WOLFCOSE_ALG_DIRECT;
    recipients[0].key = &macKey;
    recipients[0].kid = (const uint8_t*)"recip1";
    recipients[0].kidLen = 6;

    recipients[1].algId = WOLFCOSE_ALG_DIRECT;
    recipients[1].key = &macKey;
    recipients[1].kid = (const uint8_t*)"recip2";
    recipients[1].kidLen = 6;

    /* Wrong recipient with different key */
    wrongRecipient.algId = WOLFCOSE_ALG_DIRECT;
    wrongRecipient.key = &wrongKey;
    wrongRecipient.kid = (const uint8_t*)"wrong";
    wrongRecipient.kidLen = 5;

    /* Create MAC */
    ret = wc_CoseMac_Create(recipients, 2,
        WOLFCOSE_ALG_HMAC_256_256,
        payload, sizeof(payload) - 1,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    if (ret != 0) { goto cleanup; }

    /* Verify with wrong key must fail */
    ret = wc_CoseMac_Verify(&wrongRecipient, 0, out, outLen,
        NULL, 0,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    if (ret == 0) {
        /* Should have failed */
        ret = -100;
        goto cleanup;
    }

    /* Reset ret for success */
    ret = 0;

cleanup:
    return ret;
}
#endif /* !NO_HMAC && WOLFCOSE_MAC */

/* ---------------------------------------------------------------------------
 * Mac0 Test Runner (20 tests)
 * --------------------------------------------------------------------------- */
#ifndef NO_HMAC
static int test_mac0_all(void)
{
    int ret = 0;
    int passed = 0;
    int failed = 0;

    printf("\n=== COSE_Mac0 Comprehensive Tests ===\n\n");

#ifndef WOLFCOSE_NO_MAC_ALL_HMAC256
    /* HMAC-256/256 - 4 combinations */
    PRINT_TEST("hmac256_inline_noaad");
    ret = test_mac0(WOLFCOSE_ALG_HMAC_256_256, 32, 0, 0);
    CHECK_RESULT(ret, "hmac256_inline_noaad");

    PRINT_TEST("hmac256_inline_aad");
    ret = test_mac0(WOLFCOSE_ALG_HMAC_256_256, 32, 0, 1);
    CHECK_RESULT(ret, "hmac256_inline_aad");

    PRINT_TEST("hmac256_detached_noaad");
    ret = test_mac0(WOLFCOSE_ALG_HMAC_256_256, 32, 1, 0);
    CHECK_RESULT(ret, "hmac256_detached_noaad");

    PRINT_TEST("hmac256_detached_aad");
    ret = test_mac0(WOLFCOSE_ALG_HMAC_256_256, 32, 1, 1);
    CHECK_RESULT(ret, "hmac256_detached_aad");
#endif

#if defined(WOLFSSL_SHA384) && !defined(WOLFCOSE_NO_MAC_ALL_HMAC384)
    /* HMAC-384/384 - 4 combinations */
    PRINT_TEST("hmac384_inline_noaad");
    ret = test_mac0(WOLFCOSE_ALG_HMAC_384_384, 48, 0, 0);
    CHECK_RESULT(ret, "hmac384_inline_noaad");

    PRINT_TEST("hmac384_inline_aad");
    ret = test_mac0(WOLFCOSE_ALG_HMAC_384_384, 48, 0, 1);
    CHECK_RESULT(ret, "hmac384_inline_aad");

    PRINT_TEST("hmac384_detached_noaad");
    ret = test_mac0(WOLFCOSE_ALG_HMAC_384_384, 48, 1, 0);
    CHECK_RESULT(ret, "hmac384_detached_noaad");

    PRINT_TEST("hmac384_detached_aad");
    ret = test_mac0(WOLFCOSE_ALG_HMAC_384_384, 48, 1, 1);
    CHECK_RESULT(ret, "hmac384_detached_aad");
#endif

#if defined(WOLFSSL_SHA512) && !defined(WOLFCOSE_NO_MAC_ALL_HMAC512)
    /* HMAC-512/512 - 4 combinations */
    PRINT_TEST("hmac512_inline_noaad");
    ret = test_mac0(WOLFCOSE_ALG_HMAC_512_512, 64, 0, 0);
    CHECK_RESULT(ret, "hmac512_inline_noaad");

    PRINT_TEST("hmac512_inline_aad");
    ret = test_mac0(WOLFCOSE_ALG_HMAC_512_512, 64, 0, 1);
    CHECK_RESULT(ret, "hmac512_inline_aad");

    PRINT_TEST("hmac512_detached_noaad");
    ret = test_mac0(WOLFCOSE_ALG_HMAC_512_512, 64, 1, 0);
    CHECK_RESULT(ret, "hmac512_detached_noaad");

    PRINT_TEST("hmac512_detached_aad");
    ret = test_mac0(WOLFCOSE_ALG_HMAC_512_512, 64, 1, 1);
    CHECK_RESULT(ret, "hmac512_detached_aad");
#endif

#if defined(HAVE_AES_CBC) && !defined(WOLFCOSE_NO_MAC_ALL_AES_MAC)
    /* AES-MAC-128/64 - 4 combinations */
    PRINT_TEST("aes_mac_128_64_inline_noaad");
    ret = test_mac0(WOLFCOSE_ALG_AES_MAC_128_64, 16, 0, 0);
    CHECK_RESULT(ret, "aes_mac_128_64_inline_noaad");

    PRINT_TEST("aes_mac_128_64_inline_aad");
    ret = test_mac0(WOLFCOSE_ALG_AES_MAC_128_64, 16, 0, 1);
    CHECK_RESULT(ret, "aes_mac_128_64_inline_aad");

    PRINT_TEST("aes_mac_128_64_detached_noaad");
    ret = test_mac0(WOLFCOSE_ALG_AES_MAC_128_64, 16, 1, 0);
    CHECK_RESULT(ret, "aes_mac_128_64_detached_noaad");

    PRINT_TEST("aes_mac_128_64_detached_aad");
    ret = test_mac0(WOLFCOSE_ALG_AES_MAC_128_64, 16, 1, 1);
    CHECK_RESULT(ret, "aes_mac_128_64_detached_aad");

    /* AES-MAC-256/128 - 4 combinations */
    PRINT_TEST("aes_mac_256_128_inline_noaad");
    ret = test_mac0(WOLFCOSE_ALG_AES_MAC_256_128, 32, 0, 0);
    CHECK_RESULT(ret, "aes_mac_256_128_inline_noaad");

    PRINT_TEST("aes_mac_256_128_inline_aad");
    ret = test_mac0(WOLFCOSE_ALG_AES_MAC_256_128, 32, 0, 1);
    CHECK_RESULT(ret, "aes_mac_256_128_inline_aad");

    PRINT_TEST("aes_mac_256_128_detached_noaad");
    ret = test_mac0(WOLFCOSE_ALG_AES_MAC_256_128, 32, 1, 0);
    CHECK_RESULT(ret, "aes_mac_256_128_detached_noaad");

    PRINT_TEST("aes_mac_256_128_detached_aad");
    ret = test_mac0(WOLFCOSE_ALG_AES_MAC_256_128, 32, 1, 1);
    CHECK_RESULT(ret, "aes_mac_256_128_detached_aad");
#endif

    printf("\nMac0 Summary: %d passed, %d failed\n", passed, failed);
    return failed;
}
#endif /* !NO_HMAC */

/* ---------------------------------------------------------------------------
 * Multi-Recipient Test Runner
 * --------------------------------------------------------------------------- */
#if !defined(NO_HMAC) && defined(WOLFCOSE_MAC) && \
    !defined(WOLFCOSE_NO_MAC_ALL_MULTI)
static int test_mac_multi_all(void)
{
    int ret = 0;
    int passed = 0;
    int failed = 0;

    printf("\n=== COSE_Mac Multi-Recipient Comprehensive Tests ===\n\n");

    /* HMAC-256/256 with multiple recipients */
    PRINT_TEST("multi_hmac256_1recip_inline");
    ret = test_mac_multi_direct(WOLFCOSE_ALG_HMAC_256_256, 32, 1, 0, 0);
    CHECK_RESULT(ret, "multi_hmac256_1recip_inline");

    PRINT_TEST("multi_hmac256_2recip_inline");
    ret = test_mac_multi_direct(WOLFCOSE_ALG_HMAC_256_256, 32, 2, 0, 0);
    CHECK_RESULT(ret, "multi_hmac256_2recip_inline");

    PRINT_TEST("multi_hmac256_3recip_inline");
    ret = test_mac_multi_direct(WOLFCOSE_ALG_HMAC_256_256, 32, 3, 0, 0);
    CHECK_RESULT(ret, "multi_hmac256_3recip_inline");

    PRINT_TEST("multi_hmac256_2recip_aad");
    ret = test_mac_multi_direct(WOLFCOSE_ALG_HMAC_256_256, 32, 2, 0, 1);
    CHECK_RESULT(ret, "multi_hmac256_2recip_aad");

    PRINT_TEST("multi_hmac256_2recip_detached");
    ret = test_mac_multi_direct(WOLFCOSE_ALG_HMAC_256_256, 32, 2, 1, 0);
    CHECK_RESULT(ret, "multi_hmac256_2recip_detached");

    PRINT_TEST("multi_hmac256_2recip_detached_aad");
    ret = test_mac_multi_direct(WOLFCOSE_ALG_HMAC_256_256, 32, 2, 1, 1);
    CHECK_RESULT(ret, "multi_hmac256_2recip_detached_aad");

#ifdef WOLFSSL_SHA384
    /* HMAC-384/384 with multiple recipients */
    PRINT_TEST("multi_hmac384_2recip_inline");
    ret = test_mac_multi_direct(WOLFCOSE_ALG_HMAC_384_384, 48, 2, 0, 0);
    CHECK_RESULT(ret, "multi_hmac384_2recip_inline");

    PRINT_TEST("multi_hmac384_3recip_aad");
    ret = test_mac_multi_direct(WOLFCOSE_ALG_HMAC_384_384, 48, 3, 0, 1);
    CHECK_RESULT(ret, "multi_hmac384_3recip_aad");
#endif

#ifdef WOLFSSL_SHA512
    /* HMAC-512/512 with multiple recipients */
    PRINT_TEST("multi_hmac512_2recip_inline");
    ret = test_mac_multi_direct(WOLFCOSE_ALG_HMAC_512_512, 64, 2, 0, 0);
    CHECK_RESULT(ret, "multi_hmac512_2recip_inline");

    PRINT_TEST("multi_hmac512_4recip_aad");
    ret = test_mac_multi_direct(WOLFCOSE_ALG_HMAC_512_512, 64, 4, 0, 1);
    CHECK_RESULT(ret, "multi_hmac512_4recip_aad");
#endif

    /* Wrong key rejection test */
    PRINT_TEST("multi_wrong_key_fails");
    ret = test_mac_wrong_key();
    CHECK_RESULT(ret, "multi_wrong_key_fails");

    printf("\nMulti-Recipient Summary: %d passed, %d failed\n", passed, failed);
    return failed;
}
#endif /* !NO_HMAC && WOLFCOSE_MAC */

/* ---------------------------------------------------------------------------
 * Interop Vector Tests
 * --------------------------------------------------------------------------- */
#if !defined(NO_HMAC) && !defined(WOLFCOSE_NO_MAC_ALL_INTEROP)
static int test_mac0_interop(void)
{
    int ret = 0;
    int passed = 0;
    int failed = 0;
    WOLFCOSE_KEY cosKey;
    uint8_t scratch[512];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;

    /* Test vector key (32 bytes for HMAC-256) */
    static const uint8_t key[] = {
        0x84, 0x9b, 0x57, 0x21, 0x9d, 0xae, 0x48, 0xde,
        0x64, 0x6d, 0x07, 0xdb, 0xb5, 0x33, 0x56, 0x6e,
        0x84, 0x9b, 0x57, 0x21, 0x9d, 0xae, 0x48, 0xde,
        0x64, 0x6d, 0x07, 0xdb, 0xb5, 0x33, 0x56, 0x6e
    };
    static const uint8_t payload[] = "This is the content.";

    printf("\n=== COSE_Mac0 Interoperability Tests ===\n\n");

    wc_CoseKey_Init(&cosKey);
    ret = wc_CoseKey_SetSymmetric(&cosKey, key, sizeof(key));
    if (ret != 0) { goto cleanup; }

    /* Create MAC with known key */
    PRINT_TEST("interop_mac0_hmac256_roundtrip");
    ret = wc_CoseMac0_Create(&cosKey, WOLFCOSE_ALG_HMAC_256_256,
        NULL, 0,
        payload, sizeof(payload) - 1,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    if (ret != 0) { goto cleanup; }

    /* Verify with same key */
    ret = wc_CoseMac0_Verify(&cosKey, out, outLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    if (ret != 0) { goto cleanup; }

    /* Validate */
    if (hdr.alg != WOLFCOSE_ALG_HMAC_256_256) {
        ret = -1;
        goto cleanup;
    }
    if (decPayloadLen != sizeof(payload) - 1) {
        ret = -2;
        goto cleanup;
    }
    if (XMEMCMP(decPayload, payload, decPayloadLen) != 0) {
        ret = -3;
        goto cleanup;
    }

    CHECK_RESULT(ret, "interop_mac0_hmac256_roundtrip");

cleanup:
    printf("\nInterop Summary: %d passed, %d failed\n", passed, failed);
    return failed;
}
#endif /* !NO_HMAC && !WOLFCOSE_NO_MAC_ALL_INTEROP */

/* ---------------------------------------------------------------------------
 * Main Entry Point
 * --------------------------------------------------------------------------- */
int main(void)
{
    int totalFailed = 0;

    printf("========================================\n");
    printf("wolfCOSE Comprehensive MAC Tests\n");
    printf("========================================\n");

#ifndef NO_HMAC
    totalFailed += test_mac0_all();
#endif

#if !defined(NO_HMAC) && defined(WOLFCOSE_MAC) && \
    !defined(WOLFCOSE_NO_MAC_ALL_MULTI)
    totalFailed += test_mac_multi_all();
#endif

#if !defined(NO_HMAC) && !defined(WOLFCOSE_NO_MAC_ALL_INTEROP)
    totalFailed += test_mac0_interop();
#endif

#ifdef NO_HMAC
    printf("HMAC not available - MAC tests skipped\n");
#endif

    printf("\n========================================\n");
    printf("Total: %d failures\n", totalFailed);
    printf("========================================\n");

    return totalFailed;
}

#else /* !WOLFCOSE_EXAMPLE_MAC_ALL */

int main(void)
{
    printf("mac_all: example disabled (WOLFCOSE_NO_EXAMPLE_MAC_ALL defined)\n");
    return 0;
}

#endif /* WOLFCOSE_EXAMPLE_MAC_ALL */
