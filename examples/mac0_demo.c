/* mac0_demo.c
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

/* Comprehensive COSE_Mac0 demonstration
 * Tests HMAC variants with various modes
 */

#include <stdio.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfcose/wolfcose.h>

/* Guard: this demo requires both Mac0 create and verify APIs */
#if defined(WOLFCOSE_MAC0_CREATE) && defined(WOLFCOSE_MAC0_VERIFY) && \
    !defined(NO_HMAC)

#define DEMO_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s\n", msg); \
        return -1; \
    } \
} while(0)

/* All buffers on stack - no dynamic allocation */
static int demo_mac0_hmac256(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    uint8_t payload[] = "HMAC-256 test payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[256];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("--- COSE_Mac0 HMAC-256/256 ---\n");
    printf("  Payload: \"%s\" (%zu bytes)\n", payload, sizeof(payload) - 1);

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));
    DEMO_ASSERT(ret == 0, "Set symmetric key");

    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC_256_256,
        NULL, 0,                           /* kid, kidLen */
        payload, sizeof(payload) - 1,      /* payload, payloadLen */
        NULL, 0,                           /* detachedPayload, detachedLen */
        NULL, 0,                           /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    DEMO_ASSERT(ret == 0, "Create MAC");
    printf("  COSE_Mac0: %zu bytes\n", outLen);

    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0,                           /* detachedPayload, detachedLen */
        NULL, 0,                           /* extAad, extAadLen */
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    DEMO_ASSERT(ret == 0, "Verify MAC");
    DEMO_ASSERT(decPayloadLen == sizeof(payload) - 1, "Payload length");
    DEMO_ASSERT(memcmp(decPayload, payload, decPayloadLen) == 0, "Payload match");
    DEMO_ASSERT(hdr.alg == WOLFCOSE_ALG_HMAC_256_256, "Algorithm");

    printf("  Result: PASS\n");
    return 0;
}

static int demo_mac0_hmac384(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[48];
    uint8_t payload[] = "HMAC-384 test payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[256];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;
    size_t i;

    printf("--- COSE_Mac0 HMAC-384/384 ---\n");
    printf("  Payload: \"%s\" (%zu bytes)\n", payload, sizeof(payload) - 1);

    /* Initialize 48-byte key */
    for (i = 0; i < sizeof(keyData); i++) {
        keyData[i] = (uint8_t)(i + 1);
    }

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));
    DEMO_ASSERT(ret == 0, "Set symmetric key");

    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC_384_384,
        NULL, 0,                           /* kid, kidLen */
        payload, sizeof(payload) - 1,      /* payload, payloadLen */
        NULL, 0,                           /* detachedPayload, detachedLen */
        NULL, 0,                           /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    DEMO_ASSERT(ret == 0, "Create MAC");
    printf("  COSE_Mac0: %zu bytes\n", outLen);

    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0,                           /* detachedPayload, detachedLen */
        NULL, 0,                           /* extAad, extAadLen */
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    DEMO_ASSERT(ret == 0, "Verify MAC");
    DEMO_ASSERT(hdr.alg == WOLFCOSE_ALG_HMAC_384_384, "Algorithm");

    printf("  Result: PASS\n");
    return 0;
}

static int demo_mac0_hmac512(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[64];
    uint8_t payload[] = "HMAC-512 test payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[256];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;
    size_t i;

    printf("--- COSE_Mac0 HMAC-512/512 ---\n");
    printf("  Payload: \"%s\" (%zu bytes)\n", payload, sizeof(payload) - 1);

    /* Initialize 64-byte key */
    for (i = 0; i < sizeof(keyData); i++) {
        keyData[i] = (uint8_t)(i + 1);
    }

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));
    DEMO_ASSERT(ret == 0, "Set symmetric key");

    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC_512_512,
        NULL, 0,                           /* kid, kidLen */
        payload, sizeof(payload) - 1,      /* payload, payloadLen */
        NULL, 0,                           /* detachedPayload, detachedLen */
        NULL, 0,                           /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    DEMO_ASSERT(ret == 0, "Create MAC");
    printf("  COSE_Mac0: %zu bytes\n", outLen);

    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0,                           /* detachedPayload, detachedLen */
        NULL, 0,                           /* extAad, extAadLen */
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    DEMO_ASSERT(ret == 0, "Verify MAC");
    DEMO_ASSERT(hdr.alg == WOLFCOSE_ALG_HMAC_512_512, "Algorithm");

    printf("  Result: PASS\n");
    return 0;
}

static int demo_mac0_with_aad(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    uint8_t payload[] = "Payload with AAD";
    uint8_t aad[] = "Additional authenticated data";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[256];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    static const uint8_t wrongAad[] = {
        0x57u, 0x72u, 0x6Fu, 0x6Eu, 0x67u, 0x20u, 0x41u, 0x41u, 0x44u
    };
    WOLFCOSE_HDR hdr;
    int ret;

    printf("--- COSE_Mac0 with External AAD ---\n");
    printf("  Payload: \"%s\"\n", payload);
    printf("  AAD: \"%s\"\n", aad);

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));
    DEMO_ASSERT(ret == 0, "Set symmetric key");

    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC_256_256,
        NULL, 0,                           /* kid, kidLen */
        payload, sizeof(payload) - 1,      /* payload, payloadLen */
        NULL, 0,                           /* detachedPayload, detachedLen */
        aad, sizeof(aad) - 1,              /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    DEMO_ASSERT(ret == 0, "Create MAC with AAD");
    printf("  COSE_Mac0: %zu bytes\n", outLen);

    /* Verify with correct AAD */
    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0,                           /* detachedPayload, detachedLen */
        aad, sizeof(aad) - 1,              /* extAad, extAadLen */
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    DEMO_ASSERT(ret == 0, "Verify with correct AAD");

    /* Verify wrong AAD fails */
    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0,                           /* detachedPayload, detachedLen */
        wrongAad, sizeof(wrongAad) - 1,    /* extAad, extAadLen */
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    DEMO_ASSERT(ret != 0, "Wrong AAD rejected");

    printf("  Result: PASS\n");
    return 0;
}

static int demo_mac0_tamper_detection(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    uint8_t payload[] = "Tamper detection test";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[256];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("--- COSE_Mac0 Tamper Detection ---\n");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));
    DEMO_ASSERT(ret == 0, "Set symmetric key");

    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC_256_256,
        NULL, 0,                           /* kid, kidLen */
        payload, sizeof(payload) - 1,      /* payload, payloadLen */
        NULL, 0,                           /* detachedPayload, detachedLen */
        NULL, 0,                           /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    DEMO_ASSERT(ret == 0, "Create MAC");

    /* Tamper with one byte */
    out[outLen - 5] ^= 0xFF;

    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0,                           /* detachedPayload, detachedLen */
        NULL, 0,                           /* extAad, extAadLen */
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    DEMO_ASSERT(ret != 0, "Tampered message rejected");

    printf("  Result: PASS\n");
    return 0;
}

int main(void)
{
    int failures = 0;

    printf("=== wolfCOSE Mac0 Demo ===\n\n");

    if (demo_mac0_hmac256() != 0) failures++;
#ifdef WOLFSSL_SHA384
    if (demo_mac0_hmac384() != 0) failures++;
#endif
#ifdef WOLFSSL_SHA512
    if (demo_mac0_hmac512() != 0) failures++;
#endif
    if (demo_mac0_with_aad() != 0) failures++;
    if (demo_mac0_tamper_detection() != 0) failures++;

    printf("\n=== Results: %d failure(s) ===\n", failures);
    return failures;
}

#else /* Build guards not met */

int main(void)
{
#ifndef WOLFCOSE_MAC0_CREATE
    printf("mac0_demo: Mac0 create API disabled (WOLFCOSE_MAC0_CREATE not defined)\n");
#elif !defined(WOLFCOSE_MAC0_VERIFY)
    printf("mac0_demo: Mac0 verify API disabled (WOLFCOSE_MAC0_VERIFY not defined)\n");
#elif defined(NO_HMAC)
    printf("mac0_demo: HMAC not enabled in wolfSSL\n");
#endif
    return 0;
}

#endif /* WOLFCOSE_MAC0_CREATE && WOLFCOSE_MAC0_VERIFY && !NO_HMAC */
