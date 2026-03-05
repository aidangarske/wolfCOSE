/* mac0_demo.c
 *
 * Comprehensive COSE_Mac0 demonstration
 * Tests HMAC variants with various modes
 *
 * Copyright (C) 2024 wolfSSL Inc.
 */

#include <stdio.h>
#include <string.h>
#include <wolfcose/wolfcose.h>

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

    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC256,
        NULL, 0,
        payload, sizeof(payload) - 1,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    DEMO_ASSERT(ret == 0, "Create MAC");
    printf("  COSE_Mac0: %zu bytes\n", outLen);

    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    DEMO_ASSERT(ret == 0, "Verify MAC");
    DEMO_ASSERT(decPayloadLen == sizeof(payload) - 1, "Payload length");
    DEMO_ASSERT(memcmp(decPayload, payload, decPayloadLen) == 0, "Payload match");
    DEMO_ASSERT(hdr.alg == WOLFCOSE_ALG_HMAC256, "Algorithm");

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

    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC384,
        NULL, 0,
        payload, sizeof(payload) - 1,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    DEMO_ASSERT(ret == 0, "Create MAC");
    printf("  COSE_Mac0: %zu bytes\n", outLen);

    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    DEMO_ASSERT(ret == 0, "Verify MAC");
    DEMO_ASSERT(hdr.alg == WOLFCOSE_ALG_HMAC384, "Algorithm");

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

    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC512,
        NULL, 0,
        payload, sizeof(payload) - 1,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    DEMO_ASSERT(ret == 0, "Create MAC");
    printf("  COSE_Mac0: %zu bytes\n", outLen);

    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    DEMO_ASSERT(ret == 0, "Verify MAC");
    DEMO_ASSERT(hdr.alg == WOLFCOSE_ALG_HMAC512, "Algorithm");

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
    WOLFCOSE_HDR hdr;
    int ret;

    printf("--- COSE_Mac0 with External AAD ---\n");
    printf("  Payload: \"%s\"\n", payload);
    printf("  AAD: \"%s\"\n", aad);

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));
    DEMO_ASSERT(ret == 0, "Set symmetric key");

    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC256,
        NULL, 0,
        payload, sizeof(payload) - 1,
        aad, sizeof(aad) - 1,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    DEMO_ASSERT(ret == 0, "Create MAC with AAD");
    printf("  COSE_Mac0: %zu bytes\n", outLen);

    /* Verify with correct AAD */
    ret = wc_CoseMac0_Verify(&key, out, outLen,
        aad, sizeof(aad) - 1,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    DEMO_ASSERT(ret == 0, "Verify with correct AAD");

    /* Verify wrong AAD fails */
    uint8_t wrongAad[] = "Wrong AAD";
    ret = wc_CoseMac0_Verify(&key, out, outLen,
        wrongAad, sizeof(wrongAad) - 1,
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

    ret = wc_CoseMac0_Create(&key, WOLFCOSE_ALG_HMAC256,
        NULL, 0,
        payload, sizeof(payload) - 1,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    DEMO_ASSERT(ret == 0, "Create MAC");

    /* Tamper with one byte */
    out[outLen - 5] ^= 0xFF;

    ret = wc_CoseMac0_Verify(&key, out, outLen,
        NULL, 0,
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

#ifndef NO_HMAC
    if (demo_mac0_hmac256() != 0) failures++;
#ifdef WOLFSSL_SHA384
    if (demo_mac0_hmac384() != 0) failures++;
#endif
#ifdef WOLFSSL_SHA512
    if (demo_mac0_hmac512() != 0) failures++;
#endif
    if (demo_mac0_with_aad() != 0) failures++;
    if (demo_mac0_tamper_detection() != 0) failures++;
#else
    printf("HMAC not enabled in wolfSSL\n");
#endif

    printf("\n=== Results: %d failure(s) ===\n", failures);
    return failures;
}
