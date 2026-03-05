/* sign1_demo.c
 *
 * Comprehensive COSE_Sign1 demonstration
 * Tests all signature algorithms: ES256, ES384, ES512, EdDSA
 *
 * Copyright (C) 2024 wolfSSL Inc.
 */

#include <stdio.h>
#include <string.h>
#include <wolfcose/wolfcose.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/random.h>

#define DEMO_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s\n", msg); \
        return -1; \
    } \
} while(0)

/* All buffers on stack - no dynamic allocation */
#ifdef HAVE_ECC
static int demo_sign1_es256(void)
{
    WOLFCOSE_KEY key;
    ecc_key eccKey;
    WC_RNG rng;
    uint8_t payload[] = "ES256 test payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("--- COSE_Sign1 ES256 (P-256) ---\n");
    printf("  Payload: \"%s\" (%zu bytes)\n", payload, sizeof(payload) - 1);

    ret = wc_InitRng(&rng);
    DEMO_ASSERT(ret == 0, "Init RNG");

    wc_ecc_init(&eccKey);
    ret = wc_ecc_make_key(&rng, 32, &eccKey);
    DEMO_ASSERT(ret == 0, "Generate P-256 key");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &eccKey);
    DEMO_ASSERT(ret == 0, "Set ECC key");

    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256,
        NULL, 0,
        payload, sizeof(payload) - 1,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    DEMO_ASSERT(ret == 0, "Sign");
    printf("  COSE_Sign1: %zu bytes\n", outLen);

    ret = wc_CoseSign1_Verify(&key, out, outLen,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    DEMO_ASSERT(ret == 0, "Verify");
    DEMO_ASSERT(decPayloadLen == sizeof(payload) - 1, "Payload length");
    DEMO_ASSERT(memcmp(decPayload, payload, decPayloadLen) == 0, "Payload match");
    DEMO_ASSERT(hdr.alg == WOLFCOSE_ALG_ES256, "Algorithm");

    wc_ecc_free(&eccKey);
    wc_FreeRng(&rng);
    printf("  Result: PASS\n");
    return 0;
}

#ifdef WOLFSSL_SHA384
static int demo_sign1_es384(void)
{
    WOLFCOSE_KEY key;
    ecc_key eccKey;
    WC_RNG rng;
    uint8_t payload[] = "ES384 test payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("--- COSE_Sign1 ES384 (P-384) ---\n");
    printf("  Payload: \"%s\" (%zu bytes)\n", payload, sizeof(payload) - 1);

    ret = wc_InitRng(&rng);
    DEMO_ASSERT(ret == 0, "Init RNG");

    wc_ecc_init(&eccKey);
    ret = wc_ecc_make_key(&rng, 48, &eccKey);
    DEMO_ASSERT(ret == 0, "Generate P-384 key");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P384, &eccKey);
    DEMO_ASSERT(ret == 0, "Set ECC key");

    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES384,
        NULL, 0,
        payload, sizeof(payload) - 1,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    DEMO_ASSERT(ret == 0, "Sign");
    printf("  COSE_Sign1: %zu bytes\n", outLen);

    ret = wc_CoseSign1_Verify(&key, out, outLen,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    DEMO_ASSERT(ret == 0, "Verify");
    DEMO_ASSERT(hdr.alg == WOLFCOSE_ALG_ES384, "Algorithm");

    wc_ecc_free(&eccKey);
    wc_FreeRng(&rng);
    printf("  Result: PASS\n");
    return 0;
}
#endif

#ifdef WOLFSSL_SHA512
static int demo_sign1_es512(void)
{
    WOLFCOSE_KEY key;
    ecc_key eccKey;
    WC_RNG rng;
    uint8_t payload[] = "ES512 test payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[640];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("--- COSE_Sign1 ES512 (P-521) ---\n");
    printf("  Payload: \"%s\" (%zu bytes)\n", payload, sizeof(payload) - 1);

    ret = wc_InitRng(&rng);
    DEMO_ASSERT(ret == 0, "Init RNG");

    wc_ecc_init(&eccKey);
    ret = wc_ecc_make_key(&rng, 66, &eccKey);
    DEMO_ASSERT(ret == 0, "Generate P-521 key");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P521, &eccKey);
    DEMO_ASSERT(ret == 0, "Set ECC key");

    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES512,
        NULL, 0,
        payload, sizeof(payload) - 1,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    DEMO_ASSERT(ret == 0, "Sign");
    printf("  COSE_Sign1: %zu bytes\n", outLen);

    ret = wc_CoseSign1_Verify(&key, out, outLen,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    DEMO_ASSERT(ret == 0, "Verify");
    DEMO_ASSERT(hdr.alg == WOLFCOSE_ALG_ES512, "Algorithm");

    wc_ecc_free(&eccKey);
    wc_FreeRng(&rng);
    printf("  Result: PASS\n");
    return 0;
}
#endif

static int demo_sign1_with_aad(void)
{
    WOLFCOSE_KEY key;
    ecc_key eccKey;
    WC_RNG rng;
    uint8_t payload[] = "Payload with AAD";
    uint8_t aad[] = "Additional authenticated data";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("--- COSE_Sign1 with External AAD ---\n");
    printf("  Payload: \"%s\"\n", payload);
    printf("  AAD: \"%s\"\n", aad);

    ret = wc_InitRng(&rng);
    DEMO_ASSERT(ret == 0, "Init RNG");

    wc_ecc_init(&eccKey);
    ret = wc_ecc_make_key(&rng, 32, &eccKey);
    DEMO_ASSERT(ret == 0, "Generate key");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &eccKey);
    DEMO_ASSERT(ret == 0, "Set ECC key");

    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_ES256,
        NULL, 0,
        payload, sizeof(payload) - 1,
        aad, sizeof(aad) - 1,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    DEMO_ASSERT(ret == 0, "Sign with AAD");
    printf("  COSE_Sign1: %zu bytes\n", outLen);

    /* Verify with correct AAD */
    ret = wc_CoseSign1_Verify(&key, out, outLen,
        aad, sizeof(aad) - 1,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    DEMO_ASSERT(ret == 0, "Verify with correct AAD");

    /* Verify wrong AAD fails */
    uint8_t wrongAad[] = "Wrong AAD";
    ret = wc_CoseSign1_Verify(&key, out, outLen,
        wrongAad, sizeof(wrongAad) - 1,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    DEMO_ASSERT(ret != 0, "Wrong AAD rejected");

    wc_ecc_free(&eccKey);
    wc_FreeRng(&rng);
    printf("  Result: PASS\n");
    return 0;
}
#endif /* HAVE_ECC */

#ifdef HAVE_ED25519
static int demo_sign1_eddsa(void)
{
    WOLFCOSE_KEY key;
    ed25519_key edKey;
    WC_RNG rng;
    uint8_t payload[] = "EdDSA test payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[512];
    size_t outLen = 0;
    const uint8_t* decPayload = NULL;
    size_t decPayloadLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("--- COSE_Sign1 EdDSA (Ed25519) ---\n");
    printf("  Payload: \"%s\" (%zu bytes)\n", payload, sizeof(payload) - 1);

    ret = wc_InitRng(&rng);
    DEMO_ASSERT(ret == 0, "Init RNG");

    wc_ed25519_init(&edKey);
    ret = wc_ed25519_make_key(&rng, 32, &edKey);
    DEMO_ASSERT(ret == 0, "Generate Ed25519 key");

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetEd25519(&key, &edKey);
    DEMO_ASSERT(ret == 0, "Set Ed25519 key");

    ret = wc_CoseSign1_Sign(&key, WOLFCOSE_ALG_EDDSA,
        NULL, 0,
        payload, sizeof(payload) - 1,
        NULL, 0,
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen, &rng);
    DEMO_ASSERT(ret == 0, "Sign");
    printf("  COSE_Sign1: %zu bytes\n", outLen);

    ret = wc_CoseSign1_Verify(&key, out, outLen,
        NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &decPayload, &decPayloadLen);
    DEMO_ASSERT(ret == 0, "Verify");
    DEMO_ASSERT(hdr.alg == WOLFCOSE_ALG_EDDSA, "Algorithm");

    wc_ed25519_free(&edKey);
    wc_FreeRng(&rng);
    printf("  Result: PASS\n");
    return 0;
}
#endif

int main(void)
{
    int failures = 0;

    printf("=== wolfCOSE Sign1 Demo ===\n\n");

#ifdef HAVE_ECC
    if (demo_sign1_es256() != 0) failures++;
#ifdef WOLFSSL_SHA384
    if (demo_sign1_es384() != 0) failures++;
#endif
#ifdef WOLFSSL_SHA512
    if (demo_sign1_es512() != 0) failures++;
#endif
    if (demo_sign1_with_aad() != 0) failures++;
#endif

#ifdef HAVE_ED25519
    if (demo_sign1_eddsa() != 0) failures++;
#endif

    printf("\n=== Results: %d failure(s) ===\n", failures);
    return failures;
}
