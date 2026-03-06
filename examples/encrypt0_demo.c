/* encrypt0_demo.c
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

/* Comprehensive COSE_Encrypt0 demonstration
 * Tests all AES-GCM key sizes with various modes
 */

#include <stdio.h>
#include <string.h>
#include <wolfcose/wolfcose.h>
#include <wolfssl/wolfcrypt/random.h>

#define DEMO_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s\n", msg); \
        return -1; \
    } \
} while(0)

/* All buffers on stack - no dynamic allocation */
static int demo_encrypt0_a128gcm(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    uint8_t iv[12] = {
        0x02, 0xD1, 0xF7, 0xE6, 0xF2, 0x6C, 0x43, 0xD4,
        0x86, 0x8D, 0x87, 0xCE
    };
    uint8_t payload[] = "A128GCM test payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[256];
    size_t outLen = 0;
    uint8_t plaintext[128];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("--- COSE_Encrypt0 A128GCM ---\n");
    printf("  Payload: \"%s\" (%zu bytes)\n", payload, sizeof(payload) - 1);

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));
    DEMO_ASSERT(ret == 0, "Set symmetric key");

    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A128GCM,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,      /* payload, payloadLen */
        NULL, 0, NULL,                     /* detachedPayload, detachedSz, detachedLen */
        NULL, 0,                           /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    DEMO_ASSERT(ret == 0, "Encrypt");
    printf("  COSE_Encrypt0: %zu bytes\n", outLen);

    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0,                           /* detachedCt, detachedCtLen */
        NULL, 0,                           /* extAad, extAadLen */
        scratch, sizeof(scratch),
        &hdr, plaintext, sizeof(plaintext), &plaintextLen);
    DEMO_ASSERT(ret == 0, "Decrypt");
    DEMO_ASSERT(plaintextLen == sizeof(payload) - 1, "Payload length");
    DEMO_ASSERT(memcmp(plaintext, payload, plaintextLen) == 0, "Payload match");
    DEMO_ASSERT(hdr.alg == WOLFCOSE_ALG_A128GCM, "Algorithm");

    printf("  Result: PASS\n");
    return 0;
}

static int demo_encrypt0_a192gcm(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[24] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18
    };
    uint8_t iv[12] = {
        0x02, 0xD1, 0xF7, 0xE6, 0xF2, 0x6C, 0x43, 0xD4,
        0x86, 0x8D, 0x87, 0xCE
    };
    uint8_t payload[] = "A192GCM test payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[256];
    size_t outLen = 0;
    uint8_t plaintext[128];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("--- COSE_Encrypt0 A192GCM ---\n");
    printf("  Payload: \"%s\" (%zu bytes)\n", payload, sizeof(payload) - 1);

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));
    DEMO_ASSERT(ret == 0, "Set symmetric key");

    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A192GCM,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,      /* payload, payloadLen */
        NULL, 0, NULL,                     /* detachedPayload, detachedSz, detachedLen */
        NULL, 0,                           /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    DEMO_ASSERT(ret == 0, "Encrypt");
    printf("  COSE_Encrypt0: %zu bytes\n", outLen);

    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0,                           /* detachedCt, detachedCtLen */
        NULL, 0,                           /* extAad, extAadLen */
        scratch, sizeof(scratch),
        &hdr, plaintext, sizeof(plaintext), &plaintextLen);
    DEMO_ASSERT(ret == 0, "Decrypt");
    DEMO_ASSERT(hdr.alg == WOLFCOSE_ALG_A192GCM, "Algorithm");

    printf("  Result: PASS\n");
    return 0;
}

static int demo_encrypt0_a256gcm(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    uint8_t iv[12] = {
        0x02, 0xD1, 0xF7, 0xE6, 0xF2, 0x6C, 0x43, 0xD4,
        0x86, 0x8D, 0x87, 0xCE
    };
    uint8_t payload[] = "A256GCM test payload";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[256];
    size_t outLen = 0;
    uint8_t plaintext[128];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("--- COSE_Encrypt0 A256GCM ---\n");
    printf("  Payload: \"%s\" (%zu bytes)\n", payload, sizeof(payload) - 1);

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));
    DEMO_ASSERT(ret == 0, "Set symmetric key");

    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A256GCM,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,      /* payload, payloadLen */
        NULL, 0, NULL,                     /* detachedPayload, detachedSz, detachedLen */
        NULL, 0,                           /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    DEMO_ASSERT(ret == 0, "Encrypt");
    printf("  COSE_Encrypt0: %zu bytes\n", outLen);

    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0,                           /* detachedCt, detachedCtLen */
        NULL, 0,                           /* extAad, extAadLen */
        scratch, sizeof(scratch),
        &hdr, plaintext, sizeof(plaintext), &plaintextLen);
    DEMO_ASSERT(ret == 0, "Decrypt");
    DEMO_ASSERT(hdr.alg == WOLFCOSE_ALG_A256GCM, "Algorithm");

    printf("  Result: PASS\n");
    return 0;
}

static int demo_encrypt0_with_aad(void)
{
    WOLFCOSE_KEY key;
    uint8_t keyData[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    uint8_t iv[12] = {
        0x02, 0xD1, 0xF7, 0xE6, 0xF2, 0x6C, 0x43, 0xD4,
        0x86, 0x8D, 0x87, 0xCE
    };
    uint8_t payload[] = "Payload with AAD";
    uint8_t aad[] = "Additional authenticated data";
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t out[256];
    size_t outLen = 0;
    uint8_t plaintext[128];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;
    int ret;

    printf("--- COSE_Encrypt0 with External AAD ---\n");
    printf("  Payload: \"%s\"\n", payload);
    printf("  AAD: \"%s\"\n", aad);

    wc_CoseKey_Init(&key);
    ret = wc_CoseKey_SetSymmetric(&key, keyData, sizeof(keyData));
    DEMO_ASSERT(ret == 0, "Set symmetric key");

    ret = wc_CoseEncrypt0_Encrypt(&key, WOLFCOSE_ALG_A128GCM,
        iv, sizeof(iv),
        payload, sizeof(payload) - 1,      /* payload, payloadLen */
        NULL, 0, NULL,                     /* detachedPayload, detachedSz, detachedLen */
        aad, sizeof(aad) - 1,              /* extAad, extAadLen */
        scratch, sizeof(scratch),
        out, sizeof(out), &outLen);
    DEMO_ASSERT(ret == 0, "Encrypt with AAD");
    printf("  COSE_Encrypt0: %zu bytes\n", outLen);

    /* Decrypt with correct AAD */
    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0,                           /* detachedCt, detachedCtLen */
        aad, sizeof(aad) - 1,              /* extAad, extAadLen */
        scratch, sizeof(scratch),
        &hdr, plaintext, sizeof(plaintext), &plaintextLen);
    DEMO_ASSERT(ret == 0, "Decrypt with correct AAD");

    /* Verify wrong AAD fails */
    uint8_t wrongAad[] = "Wrong AAD";
    ret = wc_CoseEncrypt0_Decrypt(&key, out, outLen,
        NULL, 0,                           /* detachedCt, detachedCtLen */
        wrongAad, sizeof(wrongAad) - 1,    /* extAad, extAadLen */
        scratch, sizeof(scratch),
        &hdr, plaintext, sizeof(plaintext), &plaintextLen);
    DEMO_ASSERT(ret != 0, "Wrong AAD rejected");

    printf("  Result: PASS\n");
    return 0;
}

int main(void)
{
    int failures = 0;

    printf("=== wolfCOSE Encrypt0 Demo ===\n\n");

#ifdef HAVE_AESGCM
    if (demo_encrypt0_a128gcm() != 0) failures++;
    if (demo_encrypt0_a192gcm() != 0) failures++;
    if (demo_encrypt0_a256gcm() != 0) failures++;
    if (demo_encrypt0_with_aad() != 0) failures++;
#else
    printf("AES-GCM not enabled in wolfSSL\n");
#endif

    printf("\n=== Results: %d failure(s) ===\n", failures);
    return failures;
}
