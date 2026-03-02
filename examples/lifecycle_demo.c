/* lifecycle_demo.c
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
 * lifecycle_demo.c -- Edge-to-Cloud COSE_Sign1 Lifecycle Demo
 *
 * Simulates:
 *   1. Edge Device (Producer): CBOR-encode sensor data, sign with COSE_Sign1
 *   2. Network Transport: copy signed packet to "receive" buffer
 *   3. Cloud Server (Consumer): verify signature, extract payload
 *
 * Goal: prove full COSE security lifecycle in <1KB RAM
 *       (excluding wolfCrypt math internals).
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
#include <wolfssl/wolfcrypt/ecc.h>
#include <stdio.h>
#include <string.h>

/* Stack measurement via GCC builtin */
#ifdef __GNUC__
    #define STACK_MARKER()  ((size_t)__builtin_frame_address(0))
#else
    #define STACK_MARKER()  0
#endif

/* Static key compiled in -- simulates pre-provisioned secure storage.
 * Real devices use hardware key stores; this is for demo purposes only. */
static const uint8_t g_eccPrivKey[32] = {
    0xE0, 0x19, 0xDD, 0xF4, 0x79, 0x87, 0xE8, 0xC1,
    0x41, 0xC4, 0x86, 0x9F, 0x64, 0x81, 0x50, 0xED,
    0x0A, 0x5F, 0x08, 0xA3, 0x77, 0x1C, 0x98, 0xA5,
    0x23, 0xD7, 0x8E, 0xD3, 0x26, 0xDC, 0xE1, 0x14
};

static const uint8_t g_eccPubX[32] = {
    0x0A, 0x47, 0x52, 0xC4, 0xE2, 0xA7, 0x6F, 0x22,
    0x29, 0xD7, 0x38, 0xD8, 0x5D, 0x2D, 0xD1, 0x6E,
    0xE8, 0x56, 0x9D, 0x60, 0xFB, 0xD3, 0x88, 0x66,
    0x2C, 0x42, 0x1E, 0xCA, 0xBA, 0x03, 0x9A, 0x43
};

static const uint8_t g_eccPubY[32] = {
    0x88, 0x6C, 0xED, 0xC9, 0x31, 0xFA, 0xBA, 0x2A,
    0x9A, 0x6C, 0xD3, 0xBE, 0xD0, 0x83, 0x69, 0x93,
    0x03, 0x89, 0xB1, 0x3A, 0xC1, 0xDF, 0x37, 0xE3,
    0xAB, 0x4E, 0xAB, 0x3F, 0x0D, 0x49, 0xB4, 0x94
};

static const uint8_t g_kid[] = "edge-sensor-01";

/* ---------------------------------------------------------------------------
 * Producer: edge device
 * --------------------------------------------------------------------------- */
static int edge_device_produce(uint8_t* packet, size_t packetSz,
                                size_t* packetLen, size_t* payloadUsed)
{
    int ret;
    uint8_t payload[64];
    WOLFCOSE_CBOR_CTX cbor;
    WOLFCOSE_KEY coseKey;
    ecc_key eccKey;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    WC_RNG rng;

    /* Step 1: CBOR-encode sensor payload: {"temp": 22, "humidity": 45} */
    cbor.buf = payload;
    cbor.bufSz = sizeof(payload);
    cbor.idx = 0;

    ret = wc_CBOR_EncodeMapStart(&cbor, 2);
    if (ret == 0) {
        ret = wc_CBOR_EncodeTstr(&cbor, (const uint8_t*)"temp", 4);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeUint(&cbor, 22);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeTstr(&cbor, (const uint8_t*)"humidity", 8);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeUint(&cbor, 45);
    }
    if (ret != 0) {
        printf("[Producer] CBOR encode failed: %d\n", ret);
        return ret;
    }

    *payloadUsed = cbor.idx;
    printf("[Producer] Encoded sensor data: %zu bytes CBOR\n", cbor.idx);

    /* Step 2: Import pre-provisioned ECC P-256 key (private + public) */
    ret = wc_ecc_init(&eccKey);
    if (ret != 0) {
        printf("[Producer] ecc_init failed: %d\n", ret);
        return ret;
    }

    ret = wc_ecc_import_unsigned(&eccKey,
        (byte*)g_eccPubX, (byte*)g_eccPubY, (byte*)g_eccPrivKey,
        ECC_SECP256R1);
    if (ret != 0) {
        printf("[Producer] Key import failed: %d\n", ret);
        wc_ecc_free(&eccKey);
        return ret;
    }

    wc_CoseKey_Init(&coseKey);
    wc_CoseKey_SetEcc(&coseKey, WOLFCOSE_CRV_P256, &eccKey);

    /* Step 3: Sign with COSE_Sign1 */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        wc_ecc_free(&eccKey);
        return ret;
    }

    ret = wc_CoseSign1_Sign(&coseKey, WOLFCOSE_ALG_ES256,
        g_kid, sizeof(g_kid) - 1,
        payload, cbor.idx,
        NULL, 0,
        scratch, sizeof(scratch),
        packet, packetSz, packetLen, &rng);

    wc_FreeRng(&rng);
    wc_ecc_free(&eccKey);

    if (ret != 0) {
        printf("[Producer] Sign failed: %d\n", ret);
    }
    else {
        printf("[Producer] Signed COSE_Sign1: %zu bytes\n", *packetLen);
    }

    return ret;
}

/* ---------------------------------------------------------------------------
 * Consumer: cloud server
 * --------------------------------------------------------------------------- */
static int cloud_server_consume(const uint8_t* packet, size_t packetLen)
{
    int ret;
    WOLFCOSE_KEY coseKey;
    ecc_key eccPub;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    WOLFCOSE_HDR hdr;
    const uint8_t* payload = NULL;
    size_t payloadLen = 0;

    /* Step 1: Import pre-shared public key (same key pair as producer) */
    ret = wc_ecc_init(&eccPub);
    if (ret != 0) {
        printf("[Consumer] ecc_init failed: %d\n", ret);
        return ret;
    }

    ret = wc_ecc_import_unsigned(&eccPub,
        (byte*)g_eccPubX, (byte*)g_eccPubY, NULL,
        ECC_SECP256R1);
    if (ret != 0) {
        printf("[Consumer] Key import failed: %d\n", ret);
        wc_ecc_free(&eccPub);
        return ret;
    }

    wc_CoseKey_Init(&coseKey);
    wc_CoseKey_SetEcc(&coseKey, WOLFCOSE_CRV_P256, &eccPub);

    /* Step 2: Verify COSE_Sign1 */
    ret = wc_CoseSign1_Verify(&coseKey, packet, packetLen,
        NULL, 0, scratch, sizeof(scratch),
        &hdr, &payload, &payloadLen);

    if (ret != 0) {
        printf("[Consumer] Verification FAILED: %d\n", ret);
        wc_ecc_free(&eccPub);
        return ret;
    }

    printf("[Consumer] Signature verified: OK\n");

    /* Step 3: Decode CBOR payload */
    {
        WOLFCOSE_CBOR_CTX cbor;
        size_t mapCount;
        size_t i;
        const uint8_t* keyStr;
        size_t keyLen;
        uint64_t val;

        cbor.buf = (uint8_t*)(uintptr_t)payload;
        cbor.bufSz = payloadLen;
        cbor.idx = 0;

        ret = wc_CBOR_DecodeMapStart(&cbor, &mapCount);
        if (ret == 0) {
            for (i = 0; i < mapCount && ret == 0; i++) {
                ret = wc_CBOR_DecodeTstr(&cbor, &keyStr, &keyLen);
                if (ret != 0) break;
                ret = wc_CBOR_DecodeUint(&cbor, &val);
                if (ret != 0) break;
                printf("[Consumer] Decoded: %.*s=%llu\n",
                       (int)keyLen, keyStr, (unsigned long long)val);
            }
        }
    }

    wc_ecc_free(&eccPub);
    return ret;
}

/* ---------------------------------------------------------------------------
 * main
 * --------------------------------------------------------------------------- */
int main(void)
{
    int ret;
    uint8_t packet[512];
    size_t packetLen = 0;
    size_t payloadUsed = 0;
    size_t stackBefore, stackAfter;

    printf("=== wolfCOSE Lifecycle Demo ===\n\n");

    /* Producer: edge device signs sensor data */
    stackBefore = STACK_MARKER();
    ret = edge_device_produce(packet, sizeof(packet), &packetLen,
                               &payloadUsed);
    stackAfter = STACK_MARKER();
    if (ret != 0) {
        printf("Producer failed: %d\n", ret);
        return 1;
    }
    if (stackBefore > stackAfter) {
        printf("[Producer] Stack used: ~%zu bytes\n",
               stackBefore - stackAfter);
    }

    /* Simulate network transport */
    printf("\n--- Network transport (%zu bytes) ---\n\n", packetLen);

    /* Consumer: cloud server verifies and extracts */
    stackBefore = STACK_MARKER();
    ret = cloud_server_consume(packet, packetLen);
    stackAfter = STACK_MARKER();
    if (ret != 0) {
        printf("Consumer failed: %d\n", ret);
        return 1;
    }
    if (stackBefore > stackAfter) {
        printf("[Consumer] Stack used: ~%zu bytes\n",
               stackBefore - stackAfter);
    }

    printf("\nTotal packet size: %zu bytes\n", packetLen);
    printf("Payload overhead: %zu bytes (COSE envelope)\n",
           packetLen - payloadUsed);
    printf("\n=== Demo complete ===\n");

    return 0;
}
