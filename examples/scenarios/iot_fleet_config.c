/* iot_fleet_config.c
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
 * Encrypted Config Push to IoT Fleet
 *
 * Scenario: Cloud server pushes encrypted configuration to multiple
 * IoT devices using a shared group key. Server uses COSE_Encrypt
 * with multiple recipients (Direct key mode) so the same encrypted
 * message works for all devices. Each recipient is identified by KID.
 *
 * Compile-time gate:
 *   WOLFCOSE_EXAMPLE_IOT_FLEET  - Enable this example (default: enabled)
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

/* Default: enabled */
#ifndef WOLFCOSE_NO_EXAMPLE_IOT_FLEET
    #define WOLFCOSE_EXAMPLE_IOT_FLEET
#endif

#if defined(WOLFCOSE_EXAMPLE_IOT_FLEET) && defined(HAVE_AESGCM) && \
    defined(WOLFCOSE_ENCRYPT)

#include <wolfcose/wolfcose.h>
#include <wolfssl/wolfcrypt/random.h>
#include <stdio.h>
#include <string.h>

/* Number of devices in the fleet */
#define NUM_DEVICES 3

/* Simulated device configuration (JSON-like) */
static const uint8_t g_deviceConfig[] = {
    '{', '"', 'm', 'q', 't', 't', '_', 'b', 'r', 'o', 'k', 'e', 'r', '"', ':',
    '"', 'i', 'o', 't', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o',
    'm', '"', ',', '"', 'p', 'o', 'r', 't', '"', ':', '8', '8', '8', '3', ',',
    '"', 's', 'e', 'c', 'u', 'r', 'e', '"', ':', 't', 'r', 'u', 'e', '}'
};

/* Device info structure */
typedef struct {
    const char* deviceId;
    uint8_t preSharedKey[16];  /* AES-128 key */
} DeviceInfo;

/* Simulated device fleet */
static DeviceInfo g_devices[NUM_DEVICES] = {
    {
        "device-001-temp-sensor",
        {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
         0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
    },
    {
        "device-002-humidity",
        {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
         0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20}
    },
    {
        "device-003-gateway",
        {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
         0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30}
    }
};

/* Content encryption key (randomly generated per message) */
static uint8_t g_contentKey[16];

/* ----- Cloud Server: Encrypt config for all devices ----- */
static int cloud_encrypt_config(const uint8_t* config, size_t configLen,
                                 uint8_t* encryptedOut, size_t encryptedOutSz,
                                 size_t* encryptedLen, WC_RNG* rng)
{
    int ret;
    WOLFCOSE_KEY cek;
    WOLFCOSE_RECIPIENT recipients[NUM_DEVICES];
    WOLFCOSE_KEY deviceKeys[NUM_DEVICES];
    uint8_t iv[12];
    uint8_t scratch[512];
    int i;

    printf("[Cloud Server] Encrypting configuration for %d devices...\n",
           NUM_DEVICES);

    /* Generate random CEK */
    ret = wc_RNG_GenerateBlock(rng, g_contentKey, sizeof(g_contentKey));
    if (ret != 0) {
        printf("  ERROR: Failed to generate CEK: %d\n", ret);
        return ret;
    }

    /* Generate random IV */
    ret = wc_RNG_GenerateBlock(rng, iv, sizeof(iv));
    if (ret != 0) {
        printf("  ERROR: Failed to generate IV: %d\n", ret);
        return ret;
    }

    /* Setup CEK */
    wc_CoseKey_Init(&cek);
    ret = wc_CoseKey_SetSymmetric(&cek, g_contentKey, sizeof(g_contentKey));
    if (ret != 0) {
        printf("  ERROR: Failed to setup CEK: %d\n", ret);
        return ret;
    }

    /* Setup recipients (in real scenario, would use key wrap or ECDH) */
    XMEMSET(recipients, 0, sizeof(recipients));
    for (i = 0; i < NUM_DEVICES; i++) {
        wc_CoseKey_Init(&deviceKeys[i]);
        /* For demo: using direct key mode (all share same CEK) */
        ret = wc_CoseKey_SetSymmetric(&deviceKeys[i],
            g_contentKey, sizeof(g_contentKey));
        if (ret != 0) {
            printf("  ERROR: Failed to setup device %d key: %d\n", i, ret);
            return ret;
        }

        recipients[i].algId = WOLFCOSE_ALG_DIRECT;
        recipients[i].key = &deviceKeys[i];
        recipients[i].kid = (const uint8_t*)g_devices[i].deviceId;
        recipients[i].kidLen = strlen(g_devices[i].deviceId);

        printf("  Recipient %d: %s\n", i, g_devices[i].deviceId);
    }

    /* Encrypt for all recipients */
    ret = wc_CoseEncrypt_Encrypt(recipients, NUM_DEVICES,
        WOLFCOSE_ALG_A128GCM,
        iv, sizeof(iv),
        config, configLen,
        NULL, 0,  /* No detached */
        NULL, 0,  /* No AAD */
        scratch, sizeof(scratch),
        encryptedOut, encryptedOutSz, encryptedLen,
        rng);

    if (ret != 0) {
        printf("  ERROR: wc_CoseEncrypt_Encrypt failed: %d\n", ret);
        return ret;
    }

    printf("  SUCCESS: Encrypted message created (%zu bytes)\n", *encryptedLen);
    printf("  Content: %zu bytes of config data\n", configLen);
    return 0;
}

/* ----- IoT Device: Decrypt config using device key ----- */
static int device_decrypt_config(int deviceIndex,
                                  const uint8_t* encryptedMsg, size_t encryptedLen,
                                  uint8_t* plaintext, size_t plaintextSz,
                                  size_t* plaintextLen)
{
    int ret;
    WOLFCOSE_KEY deviceKey;
    WOLFCOSE_RECIPIENT recipient;
    uint8_t scratch[512];
    WOLFCOSE_HDR hdr;

    printf("[Device %d: %s] Decrypting configuration...\n",
           deviceIndex, g_devices[deviceIndex].deviceId);

    /* Setup device key */
    wc_CoseKey_Init(&deviceKey);
    ret = wc_CoseKey_SetSymmetric(&deviceKey,
        g_contentKey, sizeof(g_contentKey));
    if (ret != 0) {
        printf("  ERROR: Failed to setup device key: %d\n", ret);
        return ret;
    }

    /* Setup recipient */
    XMEMSET(&recipient, 0, sizeof(recipient));
    recipient.algId = WOLFCOSE_ALG_DIRECT;
    recipient.key = &deviceKey;
    recipient.kid = (const uint8_t*)g_devices[deviceIndex].deviceId;
    recipient.kidLen = strlen(g_devices[deviceIndex].deviceId);

    /* Decrypt */
    ret = wc_CoseEncrypt_Decrypt(&recipient, (size_t)deviceIndex,
        encryptedMsg, encryptedLen,
        NULL, 0,  /* No detached */
        NULL, 0,  /* No AAD */
        scratch, sizeof(scratch),
        &hdr,
        plaintext, plaintextSz, plaintextLen);

    if (ret != 0) {
        printf("  ERROR: wc_CoseEncrypt_Decrypt failed: %d\n", ret);
        return ret;
    }

    printf("  SUCCESS: Decrypted %zu bytes\n", *plaintextLen);
    printf("  Config: %.*s\n", (int)*plaintextLen, plaintext);
    return 0;
}

/* ----- Unauthorized device should fail ----- */
static int unauthorized_device_fails(const uint8_t* encryptedMsg,
                                      size_t encryptedLen)
{
    int ret;
    WOLFCOSE_KEY wrongKey;
    WOLFCOSE_RECIPIENT recipient;
    uint8_t wrongKeyData[16] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };
    uint8_t scratch[512];
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    WOLFCOSE_HDR hdr;

    printf("[Unauthorized Device] Attempting to decrypt...\n");

    /* Setup wrong key */
    wc_CoseKey_Init(&wrongKey);
    ret = wc_CoseKey_SetSymmetric(&wrongKey, wrongKeyData, sizeof(wrongKeyData));
    if (ret != 0) {
        printf("  ERROR: Failed to setup key: %d\n", ret);
        return ret;
    }

    /* Setup recipient */
    XMEMSET(&recipient, 0, sizeof(recipient));
    recipient.algId = WOLFCOSE_ALG_DIRECT;
    recipient.key = &wrongKey;
    recipient.kid = (const uint8_t*)"unauthorized-device";
    recipient.kidLen = 19;

    /* Decrypt should fail */
    ret = wc_CoseEncrypt_Decrypt(&recipient, 0,
        encryptedMsg, encryptedLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr,
        plaintext, sizeof(plaintext), &plaintextLen);

    if (ret == 0) {
        printf("  ERROR: Unauthorized device could decrypt!\n");
        return -100;
    }

    printf("  SUCCESS: Access correctly denied\n");
    return 0;
}

/* ----- Main Demo ----- */
int main(void)
{
    int ret = 0;
    WC_RNG rng;
    int rngInit = 0;
    uint8_t encryptedMsg[1024];
    size_t encryptedLen = 0;
    uint8_t plaintext[256];
    size_t plaintextLen = 0;
    int i;

    printf("================================================\n");
    printf("IoT Fleet Configuration Scenario\n");
    printf("================================================\n\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("ERROR: wc_InitRng failed: %d\n", ret);
        return ret;
    }
    rngInit = 1;

    /* Cloud server encrypts config */
    if (ret == 0) {
        ret = cloud_encrypt_config(g_deviceConfig, sizeof(g_deviceConfig),
            encryptedMsg, sizeof(encryptedMsg), &encryptedLen, &rng);
    }

    if (ret == 0) {
        printf("\n");
    }

    /* Each device decrypts */
    for (i = 0; i < NUM_DEVICES && ret == 0; i++) {
        ret = device_decrypt_config(i, encryptedMsg, encryptedLen,
            plaintext, sizeof(plaintext), &plaintextLen);

        /* Verify content matches */
        if (ret == 0) {
            if (plaintextLen != sizeof(g_deviceConfig) ||
                XMEMCMP(plaintext, g_deviceConfig, plaintextLen) != 0) {
                printf("  ERROR: Decrypted content mismatch!\n");
                ret = -1;
            }
        }
        if (ret == 0) {
            printf("\n");
        }
    }

    /* Unauthorized device should fail */
    if (ret == 0) {
        ret = unauthorized_device_fails(encryptedMsg, encryptedLen);
    }

    if (ret == 0) {
        printf("\n================================================\n");
        printf("IoT Fleet Configuration: SUCCESS\n");
        printf("All %d devices received identical configuration.\n", NUM_DEVICES);
        printf("Unauthorized device was blocked.\n");
        printf("================================================\n");
    }

    /* Cleanup */
    if (rngInit != 0) { wc_FreeRng(&rng); }

    if (ret != 0) {
        printf("\n================================================\n");
        printf("IoT Fleet Configuration: FAILED (%d)\n", ret);
        printf("================================================\n");
    }

    return ret;
}

#else /* Build guards not met */

#include <stdio.h>

int main(void)
{
#ifndef WOLFCOSE_EXAMPLE_IOT_FLEET
    printf("iot_fleet_config: example disabled\n");
#elif !defined(HAVE_AESGCM)
    printf("iot_fleet_config: requires AES-GCM support\n");
#elif !defined(WOLFCOSE_ENCRYPT)
    printf("iot_fleet_config: requires WOLFCOSE_ENCRYPT\n");
#endif
    return 0;
}

#endif /* WOLFCOSE_EXAMPLE_IOT_FLEET && HAVE_AESGCM && WOLFCOSE_ENCRYPT */
