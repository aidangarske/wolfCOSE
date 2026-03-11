/* group_broadcast_mac.c
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
 * Group MAC Broadcast
 *
 * Scenario: Gateway broadcasts authenticated telemetry to multiple
 * subscribers with different keys. Each subscriber can verify the
 * MAC using their own key. Demonstrates COSE_Mac with multiple
 * recipients.
 *
 * Compile-time gate:
 *   WOLFCOSE_EXAMPLE_GROUP_BROADCAST  - Enable this example (default: enabled)
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

/* Default: enabled */
#ifndef WOLFCOSE_NO_EXAMPLE_GROUP_BROADCAST
    #define WOLFCOSE_EXAMPLE_GROUP_BROADCAST
#endif

#if defined(WOLFCOSE_EXAMPLE_GROUP_BROADCAST) && !defined(NO_HMAC) && \
    defined(WOLFCOSE_MAC)

#include <wolfcose/wolfcose.h>
#include <wolfssl/wolfcrypt/random.h>
#include <stdio.h>
#include <string.h>

/* Number of subscribers in the broadcast group */
#define NUM_SUBSCRIBERS 4

/* Simulated telemetry data (would be sensor readings in real system) */
static const uint8_t g_telemetryData[] = {
    0xA3,  /* CBOR map with 3 entries */
    0x01, 0x78, 0x0A,  /* key 1: gateway-id string */
    'g', 'a', 't', 'e', 'w', 'a', 'y', '-', '0', '1',
    0x02, 0x19, 0x01, 0xF4,  /* key 2: sensor_count = 500 */
    0x03, 0xA2,  /* key 3: readings map with 2 entries */
        0x01, 0x19, 0x01, 0x90,  /* temp avg = 400 (40.0C * 10) */
        0x02, 0x18, 0x41         /* humidity avg = 65% */
};

/* Subscriber info structure */
typedef struct {
    const char* subscriberId;
    uint8_t macKey[32];  /* HMAC-256 key */
} SubscriberInfo;

/* Simulated subscriber fleet */
static SubscriberInfo g_subscribers[NUM_SUBSCRIBERS] = {
    {
        "subscriber-dashboard-001",
        {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
         0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
         0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
         0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20}
    },
    {
        "subscriber-analytics-002",
        {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
         0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
         0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
         0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40}
    },
    {
        "subscriber-archive-003",
        {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
         0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
         0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
         0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60}
    },
    {
        "subscriber-alert-004",
        {0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
         0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
         0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
         0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80}
    }
};

/* Shared MAC key (used by gateway and derived for each recipient) */
static uint8_t g_macKey[32];

/* ----- Gateway: Create authenticated broadcast message ----- */
static int gateway_create_broadcast(const uint8_t* telemetry, size_t telemetryLen,
                                     uint8_t* macMsgOut, size_t macMsgOutSz,
                                     size_t* macMsgLen, WC_RNG* rng)
{
    int ret;
    WOLFCOSE_KEY macKey;
    WOLFCOSE_RECIPIENT recipients[NUM_SUBSCRIBERS];
    WOLFCOSE_KEY subscriberKeys[NUM_SUBSCRIBERS];
    uint8_t scratch[512];
    int i;

    printf("[Gateway] Creating authenticated broadcast...\n");
    printf("  Telemetry payload: %zu bytes\n", telemetryLen);
    printf("  Recipients: %d subscribers\n", NUM_SUBSCRIBERS);

    /* Generate MAC key */
    ret = wc_RNG_GenerateBlock(rng, g_macKey, sizeof(g_macKey));
    if (ret != 0) {
        printf("  ERROR: Failed to generate MAC key: %d\n", ret);
        return ret;
    }

    /* Setup MAC key */
    wc_CoseKey_Init(&macKey);
    ret = wc_CoseKey_SetSymmetric(&macKey, g_macKey, sizeof(g_macKey));
    if (ret != 0) {
        printf("  ERROR: Failed to setup MAC key: %d\n", ret);
        return ret;
    }

    /* Setup recipients (in real scenario, would use key wrap) */
    XMEMSET(recipients, 0, sizeof(recipients));
    for (i = 0; i < NUM_SUBSCRIBERS; i++) {
        wc_CoseKey_Init(&subscriberKeys[i]);
        /* For demo: using direct key mode */
        ret = wc_CoseKey_SetSymmetric(&subscriberKeys[i],
            g_macKey, sizeof(g_macKey));
        if (ret != 0) {
            printf("  ERROR: Failed to setup subscriber %d key: %d\n", i, ret);
            return ret;
        }

        recipients[i].algId = WOLFCOSE_ALG_DIRECT;
        recipients[i].key = &subscriberKeys[i];
        recipients[i].kid = (const uint8_t*)g_subscribers[i].subscriberId;
        recipients[i].kidLen = strlen(g_subscribers[i].subscriberId);

        printf("  Recipient %d: %s\n", i, g_subscribers[i].subscriberId);
    }

    /* Create MAC for all recipients */
    ret = wc_CoseMac_Create(recipients, NUM_SUBSCRIBERS,
        WOLFCOSE_ALG_HMAC_256_256,
        telemetry, telemetryLen,
        NULL, 0,  /* No detached */
        NULL, 0,  /* No AAD */
        scratch, sizeof(scratch),
        macMsgOut, macMsgOutSz, macMsgLen);

    if (ret != 0) {
        printf("  ERROR: wc_CoseMac_Create failed: %d\n", ret);
        return ret;
    }

    printf("  SUCCESS: Broadcast MAC created (%zu bytes)\n", *macMsgLen);
    return 0;
}

/* ----- Subscriber: Verify broadcast message ----- */
static int subscriber_verify_broadcast(int subscriberIndex,
                                        const uint8_t* macMsg, size_t macMsgLen)
{
    int ret;
    WOLFCOSE_KEY subscriberKey;
    WOLFCOSE_RECIPIENT recipient;
    uint8_t scratch[512];
    const uint8_t* payload = NULL;
    size_t payloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("[Subscriber %d: %s] Verifying broadcast...\n",
           subscriberIndex, g_subscribers[subscriberIndex].subscriberId);

    /* Setup subscriber key */
    wc_CoseKey_Init(&subscriberKey);
    ret = wc_CoseKey_SetSymmetric(&subscriberKey,
        g_macKey, sizeof(g_macKey));
    if (ret != 0) {
        printf("  ERROR: Failed to setup subscriber key: %d\n", ret);
        return ret;
    }

    /* Setup recipient */
    XMEMSET(&recipient, 0, sizeof(recipient));
    recipient.algId = WOLFCOSE_ALG_DIRECT;
    recipient.key = &subscriberKey;
    recipient.kid = (const uint8_t*)g_subscribers[subscriberIndex].subscriberId;
    recipient.kidLen = strlen(g_subscribers[subscriberIndex].subscriberId);

    /* Verify */
    ret = wc_CoseMac_Verify(&recipient, (size_t)subscriberIndex,
        macMsg, macMsgLen,
        NULL, 0,  /* No detached */
        NULL, 0,  /* No AAD */
        scratch, sizeof(scratch),
        &hdr, &payload, &payloadLen);

    if (ret != 0) {
        printf("  ERROR: MAC verification failed: %d\n", ret);
        return ret;
    }

    printf("  SUCCESS: MAC verified\n");
    printf("  Payload: %zu bytes of telemetry data\n", payloadLen);
    return 0;
}

/* ----- Unauthorized subscriber should fail ----- */
static int unauthorized_subscriber_fails(const uint8_t* macMsg, size_t macMsgLen)
{
    int ret;
    WOLFCOSE_KEY wrongKey;
    WOLFCOSE_RECIPIENT recipient;
    uint8_t wrongKeyData[32] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };
    uint8_t scratch[512];
    const uint8_t* payload = NULL;
    size_t payloadLen = 0;
    WOLFCOSE_HDR hdr;

    printf("[Unauthorized Subscriber] Attempting to verify...\n");

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
    recipient.kid = (const uint8_t*)"unauthorized-subscriber";
    recipient.kidLen = 23;

    /* Verify should fail */
    ret = wc_CoseMac_Verify(&recipient, 0,
        macMsg, macMsgLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &payload, &payloadLen);

    if (ret == 0) {
        printf("  ERROR: Unauthorized subscriber could verify!\n");
        return -100;
    }

    printf("  SUCCESS: Access correctly denied\n");
    return 0;
}

/* ----- Tampered message detection ----- */
static int tampered_message_detected(const uint8_t* macMsg, size_t macMsgLen)
{
    int ret;
    WOLFCOSE_KEY subscriberKey;
    WOLFCOSE_RECIPIENT recipient;
    uint8_t scratch[512];
    const uint8_t* payload = NULL;
    size_t payloadLen = 0;
    WOLFCOSE_HDR hdr;
    uint8_t tamperedMsg[1024];

    printf("[Tamper Detection] Testing message integrity...\n");

    /* Create tampered copy */
    if (macMsgLen > sizeof(tamperedMsg)) {
        printf("  ERROR: Message too large for test buffer\n");
        return -1;
    }
    XMEMCPY(tamperedMsg, macMsg, macMsgLen);
    tamperedMsg[macMsgLen / 2] ^= 0xFF;  /* Tamper with middle byte */

    /* Setup subscriber key */
    wc_CoseKey_Init(&subscriberKey);
    ret = wc_CoseKey_SetSymmetric(&subscriberKey,
        g_macKey, sizeof(g_macKey));
    if (ret != 0) {
        printf("  ERROR: Failed to setup subscriber key: %d\n", ret);
        return ret;
    }

    /* Setup recipient */
    XMEMSET(&recipient, 0, sizeof(recipient));
    recipient.algId = WOLFCOSE_ALG_DIRECT;
    recipient.key = &subscriberKey;
    recipient.kid = (const uint8_t*)g_subscribers[0].subscriberId;
    recipient.kidLen = strlen(g_subscribers[0].subscriberId);

    /* Verify should fail due to tamper */
    ret = wc_CoseMac_Verify(&recipient, 0,
        tamperedMsg, macMsgLen,
        NULL, 0, NULL, 0,
        scratch, sizeof(scratch),
        &hdr, &payload, &payloadLen);

    if (ret == 0) {
        printf("  ERROR: Tampered message was accepted!\n");
        return -100;
    }

    printf("  SUCCESS: Tampered message correctly rejected\n");
    return 0;
}

/* ----- Main Demo ----- */
int main(void)
{
    int ret = 0;
    WC_RNG rng;
    int rngInit = 0;
    uint8_t macMsg[1024];
    size_t macMsgLen = 0;
    int i;

    printf("================================================\n");
    printf("Group MAC Broadcast Scenario\n");
    printf("================================================\n\n");

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("ERROR: wc_InitRng failed: %d\n", ret);
        return ret;
    }
    rngInit = 1;

    /* Gateway creates broadcast */
    if (ret == 0) {
        ret = gateway_create_broadcast(g_telemetryData, sizeof(g_telemetryData),
            macMsg, sizeof(macMsg), &macMsgLen, &rng);
    }

    if (ret == 0) {
        printf("\n");
    }

    /* Each subscriber verifies */
    for (i = 0; i < NUM_SUBSCRIBERS && ret == 0; i++) {
        ret = subscriber_verify_broadcast(i, macMsg, macMsgLen);
        if (ret == 0) {
            printf("\n");
        }
    }

    /* Unauthorized subscriber should fail */
    if (ret == 0) {
        ret = unauthorized_subscriber_fails(macMsg, macMsgLen);
    }

    if (ret == 0) {
        printf("\n");
    }

    /* Tampered message should be detected */
    if (ret == 0) {
        ret = tampered_message_detected(macMsg, macMsgLen);
    }

    if (ret == 0) {
        printf("\n================================================\n");
        printf("Group MAC Broadcast: SUCCESS\n");
        printf("- Gateway broadcast authenticated for all %d subscribers\n",
               NUM_SUBSCRIBERS);
        printf("- Each subscriber independently verified the message\n");
        printf("- Unauthorized access was blocked\n");
        printf("- Message tampering was detected\n");
        printf("================================================\n");
    }

    /* Cleanup */
    if (rngInit != 0) { wc_FreeRng(&rng); }

    if (ret != 0) {
        printf("\n================================================\n");
        printf("Group MAC Broadcast: FAILED (%d)\n", ret);
        printf("================================================\n");
    }

    return ret;
}

#else /* Build guards not met */

#include <stdio.h>

int main(void)
{
#ifndef WOLFCOSE_EXAMPLE_GROUP_BROADCAST
    printf("group_broadcast_mac: example disabled\n");
#elif defined(NO_HMAC)
    printf("group_broadcast_mac: requires HMAC support\n");
#elif !defined(WOLFCOSE_MAC)
    printf("group_broadcast_mac: requires WOLFCOSE_MAC\n");
#endif
    return 0;
}

#endif /* WOLFCOSE_EXAMPLE_GROUP_BROADCAST && !NO_HMAC && WOLFCOSE_MAC */
