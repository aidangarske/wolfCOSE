/* sign1_verify_lean.c
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

/* Verify-only lean build example.
 *
 * Build this with -DWOLFCOSE_LEAN_VERIFY. That profile compiles in only the
 * COSE_Sign1 verify path. It is the common on-device case: a device verifies a
 * signed firmware image or attestation, and signing happens off-device on a
 * server or HSM. Signing and the RNG it needs are not compiled in at all, while
 * full RFC 9052 verification (header decode, crit enforcement, duplicate-label
 * detection, Sig_structure rebuild) stays intact.
 *
 * The device holds only a public key. Here both the P-256 public key and a
 * COSE_Sign1 message produced off-device are embedded as fixed test vectors.
 */

#include <stdio.h>
#include <string.h>
#include <wolfcose/wolfcose.h>
#include <wolfssl/wolfcrypt/ecc.h>

/* P-256 public key (X and Y, 32 bytes each). The matching private key lives
 * off-device and is never present in a lean verify build. */
static const unsigned char PUB_X[32] = {
    0x2c,0x3c,0x9f,0xd7,0xfc,0x15,0x48,0x7b,0x37,0x18,0x0e,0x37,0x95,0x56,0xb4,0xfd,
    0xbb,0x11,0x3c,0x78,0xe0,0xa5,0x3a,0x0b,0x25,0x71,0xf5,0xff,0xb0,0xdf,0x93,0x28};
static const unsigned char PUB_Y[32] = {
    0x10,0xc3,0x85,0xc2,0xb6,0x8f,0x79,0xd7,0xe9,0x5e,0x43,0x62,0xf5,0xf4,0x06,0x21,
    0xdc,0x2c,0xf6,0x55,0x87,0xeb,0x94,0x61,0x13,0xe5,0xe2,0x8c,0xeb,0x2e,0xd2,0xce};

/* A COSE_Sign1 (ES256) over the payload below, signed off-device. */
static const unsigned char COSE_SIGN1[] = {
    210,132,67,161,1,38,160,88,31,119,111,108,102,67,79,83,69,32,115,105,122,101,
    32,98,101,110,99,104,109,97,114,107,32,112,97,121,108,111,97,100,88,64,59,0,
    231,221,224,83,68,247,200,191,96,153,241,21,82,224,140,57,84,22,93,156,13,27,
    158,52,92,1,3,133,149,6,107,5,177,236,51,215,88,17,151,62,250,187,32,253,203,
    136,234,87,178,237,194,236,125,41,120,249,26,131,6,201,71,139};

static const char EXPECTED_PAYLOAD[] = "wolfCOSE size benchmark payload";

int main(void)
{
    ecc_key        eccKey;
    WOLFCOSE_KEY   key;
    WOLFCOSE_HDR   hdr;
    unsigned char  scratch[256];
    const uint8_t* payload = NULL;
    size_t         payloadLen = 0;
    int            ret;
    int            rc = 1;

    if (wc_ecc_init(&eccKey) != 0) {
        (void)printf("wc_ecc_init failed\n");
        return 1;
    }

    /* Import the public key only. A NULL private scalar keeps this public. */
    ret = wc_ecc_import_unsigned(&eccKey, (byte*)PUB_X, (byte*)PUB_Y, NULL,
                                 ECC_SECP256R1);
    if (ret == 0) {
        ret = wc_CoseKey_Init(&key);
    }
    if (ret == 0) {
        ret = wc_CoseKey_SetEcc(&key, WOLFCOSE_CRV_P256, &eccKey);
    }

    if (ret == 0) {
        (void)memset(&hdr, 0, sizeof(hdr));
        ret = wc_CoseSign1_Verify(&key, COSE_SIGN1, sizeof(COSE_SIGN1),
                                  NULL, 0, NULL, 0,
                                  scratch, sizeof(scratch), &hdr,
                                  &payload, &payloadLen);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        if ((payloadLen == (sizeof(EXPECTED_PAYLOAD) - 1)) &&
            (payload != NULL) &&
            (memcmp(payload, EXPECTED_PAYLOAD, payloadLen) == 0)) {
            (void)printf("lean verify-only: COSE_Sign1 ES256 verified, "
                         "payload = \"%.*s\"\n", (int)payloadLen, payload);
            rc = 0;
        }
        else {
            (void)printf("lean verify-only: payload mismatch\n");
        }
    }
    else {
        (void)printf("lean verify-only: verify failed (%d)\n", ret);
    }

    wc_CoseKey_Free(&key);
    wc_ecc_free(&eccKey);
    return rc;
}
