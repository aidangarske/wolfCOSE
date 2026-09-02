/* interop_go_cose.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>

#include <wolfcose/wolfcose.h>

#include <stdio.h>
#include <string.h>

#include "../t_cose/interop_keys.h"

#define GO_COSE_MESSAGE_MAX_SZ 2048u

static const uint8_t g_payload[] =
    "wolfCOSE<->go-cose COSE_Sign1 interoperability";

static int init_key(WOLFCOSE_KEY* cose_key, ecc_key* ecc)
{
    word32 index = 0u;
    int ret;

    ret = wc_ecc_init(ecc);
    if (ret != 0)
        return ret;

    ret = wc_CoseKey_Init(cose_key);
    if (ret != 0) {
        wc_ecc_free(ecc);
        return ret;
    }

    ret = wc_EccPrivateKeyDecode(p256_der, &index, ecc, p256_der_len);
    if (ret == 0)
        ret = wc_CoseKey_SetEcc(cose_key, WOLFCOSE_CRV_P256, ecc);
    if (ret != 0) {
        wc_CoseKey_Free(cose_key);
        wc_ecc_free(ecc);
    }

    return ret;
}

static int read_message(uint8_t* message, size_t message_sz, size_t* message_len)
{
    int input;
    size_t length = 0u;

    if (message == NULL || message_len == NULL || message_sz == 0u)
        return -1;

    while (length < message_sz) {
        input = fgetc(stdin);
        if (input == EOF)
            break;
        message[length++] = (uint8_t)input;
    }

    if (ferror(stdin) != 0 || length == 0u)
        return -1;
    if (length == message_sz && fgetc(stdin) != EOF)
        return -1;

    *message_len = length;
    return 0;
}

static int write_message(const uint8_t* message, size_t message_len)
{
    if (message == NULL || message_len == 0u)
        return -1;
    if (fwrite(message, 1u, message_len, stdout) != message_len)
        return -1;
    if (fflush(stdout) != 0)
        return -1;

    return 0;
}

static int sign_message(void)
{
    WOLFCOSE_KEY cose_key;
    WC_RNG rng;
    ecc_key ecc;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t message[GO_COSE_MESSAGE_MAX_SZ];
    size_t message_len = 0u;
    int rng_inited = 0;
    int ret;

    ret = init_key(&cose_key, &ecc);
    if (ret != 0)
        return ret;

    ret = wc_InitRng(&rng);
    if (ret != 0)
        goto exit;
    rng_inited = 1;

    ret = wc_CoseSign1_Sign(&cose_key, WOLFCOSE_ALG_ES256, NULL, 0u,
                            g_payload, sizeof(g_payload) - 1u, NULL, 0u,
                            NULL, 0u, scratch, sizeof(scratch), message,
                            sizeof(message), &message_len, &rng);
    if (ret == 0)
        ret = write_message(message, message_len);

exit:
    if (rng_inited != 0)
        wc_FreeRng(&rng);
    wc_CoseKey_Free(&cose_key);
    wc_ecc_free(&ecc);
    return ret;
}

static int verify_message(void)
{
    WOLFCOSE_HDR header;
    WOLFCOSE_KEY cose_key;
    const uint8_t* decoded = NULL;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t message[GO_COSE_MESSAGE_MAX_SZ];
    uint8_t tampered[GO_COSE_MESSAGE_MAX_SZ];
    size_t decoded_len = 0u;
    size_t message_len = 0u;
    ecc_key ecc;
    int ret;

    ret = read_message(message, sizeof(message), &message_len);
    if (ret != 0)
        return ret;

    ret = init_key(&cose_key, &ecc);
    if (ret != 0)
        return ret;

    ret = wc_CoseSign1_Verify(&cose_key, message, message_len, NULL, 0u,
                               NULL, 0u, scratch, sizeof(scratch), &header,
                               &decoded, &decoded_len);
    if (ret == 0 && (header.alg != WOLFCOSE_ALG_ES256 ||
                     decoded_len != sizeof(g_payload) - 1u ||
                     memcmp(decoded, g_payload, decoded_len) != 0)) {
        ret = -1;
    }
    if (ret == 0) {
        memcpy(tampered, message, message_len);
        tampered[message_len - 1u] ^= 0x01u;
        ret = wc_CoseSign1_Verify(&cose_key, tampered, message_len, NULL, 0u,
                                   NULL, 0u, scratch, sizeof(scratch), &header,
                                   &decoded, &decoded_len);
        if (ret == 0)
            ret = -1;
        else
            ret = 0;
    }

    wc_CoseKey_Free(&cose_key);
    wc_ecc_free(&ecc);
    return ret;
}

int main(int argc, char** argv)
{
    int ret;

    if (argc != 2) {
        fprintf(stderr, "usage: interop_go_cose sign|verify\n");
        return 2;
    }

    if (strcmp(argv[1], "sign") == 0)
        ret = sign_message();
    else if (strcmp(argv[1], "verify") == 0)
        ret = verify_message();
    else {
        fprintf(stderr, "unknown mode: %s\n", argv[1]);
        return 2;
    }

    if (ret != 0)
        fprintf(stderr, "go-cose interop failed: %d\n", ret);

    return ret == 0 ? 0 : 1;
}
