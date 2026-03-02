/* wolfcose_tool.c
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
 * wolfCOSE CLI tool -- Swiss Army knife for COSE operations.
 * Standalone binary, never part of core library.
 *
 * Subcommands:
 *   keygen  -a <alg> -o <keyfile>
 *   sign    -k <keyfile> -a <alg> -i <payload> -o <cose_file>
 *   verify  -k <keyfile> -i <cose_file>
 *   enc     -k <keyfile> -a <alg> -i <plaintext> -o <cose_file>
 *   dec     -k <keyfile> -i <cose_file> -o <plaintext>
 *   info    -i <cose_file>
 *
 * Key files: raw COSE_Key CBOR format.
 * Exit codes: 0=success, 1=usage, 2=crypto failure, 3=I/O error.
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
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifdef HAVE_ED25519
    #include <wolfssl/wolfcrypt/ed25519.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WOLFCOSE_TOOL_MAX_MSG
    #define WOLFCOSE_TOOL_MAX_MSG  8192
#endif

#ifndef WOLFCOSE_TOOL_MAX_KEY
    #define WOLFCOSE_TOOL_MAX_KEY  512
#endif

#define EXIT_USAGE   1
#define EXIT_CRYPTO  2
#define EXIT_IO      3

static void usage(void)
{
    fprintf(stderr,
        "Usage: wolfcose_tool <command> [options]\n"
        "\n"
        "Commands:\n"
        "  keygen  -a <alg> -o <keyfile>\n"
        "  sign    -k <keyfile> -a <alg> -i <payload> -o <cose_file>\n"
        "  verify  -k <keyfile> -i <cose_file>\n"
        "  enc     -k <keyfile> -a <alg> -i <plaintext> -o <cose_file>\n"
        "  dec     -k <keyfile> -i <cose_file> -o <plaintext>\n"
        "  info    -i <cose_file>\n"
        "\n"
        "Algorithms: ES256, EdDSA, A128GCM, A256GCM\n");
}

/* Parse algorithm name to COSE algorithm ID */
static int parse_alg(const char* name, int32_t* alg)
{
    if (strcmp(name, "ES256") == 0) {
        *alg = WOLFCOSE_ALG_ES256;
    }
    else if (strcmp(name, "EdDSA") == 0) {
        *alg = WOLFCOSE_ALG_EDDSA;
    }
    else if (strcmp(name, "A128GCM") == 0) {
        *alg = WOLFCOSE_ALG_A128GCM;
    }
    else if (strcmp(name, "A256GCM") == 0) {
        *alg = WOLFCOSE_ALG_A256GCM;
    }
    else {
        fprintf(stderr, "Unknown algorithm: %s\n", name);
        return -1;
    }
    return 0;
}

/* Read entire file into buffer, return bytes read */
static int read_file(const char* path, uint8_t* buf, size_t bufSz,
                      size_t* outLen)
{
    FILE* f;
    size_t n;

    f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "Cannot open: %s\n", path);
        return EXIT_IO;
    }
    n = fread(buf, 1, bufSz, f);
    if (n == 0 && ferror(f)) {
        fclose(f);
        fprintf(stderr, "Read error: %s\n", path);
        return EXIT_IO;
    }
    fclose(f);
    *outLen = n;
    return 0;
}

/* Write buffer to file */
static int write_file(const char* path, const uint8_t* buf, size_t len)
{
    FILE* f;

    f = fopen(path, "wb");
    if (f == NULL) {
        fprintf(stderr, "Cannot create: %s\n", path);
        return EXIT_IO;
    }
    if (fwrite(buf, 1, len, f) != len) {
        fclose(f);
        fprintf(stderr, "Write error: %s\n", path);
        return EXIT_IO;
    }
    fclose(f);
    return 0;
}

/* ---------------------------------------------------------------------------
 * keygen: generate a COSE key and write to file
 * --------------------------------------------------------------------------- */
static int tool_keygen(int32_t alg, const char* outPath)
{
    int ret;
    WC_RNG rng;
    WOLFCOSE_KEY coseKey;
    uint8_t keyBuf[WOLFCOSE_TOOL_MAX_KEY];
    size_t keyLen = 0;

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        fprintf(stderr, "RNG init failed: %d\n", ret);
        return EXIT_CRYPTO;
    }

    wc_CoseKey_Init(&coseKey);

#ifdef HAVE_ECC
    if (alg == WOLFCOSE_ALG_ES256) {
        ecc_key ecc;
        wc_ecc_init(&ecc);
        ret = wc_ecc_make_key(&rng, 32, &ecc);
        if (ret != 0) {
            fprintf(stderr, "ECC keygen failed: %d\n", ret);
            wc_ecc_free(&ecc);
            wc_FreeRng(&rng);
            return EXIT_CRYPTO;
        }
        wc_CoseKey_SetEcc(&coseKey, WOLFCOSE_CRV_P256, &ecc);
        ret = wc_CoseKey_Encode(&coseKey, keyBuf, sizeof(keyBuf), &keyLen);
        wc_ecc_free(&ecc);
    }
    else
#endif
#ifdef HAVE_ED25519
    if (alg == WOLFCOSE_ALG_EDDSA) {
        ed25519_key ed;
        wc_ed25519_init(&ed);
        ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &ed);
        if (ret != 0) {
            fprintf(stderr, "Ed25519 keygen failed: %d\n", ret);
            wc_ed25519_free(&ed);
            wc_FreeRng(&rng);
            return EXIT_CRYPTO;
        }
        wc_CoseKey_SetEd25519(&coseKey, &ed);
        ret = wc_CoseKey_Encode(&coseKey, keyBuf, sizeof(keyBuf), &keyLen);
        wc_ed25519_free(&ed);
    }
    else
#endif
    if (alg == WOLFCOSE_ALG_A128GCM || alg == WOLFCOSE_ALG_A256GCM) {
        size_t kLen = (alg == WOLFCOSE_ALG_A128GCM) ? 16u : 32u;
        uint8_t symKey[32];
        ret = wc_RNG_GenerateBlock(&rng, symKey, (word32)kLen);
        if (ret != 0) {
            fprintf(stderr, "RNG generate failed: %d\n", ret);
            wc_FreeRng(&rng);
            return EXIT_CRYPTO;
        }
        wc_CoseKey_SetSymmetric(&coseKey, symKey, kLen);
        ret = wc_CoseKey_Encode(&coseKey, keyBuf, sizeof(keyBuf), &keyLen);
    }
    else {
        fprintf(stderr, "Unsupported algorithm for keygen\n");
        wc_FreeRng(&rng);
        return EXIT_USAGE;
    }

    wc_FreeRng(&rng);

    if (ret != 0) {
        fprintf(stderr, "Key encode failed: %d\n", ret);
        return EXIT_CRYPTO;
    }

    ret = write_file(outPath, keyBuf, keyLen);
    if (ret == 0) {
        printf("Generated key: %s (%zu bytes)\n", outPath, keyLen);
    }
    return ret;
}

/* ---------------------------------------------------------------------------
 * sign: COSE_Sign1 sign
 * --------------------------------------------------------------------------- */
static int tool_sign(const char* keyPath, int32_t alg,
                      const char* inPath, const char* outPath)
{
    int ret;
    uint8_t keyBuf[WOLFCOSE_TOOL_MAX_KEY];
    size_t keyLen = 0;
    uint8_t msgBuf[WOLFCOSE_TOOL_MAX_MSG];
    size_t msgLen = 0;
    uint8_t outBuf[WOLFCOSE_TOOL_MAX_MSG];
    size_t outLen = 0;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    WOLFCOSE_KEY coseKey;
    WC_RNG rng;

    ret = read_file(keyPath, keyBuf, sizeof(keyBuf), &keyLen);
    if (ret != 0) return ret;

    ret = read_file(inPath, msgBuf, sizeof(msgBuf), &msgLen);
    if (ret != 0) return ret;

    wc_CoseKey_Init(&coseKey);

#ifdef HAVE_ECC
    if (alg == WOLFCOSE_ALG_ES256) {
        ecc_key ecc;
        wc_ecc_init(&ecc);
        coseKey.key.ecc = &ecc;
        ret = wc_CoseKey_Decode(&coseKey, keyBuf, keyLen);
        if (ret != 0) {
            fprintf(stderr, "Key decode failed: %d\n", ret);
            wc_ecc_free(&ecc);
            return EXIT_CRYPTO;
        }

        ret = wc_InitRng(&rng);
        if (ret != 0) {
            wc_ecc_free(&ecc);
            return EXIT_CRYPTO;
        }

        ret = wc_CoseSign1_Sign(&coseKey, alg, NULL, 0,
            msgBuf, msgLen, NULL, 0,
            scratch, sizeof(scratch),
            outBuf, sizeof(outBuf), &outLen, &rng);

        wc_FreeRng(&rng);
        wc_ecc_free(&ecc);
    }
    else
#endif
#ifdef HAVE_ED25519
    if (alg == WOLFCOSE_ALG_EDDSA) {
        ed25519_key ed;
        wc_ed25519_init(&ed);
        coseKey.key.ed25519 = &ed;
        ret = wc_CoseKey_Decode(&coseKey, keyBuf, keyLen);
        if (ret != 0) {
            fprintf(stderr, "Key decode failed: %d\n", ret);
            wc_ed25519_free(&ed);
            return EXIT_CRYPTO;
        }

        ret = wc_InitRng(&rng);
        if (ret != 0) {
            wc_ed25519_free(&ed);
            return EXIT_CRYPTO;
        }

        ret = wc_CoseSign1_Sign(&coseKey, alg, NULL, 0,
            msgBuf, msgLen, NULL, 0,
            scratch, sizeof(scratch),
            outBuf, sizeof(outBuf), &outLen, &rng);

        wc_FreeRng(&rng);
        wc_ed25519_free(&ed);
    }
    else
#endif
    {
        fprintf(stderr, "Unsupported sign algorithm\n");
        return EXIT_USAGE;
    }

    if (ret != 0) {
        fprintf(stderr, "Sign failed: %d\n", ret);
        return EXIT_CRYPTO;
    }

    ret = write_file(outPath, outBuf, outLen);
    if (ret == 0) {
        printf("Signed: %zu byte payload -> %zu byte COSE_Sign1\n",
               msgLen, outLen);
    }
    return ret;
}

/* ---------------------------------------------------------------------------
 * verify: COSE_Sign1 verify
 * --------------------------------------------------------------------------- */
static int tool_verify(const char* keyPath, const char* inPath)
{
    int ret;
    uint8_t keyBuf[WOLFCOSE_TOOL_MAX_KEY];
    size_t keyLen = 0;
    uint8_t msgBuf[WOLFCOSE_TOOL_MAX_MSG];
    size_t msgLen = 0;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    WOLFCOSE_KEY coseKey;
    WOLFCOSE_HDR hdr;
    const uint8_t* payload = NULL;
    size_t payloadLen = 0;

    ret = read_file(keyPath, keyBuf, sizeof(keyBuf), &keyLen);
    if (ret != 0) return ret;

    ret = read_file(inPath, msgBuf, sizeof(msgBuf), &msgLen);
    if (ret != 0) return ret;

    wc_CoseKey_Init(&coseKey);

    /* Try ECC first, then Ed25519 */
#ifdef HAVE_ECC
    {
        ecc_key ecc;
        wc_ecc_init(&ecc);
        coseKey.key.ecc = &ecc;
        ret = wc_CoseKey_Decode(&coseKey, keyBuf, keyLen);
        if (ret == 0 && coseKey.kty == WOLFCOSE_KTY_EC2) {
            ret = wc_CoseSign1_Verify(&coseKey, msgBuf, msgLen,
                NULL, 0, scratch, sizeof(scratch),
                &hdr, &payload, &payloadLen);
            wc_ecc_free(&ecc);
            goto verify_done;
        }
        wc_ecc_free(&ecc);
    }
#endif

#ifdef HAVE_ED25519
    {
        ed25519_key ed;
        wc_CoseKey_Init(&coseKey);
        wc_ed25519_init(&ed);
        coseKey.key.ed25519 = &ed;
        ret = wc_CoseKey_Decode(&coseKey, keyBuf, keyLen);
        if (ret == 0 && coseKey.kty == WOLFCOSE_KTY_OKP) {
            ret = wc_CoseSign1_Verify(&coseKey, msgBuf, msgLen,
                NULL, 0, scratch, sizeof(scratch),
                &hdr, &payload, &payloadLen);
            wc_ed25519_free(&ed);
            goto verify_done;
        }
        wc_ed25519_free(&ed);
    }
#endif

    fprintf(stderr, "Unsupported key type\n");
    return EXIT_CRYPTO;

verify_done:
    if (ret != 0) {
        fprintf(stderr, "Verification FAILED: %d\n", ret);
        return EXIT_CRYPTO;
    }

    printf("Verification OK. Payload: %zu bytes\n", payloadLen);
    return 0;
}

/* ---------------------------------------------------------------------------
 * enc: COSE_Encrypt0 encrypt
 * --------------------------------------------------------------------------- */
#ifdef HAVE_AESGCM
static int tool_enc(const char* keyPath, int32_t alg,
                     const char* inPath, const char* outPath)
{
    int ret;
    uint8_t keyBuf[WOLFCOSE_TOOL_MAX_KEY];
    size_t keyLen = 0;
    uint8_t msgBuf[WOLFCOSE_TOOL_MAX_MSG];
    size_t msgLen = 0;
    uint8_t outBuf[WOLFCOSE_TOOL_MAX_MSG];
    size_t outLen = 0;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    uint8_t iv[WOLFCOSE_AES_GCM_NONCE_SZ];
    WOLFCOSE_KEY coseKey;
    WC_RNG rng;

    ret = read_file(keyPath, keyBuf, sizeof(keyBuf), &keyLen);
    if (ret != 0) return ret;

    ret = read_file(inPath, msgBuf, sizeof(msgBuf), &msgLen);
    if (ret != 0) return ret;

    wc_CoseKey_Init(&coseKey);
    coseKey.kty = WOLFCOSE_KTY_SYMMETRIC;
    ret = wc_CoseKey_Decode(&coseKey, keyBuf, keyLen);
    if (ret != 0) {
        fprintf(stderr, "Key decode failed: %d\n", ret);
        return EXIT_CRYPTO;
    }

    ret = wc_InitRng(&rng);
    if (ret != 0) return EXIT_CRYPTO;

    ret = wc_RNG_GenerateBlock(&rng, iv, sizeof(iv));
    if (ret != 0) {
        wc_FreeRng(&rng);
        return EXIT_CRYPTO;
    }

    ret = wc_CoseEncrypt0_Encrypt(&coseKey, alg,
        iv, sizeof(iv),
        msgBuf, msgLen, NULL, 0,
        scratch, sizeof(scratch),
        outBuf, sizeof(outBuf), &outLen);

    wc_FreeRng(&rng);

    if (ret != 0) {
        fprintf(stderr, "Encrypt failed: %d\n", ret);
        return EXIT_CRYPTO;
    }

    ret = write_file(outPath, outBuf, outLen);
    if (ret == 0) {
        printf("Encrypted: %zu byte plaintext -> %zu byte COSE_Encrypt0\n",
               msgLen, outLen);
    }
    return ret;
}

/* ---------------------------------------------------------------------------
 * dec: COSE_Encrypt0 decrypt
 * --------------------------------------------------------------------------- */
static int tool_dec(const char* keyPath, const char* inPath,
                     const char* outPath)
{
    int ret;
    uint8_t keyBuf[WOLFCOSE_TOOL_MAX_KEY];
    size_t keyLen = 0;
    uint8_t msgBuf[WOLFCOSE_TOOL_MAX_MSG];
    size_t msgLen = 0;
    uint8_t plainBuf[WOLFCOSE_TOOL_MAX_MSG];
    size_t plainLen = 0;
    uint8_t scratch[WOLFCOSE_MAX_SCRATCH_SZ];
    WOLFCOSE_KEY coseKey;
    WOLFCOSE_HDR hdr;

    ret = read_file(keyPath, keyBuf, sizeof(keyBuf), &keyLen);
    if (ret != 0) return ret;

    ret = read_file(inPath, msgBuf, sizeof(msgBuf), &msgLen);
    if (ret != 0) return ret;

    wc_CoseKey_Init(&coseKey);
    coseKey.kty = WOLFCOSE_KTY_SYMMETRIC;
    ret = wc_CoseKey_Decode(&coseKey, keyBuf, keyLen);
    if (ret != 0) {
        fprintf(stderr, "Key decode failed: %d\n", ret);
        return EXIT_CRYPTO;
    }

    ret = wc_CoseEncrypt0_Decrypt(&coseKey, msgBuf, msgLen,
        NULL, 0, scratch, sizeof(scratch), &hdr,
        plainBuf, sizeof(plainBuf), &plainLen);
    if (ret != 0) {
        fprintf(stderr, "Decrypt FAILED: %d\n", ret);
        return EXIT_CRYPTO;
    }

    ret = write_file(outPath, plainBuf, plainLen);
    if (ret == 0) {
        printf("Decrypted: %zu byte COSE_Encrypt0 -> %zu byte plaintext\n",
               msgLen, plainLen);
    }
    return ret;
}
#endif /* HAVE_AESGCM */

/* ---------------------------------------------------------------------------
 * info: dump CBOR structure of a COSE message
 * --------------------------------------------------------------------------- */
static int tool_info(const char* inPath)
{
    int ret;
    uint8_t msgBuf[WOLFCOSE_TOOL_MAX_MSG];
    size_t msgLen = 0;
    WOLFCOSE_CBOR_CTX ctx;
    WOLFCOSE_CBOR_ITEM item;
    size_t i;
    int indent = 0;

    ret = read_file(inPath, msgBuf, sizeof(msgBuf), &msgLen);
    if (ret != 0) return ret;

    printf("COSE message: %zu bytes\n", msgLen);

    ctx.buf = msgBuf;
    ctx.bufSz = msgLen;
    ctx.idx = 0;

    while (ctx.idx < ctx.bufSz) {
        size_t pos = ctx.idx;
        ret = wc_CBOR_DecodeHead(&ctx, &item);
        if (ret != 0) {
            printf("  [decode error at offset %zu: %d]\n", pos, ret);
            break;
        }

        for (i = 0; i < (size_t)indent; i++) printf("  ");

        switch (item.majorType) {
            case WOLFCOSE_CBOR_UINT:
                printf("[%zu] uint: %llu\n", pos,
                       (unsigned long long)item.val);
                break;
            case WOLFCOSE_CBOR_NEGINT:
                printf("[%zu] negint: -%llu\n", pos,
                       (unsigned long long)(item.val + 1));
                break;
            case WOLFCOSE_CBOR_BSTR:
                printf("[%zu] bstr(%zu): ", pos, item.dataLen);
                for (i = 0; i < item.dataLen && i < 32; i++)
                    printf("%02X", item.data[i]);
                if (item.dataLen > 32) printf("...");
                printf("\n");
                break;
            case WOLFCOSE_CBOR_TSTR:
                printf("[%zu] tstr(%zu): \"%.*s\"\n", pos, item.dataLen,
                       (int)item.dataLen, item.data);
                break;
            case WOLFCOSE_CBOR_ARRAY:
                printf("[%zu] array(%llu)\n", pos,
                       (unsigned long long)item.val);
                break;
            case WOLFCOSE_CBOR_MAP:
                printf("[%zu] map(%llu)\n", pos,
                       (unsigned long long)item.val);
                break;
            case WOLFCOSE_CBOR_TAG:
                printf("[%zu] tag(%llu)\n", pos,
                       (unsigned long long)item.val);
                break;
            case WOLFCOSE_CBOR_SIMPLE:
                if (item.val == 20) printf("[%zu] false\n", pos);
                else if (item.val == 21) printf("[%zu] true\n", pos);
                else if (item.val == 22) printf("[%zu] null\n", pos);
                else printf("[%zu] simple(%llu)\n", pos,
                            (unsigned long long)item.val);
                break;
            default:
                printf("[%zu] unknown(%u, %llu)\n", pos, item.majorType,
                       (unsigned long long)item.val);
                break;
        }
    }

    return 0;
}

/* ---------------------------------------------------------------------------
 * main
 * --------------------------------------------------------------------------- */
int main(int argc, char* argv[])
{
    const char* cmd;
    const char* algStr = NULL;
    const char* keyPath = NULL;
    const char* inPath = NULL;
    const char* outPath = NULL;
    int32_t alg = 0;
    int i;

    if (argc < 2) {
        usage();
        return EXIT_USAGE;
    }

    cmd = argv[1];

    /* Parse options */
    for (i = 2; i < argc - 1; i += 2) {
        if (strcmp(argv[i], "-a") == 0) {
            algStr = argv[i + 1];
        }
        else if (strcmp(argv[i], "-k") == 0) {
            keyPath = argv[i + 1];
        }
        else if (strcmp(argv[i], "-i") == 0) {
            inPath = argv[i + 1];
        }
        else if (strcmp(argv[i], "-o") == 0) {
            outPath = argv[i + 1];
        }
        else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage();
            return EXIT_USAGE;
        }
    }

    if (algStr != NULL) {
        if (parse_alg(algStr, &alg) != 0) {
            return EXIT_USAGE;
        }
    }

    /* Dispatch */
    if (strcmp(cmd, "keygen") == 0) {
        if (algStr == NULL || outPath == NULL) {
            fprintf(stderr, "keygen requires -a <alg> -o <keyfile>\n");
            return EXIT_USAGE;
        }
        return tool_keygen(alg, outPath);
    }
    else if (strcmp(cmd, "sign") == 0) {
        if (keyPath == NULL || algStr == NULL || inPath == NULL ||
            outPath == NULL) {
            fprintf(stderr,
                    "sign requires -k <key> -a <alg> -i <input> -o <output>\n");
            return EXIT_USAGE;
        }
        return tool_sign(keyPath, alg, inPath, outPath);
    }
    else if (strcmp(cmd, "verify") == 0) {
        if (keyPath == NULL || inPath == NULL) {
            fprintf(stderr, "verify requires -k <key> -i <input>\n");
            return EXIT_USAGE;
        }
        return tool_verify(keyPath, inPath);
    }
#ifdef HAVE_AESGCM
    else if (strcmp(cmd, "enc") == 0) {
        if (keyPath == NULL || algStr == NULL || inPath == NULL ||
            outPath == NULL) {
            fprintf(stderr,
                    "enc requires -k <key> -a <alg> -i <input> -o <output>\n");
            return EXIT_USAGE;
        }
        return tool_enc(keyPath, alg, inPath, outPath);
    }
    else if (strcmp(cmd, "dec") == 0) {
        if (keyPath == NULL || inPath == NULL || outPath == NULL) {
            fprintf(stderr,
                    "dec requires -k <key> -i <input> -o <output>\n");
            return EXIT_USAGE;
        }
        return tool_dec(keyPath, inPath, outPath);
    }
#endif
    else if (strcmp(cmd, "info") == 0) {
        if (inPath == NULL) {
            fprintf(stderr, "info requires -i <input>\n");
            return EXIT_USAGE;
        }
        return tool_info(inPath);
    }
    else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        usage();
        return EXIT_USAGE;
    }
}
