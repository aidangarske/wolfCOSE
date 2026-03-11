/* wolfcose.c
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
 * COSE Sign1/Encrypt0/Key implementation per RFC 9052.
 * All crypto via wolfCrypt wc_* APIs. Zero allocation.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "wolfcose_internal.h"
/* wolfcose.h (via internal.h) includes ecc.h, ed25519.h, ed448.h,
 * dilithium.h, rsa.h, random.h.  Only list headers not pulled in. */
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/memory.h>  /* wc_ForceZero, XMEMCPY */
#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
    #include <wolfssl/wolfcrypt/aes.h>
#endif
#ifndef NO_HMAC
    #include <wolfssl/wolfcrypt/hmac.h>
#endif
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    #include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#endif
#include <string.h>

/* ----- Constant-time comparison (side-channel safe) ----- */

/**
 * Constant-time memory comparison (matches wolfSSL ConstantCompare pattern).
 * Returns 0 if equal, non-zero otherwise.
 * Timing is independent of comparison result.
 */
static int wolfCose_ConstantCompare(const byte* a, const byte* b, int length)
{
    int i;
    int result = 0;

    for (i = 0; i < length; i++) {
        result |= (int)(a[i] ^ b[i]);
    }
    return result;
}

/* ----- Internal helpers: algorithm dispatch ----- */

int wolfCose_AlgToHashType(int32_t alg, enum wc_HashType* hashType)
{
    int ret = WOLFCOSE_SUCCESS;

    if (hashType == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        switch (alg) {
#ifdef HAVE_ECC
            case WOLFCOSE_ALG_ES256:
                *hashType = WC_HASH_TYPE_SHA256;
                break;
    #ifdef WOLFSSL_SHA384
            case WOLFCOSE_ALG_ES384:
                *hashType = WC_HASH_TYPE_SHA384;
                break;
    #endif
    #ifdef WOLFSSL_SHA512
            case WOLFCOSE_ALG_ES512:
                *hashType = WC_HASH_TYPE_SHA512;
                break;
    #endif
#endif /* HAVE_ECC */
#ifdef HAVE_ED25519
            case WOLFCOSE_ALG_EDDSA:
                *hashType = WC_HASH_TYPE_SHA512;
                break;
#endif
#ifdef WC_RSA_PSS
            case WOLFCOSE_ALG_PS256:
                *hashType = WC_HASH_TYPE_SHA256;
                break;
    #ifdef WOLFSSL_SHA384
            case WOLFCOSE_ALG_PS384:
                *hashType = WC_HASH_TYPE_SHA384;
                break;
    #endif
    #ifdef WOLFSSL_SHA512
            case WOLFCOSE_ALG_PS512:
                *hashType = WC_HASH_TYPE_SHA512;
                break;
    #endif
#endif /* WC_RSA_PSS */
            default:
                ret = WOLFCOSE_E_COSE_BAD_ALG;
                break;
        }
    }
    return ret;
}

int wolfCose_SigSize(int32_t alg, size_t* sigSz)
{
    int ret = WOLFCOSE_SUCCESS;

    if (sigSz == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        switch (alg) {
#ifdef HAVE_ECC
            case WOLFCOSE_ALG_ES256:
                *sigSz = 64;  /* r(32) || s(32) */
                break;
    #ifdef WOLFSSL_SHA384
            case WOLFCOSE_ALG_ES384:
                *sigSz = 96;  /* r(48) || s(48) */
                break;
    #endif
    #ifdef WOLFSSL_SHA512
            case WOLFCOSE_ALG_ES512:
                *sigSz = 132; /* r(66) || s(66) */
                break;
    #endif
#endif
#ifdef HAVE_ED25519
            case WOLFCOSE_ALG_EDDSA:
                *sigSz = 64;  /* ED25519_SIG_SIZE */
                break;
#endif
#ifdef HAVE_DILITHIUM
            case WOLFCOSE_ALG_ML_DSA_44:
                *sigSz = 2420;
                break;
            case WOLFCOSE_ALG_ML_DSA_65:
                *sigSz = 3309;
                break;
            case WOLFCOSE_ALG_ML_DSA_87:
                *sigSz = 4627;
                break;
#endif
            default:
                ret = WOLFCOSE_E_COSE_BAD_ALG;
                break;
        }
    }
    return ret;
}

int wolfCose_CrvKeySize(int32_t crv, size_t* keySz)
{
    int ret = WOLFCOSE_SUCCESS;

    if (keySz == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        switch (crv) {
            case WOLFCOSE_CRV_P256:
                *keySz = 32;
                break;
            case WOLFCOSE_CRV_P384:
                *keySz = 48;
                break;
            case WOLFCOSE_CRV_P521:
                *keySz = 66;
                break;
            case WOLFCOSE_CRV_ED25519:
                *keySz = 32;
                break;
            case WOLFCOSE_CRV_ED448:
                *keySz = 57;
                break;
            default:
                ret = WOLFCOSE_E_COSE_BAD_ALG;
                break;
        }
    }
    return ret;
}

#ifdef HAVE_ECC
int wolfCose_CrvToWcCurve(int32_t crv, int* wcCrv)
{
    int ret = WOLFCOSE_SUCCESS;

    if (wcCrv == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        switch (crv) {
            case WOLFCOSE_CRV_P256:
                *wcCrv = ECC_SECP256R1;
                break;
            case WOLFCOSE_CRV_P384:
                *wcCrv = ECC_SECP384R1;
                break;
            case WOLFCOSE_CRV_P521:
                *wcCrv = ECC_SECP521R1;
                break;
            default:
                ret = WOLFCOSE_E_COSE_BAD_ALG;
                break;
        }
    }
    return ret;
}
#endif

/* ----- Internal: AEAD dispatch helpers (AES-GCM, ChaCha20-Poly1305, AES-CCM) ----- */

int wolfCose_AeadKeyLen(int32_t alg, size_t* keyLen)
{
    int ret = WOLFCOSE_SUCCESS;

    if (keyLen == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        switch (alg) {
#ifdef HAVE_AESGCM
            case WOLFCOSE_ALG_A128GCM:
                *keyLen = 16;
                break;
            case WOLFCOSE_ALG_A192GCM:
                *keyLen = 24;
                break;
            case WOLFCOSE_ALG_A256GCM:
                *keyLen = 32;
                break;
#endif
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
            case WOLFCOSE_ALG_CHACHA20_POLY1305:
                *keyLen = WOLFCOSE_CHACHA_KEY_SZ;
                break;
#endif
#ifdef HAVE_AESCCM
            case WOLFCOSE_ALG_AES_CCM_16_64_128:  /* fall through */
            case WOLFCOSE_ALG_AES_CCM_64_64_128:   /* fall through */
            case WOLFCOSE_ALG_AES_CCM_16_128_128:  /* fall through */
            case WOLFCOSE_ALG_AES_CCM_64_128_128:
                *keyLen = 16;
                break;
            case WOLFCOSE_ALG_AES_CCM_16_64_256:   /* fall through */
            case WOLFCOSE_ALG_AES_CCM_64_64_256:   /* fall through */
            case WOLFCOSE_ALG_AES_CCM_16_128_256:  /* fall through */
            case WOLFCOSE_ALG_AES_CCM_64_128_256:
                *keyLen = 32;
                break;
#endif
            default:
                ret = WOLFCOSE_E_COSE_BAD_ALG;
                break;
        }
    }
    return ret;
}

int wolfCose_AeadNonceLen(int32_t alg, size_t* nonceLen)
{
    int ret = WOLFCOSE_SUCCESS;

    if (nonceLen == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        switch (alg) {
#ifdef HAVE_AESGCM
            case WOLFCOSE_ALG_A128GCM:  /* fall through */
            case WOLFCOSE_ALG_A192GCM:  /* fall through */
            case WOLFCOSE_ALG_A256GCM:
                *nonceLen = WOLFCOSE_AES_GCM_NONCE_SZ;
                break;
#endif
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
            case WOLFCOSE_ALG_CHACHA20_POLY1305:
                *nonceLen = WOLFCOSE_CHACHA_NONCE_SZ;
                break;
#endif
#ifdef HAVE_AESCCM
            case WOLFCOSE_ALG_AES_CCM_16_64_128:   /* fall through */
            case WOLFCOSE_ALG_AES_CCM_16_64_256:    /* fall through */
            case WOLFCOSE_ALG_AES_CCM_16_128_128:   /* fall through */
            case WOLFCOSE_ALG_AES_CCM_16_128_256:
                *nonceLen = 13;  /* L=2 */
                break;
            case WOLFCOSE_ALG_AES_CCM_64_64_128:    /* fall through */
            case WOLFCOSE_ALG_AES_CCM_64_64_256:    /* fall through */
            case WOLFCOSE_ALG_AES_CCM_64_128_128:   /* fall through */
            case WOLFCOSE_ALG_AES_CCM_64_128_256:
                *nonceLen = 7;   /* L=8 */
                break;
#endif
            default:
                ret = WOLFCOSE_E_COSE_BAD_ALG;
                break;
        }
    }
    return ret;
}

int wolfCose_AeadTagLen(int32_t alg, size_t* tagLen)
{
    int ret = WOLFCOSE_SUCCESS;

    if (tagLen == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        switch (alg) {
#ifdef HAVE_AESGCM
            case WOLFCOSE_ALG_A128GCM:  /* fall through */
            case WOLFCOSE_ALG_A192GCM:  /* fall through */
            case WOLFCOSE_ALG_A256GCM:
                *tagLen = WOLFCOSE_AES_GCM_TAG_SZ;
                break;
#endif
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
            case WOLFCOSE_ALG_CHACHA20_POLY1305:
                *tagLen = WOLFCOSE_CHACHA_TAG_SZ;
                break;
#endif
#ifdef HAVE_AESCCM
            case WOLFCOSE_ALG_AES_CCM_16_64_128:   /* fall through */
            case WOLFCOSE_ALG_AES_CCM_16_64_256:    /* fall through */
            case WOLFCOSE_ALG_AES_CCM_64_64_128:    /* fall through */
            case WOLFCOSE_ALG_AES_CCM_64_64_256:
                *tagLen = 8;
                break;
            case WOLFCOSE_ALG_AES_CCM_16_128_128:   /* fall through */
            case WOLFCOSE_ALG_AES_CCM_16_128_256:   /* fall through */
            case WOLFCOSE_ALG_AES_CCM_64_128_128:   /* fall through */
            case WOLFCOSE_ALG_AES_CCM_64_128_256:
                *tagLen = 16;
                break;
#endif
            default:
                ret = WOLFCOSE_E_COSE_BAD_ALG;
                break;
        }
    }
    return ret;
}

/* ----- Internal: HMAC helpers ----- */

#if !defined(NO_HMAC)
int wolfCose_HmacTagSize(int32_t alg, size_t* tagSz)
{
    int ret = WOLFCOSE_SUCCESS;

    if (tagSz == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        switch (alg) {
            case WOLFCOSE_ALG_HMAC_256_256:
                *tagSz = 32;
                break;
#ifdef WOLFSSL_SHA384
            case WOLFCOSE_ALG_HMAC_384_384:
                *tagSz = 48;
                break;
#endif
#ifdef WOLFSSL_SHA512
            case WOLFCOSE_ALG_HMAC_512_512:
                *tagSz = 64;
                break;
#endif
            default:
                ret = WOLFCOSE_E_COSE_BAD_ALG;
                break;
        }
    }
    return ret;
}

int wolfCose_HmacType(int32_t alg, int* hmacType)
{
    int ret = WOLFCOSE_SUCCESS;

    if (hmacType == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        switch (alg) {
            case WOLFCOSE_ALG_HMAC_256_256:
                *hmacType = WC_SHA256;
                break;
#ifdef WOLFSSL_SHA384
            case WOLFCOSE_ALG_HMAC_384_384:
                *hmacType = WC_SHA384;
                break;
#endif
#ifdef WOLFSSL_SHA512
            case WOLFCOSE_ALG_HMAC_512_512:
                *hmacType = WC_SHA512;
                break;
#endif
            default:
                ret = WOLFCOSE_E_COSE_BAD_ALG;
                break;
        }
    }
    return ret;
}
#endif /* !NO_HMAC */

/* ----- Internal: ECC DER <-> raw r||s conversion ----- */

#ifdef HAVE_ECC
int wolfCose_EccSignRaw(const uint8_t* hash, size_t hashLen,
                         uint8_t* sigBuf, size_t* sigLen,
                         size_t coordSz, WC_RNG* rng, ecc_key* eccKey)
{
    int ret;
    uint8_t derSig[ECC_MAX_SIG_SIZE];
    word32 derSigLen = (word32)sizeof(derSig);
    word32 rLen;
    word32 sLen;

    if (hash == NULL || sigBuf == NULL || sigLen == NULL ||
        rng == NULL || eccKey == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (*sigLen < coordSz * 2u) {
        ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
    }
    else {
        /* Sign producing DER-encoded signature */
        ret = wc_ecc_sign_hash(hash, (word32)hashLen, derSig, &derSigLen,
                                rng, eccKey);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            /* Extract raw r and s from DER */
            rLen = (word32)coordSz;
            sLen = (word32)coordSz;

            /* Zero the output buffer for left-padding */
            XMEMSET(sigBuf, 0, coordSz * 2u);

            /* wc_ecc_sig_to_rs extracts r and s as raw bytes */
            ret = wc_ecc_sig_to_rs(derSig, derSigLen,
                                    sigBuf, &rLen,
                                    sigBuf + coordSz, &sLen);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
            else {
                /* Right-justify r and s within their coordSz fields */
                if (rLen < (word32)coordSz) {
                    XMEMMOVE(sigBuf + (coordSz - (size_t)rLen), sigBuf,
                              (size_t)rLen);
                    XMEMSET(sigBuf, 0, coordSz - (size_t)rLen);
                }
                if (sLen < (word32)coordSz) {
                    XMEMMOVE(sigBuf + coordSz + (coordSz - (size_t)sLen),
                              sigBuf + coordSz, (size_t)sLen);
                    XMEMSET(sigBuf + coordSz, 0, coordSz - (size_t)sLen);
                }
                *sigLen = coordSz * 2u;
            }
        }
        wc_ForceZero(derSig, sizeof(derSig));
    }
    return ret;
}

int wolfCose_EccVerifyRaw(const uint8_t* sigBuf, size_t sigLen,
                           const uint8_t* hash, size_t hashLen,
                           size_t coordSz, ecc_key* eccKey, int* verified)
{
    int ret;
    uint8_t derSig[ECC_MAX_SIG_SIZE];
    word32 derSigLen = (word32)sizeof(derSig);

    if (sigBuf == NULL || hash == NULL || eccKey == NULL || verified == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (sigLen != coordSz * 2u) {
        ret = WOLFCOSE_E_COSE_SIG_FAIL;
    }
    else {
        *verified = 0;

        /* Convert raw r||s to DER */
        ret = wc_ecc_rs_raw_to_sig(sigBuf, (word32)coordSz,
                                     sigBuf + coordSz, (word32)coordSz,
                                     derSig, &derSigLen);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            ret = wc_ecc_verify_hash(derSig, derSigLen, hash,
                                      (word32)hashLen, verified, eccKey);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        wc_ForceZero(derSig, sizeof(derSig));
    }
    return ret;
}
#endif /* HAVE_ECC */

/* ----- Internal: Protected/Unprotected header encode/decode ----- */

int wolfCose_EncodeProtectedHdr(int32_t alg, uint8_t* buf, size_t bufSz,
                                 size_t* outLen)
{
    int ret;
    WOLFCOSE_CBOR_CTX ctx;

    if (buf == NULL || outLen == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        ctx.buf = buf;
        ctx.bufSz = bufSz;
        ctx.idx = 0;

        /* Encode map with 1 entry: {1: alg} */
        ret = wc_CBOR_EncodeMapStart(&ctx, 1);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeUint(&ctx, (uint64_t)WOLFCOSE_HDR_ALG);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeInt(&ctx, (int64_t)alg);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            *outLen = ctx.idx;
        }
    }
    return ret;
}

int wolfCose_DecodeProtectedHdr(const uint8_t* data, size_t dataLen,
                                 WOLFCOSE_HDR* hdr)
{
    int ret;
    WOLFCOSE_CBOR_CTX ctx;
    size_t mapCount;
    size_t i;
    int64_t label;
    int64_t intVal;

    if (hdr == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (data == NULL || dataLen == 0u) {
        /* Empty protected header is valid */
        ret = WOLFCOSE_SUCCESS;
    }
    else {
        ctx.buf = (uint8_t*)(uintptr_t)data; /* MISRA Rule 11.8 deviation:
                                                  cast away const for CTX buf,
                                                  decoder does not modify */
        ctx.bufSz = dataLen;
        ctx.idx = 0;

        ret = wc_CBOR_DecodeMapStart(&ctx, &mapCount);

        if (ret == WOLFCOSE_SUCCESS && mapCount > WOLFCOSE_MAX_MAP_ITEMS) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
            mapCount = 0; /* Coverity: clear tainted loop bound */
        }

        for (i = 0; i < mapCount && ret == WOLFCOSE_SUCCESS; i++) {
            ret = wc_CBOR_DecodeInt(&ctx, &label);
            if (ret != WOLFCOSE_SUCCESS) {
                break;
            }

            if (label == WOLFCOSE_HDR_ALG) {
                ret = wc_CBOR_DecodeInt(&ctx, &intVal);
                if (ret == WOLFCOSE_SUCCESS) {
                    hdr->alg = (int32_t)intVal;
                }
            }
            else if (label == WOLFCOSE_HDR_CONTENT_TYPE) {
                ret = wc_CBOR_DecodeInt(&ctx, &intVal);
                if (ret == WOLFCOSE_SUCCESS) {
                    hdr->contentType = (int32_t)intVal;
                }
            }
            else {
                /* Skip unknown header */
                ret = wc_CBOR_Skip(&ctx);
            }
        }
    }
    return ret;
}

int wolfCose_DecodeUnprotectedHdr(WOLFCOSE_CBOR_CTX* ctx, WOLFCOSE_HDR* hdr)
{
    int ret;
    size_t mapCount;
    int64_t label;
    const uint8_t* bstrData;
    size_t bstrLen;

    if (ctx == NULL || hdr == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        size_t i;
        ret = wc_CBOR_DecodeMapStart(ctx, &mapCount);

        if (ret == WOLFCOSE_SUCCESS && mapCount > WOLFCOSE_MAX_MAP_ITEMS) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
            mapCount = 0; /* Coverity: clear tainted loop bound */
        }

        for (i = 0; i < mapCount && ret == WOLFCOSE_SUCCESS; i++) {
            ret = wc_CBOR_DecodeInt(ctx, &label);
            if (ret != WOLFCOSE_SUCCESS) {
                break;
            }

            if (label == WOLFCOSE_HDR_KID) {
                ret = wc_CBOR_DecodeBstr(ctx, &bstrData, &bstrLen);
                if (ret == WOLFCOSE_SUCCESS) {
                    hdr->kid = bstrData;
                    hdr->kidLen = bstrLen;
                }
            }
            else if (label == WOLFCOSE_HDR_IV) {
                ret = wc_CBOR_DecodeBstr(ctx, &bstrData, &bstrLen);
                if (ret == WOLFCOSE_SUCCESS) {
                    hdr->iv = bstrData;
                    hdr->ivLen = bstrLen;
                }
            }
            else if (label == WOLFCOSE_HDR_PARTIAL_IV) {
                ret = wc_CBOR_DecodeBstr(ctx, &bstrData, &bstrLen);
                if (ret == WOLFCOSE_SUCCESS) {
                    hdr->partialIv = bstrData;
                    hdr->partialIvLen = bstrLen;
                }
            }
            else if (label == WOLFCOSE_HDR_ALG) {
                /* Alg can appear in unprotected too (if not in protected) */
                int64_t algVal;
                ret = wc_CBOR_DecodeInt(ctx, &algVal);
                if (ret == WOLFCOSE_SUCCESS && hdr->alg == 0) {
                    hdr->alg = (int32_t)algVal;
                }
            }
            else {
                ret = wc_CBOR_Skip(ctx);
            }
        }
    }
    return ret;
}

/* ----- COSE Key API ----- */

int wc_CoseKey_Init(WOLFCOSE_KEY* key)
{
    int ret;

    if (key == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        XMEMSET(key, 0, sizeof(WOLFCOSE_KEY));
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}

void wc_CoseKey_Free(WOLFCOSE_KEY* key)
{
    if (key != NULL) {
        /* Does NOT free the underlying wolfCrypt key -- caller owns it */
        wc_ForceZero(key, sizeof(WOLFCOSE_KEY));
    }
}

#ifdef HAVE_ECC
int wc_CoseKey_SetEcc(WOLFCOSE_KEY* key, int32_t crv, ecc_key* eccKey)
{
    int ret;

    if (key == NULL || eccKey == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        key->kty = WOLFCOSE_KTY_EC2;
        key->crv = crv;
        key->key.ecc = eccKey;
        /* Check if private key is present */
        key->hasPrivate = (wc_ecc_size(eccKey) > 0 &&
                           eccKey->type == ECC_PRIVATEKEY) ? 1u : 0u;
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}
#endif

#ifdef HAVE_ED25519
int wc_CoseKey_SetEd25519(WOLFCOSE_KEY* key, ed25519_key* edKey)
{
    int ret;

    if (key == NULL || edKey == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        key->kty = WOLFCOSE_KTY_OKP;
        key->crv = WOLFCOSE_CRV_ED25519;
        key->key.ed25519 = edKey;
        key->hasPrivate = (edKey->privKeySet != 0) ? 1u : 0u;
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}
#endif

#ifdef HAVE_ED448
int wc_CoseKey_SetEd448(WOLFCOSE_KEY* key, ed448_key* edKey)
{
    int ret;

    if (key == NULL || edKey == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        key->kty = WOLFCOSE_KTY_OKP;
        key->crv = WOLFCOSE_CRV_ED448;
        key->key.ed448 = edKey;
        key->hasPrivate = (edKey->privKeySet != 0) ? 1u : 0u;
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}
#endif /* HAVE_ED448 */

#ifdef HAVE_DILITHIUM
int wc_CoseKey_SetDilithium(WOLFCOSE_KEY* key, int32_t alg,
                              dilithium_key* dlKey)
{
    int ret;

    if (key == NULL || dlKey == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (alg != WOLFCOSE_ALG_ML_DSA_44 &&
             alg != WOLFCOSE_ALG_ML_DSA_65 &&
             alg != WOLFCOSE_ALG_ML_DSA_87) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }
    else {
        key->kty = WOLFCOSE_KTY_OKP; /* PQC uses OKP kty per COSE WG */
        key->alg = alg;
        if (alg == WOLFCOSE_ALG_ML_DSA_44)      key->crv = WOLFCOSE_CRV_ML_DSA_44;
        else if (alg == WOLFCOSE_ALG_ML_DSA_65)  key->crv = WOLFCOSE_CRV_ML_DSA_65;
        else                                      key->crv = WOLFCOSE_CRV_ML_DSA_87;
        key->key.dilithium = dlKey;
        key->hasPrivate = (dlKey->prvKeySet != 0) ? 1u : 0u;
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}
#endif /* HAVE_DILITHIUM */

#ifdef WC_RSA_PSS
int wc_CoseKey_SetRsa(WOLFCOSE_KEY* key, RsaKey* rsaKey)
{
    int ret;

    if (key == NULL || rsaKey == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        key->kty = WOLFCOSE_KTY_RSA;
        key->key.rsa = rsaKey;
        key->hasPrivate = (wc_RsaEncryptSize(rsaKey) > 0 &&
                           rsaKey->type == RSA_PRIVATE) ? 1u : 0u;
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}
#endif /* WC_RSA_PSS */

int wc_CoseKey_SetSymmetric(WOLFCOSE_KEY* key, const uint8_t* data,
                             size_t dataLen)
{
    int ret;

    if (key == NULL || data == NULL || dataLen == 0u) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        key->kty = WOLFCOSE_KTY_SYMMETRIC;
        key->key.symm.key = data;
        key->key.symm.keyLen = dataLen;
        key->hasPrivate = 1;
        ret = WOLFCOSE_SUCCESS;
    }
    return ret;
}

#if defined(WOLFCOSE_KEY_ENCODE)
int wc_CoseKey_Encode(WOLFCOSE_KEY* key, uint8_t* out, size_t outSz,
                       size_t* outLen)
{
    int ret = WOLFCOSE_SUCCESS;
    WOLFCOSE_CBOR_CTX ctx;

    if (key == NULL || out == NULL || outLen == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        ctx.buf = out;
        ctx.bufSz = outSz;
        ctx.idx = 0;

#ifdef HAVE_ECC
        if (key->kty == WOLFCOSE_KTY_EC2) {
            uint8_t xBuf[66]; /* Max P-521 coordinate */
            uint8_t yBuf[66];
            word32 xLen = (word32)sizeof(xBuf);
            word32 yLen = (word32)sizeof(yBuf);
            size_t coordSz;
            size_t mapEntries;

            ret = wolfCose_CrvKeySize(key->crv, &coordSz);

            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_ecc_export_public_raw(key->key.ecc, xBuf, &xLen,
                                               yBuf, &yLen);
                if (ret != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
            }

            /* Map: kty, crv, x, y [, d] */
            mapEntries = key->hasPrivate ? 5u : 4u;
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeMapStart(&ctx, mapEntries);
            }

            /* 1: kty */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeUint(&ctx, (uint64_t)WOLFCOSE_KEY_LABEL_KTY);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeUint(&ctx, (uint64_t)key->kty);
            }
            /* -1: crv */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeInt(&ctx, (int64_t)WOLFCOSE_KEY_LABEL_CRV);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeUint(&ctx, (uint64_t)key->crv);
            }
            /* -2: x */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeInt(&ctx, (int64_t)WOLFCOSE_KEY_LABEL_X);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeBstr(&ctx, xBuf, (size_t)xLen);
            }
            /* -3: y */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeInt(&ctx, (int64_t)WOLFCOSE_KEY_LABEL_Y);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeBstr(&ctx, yBuf, (size_t)yLen);
            }
            /* -4: d (private key, optional) */
            if (ret == WOLFCOSE_SUCCESS && key->hasPrivate) {
                uint8_t dBuf[66];
                word32 dLen = (word32)sizeof(dBuf);
                ret = wc_ecc_export_private_only(key->key.ecc, dBuf, &dLen);
                if (ret != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
                else {
                    ret = wc_CBOR_EncodeInt(&ctx,
                                             (int64_t)WOLFCOSE_KEY_LABEL_D);
                    if (ret == WOLFCOSE_SUCCESS) {
                        ret = wc_CBOR_EncodeBstr(&ctx, dBuf, (size_t)dLen);
                    }
                }
                wc_ForceZero(dBuf, sizeof(dBuf));
            }

            if (ret == WOLFCOSE_SUCCESS) {
                *outLen = ctx.idx;
            }
            wc_ForceZero(xBuf, sizeof(xBuf));
            wc_ForceZero(yBuf, sizeof(yBuf));
        }
        else
#endif /* HAVE_ECC */
#ifdef WC_RSA_PSS
        if (key->kty == WOLFCOSE_KTY_RSA) {
            /* RFC 8230: {1:3, -1:n_bstr, -2:e_bstr [, -3:d_bstr]}
             * Export n and d directly into output buffer to avoid
             * large stack allocations (RSA-4096 modulus = 512 bytes). */
            uint8_t eBuf[8]; /* exponent, typically 3 bytes */
            word32 eLen = (word32)sizeof(eBuf);
            word32 nLen;
            size_t hdrPos;
            size_t mapEntries;

            /* Get n directly into output buffer, e into small stack buf */
            mapEntries = key->hasPrivate ? 4u : 3u;
            ret = wc_CBOR_EncodeMapStart(&ctx, mapEntries);

            /* 1: kty */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeUint(&ctx,
                                          (uint64_t)WOLFCOSE_KEY_LABEL_KTY);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeUint(&ctx, (uint64_t)key->kty);
            }
            /* -1: n (modulus) — direct export into output buffer */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeInt(&ctx,
                                         (int64_t)WOLFCOSE_KEY_LABEL_CRV);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                hdrPos = ctx.idx;
                if (ctx.idx + 3u > ctx.bufSz) {
                    ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
                }
                else {
                    ctx.idx += 3u; /* reserve bstr header */
                    nLen = (word32)(ctx.bufSz - ctx.idx);
                    ret = wc_RsaFlattenPublicKey((RsaKey*)key->key.rsa,
                        eBuf, &eLen, ctx.buf + ctx.idx, &nLen);
                    if (ret != 0) {
                        ret = WOLFCOSE_E_CRYPTO;
                    }
                    else if (nLen < 256u || nLen > 65535u) {
                        ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
                    }
                    else {
                        ctx.buf[hdrPos] = 0x59u;
                        ctx.buf[hdrPos + 1u] =
                            (uint8_t)((uint32_t)nLen >> 8u);
                        ctx.buf[hdrPos + 2u] =
                            (uint8_t)((uint32_t)nLen & 0xFFu);
                        ctx.idx += (size_t)nLen;
                    }
                }
            }
            /* -2: e (exponent, small — from stack buffer) */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeInt(&ctx,
                                         (int64_t)WOLFCOSE_KEY_LABEL_X);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeBstr(&ctx, eBuf, (size_t)eLen);
            }
            /* -3: d (private exponent, optional) — direct export */
            if (ret == WOLFCOSE_SUCCESS && key->hasPrivate) {
                ret = wc_CBOR_EncodeInt(&ctx,
                                         (int64_t)WOLFCOSE_KEY_LABEL_Y);
                if (ret == WOLFCOSE_SUCCESS) {
                    hdrPos = ctx.idx;
                    if (ctx.idx + 3u > ctx.bufSz) {
                        ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
                    }
                    else {
                        /* Use output buffer tail for d, then scratch
                         * space for e2/n2/p/q that RsaExportKey requires */
                        word32 dSz, eSz2, nSz2, pSz, qSz;
                        int rsaEncSz;

                        rsaEncSz = wc_RsaEncryptSize((RsaKey*)key->key.rsa);
                        if (rsaEncSz <= 0) {
                            ret = WOLFCOSE_E_CRYPTO;
                        }
                        else {
                            size_t dOff, scrOff, needed;
                            ctx.idx += 3u;
                            dOff = ctx.idx;
                            /* After d: scratch for e2+n2+p+q */
                            scrOff = dOff + (size_t)rsaEncSz;
                            needed = scrOff + 8u + (size_t)rsaEncSz +
                                     (size_t)rsaEncSz; /* e2+n2+p+q */
                            if (needed > ctx.bufSz) {
                                ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
                            }
                            else {
                                dSz = (word32)rsaEncSz;
                                eSz2 = 8;
                                nSz2 = (word32)rsaEncSz;
                                pSz = (word32)((word32)rsaEncSz / 2u);
                                qSz = (word32)((word32)rsaEncSz / 2u);
                                ret = wc_RsaExportKey(
                                    (RsaKey*)key->key.rsa,
                                    ctx.buf + scrOff, &eSz2,
                                    ctx.buf + scrOff + 8u, &nSz2,
                                    ctx.buf + dOff, &dSz,
                                    ctx.buf + scrOff + 8u + nSz2, &pSz,
                                    ctx.buf + scrOff + 8u + nSz2 + pSz,
                                    &qSz);
                                if (ret != 0) {
                                    ret = WOLFCOSE_E_CRYPTO;
                                }
                                else if (dSz < 256u || dSz > 65535u) {
                                    ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
                                }
                                else {
                                    ctx.buf[hdrPos] = 0x59u;
                                    ctx.buf[hdrPos + 1u] =
                                        (uint8_t)((uint32_t)dSz >> 8u);
                                    ctx.buf[hdrPos + 2u] =
                                        (uint8_t)((uint32_t)dSz & 0xFFu);
                                    ctx.idx = dOff + (size_t)dSz;
                                }
                                /* Zero scratch (e2/n2/p/q) */
                                wc_ForceZero(ctx.buf + scrOff,
                                    needed - scrOff);
                            }
                        }
                    }
                }
            }

            if (ret == WOLFCOSE_SUCCESS) {
                *outLen = ctx.idx;
            }
            wc_ForceZero(eBuf, sizeof(eBuf));
        }
        else
#endif /* WC_RSA_PSS */
#ifdef HAVE_DILITHIUM
        if (key->kty == WOLFCOSE_KTY_OKP &&
            (key->crv == WOLFCOSE_CRV_ML_DSA_44 ||
             key->crv == WOLFCOSE_CRV_ML_DSA_65 ||
             key->crv == WOLFCOSE_CRV_ML_DSA_87)) {
            /* ML-DSA (Dilithium) COSE_Key: OKP with PQC curve.
             * Keys are large (pub up to 2592B, priv up to 4896B),
             * so we export directly into the output buffer to
             * avoid large stack allocations. */
            size_t dlMapEntries;
            word32 dlKeyLen;
            size_t hdrPos;

            dlMapEntries = key->hasPrivate ? 4u : 3u;
            ret = wc_CBOR_EncodeMapStart(&ctx, dlMapEntries);

            /* 1: kty = OKP (1) */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeUint(&ctx,
                                          (uint64_t)WOLFCOSE_KEY_LABEL_KTY);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeUint(&ctx, (uint64_t)key->kty);
            }
            /* -1: crv (negative for ML-DSA) */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeInt(&ctx,
                                         (int64_t)WOLFCOSE_KEY_LABEL_CRV);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeInt(&ctx, (int64_t)key->crv);
            }
            /* -2: x (public key bstr) - direct export into output */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeInt(&ctx,
                                         (int64_t)WOLFCOSE_KEY_LABEL_X);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                /* Reserve 3 bytes for CBOR bstr header (2-byte length).
                 * All Dilithium pub sizes (1312-2592) need this form. */
                hdrPos = ctx.idx;
                if (ctx.idx + 3u > ctx.bufSz) {
                    ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
                }
                else {
                    ctx.idx += 3u;
                    dlKeyLen = (word32)(ctx.bufSz - ctx.idx);
                    ret = wc_dilithium_export_public(key->key.dilithium,
                        ctx.buf + ctx.idx, &dlKeyLen);
                    if (ret != 0) {
                        ret = WOLFCOSE_E_CRYPTO;
                    }
                    else if (dlKeyLen < 256u || dlKeyLen > 65535u) {
                        /* Reserved 3 bytes for 2-byte AI; guard against
                         * future variants outside this range. */
                        ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
                    }
                    else {
                        /* bstr header: major type 2, AI 25 (2-byte len) */
                        ctx.buf[hdrPos] = 0x59u;
                        ctx.buf[hdrPos + 1u] =
                            (uint8_t)((uint32_t)dlKeyLen >> 8u);
                        ctx.buf[hdrPos + 2u] =
                            (uint8_t)((uint32_t)dlKeyLen & 0xFFu);
                        ctx.idx += (size_t)dlKeyLen;
                    }
                }
            }
            /* -4: d (private key, optional) - direct export */
            if (ret == WOLFCOSE_SUCCESS && key->hasPrivate) {
                ret = wc_CBOR_EncodeInt(&ctx,
                                         (int64_t)WOLFCOSE_KEY_LABEL_D);
                if (ret == WOLFCOSE_SUCCESS) {
                    hdrPos = ctx.idx;
                    if (ctx.idx + 3u > ctx.bufSz) {
                        ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
                    }
                    else {
                        ctx.idx += 3u;
                        dlKeyLen = (word32)(ctx.bufSz - ctx.idx);
                        ret = wc_dilithium_export_private(
                            key->key.dilithium,
                            ctx.buf + ctx.idx, &dlKeyLen);
                        if (ret != 0) {
                            ret = WOLFCOSE_E_CRYPTO;
                        }
                        else if (dlKeyLen < 256u || dlKeyLen > 65535u) {
                            ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
                        }
                        else {
                            ctx.buf[hdrPos] = 0x59u;
                            ctx.buf[hdrPos + 1u] =
                                (uint8_t)((uint32_t)dlKeyLen >> 8u);
                            ctx.buf[hdrPos + 2u] =
                                (uint8_t)((uint32_t)dlKeyLen & 0xFFu);
                            ctx.idx += (size_t)dlKeyLen;
                        }
                    }
                }
            }

            if (ret == WOLFCOSE_SUCCESS) {
                *outLen = ctx.idx;
            }
        }
        else
#endif /* HAVE_DILITHIUM */
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
        if (key->kty == WOLFCOSE_KTY_OKP) {
            uint8_t pubBuf[57]; /* Ed448 pub = 57 bytes, Ed25519 = 32 */
            word32 pubLen = (word32)sizeof(pubBuf);
            size_t mapEntries;

#ifdef HAVE_ED25519
            if (key->crv == WOLFCOSE_CRV_ED25519) {
                ret = wc_ed25519_export_public(key->key.ed25519,
                                                pubBuf, &pubLen);
                if (ret != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
            }
            else
#endif
#ifdef HAVE_ED448
            if (key->crv == WOLFCOSE_CRV_ED448) {
                ret = wc_ed448_export_public(key->key.ed448,
                                              pubBuf, &pubLen);
                if (ret != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
            }
            else
#endif
            {
                ret = WOLFCOSE_E_COSE_BAD_ALG;
            }

            mapEntries = key->hasPrivate ? 4u : 3u;
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeMapStart(&ctx, mapEntries);
            }

            /* 1: kty */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeUint(&ctx, (uint64_t)WOLFCOSE_KEY_LABEL_KTY);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeUint(&ctx, (uint64_t)key->kty);
            }
            /* -1: crv */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeInt(&ctx, (int64_t)WOLFCOSE_KEY_LABEL_CRV);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeUint(&ctx, (uint64_t)key->crv);
            }
            /* -2: x (public key) */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeInt(&ctx, (int64_t)WOLFCOSE_KEY_LABEL_X);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeBstr(&ctx, pubBuf, (size_t)pubLen);
            }
            /* -4: d (private key, optional) */
            if (ret == WOLFCOSE_SUCCESS && key->hasPrivate) {
                uint8_t privBuf[57]; /* Ed448 priv = 57 bytes */
                word32 privLen = (word32)sizeof(privBuf);
#ifdef HAVE_ED25519
                if (key->crv == WOLFCOSE_CRV_ED25519) {
                    ret = wc_ed25519_export_private_only(key->key.ed25519,
                                                          privBuf, &privLen);
                }
                else
#endif
#ifdef HAVE_ED448
                if (key->crv == WOLFCOSE_CRV_ED448) {
                    ret = wc_ed448_export_private_only(key->key.ed448,
                                                        privBuf, &privLen);
                }
                else
#endif
                {
                    ret = WOLFCOSE_E_COSE_BAD_ALG;
                }
                if (ret != 0 && ret != WOLFCOSE_E_COSE_BAD_ALG) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
                else if (ret == 0) {
                    ret = wc_CBOR_EncodeInt(&ctx,
                                             (int64_t)WOLFCOSE_KEY_LABEL_D);
                    if (ret == WOLFCOSE_SUCCESS) {
                        ret = wc_CBOR_EncodeBstr(&ctx, privBuf,
                                                  (size_t)privLen);
                    }
                }
                wc_ForceZero(privBuf, sizeof(privBuf));
            }

            if (ret == WOLFCOSE_SUCCESS) {
                *outLen = ctx.idx;
            }
            wc_ForceZero(pubBuf, sizeof(pubBuf));
        }
        else
#endif /* HAVE_ED25519 || HAVE_ED448 */
        if (key->kty == WOLFCOSE_KTY_SYMMETRIC) {
            /* {1: 4, -1: k_bytes} */
            ret = wc_CBOR_EncodeMapStart(&ctx, 2);
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeUint(&ctx, (uint64_t)WOLFCOSE_KEY_LABEL_KTY);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeUint(&ctx, (uint64_t)key->kty);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeInt(&ctx, (int64_t)WOLFCOSE_KEY_LABEL_K);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeBstr(&ctx, key->key.symm.key,
                                          key->key.symm.keyLen);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                *outLen = ctx.idx;
            }
        }
        else {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
    }

    /* Cleanup: zero output buffer on error */
    if (ret != WOLFCOSE_SUCCESS && out != NULL) {
        wc_ForceZero(out, outSz);
    }

    return ret;
}
#endif /* WOLFCOSE_KEY_ENCODE */

#if defined(WOLFCOSE_KEY_DECODE)
int wc_CoseKey_Decode(WOLFCOSE_KEY* key, const uint8_t* in, size_t inSz)
{
    int ret;
    WOLFCOSE_CBOR_CTX ctx;
    size_t mapCount;
    size_t i;
    int64_t label;
    uint64_t uval;
    const uint8_t* bstrData;
    size_t bstrLen;
    const uint8_t* xData = NULL;  /* EC2: x coord, RSA: e (exponent) */
    size_t xLen = 0;
    const uint8_t* yData = NULL;  /* EC2: y coord, RSA: d (private exp) */
    size_t yLen = 0;
    const uint8_t* dData = NULL;  /* EC2/OKP: private key */
    size_t dLen = 0;
    const uint8_t* nData = NULL;  /* RSA: n (modulus) */
    size_t nLen = 0;

    if (key == NULL || in == NULL || inSz == 0u) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        ctx.buf = (uint8_t*)(uintptr_t)in; /* MISRA Rule 11.8 deviation */
        ctx.bufSz = inSz;
        ctx.idx = 0;

        ret = wc_CBOR_DecodeMapStart(&ctx, &mapCount);

        if (ret == WOLFCOSE_SUCCESS && mapCount > WOLFCOSE_MAX_MAP_ITEMS) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
            mapCount = 0; /* Coverity: clear tainted loop bound */
        }

        for (i = 0; i < mapCount && ret == WOLFCOSE_SUCCESS; i++) {
            ret = wc_CBOR_DecodeInt(&ctx, &label);
            if (ret != WOLFCOSE_SUCCESS) {
                break;
            }

            if (label == WOLFCOSE_KEY_LABEL_KTY) {
                ret = wc_CBOR_DecodeUint(&ctx, &uval);
                if (ret == WOLFCOSE_SUCCESS) {
                    key->kty = (int32_t)uval;
                }
            }
            else if (label == WOLFCOSE_KEY_LABEL_KID) {
                ret = wc_CBOR_DecodeBstr(&ctx, &bstrData, &bstrLen);
                if (ret == WOLFCOSE_SUCCESS) {
                    key->kid = bstrData;
                    key->kidLen = bstrLen;
                }
            }
            else if (label == WOLFCOSE_KEY_LABEL_ALG) {
                int64_t algVal;
                ret = wc_CBOR_DecodeInt(&ctx, &algVal);
                if (ret == WOLFCOSE_SUCCESS) {
                    key->alg = (int32_t)algVal;
                }
            }
            else if (label == WOLFCOSE_KEY_LABEL_CRV) {
                /* -1: crv(uint/negint) for EC2/OKP, k(bstr) for Symmetric,
                 *     n(bstr) for RSA (RFC 8230).
                 * Peek at CBOR type so decode is order-independent --
                 * kty may not have been parsed yet (non-canonical CBOR). */
                if (ctx.idx < ctx.bufSz &&
                    wc_CBOR_PeekType(&ctx) == WOLFCOSE_CBOR_BSTR) {
                    /* bstr: either symmetric k or RSA n.
                     * Route to correct field in import phase via kty. */
                    ret = wc_CBOR_DecodeBstr(&ctx, &bstrData, &bstrLen);
                    if (ret == WOLFCOSE_SUCCESS) {
                        /* Stash in nData; import phase dispatches on kty */
                        nData = bstrData;
                        nLen = bstrLen;
                    }
                }
                else {
                    /* uint or negint: EC2/OKP crv */
                    int64_t crvVal;
                    ret = wc_CBOR_DecodeInt(&ctx, &crvVal);
                    if (ret == WOLFCOSE_SUCCESS) {
                        key->crv = (int32_t)crvVal;
                    }
                }
            }
            else if (label == WOLFCOSE_KEY_LABEL_X) {
                ret = wc_CBOR_DecodeBstr(&ctx, &xData, &xLen);
            }
            else if (label == WOLFCOSE_KEY_LABEL_Y) {
                ret = wc_CBOR_DecodeBstr(&ctx, &yData, &yLen);
            }
            else if (label == WOLFCOSE_KEY_LABEL_D) {
                ret = wc_CBOR_DecodeBstr(&ctx, &dData, &dLen);
            }
            else {
                ret = wc_CBOR_Skip(&ctx);
            }
        }

        /* Import key data into wolfCrypt key structs */
        if (ret == WOLFCOSE_SUCCESS) {
#ifdef HAVE_ECC
            if (key->kty == WOLFCOSE_KTY_EC2 && key->key.ecc != NULL) {
                if (xData == NULL || yData == NULL) {
                    ret = WOLFCOSE_E_COSE_BAD_HDR;
                }
                else {
                    int wcCrv;
                    ret = wolfCose_CrvToWcCurve(key->crv, &wcCrv);
                    if (ret == WOLFCOSE_SUCCESS) {
                        if (dData != NULL) {
                            ret = wc_ecc_import_unsigned(key->key.ecc,
                                (byte*)xData, (byte*)yData,
                                (byte*)dData, wcCrv);
                            if (ret == 0) {
                                key->hasPrivate = 1;
                            }
                        }
                        else {
                            ret = wc_ecc_import_unsigned(key->key.ecc,
                                (byte*)xData, (byte*)yData,
                                NULL, wcCrv);
                        }
                        if (ret != 0 && ret != WOLFCOSE_SUCCESS) {
                            ret = WOLFCOSE_E_CRYPTO;
                        }
                    }
                }
            }
            else
#endif
#ifdef WC_RSA_PSS
            if (key->kty == WOLFCOSE_KTY_RSA && key->key.rsa != NULL) {
                /* RFC 8230: -1=n(bstr), -2=e(bstr), -3=d(bstr) */
                if (nData == NULL || xData == NULL) {
                    ret = WOLFCOSE_E_COSE_BAD_HDR;
                }
                else {
                    ret = wc_RsaPublicKeyDecodeRaw(nData, (word32)nLen,
                        xData, (word32)xLen, key->key.rsa);
                    if (ret != 0) {
                        ret = WOLFCOSE_E_CRYPTO;
                    }
                    else {
                        /* Public key only — full private import from raw
                         * n,e,d components is not currently supported */
                        key->hasPrivate = 0u;
                    }
                }
            }
            else
#endif
#ifdef HAVE_DILITHIUM
            if (key->kty == WOLFCOSE_KTY_OKP &&
                key->key.dilithium != NULL &&
                (key->crv == WOLFCOSE_CRV_ML_DSA_44 ||
                 key->crv == WOLFCOSE_CRV_ML_DSA_65 ||
                 key->crv == WOLFCOSE_CRV_ML_DSA_87)) {
                byte dlLevel;
                if (key->crv == WOLFCOSE_CRV_ML_DSA_44)      dlLevel = 2;
                else if (key->crv == WOLFCOSE_CRV_ML_DSA_65)  dlLevel = 3;
                else                                            dlLevel = 5;

                if (xData == NULL) {
                    ret = WOLFCOSE_E_COSE_BAD_HDR;
                }
                else {
                    /* Set level before import */
                    ret = wc_dilithium_set_level(key->key.dilithium,
                                                  dlLevel);
                    if (ret != 0) {
                        ret = WOLFCOSE_E_CRYPTO;
                    }
                    else if (dData != NULL) {
                        ret = wc_dilithium_import_key(
                            dData, (word32)dLen,
                            xData, (word32)xLen, key->key.dilithium);
                        if (ret == 0) { key->hasPrivate = 1; }
                        else { ret = WOLFCOSE_E_CRYPTO; }
                    }
                    else {
                        ret = wc_dilithium_import_public(
                            xData, (word32)xLen, key->key.dilithium);
                        if (ret != 0) { ret = WOLFCOSE_E_CRYPTO; }
                    }
                }
            }
            else
#endif /* HAVE_DILITHIUM */
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
            if (key->kty == WOLFCOSE_KTY_OKP) {
                if (xData == NULL) {
                    ret = WOLFCOSE_E_COSE_BAD_HDR;
                }
#ifdef HAVE_ED25519
                else if (key->crv == WOLFCOSE_CRV_ED25519 &&
                         key->key.ed25519 != NULL) {
                    if (dData != NULL) {
                        ret = wc_ed25519_import_private_key(dData, (word32)dLen,
                            xData, (word32)xLen, key->key.ed25519);
                        if (ret == 0) { key->hasPrivate = 1; }
                        else { ret = WOLFCOSE_E_CRYPTO; }
                    }
                    else {
                        ret = wc_ed25519_import_public(xData, (word32)xLen,
                                                        key->key.ed25519);
                        if (ret != 0) { ret = WOLFCOSE_E_CRYPTO; }
                    }
                }
#endif
#ifdef HAVE_ED448
                else if (key->crv == WOLFCOSE_CRV_ED448 &&
                         key->key.ed448 != NULL) {
                    if (dData != NULL) {
                        ret = wc_ed448_import_private_key(dData, (word32)dLen,
                            xData, (word32)xLen, key->key.ed448);
                        if (ret == 0) { key->hasPrivate = 1; }
                        else { ret = WOLFCOSE_E_CRYPTO; }
                    }
                    else {
                        ret = wc_ed448_import_public(xData, (word32)xLen,
                                                      key->key.ed448);
                        if (ret != 0) { ret = WOLFCOSE_E_CRYPTO; }
                    }
                }
#endif
                else {
                    ret = WOLFCOSE_E_COSE_BAD_ALG;
                }
            }
            else
#endif /* HAVE_ED25519 || HAVE_ED448 */
            if (key->kty == WOLFCOSE_KTY_SYMMETRIC) {
                /* nData holds the symmetric k value (parsed from label -1) */
                if (nData != NULL) {
                    key->key.symm.key = nData;
                    key->key.symm.keyLen = nLen;
                    key->hasPrivate = 1;
                }
            }
            else {
                /* Unknown key type but we parsed OK -- leave it */
            }
        }
    }

    return ret;
}
#endif /* WOLFCOSE_KEY_DECODE */

/* ----- Internal: RSA-PSS hash-to-MGF mapping ----- */
#ifdef WC_RSA_PSS
static int wolfCose_HashToMgf(enum wc_HashType hashType, int* mgf)
{
    int ret = WOLFCOSE_SUCCESS;

    if (mgf == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (hashType == WC_HASH_TYPE_SHA256) {
        *mgf = WC_MGF1SHA256;
    }
#ifdef WOLFSSL_SHA384
    else if (hashType == WC_HASH_TYPE_SHA384) {
        *mgf = WC_MGF1SHA384;
    }
#endif
#ifdef WOLFSSL_SHA512
    else if (hashType == WC_HASH_TYPE_SHA512) {
        *mgf = WC_MGF1SHA512;
    }
#endif
    else {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }
    return ret;
}
#endif

/* -----
 * Unified Structure Builders (Phase 3 refactoring)
 *
 * These shared helpers reduce code size by unifying:
 * - Sig_structure (Sign1/Sign): [context, body_prot, [sign_prot,] ext_aad, payload]
 * - MAC_structure (Mac0/Mac): [context, body_prot, ext_aad, payload]
 * - Enc_structure (Encrypt0/Encrypt): [context, body_prot, ext_aad]
 * ----- */

/**
 * Build a ToBeSigned/ToBeMAced structure (RFC 9052 Section 4.4, 6.3).
 *
 * For Sign1/Mac0/Mac: [context, body_protected, external_aad, payload]
 * For Sign (multi-signer): [context, body_protected, sign_protected, external_aad, payload]
 */
int wolfCose_BuildToBeSignedMaced(
    const char* context, size_t contextLen,
    const uint8_t* bodyProtected, size_t bodyProtectedLen,
    const uint8_t* signProtected, size_t signProtectedLen,
    const uint8_t* extAad, size_t extAadLen,
    const uint8_t* payload, size_t payloadLen,
    uint8_t* scratch, size_t scratchSz,
    size_t* structLen)
{
    int ret;
    WOLFCOSE_CBOR_CTX ctx;
    size_t arrayLen;

    ctx.buf = scratch;
    ctx.bufSz = scratchSz;
    ctx.idx = 0;

    /* 4 elements normally, 5 if sign_protected is present (multi-signer) */
    arrayLen = (signProtected != NULL) ? 5u : 4u;

    ret = wc_CBOR_EncodeArrayStart(&ctx, arrayLen);

    /* 1. context string */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeTstr(&ctx, (const uint8_t*)context, contextLen);
    }

    /* 2. body_protected (serialized protected headers) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, bodyProtected, bodyProtectedLen);
    }

    /* 3. sign_protected (only for multi-signer) */
    if (ret == WOLFCOSE_SUCCESS && signProtected != NULL) {
        ret = wc_CBOR_EncodeBstr(&ctx, signProtected, signProtectedLen);
    }

    /* 4. external_aad */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, extAad,
                                  (extAad != NULL) ? extAadLen : 0u);
    }

    /* 5. payload */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, payload, payloadLen);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        *structLen = ctx.idx;
    }
    return ret;
}

/**
 * Build an Enc_structure for AEAD operations (RFC 9052 Section 5.3).
 *
 * [context, body_protected, external_aad]
 */
int wolfCose_BuildEncStructure(
    const char* context, size_t contextLen,
    const uint8_t* bodyProtected, size_t bodyProtectedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    size_t* structLen)
{
    int ret;
    WOLFCOSE_CBOR_CTX ctx;

    ctx.buf = scratch;
    ctx.bufSz = scratchSz;
    ctx.idx = 0;

    ret = wc_CBOR_EncodeArrayStart(&ctx, 3);

    /* 1. context string */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeTstr(&ctx, (const uint8_t*)context, contextLen);
    }

    /* 2. body_protected */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, bodyProtected, bodyProtectedLen);
    }

    /* 3. external_aad */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, extAad,
                                  (extAad != NULL) ? extAadLen : 0u);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        *structLen = ctx.idx;
    }
    return ret;
}

/* -----
 * Key Distribution Algorithms (RFC 9053 Section 6)
 *
 * These helpers implement key wrapping and key agreement for multi-recipient
 * COSE_Encrypt and COSE_Mac messages.
 * ----- */

#if defined(WOLFCOSE_KEY_WRAP)
/**
 * Get AES key wrap key size for algorithm.
 * RFC 9053 Table 17: A128KW=16, A192KW=24, A256KW=32
 */
static int wolfCose_KeyWrapKeySize(int32_t alg, size_t* keySz)
{
    int ret = WOLFCOSE_SUCCESS;

    if (keySz == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        switch (alg) {
            case WOLFCOSE_ALG_A128KW:
                *keySz = 16;
                break;
            case WOLFCOSE_ALG_A192KW:
                *keySz = 24;
                break;
            case WOLFCOSE_ALG_A256KW:
                *keySz = 32;
                break;
            default:
                ret = WOLFCOSE_E_COSE_BAD_ALG;
                break;
        }
    }
    return ret;
}

/**
 * Wrap a CEK using AES Key Wrap (RFC 3394).
 *
 * \param alg       Key wrap algorithm (A128KW, A192KW, A256KW)
 * \param kek       Key encryption key
 * \param cek       Content encryption key to wrap
 * \param cekLen    CEK length (must be multiple of 8, >= 16)
 * \param out       Output buffer for wrapped key
 * \param outSz     Output buffer size
 * \param outLen    Output: wrapped key length (cekLen + 8)
 * \return WOLFCOSE_SUCCESS or error code
 */
static int wolfCose_KeyWrap(int32_t alg, const WOLFCOSE_KEY* kek,
                             const uint8_t* cek, size_t cekLen,
                             uint8_t* out, size_t outSz, size_t* outLen)
{
    int ret;
    size_t expectedKeySz;
    int wrapRet;

    if (kek == NULL || cek == NULL || out == NULL || outLen == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (kek->kty != WOLFCOSE_KTY_SYMMETRIC) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }
    else {
        ret = wolfCose_KeyWrapKeySize(alg, &expectedKeySz);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        if (kek->key.symm.keyLen != expectedKeySz) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        else if (outSz < cekLen + 8u) {
            ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
        }
    }

    if (ret == WOLFCOSE_SUCCESS) {
        wrapRet = wc_AesKeyWrap(kek->key.symm.key, (word32)kek->key.symm.keyLen,
                                 cek, (word32)cekLen,
                                 out, (word32)outSz, NULL);
        if (wrapRet > 0) {
            *outLen = (size_t)wrapRet;
            ret = WOLFCOSE_SUCCESS;
        }
        else {
            ret = WOLFCOSE_E_CRYPTO;
        }
    }

    return ret;
}

/**
 * Unwrap a CEK using AES Key Wrap (RFC 3394).
 *
 * \param alg           Key wrap algorithm
 * \param kek           Key encryption key
 * \param wrappedCek    Wrapped CEK
 * \param wrappedLen    Wrapped CEK length
 * \param cekOut        Output buffer for unwrapped CEK
 * \param cekOutSz      Output buffer size
 * \param cekLen        Output: unwrapped CEK length
 * \return WOLFCOSE_SUCCESS or error code
 */
static int wolfCose_KeyUnwrap(int32_t alg, const WOLFCOSE_KEY* kek,
                               const uint8_t* wrappedCek, size_t wrappedLen,
                               uint8_t* cekOut, size_t cekOutSz, size_t* cekLen)
{
    int ret;
    size_t expectedKeySz;
    int unwrapRet;

    if (kek == NULL || wrappedCek == NULL || cekOut == NULL || cekLen == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else if (kek->kty != WOLFCOSE_KTY_SYMMETRIC) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }
    else if (wrappedLen < 24u) {
        /* Minimum wrapped key is 24 bytes (16 byte CEK + 8 byte IV) */
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }
    else {
        ret = wolfCose_KeyWrapKeySize(alg, &expectedKeySz);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        if (kek->key.symm.keyLen != expectedKeySz) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        else if (cekOutSz < wrappedLen - 8u) {
            ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
        }
    }

    if (ret == WOLFCOSE_SUCCESS) {
        unwrapRet = wc_AesKeyUnWrap(kek->key.symm.key,
                                     (word32)kek->key.symm.keyLen,
                                     wrappedCek, (word32)wrappedLen,
                                     cekOut, (word32)cekOutSz, NULL);
        if (unwrapRet > 0) {
            *cekLen = (size_t)unwrapRet;
            ret = WOLFCOSE_SUCCESS;
        }
        else {
            ret = WOLFCOSE_E_CRYPTO;
        }
    }

    return ret;
}
#endif /* WOLFCOSE_KEY_WRAP */

#if defined(WOLFCOSE_KEY_WRAP)
/**
 * Check if algorithm is AES Key Wrap (A128KW, A192KW, A256KW).
 */
static int wolfCose_IsKeyWrapAlg(int32_t alg)
{
    return (alg == WOLFCOSE_ALG_A128KW ||
            alg == WOLFCOSE_ALG_A192KW ||
            alg == WOLFCOSE_ALG_A256KW);
}
#endif /* WOLFCOSE_KEY_WRAP */

/* ECDH-ES Direct key agreement (RFC 9053 Section 6.3.1).
 * Enabled when ECC and HKDF are available. */
#if defined(WOLFCOSE_ECDH_ES_DIRECT) && defined(HAVE_ECC) && defined(HAVE_HKDF)
/**
 * Build COSE_KDF_Context for ECDH key derivation (RFC 9053 Section 5.2).
 *
 * Simplified version: PartyUInfo and PartyVInfo are empty arrays.
 * SuppPubInfo contains only keyDataLength and empty protected header.
 *
 * \param contentAlgId      Content encryption algorithm for derived key
 * \param keyDataLengthBits Key length in bits
 * \param out               Output buffer
 * \param outSz             Output buffer size
 * \param outLen            Output: bytes written
 * \return WOLFCOSE_SUCCESS or error code
 */
static int wolfCose_KdfContextEncode(int32_t contentAlgId,
                                      size_t keyDataLengthBits,
                                      uint8_t* out, size_t outSz,
                                      size_t* outLen)
{
    int ret;
    WOLFCOSE_CBOR_CTX ctx;

    ctx.buf = out;
    ctx.bufSz = outSz;
    ctx.idx = 0;

    /* COSE_KDF_Context = [
     *   AlgorithmID,
     *   PartyUInfo : [nil, nil, nil],
     *   PartyVInfo : [nil, nil, nil],
     *   SuppPubInfo : [keyDataLength, h'']
     * ] */
    ret = wc_CBOR_EncodeArrayStart(&ctx, 4);

    /* AlgorithmID */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(&ctx, (int64_t)contentAlgId);
    }

    /* PartyUInfo: [nil, nil, nil] */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeArrayStart(&ctx, 3);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeNull(&ctx);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeNull(&ctx);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeNull(&ctx);
    }

    /* PartyVInfo: [nil, nil, nil] */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeArrayStart(&ctx, 3);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeNull(&ctx);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeNull(&ctx);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeNull(&ctx);
    }

    /* SuppPubInfo: [keyDataLength, h''] */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeArrayStart(&ctx, 2);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(&ctx, (uint64_t)keyDataLengthBits);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, NULL, 0); /* empty protected */
    }

    if (ret == WOLFCOSE_SUCCESS) {
        *outLen = ctx.idx;
    }
    return ret;
}

/**
 * Perform ECDH-ES key derivation (RFC 9053 Section 6.3.1).
 *
 * Generates an ephemeral key pair, performs ECDH with recipient's public key,
 * and derives the CEK using HKDF.
 *
 * \param alg             ECDH algorithm (-25 or -26)
 * \param recipientPub    Recipient's public key
 * \param contentAlgId    Content encryption algorithm
 * \param cekLenBytes     Required CEK length in bytes
 * \param ephemPubX       Output: ephemeral public key X coordinate
 * \param ephemPubY       Output: ephemeral public key Y coordinate
 * \param ephemPubSz      Size of X/Y buffers
 * \param ephemPubLen     Output: actual coordinate length
 * \param cekOut          Output: derived CEK
 * \param cekOutSz        CEK buffer size
 * \param rng             Initialized RNG
 * \return WOLFCOSE_SUCCESS or error code
 */
static int wolfCose_EcdhEsDirect(int32_t alg,
                                  const WOLFCOSE_KEY* recipientPub,
                                  int32_t contentAlgId,
                                  size_t cekLenBytes,
                                  uint8_t* ephemPubX, uint8_t* ephemPubY,
                                  size_t ephemPubSz, size_t* ephemPubLen,
                                  uint8_t* cekOut, size_t cekOutSz,
                                  WC_RNG* rng)
{
    int ret = WOLFCOSE_SUCCESS;
    ecc_key ephemKey;
    int ephemInited = 0;
    uint8_t sharedSecret[66]; /* Max for P-521 */
    word32 sharedSecretLen = sizeof(sharedSecret);
    uint8_t kdfContext[64];
    size_t kdfContextLen = 0;
    int hashType = 0;
    int wcCurve = 0;
    word32 xLen, yLen;

    (void)cekOutSz; /* Size check done via cekLenBytes */

    /* Parameter validation */
    if (recipientPub == NULL || ephemPubX == NULL || ephemPubY == NULL ||
        ephemPubLen == NULL || cekOut == NULL || rng == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    if (ret == WOLFCOSE_SUCCESS &&
        (recipientPub->kty != WOLFCOSE_KTY_EC2 ||
         recipientPub->key.ecc == NULL)) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }

    /* Determine hash type from algorithm */
    if (ret == WOLFCOSE_SUCCESS) {
        if (alg == WOLFCOSE_ALG_ECDH_ES_HKDF_256) {
            hashType = WC_SHA256;
        }
        else if (alg == WOLFCOSE_ALG_ECDH_ES_HKDF_512) {
            hashType = WC_SHA512;
        }
        else {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
        }
    }

    /* Get wolfCrypt curve ID */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_CrvToWcCurve(recipientPub->crv, &wcCurve);
    }

    /* Initialize ephemeral key */
    if (ret == WOLFCOSE_SUCCESS) {
        int eccRet = wc_ecc_init(&ephemKey);
        if (eccRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            ephemInited = 1;
        }
    }

    /* Set RNG on ephemeral key for ECDH */
    if (ret == WOLFCOSE_SUCCESS) {
        int eccRet = wc_ecc_set_rng(&ephemKey, rng);
        if (eccRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
    }

    /* Generate ephemeral key pair on same curve */
    if (ret == WOLFCOSE_SUCCESS) {
        int eccRet = wc_ecc_make_key_ex(rng, 0, &ephemKey, wcCurve);
        if (eccRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
    }

    /* Set RNG on recipient key for ECDH (required by wolfSSL) */
    if (ret == WOLFCOSE_SUCCESS) {
        int eccRet = wc_ecc_set_rng(recipientPub->key.ecc, rng);
        if (eccRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
    }

    /* Perform ECDH */
    if (ret == WOLFCOSE_SUCCESS) {
        int eccRet = wc_ecc_shared_secret(&ephemKey, recipientPub->key.ecc,
                                           sharedSecret, &sharedSecretLen);
        if (eccRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
    }

    /* Build KDF context */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_KdfContextEncode(contentAlgId, cekLenBytes * 8u,
                                         kdfContext, sizeof(kdfContext),
                                         &kdfContextLen);
    }

    /* Derive CEK using HKDF */
    if (ret == WOLFCOSE_SUCCESS) {
        int hkdfRet = wc_HKDF(hashType,
                               sharedSecret, sharedSecretLen,
                               NULL, 0,  /* No salt for ECDH-ES */
                               kdfContext, (word32)kdfContextLen,
                               cekOut, (word32)cekLenBytes);
        if (hkdfRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
    }

    /* Export ephemeral public key coordinates */
    if (ret == WOLFCOSE_SUCCESS) {
        xLen = (word32)ephemPubSz;
        yLen = (word32)ephemPubSz;
        int eccRet = wc_ecc_export_public_raw(&ephemKey, ephemPubX, &xLen,
                                               ephemPubY, &yLen);
        if (eccRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            *ephemPubLen = (size_t)xLen;
        }
    }

    /* Cleanup: always executed */
    if (ephemInited != 0) {
        wc_ecc_free(&ephemKey);
    }
    wc_ForceZero(sharedSecret, sizeof(sharedSecret));

    return ret;
}

/**
 * Receive side of ECDH-ES key derivation.
 *
 * Uses recipient's private key and sender's ephemeral public key to
 * derive the CEK.
 *
 * \param alg             ECDH algorithm (-25 or -26)
 * \param recipientKey    Recipient's key (with private key)
 * \param ephemPubX       Sender's ephemeral public key X coordinate
 * \param ephemPubY       Sender's ephemeral public key Y coordinate
 * \param ephemPubLen     Coordinate length
 * \param contentAlgId    Content encryption algorithm
 * \param cekLenBytes     Required CEK length in bytes
 * \param cekOut          Output: derived CEK
 * \param cekOutSz        CEK buffer size
 * \return WOLFCOSE_SUCCESS or error code
 */
static int wolfCose_EcdhEsDirectRecv(int32_t alg,
                                      const WOLFCOSE_KEY* recipientKey,
                                      const uint8_t* ephemPubX,
                                      const uint8_t* ephemPubY,
                                      size_t ephemPubLen,
                                      int32_t contentAlgId,
                                      size_t cekLenBytes,
                                      uint8_t* cekOut, size_t cekOutSz)
{
    int ret = WOLFCOSE_SUCCESS;
    ecc_key ephemPub;
    int ephemInited = 0;
    uint8_t sharedSecret[66];
    word32 sharedSecretLen = sizeof(sharedSecret);
    uint8_t kdfContext[64];
    size_t kdfContextLen = 0;
    int hashType = 0;
    int wcCurve = 0;
    WC_RNG rng;
    int rngInited = 0;

    (void)ephemPubLen; /* Coordinate size determined by curve */
    (void)cekOutSz;    /* Size check done via cekLenBytes */

    /* Parameter validation */
    if (recipientKey == NULL || ephemPubX == NULL || ephemPubY == NULL ||
        cekOut == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    if (ret == WOLFCOSE_SUCCESS &&
        (recipientKey->kty != WOLFCOSE_KTY_EC2 ||
         recipientKey->key.ecc == NULL ||
         recipientKey->hasPrivate != 1u)) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }

    /* Determine hash type from algorithm */
    if (ret == WOLFCOSE_SUCCESS) {
        if (alg == WOLFCOSE_ALG_ECDH_ES_HKDF_256) {
            hashType = WC_SHA256;
        }
        else if (alg == WOLFCOSE_ALG_ECDH_ES_HKDF_512) {
            hashType = WC_SHA512;
        }
        else {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
        }
    }

    /* Get wolfCrypt curve ID */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_CrvToWcCurve(recipientKey->crv, &wcCurve);
    }

    /* Initialize RNG for ECDH (required by wolfSSL) */
    if (ret == WOLFCOSE_SUCCESS) {
        int rngRet = wc_InitRng(&rng);
        if (rngRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            rngInited = 1;
        }
    }

    /* Import ephemeral public key */
    if (ret == WOLFCOSE_SUCCESS) {
        int eccRet = wc_ecc_init(&ephemPub);
        if (eccRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            ephemInited = 1;
        }
    }

    /* Set RNG on ephemeral key */
    if (ret == WOLFCOSE_SUCCESS) {
        int eccRet = wc_ecc_set_rng(&ephemPub, &rng);
        if (eccRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
    }

    if (ret == WOLFCOSE_SUCCESS) {
        int eccRet = wc_ecc_import_unsigned(&ephemPub,
                                             (byte*)ephemPubX, (byte*)ephemPubY,
                                             NULL, wcCurve);
        if (eccRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
    }

    /* Set RNG on recipient key for ECDH */
    if (ret == WOLFCOSE_SUCCESS) {
        int eccRet = wc_ecc_set_rng(recipientKey->key.ecc, &rng);
        if (eccRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
    }

    /* Perform ECDH */
    if (ret == WOLFCOSE_SUCCESS) {
        int eccRet = wc_ecc_shared_secret(recipientKey->key.ecc, &ephemPub,
                                           sharedSecret, &sharedSecretLen);
        if (eccRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
    }

    /* Build KDF context */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_KdfContextEncode(contentAlgId, cekLenBytes * 8u,
                                         kdfContext, sizeof(kdfContext),
                                         &kdfContextLen);
    }

    /* Derive CEK using HKDF */
    if (ret == WOLFCOSE_SUCCESS) {
        int hkdfRet = wc_HKDF(hashType,
                               sharedSecret, sharedSecretLen,
                               NULL, 0,
                               kdfContext, (word32)kdfContextLen,
                               cekOut, (word32)cekLenBytes);
        if (hkdfRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
    }

    /* Cleanup: always executed */
    if (ephemInited != 0) {
        wc_ecc_free(&ephemPub);
    }
    if (rngInited != 0) {
        wc_FreeRng(&rng);
    }
    wc_ForceZero(sharedSecret, sizeof(sharedSecret));

    return ret;
}

/**
 * Check if algorithm is an ECDH-ES direct algorithm.
 */
static int wolfCose_IsEcdhEsDirectAlg(int32_t alg)
{
    return (alg == WOLFCOSE_ALG_ECDH_ES_HKDF_256 ||
            alg == WOLFCOSE_ALG_ECDH_ES_HKDF_512);
}

/**
 * Encode ephemeral public key as COSE_Key in recipient unprotected header.
 *
 * COSE_Key: {1: 2, -1: crv, -2: x, -3: y}
 */
static int wolfCose_EncodeEphemeralKey(WOLFCOSE_CBOR_CTX* ctx,
                                        int crv,
                                        const uint8_t* x, size_t xLen,
                                        const uint8_t* y, size_t yLen)
{
    int ret;

    /* COSE_Key map with 4 entries */
    ret = wc_CBOR_EncodeMapStart(ctx, 4);
    if (ret == WOLFCOSE_SUCCESS) {
        /* kty = EC2 (2) */
        ret = wc_CBOR_EncodeInt(ctx, 1);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(ctx, WOLFCOSE_KTY_EC2);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        /* crv */
        ret = wc_CBOR_EncodeInt(ctx, -1);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(ctx, crv);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        /* x coordinate */
        ret = wc_CBOR_EncodeInt(ctx, -2);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(ctx, x, xLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        /* y coordinate */
        ret = wc_CBOR_EncodeInt(ctx, -3);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(ctx, y, yLen);
    }

    return ret;
}

/**
 * Decode ephemeral public key from COSE_Key in recipient unprotected header.
 *
 * Parses: {1: 2, -1: crv, -2: x, -3: y}
 */
static int wolfCose_DecodeEphemeralKey(WOLFCOSE_CBOR_CTX* ctx,
                                        int* crv,
                                        uint8_t* x, size_t xSz, size_t* xLen,
                                        uint8_t* y, size_t ySz, size_t* yLen)
{
    int ret;
    size_t mapCount;
    size_t i;
    int64_t label;
    int haveCrv = 0, haveX = 0, haveY = 0;
    const uint8_t* data;
    size_t dataLen;
    int64_t intVal;

    ret = wc_CBOR_DecodeMapStart(ctx, &mapCount);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }

    for (i = 0; i < mapCount; i++) {
        ret = wc_CBOR_DecodeInt(ctx, &label);
        if (ret != WOLFCOSE_SUCCESS) {
            return ret;
        }

        if (label == 1) {
            /* kty - verify it's EC2 */
            ret = wc_CBOR_DecodeInt(ctx, &intVal);
            if (ret != WOLFCOSE_SUCCESS) {
                return ret;
            }
            if (intVal != WOLFCOSE_KTY_EC2) {
                return WOLFCOSE_E_COSE_KEY_TYPE;
            }
        }
        else if (label == -1) {
            /* crv */
            ret = wc_CBOR_DecodeInt(ctx, &intVal);
            if (ret != WOLFCOSE_SUCCESS) {
                return ret;
            }
            *crv = (int)intVal;
            haveCrv = 1;
        }
        else if (label == -2) {
            /* x coordinate */
            ret = wc_CBOR_DecodeBstr(ctx, &data, &dataLen);
            if (ret != WOLFCOSE_SUCCESS) {
                return ret;
            }
            if (dataLen > xSz) {
                return WOLFCOSE_E_BUFFER_TOO_SMALL;
            }
            memcpy(x, data, dataLen);
            *xLen = dataLen;
            haveX = 1;
        }
        else if (label == -3) {
            /* y coordinate */
            ret = wc_CBOR_DecodeBstr(ctx, &data, &dataLen);
            if (ret != WOLFCOSE_SUCCESS) {
                return ret;
            }
            if (dataLen > ySz) {
                return WOLFCOSE_E_BUFFER_TOO_SMALL;
            }
            memcpy(y, data, dataLen);
            *yLen = dataLen;
            haveY = 1;
        }
        else {
            /* Unknown label - skip */
            ret = wc_CBOR_Skip(ctx);
            if (ret != WOLFCOSE_SUCCESS) {
                return ret;
            }
        }
    }

    if (!haveCrv || !haveX || !haveY) {
        return WOLFCOSE_E_COSE_BAD_HDR;
    }

    return WOLFCOSE_SUCCESS;
}

#endif /* WOLFCOSE_ECDH_ES_DIRECT && HAVE_ECC && HAVE_HKDF */

/* ----- COSE_Sign1 API ----- */

#if defined(WOLFCOSE_SIGN1)

/**
 * Build the Sig_structure for COSE_Sign1 (wrapper for unified builder):
 *   ["Signature1", body_protected, external_aad, payload]
 */
static int wolfCose_BuildSigStructure(const uint8_t* protectedHdr,
                                       size_t protectedLen,
                                       const uint8_t* extAad, size_t extAadLen,
                                       const uint8_t* payload,
                                       size_t payloadLen,
                                       uint8_t* scratch, size_t scratchSz,
                                       size_t* structLen)
{
    /* Use unified builder with "Signature1" context, no sign_protected */
    return wolfCose_BuildToBeSignedMaced(
        "Signature1", 10,
        protectedHdr, protectedLen,
        NULL, 0,  /* no sign_protected for Sign1 */
        extAad, extAadLen,
        payload, payloadLen,
        scratch, scratchSz, structLen);
}

#if defined(WOLFCOSE_SIGN1_SIGN)
int wc_CoseSign1_Sign(WOLFCOSE_KEY* key, int32_t alg,
    const uint8_t* kid, size_t kidLen,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen,
    WC_RNG* rng)
{
    int ret = WOLFCOSE_SUCCESS;
    uint8_t protectedBuf[WOLFCOSE_PROTECTED_HDR_MAX];
    size_t protectedLen = 0;
    size_t sigStructLen = 0;
    size_t sigSz = 0;
    uint8_t hashBuf[WC_MAX_DIGEST_SIZE];
    uint8_t sigBuf[132]; /* ECC/EdDSA max: ES512 = 66+66 = 132 */
    const uint8_t* sigPtr = sigBuf; /* points to sigBuf or scratch for RSA */
    WOLFCOSE_CBOR_CTX outCtx;
    size_t unprotectedEntries;
    const uint8_t* sigPayload;
    size_t sigPayloadLen;
    int isDetached;

    /* Determine which payload to use for signature */
    if (detachedPayload != NULL) {
        sigPayload = detachedPayload;
        sigPayloadLen = detachedLen;
        isDetached = 1;
    }
    else {
        sigPayload = payload;
        sigPayloadLen = payloadLen;
        isDetached = 0;
    }

    if (key == NULL || sigPayload == NULL || scratch == NULL ||
        out == NULL || outLen == NULL || rng == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    if (ret == WOLFCOSE_SUCCESS && key->hasPrivate != 1u) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }

    /* Encode protected headers: {1: alg} */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_EncodeProtectedHdr(alg, protectedBuf,
                                           sizeof(protectedBuf), &protectedLen);
    }

    /* Build Sig_structure in scratch using appropriate payload */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_BuildSigStructure(protectedBuf, protectedLen,
                                          extAad, extAadLen,
                                          sigPayload, sigPayloadLen,
                                          scratch, scratchSz, &sigStructLen);
    }

    /* Sign based on algorithm */
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
    if (ret == WOLFCOSE_SUCCESS && alg == WOLFCOSE_ALG_EDDSA) {
        word32 edSigLen = (word32)sizeof(sigBuf);
        if (key->kty != WOLFCOSE_KTY_OKP) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        /* EdDSA signs raw Sig_structure (no pre-hash) */
        if (ret == WOLFCOSE_SUCCESS) {
#ifdef HAVE_ED25519
            if (key->crv == WOLFCOSE_CRV_ED25519) {
                ret = wc_ed25519_sign_msg(scratch, (word32)sigStructLen,
                                           sigBuf, &edSigLen, key->key.ed25519);
                if (ret != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
                else {
                    sigSz = (size_t)edSigLen;
                }
            }
            else
#endif
#ifdef HAVE_ED448
            if (key->crv == WOLFCOSE_CRV_ED448) {
                ret = wc_ed448_sign_msg(scratch, (word32)sigStructLen,
                                         sigBuf, &edSigLen, key->key.ed448,
                                         NULL, 0);
                if (ret != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
                else {
                    sigSz = (size_t)edSigLen;
                }
            }
            else
#endif
            {
                ret = WOLFCOSE_E_COSE_BAD_ALG;
            }
        }
    }
    else
#endif /* HAVE_ED25519 || HAVE_ED448 */
#ifdef HAVE_ECC
    if (ret == WOLFCOSE_SUCCESS && (alg == WOLFCOSE_ALG_ES256 ||
        alg == WOLFCOSE_ALG_ES384 || alg == WOLFCOSE_ALG_ES512)) {
        enum wc_HashType hashType;
        int digestSz = 0;
        size_t coordSz = 0;

        if (key->kty != WOLFCOSE_KTY_EC2) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }

        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_AlgToHashType(alg, &hashType);
        }

        if (ret == WOLFCOSE_SUCCESS) {
            digestSz = wc_HashGetDigestSize(hashType);
            if (digestSz <= 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }

        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_Hash(hashType, scratch, (word32)sigStructLen,
                           hashBuf, (word32)digestSz);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }

        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_CrvKeySize(key->crv, &coordSz);
        }

        if (ret == WOLFCOSE_SUCCESS) {
            size_t rawSigLen = sizeof(sigBuf);
            ret = wolfCose_EccSignRaw(hashBuf, (size_t)digestSz,
                                       sigBuf, &rawSigLen, coordSz,
                                       rng, key->key.ecc);
            if (ret == WOLFCOSE_SUCCESS) {
                sigSz = rawSigLen;
            }
        }
    }
    else
#endif
#ifdef WC_RSA_PSS
    if (ret == WOLFCOSE_SUCCESS && (alg == WOLFCOSE_ALG_PS256 ||
        alg == WOLFCOSE_ALG_PS384 || alg == WOLFCOSE_ALG_PS512)) {
        enum wc_HashType hashType;
        int digestSz = 0;
        int mgf = 0;

        if (key->kty != WOLFCOSE_KTY_RSA) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }

        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_AlgToHashType(alg, &hashType);
        }

        if (ret == WOLFCOSE_SUCCESS) {
            digestSz = wc_HashGetDigestSize(hashType);
            if (digestSz <= 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }

        /* Hash Sig_structure */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_Hash(hashType, scratch, (word32)sigStructLen,
                           hashBuf, (word32)digestSz);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }

        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_HashToMgf(hashType, &mgf);
        }

        /* RSA sig goes into scratch (after hashing, scratch is free) */
        if (ret == WOLFCOSE_SUCCESS) {
            word32 rsaSigLen = (word32)scratchSz;
            ret = wc_RsaPSS_Sign_ex(hashBuf, (word32)digestSz,
                                      scratch, rsaSigLen,
                                      hashType, mgf, digestSz,
                                      key->key.rsa, rng);
            if (ret <= 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
            else {
                sigSz = (size_t)ret;
                sigPtr = scratch;
                ret = WOLFCOSE_SUCCESS;
            }
        }
    }
    else
#endif /* WC_RSA_PSS */
#ifdef HAVE_DILITHIUM
    if (ret == WOLFCOSE_SUCCESS && (alg == WOLFCOSE_ALG_ML_DSA_44 ||
        alg == WOLFCOSE_ALG_ML_DSA_65 || alg == WOLFCOSE_ALG_ML_DSA_87)) {
        size_t expectedSigSz = 0;

        if (key->kty != WOLFCOSE_KTY_OKP || key->key.dilithium == NULL) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }

        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_SigSize(alg, &expectedSigSz);
        }

        /* Sig output goes after Sig_structure in scratch */
        if (ret == WOLFCOSE_SUCCESS && sigStructLen + expectedSigSz > scratchSz) {
            ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
        }

        if (ret == WOLFCOSE_SUCCESS) {
            word32 dlSigLen = (word32)expectedSigSz;
            ret = wc_dilithium_sign_msg(
                scratch, (word32)sigStructLen,
                scratch + sigStructLen, &dlSigLen,
                key->key.dilithium, rng);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
            else {
                sigPtr = scratch + sigStructLen;
                sigSz = (size_t)dlSigLen;
            }
        }
    }
    else
#endif /* HAVE_DILITHIUM */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }

    /* Encode COSE_Sign1 output:
     * Tag(18) [protected_bstr, unprotected_map, payload_bstr, signature_bstr]
     */
    outCtx.buf = out;
    outCtx.bufSz = outSz;
    outCtx.idx = 0;

    /* Encode COSE_Sign1 output */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeTag(&outCtx, WOLFCOSE_TAG_SIGN1);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeArrayStart(&outCtx, 4);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&outCtx, protectedBuf, protectedLen);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        unprotectedEntries = (kid != NULL && kidLen > 0u) ? 1u : 0u;
        ret = wc_CBOR_EncodeMapStart(&outCtx, unprotectedEntries);
    }

    if (ret == WOLFCOSE_SUCCESS && kid != NULL && kidLen > 0u) {
        ret = wc_CBOR_EncodeUint(&outCtx, (uint64_t)WOLFCOSE_HDR_KID);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(&outCtx, kid, kidLen);
        }
    }

    /* payload (RFC 9052 Section 2: nil if detached) */
    if (ret == WOLFCOSE_SUCCESS) {
        if (isDetached != 0) {
            ret = wc_CBOR_EncodeNull(&outCtx);
        }
        else {
            ret = wc_CBOR_EncodeBstr(&outCtx, payload, payloadLen);
        }
    }

    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&outCtx, sigPtr, sigSz);
    }

    if (ret == WOLFCOSE_SUCCESS && outLen != NULL) {
        *outLen = outCtx.idx;
    }

    /* Cleanup: always executed */
    wc_ForceZero(hashBuf, sizeof(hashBuf));
    wc_ForceZero(sigBuf, sizeof(sigBuf));
    if (scratch != NULL) {
        wc_ForceZero(scratch, scratchSz);
    }
    if (ret != WOLFCOSE_SUCCESS && out != NULL) {
        wc_ForceZero(out, outSz);
    }

    return ret;
}
#endif /* WOLFCOSE_SIGN1_SIGN */

#if defined(WOLFCOSE_SIGN1_VERIFY)
int wc_CoseSign1_Verify(WOLFCOSE_KEY* key,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    const uint8_t** payload, size_t* payloadLen)
{
    int ret = WOLFCOSE_SUCCESS;
    WOLFCOSE_CBOR_CTX ctx;
    uint64_t tag;
    size_t arrayCount = 0;
    const uint8_t* protectedData = NULL;
    size_t protectedLen = 0;
    const uint8_t* payloadData = NULL;
    size_t payloadDataLen = 0;
    const uint8_t* sigData = NULL;
    size_t sigDataLen = 0;
    size_t sigStructLen = 0;
    uint8_t hashBuf[WC_MAX_DIGEST_SIZE];
    int32_t alg = 0;
    const uint8_t* verifyPayload = NULL;
    size_t verifyPayloadLen = 0;
    int isDetached = 0;

    if (key == NULL || in == NULL || scratch == NULL || hdr == NULL ||
        payload == NULL || payloadLen == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    if (ret == WOLFCOSE_SUCCESS) {
        XMEMSET(hdr, 0, sizeof(WOLFCOSE_HDR));

        ctx.buf = (uint8_t*)(uintptr_t)in; /* MISRA Rule 11.8 deviation */
        ctx.bufSz = inSz;
        ctx.idx = 0;

        /* Optional Tag(18) */
        if (ctx.idx < ctx.bufSz &&
            wc_CBOR_PeekType(&ctx) == WOLFCOSE_CBOR_TAG) {
            ret = wc_CBOR_DecodeTag(&ctx, &tag);
            if (ret == WOLFCOSE_SUCCESS && tag != WOLFCOSE_TAG_SIGN1) {
                ret = WOLFCOSE_E_COSE_BAD_TAG;
            }
        }
    }

    /* Array of 4 elements */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeArrayStart(&ctx, &arrayCount);
        if (ret == WOLFCOSE_SUCCESS && arrayCount != 4u) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }
    }

    /* 1. Protected headers (bstr) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeBstr(&ctx, &protectedData, &protectedLen);
    }

    /* Parse protected headers */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_DecodeProtectedHdr(protectedData, protectedLen, hdr);
    }

    /* 2. Unprotected headers (map) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_DecodeUnprotectedHdr(&ctx, hdr);
    }

    /* 3. Payload (bstr or null if detached) */
    if (ret == WOLFCOSE_SUCCESS) {
        if (ctx.idx < ctx.bufSz && ctx.buf[ctx.idx] == WOLFCOSE_CBOR_NULL) {
            /* Payload is null - detached mode (RFC 9052 Section 2) */
            ctx.idx++; /* consume the null byte */
            payloadData = NULL;
            payloadDataLen = 0;
            isDetached = 1;
            hdr->flags |= WOLFCOSE_HDR_FLAG_DETACHED;

            /* Must have detached payload provided */
            if (detachedPayload == NULL) {
                ret = WOLFCOSE_E_DETACHED_PAYLOAD;
            }
            else {
                verifyPayload = detachedPayload;
                verifyPayloadLen = detachedLen;
            }
        }
        else {
            ret = wc_CBOR_DecodeBstr(&ctx, &payloadData, &payloadDataLen);
            if (ret == WOLFCOSE_SUCCESS) {
                isDetached = 0;
                verifyPayload = payloadData;
                verifyPayloadLen = payloadDataLen;
            }
        }
    }

    /* 4. Signature (bstr) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeBstr(&ctx, &sigData, &sigDataLen);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        alg = hdr->alg;

        /* Rebuild Sig_structure in scratch using appropriate payload */
        ret = wolfCose_BuildSigStructure(protectedData, protectedLen,
                                          extAad, extAadLen,
                                          verifyPayload, verifyPayloadLen,
                                          scratch, scratchSz, &sigStructLen);
    }

    (void)isDetached; /* May be used in future for additional checks */

    /* Verify based on algorithm */
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
    if (ret == WOLFCOSE_SUCCESS && alg == WOLFCOSE_ALG_EDDSA) {
        int verified = 0;
        if (key->kty != WOLFCOSE_KTY_OKP) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
#ifdef HAVE_ED25519
        if (ret == WOLFCOSE_SUCCESS && key->crv == WOLFCOSE_CRV_ED25519) {
            ret = wc_ed25519_verify_msg(sigData, (word32)sigDataLen,
                                         scratch, (word32)sigStructLen,
                                         &verified, key->key.ed25519);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        else
#endif
#ifdef HAVE_ED448
        if (ret == WOLFCOSE_SUCCESS && key->crv == WOLFCOSE_CRV_ED448) {
            ret = wc_ed448_verify_msg(sigData, (word32)sigDataLen,
                                       scratch, (word32)sigStructLen,
                                       &verified, key->key.ed448, NULL, 0);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        else
#endif
        if (ret == WOLFCOSE_SUCCESS) {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
        }
        if (ret == WOLFCOSE_SUCCESS && verified != 1) {
            ret = WOLFCOSE_E_COSE_SIG_FAIL;
        }
    }
    else
#endif
#ifdef HAVE_ECC
    if (ret == WOLFCOSE_SUCCESS &&
        (alg == WOLFCOSE_ALG_ES256 || alg == WOLFCOSE_ALG_ES384 ||
         alg == WOLFCOSE_ALG_ES512)) {
        int verified = 0;
        size_t coordSz = 0;
        enum wc_HashType hashType = WC_HASH_TYPE_NONE;
        int digestSz = 0;

        if (key->kty != WOLFCOSE_KTY_EC2) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_AlgToHashType(alg, &hashType);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            digestSz = wc_HashGetDigestSize(hashType);
            if (digestSz <= 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_Hash(hashType, scratch, (word32)sigStructLen,
                           hashBuf, (word32)digestSz);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_CrvKeySize(key->crv, &coordSz);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_EccVerifyRaw(sigData, sigDataLen,
                                         hashBuf, (size_t)digestSz,
                                         coordSz, key->key.ecc, &verified);
        }
        if (ret == WOLFCOSE_SUCCESS && verified != 1) {
            ret = WOLFCOSE_E_COSE_SIG_FAIL;
        }
    }
    else
#endif
#ifdef WC_RSA_PSS
    if (ret == WOLFCOSE_SUCCESS &&
        (alg == WOLFCOSE_ALG_PS256 || alg == WOLFCOSE_ALG_PS384 ||
         alg == WOLFCOSE_ALG_PS512)) {
        enum wc_HashType hashType = WC_HASH_TYPE_NONE;
        int digestSz = 0;
        int mgf = 0;

        if (key->kty != WOLFCOSE_KTY_RSA) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_AlgToHashType(alg, &hashType);
        }
        if (ret == WOLFCOSE_SUCCESS) {
            digestSz = wc_HashGetDigestSize(hashType);
            if (digestSz <= 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_Hash(hashType, scratch, (word32)sigStructLen,
                           hashBuf, (word32)digestSz);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_HashToMgf(hashType, &mgf);
        }
        /* Copy sig into scratch — wc_RsaPSS_VerifyCheck modifies its
         * input buffer in-place; sigData points into the caller's
         * const COSE message and must not be written to. */
        if (ret == WOLFCOSE_SUCCESS) {
            if (sigDataLen > scratchSz) {
                ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            XMEMCPY(scratch, sigData, sigDataLen);
            ret = wc_RsaPSS_VerifyCheck(scratch, (word32)sigDataLen,
                                          scratch, (word32)scratchSz,
                                          hashBuf, (word32)digestSz,
                                          hashType, mgf, key->key.rsa);
            if (ret < 0) {
                ret = WOLFCOSE_E_COSE_SIG_FAIL;
            }
            else {
                ret = WOLFCOSE_SUCCESS;
            }
        }
    }
    else
#endif /* WC_RSA_PSS */
#ifdef HAVE_DILITHIUM
    if (ret == WOLFCOSE_SUCCESS &&
        (alg == WOLFCOSE_ALG_ML_DSA_44 || alg == WOLFCOSE_ALG_ML_DSA_65 ||
         alg == WOLFCOSE_ALG_ML_DSA_87)) {
        int verified = 0;

        if (key->kty != WOLFCOSE_KTY_OKP || key->key.dilithium == NULL) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_dilithium_verify_msg(sigData, (word32)sigDataLen,
                                            scratch, (word32)sigStructLen,
                                            &verified, key->key.dilithium);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS && verified != 1) {
            ret = WOLFCOSE_E_COSE_SIG_FAIL;
        }
    }
    else
#endif /* HAVE_DILITHIUM */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }

    /* Return zero-copy payload pointer into input buffer */
    if (ret == WOLFCOSE_SUCCESS) {
        *payload = payloadData;
        *payloadLen = payloadDataLen;
    }

    /* Cleanup: always executed */
    wc_ForceZero(hashBuf, sizeof(hashBuf));
    if (scratch != NULL) {
        wc_ForceZero(scratch, scratchSz);
    }

    return ret;
}
#endif /* WOLFCOSE_SIGN1_VERIFY */

#endif /* WOLFCOSE_SIGN1 */

/* -----
 * COSE_Sign Multi-signer API (RFC 9052 Section 4.1)
 *
 * COSE_Sign = [ Headers, payload : bstr / nil, signatures : [+ COSE_Signature] ]
 * COSE_Signature = [ Headers, signature : bstr ]
 * ----- */

#if defined(WOLFCOSE_SIGN)

#if defined(WOLFCOSE_SIGN_SIGN)
/**
 * Create a multi-signer COSE_Sign message.
 *
 * \param signers       Array of signer configurations
 * \param signerCount   Number of signers (must be >= 1)
 * \param payload       Payload to sign
 * \param payloadLen    Payload length
 * \param detachedPayload  Detached payload (NULL if payload is embedded)
 * \param detachedLen   Detached payload length
 * \param extAad        External AAD (may be NULL)
 * \param extAadLen     External AAD length
 * \param scratch       Scratch buffer for Sig_structure
 * \param scratchSz     Scratch buffer size
 * \param out           Output buffer for COSE_Sign message
 * \param outSz         Output buffer size
 * \param outLen        Output: message length
 * \param rng           Initialized RNG
 * \return WOLFCOSE_SUCCESS or error code
 */
int wc_CoseSign_Sign(const WOLFCOSE_SIGNATURE* signers, size_t signerCount,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen,
    WC_RNG* rng)
{
    int ret = WOLFCOSE_SUCCESS;
    uint8_t bodyProtectedBuf[WOLFCOSE_PROTECTED_HDR_MAX];
    size_t bodyProtectedLen = 0;
    uint8_t signerProtectedBuf[WOLFCOSE_PROTECTED_HDR_MAX];
    size_t signerProtectedLen = 0;
    size_t sigStructLen = 0;
    uint8_t hashBuf[WC_MAX_DIGEST_SIZE];
    uint8_t sigBuf[132]; /* Max: ES512 = 66+66 = 132 */
    size_t sigSz = 0;
    WOLFCOSE_CBOR_CTX outCtx;
    const uint8_t* sigPayload;
    size_t sigPayloadLen;
    int isDetached;
    size_t i;
    size_t unprotectedEntries;

    /* Determine which payload to use for signature */
    if (detachedPayload != NULL) {
        sigPayload = detachedPayload;
        sigPayloadLen = detachedLen;
        isDetached = 1;
    }
    else {
        sigPayload = payload;
        sigPayloadLen = payloadLen;
        isDetached = 0;
    }

    if (signers == NULL || signerCount == 0u || sigPayload == NULL ||
        scratch == NULL || out == NULL || outLen == NULL || rng == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    /* Verify all signers have valid keys */
    for (i = 0; ret == WOLFCOSE_SUCCESS && i < signerCount; i++) {
        if (signers[i].key == NULL || signers[i].key->hasPrivate != 1u) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
    }

    /* Body protected headers: empty map for multi-signer (alg per-signer) */
    if (ret == WOLFCOSE_SUCCESS) {
        bodyProtectedBuf[0] = 0xA0u; /* Empty map */
        bodyProtectedLen = 1;

        /* Start encoding COSE_Sign output */
        outCtx.buf = out;
        outCtx.bufSz = outSz;
        outCtx.idx = 0;
    }

    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeTag(&outCtx, WOLFCOSE_TAG_SIGN);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeArrayStart(&outCtx, 3);
    }

    /* 1. Body protected headers as bstr (empty map) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&outCtx, bodyProtectedBuf, bodyProtectedLen);
    }

    /* 2. Unprotected headers: empty map */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeMapStart(&outCtx, 0);
    }

    /* 3. Payload (nil if detached) */
    if (ret == WOLFCOSE_SUCCESS) {
        if (isDetached != 0) {
            ret = wc_CBOR_EncodeNull(&outCtx);
        }
        else {
            ret = wc_CBOR_EncodeBstr(&outCtx, payload, payloadLen);
        }
    }

    /* 4. Signatures array */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeArrayStart(&outCtx, signerCount);
    }

    /* Create each COSE_Signature */
    for (i = 0; ret == WOLFCOSE_SUCCESS && i < signerCount; i++) {
        const WOLFCOSE_SIGNATURE* signer = &signers[i];
        enum wc_HashType hashType = WC_HASH_TYPE_NONE;
        size_t hashLen = 0;

        /* Get signature and hash info for this signer's algorithm */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_SigSize(signer->algId, &sigSz);
        }

        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_AlgToHashType(signer->algId, &hashType);
        }

        /* Encode signer's protected headers: {1: alg} */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_EncodeProtectedHdr(signer->algId, signerProtectedBuf,
                                               sizeof(signerProtectedBuf),
                                               &signerProtectedLen);
        }

        /* Build Sig_structure for this signer (context = "Signature") */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_BuildToBeSignedMaced(
                "Signature", 9,
                bodyProtectedBuf, bodyProtectedLen,
                signerProtectedBuf, signerProtectedLen,
                extAad, extAadLen,
                sigPayload, sigPayloadLen,
                scratch, scratchSz, &sigStructLen);
        }

        /* Hash the Sig_structure */
        if (ret == WOLFCOSE_SUCCESS) {
            hashLen = (size_t)wc_HashGetDigestSize(hashType);
            ret = wc_Hash(hashType, scratch, (word32)sigStructLen,
                           hashBuf, (word32)hashLen);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }

        /* Sign the hash */
#ifdef HAVE_ECC
        if (ret == WOLFCOSE_SUCCESS && signer->key->kty == WOLFCOSE_KTY_EC2) {
            size_t coordSz = 0;
            ret = wolfCose_CrvKeySize(signer->key->crv, &coordSz);
            if (ret == WOLFCOSE_SUCCESS) {
                sigSz = coordSz * 2u;
                ret = wolfCose_EccSignRaw(hashBuf, hashLen,
                                           sigBuf, &sigSz, coordSz,
                                           rng, signer->key->key.ecc);
            }
        }
        else
#endif
#ifdef HAVE_ED25519
        if (ret == WOLFCOSE_SUCCESS && signer->key->kty == WOLFCOSE_KTY_OKP &&
            signer->key->crv == WOLFCOSE_CRV_ED25519) {
            word32 edSigSz = ED25519_SIG_SIZE;
            ret = wc_ed25519_sign_msg(scratch, (word32)sigStructLen,
                                       sigBuf, &edSigSz,
                                       signer->key->key.ed25519);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
            else {
                sigSz = (size_t)edSigSz;
            }
        }
        else
#endif
        if (ret == WOLFCOSE_SUCCESS) {
            ret = WOLFCOSE_E_UNSUPPORTED;
        }

        /* Encode COSE_Signature: [protected, unprotected, signature] */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeArrayStart(&outCtx, 3);
        }

        /* Signer protected headers */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(&outCtx, signerProtectedBuf,
                                      signerProtectedLen);
        }

        /* Signer unprotected headers (may include kid) */
        if (ret == WOLFCOSE_SUCCESS) {
            unprotectedEntries = (signer->kid != NULL) ? 1u : 0u;
            ret = wc_CBOR_EncodeMapStart(&outCtx, unprotectedEntries);
        }

        if (ret == WOLFCOSE_SUCCESS && signer->kid != NULL) {
            ret = wc_CBOR_EncodeUint(&outCtx, WOLFCOSE_HDR_KID);
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeBstr(&outCtx, signer->kid, signer->kidLen);
            }
        }

        /* Signature */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(&outCtx, sigBuf, sigSz);
        }
    }

    if (ret == WOLFCOSE_SUCCESS) {
        *outLen = outCtx.idx;
    }

    /* Cleanup: always executed */
    wc_ForceZero(hashBuf, sizeof(hashBuf));
    wc_ForceZero(sigBuf, sizeof(sigBuf));
    if (scratch != NULL) {
        wc_ForceZero(scratch, scratchSz);
    }

    return ret;
}
#endif /* WOLFCOSE_SIGN_SIGN */

#if defined(WOLFCOSE_SIGN_VERIFY)
/**
 * Verify a specific signer's signature in a COSE_Sign message.
 *
 * \param verifyKey     Key to verify with
 * \param signerIndex   Index of signer to verify (0-based)
 * \param in            COSE_Sign message
 * \param inSz          Message length
 * \param detachedPayload  Detached payload (NULL if embedded)
 * \param detachedLen   Detached payload length
 * \param extAad        External AAD (may be NULL)
 * \param extAadLen     External AAD length
 * \param scratch       Scratch buffer
 * \param scratchSz     Scratch buffer size
 * \param hdr           Output: parsed headers
 * \param payload       Output: pointer to payload in buffer
 * \param payloadLen    Output: payload length
 * \return WOLFCOSE_SUCCESS or error code
 */
int wc_CoseSign_Verify(const WOLFCOSE_KEY* verifyKey,
    size_t signerIndex,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    const uint8_t** payload, size_t* payloadLen)
{
    int ret = WOLFCOSE_SUCCESS;
    WOLFCOSE_CBOR_CTX ctx;
    uint64_t tag;
    size_t arrayCount = 0;
    const uint8_t* bodyProtectedData = NULL;
    size_t bodyProtectedLen = 0;
    const uint8_t* payloadData = NULL;
    size_t payloadDataLen = 0;
    size_t signatureCount = 0;
    const uint8_t* signerProtectedData = NULL;
    size_t signerProtectedLen = 0;
    const uint8_t* signature = NULL;
    size_t signatureLen = 0;
    size_t sigStructLen = 0;
    uint8_t hashBuf[WC_MAX_DIGEST_SIZE];
    enum wc_HashType hashType = WC_HASH_TYPE_NONE;
    size_t hashLen = 0;
    int32_t alg = 0;
    const uint8_t* verifyPayload = NULL;
    size_t verifyPayloadLen = 0;
    int isDetached = 0;
    size_t i;
    WOLFCOSE_HDR signerHdr;

    if (verifyKey == NULL || in == NULL || scratch == NULL || hdr == NULL ||
        payload == NULL || payloadLen == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    if (ret == WOLFCOSE_SUCCESS) {
        XMEMSET(hdr, 0, sizeof(WOLFCOSE_HDR));

        ctx.buf = (uint8_t*)(uintptr_t)in;
        ctx.bufSz = inSz;
        ctx.idx = 0;

        /* Optional Tag(98) */
        if (ctx.idx < ctx.bufSz &&
            wc_CBOR_PeekType(&ctx) == WOLFCOSE_CBOR_TAG) {
            ret = wc_CBOR_DecodeTag(&ctx, &tag);
            if (ret == WOLFCOSE_SUCCESS && tag != WOLFCOSE_TAG_SIGN) {
                ret = WOLFCOSE_E_COSE_BAD_TAG;
            }
        }
    }

    /* Array of 4 elements: [protected, unprotected, payload, signatures] */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeArrayStart(&ctx, &arrayCount);
    }

    /* 1. Body protected headers (bstr) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeBstr(&ctx, &bodyProtectedData, &bodyProtectedLen);
    }

    /* Parse body protected headers */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_DecodeProtectedHdr(bodyProtectedData, bodyProtectedLen, hdr);
    }

    /* 2. Body unprotected headers (map) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_DecodeUnprotectedHdr(&ctx, hdr);
    }

    /* 3. Payload (bstr or null if detached) */
    if (ret == WOLFCOSE_SUCCESS) {
        if (ctx.idx < ctx.bufSz && ctx.buf[ctx.idx] == WOLFCOSE_CBOR_NULL) {
            ctx.idx++;
            payloadData = NULL;
            payloadDataLen = 0;
            isDetached = 1;
            hdr->flags |= WOLFCOSE_HDR_FLAG_DETACHED;

            if (detachedPayload == NULL) {
                ret = WOLFCOSE_E_DETACHED_PAYLOAD;
            }
            else {
                verifyPayload = detachedPayload;
                verifyPayloadLen = detachedLen;
            }
        }
        else {
            ret = wc_CBOR_DecodeBstr(&ctx, &payloadData, &payloadDataLen);
            if (ret == WOLFCOSE_SUCCESS) {
                isDetached = 0;
                verifyPayload = payloadData;
                verifyPayloadLen = payloadDataLen;
            }
        }
    }

    /* 4. Signatures array */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeArrayStart(&ctx, &signatureCount);
        if (ret == WOLFCOSE_SUCCESS && signerIndex >= signatureCount) {
            ret = WOLFCOSE_E_INVALID_ARG;
        }
    }

    /* Skip to the requested signer */
    for (i = 0; i < signerIndex && ret == WOLFCOSE_SUCCESS; i++) {
        ret = wc_CBOR_Skip(&ctx);
    }

    /* Parse the target COSE_Signature: [protected, unprotected, signature] */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeArrayStart(&ctx, &arrayCount);
        if (ret == WOLFCOSE_SUCCESS && arrayCount != 3u) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }
    }

    /* Signer protected headers */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeBstr(&ctx, &signerProtectedData, &signerProtectedLen);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        XMEMSET(&signerHdr, 0, sizeof(signerHdr));
        ret = wolfCose_DecodeProtectedHdr(signerProtectedData, signerProtectedLen,
                                           &signerHdr);
        if (ret == WOLFCOSE_SUCCESS) {
            alg = signerHdr.alg;
        }
    }

    /* Signer unprotected headers (skip for now) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_Skip(&ctx);
    }

    /* Signature */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeBstr(&ctx, &signature, &signatureLen);
    }

    (void)isDetached;

    /* Build Sig_structure for verification */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_BuildToBeSignedMaced(
            "Signature", 9,
            bodyProtectedData, bodyProtectedLen,
            signerProtectedData, signerProtectedLen,
            extAad, extAadLen,
            verifyPayload, verifyPayloadLen,
            scratch, scratchSz, &sigStructLen);
    }

    /* Get hash type for algorithm */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_AlgToHashType(alg, &hashType);
    }

    /* Hash the Sig_structure */
    if (ret == WOLFCOSE_SUCCESS) {
        hashLen = (size_t)wc_HashGetDigestSize(hashType);
        ret = wc_Hash(hashType, scratch, (word32)sigStructLen,
                       hashBuf, (word32)hashLen);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
    }

    /* Verify signature */
#ifdef HAVE_ECC
    if (ret == WOLFCOSE_SUCCESS && verifyKey->kty == WOLFCOSE_KTY_EC2) {
        int verified = 0;
        size_t coordSz = 0;
        ret = wolfCose_CrvKeySize(verifyKey->crv, &coordSz);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_EccVerifyRaw(signature, signatureLen,
                                         hashBuf, hashLen, coordSz,
                                         verifyKey->key.ecc, &verified);
        }
        if (ret == WOLFCOSE_SUCCESS && verified != 1) {
            ret = WOLFCOSE_E_COSE_SIG_FAIL;
        }
    }
    else
#endif
#ifdef HAVE_ED25519
    if (ret == WOLFCOSE_SUCCESS && verifyKey->kty == WOLFCOSE_KTY_OKP &&
        verifyKey->crv == WOLFCOSE_CRV_ED25519) {
        int verified = 0;
        ret = wc_ed25519_verify_msg(signature, (word32)signatureLen,
                                     scratch, (word32)sigStructLen,
                                     &verified, verifyKey->key.ed25519);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        if (ret == WOLFCOSE_SUCCESS && verified != 1) {
            ret = WOLFCOSE_E_COSE_SIG_FAIL;
        }
    }
    else
#endif
    if (ret == WOLFCOSE_SUCCESS) {
        ret = WOLFCOSE_E_UNSUPPORTED;
    }

    /* Success - return payload pointer */
    if (ret == WOLFCOSE_SUCCESS) {
        *payload = payloadData;
        *payloadLen = payloadDataLen;
        hdr->alg = alg; /* Set algorithm from verified signer */
    }

    /* Cleanup: always executed */
    wc_ForceZero(hashBuf, sizeof(hashBuf));
    wc_ForceZero(scratch, scratchSz);

    return ret;
}
#endif /* WOLFCOSE_SIGN_VERIFY */

#endif /* WOLFCOSE_SIGN */

/* ----- COSE_Encrypt0 API ----- */

#if defined(WOLFCOSE_ENCRYPT0) && (defined(HAVE_AESGCM) || defined(HAVE_AESCCM) || \
    (defined(HAVE_CHACHA) && defined(HAVE_POLY1305)))

/**
 * Build the Enc_structure for COSE_Encrypt0 (wrapper for unified builder):
 *   ["Encrypt0", body_protected, external_aad]
 */
static int wolfCose_BuildEncStructure0(const uint8_t* protectedHdr,
                                        size_t protectedLen,
                                        const uint8_t* extAad,
                                        size_t extAadLen,
                                        uint8_t* scratch, size_t scratchSz,
                                        size_t* structLen)
{
    /* Use unified builder with "Encrypt0" context */
    return wolfCose_BuildEncStructure(
        "Encrypt0", 8,
        protectedHdr, protectedLen,
        extAad, extAadLen,
        scratch, scratchSz, structLen);
}

#if defined(WOLFCOSE_ENCRYPT0_ENCRYPT)
int wc_CoseEncrypt0_Encrypt(WOLFCOSE_KEY* key, int32_t alg,
    const uint8_t* iv, size_t ivLen,
    const uint8_t* payload, size_t payloadLen,
    uint8_t* detachedPayload, size_t detachedSz, size_t* detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen)
{
    int ret = WOLFCOSE_SUCCESS;
#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
    Aes aes;
    int aesInited = 0;
#endif
    uint8_t protectedBuf[WOLFCOSE_PROTECTED_HDR_MAX];
    size_t protectedLen = 0;
    size_t encStructLen = 0;
    size_t aeadKeyLen = 0;
    size_t aeadTagLen = 0;
    WOLFCOSE_CBOR_CTX outCtx;
    size_t ciphertextTotalLen = 0;
    size_t ciphertextOffset = 0;
    int isDetached;

    /* Determine if detached mode */
    isDetached = (detachedPayload != NULL);

    if (key == NULL || iv == NULL || payload == NULL || scratch == NULL ||
        out == NULL || outLen == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    /* For detached mode, need detachedLen output and sufficient buffer */
    if (ret == WOLFCOSE_SUCCESS && isDetached && (detachedLen == NULL ||
        detachedSz < payloadLen + WOLFCOSE_AES_GCM_TAG_SZ)) {
        ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
    }

    if (ret == WOLFCOSE_SUCCESS && key->kty != WOLFCOSE_KTY_SYMMETRIC) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }

    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_AeadKeyLen(alg, &aeadKeyLen);
    }

    if (ret == WOLFCOSE_SUCCESS && key->key.symm.keyLen != aeadKeyLen) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }

    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_AeadTagLen(alg, &aeadTagLen);
    }

    /* Validate nonce length matches algorithm spec */
    if (ret == WOLFCOSE_SUCCESS) {
        size_t expectedNonceLen;
        ret = wolfCose_AeadNonceLen(alg, &expectedNonceLen);
        if (ret == WOLFCOSE_SUCCESS && ivLen != expectedNonceLen) {
            ret = WOLFCOSE_E_INVALID_ARG;
        }
    }

    /* Encode protected headers */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_EncodeProtectedHdr(alg, protectedBuf,
                                           sizeof(protectedBuf), &protectedLen);
    }

    /* Build Enc_structure in scratch (used as AAD for AES-GCM) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_BuildEncStructure0(protectedBuf, protectedLen,
                                          extAad, extAadLen,
                                          scratch, scratchSz, &encStructLen);
    }

    /* Build output COSE_Encrypt0 structure up to ciphertext */
    if (ret == WOLFCOSE_SUCCESS) {
        outCtx.buf = out;
        outCtx.bufSz = outSz;
        outCtx.idx = 0;
        ret = wc_CBOR_EncodeTag(&outCtx, WOLFCOSE_TAG_ENCRYPT0);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeArrayStart(&outCtx, 3);
    }

    /* protected headers as bstr */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&outCtx, protectedBuf, protectedLen);
    }

    /* unprotected headers: {5: iv} */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeMapStart(&outCtx, 1);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeUint(&outCtx, (uint64_t)WOLFCOSE_HDR_IV);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&outCtx, iv, ivLen);
    }

    /* Ciphertext handling: attached or detached */
    if (ret == WOLFCOSE_SUCCESS) {
        ciphertextTotalLen = payloadLen + aeadTagLen;
    }

    /* Dispatch encryption by algorithm */
#ifdef HAVE_AESGCM
    if (ret == WOLFCOSE_SUCCESS &&
        (alg == WOLFCOSE_ALG_A128GCM || alg == WOLFCOSE_ALG_A192GCM ||
         alg == WOLFCOSE_ALG_A256GCM)) {
        ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            aesInited = 1;
            ret = wc_AesGcmSetKey(&aes, key->key.symm.key, (word32)aeadKeyLen);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }

        if (ret == WOLFCOSE_SUCCESS && isDetached != 0) {
            /* Detached mode: ciphertext goes to detachedPayload buffer */
            ret = wc_AesGcmEncrypt(&aes,
                detachedPayload,                      /* ciphertext output */
                payload, (word32)payloadLen,          /* plaintext input */
                iv, (word32)ivLen,                    /* nonce */
                detachedPayload + payloadLen,         /* auth tag (after ct) */
                (word32)aeadTagLen,
                scratch, (word32)encStructLen);       /* AAD = Enc_structure */
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
            else {
                *detachedLen = ciphertextTotalLen;
                /* Encode null in the message */
                ret = wc_CBOR_EncodeNull(&outCtx);
            }
        }
        else if (ret == WOLFCOSE_SUCCESS) {
            /* Attached mode: ciphertext in message */
            ret = wolfCose_CBOR_EncodeHead(&outCtx, WOLFCOSE_CBOR_BSTR,
                                            (uint64_t)ciphertextTotalLen);
            /* Check there's room for ciphertext + tag */
            if (ret == WOLFCOSE_SUCCESS &&
                outCtx.idx + ciphertextTotalLen > outCtx.bufSz) {
                ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ciphertextOffset = outCtx.idx;
                ret = wc_AesGcmEncrypt(&aes,
                    out + ciphertextOffset,              /* ciphertext output */
                    payload, (word32)payloadLen,          /* plaintext input */
                    iv, (word32)ivLen,                    /* nonce */
                    out + ciphertextOffset + payloadLen,  /* auth tag */
                    (word32)aeadTagLen,
                    scratch, (word32)encStructLen);       /* AAD */
                if (ret != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
                else {
                    outCtx.idx += ciphertextTotalLen;
                }
            }
        }
    }
    else
#endif /* HAVE_AESGCM */
#ifdef HAVE_AESCCM
    if (ret == WOLFCOSE_SUCCESS &&
        (alg == WOLFCOSE_ALG_AES_CCM_16_64_128  ||
         alg == WOLFCOSE_ALG_AES_CCM_16_64_256  ||
         alg == WOLFCOSE_ALG_AES_CCM_64_64_128  ||
         alg == WOLFCOSE_ALG_AES_CCM_64_64_256  ||
         alg == WOLFCOSE_ALG_AES_CCM_16_128_128 ||
         alg == WOLFCOSE_ALG_AES_CCM_16_128_256 ||
         alg == WOLFCOSE_ALG_AES_CCM_64_128_128 ||
         alg == WOLFCOSE_ALG_AES_CCM_64_128_256)) {
        /* AES-CCM: attached mode only for now */
        ret = wolfCose_CBOR_EncodeHead(&outCtx, WOLFCOSE_CBOR_BSTR,
                                        (uint64_t)ciphertextTotalLen);
        if (ret == WOLFCOSE_SUCCESS &&
            outCtx.idx + ciphertextTotalLen > outCtx.bufSz) {
            ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ciphertextOffset = outCtx.idx;
            ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
            else {
                aesInited = 1;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_AesCcmSetKey(&aes, key->key.symm.key, (word32)aeadKeyLen);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_AesCcmEncrypt(&aes,
                out + ciphertextOffset,
                payload, (word32)payloadLen,
                iv, (word32)ivLen,
                out + ciphertextOffset + payloadLen,
                (word32)aeadTagLen,
                scratch, (word32)encStructLen);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
            else {
                outCtx.idx += ciphertextTotalLen;
            }
        }
    }
    else
#endif /* HAVE_AESCCM */
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    if (ret == WOLFCOSE_SUCCESS && alg == WOLFCOSE_ALG_CHACHA20_POLY1305) {
        /* ChaCha20-Poly1305: attached mode only for now */
        ret = wolfCose_CBOR_EncodeHead(&outCtx, WOLFCOSE_CBOR_BSTR,
                                        (uint64_t)ciphertextTotalLen);
        if (ret == WOLFCOSE_SUCCESS &&
            outCtx.idx + ciphertextTotalLen > outCtx.bufSz) {
            ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ciphertextOffset = outCtx.idx;
            ret = wc_ChaCha20Poly1305_Encrypt(
                key->key.symm.key, iv,
                scratch, (word32)encStructLen,
                payload, (word32)payloadLen,
                out + ciphertextOffset,
                out + ciphertextOffset + payloadLen);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
            else {
                outCtx.idx += ciphertextTotalLen;
            }
        }
    }
    else
#endif /* HAVE_CHACHA && HAVE_POLY1305 */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }

    if (ret == WOLFCOSE_SUCCESS && outLen != NULL) {
        *outLen = outCtx.idx;
    }

    /* Cleanup: always executed */
#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
    if (aesInited != 0) {
        wc_AesFree(&aes);
    }
#endif
    if (scratch != NULL) {
        wc_ForceZero(scratch, scratchSz);
    }

    return ret;
}
#endif /* WOLFCOSE_ENCRYPT0_ENCRYPT */

#if defined(WOLFCOSE_ENCRYPT0_DECRYPT)
int wc_CoseEncrypt0_Decrypt(WOLFCOSE_KEY* key,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedCt, size_t detachedCtLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    uint8_t* plaintext, size_t plaintextSz, size_t* plaintextLen)
{
    int ret = WOLFCOSE_SUCCESS;
#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
    Aes aes;
    int aesInited = 0;
#endif
    WOLFCOSE_CBOR_CTX ctx;
    uint64_t tag;
    size_t arrayCount = 0;
    const uint8_t* protectedData = NULL;
    size_t protectedLen = 0;
    const uint8_t* ciphertext = NULL;
    size_t ciphertextLen = 0;
    size_t encStructLen = 0;
    size_t aeadKeyLen = 0;
    size_t aeadTagLen = 0;
    size_t payloadSz = 0;
    int32_t alg = 0;
    int isDetached = 0;

    if (key == NULL || in == NULL || scratch == NULL || hdr == NULL ||
        plaintext == NULL || plaintextLen == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    if (ret == WOLFCOSE_SUCCESS && key->kty != WOLFCOSE_KTY_SYMMETRIC) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }

    if (ret == WOLFCOSE_SUCCESS) {
        XMEMSET(hdr, 0, sizeof(WOLFCOSE_HDR));

        ctx.buf = (uint8_t*)(uintptr_t)in; /* MISRA Rule 11.8 deviation */
        ctx.bufSz = inSz;
        ctx.idx = 0;

        /* Optional Tag(16) */
        if (ctx.idx < ctx.bufSz &&
            wc_CBOR_PeekType(&ctx) == WOLFCOSE_CBOR_TAG) {
            ret = wc_CBOR_DecodeTag(&ctx, &tag);
            if (ret == WOLFCOSE_SUCCESS && tag != WOLFCOSE_TAG_ENCRYPT0) {
                ret = WOLFCOSE_E_COSE_BAD_TAG;
            }
        }
    }

    /* Array of 3 */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeArrayStart(&ctx, &arrayCount);
        if (ret == WOLFCOSE_SUCCESS && arrayCount != 3u) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }
    }

    /* 1. Protected headers */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeBstr(&ctx, &protectedData, &protectedLen);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_DecodeProtectedHdr(protectedData, protectedLen, hdr);
    }

    /* 2. Unprotected headers */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_DecodeUnprotectedHdr(&ctx, hdr);
    }

    /* 3. Ciphertext (bstr or null if detached) */
    if (ret == WOLFCOSE_SUCCESS) {
        if (ctx.idx < ctx.bufSz && ctx.buf[ctx.idx] == WOLFCOSE_CBOR_NULL) {
            /* Ciphertext is null - detached mode */
            ctx.idx++; /* consume the null byte */
            isDetached = 1;
            hdr->flags |= WOLFCOSE_HDR_FLAG_DETACHED;

            /* Must have detached ciphertext provided */
            if (detachedCt == NULL || detachedCtLen == 0u) {
                ret = WOLFCOSE_E_DETACHED_PAYLOAD;
            }
            else {
                ciphertext = detachedCt;
                ciphertextLen = detachedCtLen;
            }
        }
        else {
            ret = wc_CBOR_DecodeBstr(&ctx, &ciphertext, &ciphertextLen);
            if (ret == WOLFCOSE_SUCCESS) {
                isDetached = 0;
            }
        }
    }

    (void)isDetached; /* May be used in future for additional checks */

    if (ret == WOLFCOSE_SUCCESS) {
        alg = hdr->alg;
        ret = wolfCose_AeadKeyLen(alg, &aeadKeyLen);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_AeadTagLen(alg, &aeadTagLen);
    }

    if (ret == WOLFCOSE_SUCCESS && ciphertextLen < aeadTagLen) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
    }

    if (ret == WOLFCOSE_SUCCESS && key->key.symm.keyLen != aeadKeyLen) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }

    /* Payload size = ciphertext minus tag */
    if (ret == WOLFCOSE_SUCCESS) {
        payloadSz = ciphertextLen - aeadTagLen;
        if (payloadSz > plaintextSz) {
            ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
        }
    }

    if (ret == WOLFCOSE_SUCCESS &&
        (hdr->iv == NULL || hdr->ivLen == 0u)) {
        ret = WOLFCOSE_E_COSE_BAD_HDR;
    }

    /* Validate nonce length matches algorithm spec */
    if (ret == WOLFCOSE_SUCCESS) {
        size_t expectedNonceLen;
        ret = wolfCose_AeadNonceLen(alg, &expectedNonceLen);
        if (ret == WOLFCOSE_SUCCESS && hdr->ivLen != expectedNonceLen) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
        }
    }

    /* Build Enc_structure as AAD */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_BuildEncStructure0(protectedData, protectedLen,
                                          extAad, extAadLen,
                                          scratch, scratchSz, &encStructLen);
    }

    /* Dispatch decryption by algorithm */
#ifdef HAVE_AESGCM
    if (ret == WOLFCOSE_SUCCESS &&
        (alg == WOLFCOSE_ALG_A128GCM || alg == WOLFCOSE_ALG_A192GCM ||
         alg == WOLFCOSE_ALG_A256GCM)) {
        ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            aesInited = 1;
            ret = wc_AesGcmSetKey(&aes, key->key.symm.key, (word32)aeadKeyLen);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_AesGcmDecrypt(&aes,
                plaintext,
                ciphertext, (word32)payloadSz,
                hdr->iv, (word32)hdr->ivLen,
                ciphertext + payloadSz, (word32)aeadTagLen,
                scratch, (word32)encStructLen);
            if (ret != 0) {
                ret = WOLFCOSE_E_COSE_DECRYPT_FAIL;
            }
        }
    }
    else
#endif /* HAVE_AESGCM */
#ifdef HAVE_AESCCM
    if (ret == WOLFCOSE_SUCCESS &&
        (alg == WOLFCOSE_ALG_AES_CCM_16_64_128  ||
         alg == WOLFCOSE_ALG_AES_CCM_16_64_256  ||
         alg == WOLFCOSE_ALG_AES_CCM_64_64_128  ||
         alg == WOLFCOSE_ALG_AES_CCM_64_64_256  ||
         alg == WOLFCOSE_ALG_AES_CCM_16_128_128 ||
         alg == WOLFCOSE_ALG_AES_CCM_16_128_256 ||
         alg == WOLFCOSE_ALG_AES_CCM_64_128_128 ||
         alg == WOLFCOSE_ALG_AES_CCM_64_128_256)) {
        ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            aesInited = 1;
            ret = wc_AesCcmSetKey(&aes, key->key.symm.key, (word32)aeadKeyLen);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_AesCcmDecrypt(&aes,
                plaintext,
                ciphertext, (word32)payloadSz,
                hdr->iv, (word32)hdr->ivLen,
                ciphertext + payloadSz, (word32)aeadTagLen,
                scratch, (word32)encStructLen);
            if (ret != 0) {
                ret = WOLFCOSE_E_COSE_DECRYPT_FAIL;
            }
        }
    }
    else
#endif /* HAVE_AESCCM */
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    if (ret == WOLFCOSE_SUCCESS && alg == WOLFCOSE_ALG_CHACHA20_POLY1305) {
        ret = wc_ChaCha20Poly1305_Decrypt(
            key->key.symm.key, hdr->iv,
            scratch, (word32)encStructLen,
            ciphertext, (word32)payloadSz,
            ciphertext + payloadSz,
            plaintext);
        if (ret != 0) {
            ret = WOLFCOSE_E_COSE_DECRYPT_FAIL;
        }
    }
    else
#endif /* HAVE_CHACHA && HAVE_POLY1305 */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }

    if (ret == WOLFCOSE_SUCCESS) {
        *plaintextLen = payloadSz;
    }

    /* Cleanup: always executed */
#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
    if (aesInited != 0) {
        wc_AesFree(&aes);
    }
#endif
    if (scratch != NULL) {
        wc_ForceZero(scratch, scratchSz);
    }
    /* Zero plaintext on failure to prevent unauthenticated data leak */
    if (ret != WOLFCOSE_SUCCESS && plaintext != NULL) {
        wc_ForceZero(plaintext, plaintextSz);
    }

    return ret;
}
#endif /* WOLFCOSE_ENCRYPT0_DECRYPT */

#endif /* WOLFCOSE_ENCRYPT0 && (HAVE_AESGCM || HAVE_AESCCM || (HAVE_CHACHA && HAVE_POLY1305)) */

/* -----
 * COSE_Mac0 API (RFC 9052 Section 6.2)
 * Supports HMAC (RFC 9053 Section 3.1) and AES-CBC-MAC (RFC 9053 Section 3.2)
 * ----- */

#if defined(WOLFCOSE_MAC0) && (!defined(NO_HMAC) || defined(HAVE_AES_CBC))

/**
 * Build the MAC_structure for COSE_Mac0 (wrapper for unified builder):
 *   ["MAC0", body_protected, external_aad, payload]
 */
static int wolfCose_BuildMacStructure(const uint8_t* protectedHdr,
                                       size_t protectedLen,
                                       const uint8_t* extAad,
                                       size_t extAadLen,
                                       const uint8_t* payload,
                                       size_t payloadLen,
                                       uint8_t* scratch, size_t scratchSz,
                                       size_t* structLen)
{
    /* Use unified builder with "MAC0" context, no sign_protected */
    return wolfCose_BuildToBeSignedMaced(
        "MAC0", 4,
        protectedHdr, protectedLen,
        NULL, 0,  /* no sign_protected for Mac0 */
        extAad, extAadLen,
        payload, payloadLen,
        scratch, scratchSz, structLen);
}

/**
 * Get MAC tag size for a COSE MAC algorithm (HMAC or AES-CBC-MAC).
 */
static int wolfCose_MacTagSize(int32_t alg, size_t* tagSz)
{
    int ret = WOLFCOSE_SUCCESS;

    if (tagSz == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        switch (alg) {
#ifndef NO_HMAC
            case WOLFCOSE_ALG_HMAC_256_256:
                *tagSz = 32; /* SHA-256 output */
                break;
#ifdef WOLFSSL_SHA384
            case WOLFCOSE_ALG_HMAC_384_384:
                *tagSz = 48; /* SHA-384 output */
                break;
#endif
#ifdef WOLFSSL_SHA512
            case WOLFCOSE_ALG_HMAC_512_512:
                *tagSz = 64; /* SHA-512 output */
                break;
#endif
#endif /* !NO_HMAC */
#ifdef HAVE_AES_CBC
            case WOLFCOSE_ALG_AES_MAC_128_64:
            case WOLFCOSE_ALG_AES_MAC_256_64:
                *tagSz = 8; /* 64-bit tag */
                break;
            case WOLFCOSE_ALG_AES_MAC_128_128:
            case WOLFCOSE_ALG_AES_MAC_256_128:
                *tagSz = 16; /* 128-bit tag */
                break;
#endif
            default:
                ret = WOLFCOSE_E_COSE_BAD_ALG;
                break;
        }
    }
    return ret;
}

#ifdef HAVE_AES_CBC
/**
 * Get AES key size in bytes for AES-CBC-MAC algorithm.
 */
static int wolfCose_AesCbcMacKeySize(int32_t alg, size_t* keySz)
{
    int ret = WOLFCOSE_SUCCESS;

    if (keySz == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        switch (alg) {
            case WOLFCOSE_ALG_AES_MAC_128_64:
            case WOLFCOSE_ALG_AES_MAC_128_128:
                *keySz = 16; /* AES-128 */
                break;
            case WOLFCOSE_ALG_AES_MAC_256_64:
            case WOLFCOSE_ALG_AES_MAC_256_128:
                *keySz = 32; /* AES-256 */
                break;
            default:
                ret = WOLFCOSE_E_COSE_BAD_ALG;
                break;
        }
    }
    return ret;
}

/**
 * Compute AES-CBC-MAC (RFC 9053 Section 3.2).
 *
 * AES-CBC-MAC uses AES in CBC mode with a zero IV. The final ciphertext
 * block is the MAC tag, truncated to the specified size.
 *
 * Implementation note: Uses wc_AesCbcEncrypt for portability. We process
 * one block at a time to extract the final ciphertext block as the MAC.
 */
static int wolfCose_AesCbcMac(const uint8_t* key, size_t keyLen,
                               const uint8_t* data, size_t dataLen,
                               uint8_t* tag, size_t tagLen)
{
    int ret = WOLFCOSE_SUCCESS;
    Aes aes;
    int aesInited = 0;
    uint8_t iv[AES_BLOCK_SIZE];
    uint8_t inBlock[AES_BLOCK_SIZE];
    uint8_t outBlock[AES_BLOCK_SIZE];
    size_t numBlocks = 0;
    size_t lastBlockLen = 0;
    size_t i;

    /* Parameter validation */
    if (key == NULL || tag == NULL || tagLen > AES_BLOCK_SIZE) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    /* Initialize with zero IV per RFC 9053 */
    if (ret == WOLFCOSE_SUCCESS) {
        XMEMSET(iv, 0, sizeof(iv));
        XMEMSET(outBlock, 0, sizeof(outBlock));

        int aesRet = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (aesRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }
        else {
            aesInited = 1;
        }
    }

    /* Process full blocks */
    if (ret == WOLFCOSE_SUCCESS) {
        numBlocks = dataLen / AES_BLOCK_SIZE;
        lastBlockLen = dataLen % AES_BLOCK_SIZE;

        for (i = 0; ret == WOLFCOSE_SUCCESS && i < numBlocks; i++) {
            /* Set key and IV for each block (IV is previous ciphertext block) */
            int aesRet = wc_AesSetKey(&aes, key, (word32)keyLen, iv,
                                       AES_ENCRYPTION);
            if (aesRet != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }

            /* Encrypt this block - CBC mode XORs with IV internally */
            if (ret == WOLFCOSE_SUCCESS) {
                aesRet = wc_AesCbcEncrypt(&aes, outBlock,
                                           &data[i * AES_BLOCK_SIZE],
                                           AES_BLOCK_SIZE);
                if (aesRet != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
            }

            /* Use output as next IV */
            if (ret == WOLFCOSE_SUCCESS) {
                XMEMCPY(iv, outBlock, AES_BLOCK_SIZE);
            }
        }
    }

    /* Process last partial block with zero padding */
    if (ret == WOLFCOSE_SUCCESS && (lastBlockLen > 0 || dataLen == 0)) {
        /* Pad with zeros */
        XMEMSET(inBlock, 0, sizeof(inBlock));
        for (i = 0; i < lastBlockLen; i++) {
            inBlock[i] = data[numBlocks * AES_BLOCK_SIZE + i];
        }

        /* Set key and IV */
        int aesRet = wc_AesSetKey(&aes, key, (word32)keyLen, iv, AES_ENCRYPTION);
        if (aesRet != 0) {
            ret = WOLFCOSE_E_CRYPTO;
        }

        /* Encrypt final block */
        if (ret == WOLFCOSE_SUCCESS) {
            aesRet = wc_AesCbcEncrypt(&aes, outBlock, inBlock, AES_BLOCK_SIZE);
            if (aesRet != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
    }

    /* Copy truncated tag on success */
    if (ret == WOLFCOSE_SUCCESS) {
        XMEMCPY(tag, outBlock, tagLen);
    }

    /* Cleanup: always executed */
    if (aesInited != 0) {
        wc_AesFree(&aes);
    }
    wc_ForceZero(inBlock, sizeof(inBlock));
    wc_ForceZero(outBlock, sizeof(outBlock));
    wc_ForceZero(iv, sizeof(iv));

    return ret;
}
#endif /* HAVE_AES_CBC */

/**
 * Check if algorithm is HMAC-based.
 */
static int wolfCose_IsHmacAlg(int32_t alg)
{
    return (alg == WOLFCOSE_ALG_HMAC_256_256
#ifdef WOLFSSL_SHA384
         || alg == WOLFCOSE_ALG_HMAC_384_384
#endif
#ifdef WOLFSSL_SHA512
         || alg == WOLFCOSE_ALG_HMAC_512_512
#endif
    );
}

/**
 * Check if algorithm is AES-CBC-MAC based.
 */
static int wolfCose_IsAesCbcMacAlg(int32_t alg)
{
    return (alg == WOLFCOSE_ALG_AES_MAC_128_64 ||
            alg == WOLFCOSE_ALG_AES_MAC_256_64 ||
            alg == WOLFCOSE_ALG_AES_MAC_128_128 ||
            alg == WOLFCOSE_ALG_AES_MAC_256_128);
}

#if defined(WOLFCOSE_MAC0_CREATE)
int wc_CoseMac0_Create(WOLFCOSE_KEY* key, int32_t alg,
    const uint8_t* kid, size_t kidLen,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen)
{
    int ret = WOLFCOSE_SUCCESS;
#ifndef NO_HMAC
    Hmac hmac;
    int hmacInited = 0;
    int hmacType = 0;
#endif
    uint8_t protectedBuf[WOLFCOSE_PROTECTED_HDR_MAX];
    size_t protectedLen = 0;
    size_t macStructLen = 0;
    size_t tagSz = 0;
    uint8_t tagBuf[WC_MAX_DIGEST_SIZE];
    WOLFCOSE_CBOR_CTX outCtx;
    const uint8_t* macPayload;
    size_t macPayloadLen;
    int isDetached;
    size_t unprotectedEntries;

    /* Determine which payload to use for MAC */
    if (detachedPayload != NULL) {
        macPayload = detachedPayload;
        macPayloadLen = detachedLen;
        isDetached = 1;
    }
    else {
        macPayload = payload;
        macPayloadLen = payloadLen;
        isDetached = 0;
    }

    if (key == NULL || macPayload == NULL || scratch == NULL ||
        out == NULL || outLen == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    if (ret == WOLFCOSE_SUCCESS && key->kty != WOLFCOSE_KTY_SYMMETRIC) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }

    /* Get tag size for this algorithm (works for both HMAC and AES-CBC-MAC) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_MacTagSize(alg, &tagSz);
    }

    /* Encode protected headers: {1: alg} */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_EncodeProtectedHdr(alg, protectedBuf,
                                           sizeof(protectedBuf), &protectedLen);
    }

    /* Build MAC_structure in scratch using appropriate payload */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_BuildMacStructure(protectedBuf, protectedLen,
                                          extAad, extAadLen,
                                          macPayload, macPayloadLen,
                                          scratch, scratchSz, &macStructLen);
    }

    /* Compute MAC based on algorithm type */
#ifndef NO_HMAC
    if (ret == WOLFCOSE_SUCCESS && wolfCose_IsHmacAlg(alg) != 0) {
        ret = wolfCose_HmacType(alg, &hmacType);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
            else {
                hmacInited = 1;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_HmacSetKey(&hmac, hmacType, key->key.symm.key,
                                 (word32)key->key.symm.keyLen);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_HmacUpdate(&hmac, scratch, (word32)macStructLen);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_HmacFinal(&hmac, tagBuf);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
    }
    else
#endif /* !NO_HMAC */
#ifdef HAVE_AES_CBC
    if (ret == WOLFCOSE_SUCCESS && wolfCose_IsAesCbcMacAlg(alg) != 0) {
        size_t expectedKeyLen = 0;
        ret = wolfCose_AesCbcMacKeySize(alg, &expectedKeyLen);
        if (ret == WOLFCOSE_SUCCESS && key->key.symm.keyLen != expectedKeyLen) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_AesCbcMac(key->key.symm.key, key->key.symm.keyLen,
                                      scratch, macStructLen,
                                      tagBuf, tagSz);
        }
    }
    else
#endif /* HAVE_AES_CBC */
    if (ret == WOLFCOSE_SUCCESS) {
        /* Unknown algorithm */
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }

    /* Encode COSE_Mac0 output:
     * Tag(17) [protected_bstr, unprotected_map, payload_bstr, tag_bstr]
     */
    if (ret == WOLFCOSE_SUCCESS) {
        outCtx.buf = out;
        outCtx.bufSz = outSz;
        outCtx.idx = 0;
        ret = wc_CBOR_EncodeTag(&outCtx, WOLFCOSE_TAG_MAC0);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeArrayStart(&outCtx, 4);
    }

    /* protected headers as bstr */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&outCtx, protectedBuf, protectedLen);
    }

    /* unprotected headers map (with kid if present) */
    if (ret == WOLFCOSE_SUCCESS) {
        unprotectedEntries = (kid != NULL && kidLen > 0u) ? 1u : 0u;
        ret = wc_CBOR_EncodeMapStart(&outCtx, unprotectedEntries);
    }
    if (ret == WOLFCOSE_SUCCESS && kid != NULL && kidLen > 0u) {
        ret = wc_CBOR_EncodeUint(&outCtx, (uint64_t)WOLFCOSE_HDR_KID);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(&outCtx, kid, kidLen);
        }
    }

    /* payload (RFC 9052 Section 2: nil if detached) */
    if (ret == WOLFCOSE_SUCCESS) {
        if (isDetached != 0) {
            ret = wc_CBOR_EncodeNull(&outCtx);
        }
        else {
            ret = wc_CBOR_EncodeBstr(&outCtx, payload, payloadLen);
        }
    }

    /* tag (MAC) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&outCtx, tagBuf, tagSz);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        *outLen = outCtx.idx;
    }

    /* Cleanup: always executed */
#ifndef NO_HMAC
    if (hmacInited != 0) {
        wc_HmacFree(&hmac);
    }
#endif
    wc_ForceZero(tagBuf, sizeof(tagBuf));
    wc_ForceZero(scratch, scratchSz);

    return ret;
}
#endif /* WOLFCOSE_MAC0_CREATE */

#if defined(WOLFCOSE_MAC0_VERIFY)
int wc_CoseMac0_Verify(WOLFCOSE_KEY* key,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    const uint8_t** payload, size_t* payloadLen)
{
    int ret = WOLFCOSE_SUCCESS;
#ifndef NO_HMAC
    Hmac hmac;
    int hmacInited = 0;
    int hmacType = 0;
#endif
    WOLFCOSE_CBOR_CTX ctx;
    uint64_t tag;
    size_t arrayCount = 0;
    const uint8_t* protectedData = NULL;
    size_t protectedLen = 0;
    const uint8_t* payloadData = NULL;
    size_t payloadDataLen = 0;
    const uint8_t* macTag = NULL;
    size_t macTagLen = 0;
    size_t macStructLen = 0;
    size_t expectedTagSz = 0;
    uint8_t computedTag[WC_MAX_DIGEST_SIZE];
    int32_t alg = 0;
    const uint8_t* verifyPayload = NULL;
    size_t verifyPayloadLen = 0;
    int isDetached = 0;

    if (key == NULL || in == NULL || scratch == NULL || hdr == NULL ||
        payload == NULL || payloadLen == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    if (ret == WOLFCOSE_SUCCESS && key->kty != WOLFCOSE_KTY_SYMMETRIC) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
    }

    if (ret == WOLFCOSE_SUCCESS) {
        XMEMSET(hdr, 0, sizeof(WOLFCOSE_HDR));

        ctx.buf = (uint8_t*)(uintptr_t)in; /* MISRA Rule 11.8 deviation */
        ctx.bufSz = inSz;
        ctx.idx = 0;

        /* Optional Tag(17) */
        if (ctx.idx < ctx.bufSz &&
            wc_CBOR_PeekType(&ctx) == WOLFCOSE_CBOR_TAG) {
            ret = wc_CBOR_DecodeTag(&ctx, &tag);
            if (ret == WOLFCOSE_SUCCESS && tag != WOLFCOSE_TAG_MAC0) {
                ret = WOLFCOSE_E_COSE_BAD_TAG;
            }
        }
    }

    /* Array of 4 elements */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeArrayStart(&ctx, &arrayCount);
        if (ret == WOLFCOSE_SUCCESS && arrayCount != 4u) {
            ret = WOLFCOSE_E_CBOR_MALFORMED;
        }
    }

    /* 1. Protected headers (bstr) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeBstr(&ctx, &protectedData, &protectedLen);
    }

    /* Parse protected headers */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_DecodeProtectedHdr(protectedData, protectedLen, hdr);
    }

    /* 2. Unprotected headers (map) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_DecodeUnprotectedHdr(&ctx, hdr);
    }

    /* 3. Payload (bstr or null if detached) */
    if (ret == WOLFCOSE_SUCCESS) {
        if (ctx.idx < ctx.bufSz && ctx.buf[ctx.idx] == WOLFCOSE_CBOR_NULL) {
            /* Payload is null - detached mode (RFC 9052 Section 2) */
            ctx.idx++; /* consume the null byte */
            payloadData = NULL;
            payloadDataLen = 0;
            isDetached = 1;
            hdr->flags |= WOLFCOSE_HDR_FLAG_DETACHED;

            /* Must have detached payload provided */
            if (detachedPayload == NULL) {
                ret = WOLFCOSE_E_DETACHED_PAYLOAD;
            }
            else {
                verifyPayload = detachedPayload;
                verifyPayloadLen = detachedLen;
            }
        }
        else {
            ret = wc_CBOR_DecodeBstr(&ctx, &payloadData, &payloadDataLen);
            if (ret == WOLFCOSE_SUCCESS) {
                isDetached = 0;
                verifyPayload = payloadData;
                verifyPayloadLen = payloadDataLen;
            }
        }
    }

    /* 4. Tag (bstr) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_DecodeBstr(&ctx, &macTag, &macTagLen);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        alg = hdr->alg;
        /* Get expected tag size for this algorithm */
        ret = wolfCose_MacTagSize(alg, &expectedTagSz);
    }

    if (ret == WOLFCOSE_SUCCESS && macTagLen != expectedTagSz) {
        ret = WOLFCOSE_E_MAC_FAIL;
    }

    /* Rebuild MAC_structure in scratch using appropriate payload */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_BuildMacStructure(protectedData, protectedLen,
                                          extAad, extAadLen,
                                          verifyPayload, verifyPayloadLen,
                                          scratch, scratchSz, &macStructLen);
    }

    (void)isDetached; /* May be used in future for additional checks */

    /* Compute MAC based on algorithm type */
#ifndef NO_HMAC
    if (ret == WOLFCOSE_SUCCESS && wolfCose_IsHmacAlg(alg) != 0) {
        ret = wolfCose_HmacType(alg, &hmacType);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
            else {
                hmacInited = 1;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_HmacSetKey(&hmac, hmacType, key->key.symm.key,
                                 (word32)key->key.symm.keyLen);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_HmacUpdate(&hmac, scratch, (word32)macStructLen);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_HmacFinal(&hmac, computedTag);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }
    }
    else
#endif /* !NO_HMAC */
#ifdef HAVE_AES_CBC
    if (ret == WOLFCOSE_SUCCESS && wolfCose_IsAesCbcMacAlg(alg) != 0) {
        size_t expectedKeyLen = 0;
        ret = wolfCose_AesCbcMacKeySize(alg, &expectedKeyLen);
        if (ret == WOLFCOSE_SUCCESS && key->key.symm.keyLen != expectedKeyLen) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_AesCbcMac(key->key.symm.key, key->key.symm.keyLen,
                                      scratch, macStructLen,
                                      computedTag, expectedTagSz);
        }
    }
    else
#endif /* HAVE_AES_CBC */
    if (ret == WOLFCOSE_SUCCESS) {
        /* Unknown algorithm */
        ret = WOLFCOSE_E_COSE_BAD_ALG;
    }

    /* Constant-time comparison */
    if (ret == WOLFCOSE_SUCCESS) {
        if (wolfCose_ConstantCompare(computedTag, macTag, (int)expectedTagSz) != 0) {
            ret = WOLFCOSE_E_MAC_FAIL;
        }
    }

    /* Return zero-copy payload pointer into input buffer */
    if (ret == WOLFCOSE_SUCCESS) {
        *payload = payloadData;
        *payloadLen = payloadDataLen;
    }

    /* Cleanup: always executed */
#ifndef NO_HMAC
    if (hmacInited != 0) {
        wc_HmacFree(&hmac);
    }
#endif
    wc_ForceZero(computedTag, sizeof(computedTag));
    wc_ForceZero(scratch, scratchSz);

    return ret;
}
#endif /* WOLFCOSE_MAC0_VERIFY */

#endif /* WOLFCOSE_MAC0 && (!NO_HMAC || HAVE_AES_CBC) */

/* ----- COSE_Encrypt Multi-Recipient API (RFC 9052 Section 5.1) ----- */

#if defined(WOLFCOSE_ENCRYPT) && defined(HAVE_AESGCM)

/**
 * Build the Enc_structure for COSE_Encrypt (context = "Encrypt"):
 *   ["Encrypt", body_protected, external_aad]
 */
static int wolfCose_BuildEncStructureMulti(const uint8_t* protectedHdr,
                                            size_t protectedLen,
                                            const uint8_t* extAad,
                                            size_t extAadLen,
                                            uint8_t* scratch, size_t scratchSz,
                                            size_t* structLen)
{
    static const char context[] = "Encrypt";
    return wolfCose_BuildEncStructure(context, sizeof(context) - 1u,
                                       protectedHdr, protectedLen,
                                       extAad, extAadLen,
                                       scratch, scratchSz, structLen);
}

#if defined(WOLFCOSE_ENCRYPT_ENCRYPT)
/**
 * wc_CoseEncrypt_Encrypt - Create a COSE_Encrypt message (RFC 9052 Section 5.1)
 *
 * Structure: [Headers, ciphertext, recipients: [+ COSE_recipient]]
 * Each COSE_recipient: [Headers, wrapped_cek]
 *
 * For simplicity, this implementation uses direct key (no key wrap):
 * - The content encryption key (CEK) is pre-shared or derived externally
 * - Recipients array contains header-only entries with no wrapped key
 */
int wc_CoseEncrypt_Encrypt(const WOLFCOSE_RECIPIENT* recipients,
    size_t recipientCount,
    int32_t contentAlgId,
    const uint8_t* iv, size_t ivLen,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen,
    WC_RNG* rng)
{
    int ret = WOLFCOSE_SUCCESS;
    WOLFCOSE_CBOR_CTX ctx;
    uint8_t protectedBuf[WOLFCOSE_PROTECTED_HDR_MAX];
    size_t protectedLen = 0;
    uint8_t recipientProtectedBuf[WOLFCOSE_PROTECTED_HDR_MAX];
    size_t recipientProtectedLen = 0;
    size_t encStructLen = 0;
    Aes aes;
    int aesInited = 0;
    size_t keyLen;
    size_t ciphertextLen;
    const uint8_t* encryptPayload;
    size_t encryptPayloadLen;
    size_t i;
    const uint8_t* encKey;
#if defined(WOLFCOSE_ECDH_ES_DIRECT) && defined(HAVE_ECC) && defined(HAVE_HKDF)
    uint8_t cek[32];           /* Derived CEK for ECDH-ES (max 256-bit) */
    uint8_t ephemPubX[66];     /* Max for P-521 */
    uint8_t ephemPubY[66];
    size_t ephemPubLen = 0;
    int useEcdhEs = 0;
    int recipientCrv = 0;
#endif
#if defined(WOLFCOSE_KEY_WRAP)
    uint8_t cekKeyWrap[32];    /* Random CEK for key wrap (max 256-bit) */
    uint8_t wrappedCek[40];    /* Wrapped CEK (CEK + 8 bytes for wrap) */
    size_t wrappedCekLen = 0;
    int useKeyWrap = 0;
#endif

    (void)aesInited;  /* Set but not read - AES freed inline */

    /* Parameter validation */
    if (recipients == NULL || recipientCount == 0u ||
        out == NULL || outLen == NULL || scratch == NULL ||
        iv == NULL || ivLen == 0u) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    /* Must have either payload or detached */
    if (ret == WOLFCOSE_SUCCESS && payload == NULL && detachedPayload == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }

    /* Get the payload to encrypt */
    if (ret == WOLFCOSE_SUCCESS) {
        if (detachedPayload != NULL) {
            encryptPayload = detachedPayload;
            encryptPayloadLen = detachedLen;
        } else {
            encryptPayload = payload;
            encryptPayloadLen = payloadLen;
        }
    }

    /* Get key length for algorithm */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_AeadKeyLen(contentAlgId, &keyLen);
    }

    /* Validate first recipient and determine key mode */
#if defined(WOLFCOSE_ECDH_ES_DIRECT) && defined(HAVE_ECC) && defined(HAVE_HKDF)
    if (ret == WOLFCOSE_SUCCESS && wolfCose_IsEcdhEsDirectAlg(recipients[0].algId)) {
        /* ECDH-ES: recipient key is EC2 public key */
        if (recipients[0].key == NULL ||
            recipients[0].key->kty != WOLFCOSE_KTY_EC2 ||
            recipients[0].key->key.ecc == NULL) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        else if (rng == NULL) {
            ret = WOLFCOSE_E_INVALID_ARG;
        }
        else {
            recipientCrv = recipients[0].key->crv;

            /* Derive CEK from ephemeral-static ECDH */
            ret = wolfCose_EcdhEsDirect(
                recipients[0].algId,
                recipients[0].key,
                contentAlgId,
                keyLen,
                ephemPubX, ephemPubY,
                sizeof(ephemPubX), &ephemPubLen,
                cek, sizeof(cek),
                rng);
            if (ret == WOLFCOSE_SUCCESS) {
                useEcdhEs = 1;
                encKey = cek;
            }
        }
    }
    else
#endif
#if defined(WOLFCOSE_KEY_WRAP)
    if (ret == WOLFCOSE_SUCCESS && wolfCose_IsKeyWrapAlg(recipients[0].algId)) {
        /* AES Key Wrap: recipient key is KEK (symmetric) */
        size_t kekLen = 0;

        if (recipients[0].key == NULL ||
            recipients[0].key->kty != WOLFCOSE_KTY_SYMMETRIC) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        else if (rng == NULL) {
            ret = WOLFCOSE_E_INVALID_ARG;
        }
        else {
            /* Verify KEK size matches algorithm */
            ret = wolfCose_KeyWrapKeySize(recipients[0].algId, &kekLen);
        }
        if (ret == WOLFCOSE_SUCCESS &&
            recipients[0].key->key.symm.keyLen != kekLen) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }

        /* Generate random CEK */
        if (ret == WOLFCOSE_SUCCESS) {
            int rngRet = wc_RNG_GenerateBlock(rng, cekKeyWrap, (word32)keyLen);
            if (rngRet != 0) {
                ret = WOLFCOSE_E_CRYPTO;
            }
        }

        /* Wrap CEK with KEK */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wolfCose_KeyWrap(recipients[0].algId, recipients[0].key,
                                    cekKeyWrap, keyLen,
                                    wrappedCek, sizeof(wrappedCek), &wrappedCekLen);
            if (ret == WOLFCOSE_SUCCESS) {
                useKeyWrap = 1;
                encKey = cekKeyWrap;
            }
        }
    }
    else
#endif
    if (ret == WOLFCOSE_SUCCESS) {
        /* Direct key: recipient key is symmetric */
        if (recipients[0].key == NULL ||
            recipients[0].key->kty != WOLFCOSE_KTY_SYMMETRIC ||
            recipients[0].key->key.symm.keyLen != keyLen) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
        }
        else {
            encKey = recipients[0].key->key.symm.key;
        }
        (void)rng;
    }

    /* Encode body protected header: {1: alg} */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_EncodeProtectedHdr(contentAlgId, protectedBuf,
                                           sizeof(protectedBuf), &protectedLen);
    }

    /* Build Enc_structure for AAD */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wolfCose_BuildEncStructureMulti(protectedBuf, protectedLen,
                                               extAad, extAadLen,
                                               scratch, scratchSz, &encStructLen);
    }

    /* Initialize CBOR encoder */
    if (ret == WOLFCOSE_SUCCESS) {
        ctx.buf = out;
        ctx.bufSz = outSz;
        ctx.idx = 0;

        /* Encode COSE_Encrypt tag (96) */
        ret = wc_CBOR_EncodeTag(&ctx, WOLFCOSE_TAG_ENCRYPT);
    }

    /* Start outer array [protected, unprotected, ciphertext, recipients] */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeArrayStart(&ctx, 4u);
    }

    /* [0] protected header bstr */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, protectedBuf, protectedLen);
    }

    /* [1] unprotected header map with IV */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeMapStart(&ctx, 1u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeInt(&ctx, WOLFCOSE_HDR_IV);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, iv, ivLen);
    }

    /* Calculate ciphertext size (plaintext + tag) */
    if (ret == WOLFCOSE_SUCCESS) {
        ciphertextLen = encryptPayloadLen + AES_BLOCK_SIZE;

        /* [2] ciphertext bstr (or null if detached) */
        if (detachedPayload != NULL) {
            /* Detached ciphertext - encode null */
            ret = wc_CBOR_EncodeNull(&ctx);
            /* Note: in detached mode, ciphertext would be stored externally.
             * For simplicity, we don't support detached ciphertext in multi-recipient
             * encryption in this implementation. */
        } else {
            /* Encode ciphertext bstr header, then encrypt in place */
            ret = wolfCose_CBOR_EncodeHead(&ctx, WOLFCOSE_CBOR_BSTR, ciphertextLen);

            /* Ensure we have space for ciphertext */
            if (ret == WOLFCOSE_SUCCESS && ctx.idx + ciphertextLen > ctx.bufSz) {
                ret = WOLFCOSE_E_CBOR_OVERFLOW;
            }

            /* Encrypt: AES-GCM */
            if (ret == WOLFCOSE_SUCCESS) {
                int aesRet = wc_AesInit(&aes, NULL, INVALID_DEVID);
                if (aesRet != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                } else {
                    aesRet = wc_AesGcmSetKey(&aes, encKey, (word32)keyLen);
                    if (aesRet != 0) {
                        ret = WOLFCOSE_E_CRYPTO;
                    } else {
                        /* Encrypt into output buffer */
                        aesRet = wc_AesGcmEncrypt(&aes,
                                        ctx.buf + ctx.idx,          /* ciphertext */
                                        encryptPayload, (word32)encryptPayloadLen,
                                        iv, (word32)ivLen,
                                        ctx.buf + ctx.idx + encryptPayloadLen,  /* tag */
                                        AES_BLOCK_SIZE,
                                        scratch, (word32)encStructLen);  /* AAD */
                        if (aesRet != 0) {
                            ret = WOLFCOSE_E_CRYPTO;
                        }
                    }
                    wc_AesFree(&aes);
                }
            }

            if (ret == WOLFCOSE_SUCCESS) {
                ctx.idx += ciphertextLen;
            }
        }
    }

    /* [3] recipients array */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeArrayStart(&ctx, (uint64_t)recipientCount);
    }

    /* Encode each recipient */
    for (i = 0; ret == WOLFCOSE_SUCCESS && i < recipientCount; i++) {
        /* For direct key agreement, the wrapped CEK is empty */
        /* COSE_recipient = [protected, unprotected, ciphertext] */

        /* Encode recipient protected header */
        if (recipients[i].algId != 0) {
            ret = wolfCose_EncodeProtectedHdr(recipients[i].algId,
                recipientProtectedBuf, sizeof(recipientProtectedBuf),
                &recipientProtectedLen);
        } else {
            /* Direct key - no alg in protected, use empty bstr */
            recipientProtectedLen = 0;
        }

        /* Start recipient array [protected, unprotected, ciphertext] */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeArrayStart(&ctx, 3u);
        }

        /* [0] protected header bstr */
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(&ctx, recipientProtectedBuf, recipientProtectedLen);
        }

        /* [1] unprotected header map */
        if (ret == WOLFCOSE_SUCCESS) {
#if defined(WOLFCOSE_ECDH_ES_DIRECT) && defined(HAVE_ECC) && defined(HAVE_HKDF)
            if (useEcdhEs != 0) {
                /* ECDH-ES: encode ephemeral key (and optionally kid) */
                size_t mapEntries = 1;  /* At least ephemeral key */
                if (recipients[i].kid != NULL && recipients[i].kidLen > 0u) {
                    mapEntries++;
                }
                ret = wc_CBOR_EncodeMapStart(&ctx, mapEntries);
                /* Encode ephemeral key: {-1: COSE_Key} */
                if (ret == WOLFCOSE_SUCCESS) {
                    ret = wc_CBOR_EncodeInt(&ctx, WOLFCOSE_HDR_EPHEMERAL_KEY);
                }
                if (ret == WOLFCOSE_SUCCESS) {
                    ret = wolfCose_EncodeEphemeralKey(&ctx, recipientCrv,
                        ephemPubX, ephemPubLen, ephemPubY, ephemPubLen);
                }
                /* Optionally add kid */
                if (ret == WOLFCOSE_SUCCESS && recipients[i].kid != NULL &&
                    recipients[i].kidLen > 0u) {
                    ret = wc_CBOR_EncodeInt(&ctx, WOLFCOSE_HDR_KID);
                    if (ret == WOLFCOSE_SUCCESS) {
                        ret = wc_CBOR_EncodeBstr(&ctx, recipients[i].kid,
                                                  recipients[i].kidLen);
                    }
                }
            }
            else
#endif
            if (recipients[i].kid != NULL && recipients[i].kidLen > 0u) {
                ret = wc_CBOR_EncodeMapStart(&ctx, 1u);
                if (ret == WOLFCOSE_SUCCESS) {
                    ret = wc_CBOR_EncodeInt(&ctx, WOLFCOSE_HDR_KID);
                }
                if (ret == WOLFCOSE_SUCCESS) {
                    ret = wc_CBOR_EncodeBstr(&ctx, recipients[i].kid,
                                              recipients[i].kidLen);
                }
            } else {
                /* Empty map */
                ret = wc_CBOR_EncodeMapStart(&ctx, 0u);
            }
        }

        /* [2] wrapped CEK (empty for direct key and ECDH-ES, actual for key wrap) */
        if (ret == WOLFCOSE_SUCCESS) {
#if defined(WOLFCOSE_KEY_WRAP)
            if (useKeyWrap != 0) {
                ret = wc_CBOR_EncodeBstr(&ctx, wrappedCek, wrappedCekLen);
            }
            else
#endif
            {
                ret = wc_CBOR_EncodeBstr(&ctx, NULL, 0);
            }
        }
    }

    /* Set output length on success */
    if (ret == WOLFCOSE_SUCCESS) {
        *outLen = ctx.idx;
    }

    /* Cleanup: always scrub CEK material */
#if defined(WOLFCOSE_KEY_WRAP)
    if (useKeyWrap != 0) {
        wc_ForceZero(cekKeyWrap, sizeof(cekKeyWrap));
    }
#endif
#if defined(WOLFCOSE_ECDH_ES_DIRECT) && defined(HAVE_ECC) && defined(HAVE_HKDF)
    if (useEcdhEs != 0) {
        wc_ForceZero(cek, sizeof(cek));
    }
#endif

    return ret;
}
#endif /* WOLFCOSE_ENCRYPT_ENCRYPT */

#if defined(WOLFCOSE_ENCRYPT_DECRYPT)
/**
 * wc_CoseEncrypt_Decrypt - Decrypt a COSE_Encrypt message
 */
int wc_CoseEncrypt_Decrypt(const WOLFCOSE_RECIPIENT* recipient,
    size_t recipientIndex,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedCt, size_t detachedCtLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    uint8_t* plaintext, size_t plaintextSz, size_t* plaintextLen)
{
    int ret;
    WOLFCOSE_CBOR_CTX ctx;
    WOLFCOSE_CBOR_ITEM item;
    uint64_t tag;
    size_t arrayCount;
    const uint8_t* protectedData;
    size_t protectedLen;
    const uint8_t* ciphertext;
    size_t ciphertextLen;
    size_t encStructLen;
    size_t recipientsCount;
    size_t i;
    Aes aes;
    int32_t alg;
    size_t keyLen;
    size_t payloadLen;
    const uint8_t* decKey;
    const uint8_t* recipientProtectedData;
    size_t recipientProtectedLen;
    int32_t recipientAlgId = 0;
#if defined(WOLFCOSE_ECDH_ES_DIRECT) && defined(HAVE_ECC) && defined(HAVE_HKDF)
    uint8_t cek[32];           /* Derived CEK for ECDH-ES (max 256-bit) */
    uint8_t ephemPubX[66];     /* Max for P-521 */
    uint8_t ephemPubY[66];
    size_t ephemPubXLen = 0;
    size_t ephemPubYLen = 0;
    int ephemCrv = 0;
    int useEcdhEs = 0;
#endif
#if defined(WOLFCOSE_KEY_WRAP)
    uint8_t cekKeyWrap[32];    /* Unwrapped CEK for key wrap (max 256-bit) */
    const uint8_t* wrappedCekData = NULL;
    size_t wrappedCekLen = 0;
    size_t unwrappedCekLen = 0;
    int useKeyWrap = 0;
#endif

    /* Parameter validation */
    if (recipient == NULL || in == NULL || inSz == 0u ||
        hdr == NULL || plaintext == NULL || plaintextLen == NULL ||
        scratch == NULL) {
        return WOLFCOSE_E_INVALID_ARG;
    }

    /* Initialize header output */
    memset(hdr, 0, sizeof(*hdr));

    /* Initialize CBOR decoder */
    ctx.buf = (uint8_t*)in;
    ctx.bufSz = inSz;
    ctx.idx = 0;

    /* Decode and verify tag (96 = COSE_Encrypt) */
    ret = wc_CBOR_DecodeTag(&ctx, &tag);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }
    if (tag != WOLFCOSE_TAG_ENCRYPT) {
        return WOLFCOSE_E_CBOR_TYPE;
    }

    /* Decode outer array - must be 4 elements */
    ret = wc_CBOR_DecodeArrayStart(&ctx, &arrayCount);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }
    if (arrayCount != 4u) {
        return WOLFCOSE_E_CBOR_TYPE;
    }

    /* [0] Decode protected header bstr */
    ret = wc_CBOR_DecodeBstr(&ctx, &protectedData, &protectedLen);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }

    /* Parse protected header to get algorithm */
    ret = wolfCose_DecodeProtectedHdr(protectedData, protectedLen, hdr);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }
    alg = hdr->alg;

    /* [1] Decode unprotected header (get IV) */
    ret = wolfCose_DecodeUnprotectedHdr(&ctx, hdr);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }

    /* [2] Decode ciphertext bstr */
    ret = wolfCose_CBOR_DecodeHead(&ctx, &item);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }

    if (item.majorType == WOLFCOSE_CBOR_SIMPLE && item.val == 22u) {
        /* Null - detached ciphertext */
        if (detachedCt == NULL) {
            hdr->flags |= WOLFCOSE_HDR_FLAG_DETACHED;
            return WOLFCOSE_E_DETACHED_PAYLOAD;
        }
        ciphertext = detachedCt;
        ciphertextLen = detachedCtLen;
        hdr->flags |= WOLFCOSE_HDR_FLAG_DETACHED;
    } else if (item.majorType == WOLFCOSE_CBOR_BSTR) {
        ciphertext = item.data;
        ciphertextLen = item.dataLen;
    } else {
        return WOLFCOSE_E_CBOR_TYPE;
    }

    /* [3] Decode recipients array */
    ret = wc_CBOR_DecodeArrayStart(&ctx, &recipientsCount);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }

    /* Validate recipient index */
    if (recipientIndex >= recipientsCount) {
        return WOLFCOSE_E_INVALID_ARG;
    }

    /* Skip to the requested recipient */
    for (i = 0; i < recipientIndex; i++) {
        ret = wc_CBOR_Skip(&ctx);
        if (ret != WOLFCOSE_SUCCESS) {
            return ret;
        }
    }

    /* Parse the recipient we're interested in */
    ret = wc_CBOR_DecodeArrayStart(&ctx, &arrayCount);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }
    if (arrayCount != 3u) {
        return WOLFCOSE_E_CBOR_TYPE;
    }

    /* [0] Decode recipient protected header to get algorithm */
    ret = wc_CBOR_DecodeBstr(&ctx, &recipientProtectedData, &recipientProtectedLen);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }
    if (recipientProtectedLen > 0) {
        WOLFCOSE_HDR recipientHdr;
        memset(&recipientHdr, 0, sizeof(recipientHdr));
        ret = wolfCose_DecodeProtectedHdr(recipientProtectedData,
                                           recipientProtectedLen, &recipientHdr);
        if (ret != WOLFCOSE_SUCCESS) {
            return ret;
        }
        recipientAlgId = recipientHdr.alg;
    }

    /* [1] Decode recipient unprotected header */
#if defined(WOLFCOSE_ECDH_ES_DIRECT) && defined(HAVE_ECC) && defined(HAVE_HKDF)
    if (wolfCose_IsEcdhEsDirectAlg(recipientAlgId)) {
        /* ECDH-ES: parse unprotected header to get ephemeral key */
        size_t mapCount;
        size_t j;

        ret = wc_CBOR_DecodeMapStart(&ctx, &mapCount);
        if (ret != WOLFCOSE_SUCCESS) {
            return ret;
        }

        for (j = 0; j < mapCount; j++) {
            int64_t label;
            ret = wc_CBOR_DecodeInt(&ctx, &label);
            if (ret != WOLFCOSE_SUCCESS) {
                return ret;
            }

            if (label == WOLFCOSE_HDR_EPHEMERAL_KEY) {
                /* Decode ephemeral COSE_Key */
                ret = wolfCose_DecodeEphemeralKey(&ctx, &ephemCrv,
                    ephemPubX, sizeof(ephemPubX), &ephemPubXLen,
                    ephemPubY, sizeof(ephemPubY), &ephemPubYLen);
                if (ret != WOLFCOSE_SUCCESS) {
                    return ret;
                }
            }
            else {
                /* Skip other header entries */
                ret = wc_CBOR_Skip(&ctx);
                if (ret != WOLFCOSE_SUCCESS) {
                    return ret;
                }
            }
        }

        /* Verify we got the ephemeral key */
        if (ephemPubXLen == 0 || ephemPubYLen == 0) {
            return WOLFCOSE_E_COSE_BAD_HDR;
        }
        useEcdhEs = 1;
    }
    else
#endif
    {
        /* Non-ECDH: skip unprotected header */
        ret = wc_CBOR_Skip(&ctx);
        if (ret != WOLFCOSE_SUCCESS) {
            return ret;
        }
    }

    /* [2] Decode wrapped CEK (read for key wrap, skip for direct/ECDH-ES) */
#if defined(WOLFCOSE_KEY_WRAP)
    if (wolfCose_IsKeyWrapAlg(recipientAlgId)) {
        ret = wc_CBOR_DecodeBstr(&ctx, &wrappedCekData, &wrappedCekLen);
        if (ret != WOLFCOSE_SUCCESS) {
            return ret;
        }
        if (wrappedCekLen < 24u) {
            /* Minimum: 16-byte CEK + 8-byte wrap overhead */
            return WOLFCOSE_E_CBOR_MALFORMED;
        }
        useKeyWrap = 1;
    }
    else
#endif
    {
        ret = wc_CBOR_Skip(&ctx);
        if (ret != WOLFCOSE_SUCCESS) {
            return ret;
        }
    }

    /* Get key length for algorithm */
    ret = wolfCose_AeadKeyLen(alg, &keyLen);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }

    /* Validate key and derive CEK if needed */
#if defined(WOLFCOSE_ECDH_ES_DIRECT) && defined(HAVE_ECC) && defined(HAVE_HKDF)
    if (useEcdhEs) {
        /* ECDH-ES: recipient key must be EC2 with private key */
        if (recipient->key == NULL ||
            recipient->key->kty != WOLFCOSE_KTY_EC2 ||
            recipient->key->key.ecc == NULL ||
            recipient->key->hasPrivate != 1u) {
            return WOLFCOSE_E_COSE_KEY_TYPE;
        }

        /* Derive CEK using recipient's private key and sender's ephemeral public */
        ret = wolfCose_EcdhEsDirectRecv(
            recipientAlgId,
            recipient->key,
            ephemPubX, ephemPubY,
            ephemPubXLen,
            alg,
            keyLen,
            cek, sizeof(cek));
        if (ret != WOLFCOSE_SUCCESS) {
            return ret;
        }
        decKey = cek;
    }
    else
#endif
#if defined(WOLFCOSE_KEY_WRAP)
    if (useKeyWrap) {
        /* Key Wrap: recipient key is KEK, unwrap the CEK */
        if (recipient->key == NULL ||
            recipient->key->kty != WOLFCOSE_KTY_SYMMETRIC) {
            return WOLFCOSE_E_COSE_KEY_TYPE;
        }

        /* Unwrap the CEK */
        ret = wolfCose_KeyUnwrap(recipientAlgId, recipient->key,
                                  wrappedCekData, wrappedCekLen,
                                  cekKeyWrap, sizeof(cekKeyWrap), &unwrappedCekLen);
        if (ret != WOLFCOSE_SUCCESS) {
            return ret;
        }

        /* Verify unwrapped CEK length matches expected content key length */
        if (unwrappedCekLen != keyLen) {
            wc_ForceZero(cekKeyWrap, sizeof(cekKeyWrap));
            return WOLFCOSE_E_COSE_KEY_TYPE;
        }

        decKey = cekKeyWrap;
    }
    else
#endif
    {
        /* Direct key: recipient key is symmetric */
        if (recipient->key == NULL ||
            recipient->key->kty != WOLFCOSE_KTY_SYMMETRIC ||
            recipient->key->key.symm.keyLen != keyLen) {
            return WOLFCOSE_E_COSE_KEY_TYPE;
        }
        decKey = recipient->key->key.symm.key;
    }

    /* Must have ciphertext longer than tag */
    if (ciphertextLen <= AES_BLOCK_SIZE) {
        return WOLFCOSE_E_CBOR_TYPE;
    }

    payloadLen = ciphertextLen - AES_BLOCK_SIZE;

    /* Check plaintext buffer size */
    if (payloadLen > plaintextSz) {
        return WOLFCOSE_E_CBOR_OVERFLOW;
    }

    /* Build Enc_structure for AAD */
    ret = wolfCose_BuildEncStructureMulti(protectedData, protectedLen,
                                           extAad, extAadLen,
                                           scratch, scratchSz, &encStructLen);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }

    /* Decrypt: AES-GCM */
    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) {
#if defined(WOLFCOSE_KEY_WRAP)
        if (useKeyWrap) {
            wc_ForceZero(cekKeyWrap, sizeof(cekKeyWrap));
        }
#endif
#if defined(WOLFCOSE_ECDH_ES_DIRECT) && defined(HAVE_ECC) && defined(HAVE_HKDF)
        if (useEcdhEs) {
            wc_ForceZero(cek, sizeof(cek));
        }
#endif
        return WOLFCOSE_E_CRYPTO;
    }

    ret = wc_AesGcmSetKey(&aes, decKey, (word32)keyLen);
    if (ret != 0) {
        wc_AesFree(&aes);
#if defined(WOLFCOSE_KEY_WRAP)
        if (useKeyWrap) {
            wc_ForceZero(cekKeyWrap, sizeof(cekKeyWrap));
        }
#endif
#if defined(WOLFCOSE_ECDH_ES_DIRECT) && defined(HAVE_ECC) && defined(HAVE_HKDF)
        if (useEcdhEs) {
            wc_ForceZero(cek, sizeof(cek));
        }
#endif
        return WOLFCOSE_E_CRYPTO;
    }

    ret = wc_AesGcmDecrypt(&aes,
                            plaintext, ciphertext, (word32)payloadLen,
                            hdr->iv, (word32)hdr->ivLen,
                            ciphertext + payloadLen, AES_BLOCK_SIZE,
                            scratch, (word32)encStructLen);
    wc_AesFree(&aes);

#if defined(WOLFCOSE_KEY_WRAP)
    if (useKeyWrap) {
        wc_ForceZero(cekKeyWrap, sizeof(cekKeyWrap));
    }
#endif
#if defined(WOLFCOSE_ECDH_ES_DIRECT) && defined(HAVE_ECC) && defined(HAVE_HKDF)
    if (useEcdhEs) {
        wc_ForceZero(cek, sizeof(cek));
    }
#endif

    if (ret != 0) {
        return WOLFCOSE_E_COSE_DECRYPT_FAIL;
    }

    *plaintextLen = payloadLen;
    return WOLFCOSE_SUCCESS;
}
#endif /* WOLFCOSE_ENCRYPT_DECRYPT */

#endif /* WOLFCOSE_ENCRYPT && HAVE_AESGCM */

/* ----- COSE_Mac Multi-Recipient API (RFC 9052 Section 6.1) ----- */

#if defined(WOLFCOSE_MAC) && !defined(NO_HMAC)

/**
 * Build the MAC_structure for COSE_Mac (context = "MAC"):
 *   ["MAC", body_protected, external_aad, payload]
 */
static int wolfCose_BuildMacStructureMulti(const uint8_t* protectedHdr,
                                            size_t protectedLen,
                                            const uint8_t* extAad,
                                            size_t extAadLen,
                                            const uint8_t* payload,
                                            size_t payloadLen,
                                            uint8_t* scratch, size_t scratchSz,
                                            size_t* structLen)
{
    static const char context[] = "MAC";
    return wolfCose_BuildToBeSignedMaced(context, sizeof(context) - 1u,
                                          protectedHdr, protectedLen,
                                          NULL, 0,  /* no sign_protected */
                                          extAad, extAadLen,
                                          payload, payloadLen,
                                          scratch, scratchSz, structLen);
}

#if defined(WOLFCOSE_MAC_CREATE)
/**
 * wc_CoseMac_Create - Create a COSE_Mac message (RFC 9052 Section 6.1)
 *
 * Structure: [Headers, payload, tag, recipients: [+ COSE_recipient]]
 *
 * For direct key mode: the MAC key is pre-shared among all recipients.
 */
int wc_CoseMac_Create(const WOLFCOSE_RECIPIENT* recipients,
    size_t recipientCount,
    int32_t macAlgId,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen)
{
    int ret;
    WOLFCOSE_CBOR_CTX ctx;
    uint8_t protectedBuf[WOLFCOSE_PROTECTED_HDR_MAX];
    size_t protectedLen = 0;
    uint8_t recipientProtectedBuf[WOLFCOSE_PROTECTED_HDR_MAX];
    size_t recipientProtectedLen = 0;
    size_t macStructLen = 0;
    uint8_t macTag[WC_MAX_DIGEST_SIZE];
    size_t macTagLen = 0;
    const uint8_t* macPayload;
    size_t macPayloadLen;
    size_t i;
    Hmac hmac;
    int hashType;

    /* Parameter validation */
    if (recipients == NULL || recipientCount == 0u ||
        out == NULL || outLen == NULL || scratch == NULL) {
        return WOLFCOSE_E_INVALID_ARG;
    }

    /* Must have either payload or detached */
    if (payload == NULL && detachedPayload == NULL) {
        return WOLFCOSE_E_INVALID_ARG;
    }

    /* Get the payload to MAC */
    if (detachedPayload != NULL) {
        macPayload = detachedPayload;
        macPayloadLen = detachedLen;
    } else {
        macPayload = payload;
        macPayloadLen = payloadLen;
    }

    /* Validate first recipient has correct key */
    if (recipients[0].key == NULL ||
        recipients[0].key->kty != WOLFCOSE_KTY_SYMMETRIC) {
        return WOLFCOSE_E_COSE_KEY_TYPE;
    }

    /* Get tag size for algorithm */
    ret = wolfCose_MacTagSize(macAlgId, &macTagLen);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }

    /* Map algorithm to HMAC type */
    ret = wolfCose_HmacType(macAlgId, &hashType);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }

    /* Encode body protected header: {1: alg} */
    ret = wolfCose_EncodeProtectedHdr(macAlgId, protectedBuf,
                                       sizeof(protectedBuf), &protectedLen);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }

    /* Build MAC_structure */
    ret = wolfCose_BuildMacStructureMulti(protectedBuf, protectedLen,
                                           extAad, extAadLen,
                                           macPayload, macPayloadLen,
                                           scratch, scratchSz, &macStructLen);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }

    /* Compute HMAC */
    ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (ret != 0) {
        return WOLFCOSE_E_CRYPTO;
    }

    ret = wc_HmacSetKey(&hmac, hashType,
                         recipients[0].key->key.symm.key,
                         (word32)recipients[0].key->key.symm.keyLen);
    if (ret != 0) {
        wc_HmacFree(&hmac);
        return WOLFCOSE_E_CRYPTO;
    }

    ret = wc_HmacUpdate(&hmac, scratch, (word32)macStructLen);
    if (ret != 0) {
        wc_HmacFree(&hmac);
        return WOLFCOSE_E_CRYPTO;
    }

    ret = wc_HmacFinal(&hmac, macTag);
    wc_HmacFree(&hmac);

    if (ret != 0) {
        return WOLFCOSE_E_CRYPTO;
    }

    /* Initialize CBOR encoder */
    ctx.buf = out;
    ctx.bufSz = outSz;
    ctx.idx = 0;

    /* Encode COSE_Mac tag (97) */
    ret = wc_CBOR_EncodeTag(&ctx, WOLFCOSE_TAG_MAC);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }

    /* Start outer array [protected, unprotected, payload, tag, recipients] */
    ret = wc_CBOR_EncodeArrayStart(&ctx, 5u);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }

    /* [0] protected header bstr */
    ret = wc_CBOR_EncodeBstr(&ctx, protectedBuf, protectedLen);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }

    /* [1] unprotected header (empty map) */
    ret = wc_CBOR_EncodeMapStart(&ctx, 0u);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }

    /* [2] payload (or null if detached) */
    if (detachedPayload != NULL) {
        ret = wc_CBOR_EncodeNull(&ctx);
    } else {
        ret = wc_CBOR_EncodeBstr(&ctx, payload, payloadLen);
    }
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }

    /* [3] tag */
    ret = wc_CBOR_EncodeBstr(&ctx, macTag, macTagLen);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }

    /* [4] recipients array */
    ret = wc_CBOR_EncodeArrayStart(&ctx, (uint64_t)recipientCount);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }

    /* Encode each recipient */
    for (i = 0; i < recipientCount; i++) {
        /* COSE_recipient = [protected, unprotected, ciphertext] */

        /* Encode recipient protected header */
        if (recipients[i].algId != 0) {
            ret = wolfCose_EncodeProtectedHdr(recipients[i].algId,
                recipientProtectedBuf, sizeof(recipientProtectedBuf),
                &recipientProtectedLen);
            if (ret != WOLFCOSE_SUCCESS) {
                return ret;
            }
        } else {
            recipientProtectedLen = 0;
        }

        /* Start recipient array [protected, unprotected, ciphertext] */
        ret = wc_CBOR_EncodeArrayStart(&ctx, 3u);
        if (ret != WOLFCOSE_SUCCESS) {
            return ret;
        }

        /* [0] protected header bstr */
        ret = wc_CBOR_EncodeBstr(&ctx, recipientProtectedBuf, recipientProtectedLen);
        if (ret != WOLFCOSE_SUCCESS) {
            return ret;
        }

        /* [1] unprotected header map (with kid if present) */
        if (recipients[i].kid != NULL && recipients[i].kidLen > 0u) {
            ret = wc_CBOR_EncodeMapStart(&ctx, 1u);
            if (ret != WOLFCOSE_SUCCESS) {
                return ret;
            }
            ret = wc_CBOR_EncodeInt(&ctx, WOLFCOSE_HDR_KID);
            if (ret != WOLFCOSE_SUCCESS) {
                return ret;
            }
            ret = wc_CBOR_EncodeBstr(&ctx, recipients[i].kid, recipients[i].kidLen);
            if (ret != WOLFCOSE_SUCCESS) {
                return ret;
            }
        } else {
            ret = wc_CBOR_EncodeMapStart(&ctx, 0u);
            if (ret != WOLFCOSE_SUCCESS) {
                return ret;
            }
        }

        /* [2] wrapped key (empty for direct key) */
        ret = wc_CBOR_EncodeBstr(&ctx, NULL, 0);
        if (ret != WOLFCOSE_SUCCESS) {
            return ret;
        }
    }

    *outLen = ctx.idx;
    wc_ForceZero(macTag, sizeof(macTag));
    return WOLFCOSE_SUCCESS;
}
#endif /* WOLFCOSE_MAC_CREATE */

#if defined(WOLFCOSE_MAC_VERIFY)
/**
 * wc_CoseMac_Verify - Verify a COSE_Mac message
 */
int wc_CoseMac_Verify(const WOLFCOSE_RECIPIENT* recipient,
    size_t recipientIndex,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    const uint8_t** payload, size_t* payloadLen)
{
    int ret;
    WOLFCOSE_CBOR_CTX ctx;
    WOLFCOSE_CBOR_ITEM item;
    uint64_t tag;
    size_t arrayCount;
    const uint8_t* protectedData;
    size_t protectedLen;
    const uint8_t* payloadData;
    size_t payloadDataLen;
    const uint8_t* macTag;
    size_t macTagLen;
    size_t recipientsCount;
    size_t i;
    int32_t alg;
    size_t macStructLen;
    size_t expectedTagLen;
    uint8_t computedTag[WC_MAX_DIGEST_SIZE];
    Hmac hmac;
    int hashType;
    const uint8_t* verifyPayload;
    size_t verifyPayloadLen;

    /* Parameter validation */
    if (recipient == NULL || in == NULL || inSz == 0u ||
        hdr == NULL || payload == NULL || payloadLen == NULL ||
        scratch == NULL) {
        return WOLFCOSE_E_INVALID_ARG;
    }

    /* Initialize header output */
    memset(hdr, 0, sizeof(*hdr));

    /* Initialize CBOR decoder */
    ctx.buf = (uint8_t*)in;
    ctx.bufSz = inSz;
    ctx.idx = 0;

    /* Decode and verify tag (97 = COSE_Mac) */
    ret = wc_CBOR_DecodeTag(&ctx, &tag);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }
    if (tag != WOLFCOSE_TAG_MAC) {
        return WOLFCOSE_E_CBOR_TYPE;
    }

    /* Decode outer array - must be 5 elements */
    ret = wc_CBOR_DecodeArrayStart(&ctx, &arrayCount);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }
    if (arrayCount != 5u) {
        return WOLFCOSE_E_CBOR_TYPE;
    }

    /* [0] Decode protected header bstr */
    ret = wc_CBOR_DecodeBstr(&ctx, &protectedData, &protectedLen);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }

    /* Parse protected header to get algorithm */
    ret = wolfCose_DecodeProtectedHdr(protectedData, protectedLen, hdr);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }
    alg = hdr->alg;

    /* [1] Decode unprotected header */
    ret = wolfCose_DecodeUnprotectedHdr(&ctx, hdr);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }

    /* [2] Decode payload */
    ret = wolfCose_CBOR_DecodeHead(&ctx, &item);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }

    if (item.majorType == WOLFCOSE_CBOR_SIMPLE && item.val == 22u) {
        /* Null - detached payload */
        if (detachedPayload == NULL) {
            hdr->flags |= WOLFCOSE_HDR_FLAG_DETACHED;
            return WOLFCOSE_E_DETACHED_PAYLOAD;
        }
        payloadData = NULL;
        payloadDataLen = 0;
        verifyPayload = detachedPayload;
        verifyPayloadLen = detachedLen;
        hdr->flags |= WOLFCOSE_HDR_FLAG_DETACHED;
    } else if (item.majorType == WOLFCOSE_CBOR_BSTR) {
        payloadData = item.data;
        payloadDataLen = item.dataLen;
        verifyPayload = payloadData;
        verifyPayloadLen = payloadDataLen;
    } else {
        return WOLFCOSE_E_CBOR_TYPE;
    }

    /* [3] Decode tag */
    ret = wc_CBOR_DecodeBstr(&ctx, &macTag, &macTagLen);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }

    /* [4] Decode recipients array */
    ret = wc_CBOR_DecodeArrayStart(&ctx, &recipientsCount);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }

    /* Validate recipient index */
    if (recipientIndex >= recipientsCount) {
        return WOLFCOSE_E_INVALID_ARG;
    }

    /* Skip to the requested recipient */
    for (i = 0; i < recipientIndex; i++) {
        ret = wc_CBOR_Skip(&ctx);
        if (ret != WOLFCOSE_SUCCESS) {
            return ret;
        }
    }

    /* Parse the recipient (skip it - we use the provided key) */
    ret = wc_CBOR_Skip(&ctx);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }

    /* Validate key */
    if (recipient->key == NULL ||
        recipient->key->kty != WOLFCOSE_KTY_SYMMETRIC) {
        return WOLFCOSE_E_COSE_KEY_TYPE;
    }

    /* Get expected tag size */
    ret = wolfCose_MacTagSize(alg, &expectedTagLen);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }

    if (macTagLen != expectedTagLen) {
        return WOLFCOSE_E_MAC_FAIL;
    }

    /* Map algorithm to HMAC type */
    ret = wolfCose_HmacType(alg, &hashType);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }

    /* Build MAC_structure */
    ret = wolfCose_BuildMacStructureMulti(protectedData, protectedLen,
                                           extAad, extAadLen,
                                           verifyPayload, verifyPayloadLen,
                                           scratch, scratchSz, &macStructLen);
    if (ret != WOLFCOSE_SUCCESS) {
        return ret;
    }

    /* Compute HMAC */
    ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (ret != 0) {
        return WOLFCOSE_E_CRYPTO;
    }

    ret = wc_HmacSetKey(&hmac, hashType,
                         recipient->key->key.symm.key,
                         (word32)recipient->key->key.symm.keyLen);
    if (ret != 0) {
        wc_HmacFree(&hmac);
        return WOLFCOSE_E_CRYPTO;
    }

    ret = wc_HmacUpdate(&hmac, scratch, (word32)macStructLen);
    if (ret != 0) {
        wc_HmacFree(&hmac);
        return WOLFCOSE_E_CRYPTO;
    }

    ret = wc_HmacFinal(&hmac, computedTag);
    wc_HmacFree(&hmac);

    if (ret != 0) {
        wc_ForceZero(computedTag, sizeof(computedTag));
        return WOLFCOSE_E_CRYPTO;
    }

    /* Constant-time comparison */
    if (wolfCose_ConstantCompare(computedTag, macTag, (int)expectedTagLen) != 0) {
        wc_ForceZero(computedTag, sizeof(computedTag));
        return WOLFCOSE_E_MAC_FAIL;
    }

    wc_ForceZero(computedTag, sizeof(computedTag));

    /* Return payload pointer */
    *payload = payloadData;
    *payloadLen = payloadDataLen;
    return WOLFCOSE_SUCCESS;
}
#endif /* WOLFCOSE_MAC_VERIFY */

#endif /* WOLFCOSE_MAC && !NO_HMAC */
