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
#if !defined(NO_HMAC)
    #include <wolfssl/wolfcrypt/hmac.h>
#endif
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    #include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#endif
#include <string.h>

/* ---------------------------------------------------------------------------
 * Internal helpers: algorithm dispatch
 * --------------------------------------------------------------------------- */

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

/* ---------------------------------------------------------------------------
 * Internal: AEAD dispatch helpers (AES-GCM, ChaCha20-Poly1305, AES-CCM)
 * --------------------------------------------------------------------------- */

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

/* ---------------------------------------------------------------------------
 * Internal: HMAC helpers
 * --------------------------------------------------------------------------- */

#if !defined(NO_HMAC)
int wolfCose_HmacTagSize(int32_t alg, size_t* tagSz)
{
    int ret = WOLFCOSE_SUCCESS;

    if (tagSz == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
    }
    else {
        switch (alg) {
            case WOLFCOSE_ALG_HMAC256:
                *tagSz = 32;
                break;
#ifdef WOLFSSL_SHA384
            case WOLFCOSE_ALG_HMAC384:
                *tagSz = 48;
                break;
#endif
#ifdef WOLFSSL_SHA512
            case WOLFCOSE_ALG_HMAC512:
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
            case WOLFCOSE_ALG_HMAC256:
                *hmacType = WC_SHA256;
                break;
#ifdef WOLFSSL_SHA384
            case WOLFCOSE_ALG_HMAC384:
                *hmacType = WC_SHA384;
                break;
#endif
#ifdef WOLFSSL_SHA512
            case WOLFCOSE_ALG_HMAC512:
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

/* ---------------------------------------------------------------------------
 * Internal: ECC DER <-> raw r||s conversion
 * --------------------------------------------------------------------------- */

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

/* ---------------------------------------------------------------------------
 * Internal: Protected/Unprotected header encode/decode
 * --------------------------------------------------------------------------- */

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

/* ---------------------------------------------------------------------------
 * COSE Key API
 * --------------------------------------------------------------------------- */

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
        XMEMSET(key, 0, sizeof(WOLFCOSE_KEY));
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
        key->hasPrivate = 1u; /* assume private after make_key */
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

int wc_CoseKey_Encode(WOLFCOSE_KEY* key, uint8_t* out, size_t outSz,
                       size_t* outLen)
{
    int ret;
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
            if (ret != WOLFCOSE_SUCCESS) {
                goto cleanup;
            }

            ret = wc_ecc_export_public_raw(key->key.ecc, xBuf, &xLen,
                                            yBuf, &yLen);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
                goto cleanup;
            }

            /* Map: kty, crv, x, y [, d] */
            mapEntries = key->hasPrivate ? 5u : 4u;
            ret = wc_CBOR_EncodeMapStart(&ctx, mapEntries);

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
            /* RFC 8230: {1:3, -1:n_bstr, -2:e_bstr [, -3:d_bstr]} */
            uint8_t nBuf[512]; /* RSA-4096 modulus max */
            uint8_t eBuf[8];   /* exponent, typically 3 bytes */
            word32 nLen = (word32)sizeof(nBuf);
            word32 eLen = (word32)sizeof(eBuf);
            size_t mapEntries;

            ret = wc_RsaFlattenPublicKey((RsaKey*)key->key.rsa,
                                          eBuf, &eLen, nBuf, &nLen);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
                goto cleanup;
            }

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
            /* -1: n (modulus) */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeInt(&ctx,
                                         (int64_t)WOLFCOSE_KEY_LABEL_CRV);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeBstr(&ctx, nBuf, (size_t)nLen);
            }
            /* -2: e (exponent) */
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeInt(&ctx,
                                         (int64_t)WOLFCOSE_KEY_LABEL_X);
            }
            if (ret == WOLFCOSE_SUCCESS) {
                ret = wc_CBOR_EncodeBstr(&ctx, eBuf, (size_t)eLen);
            }
            /* -3: d (private exponent, optional) */
            if (ret == WOLFCOSE_SUCCESS && key->hasPrivate) {
                uint8_t dBuf[512];
                uint8_t pBuf[256], qBuf[256];
                word32 dSz = (word32)sizeof(dBuf);
                word32 nSz2 = (word32)sizeof(nBuf);
                word32 eSz2 = (word32)sizeof(eBuf);
                word32 pSz = (word32)sizeof(pBuf);
                word32 qSz = (word32)sizeof(qBuf);

                ret = wc_RsaExportKey((RsaKey*)key->key.rsa,
                    eBuf, &eSz2, nBuf, &nSz2,
                    dBuf, &dSz, pBuf, &pSz, qBuf, &qSz);
                if (ret != 0) {
                    ret = WOLFCOSE_E_CRYPTO;
                }
                else {
                    ret = wc_CBOR_EncodeInt(&ctx,
                                             (int64_t)WOLFCOSE_KEY_LABEL_Y);
                    if (ret == WOLFCOSE_SUCCESS) {
                        ret = wc_CBOR_EncodeBstr(&ctx, dBuf, (size_t)dSz);
                    }
                }
                wc_ForceZero(dBuf, sizeof(dBuf));
                wc_ForceZero(pBuf, sizeof(pBuf));
                wc_ForceZero(qBuf, sizeof(qBuf));
            }

            if (ret == WOLFCOSE_SUCCESS) {
                *outLen = ctx.idx;
            }
            wc_ForceZero(nBuf, sizeof(nBuf));
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
            }
            else
#endif
#ifdef HAVE_ED448
            if (key->crv == WOLFCOSE_CRV_ED448) {
                ret = wc_ed448_export_public(key->key.ed448,
                                              pubBuf, &pubLen);
            }
            else
#endif
            {
                ret = WOLFCOSE_E_COSE_BAD_ALG;
                goto cleanup;
            }
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
                goto cleanup;
            }

            mapEntries = key->hasPrivate ? 4u : 3u;
            ret = wc_CBOR_EncodeMapStart(&ctx, mapEntries);

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

    /* MISRA Rule 15.1 deviation: forward goto to single cleanup label */
cleanup: /* used by ECC/Ed25519 error paths above */
    if (ret != WOLFCOSE_SUCCESS && out != NULL) {
        wc_ForceZero(out, outSz);
    }
    return ret;
}

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
                /* -1: crv(uint) for EC2/OKP, k(bstr) for Symmetric,
                 *     n(bstr) for RSA (RFC 8230) */
                if (key->kty == WOLFCOSE_KTY_SYMMETRIC) {
                    ret = wc_CBOR_DecodeBstr(&ctx, &bstrData, &bstrLen);
                    if (ret == WOLFCOSE_SUCCESS) {
                        key->key.symm.key = bstrData;
                        key->key.symm.keyLen = bstrLen;
                        key->hasPrivate = 1;
                    }
                }
                else if (key->kty == WOLFCOSE_KTY_RSA) {
                    /* RSA: -1 is n (modulus), bstr */
                    ret = wc_CBOR_DecodeBstr(&ctx, &nData, &nLen);
                }
                else {
                    /* EC2/OKP: crv is uint (P-256=1, Ed25519=6, etc.)
                     * Dilithium: crv is negint (ML-DSA-44=-48, etc.)
                     * Use DecodeInt to handle both. */
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
                /* Already handled above in the -1 label parsing */
            }
            else {
                /* Unknown key type but we parsed OK -- leave it */
            }
        }
    }

    return ret;
}

/* ---------------------------------------------------------------------------
 * Internal: RSA-PSS hash-to-MGF mapping
 * --------------------------------------------------------------------------- */
#ifdef WC_RSA_PSS
static int wolfCose_HashToMgf(enum wc_HashType hashType, int* mgf)
{
    int ret = WOLFCOSE_SUCCESS;

    if (hashType == WC_HASH_TYPE_SHA256) {
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

/* ---------------------------------------------------------------------------
 * COSE_Sign1 API
 * --------------------------------------------------------------------------- */

/**
 * Build the Sig_structure for COSE_Sign1:
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
    int ret;
    WOLFCOSE_CBOR_CTX ctx;

    ctx.buf = scratch;
    ctx.bufSz = scratchSz;
    ctx.idx = 0;

    /* RFC 9052 Section 4.4: Sig_structure = [
     *   context : "Signature1",
     *   body_protected : bstr,
     *   external_aad : bstr,
     *   payload : bstr
     * ] */
    ret = wc_CBOR_EncodeArrayStart(&ctx, 4);

    /* context string */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeTstr(&ctx, (const uint8_t*)"Signature1", 10);
    }

    /* body_protected (serialized protected headers) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, protectedHdr, protectedLen);
    }

    /* external_aad */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, extAad,
                                  (extAad != NULL) ? extAadLen : 0u);
    }

    /* payload */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, payload, payloadLen);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        *structLen = ctx.idx;
    }
    return ret;
}

int wc_CoseSign1_Sign(WOLFCOSE_KEY* key, int32_t alg,
    const uint8_t* kid, size_t kidLen,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen,
    WC_RNG* rng)
{
    int ret;
    uint8_t protectedBuf[WOLFCOSE_PROTECTED_HDR_MAX];
    size_t protectedLen = 0;
    size_t sigStructLen = 0;
    size_t sigSz = 0;
    uint8_t hashBuf[WC_MAX_DIGEST_SIZE];
    uint8_t sigBuf[132]; /* ECC/EdDSA max: ES512 = 66+66 = 132 */
    const uint8_t* sigPtr = sigBuf; /* points to sigBuf or scratch for RSA */
    WOLFCOSE_CBOR_CTX outCtx;
    size_t unprotectedEntries;

    if (key == NULL || payload == NULL || scratch == NULL ||
        out == NULL || outLen == NULL || rng == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
        goto cleanup;
    }

    if (key->hasPrivate != 1u) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
        goto cleanup;
    }

    /* Encode protected headers: {1: alg} */
    ret = wolfCose_EncodeProtectedHdr(alg, protectedBuf,
                                       sizeof(protectedBuf), &protectedLen);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    /* Build Sig_structure in scratch */
    ret = wolfCose_BuildSigStructure(protectedBuf, protectedLen,
                                      extAad, extAadLen,
                                      payload, payloadLen,
                                      scratch, scratchSz, &sigStructLen);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    /* Sign based on algorithm */
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
    if (alg == WOLFCOSE_ALG_EDDSA) {
        word32 edSigLen = (word32)sizeof(sigBuf);
        if (key->kty != WOLFCOSE_KTY_OKP) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
            goto cleanup;
        }
        /* EdDSA signs raw Sig_structure (no pre-hash) */
#ifdef HAVE_ED25519
        if (key->crv == WOLFCOSE_CRV_ED25519) {
            ret = wc_ed25519_sign_msg(scratch, (word32)sigStructLen,
                                       sigBuf, &edSigLen, key->key.ed25519);
        }
        else
#endif
#ifdef HAVE_ED448
        if (key->crv == WOLFCOSE_CRV_ED448) {
            ret = wc_ed448_sign_msg(scratch, (word32)sigStructLen,
                                     sigBuf, &edSigLen, key->key.ed448,
                                     NULL, 0);
        }
        else
#endif
        {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
            goto cleanup;
        }
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
            goto cleanup;
        }
        sigSz = (size_t)edSigLen;
    }
    else
#endif /* HAVE_ED25519 || HAVE_ED448 */
#ifdef HAVE_ECC
    if (alg == WOLFCOSE_ALG_ES256 || alg == WOLFCOSE_ALG_ES384 ||
        alg == WOLFCOSE_ALG_ES512) {
        enum wc_HashType hashType;
        int digestSz;
        size_t coordSz;

        if (key->kty != WOLFCOSE_KTY_EC2) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
            goto cleanup;
        }

        ret = wolfCose_AlgToHashType(alg, &hashType);
        if (ret != WOLFCOSE_SUCCESS) {
            goto cleanup;
        }

        digestSz = wc_HashGetDigestSize(hashType);
        if (digestSz <= 0) {
            ret = WOLFCOSE_E_CRYPTO;
            goto cleanup;
        }

        ret = wc_Hash(hashType, scratch, (word32)sigStructLen,
                       hashBuf, (word32)digestSz);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
            goto cleanup;
        }

        ret = wolfCose_CrvKeySize(key->crv, &coordSz);
        if (ret != WOLFCOSE_SUCCESS) {
            goto cleanup;
        }

        {
            size_t rawSigLen = sizeof(sigBuf);
            ret = wolfCose_EccSignRaw(hashBuf, (size_t)digestSz,
                                       sigBuf, &rawSigLen, coordSz,
                                       rng, key->key.ecc);
            if (ret != WOLFCOSE_SUCCESS) {
                goto cleanup;
            }
            sigSz = rawSigLen;
        }
    }
    else
#endif
#ifdef WC_RSA_PSS
    if (alg == WOLFCOSE_ALG_PS256 || alg == WOLFCOSE_ALG_PS384 ||
        alg == WOLFCOSE_ALG_PS512) {
        enum wc_HashType hashType;
        int digestSz;
        int mgf;
        word32 rsaSigLen;

        if (key->kty != WOLFCOSE_KTY_RSA) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
            goto cleanup;
        }

        ret = wolfCose_AlgToHashType(alg, &hashType);
        if (ret != WOLFCOSE_SUCCESS) {
            goto cleanup;
        }

        digestSz = wc_HashGetDigestSize(hashType);
        if (digestSz <= 0) {
            ret = WOLFCOSE_E_CRYPTO;
            goto cleanup;
        }

        /* Hash Sig_structure */
        ret = wc_Hash(hashType, scratch, (word32)sigStructLen,
                       hashBuf, (word32)digestSz);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
            goto cleanup;
        }

        ret = wolfCose_HashToMgf(hashType, &mgf);
        if (ret != WOLFCOSE_SUCCESS) {
            goto cleanup;
        }

        /* RSA sig goes into scratch (after hashing, scratch is free) */
        rsaSigLen = (word32)scratchSz;
        ret = wc_RsaPSS_Sign_ex(hashBuf, (word32)digestSz,
                                  scratch, rsaSigLen,
                                  hashType, mgf, digestSz,
                                  key->key.rsa, rng);
        if (ret <= 0) {
            ret = WOLFCOSE_E_CRYPTO;
            goto cleanup;
        }
        sigSz = (size_t)ret;
        sigPtr = scratch;
        ret = WOLFCOSE_SUCCESS;
    }
    else
#endif /* WC_RSA_PSS */
#ifdef HAVE_DILITHIUM
    if (alg == WOLFCOSE_ALG_ML_DSA_44 || alg == WOLFCOSE_ALG_ML_DSA_65 ||
        alg == WOLFCOSE_ALG_ML_DSA_87) {
        size_t expectedSigSz;

        if (key->kty != WOLFCOSE_KTY_OKP || key->key.dilithium == NULL) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
            goto cleanup;
        }

        ret = wolfCose_SigSize(alg, &expectedSigSz);
        if (ret != WOLFCOSE_SUCCESS) {
            goto cleanup;
        }

        /* Sig output goes after Sig_structure in scratch */
        if (sigStructLen + expectedSigSz > scratchSz) {
            ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
            goto cleanup;
        }

        {
            word32 dlSigLen = (word32)expectedSigSz;
            ret = wc_dilithium_sign_msg(
                scratch, (word32)sigStructLen,
                scratch + sigStructLen, &dlSigLen,
                key->key.dilithium, rng);
            if (ret != 0) {
                ret = WOLFCOSE_E_CRYPTO;
                goto cleanup;
            }
            sigPtr = scratch + sigStructLen;
            sigSz = (size_t)dlSigLen;
        }
    }
    else
#endif /* HAVE_DILITHIUM */
    {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
        goto cleanup;
    }

    /* Encode COSE_Sign1 output:
     * Tag(18) [protected_bstr, unprotected_map, payload_bstr, signature_bstr]
     */
    outCtx.buf = out;
    outCtx.bufSz = outSz;
    outCtx.idx = 0;

    ret = wc_CBOR_EncodeTag(&outCtx, WOLFCOSE_TAG_SIGN1);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    ret = wc_CBOR_EncodeArrayStart(&outCtx, 4);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    ret = wc_CBOR_EncodeBstr(&outCtx, protectedBuf, protectedLen);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    unprotectedEntries = (kid != NULL && kidLen > 0u) ? 1u : 0u;
    ret = wc_CBOR_EncodeMapStart(&outCtx, unprotectedEntries);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }
    if (kid != NULL && kidLen > 0u) {
        ret = wc_CBOR_EncodeUint(&outCtx, (uint64_t)WOLFCOSE_HDR_KID);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(&outCtx, kid, kidLen);
        }
        if (ret != WOLFCOSE_SUCCESS) {
            goto cleanup;
        }
    }

    ret = wc_CBOR_EncodeBstr(&outCtx, payload, payloadLen);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    ret = wc_CBOR_EncodeBstr(&outCtx, sigPtr, sigSz);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    *outLen = outCtx.idx;

cleanup:
    wc_ForceZero(hashBuf, sizeof(hashBuf));
    wc_ForceZero(sigBuf, sizeof(sigBuf));
    if (scratch != NULL) {
        wc_ForceZero(scratch, scratchSz);
    }
    return ret;
}

int wc_CoseSign1_Verify(WOLFCOSE_KEY* key,
    const uint8_t* in, size_t inSz,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    const uint8_t** payload, size_t* payloadLen)
{
    int ret;
    WOLFCOSE_CBOR_CTX ctx;
    uint64_t tag;
    size_t arrayCount;
    const uint8_t* protectedData;
    size_t protectedLen;
    const uint8_t* payloadData;
    size_t payloadDataLen;
    const uint8_t* sigData;
    size_t sigDataLen;
    size_t sigStructLen = 0;
    uint8_t hashBuf[WC_MAX_DIGEST_SIZE];
    int32_t alg;

    if (key == NULL || in == NULL || scratch == NULL || hdr == NULL ||
        payload == NULL || payloadLen == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
        goto cleanup;
    }

    XMEMSET(hdr, 0, sizeof(WOLFCOSE_HDR));

    ctx.buf = (uint8_t*)(uintptr_t)in; /* MISRA Rule 11.8 deviation */
    ctx.bufSz = inSz;
    ctx.idx = 0;

    /* Optional Tag(18) */
    if (ctx.idx < ctx.bufSz &&
        wc_CBOR_PeekType(&ctx) == WOLFCOSE_CBOR_TAG) {
        ret = wc_CBOR_DecodeTag(&ctx, &tag);
        if (ret != WOLFCOSE_SUCCESS) {
            goto cleanup;
        }
        if (tag != WOLFCOSE_TAG_SIGN1) {
            ret = WOLFCOSE_E_COSE_BAD_TAG;
            goto cleanup;
        }
    }

    /* Array of 4 elements */
    ret = wc_CBOR_DecodeArrayStart(&ctx, &arrayCount);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }
    if (arrayCount != 4u) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
        goto cleanup;
    }

    /* 1. Protected headers (bstr) */
    ret = wc_CBOR_DecodeBstr(&ctx, &protectedData, &protectedLen);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    /* Parse protected headers */
    ret = wolfCose_DecodeProtectedHdr(protectedData, protectedLen, hdr);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    /* 2. Unprotected headers (map) */
    ret = wolfCose_DecodeUnprotectedHdr(&ctx, hdr);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    /* 3. Payload (bstr) */
    ret = wc_CBOR_DecodeBstr(&ctx, &payloadData, &payloadDataLen);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    /* 4. Signature (bstr) */
    ret = wc_CBOR_DecodeBstr(&ctx, &sigData, &sigDataLen);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    alg = hdr->alg;

    /* Rebuild Sig_structure in scratch */
    ret = wolfCose_BuildSigStructure(protectedData, protectedLen,
                                      extAad, extAadLen,
                                      payloadData, payloadDataLen,
                                      scratch, scratchSz, &sigStructLen);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    /* Verify based on algorithm */
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
    if (alg == WOLFCOSE_ALG_EDDSA) {
        int verified = 0;
        if (key->kty != WOLFCOSE_KTY_OKP) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
            goto cleanup;
        }
#ifdef HAVE_ED25519
        if (key->crv == WOLFCOSE_CRV_ED25519) {
            ret = wc_ed25519_verify_msg(sigData, (word32)sigDataLen,
                                         scratch, (word32)sigStructLen,
                                         &verified, key->key.ed25519);
        }
        else
#endif
#ifdef HAVE_ED448
        if (key->crv == WOLFCOSE_CRV_ED448) {
            ret = wc_ed448_verify_msg(sigData, (word32)sigDataLen,
                                       scratch, (word32)sigStructLen,
                                       &verified, key->key.ed448, NULL, 0);
        }
        else
#endif
        {
            ret = WOLFCOSE_E_COSE_BAD_ALG;
            goto cleanup;
        }
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
            goto cleanup;
        }
        if (verified != 1) {
            ret = WOLFCOSE_E_COSE_SIG_FAIL;
            goto cleanup;
        }
    }
    else
#endif
#ifdef HAVE_ECC
    if (alg == WOLFCOSE_ALG_ES256 || alg == WOLFCOSE_ALG_ES384 ||
        alg == WOLFCOSE_ALG_ES512) {
        int verified = 0;
        size_t coordSz;
        enum wc_HashType hashType;
        int digestSz;

        if (key->kty != WOLFCOSE_KTY_EC2) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
            goto cleanup;
        }

        ret = wolfCose_AlgToHashType(alg, &hashType);
        if (ret != WOLFCOSE_SUCCESS) {
            goto cleanup;
        }

        digestSz = wc_HashGetDigestSize(hashType);
        if (digestSz <= 0) {
            ret = WOLFCOSE_E_CRYPTO;
            goto cleanup;
        }

        ret = wc_Hash(hashType, scratch, (word32)sigStructLen,
                       hashBuf, (word32)digestSz);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
            goto cleanup;
        }

        ret = wolfCose_CrvKeySize(key->crv, &coordSz);
        if (ret != WOLFCOSE_SUCCESS) {
            goto cleanup;
        }

        ret = wolfCose_EccVerifyRaw(sigData, sigDataLen,
                                     hashBuf, (size_t)digestSz,
                                     coordSz, key->key.ecc, &verified);
        if (ret != WOLFCOSE_SUCCESS) {
            goto cleanup;
        }
        if (verified != 1) {
            ret = WOLFCOSE_E_COSE_SIG_FAIL;
            goto cleanup;
        }
    }
    else
#endif
#ifdef WC_RSA_PSS
    if (alg == WOLFCOSE_ALG_PS256 || alg == WOLFCOSE_ALG_PS384 ||
        alg == WOLFCOSE_ALG_PS512) {
        enum wc_HashType hashType;
        int digestSz;
        int mgf;

        if (key->kty != WOLFCOSE_KTY_RSA) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
            goto cleanup;
        }

        ret = wolfCose_AlgToHashType(alg, &hashType);
        if (ret != WOLFCOSE_SUCCESS) {
            goto cleanup;
        }

        digestSz = wc_HashGetDigestSize(hashType);
        if (digestSz <= 0) {
            ret = WOLFCOSE_E_CRYPTO;
            goto cleanup;
        }

        ret = wc_Hash(hashType, scratch, (word32)sigStructLen,
                       hashBuf, (word32)digestSz);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
            goto cleanup;
        }

        ret = wolfCose_HashToMgf(hashType, &mgf);
        if (ret != WOLFCOSE_SUCCESS) {
            goto cleanup;
        }

        /* Copy sig into scratch — wc_RsaPSS_VerifyCheck modifies its
         * input buffer in-place; sigData points into the caller's
         * const COSE message and must not be written to. */
        if (sigDataLen > scratchSz) {
            ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
            goto cleanup;
        }
        XMEMCPY(scratch, sigData, sigDataLen);
        ret = wc_RsaPSS_VerifyCheck(scratch, (word32)sigDataLen,
                                      scratch, (word32)scratchSz,
                                      hashBuf, (word32)digestSz,
                                      hashType, mgf, key->key.rsa);
        if (ret < 0) {
            ret = WOLFCOSE_E_COSE_SIG_FAIL;
            goto cleanup;
        }
        ret = WOLFCOSE_SUCCESS;
    }
    else
#endif /* WC_RSA_PSS */
#ifdef HAVE_DILITHIUM
    if (alg == WOLFCOSE_ALG_ML_DSA_44 || alg == WOLFCOSE_ALG_ML_DSA_65 ||
        alg == WOLFCOSE_ALG_ML_DSA_87) {
        int verified = 0;

        if (key->kty != WOLFCOSE_KTY_OKP || key->key.dilithium == NULL) {
            ret = WOLFCOSE_E_COSE_KEY_TYPE;
            goto cleanup;
        }

        ret = wc_dilithium_verify_msg(sigData, (word32)sigDataLen,
                                        scratch, (word32)sigStructLen,
                                        &verified, key->key.dilithium);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
            goto cleanup;
        }
        if (verified != 1) {
            ret = WOLFCOSE_E_COSE_SIG_FAIL;
            goto cleanup;
        }
    }
    else
#endif /* HAVE_DILITHIUM */
    {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
        goto cleanup;
    }

    /* Return zero-copy payload pointer into input buffer */
    *payload = payloadData;
    *payloadLen = payloadDataLen;

cleanup:
    wc_ForceZero(hashBuf, sizeof(hashBuf));
    if (scratch != NULL) {
        wc_ForceZero(scratch, scratchSz);
    }
    return ret;
}

/* ---------------------------------------------------------------------------
 * COSE_Encrypt0 API
 * --------------------------------------------------------------------------- */

#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM) || \
    (defined(HAVE_CHACHA) && defined(HAVE_POLY1305))

/**
 * Build the Enc_structure for COSE_Encrypt0:
 *   ["Encrypt0", body_protected, external_aad]
 */
static int wolfCose_BuildEncStructure(const uint8_t* protectedHdr,
                                       size_t protectedLen,
                                       const uint8_t* extAad,
                                       size_t extAadLen,
                                       uint8_t* scratch, size_t scratchSz,
                                       size_t* structLen)
{
    int ret;
    WOLFCOSE_CBOR_CTX ctx;

    ctx.buf = scratch;
    ctx.bufSz = scratchSz;
    ctx.idx = 0;

    /* RFC 9052 Section 5.3: Enc_structure = [
     *   context : "Encrypt0",
     *   body_protected : bstr,
     *   external_aad : bstr
     * ] */
    ret = wc_CBOR_EncodeArrayStart(&ctx, 3);

    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeTstr(&ctx, (const uint8_t*)"Encrypt0", 8);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, protectedHdr, protectedLen);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, extAad,
                                  (extAad != NULL) ? extAadLen : 0u);
    }
    if (ret == WOLFCOSE_SUCCESS) {
        *structLen = ctx.idx;
    }
    return ret;
}

int wc_CoseEncrypt0_Encrypt(WOLFCOSE_KEY* key, int32_t alg,
    const uint8_t* iv, size_t ivLen,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen)
{
    int ret;
#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
    Aes aes;
    int aesInited = 0;
#endif
    uint8_t protectedBuf[WOLFCOSE_PROTECTED_HDR_MAX];
    size_t protectedLen = 0;
    size_t encStructLen = 0;
    size_t aeadKeyLen;
    size_t aeadTagLen;
    WOLFCOSE_CBOR_CTX outCtx;
    size_t ciphertextTotalLen;
    size_t ciphertextOffset;

    if (key == NULL || iv == NULL || payload == NULL || scratch == NULL ||
        out == NULL || outLen == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
        goto cleanup;
    }

    if (key->kty != WOLFCOSE_KTY_SYMMETRIC) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
        goto cleanup;
    }

    ret = wolfCose_AeadKeyLen(alg, &aeadKeyLen);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    if (key->key.symm.keyLen != aeadKeyLen) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
        goto cleanup;
    }

    ret = wolfCose_AeadTagLen(alg, &aeadTagLen);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    /* Validate nonce length matches algorithm spec */
    {
        size_t expectedNonceLen;
        ret = wolfCose_AeadNonceLen(alg, &expectedNonceLen);
        if (ret != WOLFCOSE_SUCCESS) {
            goto cleanup;
        }
        if (ivLen != expectedNonceLen) {
            ret = WOLFCOSE_E_INVALID_ARG;
            goto cleanup;
        }
    }

    /* Encode protected headers */
    ret = wolfCose_EncodeProtectedHdr(alg, protectedBuf,
                                       sizeof(protectedBuf), &protectedLen);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    /* Build Enc_structure in scratch (used as AAD) */
    ret = wolfCose_BuildEncStructure(protectedBuf, protectedLen,
                                      extAad, extAadLen,
                                      scratch, scratchSz, &encStructLen);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    /* Build output COSE_Encrypt0 structure up to ciphertext */
    outCtx.buf = out;
    outCtx.bufSz = outSz;
    outCtx.idx = 0;

    ret = wc_CBOR_EncodeTag(&outCtx, WOLFCOSE_TAG_ENCRYPT0);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    ret = wc_CBOR_EncodeArrayStart(&outCtx, 3);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    /* protected headers as bstr */
    ret = wc_CBOR_EncodeBstr(&outCtx, protectedBuf, protectedLen);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    /* unprotected headers: {5: iv} */
    ret = wc_CBOR_EncodeMapStart(&outCtx, 1);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }
    ret = wc_CBOR_EncodeUint(&outCtx, (uint64_t)WOLFCOSE_HDR_IV);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }
    ret = wc_CBOR_EncodeBstr(&outCtx, iv, ivLen);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    /* Ciphertext bstr: payload + AEAD tag */
    ciphertextTotalLen = payloadLen + aeadTagLen;
    ret = wolfCose_CBOR_EncodeHead(&outCtx, WOLFCOSE_CBOR_BSTR,
                                    (uint64_t)ciphertextTotalLen);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    /* Check there's room for ciphertext + tag */
    if (outCtx.idx + ciphertextTotalLen > outCtx.bufSz) {
        ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    ciphertextOffset = outCtx.idx;

    /* Dispatch encryption by algorithm */
#ifdef HAVE_AESGCM
    if (alg == WOLFCOSE_ALG_A128GCM || alg == WOLFCOSE_ALG_A192GCM ||
        alg == WOLFCOSE_ALG_A256GCM) {
        ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
            goto cleanup;
        }
        aesInited = 1;

        ret = wc_AesGcmSetKey(&aes, key->key.symm.key, (word32)aeadKeyLen);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
            goto cleanup;
        }

        ret = wc_AesGcmEncrypt(&aes,
            out + ciphertextOffset,
            payload, (word32)payloadLen,
            iv, (word32)ivLen,
            out + ciphertextOffset + payloadLen,
            (word32)aeadTagLen,
            scratch, (word32)encStructLen);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
            goto cleanup;
        }
    }
    else
#endif /* HAVE_AESGCM */
#ifdef HAVE_AESCCM
    if (alg == WOLFCOSE_ALG_AES_CCM_16_64_128  ||
        alg == WOLFCOSE_ALG_AES_CCM_16_64_256  ||
        alg == WOLFCOSE_ALG_AES_CCM_64_64_128  ||
        alg == WOLFCOSE_ALG_AES_CCM_64_64_256  ||
        alg == WOLFCOSE_ALG_AES_CCM_16_128_128 ||
        alg == WOLFCOSE_ALG_AES_CCM_16_128_256 ||
        alg == WOLFCOSE_ALG_AES_CCM_64_128_128 ||
        alg == WOLFCOSE_ALG_AES_CCM_64_128_256) {
        ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
            goto cleanup;
        }
        aesInited = 1;

        ret = wc_AesCcmSetKey(&aes, key->key.symm.key, (word32)aeadKeyLen);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
            goto cleanup;
        }

        ret = wc_AesCcmEncrypt(&aes,
            out + ciphertextOffset,
            payload, (word32)payloadLen,
            iv, (word32)ivLen,
            out + ciphertextOffset + payloadLen,
            (word32)aeadTagLen,
            scratch, (word32)encStructLen);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
            goto cleanup;
        }
    }
    else
#endif /* HAVE_AESCCM */
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    if (alg == WOLFCOSE_ALG_CHACHA20_POLY1305) {
        ret = wc_ChaCha20Poly1305_Encrypt(
            key->key.symm.key, iv,
            scratch, (word32)encStructLen,
            payload, (word32)payloadLen,
            out + ciphertextOffset,
            out + ciphertextOffset + payloadLen);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
            goto cleanup;
        }
    }
    else
#endif /* HAVE_CHACHA && HAVE_POLY1305 */
    {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
        goto cleanup;
    }

    outCtx.idx += ciphertextTotalLen;
    *outLen = outCtx.idx;
    ret = WOLFCOSE_SUCCESS;

cleanup:
#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
    if (aesInited) {
        wc_AesFree(&aes);
    }
#endif
    if (scratch != NULL) {
        wc_ForceZero(scratch, scratchSz);
    }
    return ret;
}

int wc_CoseEncrypt0_Decrypt(WOLFCOSE_KEY* key,
    const uint8_t* in, size_t inSz,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    uint8_t* plaintext, size_t plaintextSz, size_t* plaintextLen)
{
    int ret;
#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
    Aes aes;
    int aesInited = 0;
#endif
    WOLFCOSE_CBOR_CTX ctx;
    uint64_t tag;
    size_t arrayCount;
    const uint8_t* protectedData;
    size_t protectedLen;
    const uint8_t* ciphertext;
    size_t ciphertextLen;
    size_t encStructLen = 0;
    size_t aeadKeyLen;
    size_t aeadTagLen;
    size_t payloadSz;
    int32_t alg;

    if (key == NULL || in == NULL || scratch == NULL || hdr == NULL ||
        plaintext == NULL || plaintextLen == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
        goto cleanup;
    }

    if (key->kty != WOLFCOSE_KTY_SYMMETRIC) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
        goto cleanup;
    }

    XMEMSET(hdr, 0, sizeof(WOLFCOSE_HDR));

    ctx.buf = (uint8_t*)(uintptr_t)in; /* MISRA Rule 11.8 deviation */
    ctx.bufSz = inSz;
    ctx.idx = 0;

    /* Optional Tag(16) */
    if (ctx.idx < ctx.bufSz &&
        wc_CBOR_PeekType(&ctx) == WOLFCOSE_CBOR_TAG) {
        ret = wc_CBOR_DecodeTag(&ctx, &tag);
        if (ret != WOLFCOSE_SUCCESS) {
            goto cleanup;
        }
        if (tag != WOLFCOSE_TAG_ENCRYPT0) {
            ret = WOLFCOSE_E_COSE_BAD_TAG;
            goto cleanup;
        }
    }

    /* Array of 3 */
    ret = wc_CBOR_DecodeArrayStart(&ctx, &arrayCount);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }
    if (arrayCount != 3u) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
        goto cleanup;
    }

    /* 1. Protected headers */
    ret = wc_CBOR_DecodeBstr(&ctx, &protectedData, &protectedLen);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    ret = wolfCose_DecodeProtectedHdr(protectedData, protectedLen, hdr);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    /* 2. Unprotected headers */
    ret = wolfCose_DecodeUnprotectedHdr(&ctx, hdr);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    /* 3. Ciphertext (bstr) */
    ret = wc_CBOR_DecodeBstr(&ctx, &ciphertext, &ciphertextLen);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    alg = hdr->alg;

    ret = wolfCose_AeadKeyLen(alg, &aeadKeyLen);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    ret = wolfCose_AeadTagLen(alg, &aeadTagLen);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    if (ciphertextLen < aeadTagLen) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
        goto cleanup;
    }

    if (key->key.symm.keyLen != aeadKeyLen) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
        goto cleanup;
    }

    /* Payload size = ciphertext minus tag */
    payloadSz = ciphertextLen - aeadTagLen;
    if (payloadSz > plaintextSz) {
        ret = WOLFCOSE_E_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    if (hdr->iv == NULL || hdr->ivLen == 0u) {
        ret = WOLFCOSE_E_COSE_BAD_HDR;
        goto cleanup;
    }

    /* Validate nonce length matches algorithm spec */
    {
        size_t expectedNonceLen;
        ret = wolfCose_AeadNonceLen(alg, &expectedNonceLen);
        if (ret != WOLFCOSE_SUCCESS) {
            goto cleanup;
        }
        if (hdr->ivLen != expectedNonceLen) {
            ret = WOLFCOSE_E_COSE_BAD_HDR;
            goto cleanup;
        }
    }

    /* Build Enc_structure as AAD */
    ret = wolfCose_BuildEncStructure(protectedData, protectedLen,
                                      extAad, extAadLen,
                                      scratch, scratchSz, &encStructLen);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    /* Dispatch decryption by algorithm */
#ifdef HAVE_AESGCM
    if (alg == WOLFCOSE_ALG_A128GCM || alg == WOLFCOSE_ALG_A192GCM ||
        alg == WOLFCOSE_ALG_A256GCM) {
        ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
            goto cleanup;
        }
        aesInited = 1;

        ret = wc_AesGcmSetKey(&aes, key->key.symm.key, (word32)aeadKeyLen);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
            goto cleanup;
        }

        ret = wc_AesGcmDecrypt(&aes,
            plaintext,
            ciphertext, (word32)payloadSz,
            hdr->iv, (word32)hdr->ivLen,
            ciphertext + payloadSz, (word32)aeadTagLen,
            scratch, (word32)encStructLen);
        if (ret != 0) {
            ret = WOLFCOSE_E_COSE_DECRYPT_FAIL;
            goto cleanup;
        }
    }
    else
#endif /* HAVE_AESGCM */
#ifdef HAVE_AESCCM
    if (alg == WOLFCOSE_ALG_AES_CCM_16_64_128  ||
        alg == WOLFCOSE_ALG_AES_CCM_16_64_256  ||
        alg == WOLFCOSE_ALG_AES_CCM_64_64_128  ||
        alg == WOLFCOSE_ALG_AES_CCM_64_64_256  ||
        alg == WOLFCOSE_ALG_AES_CCM_16_128_128 ||
        alg == WOLFCOSE_ALG_AES_CCM_16_128_256 ||
        alg == WOLFCOSE_ALG_AES_CCM_64_128_128 ||
        alg == WOLFCOSE_ALG_AES_CCM_64_128_256) {
        ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
            goto cleanup;
        }
        aesInited = 1;

        ret = wc_AesCcmSetKey(&aes, key->key.symm.key, (word32)aeadKeyLen);
        if (ret != 0) {
            ret = WOLFCOSE_E_CRYPTO;
            goto cleanup;
        }

        ret = wc_AesCcmDecrypt(&aes,
            plaintext,
            ciphertext, (word32)payloadSz,
            hdr->iv, (word32)hdr->ivLen,
            ciphertext + payloadSz, (word32)aeadTagLen,
            scratch, (word32)encStructLen);
        if (ret != 0) {
            ret = WOLFCOSE_E_COSE_DECRYPT_FAIL;
            goto cleanup;
        }
    }
    else
#endif /* HAVE_AESCCM */
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    if (alg == WOLFCOSE_ALG_CHACHA20_POLY1305) {
        ret = wc_ChaCha20Poly1305_Decrypt(
            key->key.symm.key, hdr->iv,
            scratch, (word32)encStructLen,
            ciphertext, (word32)payloadSz,
            ciphertext + payloadSz,
            plaintext);
        if (ret != 0) {
            ret = WOLFCOSE_E_COSE_DECRYPT_FAIL;
            goto cleanup;
        }
    }
    else
#endif /* HAVE_CHACHA && HAVE_POLY1305 */
    {
        ret = WOLFCOSE_E_COSE_BAD_ALG;
        goto cleanup;
    }

    *plaintextLen = payloadSz;
    ret = WOLFCOSE_SUCCESS;

cleanup:
#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
    if (aesInited) {
        wc_AesFree(&aes);
    }
#endif
    if (scratch != NULL) {
        wc_ForceZero(scratch, scratchSz);
    }
    return ret;
}

#endif /* HAVE_AESGCM || HAVE_AESCCM || (HAVE_CHACHA && HAVE_POLY1305) */

/* ---------------------------------------------------------------------------
 * COSE_Mac0 API (RFC 9052 Section 6.2)
 * --------------------------------------------------------------------------- */

#if !defined(NO_HMAC)

/**
 * Build the MAC_structure for COSE_Mac0:
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
    int ret;
    WOLFCOSE_CBOR_CTX ctx;

    ctx.buf = scratch;
    ctx.bufSz = scratchSz;
    ctx.idx = 0;

    /* RFC 9052 Section 6.3: MAC_structure = [
     *   context : "MAC0",
     *   body_protected : bstr,
     *   external_aad : bstr,
     *   payload : bstr
     * ] */
    ret = wc_CBOR_EncodeArrayStart(&ctx, 4);

    /* context string */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeTstr(&ctx, (const uint8_t*)"MAC0", 4);
    }

    /* body_protected (serialized protected headers) */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, protectedHdr, protectedLen);
    }

    /* external_aad */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, extAad,
                                  (extAad != NULL) ? extAadLen : 0u);
    }

    /* payload */
    if (ret == WOLFCOSE_SUCCESS) {
        ret = wc_CBOR_EncodeBstr(&ctx, payload, payloadLen);
    }

    if (ret == WOLFCOSE_SUCCESS) {
        *structLen = ctx.idx;
    }
    return ret;
}

int wc_CoseMac0_Create(WOLFCOSE_KEY* key, int32_t alg,
    const uint8_t* kid, size_t kidLen,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen)
{
    int ret;
    uint8_t protectedBuf[WOLFCOSE_PROTECTED_HDR_MAX];
    size_t protectedLen = 0;
    size_t macStructLen = 0;
    size_t tagSz = 0;
    int hmacType = 0;
    uint8_t tagBuf[64]; /* HMAC-512 max = 64 bytes */
    Hmac hmac;
    int hmacInited = 0;
    WOLFCOSE_CBOR_CTX outCtx;
    size_t unprotectedEntries;

    if (key == NULL || payload == NULL || scratch == NULL ||
        out == NULL || outLen == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
        goto cleanup;
    }

    if (key->kty != WOLFCOSE_KTY_SYMMETRIC) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
        goto cleanup;
    }

    /* Get tag size and HMAC type */
    ret = wolfCose_HmacTagSize(alg, &tagSz);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    ret = wolfCose_HmacType(alg, &hmacType);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    /* Encode protected headers: {1: alg} */
    ret = wolfCose_EncodeProtectedHdr(alg, protectedBuf,
                                       sizeof(protectedBuf), &protectedLen);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    /* Build MAC_structure in scratch */
    ret = wolfCose_BuildMacStructure(protectedBuf, protectedLen,
                                      extAad, extAadLen,
                                      payload, payloadLen,
                                      scratch, scratchSz, &macStructLen);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    /* Compute HMAC */
    ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (ret != 0) {
        ret = WOLFCOSE_E_CRYPTO;
        goto cleanup;
    }
    hmacInited = 1;

    ret = wc_HmacSetKey(&hmac, hmacType, key->key.symm.key,
                          (word32)key->key.symm.keyLen);
    if (ret != 0) {
        ret = WOLFCOSE_E_CRYPTO;
        goto cleanup;
    }

    ret = wc_HmacUpdate(&hmac, scratch, (word32)macStructLen);
    if (ret != 0) {
        ret = WOLFCOSE_E_CRYPTO;
        goto cleanup;
    }

    ret = wc_HmacFinal(&hmac, tagBuf);
    if (ret != 0) {
        ret = WOLFCOSE_E_CRYPTO;
        goto cleanup;
    }

    /* Encode COSE_Mac0 output:
     * Tag(17) [protected_bstr, unprotected_map, payload_bstr, tag_bstr]
     */
    outCtx.buf = out;
    outCtx.bufSz = outSz;
    outCtx.idx = 0;

    ret = wc_CBOR_EncodeTag(&outCtx, WOLFCOSE_TAG_MAC0);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    ret = wc_CBOR_EncodeArrayStart(&outCtx, 4);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    /* protected headers as bstr */
    ret = wc_CBOR_EncodeBstr(&outCtx, protectedBuf, protectedLen);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    /* unprotected headers map */
    unprotectedEntries = (kid != NULL && kidLen > 0u) ? 1u : 0u;
    ret = wc_CBOR_EncodeMapStart(&outCtx, unprotectedEntries);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }
    if (kid != NULL && kidLen > 0u) {
        ret = wc_CBOR_EncodeUint(&outCtx, (uint64_t)WOLFCOSE_HDR_KID);
        if (ret == WOLFCOSE_SUCCESS) {
            ret = wc_CBOR_EncodeBstr(&outCtx, kid, kidLen);
        }
        if (ret != WOLFCOSE_SUCCESS) {
            goto cleanup;
        }
    }

    /* payload */
    ret = wc_CBOR_EncodeBstr(&outCtx, payload, payloadLen);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    /* HMAC tag */
    ret = wc_CBOR_EncodeBstr(&outCtx, tagBuf, tagSz);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    *outLen = outCtx.idx;

cleanup:
    if (hmacInited) {
        wc_HmacFree(&hmac);
    }
    wc_ForceZero(tagBuf, sizeof(tagBuf));
    if (scratch != NULL) {
        wc_ForceZero(scratch, scratchSz);
    }
    return ret;
}

int wc_CoseMac0_Verify(WOLFCOSE_KEY* key,
    const uint8_t* in, size_t inSz,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    const uint8_t** payload, size_t* payloadLen)
{
    int ret;
    WOLFCOSE_CBOR_CTX ctx;
    uint64_t tag;
    size_t arrayCount;
    const uint8_t* protectedData;
    size_t protectedLen;
    const uint8_t* payloadData;
    size_t payloadDataLen;
    const uint8_t* macTag;
    size_t macTagLen;
    size_t macStructLen = 0;
    size_t expectedTagSz = 0;
    int hmacType = 0;
    uint8_t computedTag[64]; /* HMAC-512 max */
    Hmac hmac;
    int hmacInited = 0;
    int32_t alg;
    size_t i;
    uint8_t diff;

    if (key == NULL || in == NULL || scratch == NULL || hdr == NULL ||
        payload == NULL || payloadLen == NULL) {
        ret = WOLFCOSE_E_INVALID_ARG;
        goto cleanup;
    }

    if (key->kty != WOLFCOSE_KTY_SYMMETRIC) {
        ret = WOLFCOSE_E_COSE_KEY_TYPE;
        goto cleanup;
    }

    XMEMSET(hdr, 0, sizeof(WOLFCOSE_HDR));

    ctx.buf = (uint8_t*)(uintptr_t)in; /* MISRA Rule 11.8 deviation */
    ctx.bufSz = inSz;
    ctx.idx = 0;

    /* Optional Tag(17) */
    if (ctx.idx < ctx.bufSz &&
        wc_CBOR_PeekType(&ctx) == WOLFCOSE_CBOR_TAG) {
        ret = wc_CBOR_DecodeTag(&ctx, &tag);
        if (ret != WOLFCOSE_SUCCESS) {
            goto cleanup;
        }
        if (tag != WOLFCOSE_TAG_MAC0) {
            ret = WOLFCOSE_E_COSE_BAD_TAG;
            goto cleanup;
        }
    }

    /* Array of 4 elements */
    ret = wc_CBOR_DecodeArrayStart(&ctx, &arrayCount);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }
    if (arrayCount != 4u) {
        ret = WOLFCOSE_E_CBOR_MALFORMED;
        goto cleanup;
    }

    /* 1. Protected headers (bstr) */
    ret = wc_CBOR_DecodeBstr(&ctx, &protectedData, &protectedLen);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    /* Parse protected headers */
    ret = wolfCose_DecodeProtectedHdr(protectedData, protectedLen, hdr);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    /* 2. Unprotected headers (map) */
    ret = wolfCose_DecodeUnprotectedHdr(&ctx, hdr);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    /* 3. Payload (bstr) */
    ret = wc_CBOR_DecodeBstr(&ctx, &payloadData, &payloadDataLen);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    /* 4. Tag (bstr) */
    ret = wc_CBOR_DecodeBstr(&ctx, &macTag, &macTagLen);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    alg = hdr->alg;

    /* Get expected tag size and HMAC type */
    ret = wolfCose_HmacTagSize(alg, &expectedTagSz);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    if (macTagLen != expectedTagSz) {
        ret = WOLFCOSE_E_COSE_MAC_FAIL;
        goto cleanup;
    }

    ret = wolfCose_HmacType(alg, &hmacType);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    /* Rebuild MAC_structure in scratch */
    ret = wolfCose_BuildMacStructure(protectedData, protectedLen,
                                      extAad, extAadLen,
                                      payloadData, payloadDataLen,
                                      scratch, scratchSz, &macStructLen);
    if (ret != WOLFCOSE_SUCCESS) {
        goto cleanup;
    }

    /* Recompute HMAC */
    ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (ret != 0) {
        ret = WOLFCOSE_E_CRYPTO;
        goto cleanup;
    }
    hmacInited = 1;

    ret = wc_HmacSetKey(&hmac, hmacType, key->key.symm.key,
                          (word32)key->key.symm.keyLen);
    if (ret != 0) {
        ret = WOLFCOSE_E_CRYPTO;
        goto cleanup;
    }

    ret = wc_HmacUpdate(&hmac, scratch, (word32)macStructLen);
    if (ret != 0) {
        ret = WOLFCOSE_E_CRYPTO;
        goto cleanup;
    }

    ret = wc_HmacFinal(&hmac, computedTag);
    if (ret != 0) {
        ret = WOLFCOSE_E_CRYPTO;
        goto cleanup;
    }

    /* Constant-time compare */
    diff = 0;
    for (i = 0; i < expectedTagSz; i++) {
        diff |= computedTag[i] ^ macTag[i];
    }
    if (diff != 0u) {
        ret = WOLFCOSE_E_COSE_MAC_FAIL;
        goto cleanup;
    }

    /* Return zero-copy payload pointer into input buffer */
    *payload = payloadData;
    *payloadLen = payloadDataLen;

cleanup:
    if (hmacInited) {
        wc_HmacFree(&hmac);
    }
    wc_ForceZero(computedTag, sizeof(computedTag));
    if (scratch != NULL) {
        wc_ForceZero(scratch, scratchSz);
    }
    return ret;
}

#endif /* !NO_HMAC */
