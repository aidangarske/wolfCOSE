/* wolfcose.h
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

#ifndef WOLFCOSE_H
#define WOLFCOSE_H

#include <wolfcose/visibility.h>

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#include <stdint.h>
#include <stddef.h>

#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifdef HAVE_ED25519
    #include <wolfssl/wolfcrypt/ed25519.h>
#endif
#ifdef WC_RSA_PSS
    #include <wolfssl/wolfcrypt/rsa.h>
#endif
#ifdef HAVE_ED448
    #include <wolfssl/wolfcrypt/ed448.h>
#endif
#ifdef HAVE_DILITHIUM
    #include <wolfssl/wolfcrypt/dilithium.h>
#endif
#include <wolfssl/wolfcrypt/random.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------------
 * Compile-time feature gates — opt-out design
 *
 * Users exclude features via WOLFCOSE_NO_* defines:
 *   -DWOLFCOSE_NO_ENCRYPT0 -DWOLFCOSE_NO_MAC0   → Sign-only build
 *   -DWOLFCOSE_NO_SIGN1_SIGN -DWOLFCOSE_NO_CBOR_ENCODE → Verify-only build
 *
 * Parent gates imply children unless child is explicitly excluded.
 * --------------------------------------------------------------------------- */

/* === Message Type Gates === */

/* SIGN1 */
#if !defined(WOLFCOSE_NO_SIGN1) && !defined(WOLFCOSE_SIGN1)
    #define WOLFCOSE_SIGN1
#endif
#if defined(WOLFCOSE_SIGN1)
    #if !defined(WOLFCOSE_NO_SIGN1_SIGN)
        #define WOLFCOSE_SIGN1_SIGN
    #endif
    #if !defined(WOLFCOSE_NO_SIGN1_VERIFY)
        #define WOLFCOSE_SIGN1_VERIFY
    #endif
#endif

/* ENCRYPT0 */
#if !defined(WOLFCOSE_NO_ENCRYPT0) && !defined(WOLFCOSE_ENCRYPT0)
    #define WOLFCOSE_ENCRYPT0
#endif
#if defined(WOLFCOSE_ENCRYPT0)
    #if !defined(WOLFCOSE_NO_ENCRYPT0_ENCRYPT)
        #define WOLFCOSE_ENCRYPT0_ENCRYPT
    #endif
    #if !defined(WOLFCOSE_NO_ENCRYPT0_DECRYPT)
        #define WOLFCOSE_ENCRYPT0_DECRYPT
    #endif
#endif

/* MAC0 */
#if !defined(WOLFCOSE_NO_MAC0) && !defined(WOLFCOSE_MAC0)
    #define WOLFCOSE_MAC0
#endif
#if defined(WOLFCOSE_MAC0)
    #if !defined(WOLFCOSE_NO_MAC0_CREATE)
        #define WOLFCOSE_MAC0_CREATE
    #endif
    #if !defined(WOLFCOSE_NO_MAC0_VERIFY)
        #define WOLFCOSE_MAC0_VERIFY
    #endif
#endif

/* Multi-signer SIGN */
#if !defined(WOLFCOSE_NO_SIGN) && !defined(WOLFCOSE_SIGN)
    #define WOLFCOSE_SIGN
#endif
#if defined(WOLFCOSE_SIGN)
    #if !defined(WOLFCOSE_NO_SIGN_SIGN)
        #define WOLFCOSE_SIGN_SIGN
    #endif
    #if !defined(WOLFCOSE_NO_SIGN_VERIFY)
        #define WOLFCOSE_SIGN_VERIFY
    #endif
#endif

/* Multi-recipient ENCRYPT */
#if !defined(WOLFCOSE_NO_ENCRYPT) && !defined(WOLFCOSE_ENCRYPT)
    #define WOLFCOSE_ENCRYPT
#endif
#if defined(WOLFCOSE_ENCRYPT)
    #if !defined(WOLFCOSE_NO_ENCRYPT_ENCRYPT)
        #define WOLFCOSE_ENCRYPT_ENCRYPT
    #endif
    #if !defined(WOLFCOSE_NO_ENCRYPT_DECRYPT)
        #define WOLFCOSE_ENCRYPT_DECRYPT
    #endif
#endif

/* Multi-recipient MAC */
#if !defined(WOLFCOSE_NO_MAC) && !defined(WOLFCOSE_MAC)
    #define WOLFCOSE_MAC
#endif
#if defined(WOLFCOSE_MAC)
    #if !defined(WOLFCOSE_NO_MAC_CREATE)
        #define WOLFCOSE_MAC_CREATE
    #endif
    #if !defined(WOLFCOSE_NO_MAC_VERIFY)
        #define WOLFCOSE_MAC_VERIFY
    #endif
#endif

/* === Recipient/Key Distribution Gates === */

#if !defined(WOLFCOSE_NO_RECIPIENTS) && !defined(WOLFCOSE_RECIPIENTS)
    #define WOLFCOSE_RECIPIENTS
#endif
#if defined(WOLFCOSE_RECIPIENTS)
    #if !defined(WOLFCOSE_NO_KEY_WRAP) && defined(HAVE_AES_KEYWRAP)
        #define WOLFCOSE_KEY_WRAP
    #endif
    #if !defined(WOLFCOSE_NO_ECDH) && (defined(HAVE_ECC) || defined(HAVE_CURVE25519))
        #define WOLFCOSE_ECDH
    #endif
    #if !defined(WOLFCOSE_NO_ECDH_WRAP) && defined(WOLFCOSE_ECDH) && \
        defined(WOLFCOSE_KEY_WRAP)
        #define WOLFCOSE_ECDH_WRAP
    #endif
    #if !defined(WOLFCOSE_NO_ECDH_ES_DIRECT) && defined(WOLFCOSE_ECDH) && \
        defined(HAVE_ECC) && defined(HAVE_HKDF)
        #define WOLFCOSE_ECDH_ES_DIRECT
    #endif
#endif

/* === CBOR Layer Gates === */

#if !defined(WOLFCOSE_NO_CBOR_ENCODE) && !defined(WOLFCOSE_CBOR_ENCODE)
    #define WOLFCOSE_CBOR_ENCODE
#endif
#if !defined(WOLFCOSE_NO_CBOR_DECODE) && !defined(WOLFCOSE_CBOR_DECODE)
    #define WOLFCOSE_CBOR_DECODE
#endif

/* === COSE_Key Gates === */

#if !defined(WOLFCOSE_NO_KEY_ENCODE) && !defined(WOLFCOSE_KEY_ENCODE)
    #define WOLFCOSE_KEY_ENCODE
#endif
#if !defined(WOLFCOSE_NO_KEY_DECODE) && !defined(WOLFCOSE_KEY_DECODE)
    #define WOLFCOSE_KEY_DECODE
#endif

/* === Auto-enable dependencies === */

/* Sign/Encrypt/Mac operations need CBOR encode */
#if defined(WOLFCOSE_SIGN1_SIGN) || defined(WOLFCOSE_ENCRYPT0_ENCRYPT) || \
    defined(WOLFCOSE_MAC0_CREATE)
    #if !defined(WOLFCOSE_CBOR_ENCODE)
        #define WOLFCOSE_CBOR_ENCODE
    #endif
#endif

/* Verify/Decrypt operations need CBOR decode */
#if defined(WOLFCOSE_SIGN1_VERIFY) || defined(WOLFCOSE_ENCRYPT0_DECRYPT) || \
    defined(WOLFCOSE_MAC0_VERIFY)
    #if !defined(WOLFCOSE_CBOR_DECODE)
        #define WOLFCOSE_CBOR_DECODE
    #endif
#endif

/* ---------------------------------------------------------------------------
 * Error codes (-9000 to -9099)
 * --------------------------------------------------------------------------- */
#define WOLFCOSE_SUCCESS             0
#define WOLFCOSE_E_INVALID_ARG      (-9000)
#define WOLFCOSE_E_BUFFER_TOO_SMALL (-9001)
#define WOLFCOSE_E_CBOR_MALFORMED   (-9002)
#define WOLFCOSE_E_CBOR_TYPE        (-9003)
#define WOLFCOSE_E_CBOR_OVERFLOW    (-9004)
#define WOLFCOSE_E_CBOR_DEPTH       (-9006)
#define WOLFCOSE_E_COSE_BAD_TAG     (-9010)
#define WOLFCOSE_E_COSE_BAD_ALG     (-9011)
#define WOLFCOSE_E_COSE_SIG_FAIL    (-9012)
#define WOLFCOSE_E_COSE_DECRYPT_FAIL (-9013)
#define WOLFCOSE_E_COSE_BAD_HDR     (-9014)
#define WOLFCOSE_E_COSE_KEY_TYPE    (-9015)
#define WOLFCOSE_E_COSE_MAC_FAIL    (-9016)
#define WOLFCOSE_E_CRYPTO           (-9020)
#define WOLFCOSE_E_UNSUPPORTED      (-9021)
#define WOLFCOSE_E_MAC_FAIL         (-9022)
#define WOLFCOSE_E_DETACHED_PAYLOAD (-9023)

/* ---------------------------------------------------------------------------
 * Configurable limits
 * --------------------------------------------------------------------------- */
#ifndef WOLFCOSE_MAX_SCRATCH_SZ
    #define WOLFCOSE_MAX_SCRATCH_SZ      512
#endif
#ifndef WOLFCOSE_PROTECTED_HDR_MAX
    #define WOLFCOSE_PROTECTED_HDR_MAX    64
#endif
#ifndef WOLFCOSE_CBOR_MAX_DEPTH
    #define WOLFCOSE_CBOR_MAX_DEPTH        8
#endif
#ifndef WOLFCOSE_MAX_MAP_ITEMS
    #define WOLFCOSE_MAX_MAP_ITEMS        16
#endif
#ifndef WOLFCOSE_MAX_SIG_SZ
    #if defined(HAVE_DILITHIUM)
        #define WOLFCOSE_MAX_SIG_SZ  4627
    #elif defined(WC_RSA_PSS)
        #define WOLFCOSE_MAX_SIG_SZ  512
    #else
        #define WOLFCOSE_MAX_SIG_SZ  132
    #endif
#endif

/* ---------------------------------------------------------------------------
 * CBOR constants (RFC 8949)
 * --------------------------------------------------------------------------- */

/* Major types (top 3 bits of initial byte) */
#define WOLFCOSE_CBOR_UINT      0u
#define WOLFCOSE_CBOR_NEGINT    1u
#define WOLFCOSE_CBOR_BSTR      2u
#define WOLFCOSE_CBOR_TSTR      3u
#define WOLFCOSE_CBOR_ARRAY     4u
#define WOLFCOSE_CBOR_MAP       5u
#define WOLFCOSE_CBOR_TAG       6u
#define WOLFCOSE_CBOR_SIMPLE    7u

/* Additional information values */
#define WOLFCOSE_CBOR_AI_1BYTE  24u
#define WOLFCOSE_CBOR_AI_2BYTE  25u
#define WOLFCOSE_CBOR_AI_4BYTE  26u
#define WOLFCOSE_CBOR_AI_8BYTE  27u
#define WOLFCOSE_CBOR_AI_INDEF  31u

/* Simple values */
#define WOLFCOSE_CBOR_FALSE     0xF4u
#define WOLFCOSE_CBOR_TRUE      0xF5u
#define WOLFCOSE_CBOR_NULL      0xF6u
#define WOLFCOSE_CBOR_BREAK     0xFFu

/* Float half/single/double AI */
#define WOLFCOSE_CBOR_AI_FLOAT16 25u
#define WOLFCOSE_CBOR_AI_FLOAT32 26u
#define WOLFCOSE_CBOR_AI_FLOAT64 27u

/* ---------------------------------------------------------------------------
 * COSE constants (RFC 9052)
 * --------------------------------------------------------------------------- */

/* Tags (RFC 9052) */
#define WOLFCOSE_TAG_SIGN1      18u
#define WOLFCOSE_TAG_ENCRYPT0   16u
#define WOLFCOSE_TAG_MAC0       17u
#define WOLFCOSE_TAG_SIGN       98u  /* Multi-signer */
#define WOLFCOSE_TAG_ENCRYPT    96u  /* Multi-recipient encryption */
#define WOLFCOSE_TAG_MAC        97u  /* Multi-recipient MAC */

/* Header labels */
#define WOLFCOSE_HDR_ALG         1
#define WOLFCOSE_HDR_CRIT        2
#define WOLFCOSE_HDR_CONTENT_TYPE 3
#define WOLFCOSE_HDR_KID         4
#define WOLFCOSE_HDR_IV          5
#define WOLFCOSE_HDR_PARTIAL_IV  6
#define WOLFCOSE_HDR_EPHEMERAL_KEY (-1)  /* Ephemeral COSE_Key for ECDH */

/* Algorithms */
#define WOLFCOSE_ALG_ES256      (-7)
#define WOLFCOSE_ALG_ES384      (-35)
#define WOLFCOSE_ALG_ES512      (-36)
#define WOLFCOSE_ALG_EDDSA      (-8)
#define WOLFCOSE_ALG_PS256      (-37)
#define WOLFCOSE_ALG_PS384      (-38)
#define WOLFCOSE_ALG_PS512      (-39)
#define WOLFCOSE_ALG_A128GCM     1
#define WOLFCOSE_ALG_A192GCM     2
#define WOLFCOSE_ALG_A256GCM     3
#define WOLFCOSE_ALG_HMAC_256_256  5   /* HMAC w/ SHA-256, 256-bit tag */
#define WOLFCOSE_ALG_HMAC_384_384  6   /* HMAC w/ SHA-384, 384-bit tag */
#define WOLFCOSE_ALG_HMAC_512_512  7   /* HMAC w/ SHA-512, 512-bit tag */
#define WOLFCOSE_ALG_CHACHA20_POLY1305 24
/* AES-CCM (RFC 9053 Section 4.2) */
#define WOLFCOSE_ALG_AES_CCM_16_64_128   10
#define WOLFCOSE_ALG_AES_CCM_16_64_256   11
#define WOLFCOSE_ALG_AES_CCM_64_64_128   12
#define WOLFCOSE_ALG_AES_CCM_64_64_256   13
#define WOLFCOSE_ALG_AES_CCM_16_128_128  30
#define WOLFCOSE_ALG_AES_CCM_16_128_256  31
#define WOLFCOSE_ALG_AES_CCM_64_128_128  32
#define WOLFCOSE_ALG_AES_CCM_64_128_256  33

/* AES-CBC-MAC algorithms (RFC 9053 Section 3.2) */
#define WOLFCOSE_ALG_AES_MAC_128_64   14  /* AES-128 key, 64-bit tag */
#define WOLFCOSE_ALG_AES_MAC_256_64   15  /* AES-256 key, 64-bit tag */
#define WOLFCOSE_ALG_AES_MAC_128_128  25  /* AES-128 key, 128-bit tag */
#define WOLFCOSE_ALG_AES_MAC_256_128  26  /* AES-256 key, 128-bit tag */

/* Key Distribution Algorithms (RFC 9053 Section 6) */
#define WOLFCOSE_ALG_A128KW       (-3)   /* AES-128 Key Wrap */
#define WOLFCOSE_ALG_A192KW       (-4)   /* AES-192 Key Wrap */
#define WOLFCOSE_ALG_A256KW       (-5)   /* AES-256 Key Wrap */
#define WOLFCOSE_ALG_DIRECT       (-6)   /* Direct use of CEK */
#define WOLFCOSE_ALG_ECDH_ES_HKDF_256  (-25)  /* ECDH-ES + HKDF-256 */
#define WOLFCOSE_ALG_ECDH_ES_HKDF_512  (-26)  /* ECDH-ES + HKDF-512 */
#define WOLFCOSE_ALG_ECDH_SS_HKDF_256  (-27)  /* ECDH-SS + HKDF-256 */
#define WOLFCOSE_ALG_ECDH_SS_HKDF_512  (-28)  /* ECDH-SS + HKDF-512 */
#define WOLFCOSE_ALG_ECDH_ES_A128KW    (-29)  /* ECDH-ES + A128KW */
#define WOLFCOSE_ALG_ECDH_ES_A192KW    (-30)  /* ECDH-ES + A192KW */
#define WOLFCOSE_ALG_ECDH_ES_A256KW    (-31)  /* ECDH-ES + A256KW */

#ifdef HAVE_DILITHIUM
#define WOLFCOSE_ALG_ML_DSA_44   (-48)   /* ML-DSA (Dilithium) Level 2 */
#define WOLFCOSE_ALG_ML_DSA_65   (-49)   /* ML-DSA Level 3 */
#define WOLFCOSE_ALG_ML_DSA_87   (-50)   /* ML-DSA Level 5 */
#endif

/* Key types */
#define WOLFCOSE_KTY_OKP         1
#define WOLFCOSE_KTY_EC2         2
#define WOLFCOSE_KTY_RSA         3
#define WOLFCOSE_KTY_SYMMETRIC   4

/* Curves */
#define WOLFCOSE_CRV_P256        1
#define WOLFCOSE_CRV_P384        2
#define WOLFCOSE_CRV_P521        3
#define WOLFCOSE_CRV_ED25519     6
#define WOLFCOSE_CRV_ED448       7
/* Provisional PQC curve IDs (not yet in IANA registry) */
#define WOLFCOSE_CRV_ML_DSA_44   (-48)
#define WOLFCOSE_CRV_ML_DSA_65   (-49)
#define WOLFCOSE_CRV_ML_DSA_87   (-50)

/* COSE_Key map labels */
#define WOLFCOSE_KEY_LABEL_KTY    1
#define WOLFCOSE_KEY_LABEL_KID    2
#define WOLFCOSE_KEY_LABEL_ALG    3
#define WOLFCOSE_KEY_LABEL_CRV   (-1)
#define WOLFCOSE_KEY_LABEL_X     (-2)
#define WOLFCOSE_KEY_LABEL_Y     (-3)
#define WOLFCOSE_KEY_LABEL_D     (-4)
#define WOLFCOSE_KEY_LABEL_K     (-1)  /* Symmetric key value */

/* AES-GCM constants */
#define WOLFCOSE_AES_GCM_TAG_SZ  16
#define WOLFCOSE_AES_GCM_NONCE_SZ 12

/* ChaCha20-Poly1305 constants */
#define WOLFCOSE_CHACHA_KEY_SZ    32
#define WOLFCOSE_CHACHA_NONCE_SZ  12
#define WOLFCOSE_CHACHA_TAG_SZ    16

/* ---------------------------------------------------------------------------
 * Structs
 * --------------------------------------------------------------------------- */

/**
 * \brief CBOR encoder/decoder context. Zero-copy cursor over a buffer.
 */
typedef struct WOLFCOSE_CBOR_CTX {
    uint8_t* buf;      /**< Buffer pointer (encode: output, decode: input) */
    size_t   bufSz;    /**< Total buffer size */
    size_t   idx;      /**< Current read/write position */
} WOLFCOSE_CBOR_CTX;

/**
 * \brief Decoded CBOR item. For bstr/tstr, data points into the input buffer.
 */
typedef struct WOLFCOSE_CBOR_ITEM {
    uint8_t        majorType;  /**< Major type (0-7) */
    uint64_t       val;        /**< Numeric value or length of bstr/tstr/array/map */
    const uint8_t* data;       /**< Pointer into input buffer (bstr/tstr only) */
    size_t         dataLen;    /**< Length of data (bstr/tstr only) */
} WOLFCOSE_CBOR_ITEM;

/**
 * \brief Parsed COSE headers. Zero-copy pointers into the encoded message.
 */
typedef struct WOLFCOSE_HDR {
    int32_t        alg;           /**< Algorithm (from protected or unprotected) */
    const uint8_t* kid;           /**< Key ID pointer */
    size_t         kidLen;        /**< Key ID length */
    const uint8_t* iv;            /**< IV pointer */
    size_t         ivLen;         /**< IV length */
    const uint8_t* partialIv;     /**< Partial IV pointer */
    size_t         partialIvLen;  /**< Partial IV length */
    int32_t        contentType;   /**< Content type, 0 if absent */
    uint8_t        flags;         /**< Header flags (see WOLFCOSE_HDR_FLAG_*) */
} WOLFCOSE_HDR;

/** \brief Flag indicating payload is detached (RFC 9052 Section 2) */
#define WOLFCOSE_HDR_FLAG_DETACHED 0x01u

/**
 * \brief COSE key structure. Pointers to caller-owned wolfCrypt key structs.
 *
 * Caller allocates and initializes wolfCrypt keys (wc_ecc_init, etc).
 * wolfCOSE never owns key lifecycle -- wc_CoseKey_Free does NOT free the
 * underlying wolfCrypt key.
 */
typedef struct WOLFCOSE_KEY {
    int32_t        kty;       /**< WOLFCOSE_KTY_* */
    int32_t        alg;       /**< WOLFCOSE_ALG_*, 0 if unset */
    int32_t        crv;       /**< WOLFCOSE_CRV_*, 0 if N/A */
    const uint8_t* kid;       /**< Key ID, zero-copy pointer */
    size_t         kidLen;    /**< Key ID length */
    union {
#ifdef HAVE_ECC
        ecc_key*       ecc;       /**< Caller-owned, init'd via wolfCrypt */
#endif
#ifdef HAVE_ED25519
        ed25519_key*   ed25519;   /**< Caller-owned */
#endif
#ifdef HAVE_ED448
        ed448_key*     ed448;     /**< Caller-owned */
#endif
#ifdef WC_RSA_PSS
        RsaKey*        rsa;       /**< Caller-owned RSA key */
#endif
#ifdef HAVE_DILITHIUM
        dilithium_key* dilithium; /**< PQC future: ML-DSA */
#endif
        void*          pqc;       /**< Generic PQC handle for future algos */
        struct {
            const uint8_t* key;    /**< Pointer to caller-owned key material */
            size_t         keyLen; /**< Key material length */
        } symm;
    } key;
    uint8_t hasPrivate;  /**< 1 if private key material present */
} WOLFCOSE_KEY;

/**
 * \brief COSE_recipient structure for multi-recipient messages (RFC 9052 Section 5.1, 6.1).
 *
 * Represents a single recipient in COSE_Encrypt or COSE_Mac messages.
 * Used for key distribution (wrap, ECDH, direct).
 */
typedef struct WOLFCOSE_RECIPIENT {
    int32_t        algId;       /**< Key distribution algorithm (-3..-31, -6) */
    WOLFCOSE_KEY*  key;         /**< Caller-owned key (KEK for wrap, recipient pubkey for ECDH) */
    const uint8_t* kid;         /**< Key ID for recipient lookup */
    size_t         kidLen;      /**< Key ID length */
} WOLFCOSE_RECIPIENT;

/**
 * \brief COSE_Signature structure for multi-signer messages (RFC 9052 Section 4.1).
 *
 * Represents a single signer in a COSE_Sign message.
 */
typedef struct WOLFCOSE_SIGNATURE {
    int32_t        algId;       /**< Signature algorithm (ES256, EdDSA, etc.) */
    WOLFCOSE_KEY*  key;         /**< Caller-owned signing key */
    const uint8_t* kid;         /**< Key ID for signer identification */
    size_t         kidLen;      /**< Key ID length */
} WOLFCOSE_SIGNATURE;

/* ---------------------------------------------------------------------------
 * CBOR Encode API (RFC 8949)
 *
 * All functions return WOLFCOSE_SUCCESS or a negative error code.
 * Guarded by WOLFCOSE_CBOR_ENCODE — can be excluded for decode-only builds.
 * --------------------------------------------------------------------------- */

#if defined(WOLFCOSE_CBOR_ENCODE)

/**
 * \brief Encode an unsigned integer.
 * \param ctx  Encoder context with output buffer.
 * \param val  Value to encode.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_EncodeUint(WOLFCOSE_CBOR_CTX* ctx, uint64_t val);

/**
 * \brief Encode a negative integer. Encodes CBOR value -(val+1).
 * \param ctx  Encoder context.
 * \param val  Magnitude minus one (e.g., 0 encodes -1, 99 encodes -100).
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_EncodeNegInt(WOLFCOSE_CBOR_CTX* ctx, uint64_t val);

/**
 * \brief Encode a signed integer. Dispatches to EncodeUint or EncodeNegInt.
 * \param ctx  Encoder context.
 * \param val  Signed value.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_EncodeInt(WOLFCOSE_CBOR_CTX* ctx, int64_t val);

/**
 * \brief Encode a byte string (major type 2).
 * \param ctx   Encoder context.
 * \param data  Byte string data (may be NULL if len is 0).
 * \param len   Length of data.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_EncodeBstr(WOLFCOSE_CBOR_CTX* ctx,
                                     const uint8_t* data, size_t len);

/**
 * \brief Encode a text string (major type 3).
 * \param ctx   Encoder context.
 * \param str   UTF-8 text (not null-terminated requirement).
 * \param len   Length in bytes.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_EncodeTstr(WOLFCOSE_CBOR_CTX* ctx,
                                     const uint8_t* str, size_t len);

/**
 * \brief Encode a definite-length array header.
 * \param ctx    Encoder context.
 * \param count  Number of items that follow.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_EncodeArrayStart(WOLFCOSE_CBOR_CTX* ctx,
                                           size_t count);

/**
 * \brief Encode a definite-length map header.
 * \param ctx    Encoder context.
 * \param count  Number of key-value pairs that follow.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_EncodeMapStart(WOLFCOSE_CBOR_CTX* ctx, size_t count);

/**
 * \brief Encode a CBOR tag (major type 6).
 * \param ctx  Encoder context.
 * \param tag  Tag number.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_EncodeTag(WOLFCOSE_CBOR_CTX* ctx, uint64_t tag);

/** \brief Encode CBOR true (0xF5). */
WOLFCOSE_API int wc_CBOR_EncodeTrue(WOLFCOSE_CBOR_CTX* ctx);

/** \brief Encode CBOR false (0xF4). */
WOLFCOSE_API int wc_CBOR_EncodeFalse(WOLFCOSE_CBOR_CTX* ctx);

/** \brief Encode CBOR null (0xF6). */
WOLFCOSE_API int wc_CBOR_EncodeNull(WOLFCOSE_CBOR_CTX* ctx);

#ifdef WOLFCOSE_FLOAT
/** \brief Encode an IEEE 754 single-precision float. */
WOLFCOSE_API int wc_CBOR_EncodeFloat(WOLFCOSE_CBOR_CTX* ctx, float val);

/** \brief Encode an IEEE 754 double-precision float. */
WOLFCOSE_API int wc_CBOR_EncodeDouble(WOLFCOSE_CBOR_CTX* ctx, double val);
#endif

#endif /* WOLFCOSE_CBOR_ENCODE */

/* ---------------------------------------------------------------------------
 * CBOR Decode API (zero-copy, single-pass)
 *
 * Guarded by WOLFCOSE_CBOR_DECODE — always needed for verify/decrypt builds.
 * --------------------------------------------------------------------------- */

#if defined(WOLFCOSE_CBOR_DECODE)

/**
 * \brief Decode a CBOR data item head. Core decoder function.
 *        For bstr/tstr, sets item->data to point into the input buffer.
 * \param ctx   Decoder context (advances idx past the decoded item head + data).
 * \param item  Output: decoded item.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_DecodeHead(WOLFCOSE_CBOR_CTX* ctx,
                                     WOLFCOSE_CBOR_ITEM* item);

/**
 * \brief Decode an unsigned integer. Type-checks for major type 0.
 * \param ctx  Decoder context.
 * \param val  Output: decoded value.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_DecodeUint(WOLFCOSE_CBOR_CTX* ctx, uint64_t* val);

/**
 * \brief Decode a signed integer (major type 0 or 1).
 * \param ctx  Decoder context.
 * \param val  Output: decoded signed value.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_DecodeInt(WOLFCOSE_CBOR_CTX* ctx, int64_t* val);

/**
 * \brief Decode a byte string. Zero-copy: *data points into ctx->buf.
 * \param ctx      Decoder context.
 * \param data     Output: pointer into input buffer.
 * \param dataLen  Output: byte string length.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_DecodeBstr(WOLFCOSE_CBOR_CTX* ctx,
                                     const uint8_t** data, size_t* dataLen);

/**
 * \brief Decode a text string. Zero-copy: *str points into ctx->buf.
 * \param ctx     Decoder context.
 * \param str     Output: pointer into input buffer.
 * \param strLen  Output: text string length in bytes.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_DecodeTstr(WOLFCOSE_CBOR_CTX* ctx,
                                     const uint8_t** str, size_t* strLen);

/**
 * \brief Decode an array header (major type 4).
 * \param ctx    Decoder context.
 * \param count  Output: number of items in the array.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_DecodeArrayStart(WOLFCOSE_CBOR_CTX* ctx,
                                           size_t* count);

/**
 * \brief Decode a map header (major type 5).
 * \param ctx    Decoder context.
 * \param count  Output: number of key-value pairs.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_DecodeMapStart(WOLFCOSE_CBOR_CTX* ctx,
                                         size_t* count);

/**
 * \brief Decode a tag (major type 6).
 * \param ctx  Decoder context.
 * \param tag  Output: tag value.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_DecodeTag(WOLFCOSE_CBOR_CTX* ctx, uint64_t* tag);

/**
 * \brief Skip over a complete CBOR item (including nested arrays/maps).
 *        Uses iterative traversal with bounded stack depth.
 * \param ctx  Decoder context (idx advances past the skipped item).
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CBOR_Skip(WOLFCOSE_CBOR_CTX* ctx);

/**
 * \brief Peek at the major type of the next item without consuming it.
 * \param ctx  Decoder context. Must have idx < bufSz.
 * \return Major type (0-7).
 */
#define wc_CBOR_PeekType(ctx) ((ctx)->buf[(ctx)->idx] >> 5)

#endif /* WOLFCOSE_CBOR_DECODE */

/* ---------------------------------------------------------------------------
 * COSE Key API
 * --------------------------------------------------------------------------- */

/**
 * \brief Initialize a WOLFCOSE_KEY structure (zero all fields).
 * \param key  Key structure to initialize.
 * \return WOLFCOSE_SUCCESS or WOLFCOSE_E_INVALID_ARG.
 */
WOLFCOSE_API int wc_CoseKey_Init(WOLFCOSE_KEY* key);

/**
 * \brief Free a WOLFCOSE_KEY. Does NOT free the underlying wolfCrypt key
 *        (caller owns key lifecycle). Zeros the structure.
 * \param key  Key to free.
 */
WOLFCOSE_API void wc_CoseKey_Free(WOLFCOSE_KEY* key);

#ifdef HAVE_ECC
/**
 * \brief Attach an ECC key to a COSE key structure.
 * \param key     COSE key (must be initialized).
 * \param crv     WOLFCOSE_CRV_P256/P384/P521.
 * \param eccKey  Caller-owned, initialized ecc_key.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseKey_SetEcc(WOLFCOSE_KEY* key, int32_t crv,
                                    ecc_key* eccKey);
#endif

#ifdef HAVE_ED25519
/**
 * \brief Attach an Ed25519 key to a COSE key structure.
 * \param key    COSE key (must be initialized).
 * \param edKey  Caller-owned, initialized ed25519_key.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseKey_SetEd25519(WOLFCOSE_KEY* key,
                                        ed25519_key* edKey);
#endif

#ifdef HAVE_ED448
WOLFCOSE_API int wc_CoseKey_SetEd448(WOLFCOSE_KEY* key, ed448_key* edKey);
#endif

#ifdef HAVE_DILITHIUM
WOLFCOSE_API int wc_CoseKey_SetDilithium(WOLFCOSE_KEY* key, int32_t alg,
                                           dilithium_key* dlKey);
#endif

#ifdef WC_RSA_PSS
WOLFCOSE_API int wc_CoseKey_SetRsa(WOLFCOSE_KEY* key, RsaKey* rsaKey);
#endif

/**
 * \brief Attach a symmetric key to a COSE key structure.
 * \param key      COSE key (must be initialized).
 * \param data     Pointer to caller-owned key material.
 * \param dataLen  Key material length in bytes.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseKey_SetSymmetric(WOLFCOSE_KEY* key,
                                          const uint8_t* data, size_t dataLen);

#if defined(WOLFCOSE_KEY_ENCODE)
/**
 * \brief Encode a WOLFCOSE_KEY to CBOR COSE_Key map format.
 * \param key     Key to encode.
 * \param out     Output buffer.
 * \param outSz   Output buffer size.
 * \param outLen  Output: number of bytes written.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseKey_Encode(WOLFCOSE_KEY* key, uint8_t* out,
                                    size_t outSz, size_t* outLen);
#endif /* WOLFCOSE_KEY_ENCODE */

#if defined(WOLFCOSE_KEY_DECODE)
/**
 * \brief Decode a CBOR COSE_Key map into a WOLFCOSE_KEY structure.
 *        For symmetric keys, pointers reference the input buffer.
 *        For ECC/Ed25519, caller must pre-allocate and attach key struct.
 * \param key   Key structure (should be initialized, with wolfCrypt key
 *              attached for asymmetric types).
 * \param in    Input CBOR buffer.
 * \param inSz  Input buffer size.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseKey_Decode(WOLFCOSE_KEY* key, const uint8_t* in,
                                    size_t inSz);
#endif /* WOLFCOSE_KEY_DECODE */

/* ---------------------------------------------------------------------------
 * COSE_Sign1 API (RFC 9052 Section 4.3)
 * --------------------------------------------------------------------------- */

#if defined(WOLFCOSE_SIGN1_SIGN)
/**
 * \brief Sign a payload producing a COSE_Sign1 message (RFC 9052 Section 4.3).
 *
 * \param key             WOLFCOSE_KEY with hasPrivate=1. Caller retains ownership.
 * \param alg             Algorithm identifier (WOLFCOSE_ALG_ES256, etc).
 * \param kid             Key ID to include in unprotected headers (NULL if none).
 * \param kidLen          Key ID length.
 * \param payload         Payload to sign (NULL if detached).
 * \param payloadLen      Payload length (0 if detached).
 * \param detachedPayload Detached payload for signing (NULL if attached).
 *                        If non-NULL, payload is encoded as CBOR null.
 * \param detachedLen     Detached payload length.
 * \param extAad          External additional authenticated data (NULL if none).
 * \param extAadLen       External AAD length.
 * \param scratch         Working buffer for Sig_structure.
 * \param scratchSz       Scratch buffer size.
 * \param out             Output buffer.
 * \param outSz           Output buffer size.
 * \param outLen          Output: bytes written to out.
 * \param rng             Initialized WC_RNG.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseSign1_Sign(WOLFCOSE_KEY* key, int32_t alg,
    const uint8_t* kid, size_t kidLen,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen,
    WC_RNG* rng);
#endif /* WOLFCOSE_SIGN1_SIGN */

#if defined(WOLFCOSE_SIGN1_VERIFY)
/**
 * \brief Verify a COSE_Sign1 message and extract the payload.
 *
 * \param key             WOLFCOSE_KEY with public key. Caller retains ownership.
 * \param in              Input COSE_Sign1 message.
 * \param inSz            Input message size.
 * \param detachedPayload Detached payload for verification (NULL if attached).
 *                        Required if message has nil payload.
 * \param detachedLen     Detached payload length.
 * \param extAad          External additional authenticated data (NULL if none).
 * \param extAadLen       External AAD length.
 * \param scratch         Working buffer for Sig_structure reconstruction.
 * \param scratchSz       Scratch buffer size.
 * \param hdr             Output: parsed COSE headers. flags field indicates detached.
 * \param payload         Output: zero-copy pointer to payload (NULL if detached).
 * \param payloadLen      Output: payload length (0 if detached).
 * \return WOLFCOSE_SUCCESS or negative error code.
 *         WOLFCOSE_E_DETACHED_PAYLOAD if payload is nil and detachedPayload is NULL.
 */
WOLFCOSE_API int wc_CoseSign1_Verify(WOLFCOSE_KEY* key,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    const uint8_t** payload, size_t* payloadLen);
#endif /* WOLFCOSE_SIGN1_VERIFY */

/* ---------------------------------------------------------------------------
 * COSE_Encrypt0 API (RFC 9052 Section 5.3)
 * --------------------------------------------------------------------------- */

#if defined(WOLFCOSE_ENCRYPT0_ENCRYPT)
/**
 * \brief Encrypt a payload producing a COSE_Encrypt0 message.
 *
 * \param key             WOLFCOSE_KEY with symmetric key material.
 * \param alg             Algorithm (WOLFCOSE_ALG_A128GCM/A192GCM/A256GCM).
 * \param iv              Initialization vector (12 bytes for AES-GCM).
 * \param ivLen           IV length.
 * \param payload         Plaintext payload (NULL if detached).
 * \param payloadLen      Payload length (0 if detached).
 * \param detachedPayload Detached ciphertext destination (NULL if attached).
 *                        If non-NULL, ciphertext is stored here, message has nil.
 * \param detachedSz      Detached buffer size.
 * \param detachedLen     Output: detached ciphertext length.
 * \param extAad          External additional authenticated data (NULL if none).
 * \param extAadLen       External AAD length.
 * \param scratch         Working buffer for Enc_structure.
 * \param scratchSz       Scratch buffer size.
 * \param out             Output buffer.
 * \param outSz           Output buffer size.
 * \param outLen          Output: bytes written to out.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseEncrypt0_Encrypt(WOLFCOSE_KEY* key, int32_t alg,
    const uint8_t* iv, size_t ivLen,
    const uint8_t* payload, size_t payloadLen,
    uint8_t* detachedPayload, size_t detachedSz, size_t* detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen);
#endif /* WOLFCOSE_ENCRYPT0_ENCRYPT */

#if defined(WOLFCOSE_ENCRYPT0_DECRYPT)
/**
 * \brief Decrypt a COSE_Encrypt0 message.
 *
 * \param key             WOLFCOSE_KEY with symmetric key material.
 * \param in              Input COSE_Encrypt0 message.
 * \param inSz            Input size.
 * \param detachedCt      Detached ciphertext (NULL if attached).
 *                        Required if message has nil ciphertext.
 * \param detachedCtLen   Detached ciphertext length.
 * \param extAad          External additional authenticated data (NULL if none).
 * \param extAadLen       External AAD length.
 * \param scratch         Working buffer for Enc_structure reconstruction.
 * \param scratchSz       Scratch buffer size.
 * \param hdr             Output: parsed COSE headers.
 * \param plaintext       Output buffer for decrypted payload.
 * \param plaintextSz     Plaintext buffer size.
 * \param plaintextLen    Output: decrypted payload length.
 * \return WOLFCOSE_SUCCESS or negative error code.
 *         WOLFCOSE_E_DETACHED_PAYLOAD if ciphertext is nil and detachedCt is NULL.
 */
WOLFCOSE_API int wc_CoseEncrypt0_Decrypt(WOLFCOSE_KEY* key,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedCt, size_t detachedCtLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    uint8_t* plaintext, size_t plaintextSz, size_t* plaintextLen);
#endif /* WOLFCOSE_ENCRYPT0_DECRYPT */

/* ---------------------------------------------------------------------------
 * COSE_Mac0 API (RFC 9052 Section 6.2)
 * --------------------------------------------------------------------------- */

#if defined(WOLFCOSE_MAC0_CREATE) && !defined(NO_HMAC)
/**
 * \brief Create a COSE_Mac0 message (RFC 9052 Section 6.2).
 *
 * \param key             WOLFCOSE_KEY with symmetric key for HMAC.
 * \param alg             Algorithm (WOLFCOSE_ALG_HMAC_256_256).
 * \param kid             Key identifier for unprotected header (NULL if none).
 * \param kidLen          Key identifier length.
 * \param payload         Payload to authenticate (NULL if detached).
 * \param payloadLen      Payload length (0 if detached).
 * \param detachedPayload Detached payload for MAC (NULL if attached).
 *                        If non-NULL, payload is encoded as CBOR null.
 * \param detachedLen     Detached payload length.
 * \param extAad          External additional authenticated data (NULL if none).
 * \param extAadLen       External AAD length.
 * \param scratch         Working buffer for MAC_structure.
 * \param scratchSz       Scratch buffer size.
 * \param out             Output buffer.
 * \param outSz           Output buffer size.
 * \param outLen          Output: bytes written to out.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseMac0_Create(WOLFCOSE_KEY* key, int32_t alg,
    const uint8_t* kid, size_t kidLen,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen);
#endif /* WOLFCOSE_MAC0_CREATE && !NO_HMAC */

#if defined(WOLFCOSE_MAC0_VERIFY) && !defined(NO_HMAC)
/**
 * \brief Verify a COSE_Mac0 message and extract the payload.
 *
 * \param key             WOLFCOSE_KEY with symmetric key for HMAC.
 * \param in              Input COSE_Mac0 message.
 * \param inSz            Input message size.
 * \param detachedPayload Detached payload for verification (NULL if attached).
 *                        Required if message has nil payload.
 * \param detachedLen     Detached payload length.
 * \param extAad          External additional authenticated data (NULL if none).
 * \param extAadLen       External AAD length.
 * \param scratch         Working buffer for MAC_structure reconstruction.
 * \param scratchSz       Scratch buffer size.
 * \param hdr             Output: parsed COSE headers. flags field indicates detached.
 * \param payload         Output: zero-copy pointer to payload (NULL if detached).
 * \param payloadLen      Output: payload length (0 if detached).
 * \return WOLFCOSE_SUCCESS or negative error code.
 *         WOLFCOSE_E_DETACHED_PAYLOAD if payload is nil and detachedPayload is NULL.
 */
WOLFCOSE_API int wc_CoseMac0_Verify(WOLFCOSE_KEY* key,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    const uint8_t** payload, size_t* payloadLen);
#endif /* WOLFCOSE_MAC0_VERIFY && !NO_HMAC */

/* ---------------------------------------------------------------------------
 * COSE_Sign Multi-Signer API (RFC 9052 Section 4.1)
 * --------------------------------------------------------------------------- */

#if defined(WOLFCOSE_SIGN_SIGN)
/**
 * \brief Create a COSE_Sign message with multiple signers (RFC 9052 Section 4.1).
 *
 * Creates a COSE_Sign structure:
 *   COSE_Sign = [Headers, payload, signatures : [+ COSE_Signature]]
 *
 * Each COSE_Signature contains signer-specific protected headers (alg)
 * and the signature computed over:
 *   Sig_structure = ["Signature", body_protected, sign_protected, ext_aad, payload]
 *
 * \param signers         Array of WOLFCOSE_SIGNATURE with keys and algorithms.
 * \param signerCount     Number of signers (must be >= 1).
 * \param payload         Payload to sign (NULL if detached).
 * \param payloadLen      Payload length (0 if detached).
 * \param detachedPayload Detached payload for signing (NULL if attached).
 *                        If non-NULL, payload is encoded as CBOR null.
 * \param detachedLen     Detached payload length.
 * \param extAad          External additional authenticated data (NULL if none).
 * \param extAadLen       External AAD length.
 * \param scratch         Working buffer for Sig_structure.
 * \param scratchSz       Scratch buffer size.
 * \param out             Output buffer.
 * \param outSz           Output buffer size.
 * \param outLen          Output: bytes written to out.
 * \param rng             Initialized WC_RNG.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseSign_Sign(const WOLFCOSE_SIGNATURE* signers,
    size_t signerCount,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen,
    WC_RNG* rng);
#endif /* WOLFCOSE_SIGN_SIGN */

#if defined(WOLFCOSE_SIGN_VERIFY)
/**
 * \brief Verify one signature in a COSE_Sign message.
 *
 * Verifies the signature at signerIndex against the provided verifyKey.
 * The caller must match the key to the signer (via kid or out-of-band).
 *
 * \param verifyKey       WOLFCOSE_KEY with public key. Caller retains ownership.
 * \param signerIndex     0-based index of signer to verify.
 * \param in              Input COSE_Sign message.
 * \param inSz            Input message size.
 * \param detachedPayload Detached payload for verification (NULL if attached).
 *                        Required if message has nil payload.
 * \param detachedLen     Detached payload length.
 * \param extAad          External additional authenticated data (NULL if none).
 * \param extAadLen       External AAD length.
 * \param scratch         Working buffer for Sig_structure reconstruction.
 * \param scratchSz       Scratch buffer size.
 * \param hdr             Output: parsed COSE headers (body level).
 * \param payload         Output: zero-copy pointer to payload (NULL if detached).
 * \param payloadLen      Output: payload length (0 if detached).
 * \return WOLFCOSE_SUCCESS or negative error code.
 *         WOLFCOSE_E_DETACHED_PAYLOAD if payload is nil and detachedPayload is NULL.
 */
WOLFCOSE_API int wc_CoseSign_Verify(const WOLFCOSE_KEY* verifyKey,
    size_t signerIndex,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    const uint8_t** payload, size_t* payloadLen);
#endif /* WOLFCOSE_SIGN_VERIFY */

/* ---------------------------------------------------------------------------
 * COSE_Encrypt Multi-Recipient API (RFC 9052 Section 5.1)
 * --------------------------------------------------------------------------- */

#if defined(WOLFCOSE_ENCRYPT_ENCRYPT)
/**
 * \brief Create a COSE_Encrypt message with recipients (RFC 9052 Section 5.1).
 *
 * Creates a COSE_Encrypt structure:
 *   COSE_Encrypt = [Headers, ciphertext, recipients : [+ COSE_recipient]]
 *
 * Currently supports direct key mode where the content encryption key (CEK)
 * is the same for all recipients (pre-shared). The recipients array contains
 * header-only entries identifying which key is used.
 *
 * \param recipients       Array of WOLFCOSE_RECIPIENT with keys.
 * \param recipientCount   Number of recipients (must be >= 1).
 * \param contentAlgId     Content encryption algorithm (A128GCM, etc).
 * \param iv               Initialization vector.
 * \param ivLen            IV length.
 * \param payload          Payload to encrypt (NULL if detached).
 * \param payloadLen       Payload length (0 if detached).
 * \param detachedPayload  Detached payload for encryption (NULL if attached).
 * \param detachedLen      Detached payload length.
 * \param extAad           External additional authenticated data (NULL if none).
 * \param extAadLen        External AAD length.
 * \param scratch          Working buffer for Enc_structure.
 * \param scratchSz        Scratch buffer size.
 * \param out              Output buffer.
 * \param outSz            Output buffer size.
 * \param outLen           Output: bytes written to out.
 * \param rng              Initialized WC_RNG (for future CEK generation).
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseEncrypt_Encrypt(const WOLFCOSE_RECIPIENT* recipients,
    size_t recipientCount,
    int32_t contentAlgId,
    const uint8_t* iv, size_t ivLen,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen,
    WC_RNG* rng);
#endif /* WOLFCOSE_ENCRYPT_ENCRYPT */

#if defined(WOLFCOSE_ENCRYPT_DECRYPT)
/**
 * \brief Decrypt a COSE_Encrypt message.
 *
 * Decrypts using the key from the specified recipient entry.
 *
 * \param recipient        WOLFCOSE_RECIPIENT with decryption key.
 * \param recipientIndex   0-based index of recipient to use.
 * \param in               Input COSE_Encrypt message.
 * \param inSz             Input message size.
 * \param detachedCt       Detached ciphertext (NULL if attached).
 * \param detachedCtLen    Detached ciphertext length.
 * \param extAad           External additional authenticated data (NULL if none).
 * \param extAadLen        External AAD length.
 * \param scratch          Working buffer for Enc_structure reconstruction.
 * \param scratchSz        Scratch buffer size.
 * \param hdr              Output: parsed COSE headers.
 * \param plaintext        Output buffer for decrypted payload.
 * \param plaintextSz      Plaintext buffer size.
 * \param plaintextLen     Output: decrypted payload length.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseEncrypt_Decrypt(const WOLFCOSE_RECIPIENT* recipient,
    size_t recipientIndex,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedCt, size_t detachedCtLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    uint8_t* plaintext, size_t plaintextSz, size_t* plaintextLen);
#endif /* WOLFCOSE_ENCRYPT_DECRYPT */

/* ---------------------------------------------------------------------------
 * COSE_Mac Multi-Recipient API (RFC 9052 Section 6.1)
 * --------------------------------------------------------------------------- */

#if defined(WOLFCOSE_MAC_CREATE)
/**
 * \brief Create a COSE_Mac message with recipients (RFC 9052 Section 6.1).
 *
 * Creates a COSE_Mac structure:
 *   COSE_Mac = [Headers, payload, tag, recipients : [+ COSE_recipient]]
 *
 * For direct key mode: the MAC key is pre-shared among all recipients.
 *
 * \param recipients       Array of WOLFCOSE_RECIPIENT with keys.
 * \param recipientCount   Number of recipients (must be >= 1).
 * \param macAlgId         MAC algorithm (HMAC-256/256, etc).
 * \param payload          Payload to authenticate (NULL if detached).
 * \param payloadLen       Payload length (0 if detached).
 * \param detachedPayload  Detached payload for MAC (NULL if attached).
 * \param detachedLen      Detached payload length.
 * \param extAad           External additional authenticated data (NULL if none).
 * \param extAadLen        External AAD length.
 * \param scratch          Working buffer for MAC_structure.
 * \param scratchSz        Scratch buffer size.
 * \param out              Output buffer.
 * \param outSz            Output buffer size.
 * \param outLen           Output: bytes written to out.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseMac_Create(const WOLFCOSE_RECIPIENT* recipients,
    size_t recipientCount,
    int32_t macAlgId,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen);
#endif /* WOLFCOSE_MAC_CREATE */

#if defined(WOLFCOSE_MAC_VERIFY)
/**
 * \brief Verify a COSE_Mac message.
 *
 * Verifies using the key from the specified recipient entry.
 *
 * \param recipient        WOLFCOSE_RECIPIENT with MAC key.
 * \param recipientIndex   0-based index of recipient to use.
 * \param in               Input COSE_Mac message.
 * \param inSz             Input message size.
 * \param detachedPayload  Detached payload for verification (NULL if attached).
 * \param detachedLen      Detached payload length.
 * \param extAad           External additional authenticated data (NULL if none).
 * \param extAadLen        External AAD length.
 * \param scratch          Working buffer for MAC_structure reconstruction.
 * \param scratchSz        Scratch buffer size.
 * \param hdr              Output: parsed COSE headers.
 * \param payload          Output: zero-copy pointer to payload (NULL if detached).
 * \param payloadLen       Output: payload length (0 if detached).
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseMac_Verify(const WOLFCOSE_RECIPIENT* recipient,
    size_t recipientIndex,
    const uint8_t* in, size_t inSz,
    const uint8_t* detachedPayload, size_t detachedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    const uint8_t** payload, size_t* payloadLen);
#endif /* WOLFCOSE_MAC_VERIFY */

#ifdef __cplusplus
}
#endif

#endif /* WOLFCOSE_H */
