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
#include <wolfssl/wolfcrypt/random.h>

#ifdef __cplusplus
extern "C" {
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
#define WOLFCOSE_E_CRYPTO           (-9020)
#define WOLFCOSE_E_UNSUPPORTED      (-9021)

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

/* Tags */
#define WOLFCOSE_TAG_SIGN1      18u
#define WOLFCOSE_TAG_ENCRYPT0   16u

/* Header labels */
#define WOLFCOSE_HDR_ALG         1
#define WOLFCOSE_HDR_CRIT        2
#define WOLFCOSE_HDR_CONTENT_TYPE 3
#define WOLFCOSE_HDR_KID         4
#define WOLFCOSE_HDR_IV          5
#define WOLFCOSE_HDR_PARTIAL_IV  6

/* Algorithms */
#define WOLFCOSE_ALG_ES256      (-7)
#define WOLFCOSE_ALG_ES384      (-35)
#define WOLFCOSE_ALG_ES512      (-36)
#define WOLFCOSE_ALG_EDDSA      (-8)
#define WOLFCOSE_ALG_A128GCM     1
#define WOLFCOSE_ALG_A192GCM     2
#define WOLFCOSE_ALG_A256GCM     3

/* PQC Algorithm IDs -- reserved, implementation guarded by #ifdef */
/* #define WOLFCOSE_ALG_ML_DSA_44   (-48) */  /* ML-DSA (Dilithium) Level 2 */
/* #define WOLFCOSE_ALG_ML_DSA_65   (-49) */  /* ML-DSA Level 3 */
/* #define WOLFCOSE_ALG_ML_DSA_87   (-50) */  /* ML-DSA Level 5 */

/* Key types */
#define WOLFCOSE_KTY_OKP         1
#define WOLFCOSE_KTY_EC2         2
#define WOLFCOSE_KTY_SYMMETRIC   4

/* Curves */
#define WOLFCOSE_CRV_P256        1
#define WOLFCOSE_CRV_P384        2
#define WOLFCOSE_CRV_P521        3
#define WOLFCOSE_CRV_ED25519     6
#define WOLFCOSE_CRV_ED448       7

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
} WOLFCOSE_HDR;

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

/* ---------------------------------------------------------------------------
 * CBOR Encode API (RFC 8949)
 *
 * All functions return WOLFCOSE_SUCCESS or a negative error code.
 * --------------------------------------------------------------------------- */

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

/* ---------------------------------------------------------------------------
 * CBOR Decode API (zero-copy, single-pass)
 * --------------------------------------------------------------------------- */

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

/**
 * \brief Attach a symmetric key to a COSE key structure.
 * \param key      COSE key (must be initialized).
 * \param data     Pointer to caller-owned key material.
 * \param dataLen  Key material length in bytes.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseKey_SetSymmetric(WOLFCOSE_KEY* key,
                                          const uint8_t* data, size_t dataLen);

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

/* ---------------------------------------------------------------------------
 * COSE_Sign1 API (RFC 9052 Section 4.3)
 * --------------------------------------------------------------------------- */

/**
 * \brief Sign a payload producing a COSE_Sign1 message (RFC 9052 Section 4.3).
 *
 * \param key        WOLFCOSE_KEY with hasPrivate=1. Caller retains ownership.
 * \param alg        Algorithm identifier (WOLFCOSE_ALG_ES256, etc).
 * \param kid        Key ID to include in unprotected headers (NULL if none).
 * \param kidLen     Key ID length.
 * \param payload    Payload to sign.
 * \param payloadLen Payload length.
 * \param extAad     External additional authenticated data (NULL if none).
 * \param extAadLen  External AAD length.
 * \param scratch    Working buffer for Sig_structure. Minimum size:
 *                   28 + protectedLen + extAadLen + payloadLen.
 * \param scratchSz  Scratch buffer size.
 * \param out        Output buffer. Minimum size:
 *                   ~protectedLen + payloadLen + sigLen + 20 bytes overhead.
 * \param outSz      Output buffer size.
 * \param outLen     Output: bytes written to out.
 * \param rng        Initialized WC_RNG. Caller must call wc_InitRng() first.
 *                   For FIPS: must be FIPS-validated DRBG instance.
 * \return WOLFCOSE_SUCCESS or negative error code.
 *         WOLFCOSE_E_CRYPTO if wolfCrypt fails.
 */
WOLFCOSE_API int wc_CoseSign1_Sign(WOLFCOSE_KEY* key, int32_t alg,
    const uint8_t* kid, size_t kidLen,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen,
    WC_RNG* rng);

/**
 * \brief Verify a COSE_Sign1 message and extract the payload.
 *
 * \param key        WOLFCOSE_KEY with public key. Caller retains ownership.
 * \param in         Input COSE_Sign1 message.
 * \param inSz       Input message size.
 * \param extAad     External additional authenticated data (NULL if none).
 * \param extAadLen  External AAD length.
 * \param scratch    Working buffer for Sig_structure reconstruction.
 * \param scratchSz  Scratch buffer size.
 * \param hdr        Output: parsed COSE headers.
 * \param payload    Output: zero-copy pointer to payload within in buffer.
 * \param payloadLen Output: payload length.
 * \return WOLFCOSE_SUCCESS or negative error code.
 *         WOLFCOSE_E_COSE_SIG_FAIL if signature verification fails.
 */
WOLFCOSE_API int wc_CoseSign1_Verify(WOLFCOSE_KEY* key,
    const uint8_t* in, size_t inSz,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    const uint8_t** payload, size_t* payloadLen);

/* ---------------------------------------------------------------------------
 * COSE_Encrypt0 API (RFC 9052 Section 5.3)
 * --------------------------------------------------------------------------- */

/**
 * \brief Encrypt a payload producing a COSE_Encrypt0 message.
 *
 * \param key        WOLFCOSE_KEY with symmetric key material.
 * \param alg        Algorithm (WOLFCOSE_ALG_A128GCM/A192GCM/A256GCM).
 * \param iv         Initialization vector (12 bytes for AES-GCM).
 * \param ivLen      IV length.
 * \param payload    Plaintext payload.
 * \param payloadLen Payload length.
 * \param extAad     External additional authenticated data (NULL if none).
 * \param extAadLen  External AAD length.
 * \param scratch    Working buffer for Enc_structure.
 * \param scratchSz  Scratch buffer size.
 * \param out        Output buffer.
 * \param outSz      Output buffer size.
 * \param outLen     Output: bytes written to out.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_API int wc_CoseEncrypt0_Encrypt(WOLFCOSE_KEY* key, int32_t alg,
    const uint8_t* iv, size_t ivLen,
    const uint8_t* payload, size_t payloadLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    uint8_t* out, size_t outSz, size_t* outLen);

/**
 * \brief Decrypt a COSE_Encrypt0 message.
 *
 * \param key          WOLFCOSE_KEY with symmetric key material.
 * \param in           Input COSE_Encrypt0 message.
 * \param inSz         Input size.
 * \param extAad       External additional authenticated data (NULL if none).
 * \param extAadLen    External AAD length.
 * \param scratch      Working buffer for Enc_structure reconstruction.
 * \param scratchSz    Scratch buffer size.
 * \param hdr          Output: parsed COSE headers.
 * \param plaintext    Output buffer for decrypted payload.
 * \param plaintextSz  Plaintext buffer size.
 * \param plaintextLen Output: decrypted payload length.
 * \return WOLFCOSE_SUCCESS or negative error code.
 *         WOLFCOSE_E_COSE_DECRYPT_FAIL if decryption/authentication fails.
 */
WOLFCOSE_API int wc_CoseEncrypt0_Decrypt(WOLFCOSE_KEY* key,
    const uint8_t* in, size_t inSz,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    WOLFCOSE_HDR* hdr,
    uint8_t* plaintext, size_t plaintextSz, size_t* plaintextLen);

#ifdef __cplusplus
}
#endif

#endif /* WOLFCOSE_H */
