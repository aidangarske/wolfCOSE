/* wolfcose_internal.h
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

#ifndef WOLFCOSE_INTERNAL_H
#define WOLFCOSE_INTERNAL_H

#include <wolfcose/wolfcose.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>
#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
    #include <wolfssl/wolfcrypt/aes.h>
#endif
#if !defined(NO_HMAC)
    #include <wolfssl/wolfcrypt/hmac.h>
#endif
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    #include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ----- Secure memory zero -----
 * Portable secure-zero using a volatile pointer so the compiler cannot
 * optimise the writes away. Used in place of wc_ForceZero so wolfCOSE
 * links against the full 5.x range (wc_ForceZero only became a public
 * WOLFSSL_API symbol in v5.8.4). Definition lives in wolfcose.c. */
WOLFCOSE_LOCAL void wolfCose_ForceZero(void* mem, size_t len);

/* ----- Big-endian load/store macros (bit-shift only, no platform dependencies) ----- */

#define WOLFCOSE_STORE_BE16(buf, val) do {                     \
    (buf)[0] = (uint8_t)(((uint16_t)(val)) >> 8);             \
    (buf)[1] = (uint8_t)(((uint16_t)(val)) & 0xFFu);          \
} while (0)

#define WOLFCOSE_STORE_BE32(buf, val) do {                     \
    (buf)[0] = (uint8_t)(((uint32_t)(val)) >> 24);            \
    (buf)[1] = (uint8_t)(((uint32_t)(val)) >> 16);            \
    (buf)[2] = (uint8_t)(((uint32_t)(val)) >> 8);             \
    (buf)[3] = (uint8_t)(((uint32_t)(val)) & 0xFFu);          \
} while (0)

#define WOLFCOSE_STORE_BE64(buf, val) do {                     \
    (buf)[0] = (uint8_t)(((uint64_t)(val)) >> 56);            \
    (buf)[1] = (uint8_t)(((uint64_t)(val)) >> 48);            \
    (buf)[2] = (uint8_t)(((uint64_t)(val)) >> 40);            \
    (buf)[3] = (uint8_t)(((uint64_t)(val)) >> 32);            \
    (buf)[4] = (uint8_t)(((uint64_t)(val)) >> 24);            \
    (buf)[5] = (uint8_t)(((uint64_t)(val)) >> 16);            \
    (buf)[6] = (uint8_t)(((uint64_t)(val)) >> 8);             \
    (buf)[7] = (uint8_t)(((uint64_t)(val)) & 0xFFu);          \
} while (0)

#define WOLFCOSE_LOAD_BE16(buf)                                \
    ((uint16_t)(((uint16_t)(buf)[0] << 8) |                    \
                ((uint16_t)(buf)[1])))

#define WOLFCOSE_LOAD_BE32(buf)                                \
    ((uint32_t)(((uint32_t)(buf)[0] << 24) |                   \
                ((uint32_t)(buf)[1] << 16) |                   \
                ((uint32_t)(buf)[2] << 8)  |                   \
                ((uint32_t)(buf)[3])))

#define WOLFCOSE_LOAD_BE64(buf)                                \
    ((uint64_t)(((uint64_t)(buf)[0] << 56) |                   \
                ((uint64_t)(buf)[1] << 48) |                   \
                ((uint64_t)(buf)[2] << 40) |                   \
                ((uint64_t)(buf)[3] << 32) |                   \
                ((uint64_t)(buf)[4] << 24) |                   \
                ((uint64_t)(buf)[5] << 16) |                   \
                ((uint64_t)(buf)[6] << 8)  |                   \
                ((uint64_t)(buf)[7])))

/* ----- Internal CBOR head encode/decode ----- */

/**
 * \brief Encode a CBOR initial byte + argument.
 * RFC 8949 Section 3.1: initial_byte = (majorType << 5) | additional_info
 */
WOLFCOSE_LOCAL int wolfCose_CBOR_EncodeHead(WOLFCOSE_CBOR_CTX* ctx,
                                             uint8_t majorType, uint64_t val);

/**
 * \brief Decode a CBOR initial byte + argument. Sets item fields.
 * For bstr/tstr: item->data points into ctx->buf, item->dataLen set.
 */
WOLFCOSE_LOCAL int wolfCose_CBOR_DecodeHead(WOLFCOSE_CBOR_CTX* ctx,
                                             WOLFCOSE_CBOR_ITEM* item);

/* ----- COSE internal helpers ----- */

/**
 * \brief Encode a protected header map: {1: alg} as a bstr.
 * \param alg     Algorithm identifier.
 * \param buf     Output buffer.
 * \param bufSz   Buffer size.
 * \param outLen  Output: bytes written.
 */
WOLFCOSE_LOCAL int wolfCose_EncodeProtectedHdr(int32_t alg, uint8_t* buf,
                                                size_t bufSz, size_t* outLen);

/**
 * \brief Decode a protected header bstr (containing a CBOR map).
 * \param data     Raw bstr content.
 * \param dataLen  Length of bstr.
 * \param hdr      Output: parsed header fields.
 */
WOLFCOSE_LOCAL int wolfCose_DecodeProtectedHdr(const uint8_t* data,
                                                size_t dataLen,
                                                WOLFCOSE_HDR* hdr);

/**
 * \brief Decode an unprotected header map from the decoder context.
 * \param ctx  Decoder context positioned at the map.
 * \param hdr  Output: parsed header fields (merged with protected).
 */
WOLFCOSE_LOCAL int wolfCose_DecodeUnprotectedHdr(WOLFCOSE_CBOR_CTX* ctx,
                                                  WOLFCOSE_HDR* hdr);

/**
 * \brief Map COSE algorithm ID to wolfCrypt hash type.
 *        Central hash agility point -- extend here for PQC (SHA3, SHAKE).
 * \param alg      COSE algorithm ID.
 * \param hashType Output: wolfCrypt hash type.
 * \return WOLFCOSE_SUCCESS or WOLFCOSE_E_COSE_BAD_ALG.
 */
WOLFCOSE_LOCAL int wolfCose_AlgToHashType(int32_t alg,
                                           enum wc_HashType* hashType);

/**
 * \brief Get signature size for an algorithm.
 * \param alg    COSE algorithm ID.
 * \param sigSz  Output: signature size in bytes.
 * \return WOLFCOSE_SUCCESS or WOLFCOSE_E_COSE_BAD_ALG.
 */
WOLFCOSE_LOCAL int wolfCose_SigSize(int32_t alg, size_t* sigSz);

/**
 * \brief Get key size (coordinate size) for a COSE curve.
 * \param crv    COSE curve ID.
 * \param keySz  Output: coordinate size in bytes.
 * \return WOLFCOSE_SUCCESS or WOLFCOSE_E_COSE_BAD_ALG.
 */
WOLFCOSE_LOCAL int wolfCose_CrvKeySize(int32_t crv, size_t* keySz);

#ifdef HAVE_ECC
/**
 * \brief Map COSE curve ID to wolfCrypt ECC curve ID.
 * \param crv    COSE curve ID.
 * \param wcCrv  Output: wolfCrypt ECC_SECP* value.
 * \return WOLFCOSE_SUCCESS or WOLFCOSE_E_COSE_BAD_ALG.
 */
WOLFCOSE_LOCAL int wolfCose_CrvToWcCurve(int32_t crv, int* wcCrv);
#endif

/* -----
 * Unified structure builders (RFC 9052 Section 4.4, 5.3, 6.3)
 *
 * These shared helpers reduce code size by unifying:
 * - Sig_structure (Sign1/Sign): ["Signature1"|"Signature", body_prot, [sign_prot,] ext_aad, payload]
 * - MAC_structure (Mac0/Mac): ["MAC0"|"MAC", body_prot, ext_aad, payload]
 * - Enc_structure (Encrypt0/Encrypt): ["Encrypt0"|"Encrypt", body_prot, ext_aad]
 * ----- */

/**
 * \brief Build a ToBeSigned/ToBeMAced structure.
 *
 * This unified builder handles both Sig_structure and MAC_structure since they
 * share the same 4-element format: [context, body_protected, external_aad, payload]
 *
 * For multi-signer COSE_Sign, set signProtected non-NULL to create the 5-element
 * format: [context, body_protected, sign_protected, external_aad, payload]
 *
 * \param context         Context string ("Signature1", "Signature", "MAC0", "MAC")
 * \param contextLen      Length of context string
 * \param bodyProtected   Serialized protected headers (body-level)
 * \param bodyProtectedLen Length of body protected headers
 * \param signProtected   Signer-specific protected headers (NULL for Sign1/Mac0/Mac)
 * \param signProtectedLen Length of sign protected headers
 * \param extAad          External AAD (may be NULL)
 * \param extAadLen       Length of external AAD
 * \param payload         Payload bytes
 * \param payloadLen      Length of payload
 * \param scratch         Output buffer for structure
 * \param scratchSz       Size of output buffer
 * \param structLen       Output: bytes written
 * \return WOLFCOSE_SUCCESS or error code
 */
WOLFCOSE_LOCAL int wolfCose_BuildToBeSignedMaced(
    const char* context, size_t contextLen,
    const uint8_t* bodyProtected, size_t bodyProtectedLen,
    const uint8_t* signProtected, size_t signProtectedLen,
    const uint8_t* extAad, size_t extAadLen,
    const uint8_t* payload, size_t payloadLen,
    uint8_t* scratch, size_t scratchSz,
    size_t* structLen);

/**
 * \brief Build an Enc_structure for AEAD operations.
 *
 * Creates: [context, body_protected, external_aad]
 *
 * \param context         Context string ("Encrypt0" or "Encrypt")
 * \param contextLen      Length of context string
 * \param bodyProtected   Serialized protected headers
 * \param bodyProtectedLen Length of protected headers
 * \param extAad          External AAD (may be NULL)
 * \param extAadLen       Length of external AAD
 * \param scratch         Output buffer for structure
 * \param scratchSz       Size of output buffer
 * \param structLen       Output: bytes written
 * \return WOLFCOSE_SUCCESS or error code
 */
WOLFCOSE_LOCAL int wolfCose_BuildEncStructure(
    const char* context, size_t contextLen,
    const uint8_t* bodyProtected, size_t bodyProtectedLen,
    const uint8_t* extAad, size_t extAadLen,
    uint8_t* scratch, size_t scratchSz,
    size_t* structLen);

/**
 * \brief Get AEAD key length for any COSE AEAD algorithm.
 *        Dispatches across AES-GCM, ChaCha20-Poly1305, AES-CCM.
 * \param alg     COSE algorithm ID.
 * \param keyLen  Output: key length in bytes.
 * \return WOLFCOSE_SUCCESS or WOLFCOSE_E_COSE_BAD_ALG.
 */
WOLFCOSE_LOCAL int wolfCose_AeadKeyLen(int32_t alg, size_t* keyLen);

/**
 * \brief Get AEAD nonce length for any COSE AEAD algorithm.
 * \param alg       COSE algorithm ID.
 * \param nonceLen  Output: nonce length in bytes.
 * \return WOLFCOSE_SUCCESS or WOLFCOSE_E_COSE_BAD_ALG.
 */
WOLFCOSE_LOCAL int wolfCose_AeadNonceLen(int32_t alg, size_t* nonceLen);

/**
 * \brief Get AEAD tag length for any COSE AEAD algorithm.
 * \param alg     COSE algorithm ID.
 * \param tagLen  Output: tag length in bytes.
 * \return WOLFCOSE_SUCCESS or WOLFCOSE_E_COSE_BAD_ALG.
 */
WOLFCOSE_LOCAL int wolfCose_AeadTagLen(int32_t alg, size_t* tagLen);

#if !defined(NO_HMAC)
/**
 * \brief Map COSE HMAC algorithm ID to wolfCrypt HMAC type.
 * \param alg       COSE algorithm ID.
 * \param hmacType  Output: wolfCrypt hash type for HMAC.
 * \return WOLFCOSE_SUCCESS or WOLFCOSE_E_COSE_BAD_ALG.
 */
WOLFCOSE_LOCAL int wolfCose_HmacType(int32_t alg, int* hmacType);
#endif /* !NO_HMAC */

#ifdef HAVE_ECC
/**
 * \brief Sign a hash with ECC, producing raw r||s output.
 *        Wraps wolfCrypt DER signature -> fixed-width r||s conversion.
 * \param hash     Hash to sign.
 * \param hashLen  Hash length.
 * \param sigBuf   Output: raw r||s signature.
 * \param sigLen   In/Out: buffer size / bytes written.
 * \param coordSz  Coordinate size for this curve (e.g., 32 for P-256).
 * \param rng      Initialized WC_RNG.
 * \param eccKey   Caller-owned ECC key with private key.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_LOCAL int wolfCose_EccSignRaw(const uint8_t* hash, size_t hashLen,
                                        uint8_t* sigBuf, size_t* sigLen,
                                        size_t coordSz,
                                        WC_RNG* rng, ecc_key* eccKey);

/**
 * \brief Verify a raw r||s ECC signature.
 *        Converts raw r||s -> DER then calls wc_ecc_verify_hash.
 * \param sigBuf    Raw r||s signature.
 * \param sigLen    Signature length.
 * \param hash      Hash to verify against.
 * \param hashLen   Hash length.
 * \param coordSz   Coordinate size for this curve.
 * \param eccKey    Caller-owned ECC key with public key.
 * \param verified  Output: 1 if signature verified, 0 otherwise.
 * \return WOLFCOSE_SUCCESS or negative error code.
 */
WOLFCOSE_LOCAL int wolfCose_EccVerifyRaw(const uint8_t* sigBuf, size_t sigLen,
                                          const uint8_t* hash, size_t hashLen,
                                          size_t coordSz,
                                          ecc_key* eccKey, int* verified);
#endif /* HAVE_ECC */

#ifdef __cplusplus
}
#endif

#endif /* WOLFCOSE_INTERNAL_H */
