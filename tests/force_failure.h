/* force_failure.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * Forced failure injection layer for wolfCrypt functions.
 * This allows testing of error handling paths without rebuilding wolfSSL
 * with WOLFSSL_FORCE_MALLOC_FAIL_TEST.
 *
 * Usage:
 *   1. Build with -DWOLFCOSE_FORCE_FAILURE
 *   2. Call wolfForceFailure_Set(WOLF_FAIL_ECC_SIGN) before the test
 *   3. Call the wolfCOSE API that uses wc_ecc_sign_hash internally
 *   4. The injection point intercepts the call and returns an error
 *   5. Verify the wolfCOSE API returns the expected error code
 *
 * See FORCE_FAILURE.md for full documentation.
 */

#ifndef WOLFCOSE_FORCE_FAILURE_H
#define WOLFCOSE_FORCE_FAILURE_H

#ifdef WOLFCOSE_FORCE_FAILURE

/* Failure injection points - one for each wolfCrypt function we need to fail */
typedef enum {
    WOLF_FAIL_NONE = 0,

    /* ECC failures */
    WOLF_FAIL_ECC_SIGN,              /* wc_ecc_sign_hash */
    WOLF_FAIL_ECC_SIG_TO_RS,         /* wc_ecc_sig_to_rs */
    WOLF_FAIL_ECC_RS_TO_SIG,         /* wc_ecc_rs_raw_to_sig */
    WOLF_FAIL_ECC_VERIFY,            /* wc_ecc_verify_hash */
    WOLF_FAIL_ECC_EXPORT_X963,       /* wc_ecc_export_x963 */
    WOLF_FAIL_ECC_IMPORT_X963,       /* wc_ecc_import_x963 */
    WOLF_FAIL_ECC_EXPORT_PRIVATE,    /* wc_ecc_export_private_only */

    /* RSA failures */
    WOLF_FAIL_RSA_ENCRYPT_SIZE,      /* wc_RsaEncryptSize */
    WOLF_FAIL_RSA_EXPORT_KEY,        /* wc_RsaExportKey */
    WOLF_FAIL_RSA_PUBLIC_DECODE,     /* wc_RsaPublicKeyDecode */
    WOLF_FAIL_RSA_PRIVATE_DECODE,    /* RsaPrivateKeyDecode */
    WOLF_FAIL_RSA_SSL_SIGN,          /* wc_RsaPSS_Sign */
    WOLF_FAIL_RSA_SSL_VERIFY,        /* wc_RsaPSS_Verify */

    /* EdDSA failures */
    WOLF_FAIL_ED25519_SIGN,          /* wc_ed25519_sign_msg */
    WOLF_FAIL_ED25519_VERIFY,        /* wc_ed25519_verify_msg */
    WOLF_FAIL_ED25519_EXPORT_PUB,    /* wc_ed25519_export_public */
    WOLF_FAIL_ED25519_EXPORT_PRIV,   /* wc_ed25519_export_private_only */
    WOLF_FAIL_ED25519_IMPORT_PUB,    /* wc_ed25519_import_public */
    WOLF_FAIL_ED25519_IMPORT_PRIV,   /* wc_ed25519_import_private_key */
    WOLF_FAIL_ED448_SIGN,            /* wc_ed448_sign_msg */
    WOLF_FAIL_ED448_VERIFY,          /* wc_ed448_verify_msg */
    WOLF_FAIL_ED448_EXPORT_PUB,      /* wc_ed448_export_public */
    WOLF_FAIL_ED448_EXPORT_PRIV,     /* wc_ed448_export_private_only */
    WOLF_FAIL_ED448_IMPORT_PUB,      /* wc_ed448_import_public */
    WOLF_FAIL_ED448_IMPORT_PRIV,     /* wc_ed448_import_private_key */

    /* Dilithium failures */
    WOLF_FAIL_DILITHIUM_SIGN,        /* wc_dilithium_sign_msg */
    WOLF_FAIL_DILITHIUM_VERIFY,      /* wc_dilithium_verify_msg */
    WOLF_FAIL_DILITHIUM_EXPORT_PUB,  /* wc_dilithium_export_public */
    WOLF_FAIL_DILITHIUM_EXPORT_PRIV, /* wc_dilithium_export_private */
    WOLF_FAIL_DILITHIUM_IMPORT_PUB,  /* wc_dilithium_import_public */
    WOLF_FAIL_DILITHIUM_IMPORT_PRIV, /* wc_dilithium_import_private */

    /* HMAC failures */
    WOLF_FAIL_HMAC_SET_KEY,          /* wc_HmacSetKey */
    WOLF_FAIL_HMAC_UPDATE,           /* wc_HmacUpdate */
    WOLF_FAIL_HMAC_FINAL,            /* wc_HmacFinal */

    /* AES failures */
    WOLF_FAIL_AES_GCM_SET_KEY,       /* wc_AesGcmSetKey */
    WOLF_FAIL_AES_GCM_ENCRYPT,       /* wc_AesGcmEncrypt */
    WOLF_FAIL_AES_GCM_DECRYPT,       /* wc_AesGcmDecrypt */
    WOLF_FAIL_AES_CCM_SET_KEY,       /* wc_AesCcmSetKey */
    WOLF_FAIL_AES_CCM_ENCRYPT,       /* wc_AesCcmEncrypt */
    WOLF_FAIL_AES_CCM_DECRYPT,       /* wc_AesCcmDecrypt */

    /* ECDH failures */
    WOLF_FAIL_ECDH_SHARED_SECRET,    /* wc_ecc_shared_secret */

    /* Hash failures */
    WOLF_FAIL_HASH,                  /* wc_Hash */

    WOLF_FAIL_COUNT
} WolfForceFailure;

/* Set the next failure point. After the failure is triggered, it resets. */
void wolfForceFailure_Set(WolfForceFailure failure);

/* Get current failure point (for internal use) */
WolfForceFailure wolfForceFailure_Get(void);

/* Clear failure and reset to no failure */
void wolfForceFailure_Clear(void);

/* Check if a specific failure is set and consume it (returns 1 if set) */
int wolfForceFailure_Check(WolfForceFailure failure);

#endif /* WOLFCOSE_FORCE_FAILURE */

#endif /* WOLFCOSE_FORCE_FAILURE_H */
