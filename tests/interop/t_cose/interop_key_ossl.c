/* interop_key_ossl.c — t_cose-side asymmetric key loader, OpenSSL backend (test-only).
 *
 * Isolated from the wolfCrypt side: this TU includes OpenSSL + t_cose's
 * backend-agnostic key header ONLY (no wolfSSL), so the two crypto stacks never
 * collide in one translation unit (they both define SHA256 etc.). Loads the same
 * shared DER bytes the wolfCrypt side uses, via d2i_AutoPrivateKey (SEC1, PKCS#1
 * and PKCS#8 are all auto-detected). Symmetric keys are handled in the harness
 * via the backend-agnostic t_cose_key_init_symmetric().
 *
 * Copyright (C) 2026 wolfSSL Inc.  GPL-3.0-or-later (see wolfCOSE LICENSE).
 */

#include "t_cose/t_cose_key.h"
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "interop_cases.h"
#include "interop_keys.h"

struct t_cose_key interop_tcose_load(int key_id);
void              interop_tcose_free(struct t_cose_key key);

static const unsigned char* der_for(int key_id, long* len)
{
    switch (key_id) {
        case IT_KEY_P256:    *len = (long)p256_der_len;    return p256_der;
        case IT_KEY_P384:    *len = (long)p384_der_len;    return p384_der;
        case IT_KEY_P521:    *len = (long)p521_der_len;    return p521_der;
        case IT_KEY_ED25519: *len = (long)ed25519_der_len; return ed25519_der;
        case IT_KEY_ED448:   *len = (long)ed448_der_len;   return ed448_der;
        case IT_KEY_RSA2048: *len = (long)rsa2048_der_len; return rsa2048_der;
        default:             *len = 0;                     return NULL;
    }
}

struct t_cose_key interop_tcose_load(int key_id)
{
    struct t_cose_key k;
    long len = 0;
    const unsigned char* der = der_for(key_id, &len);
    const unsigned char* p = der;

    k.key.ptr = NULL;
    if (der != NULL) {
        k.key.ptr = d2i_AutoPrivateKey(NULL, &p, len);
    }
    return k;
}

void interop_tcose_free(struct t_cose_key key)
{
    EVP_PKEY_free((EVP_PKEY*)key.key.ptr);
}
