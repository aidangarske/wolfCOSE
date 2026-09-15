/* Minimal synthetic wolfSSL feature set for HPKE prerequisite gate tests. */
#ifndef WOLFCOSE_TEST_HPKE_USER_SETTINGS_H
#define WOLFCOSE_TEST_HPKE_USER_SETTINGS_H

#define HAVE_HPKE
#define HAVE_ECC
#define HAVE_AESGCM
#define WOLFSSL_AES_128

#if !defined(WOLFCOSE_TEST_NO_HKDF)
    #define HAVE_HKDF
#endif

#if defined(WOLFCOSE_TEST_NO_ECC_DHE)
    #define NO_ECC_DHE
#else
    #define HAVE_ECC_DHE
#endif

#endif /* WOLFCOSE_TEST_HPKE_USER_SETTINGS_H */
