/* interop_cases.h — shared identifiers for the wolfCOSE<->t_cose interop matrix.
 * Both the wolfCrypt-side harness and the t_cose-side key loader include this so
 * a key id means the same thing on both sides. Test-only.
 */
#ifndef WOLFCOSE_INTEROP_CASES_H
#define WOLFCOSE_INTEROP_CASES_H

/* Which fixed key fixture a case uses (see interop_keys.h). */
enum it_key {
    IT_KEY_P256 = 0,
    IT_KEY_P384,
    IT_KEY_P521,
    IT_KEY_ED25519,
    IT_KEY_ED448,
    IT_KEY_RSA2048,
    IT_KEY_SYM16,
    IT_KEY_SYM24,
    IT_KEY_SYM32,
    IT_KEY_SYM48,
    IT_KEY_SYM64
};

#endif /* WOLFCOSE_INTEROP_CASES_H */
