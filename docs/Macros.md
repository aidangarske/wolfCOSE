# Configuration Macros

wolfCOSE uses an opt-out design: all features are enabled by default, and you disable the ones you don't need with `WOLFCOSE_NO_*` defines. A more configurable model — opt-in tuning via `user_settings.h` for features that should not be on by default — is on the roadmap.

## Message Type Gates

### COSE_Sign1 (Single Signer)

| Define | Description | Default |
|--------|-------------|---------|
| `WOLFCOSE_SIGN1` | Enable COSE_Sign1 message type | Enabled |
| `WOLFCOSE_NO_SIGN1` | Disable COSE_Sign1 entirely | - |
| `WOLFCOSE_SIGN1_SIGN` | Enable Sign1 creation | Enabled |
| `WOLFCOSE_NO_SIGN1_SIGN` | Disable Sign1 creation | - |
| `WOLFCOSE_SIGN1_VERIFY` | Enable Sign1 verification | Enabled |
| `WOLFCOSE_NO_SIGN1_VERIFY` | Disable Sign1 verification | - |

### COSE_Encrypt0 (Symmetric Encryption)

| Define | Description | Default |
|--------|-------------|---------|
| `WOLFCOSE_ENCRYPT0` | Enable COSE_Encrypt0 message type | Enabled |
| `WOLFCOSE_NO_ENCRYPT0` | Disable COSE_Encrypt0 entirely | - |
| `WOLFCOSE_ENCRYPT0_ENCRYPT` | Enable Encrypt0 creation | Enabled |
| `WOLFCOSE_NO_ENCRYPT0_ENCRYPT` | Disable Encrypt0 creation | - |
| `WOLFCOSE_ENCRYPT0_DECRYPT` | Enable Encrypt0 decryption | Enabled |
| `WOLFCOSE_NO_ENCRYPT0_DECRYPT` | Disable Encrypt0 decryption | - |

### COSE_Mac0 (Symmetric MAC)

| Define | Description | Default |
|--------|-------------|---------|
| `WOLFCOSE_MAC0` | Enable COSE_Mac0 message type | Enabled |
| `WOLFCOSE_NO_MAC0` | Disable COSE_Mac0 entirely | - |
| `WOLFCOSE_MAC0_CREATE` | Enable Mac0 creation | Enabled |
| `WOLFCOSE_NO_MAC0_CREATE` | Disable Mac0 creation | - |
| `WOLFCOSE_MAC0_VERIFY` | Enable Mac0 verification | Enabled |
| `WOLFCOSE_NO_MAC0_VERIFY` | Disable Mac0 verification | - |

### COSE_Sign (Multi-Signer)

| Define | Description | Default |
|--------|-------------|---------|
| `WOLFCOSE_SIGN` | Enable COSE_Sign (multi-signer) | Enabled |
| `WOLFCOSE_NO_SIGN` | Disable COSE_Sign entirely | - |
| `WOLFCOSE_SIGN_SIGN` | Enable Sign creation | Enabled |
| `WOLFCOSE_NO_SIGN_SIGN` | Disable Sign creation | - |
| `WOLFCOSE_SIGN_VERIFY` | Enable Sign verification | Enabled |
| `WOLFCOSE_NO_SIGN_VERIFY` | Disable Sign verification | - |

### COSE_Encrypt (Multi-Recipient)

| Define | Description | Default |
|--------|-------------|---------|
| `WOLFCOSE_ENCRYPT` | Enable COSE_Encrypt (multi-recipient) | Enabled |
| `WOLFCOSE_NO_ENCRYPT` | Disable COSE_Encrypt entirely | - |
| `WOLFCOSE_ENCRYPT_ENCRYPT` | Enable Encrypt creation | Enabled |
| `WOLFCOSE_NO_ENCRYPT_ENCRYPT` | Disable Encrypt creation | - |
| `WOLFCOSE_ENCRYPT_DECRYPT` | Enable Encrypt decryption | Enabled |
| `WOLFCOSE_NO_ENCRYPT_DECRYPT` | Disable Encrypt decryption | - |

### COSE_Mac (Multi-Recipient)

| Define | Description | Default |
|--------|-------------|---------|
| `WOLFCOSE_MAC` | Enable COSE_Mac (multi-recipient) | Enabled |
| `WOLFCOSE_NO_MAC` | Disable COSE_Mac entirely | - |
| `WOLFCOSE_MAC_CREATE` | Enable Mac creation | Enabled |
| `WOLFCOSE_NO_MAC_CREATE` | Disable Mac creation | - |
| `WOLFCOSE_MAC_VERIFY` | Enable Mac verification | Enabled |
| `WOLFCOSE_NO_MAC_VERIFY` | Disable Mac verification | - |

---

## Key Distribution Gates

| Define | Description | Default |
|--------|-------------|---------|
| `WOLFCOSE_RECIPIENTS` | Enable recipient array support | Enabled |
| `WOLFCOSE_NO_RECIPIENTS` | Disable all multi-recipient support | - |
| `WOLFCOSE_KEY_WRAP` | Enable AES Key Wrap (A128KW, A192KW, A256KW) | Enabled* |
| `WOLFCOSE_NO_KEY_WRAP` | Disable AES Key Wrap | - |
| `WOLFCOSE_ECDH` | Enable ECDH key distribution | Enabled* |
| `WOLFCOSE_NO_ECDH` | Disable ECDH | - |
| `WOLFCOSE_ECDH_WRAP` | Enable ECDH-ES + AES-KW combined modes | Enabled* |
| `WOLFCOSE_NO_ECDH_WRAP` | Disable ECDH + wrap | - |

*Requires corresponding wolfSSL feature enabled (`HAVE_AES_KEYWRAP`, `HAVE_ECC`)

---

## CBOR Layer Gates

| Define | Description | Default |
|--------|-------------|---------|
| `WOLFCOSE_CBOR_ENCODE` | Enable CBOR encoding | Enabled |
| `WOLFCOSE_NO_CBOR_ENCODE` | Disable CBOR encoding | - |
| `WOLFCOSE_CBOR_DECODE` | Enable CBOR decoding | Enabled |
| `WOLFCOSE_NO_CBOR_DECODE` | Disable CBOR decoding | - |

---

## COSE_Key Gates

| Define | Description | Default |
|--------|-------------|---------|
| `WOLFCOSE_KEY_ENCODE` | Enable COSE_Key encoding | Enabled |
| `WOLFCOSE_NO_KEY_ENCODE` | Disable COSE_Key encoding | - |
| `WOLFCOSE_KEY_DECODE` | Enable COSE_Key decoding | Enabled |
| `WOLFCOSE_NO_KEY_DECODE` | Disable COSE_Key decoding | - |

---

## Size Configuration

| Define | Description | Default |
|--------|-------------|---------|
| `WOLFCOSE_MAX_SCRATCH_SZ` | Scratch buffer size for Sig_structure/Enc_structure | 512 |
| `WOLFCOSE_PROTECTED_HDR_MAX` | Max protected header size | 64 |
| `WOLFCOSE_CBOR_MAX_DEPTH` | Max CBOR nesting depth | 8 |

### Tuning for Constrained Targets

```c
/* In your user_settings.h or build flags: */

/* Reduce scratch buffer (default 512, minimum depends on payload size) */
#define WOLFCOSE_MAX_SCRATCH_SZ   256

/* Reduce protected header buffer */
#define WOLFCOSE_PROTECTED_HDR_MAX  32

/* Reduce CBOR nesting depth (default 8) */
#define WOLFCOSE_CBOR_MAX_DEPTH     4

/* For PQC (ML-DSA), increase scratch and signature buffers */
/* #define WOLFCOSE_MAX_SCRATCH_SZ  8192 */
/* #define WOLFCOSE_MAX_SIG_SZ      4627 */
```

---

## Example Build Configurations

### Sign-Only Build (Minimal)

```bash
make CFLAGS="-DWOLFCOSE_NO_ENCRYPT0 -DWOLFCOSE_NO_MAC0 -DWOLFCOSE_NO_ENCRYPT -DWOLFCOSE_NO_MAC"
```

### Verify-Only Build

```bash
make CFLAGS="-DWOLFCOSE_NO_SIGN1_SIGN -DWOLFCOSE_NO_ENCRYPT0_ENCRYPT -DWOLFCOSE_NO_MAC0_CREATE"
```

### Sign1-Only Build (Smallest)

```bash
make CFLAGS="-DWOLFCOSE_NO_ENCRYPT0 -DWOLFCOSE_NO_MAC0 -DWOLFCOSE_NO_SIGN -DWOLFCOSE_NO_ENCRYPT -DWOLFCOSE_NO_MAC"
```

### No Multi-Recipient Support

```bash
make CFLAGS="-DWOLFCOSE_NO_RECIPIENTS"
```

---

## wolfSSL Dependencies

wolfCOSE requires these wolfSSL features for full functionality:

| wolfSSL Define | wolfCOSE Feature |
|----------------|------------------|
| `HAVE_ECC` | ECDSA signing (ES256/ES384/ES512), ECDH key agreement |
| `HAVE_ED25519` | EdDSA signing (Ed25519) |
| `HAVE_ED448` | EdDSA signing (Ed448) |
| `WOLFSSL_HAVE_MLDSA` | ML-DSA post-quantum signing |
| `WC_RSA_PSS` | RSA-PSS signing (PS256/PS384/PS512) |
| `HAVE_AESGCM` | AES-GCM encryption |
| `HAVE_AESCCM` | AES-CCM encryption |
| `HAVE_CHACHA && HAVE_POLY1305` | ChaCha20-Poly1305 encryption |
| `HAVE_AES_CBC` | AES-CBC-MAC |
| `NO_HMAC` (NOT defined) | HMAC algorithms |
| `WOLFSSL_SHA384` | SHA-384 for ES384, HMAC-384 |
| `WOLFSSL_SHA512` | SHA-512 for ES512, HMAC-512 |
| `HAVE_AES_KEYWRAP` | AES Key Wrap distribution |
| `HAVE_HKDF` | ECDH-ES key derivation |

---

## Test and Example Gates

### Comprehensive Test Gates

Each comprehensive test file can be disabled:

| Define | Description |
|--------|-------------|
| `WOLFCOSE_NO_EXAMPLE_SIGN_ALL` | Disable sign_all.c |
| `WOLFCOSE_NO_EXAMPLE_ENCRYPT_ALL` | Disable encrypt_all.c |
| `WOLFCOSE_NO_EXAMPLE_MAC_ALL` | Disable mac_all.c |
| `WOLFCOSE_NO_EXAMPLE_ERRORS_ALL` | Disable errors_all.c |

Sub-gates within tests:

| Define | Description |
|--------|-------------|
| `WOLFCOSE_NO_SIGN_ALL_ES256` | Skip ES256 tests in sign_all |
| `WOLFCOSE_NO_SIGN_ALL_MULTI` | Skip multi-signer tests |
| `WOLFCOSE_NO_ENCRYPT_ALL_A128GCM` | Skip A128GCM tests |
| `WOLFCOSE_NO_MAC_ALL_HMAC256` | Skip HMAC-256 tests |

### Scenario Example Gates

| Define | Description |
|--------|-------------|
| `WOLFCOSE_NO_EXAMPLE_FIRMWARE_UPDATE` | Disable firmware_update.c |
| `WOLFCOSE_NO_EXAMPLE_MULTI_PARTY` | Disable multi_party_approval.c |
| `WOLFCOSE_NO_EXAMPLE_IOT_FLEET` | Disable iot_fleet_config.c |
| `WOLFCOSE_NO_EXAMPLE_SENSOR_ATTEST` | Disable sensor_attestation.c |
| `WOLFCOSE_NO_EXAMPLE_GROUP_BROADCAST` | Disable group_broadcast_mac.c |

---

## See Also

- [[Getting Started]]: Build instructions
- [[Algorithms]]: Supported algorithms with guards
- [[Testing]]: Test configuration
