# Configuration Macros

wolfCOSE has two configuration modes. The default is an opt-out full build: every algorithm wolfSSL provides is enabled, and you strip what you don't need with `WOLFCOSE_NO_*` defines. Alternatively, `WOLFCOSE_LEAN` switches to an opt-in core build and you add extensions with `WOLFCOSE_ENABLE_*`. See [Lean Configuration Layer](#lean-configuration-layer).

## Lean Configuration Layer

Defining `WOLFCOSE_LEAN` keeps only the core — `COSE_Sign1`/`Encrypt0`/`Mac0` with ES256, AES-GCM, and HMAC-SHA256 — and turns every other algorithm into an opt-in. This is the recommended starting point for constrained targets.

| Define | Description |
|--------|-------------|
| `WOLFCOSE_LEAN` | Core-only base; all extensions become opt-in |
| `WOLFCOSE_ENABLE_ALL` | Re-enable every extension on top of `WOLFCOSE_LEAN` |
| `WOLFCOSE_ENABLE_<X>` | Opt in a single extension (see list below) |

Extension names for `WOLFCOSE_ENABLE_<X>`: `ES384`, `ES512`, `EDDSA`, `ED448`, `RSAPSS`, `MLDSA`, `HMAC384`, `HMAC512`, `AESCCM`, `CHACHA20`, `AESMAC`, `AESWRAP`, `ECDH_ES`, `SIGN` (multi-signer), `ENCRYPT` (multi-recipient), `MAC` (multi-recipient).

An extension is compiled in when it is explicitly enabled (`WOLFCOSE_ENABLE_<X>` or `WOLFCOSE_ENABLE_ALL`), or — in a non-lean build — when wolfSSL provides the primitive and it is not opted out with `WOLFCOSE_NO_<X>`. Enabling an extension wolfSSL cannot provide is a compile error. The resolved state is exposed internally as read-only `WOLFCOSE_HAVE_<X>` gates (e.g. `WOLFCOSE_HAVE_MLDSA`); sources, tests, and examples compile against those, so you set `WOLFCOSE_ENABLE_*`/`WOLFCOSE_NO_*`, not `WOLFCOSE_HAVE_*`.

## Algorithm Gates

Per-algorithm opt-outs for the default (non-lean) build. Each also has a `WOLFCOSE_ENABLE_<X>` form for lean opt-in. `ES256`, `AESGCM`, and `HMAC256` form the lean core and stay on unless explicitly opted out.

| Opt-out | Algorithm | wolfSSL requirement |
|---------|-----------|---------------------|
| `WOLFCOSE_NO_ES256` | ECDSA P-256 (ES256) | `HAVE_ECC` |
| `WOLFCOSE_NO_ES384` | ECDSA P-384 (ES384) | `HAVE_ECC` + `WOLFSSL_SHA384` |
| `WOLFCOSE_NO_ES512` | ECDSA P-521 (ES512) | `HAVE_ECC` + `WOLFSSL_SHA512` |
| `WOLFCOSE_NO_EDDSA` | Ed25519 | `HAVE_ED25519` |
| `WOLFCOSE_NO_ED448` | Ed448 | `HAVE_ED448` |
| `WOLFCOSE_NO_RSAPSS` | RSA-PSS (PS256/384/512) | `WC_RSA_PSS` |
| `WOLFCOSE_NO_MLDSA` | ML-DSA (FIPS 204) | `WOLFSSL_HAVE_MLDSA` |
| `WOLFCOSE_NO_AESGCM` | AES-GCM | `HAVE_AESGCM` |
| `WOLFCOSE_NO_AESCCM` | AES-CCM | `HAVE_AESCCM` |
| `WOLFCOSE_NO_CHACHA20` | ChaCha20-Poly1305 | `HAVE_CHACHA` + `HAVE_POLY1305` |
| `WOLFCOSE_NO_HMAC256` | HMAC-SHA256 | HMAC (`NO_HMAC` unset) |
| `WOLFCOSE_NO_HMAC384` | HMAC-SHA384 | `WOLFSSL_SHA384` |
| `WOLFCOSE_NO_HMAC512` | HMAC-SHA512 | `WOLFSSL_SHA512` |
| `WOLFCOSE_NO_AESMAC` | AES-CBC-MAC | `HAVE_AES_CBC` |

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
| `WOLFCOSE_NO_RECIPIENTS` | Disable all multi-recipient support (COSE_Encrypt/COSE_Mac) | - |
| `WOLFCOSE_NO_AESWRAP` | Disable AES Key Wrap (A128KW, A192KW, A256KW) | - |
| `WOLFCOSE_NO_ECDH_ES` | Disable ECDH-ES key agreement | - |
| `WOLFCOSE_ENABLE_AESWRAP` | Opt in AES Key Wrap under `WOLFCOSE_LEAN` | - |
| `WOLFCOSE_ENABLE_ECDH_ES` | Opt in ECDH-ES under `WOLFCOSE_LEAN` | - |

Resolved internally as read-only `WOLFCOSE_KEY_WRAP`, `WOLFCOSE_ECDH`, and `WOLFCOSE_ECDH_WRAP` gates. Requires the matching wolfSSL feature (`HAVE_AES_KEYWRAP`; `HAVE_ECC` + `HAVE_HKDF` for ECDH-ES) and at least one multi-recipient message type enabled.

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
| `WOLFCOSE_MIN_BUFFERS` | Trim the working set to the minimum that fits the enabled algorithms | - |

### `WOLFCOSE_MIN_BUFFERS`

One define that trims the caller working set to the minimum that still fits the enabled algorithms. It tightens the CBOR parsing limits (`WOLFCOSE_CBOR_MAX_DEPTH` 8→6, `WOLFCOSE_MAX_MAP_ITEMS` 16→8) and keeps the algorithm-driven signature/scratch floors, which track the largest enabled signature algorithm:

| Enabled signature algorithm | `WOLFCOSE_MAX_SIG_SZ` | `WOLFCOSE_MAX_SCRATCH_SZ` |
|---|---|---|
| ES256/384/512, EdDSA (Ed25519/Ed448) | 132 | 512 |
| RSA-PSS (PS256/384/512) | 512 | 512 |
| ML-DSA-44/65/87 | 4627 | 8192 |

Because the floor follows the algorithm, `WOLFCOSE_MIN_BUFFERS` stays valid with any algorithm — ML-DSA and RSA-PSS simply use that algorithm's floor rather than the ECC floor (ML-DSA-87's 4627-byte signature is the largest wolfCOSE supports). It stays zero-heap and shrinks buffers, not stack frames. An explicit `-D` override of any individual limit takes precedence.

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

#### Tuning the wolfCrypt backend

The limits above are wolfCOSE's working set. Shrinking the wolfCrypt backend
itself — big-number math, AES tables, flash and stack footprint — is a wolfSSL
build concern, not a wolfCOSE one. See the
[wolfSSL Tuning Guide](https://www.wolfssl.com/documentation/manuals/wolfssl-tuning-guide/index.html)
and the [wolfSSL Manual](https://www.wolfssl.com/documentation/manuals/wolfssl/)
for the relevant options (e.g. `--enable-sp-math-all`, `WOLFSSL_SP_SMALL`,
`WOLFSSL_AES_SMALL_TABLES`). Build your application with
`-ffunction-sections -fdata-sections -Wl,--gc-sections` so only the COSE
functions you call are linked.

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
