---
layout: post
title: "What is COSE? A short introduction"
date: 2026-04-30 09:00:00
---

*CBOR Object Signing and Encryption: JOSE for the embedded world*

If you have ever shipped a JSON Web Token, you know the JOSE family: JWT, JWS, JWE. They are how the web does authenticated and encrypted structured data. JSON is verbose but human-readable, so the wire format trades bytes for ease of debugging. That tradeoff makes sense in a browser. It does not make sense in a sensor that talks over LoRaWAN with a 51-byte payload budget.

COSE stands for CBOR Object Signing and Encryption. It is defined in [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052) and [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053), and it is the JOSE equivalent for binary, constrained-device protocols.

## CBOR in One Paragraph

CBOR ([RFC 8949](https://www.rfc-editor.org/rfc/rfc8949)) is a binary serialization format that encodes the same data model as JSON (maps, arrays, integers, byte strings, text strings, booleans, null) but in fewer bytes and with no parsing ambiguity. A small integer is one byte. A short string is its UTF-8 bytes prefixed by a one-byte length. There are no quotes, commas, or whitespace to skip. A typical IoT message is 30 to 50 percent smaller in CBOR than the equivalent JSON, and a CBOR parser fits in 2 to 3 KB of code.

CBOR alone gives you compact serialization. It does not give you signatures, authentication, or encryption. That is what COSE adds.

## What COSE Is

COSE wraps cryptographic operations around a CBOR payload. The structures are intentionally close to their JOSE cousins. If you have written JWS, `COSE_Sign` will look familiar. The difference is that every byte is CBOR.

There are six COSE message types, in three pairs:

| Operation | One-actor variant | Many-actor variant |
|---|---|---|
| Digital signature | `COSE_Sign1` | `COSE_Sign` |
| Authenticated encryption | `COSE_Encrypt0` | `COSE_Encrypt` |
| Message authentication code | `COSE_Mac0` | `COSE_Mac` |

The `*0` variants are the simple case: one signer, or one recipient, or one MAC. The non-`0` variants support multiple actors. That covers multiple signers on the same payload (for hybrid classical/PQC migrations or multi-party approvals), multiple recipients on the same encrypted message (for fleet broadcast), or multiple MAC tags (for multicast groups).

A `COSE_Sign1` looks like this on the wire (CBOR diagnostic notation):

```
18([
  h'A10126',                  / protected: { 1: -7 (alg = ES256) } /
  { 4: h'766B65792D31' },     / unprotected: { 4: "vkey-1" (kid) } /
  h'48656C6C6F',              / payload: "Hello" /
  h'30450221...3045'          / signature: ECDSA over Sig_structure /
])
```

Three things to notice. First: the algorithm identifier is a small integer (-7 for ES256), not a string like JWT's `"ES256"`. Second: the protected header is itself CBOR-encoded inside a byte string, so the verifier signs over the exact bytes the signer used (no canonicalization disputes). Third: the whole structure is one CBOR array, four elements long. There is nothing to parse beyond CBOR.

## Why Not Just Use JOSE / JWT?

If you are writing a web service, you should probably use JOSE. JWT has tooling, library support in every language, and the verbosity does not matter when you are sending it over HTTP. COSE exists for the cases where JOSE does not fit:

- **Wire size matters.** Over LoRaWAN, BLE, or NB-IoT, every byte costs power and latency. A `COSE_Sign1` with a P-256 signature is roughly 90 bytes; the equivalent JWS with the same key is roughly 250.
- **You do not have a JSON parser.** A JSON parser plus a Base64URL decoder eats a meaningful chunk of a microcontroller with 256 KB of flash. CBOR + COSE fits in under 10 KB.
- **You do not have an X.509 stack.** JOSE assumes you can validate certificates. On a sensor running a bare-metal RTOS, you often cannot. COSE works with raw public keys (`kty=OKP` / `kty=EC2` / `kty=RSA`) referenced by `kid`, no PKI required.
- **Symmetric protocols matter.** A surprising amount of IoT runs on shared symmetric keys provisioned at manufacture. `COSE_Mac0` and `COSE_Encrypt0` map cleanly onto that. JOSE has the same primitives but is rarely deployed that way.

## Where COSE Shows Up in the Real World

- **Firmware signing.** [SUIT](https://datatracker.ietf.org/wg/suit/about/) (Software Updates for IoT) is the IETF working group standardizing OTA firmware updates for constrained devices. SUIT manifests are signed CBOR documents. `COSE_Sign1` covers single-vendor signing, and `COSE_Sign` covers multi-party (silicon vendor + OEM) approval.
- **Remote attestation.** [EAT](https://datatracker.ietf.org/wg/rats/about/) (Entity Attestation Tokens) is the CBOR/COSE equivalent of a JWT used to attest device boot state, key provenance, and TEE measurements.
- **CWT.** [CBOR Web Tokens](https://www.rfc-editor.org/rfc/rfc8392) are JWT but in CBOR. They are used in OAuth profiles for constrained environments.
- **Group communication.** OSCORE and Group OSCORE use COSE structures to authenticate CoAP messages between IoT devices and gateways.
- **Post-quantum migration.** As classical signatures are being replaced with ML-DSA and SLH-DSA, COSE is one of the few protocols that already has draft IANA assignments for PQC algorithm IDs.

## What You Need to Use COSE

- A CBOR encoder/decoder (RFC 8949). Many exist; sizes vary from ~2 KB (NanoCBOR, wolfCOSE's built-in engine) to ~25 KB (QCBOR).
- A crypto library that implements the algorithms you want to use. ECDSA P-256 covers most of what is deployed today; AES-GCM and HMAC-SHA-256 are the common symmetric choices; ML-DSA is the PQC option.
- A COSE library that wires the two together. The current C / C++ options are `t_cose` (Sign1 only, requires QCBOR + OpenSSL or mbedTLS), `COSE-C` (full message set, requires cn-cbor + OpenSSL), `libcose` (Sign1 only, libsodium backend), and [wolfCOSE](https://github.com/aidangarske/wolfCOSE) (full message set, wolfCrypt backend, no malloc).

## Further Reading

- [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052) defines the COSE structures and processing rules.
- [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053) specifies the initial COSE algorithm set.
- [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949) defines CBOR, the binary serialization format used by COSE.
- The [IANA COSE registry](https://www.iana.org/assignments/cose/cose.xhtml) lists assigned algorithm identifiers and parameter values.
- The [SUIT working group](https://datatracker.ietf.org/wg/suit/about/) develops firmware update standards built on COSE.

If you have a specific use case (firmware signing, attestation, fleet config) and you are wondering whether COSE is the right tool, the short answer is: probably yes, if your devices are constrained. The longer answer depends on what crypto stack you already have and how much flash you have left.
