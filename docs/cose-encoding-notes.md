# wolfCOSE Encoding Notes (analyzed findings)

Records the rationale for two recipient-encoding findings that were analyzed
against RFC 9052 and intentionally left as-is or deferred.

## Recipient ciphertext for direct / ECDH-ES / direct key-wrap: empty bstr (not nil)

For recipients that carry no encrypted key (direct key `-6`, ECDH-ES direct,
and direct-mode entries), wolfCOSE encodes the `COSE_recipient` ciphertext
field as a zero-length byte string (`h''`).

This is correct and intentional. RFC 9052 Appendix C.3.1 (the "Direct ECDH"
example) and the cose-wg `Examples` repository both encode the recipient
ciphertext as empty `bstr` (`h''`), not the CBOR `nil` simple value. Changing
to `nil` would diverge from the RFC's own test vectors and break interop, so it
is deliberately not done.

## AES Key Wrap recipient: `alg` placement

wolfCOSE currently encodes the key-wrap algorithm in the recipient *protected*
header. RFC 9052 Section 3 permits a header parameter to appear in either the
protected or unprotected bucket, so this is conformant. For AES Key Wrap the
recipient headers are not cryptographically bound in either bucket, so there is
no security difference.

The canonical RFC/cose-wg examples place the key-wrap `alg` in the *unprotected*
bucket with a zero-length protected header. Aligning with that canonical form
is a worthwhile interoperability enhancement, but it requires reordering the
multi-recipient decrypt path (the algorithm is currently classified from the
protected header before the unprotected map is decoded). Because the current
encoding is already RFC-legal, that change is deferred to a dedicated, reviewed
update rather than bundled here. A robust implementation should accept `alg`
from either bucket on decode (Postel's law) when it is made.

## Decode strictness (API contract)

The hardening pass tightened several decode-side behaviors. These apply to all
public decode/verify/decrypt entry points (and, where noted, the generic
`wc_CBOR_Decode*` primitives), so integrators upgrading from older wolfCOSE
should be aware:

- **Preferred (shortest-form) CBOR is required on decode.** Per RFC 8949
  Section 4.2.1 (deterministic encoding, which COSE mandates for
  security-relevant structures), `wolfCose_CBOR_DecodeHead` rejects overlong
  integer/length/tag arguments for every major type except simple/float.
  Because it is the lowest-level primitive, this also applies to the generic
  `wc_CBOR_Decode*` APIs. wolfCOSE's own encoder always emits shortest form, so
  round-trips and RFC test vectors are unaffected; only non-preferred input
  from lenient third-party encoders is now rejected with
  `WOLFCOSE_E_CBOR_MALFORMED`.
- **`inSz` must equal the exact encoded object length.** Every verify/decrypt
  API (and `wc_CoseKey_Decode`) now rejects trailing bytes after the COSE
  object (RFC 8949 Section 5.3.1) with `WOLFCOSE_E_CBOR_MALFORMED`. Callers must
  pass the precise message length, not a fixed receive-buffer capacity.
- **EC2 / ephemeral coordinates must be exactly the curve size.** Per RFC 9053
  Section 7.1.1, `x`/`y`/`d` (and ephemeral `x`/`y`) must equal the curve
  coordinate size with leading zeros preserved; leading-zero-stripped (short)
  coordinates are rejected with `WOLFCOSE_E_COSE_BAD_HDR`, including on
  metadata-only EC2 key decode.
- **HMAC keys must meet the per-algorithm minimum.** HMAC-256/384/512 require a
  key of at least 32/48/64 bytes (RFC 9053 Section 3.1); shorter keys are
  rejected with `WOLFCOSE_E_COSE_KEY_TYPE`. Define
  `WOLFCOSE_ALLOW_SHORT_HMAC_KEY` to restore the legacy accept-any-length
  behavior.
- **MAC create requires an explicit payload.** `wc_CoseMac0_Create` /
  `wc_CoseMac_Create` reject an omitted payload (`payload == NULL` and
  `detachedPayload == NULL`) with `WOLFCOSE_E_INVALID_ARG`. To authenticate an
  empty payload, pass a non-NULL zero-length buffer.
