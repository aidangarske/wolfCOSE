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
