# wolfCOSE ⇄ go-cose Interop

This test uses [Veraison go-cose](https://github.com/veraison/go-cose) as an
independent Go oracle for tagged ES256 `COSE_Sign1` messages. Both directions
are live: wolfCOSE signs and go-cose verifies, then go-cose signs and wolfCOSE
verifies. Each verifier also rejects a modified signature.

It also verifies the RFC 9783 Appendix A ES256 PSA token with go-cose and
uses Go's CBOR decoder to decode its standard EAT claims: UEID, nonce, profile,
and boot seed. The wolfCOSE C test covers the PSA-specific claims in the same
token.

The P-256 private key matches the deterministic fixture from the t_cose
interop suite. It is never a production key.

## Run

Go 1.21 or later is required.

```bash
make interop-go-cose
```

go-cose currently provides the Sign and Sign1 coverage used here. `Mac0` and
`Encrypt0` remain covered by the t_cose wire suite and the project tests.
