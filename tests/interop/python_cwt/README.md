# python-cwt interop

`main.py` is a live peer for `interop_python_cwt.c`, using
[python-cwt](https://github.com/ritou/cwt) 3.3.0. The fully pinned
`requirements.txt` keeps the Python dependency set reproducible.

The target exchanges tagged `COSE_Encrypt` and `COSE_Mac` messages in both
directions for A128GCM direct use, ECDH-ES plus HKDF-SHA-256, A128KW, and
HMAC-256 direct MAC recipients. wolfCOSE emits an empty protected recipient
bucket with the algorithm in the unprotected header per RFC 9053 Section 6.2.1,
which python-cwt 3.3.0 both produces and accepts, so A128KW interoperates in
both directions. Every live case uses external AAD, checks the
decoded payload, and rejects a modified authenticated byte. The Python peer
also verifies and CBOR-decodes the RFC 9783 PSA attestation token,
independently exercising its EAT claims.
