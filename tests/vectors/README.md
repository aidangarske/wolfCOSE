# COSE Test Vectors

This directory contains test vectors for validating wolfCOSE's COSE implementation.

## Sources

Test vectors are derived from:
- [COSE Working Group Examples](https://github.com/cose-wg/Examples) - RFC 9052/9053 reference vectors
- [RFC 8152](https://datatracker.ietf.org/doc/html/rfc8152) - COSE Appendix C examples

## Directory Structure

```
vectors/
├── sign1/          # COSE_Sign1 test vectors
├── encrypt0/       # COSE_Encrypt0 test vectors
├── mac0/           # COSE_Mac0 test vectors
└── README.md       # This file
```

## Test Vector Format

Test vectors are embedded as C arrays in `tests/test_interop.c` for simplicity
and to avoid runtime file I/O dependencies. Each vector includes:
- Input key material (COSE_Key format or raw bytes)
- Expected COSE message (CBOR-encoded)
- Expected payload
- Algorithm identifier

## License

COSE Working Group examples are provided under their original license terms.
Test vectors derived from RFCs are public domain per IETF policy.

## Adding New Vectors

To add new test vectors:
1. Obtain the CBOR-encoded test vector
2. Convert to C hex array format
3. Add to appropriate test function in `test_interop.c`
4. Include expected values for verification
