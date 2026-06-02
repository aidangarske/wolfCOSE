# Testing

wolfCOSE includes comprehensive testing infrastructure for unit tests, algorithm coverage, code coverage, and failure injection testing. Code coverage is enforced by CI: `wolfcose.c` requires 99.30% minimum and `wolfcose_cbor.c` requires 100%. These thresholds are validated on every push and PR to ensure coverage doesn't regress. 

## Running Tests

### Basic Unit Tests

```bash
make test
```

This runs the full test suite including:
- CBOR encoding/decoding tests (RFC 8949 Appendix A vectors)
- COSE Sign1/Encrypt0/Mac0 tests
- COSE Sign/Encrypt/Mac multi-party tests
- Interoperability tests with COSE Working Group vectors

### CLI Tool Tests

```bash
make tool-test
```

Round-trip self-tests for all 17 supported CLI algorithms. Each algorithm is tested with key generation, operation, and verification.

### Comprehensive Algorithm Tests

```bash
make comprehensive
```

Runs ~240 algorithm combination tests covering:
- All signature algorithms with various payloads
- All encryption algorithms with various key sizes
- All MAC algorithms
- Multi-signer and multi-recipient combinations
- Error handling and edge cases

### Scenario Examples

```bash
make scenarios
```

Runs real-world scenario examples:
- Firmware signing with ML-DSA
- Multi-party approval workflows
- IoT fleet configuration
- Sensor attestation
- Group broadcast MAC

---

## Code Coverage

### Running Coverage

```bash
make coverage
```

This compiles with gcov instrumentation and runs tests, producing coverage reports.

### Coverage Targets

| Component | Target |
|-----------|--------|
| `wolfcose.c` | 99% minimum |
| `wolfcose_cbor.c` | 100% minimum |

### Coverage with Failure Injection

```bash
make coverage-force-failure
```

This enables additional coverage by testing error paths that normally require wolfCrypt internal failures.

---

## Force Failure Testing

wolfCOSE includes a failure injection system for testing error paths that are difficult to reach through normal testing.

The `WOLFCOSE_FORCE_FAILURE` build flag enables controlled injection of failures at specific points in the code. This allows testing of:

- Crypto operation failures (signature, encryption, decryption, MAC)
- Key operation failures
- Memory/buffer errors
- Internal state errors

### Production Builds

The force failure system compiles out completely in production builds. When `WOLFCOSE_FORCE_FAILURE` is not defined:

- All failure injection code is excluded
- `wolfForceFailure_Check()` always returns 0
- No runtime overhead

---

## CI Pipeline

wolfCOSE runs the following CI checks on every push and pull request:

### Build and Test Matrix

| Environment | Compilers |
|-------------|-----------|
| Ubuntu (latest + 22.04) | GCC 10, 11, 12, 13, 14 |
| Ubuntu (latest + 22.04) | Clang 14, 15, 16, 17, 18 |
| macOS | Xcode default |

### Test Stages

1. **Build**: Compile library and tests
2. **Unit Tests**: Run CBOR and COSE test suites
3. **Comprehensive Tests**: ~240 algorithm combination tests
4. **Scenario Examples**: Real-world workflow tests
5. **Tool Tests**: CLI round-trip tests (17 algorithms)

### Static Analysis

| Tool | Purpose |
|------|---------|
| cppcheck | Static code analysis |
| Clang Static Analyzer | Data flow analysis |
| GCC `-fanalyzer` | GCC's built-in analyzer |
| Advanced Internal Static Analysis | Security Audit |
| In PR Opus 4.6 Diff review with wolfSSL internal review bot | Security Audit |

### Coverity Scan

Nightly defect analysis via [Coverity Scan](https://scan.coverity.com/projects/wolfcose).

[![Coverity Scan Build Status](https://scan.coverity.com/projects/32918/badge.svg)](https://scan.coverity.com/projects/wolfcose)

---

## Test File Structure

```
tests/
  test_cbor.c        # CBOR vectors (RFC 8949 Appendix A) + round-trip
  test_cose.c        # COSE Sign1/Encrypt0/Mac0/Sign/Encrypt/Mac tests
  test_interop.c     # Interoperability tests with RFC vectors
  test_main.c        # Test harness (CI exit codes)
  force_failure.c    # Failure injection implementation
  force_failure.h    # Failure injection API
  vectors/           # Test vectors from COSE Working Group
```

### Test Categories in test_cose.c

| Category | Description |
|----------|-------------|
| Sign1 Tests | Single-signer signature creation and verification |
| Encrypt0 Tests | Symmetric encryption and decryption |
| Mac0 Tests | Symmetric MAC creation and verification |
| Sign Tests | Multi-signer messages |
| Encrypt Tests | Multi-recipient encryption |
| Mac Tests | Multi-recipient MAC |
| Key Tests | COSE_Key encoding and decoding |
| Error Tests | Invalid inputs, tampered messages |
| Detached Payload Tests | Messages with external payloads |
| External AAD Tests | Additional authenticated data |

---

## Test Vectors

The `tests/vectors/` directory contains test vectors from:
- COSE Working Group examples
- RFC 9052 examples
- Custom edge case vectors

Vector format is typically CBOR diagnostic notation or hex dumps with expected outputs.

---

## See Also

- [[Getting Started]]: Build instructions
- [[Macros]]: Test configuration macros
- [[Project Structure]]: Source file layout
