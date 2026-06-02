# wolfCOSE MISRA C Deviations

This file records deviations from MISRA C:2012 / C:2023 for code paths that the
scanners flag but that are intentional. The core library (`src/`, `include/`)
targets full compliance; the deviations below are scoped to test and example
code, or to documented design decisions. Mirror updates here to the
[MISRA Compliance wiki](https://github.com/wolfSSL/wolfCOSE/wiki/MISRA-Compliance).

Scope note: `tests/` and `examples/` are not part of the shippable library and
are not constrained by the zero-allocation or strict-conformance rules that
apply to `src/` and `include/`.

## Deviations

### Rule 21.6 — Standard I/O functions (`printf`/`fprintf`)
- **Where:** `tests/`, `examples/`.
- **Rationale:** Test harnesses and demonstration programs report PASS/FAIL and
  human-readable status to the console. Library code under `src/` uses no
  standard I/O. Not applicable to shippable code.

### Rule 11.3 — Cast between pointer-to-object types (string literal → `const uint8_t*`)
- **Where:** `tests/`, `examples/` (e.g. `(const uint8_t*)"IETF"`).
- **Rationale:** COSE byte-string inputs are conventionally written as string
  literals in test vectors and demos. The cast is read-only and the data is
  never modified. Library APIs take `const uint8_t*`.

### Rule 21.15 — `memcmp` pointed-to type compatibility
- **Where:** `tests/` (comparing decoded `uint8_t` payloads against string
  literals).
- **Rationale:** Test-only equality checks of recovered payloads against
  expected literals; both operands are byte data.

### Rule 17.7 — Unused return value
- **Where:** `tests/`, `examples/` (e.g. `wc_CoseKey_Init`, `wc_ecc_init` in
  setup where failure is not the property under test).
- **Rationale:** Setup calls in tests/demos whose failure is not the assertion
  target. Library code checks every return value.

### Rule 10.4 — Mixed essential type in `sizeof(array) - 1`
- **Where:** `examples/`, `tests/` (string-literal payload lengths).
- **Rationale:** `sizeof(literal) - 1` to drop the NUL terminator is a common,
  well-understood idiom in demo/test payload setup.

### Rule 15.6 — Non-compound selection/iteration bodies
- **Where:** `examples/`, `tests/` (e.g. `if (demo_x() != 0) failures++;`).
- **Rationale:** Localized to test/demo control flow. Library code uses braces
  throughout.

### Rule 14.4 — `do { ... } while (0)` controlling expression not Boolean
- **Where:** Test/demo assertion and macro wrappers.
- **Rationale:** The `do { } while (0)` single-evaluation macro idiom is the
  standard, safest multi-statement macro form.

### Rule 15.1 — `goto` for cleanup
- **Where:** `tests/` (e.g. `goto cleanup;` in multi-key setup).
- **Rationale:** Test-only single-exit cleanup. New library code uses
  fallthrough cleanup; pre-existing library `goto cleanup` follows local style.

### Rule 19.2 — `union` keyword
- **Where:** `WOLFCOSE_KEY.key` (public header).
- **Rationale:** Tagged union discriminated by `kty`/`crv`; only the member
  matching the key type is accessed. A tagged union keeps the public key object
  small for embedded/zero-allocation use, which is a core wolfCOSE goal.

### Rule 1.2 — Language extensions (visibility / builtins)
- **Where:** `include/wolfcose/visibility.h` (`__declspec`/`__attribute__`),
  `examples/lifecycle_demo.c` (`__builtin_frame_address`).
- **Rationale:** Symbol visibility for shared-library builds requires
  compiler-specific attributes; the demo stack marker is diagnostic only and
  compiles to a no-op on non-GNU toolchains.
