# PSA and EAT implementation checklist

This is the working checklist for the RFC 9783 PSA token implementation.
Items move to complete only after their associated code and test evidence are
present.

## Core protocol

- [x] Isolate the work from the user's existing dirty worktree.
- [x] Add an optional RFC 8949 variation tolerant decode path while retaining
      strict decode as the default COSE API behavior.
- [x] Add tagged COSE Sign1 and Mac0 envelope authentication before claim use.
- [x] Add current `tag:psacertified.org,2023:psa#tfm` claim issuance.
- [x] Add current and `PSA_IOT_PROFILE_1` claim consumption.
- [x] Complete legacy-profile differences, including optional legacy profile,
      fixed boot seed, old certification reference, and no-measurements form.
- [x] Enforce direct, attached token boundaries and document certificate-chain
      handling.
- [x] Validate all caller-visible API argument and lifetime rules.

## wolfTrust and PSA integration

- [x] Provide a raw-token verifier suitable for
      `psa_initial_attest_get_token()` output.
- [x] Provide UEID based caller-owned key resolution.
- [x] Verify the delegated/external signer path accepts a NULL RNG and test it
      through the PSA issuer wrapper.
- [x] Add a focused PSA client token-acquisition handoff example to the
      integration guide without a wolfCOSE PSA-library dependency.

## Verification and interop

- [x] Unit-test current Sign1, Mac0, nonce enforcement, UEID resolution,
      claim duplicates, and tolerant claims decoding.
- [x] Add RFC 9783 Appendix A Sign1 and Mac0 vectors.
- [x] Add negative envelope tests: untagged/CWT-tagged/detached/x5chain,
      unsupported algorithms, malformed and indefinite CBOR.
- [x] Exercise ES256/384/512 and HMAC 256/384/512 where configured.
- [x] Add a verify-only, full `#tfm` receiver build/test with no creation API.
- [x] Extend t_cose wire interop with profile payload coverage in both
      directions.
- [x] Run a dedicated Codex-backed Skoll RFC 9783 conformance scan with no
      findings at any severity.
- [x] Run RFC 9783's iat-verifier-generated Appendix A vectors in CI and
      label them as external static vectors rather than a live tool runner.
- [x] Update coverage instrumentation and thresholds for the new source.
- [x] Run unit, C99, lean, sanitizer, macro-gate, and t_cose interop gates.
- [x] Keep variation-tolerant decoding scoped to COSE verification operations,
      without putting profile state in the PSA/EAT public API.
- [x] Enforce RFC 9783 Section 5.2 `#tfm` receiver capability as a derived
      full-profile gate; reject partial standard-profile consumption while
      allowing an attester to issue with one RFC-permitted protection path.
- [x] Derive ECDSA support from the concrete wolfSSL P-256, P-384, and P-521
      curve configuration, including `ECC_USER_CURVES` and `ECC_MIN_KEY_SZ`
      boundary feature-matrix tests.
- [x] Recognize disabled and mixed standardized claim namespaces as profile
      errors rather than skipping them as extensions.
- [x] Prove variation-tolerant authenticated decoding for non-preferred claim
      maps, byte strings, arrays, unsigned values, and signed values while the
      ordinary public CBOR decoder remains strict.
- [x] Prove malformed routing claims are rejected before the UEID key resolver
      runs, and that duplicate text labels are rejected in every header map.
- [x] Test the exact and plus-one combined protected/unprotected text-label
      tracking boundary.
- [x] Cover receiver-side nonce-length mismatch, component hash boundaries,
      every valid lifecycle class, and current certification-reference syntax.
- [x] Test exact and plus-one top-level/component claim-map limits in CI, and
      reject every below-minimum resource limit at compile time.
- [x] Compile the enabled PSA/EAT implementation under the strict MISRA C:2023
      compiler-warning profile, not only under clang-tidy.
- [x] Run enabled PSA/EAT conformance and macro-gate tests against the supported
      wolfSSL v5.8.0 compatibility floor in the version matrix.

## Documentation and release readiness

- [x] Write the RFC 9783 API and integration guide.
- [x] Document security boundary, policy responsibilities, modern versus
      legacy behavior, supported algorithms, and unsupported trust models.
- [x] Update README, feature-macro, testing, release notes, and ChangeLog.
- [x] Add a practical current-profile issue, verify, and component-appraisal
      onboarding example and run it in CI.
- [x] Final diff review, public-header audit, full validation, and Codex-backed
      Skoll remediation to no validated findings above low severity.
