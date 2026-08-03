# Phase 3 Confirmed Blocker Repairs — Evidence

## Baseline and scope

- Starting branch: `phase3/anonymous-membership-prototype`
- Starting commit: `a875d11228d42a9447428ce6d8abab89ec8465b4`
- Rust toolchain: `1.97.1`
- Cargo resolution and validation: locked and offline
- Scope: production hashing, test-only proof-suite release gating, and
  manifest-bound approval-package ingestion only.

No Triptych equation, padding, linking-tag, archive, receipt, signature,
cutoff, anonymity-threshold, Ootle, or CLI-product behavior was changed.

## Production hash provider

`Blake3HashProviderV1` has the stable algorithm identifier:

`BLAKE3-256/tari-cc-private-ballot/v1`

The provider receives the existing domain-separated frame unchanged. The
following version-one known-answer vectors are asserted in protocol tests:

| Domain and payload | BLAKE3-256 digest |
| --- | --- |
| `ElectionManifestV1`, empty payload | `2b0ecbaaba027f4cf8a4c3bef03e898be8596183d10e0c632abe3b76b9556dd6` |
| `RegistrySnapshotV1`, `registry` | `822704900dc348bc6d3093dff26b265a2c8b48ed6334c16dd8507522045fea87` |
| `BallotPackageV1`, `one\0two\0three` | `5f44b5533d33ccc193b0a606f65bb64f8bb7c5c8112875e94bcbeaaec746cf5` |
| `CandidateSetV1`, `same-bytes` | `47add841e5bf33952ec3a80aa57b9b1f132c8c5926013ae484c18605a21e3644` |
| `ElectionScopeV1`, `same-bytes` | `e9e023e9c2d207825d83741a47b06d5e066b6e554a6f34324ff642739bd99f3a` |
| `ApprovalBallotPayloadV1`, `alpha-beta` | `347b2e7a3e7fa117615ef247155bb987e98946e1ed039e4291d988cf9a65f3ec` |

The production-provider integration test covers registry commitment,
candidate-set commitment, manifest hash, payload hash, manifest-derived scope,
archive-file digest, archive hash, and archive hash-provider identifier.
Test-only hash vectors remain explicitly test-only and are not interchangeable
with artifacts produced using this algorithm identifier.

## Proof-suite release gate

`test-only-suites` is a non-default feature of the crypto crate.
`test_only_verifier` is exported only with `cfg(test)` or that explicit feature.
The production ingestion policy allows only `TARI_TRIPTYCH_PROTOTYPE_V1` and
returns `UNSUPPORTED_PROOF_SUITE` for the reserved test-only suite.

A release check without default features compiles the crypto crate without the
test-only export. A separate explicit-feature release check compiles when
`test-only-suites` is deliberately supplied. CLI test/dev dependency wiring
enables the feature only for test targets that use the visible test suite.

## Manifest-bound approval-package ingestion

`ingest_approval_ballot_package_v1` enforces this order:

1. canonical outer-package decode;
2. package manifest-hash and proof-suite binding;
3. production proof-suite policy;
4. authoritative candidate-set commitment against the manifest;
5. payload decode using authoritative candidates and manifest approval limits;
6. statement reconstruction and proof verification;
7. lifecycle validation and first-valid-nullifier ledger acceptance.

The API rejects before ledger mutation for wrong authoritative candidate set,
unknown candidate, too many selections, disallowed abstention, wrong manifest,
wrong suite, and the test-only suite. Real Triptych application-boundary,
offline-replay, and multi-member CLI replay tests use the boundary for normal
acceptance.

## Validation

Passed with Rust 1.97.1, locked offline Cargo:

- targeted production hash vectors;
- targeted manifest-bound ingestion tests;
- real Triptych application-boundary tests;
- real Triptych offline archive replay;
- multi-member real Triptych replay;
- deterministic mutation, hostile-CBOR, and semantic-rejection corpora;
- default-feature-free and explicit-test-feature crypto release checks;
- workspace `cargo check --all-targets`;
- workspace `cargo test` (ignored large-election tests were not run);
- workspace Clippy with `-D warnings` and `--no-deps`.

`cargo fmt --all -- --check` reports formatting differences only in the five
unchanged vendored Tari Triptych files. Rust 1.97.1 formats those baseline files
differently; they were intentionally restored unchanged because this repair
slice must not alter vendored Triptych code.

All commands used Cargo's `--offline` mode. No network operation was requested
or performed.
