# Phase 3 Slice 3C17: combined adversarial assurance

## Starting state and scope

- Branch: `phase3/anonymous-membership-prototype`
- Starting HEAD: `70611e40fa202af736b8109080178f8242c0fc3b`
- Working tree: clean before this slice.
- Toolchain: Rust `1.97.1`; Cargo was always invoked with `--locked --offline`.
- Network access: none.

This slice adds project-owned regression evidence only. It does not change production verification, cryptographic constructions, canonical formats, nullifier semantics, or the vendored Tari Triptych implementation. No production defect was found.

## Files and test organization

- `crates/cli/tests/triptych_adversarial_assurance.rs` (new)
- `crates/crypto/src/triptych_verifier.rs` (test-only vendor batch-equivalence coverage)
- `docs/reviews/PHASE3_SLICE3C17_COMBINED_ADVERSARIAL_ASSURANCE_2026-08-03.md` (this evidence)

The CLI target has four non-ignored tests and one ignored/manual release timing test. The fixture uses existing project-owned deterministic public keys, while normal proofs are produced by the project prover's secure randomness path.

## Complete package-to-ledger corpus

Every malformed case is submitted through `ingest_approval_ballot_package_v1`, covering canonical package decoding, manifest and suite binding, candidate and approval-limit validation, envelope and inner-proof parsing, proof verification, lifecycle validation, and ledger mutation only after success.

For each category, the test checks that a structural decode round-trips to exactly one canonical sequence, submits every malformed case twice with the same stable `ValidationCode`, requires an empty ledger throughout, then accepts the untouched baseline once and requires its replay to return `DUPLICATE_NULLIFIER`.

The elapsed bound covers the structural check and complete ingestion call. It is intentionally broad: 30 seconds per malformed input only flags a spectacular hang rather than serving as a microbenchmark.

| Primary category | Mutations |
| --- | ---: |
| Every complete canonical-package truncation | 529 |
| Every proof-envelope truncation | 458 |
| Every inner-proof truncation | 424 |
| Outer appended suffixes | 8 |
| Envelope/inner-proof appended suffixes | 8 |
| Outer, header/tag, point, scalar, and fixed-stride inner-proof bit flips | 1,088 |
| CBOR/envelope/point-scalar/proof-limit framing | 9 |
| Fixed-seed random-looking bounded arrays | 14 |
| **Primary corpus total** | **2,538** |

The stride begins at inner-proof byte zero, continues with fixed stride 17, and explicitly includes the final byte. The representative point and scalar ranges are separately flipped exhaustively; sampled overlaps are omitted. This is bounded mutation evidence, not a claim of exhaustive algebraic mutation.

Suffixes include zero/nonzero one-byte values, 8 and 32 bytes, another valid envelope, another valid inner proof, a complete canonical package, and a canonical payload. Framing covers shorter/longer and noncanonical CBOR lengths, zero proof, maximum and maximum-plus-one proof lengths, unsupported envelope version, and malformed point/scalar lengths. Random arrays use fixed seed `0x3c17_5eed_c0de_2026` at 0, 1, fixture-relative near-valid sizes, envelope/inner-proof boundaries, 1 KiB, 1 MiB, and 1 MiB plus one byte. “Just below known real package” is fixture-relative, not a claim of a protocol-wide minimum package size.

The final primary run observed a maximum input of 1,048,577 bytes, a maximum per-input elapsed time of 291 ms, and a primary-corpus runtime of 84,062 ms. No production parser panic was caught or expected; malformed inputs returned ordinary errors.

### Rejection codes

| Stable `ValidationCode` | Primary corpus | Field/context substitutions | Combined |
| --- | ---: | ---: | ---: |
| `INVALID_CBOR` | 540 | 0 | 540 |
| `INVALID_DATA` | 11 | 0 | 11 |
| `MALFORMED_PROOF` | 1,853 | 7 | 1,860 |
| `NON_CANONICAL_CBOR` | 2 | 0 | 2 |
| `PROTOCOL_LIMIT_EXCEEDED` | 2 | 0 | 2 |
| `TRAILING_CBOR_DATA` | 9 | 0 | 9 |
| `UNEXPECTED_CBOR_TYPE` | 20 | 0 | 20 |
| `UNSUPPORTED_PROTOCOL_VERSION` | 5 | 0 | 5 |
| `WRONG_MANIFEST_HASH` | 96 | 0 | 96 |
| `UNSUPPORTED_PROOF_SUITE` | 0 | 1 | 1 |
| **Total** | **2,538** | **8** | **2,546** |

The eight substitutions cover a different valid proof's linking tag, inner proof, whole envelope, payload, and suite identifier, plus a source proof under a different election manifest/hash, registry context, and authoritative candidate set. All reject before ledger mutation.

## Batch-versus-individual verification

The vendored crate exposes `TriptychProof::verify_batch`, `verify_batch_with_single_blame`, and `verify_batch_with_full_blame`. It only accepts homogeneous input sets and parameters, so heterogeneous registry/parameter batching is intentionally not an application capability.

A crypto-unit test builds project statements, parses project envelopes/proofs, and proves batch success exactly matches individual verification for all-valid, empty, single-item, and duplicate cryptographically valid batches; a substituted proof at first, middle, and last positions; multiple substituted proofs with exact full-blame indexes `[1, 3]`; and a mixed-registry attempt rejected as `ProofError::InvalidParameter`.

Production remains individually verified: no production batch API or behavior was added. A duplicate valid proof is batch-valid, while the package-to-ledger corpus separately proves the second successful submission is rejected as `DUPLICATE_NULLIFIER`.

## Signer-position serialization smoke

A 16-member canonical registry exercises positions 0, 4, 8, 12, and 15. It creates two fresh secure proofs for each position with equal ballot content, parses package/envelope framing, and accepts each through the complete package-to-ledger path on a fresh ledger.

| Property | Result |
| --- | ---: |
| Inner proof bytes | 616 |
| Envelope bytes | 650 |
| Canonical package bytes | 721 |
| Project-owned non-proof prefix bytes | 71 |
| Canonical package fields | 5 |

The byte-identical project-owned non-proof prefix covers protocol version, manifest hash, proof-suite identifier, payload, and proof byte-string framing. No explicit signer index or signer-dependent optional project-owned package field was observed. This does not prove opaque proof bytes cannot encode information algebraically and does not prove zero knowledge.

## Manual release timing smoke

`manual_release_signer_position_timing_smoke` is ignored by default and was not run for this slice. It fails fast outside a release build. Run it with:

```powershell
rustup.exe run 1.97.1 cargo test --manifest-path Cargo.toml --locked --offline --release -p tari-cc-private-ballot-cli --test triptych_adversarial_assurance -- --ignored --nocapture
```

It warms every representative signer path, deterministically interleaves five positions with seed `0x3c17_71ae_5eed_2026`, collects 12 samples per position, and reports minimum, median, mean, maximum, and population standard deviation. It fails only when either the median or mean extreme ratio exceeds 5x. The result depends on hardware, OS scheduling, and background load; passing is not a constant-time proof and failure requires investigation.

## Randomness, hazmat, and secret-handling inventory

The project-owned policy test verifies source-level release policy: the production `triptych` dependency has `default-features = false` and the project manifest does not enable `hazmat`; the normal prover imports `rand_core::OsRng` and calls `TriptychProof::prove_with_rng` with `OsRng`; the project prover does not call `prove_vartime` or `prove_with_rng_vartime` and does not print secrets; the test-only verifier is feature/test gated; the test-only suite is rejected by `ProductionProofSuitePolicyV1`; and secret-key `Debug` output is exactly `[REDACTED]`.

Two source-level limits are recorded rather than overstated. The deterministic hashing helper is gated by `cfg(any(test, debug_assertions))`, so it is excluded from normal release builds but is not strictly test-only in a debug non-test build. The vendor's private verifier-only `NullRng` transcript-weight mechanism is not a project caller-supplied prover RNG and is not claimed to be test-only. The source scan also cannot establish all possible downstream feature unification outside this locked workspace build.

## Validation performed

All completed successfully with Rust `1.97.1`, `--locked`, and `--offline`:

```powershell
rustup.exe run 1.97.1 cargo test --manifest-path Cargo.toml --locked --offline -p tari-cc-private-ballot-crypto --features test-only-suites
rustup.exe run 1.97.1 cargo test --manifest-path Cargo.toml --locked --offline -p tari-cc-private-ballot-verifier
rustup.exe run 1.97.1 cargo test --manifest-path Cargo.toml --locked --offline -p tari-cc-private-ballot-verifier --test real_triptych_ballot
rustup.exe run 1.97.1 cargo test --manifest-path Cargo.toml --locked --offline -p tari-cc-private-ballot-cli --test triptych_adversarial_assurance
rustup.exe run 1.97.1 cargo test --manifest-path Cargo.toml --locked --offline -p tari-cc-private-ballot-cli --test hostile_cbor_corpus
rustup.exe run 1.97.1 cargo test --manifest-path Cargo.toml --locked --offline -p tari-cc-private-ballot-cli --test deterministic_mutation_matrix
rustup.exe run 1.97.1 cargo check --manifest-path Cargo.toml --locked --offline --workspace --all-targets
rustup.exe run 1.97.1 cargo clippy --manifest-path Cargo.toml --locked --offline --workspace --all-targets --no-deps -- -D warnings
```

The final assurance-target run reports 4 passed and 1 ignored in 85.38 seconds. The pre-existing vendored `OperationTiming::Variable` dead-code warning remains the only Rust warning observed; it is not suppressed or changed by this slice. No prohibited large election/signer suite, unbounded fuzzing, or timing run was executed.

## Limitations and staging note

These tests are regression evidence only. They do not prove mathematical soundness, zero knowledge, constant-time behavior, absence of every side channel, or formal resource bounds. Vendored Tari Triptych is read only and unchanged.

After this file is staged, the task handoff records the exact staged file count, staged-blob byte counts/SHA-256 values, and staged binary-patch byte count/SHA-256 without making this file's self-hash stale. No commit is created.
