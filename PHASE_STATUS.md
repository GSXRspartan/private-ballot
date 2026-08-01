# Phase Status

- Last updated: 2026-08-01
- Current branch: `phase2/protocol-foundation`
- Current project state: Phase 2 offline Rust foundation complete
- Implementation baseline: `d9e46e1`
- Next authorized work: Phase 3 anonymous-membership prototype and
  cross-platform CI

## Phase 2 assessment

Phase 2 established and validated the non-production protocol, archive,
verification, vector, and parser-fuzzing foundation needed to begin real
anonymous-membership prototyping.

Phase 2 is complete for deterministic test plumbing.

Phase 2 is not complete for production cryptography, binding governance,
native macOS validation, Ootle integration, or a real Core Contributor or
Council election.

## Completed Phase 2 foundation

Across 30 commits after the Phase 1 transition, Phase 2 delivered:

- an eight-crate Rust 2024 workspace pinned to Rust 1.97;
- strict bounded canonical CBOR primitives;
- stable validation and rejection codes;
- domain-separated deterministic hash and commitment boundaries;
- canonical registry snapshots and voter-owned governance-key policy;
- canonical selectable-option sets and approval payloads;
- versioned election manifests and manifest-derived election scopes;
- proof-bound statement reconstruction;
- a proof-verification authority interface;
- proof-authenticated ballot acceptance and first-valid-nullifier policy;
- append-only election lifecycle enforcement;
- metadata-minimized replay transcripts;
- canonical archive file catalogs and archive manifests;
- canonical proof-bearing ballot packages and self-contained test replay;
- deterministic approval tallies with explicit ties;
- hostile-CBOR and semantic-rejection corpora;
- deterministic mutation and synthetic-cohort tests;
- offline archive replay gates;
- nine published valid canonical vector families/examples;
- an independent standard-library Python vector verifier;
- seven real libFuzzer parser targets.

## Validation evidence

At baseline `d9e46e1`:

- 220 Rust workspace tests are registered and pass;
- debug and release workspace checks pass;
- Clippy passes with warnings denied;
- the independent Python verifier confirms canonical decode/re-encode and
  domain-separated test-hash agreement for nine valid cases across six object
  families;
- Windows validation passes;
- Linux x86_64 validation passes;
- seven libFuzzer targets complete 64 bounded runs each, for 448 executions,
  using 137 deterministic seeds;
- no known parser crash was found in the bounded campaign.

The pre-closeout baseline contains 288 tracked files. Its tracked-file
SHA-256 manifest is preserved at:

`docs/reviews/PHASE2_FOUNDATION_HASHES_D9E46E1.csv`

Manifest SHA-256:

`8235EBB98FF717B8D6F5DE9CFA10AC2069209808C040CEC0FABDE8D44E2C2A22`

## Platform status

- Windows: natively validated.
- Linux x86_64: natively validated, including cargo-fuzz.
- macOS: intended and structurally plausible, but not natively validated.
- Continuous integration: no tracked CI workflow exists yet.

No platform-specific Rust source references were found during the closeout
inventory. This does not replace native macOS build and test evidence.

## Decisions that remain established

- The offline election archive is independently authoritative and verifiable.
- Ootle is an append-only lifecycle and commitment anchor, not the sole archive.
- Voters create or import dedicated governance keys; an election authority
  never owns voter private keys.
- The first pilot is harmless and non-binding.
- Stable machine option identifiers are separate from display names.
- The first valid ballot for an election-scoped nullifier counts.
- Unknown, duplicate, malformed, oversized, and noncanonical ballots are
  rejected.
- Unresolved ties are reported as ties.
- Protocol objects use deterministic CBOR and published byte vectors.
- Test-only proof plumbing remains visibly non-production.

## Still blocked

The following remain unresolved and must not be represented as complete:

1. Exact production anonymous-membership construction and suite version.
2. Security review of election-scoped linkability and nullifier derivation.
3. Registry enrollment, replacement, revocation, and compromised-key
   procedures.
4. Binding-election sealed-ballot design.
5. Exact single-seat ranked-choice rules.
6. Exact multi-seat Council election method.
7. Binding-election tie resolution.
8. Election-administration authorization and dispute procedures.
9. Independent cryptographic and implementation review.
10. Native macOS build and test validation.
11. Production Ootle anchoring and recovery behavior.
12. A user-facing desktop application and packaging.

## Explicit prohibitions

Until later phases expressly authorize them:

- do not conduct a binding election;
- do not describe the system as production secure or anonymously secure;
- do not treat the test-only proof provider as cryptographic anonymity;
- do not enable test-only proof plumbing for a binding or consequential vote;
- do not integrate walletd, an indexer, or Ootle into the Phase 2 baseline;
- do not publish or rely on real voter private keys;
- do not treat an unmerged governance proposal as final policy;
- do not claim macOS support has been validated.

## Next milestone

Phase 3 begins with:

1. a scope-linkable Ristretto255 ring-signature prototype behind the existing
   proof-verification interface;
2. deterministic proof vectors and malformed-proof tests;
3. Windows, Linux, and macOS CI for the platform-neutral workspace;
4. an explicit security and privacy review of election-scoped linkability;
5. continued prohibition on any binding election.

Semaphore remains a fallback research direction if the preferred construction
cannot satisfy the protocol and deployment constraints. BBS-based credentials
remain deferred.

The harmless non-binding pilot follows only after those gates are satisfied.
