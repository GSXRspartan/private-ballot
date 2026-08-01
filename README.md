# Tari CC Private Ballot

An offline-verifiable private-ballot protocol foundation for Tari governance,
with an optional append-only Tari Ootle commitment anchor.

## Current status

Phase 2 is complete as a non-production Rust protocol foundation.

The repository currently provides:

- deterministic and bounded canonical CBOR;
- versioned registry, ballot, manifest, package, lifecycle, tally, and archive
  models;
- proof-verification authority boundaries and election-scoped duplicate
  detection;
- metadata-minimized offline replay;
- published valid and invalid test vectors;
- an independent Python canonical-vector verifier;
- seven libFuzzer parser targets.

The implementation baseline is commit `d9e46e1`.

## Validation status

- Windows: Rust workspace checks, Clippy, 220 tests, and the independent
  canonical-vector verifier passed.
- Linux x86_64: the same workspace gates passed, and seven libFuzzer targets
  completed bounded offline smoke runs using 137 deterministic seeds.
- macOS: intended to be supported, but no native macOS validation has run yet.

Platform-neutral Rust source contains no current Windows-, Unix-, or
macOS-specific code paths. That is encouraging, not magical proof. Native
macOS CI remains required.

## Design principle

The complete offline election archive must be sufficient to verify an
election. Ootle may record immutable commitments and lifecycle transitions,
but it is not the only copy and is not trusted to survive testnet resets.

## Safety status

This repository is not production election software.

The current proof and hash providers are deterministic, forgeable,
non-anonymous test plumbing:

- `TEST_ONLY_NOT_ANONYMOUS_NOT_FOR_BINDING_ELECTIONS`
- `TEST_ONLY_DETERMINISTIC_HASH_NOT_CRYPTOGRAPHIC`

Do not use this repository for a binding Core Contributor, Council, treasury,
charter, or other governance election.

## Next phase

Phase 3 begins with a reviewed anonymous-membership prototype and a
Windows/Linux/macOS CI matrix. A harmless non-binding pilot remains blocked
until the production-oriented proof path and cross-platform validation gates
exist.

See:

- `PHASE_STATUS.md`
- `ROADMAP.md`
- `docs/reviews/PHASE2_CLOSEOUT_2026-08-01.md`
- `docs/OPEN_QUESTIONS.md`
