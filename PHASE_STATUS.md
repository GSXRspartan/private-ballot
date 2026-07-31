# Phase Status

- Last updated: 2026-07-31
- Current branch: `phase1/spec-finalization`
- Current project state: Phase 1 specification foundation reviewed
- Next authorized work: Phase 2 test-only protocol and archive plumbing

## Phase 1 assessment

Phase 1 has established a coherent specification foundation for beginning
non-production implementation work.

Phase 1 is not complete for production cryptography, binding governance,
or a real Core Contributor or Council election.

## Completed Phase 1 foundation

- Initial repository and specification baseline committed at `dbeeabd`.
- Tari governance source snapshot pinned at `05eb7a9`.
- MVP ballot validation and tally policy recorded at `5e6943c`.
- Anonymous-membership research direction recorded at `ab5daf3`.
- Canonical data-format and test-vector plan recorded at `3f2b7d3`.
- Phase 1 consistency review recorded at `bb6d324`.
- Pilot-scope clarification and review correction recorded at `928e08d`.

## Decisions currently established

- The offline election archive is independently authoritative and verifiable.
- Ootle is an append-only lifecycle and commitment anchor, not the sole archive.
- Election authority uses dedicated governance keys, never wallet keys.
- The first pilot is a harmless non-binding approval poll.
- Stable machine candidate identifiers are separate from display names.
- The first valid ballot for an election-scoped nullifier counts.
- Unknown, duplicate, malformed, and noncanonical ballots are rejected.
- Unresolved ties are reported as ties.
- Protocol objects use deterministic CBOR and published byte vectors.
- Test-only proof plumbing must be visibly non-production.

## Phase 2 work now authorized

Phase 2 may implement:

- the Rust workspace and crate boundaries;
- versioned protocol data types;
- deterministic CBOR encoding and canonicality checks;
- stable validation and rejection codes;
- registry, candidate, ballot, receipt, tally, result, and archive models;
- deterministic hashes and domain-separation labels;
- valid and invalid test-vector scaffolding;
- a release-disabled test-only proof provider;
- offline verification and archive plumbing.

Phase 2 must remain independent of walletd, an indexer, and Ootle.

## Still blocked

The following remain unresolved and must not be represented as complete:

1. Exact production anonymous-membership construction and suite version.
2. Security rationale for election-scoped linkability or nullifiers.
3. Registry enrollment, replacement, and compromised-key procedures.
4. Binding-election sealed-ballot design.
5. Exact single-seat ranked-choice rules.
6. Exact multi-seat Council election method.
7. Binding-election tie resolution.
8. Election administration authorization and dispute procedures.
9. Independent cryptographic and implementation review.
10. Independently implemented verifier or equivalent cross-check.

## Explicit prohibitions

Until later phases expressly authorize them:

- do not conduct a binding election;
- do not describe the system as production secure;
- do not use the Python LSAG proof of concept as production code;
- do not enable the test-only proof provider in release builds;
- do not integrate walletd, an indexer, or Ootle;
- do not publish or rely on real voter private keys;
- do not treat the current RFC pull request as merged governance policy.

## Next milestone

Create the Phase 2 Rust workspace baseline with protocol types, canonical
serialization boundaries, deterministic validation errors, and a clearly
marked test-only proof interface.
