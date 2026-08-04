# Roadmap

## Phase 1 â€” Specification

**Status: complete as a reviewed non-production foundation.**

Delivered:

- threat model and election lifecycle;
- governance-key registry rules;
- canonical manifest and ballot schemas;
- archive format and Ootle anchor boundary;
- tally and dispute policy;
- anonymous-membership construction decision record;
- canonical data-format and test-vector plan;
- consistency review and pilot-scope correction.

Historical Phase 1 documents remain drafts for public review. They are not
Tari governance approval and do not authorize a binding election.

## Phase 2 â€” Offline Rust foundation

**Status: complete at implementation baseline `d9e46e1`.**

Delivered:

1. `protocol`: bounded canonical CBOR, versioning, limits, domain separation,
   commitments, proof statements, and election scope;
2. `registry`: canonical immutable snapshots and voter-owned governance-key
   policy;
3. `ballot`: canonical selectable options, approval payloads, manifests,
   packages, and append-only lifecycle;
4. `tally`: deterministic non-binding approval tally with explicit ties;
5. `archive`: canonical file catalogs, manifests, and metadata-minimized replay;
6. `verifier`: proof-bound statement reconstruction, proof authority boundary,
   first-valid-nullifier acceptance, and replay;
7. `crypto`: release-inappropriate test-only proof plumbing behind an explicit
   verification interface;
8. `cli` tests: hostile CBOR, semantic rejection, mutation matrices, synthetic
   cohorts, archive replay, and valid-vector publication;
9. independent Python canonical-vector verification;
10. seven cargo-fuzz parser targets.

Validation baseline:

- 30 Phase 2 commits;
- 288 tracked files before closeout documentation;
- 220 passing Rust tests;
- nine valid canonical vector cases across six object families;
- 16 hostile CBOR cases;
- 17 semantic rejection cases;
- 137 deterministic fuzz seeds;
- seven targets with 448 bounded Linux fuzz executions;
- native Windows and Linux validation;
- no native macOS validation yet.

No walletd, indexer, Ootle, production key generation, or binding-election
integration belongs in the Phase 2 baseline.

## Phase 3 â€” Anonymous-membership prototype and portability

**Status: next.**

Build in this order:

1. preserve the current proof-verification authority boundary;
2. prototype scope-linkable Ristretto255 ring signatures;
3. bind proofs to the existing canonical proof statement;
4. derive and verify election-scoped linkability material;
5. publish deterministic proof and rejection vectors;
6. add malformed-proof and adversarial tests;
7. add Windows, Linux, and macOS continuous integration;
8. run native macOS checks on Apple Silicon and, when practical, Intel macOS;
9. document privacy limits, signer-set assumptions, and denial-of-service
   limits;
10. obtain focused cryptographic review before pilot use.

Semaphore remains the fallback construction if the preferred Ristretto255 path
cannot satisfy the requirements. BBS-based credentials remain deferred.

Exit gate:

- a reviewed prototype authenticates eligibility and ballot statements;
- duplicate voting is detected without publishing voter identity;
- test-only proof plumbing cannot be mistaken for the real suite;
- deterministic vectors and independent checks exist;
- Windows, Linux, and macOS workspace gates pass;
- no claim of production security is made.

## Phase 4 â€” Harmless non-binding pilot

Phase 4 now also covers the harmless, non-binding Ootle testnet anchor
prototype. The prototype anchors only the existing completed `ArchiveHashV1`
and keeps offline verification authoritative. Earlier wording that placed this
anchor work in Phase 5 is superseded and renumbered into Phase 4; see
[ADR-0006](docs/decisions/ADR-0006-phase4-ootle-anchor-prototype-scope.md).
Binding governance use remains unauthorized, and independent cryptographic and
implementation review remains required before any binding use.

Run a volunteer-only, low-consequence approval poll.

Publish:

- frozen manifest and registry snapshot;
- canonical ballot packages;
- receipts;
- verification and tally transcripts;
- complete offline archive;
- optional testnet anchor commitments;
- incident log and retrospective.

The pilot remains non-binding. Public-ballot mode is acceptable only when the
subject is harmless and early disclosure is acceptable.

Exit gate:

- complete archive independently verifies;
- no accepted duplicate nullifier exists;
- no voter identity, wallet address, IP address, or device identifier appears
  in a ballot package;
- all participants are told the pilot is experimental and non-binding.

## Phase 5 â€” Ootle testnet anchoring

The harmless, non-binding testnet anchor *prototype* is renumbered into Phase 4
(see [ADR-0006](docs/decisions/ADR-0006-phase4-ootle-anchor-prototype-scope.md)).
Phase 5 retains the later, broader on-chain work beyond that prototype.

Add an optional template that records only append-only commitments and
lifecycle transitions.

Ootle is not the sole archive and must not receive voter identities, private
keys, or plaintext voter mappings.

Exit gate:

- offline verification remains complete without Ootle;
- re-anchoring after a testnet reset is explicit and auditable;
- authorization and state transitions are reviewed.

## Phase 6 â€” Independent review and MVP release

Require:

- independent cryptographic review;
- independent implementation review;
- native platform validation and packaging;
- operational procedures for enrollment, replacement, revocation, disputes,
  backups, and recovery;
- an exact approved governance source revision;
- explicit authorization before any binding use.

Only after this phase may the community consider consequential or binding use.
