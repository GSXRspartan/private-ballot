# Phase Status

- Last updated: 2026-08-08
- Current branch: `phase5/gui-core-foundation`
- Current project state: Phase 4 harmless non-binding Ootle testnet anchor
  prototype complete at tag `phase4-release-build-2026-08-06`
  (`05d923da1e552b7fdf2abf1129bf53334620d6f1`); Phase 5 GUI begun
- Implementation baseline: `05d923da` (Phase 4 release build)
- Next authorized work: Phase 5 GUI slices following Slice 5A6
  (organizer election creation, eligibility registry, freeze, and export)

> Note: the sections below this header were last maintained at the Phase 2
> closeout (2026-08-01). Phase 3 delivered the reviewed Triptych
> anonymous-membership prototype; Phase 4 delivered the canonical anchor
> record, walletd/indexer adapters, lifecycle orchestration, durable
> snapshots, canonical evidence, and operator tooling; see `ROADMAP.md`,
> `docs/decisions/ADR-0006`, and the Phase 3/Phase 4 review documents under
> `docs/reviews/`. Phase 5 Slice 5A2 added the additive
> `tari-cc-private-ballot-gui-core` application facade crate; see
> `docs/reviews/PHASE5_SLICE5A2_GUI_CORE_FOUNDATION_2026-08-07.md` and
> `docs/decisions/ADR-0007-phase5-gui-stack-and-rust-boundary.md`.
> Phase 5 Slice 5A3 added the Tauri 2 + React + TypeScript + Vite desktop
> shell under `gui/` (see
> `docs/reviews/PHASE5_SLICE5A3_TAURI_DESKTOP_SHELL_2026-08-07.md`). After a
> one-time networked fetch of the Tauri crate family, the native build was
> completed on this machine: the Rust shell and its full dependency graph
> compiled (offline `cargo check` passes), the release executable was
> produced, and Windows MSI and NSIS installers were built. Slice 5A3 is
> documented as READY FOR 5A4 (see §14 of that review). Installer
> installation, code signing, and macOS/Linux packaging were not tested.
> Phase 5 Slice 5A4 turned the GUI shell into a real application workflow
> for loading and inspecting an existing election: native Tauri file
> selection for the three canonical artifacts, real election loading
> through gui-core, structured backend error presentation, real
> backend-derived Home and Manage Election data, ballot-type-neutral
> terminology, "Governance Pilot" product-status wording, and Esmeralda
> Testnet as the current network (see
> `docs/reviews/PHASE5_SLICE5A4_REAL_ELECTION_LOADING_2026-08-07.md`).
> Slice 5A4 is documented as READY FOR 5A5. No commit was created; all
> changes are staged only. Phase 5 Slice 5A5 added privacy-aware participation
> metrics and a sealed-disclosure policy (default `SealedUntilClose` while
> voting is open) derived authoritatively from the registry size and acceptance
> ledger, plus dashboard analytics (see
> `docs/reviews/PHASE5_SLICE5A5_PARTICIPATION_AND_DISCLOSURE_2026-08-07.md`).
> Phase 5 Slice 5A6 added the real organizer election-creation workflow: a
> backend-authoritative `GuiElectionDraftV1` facade that validates every field,
> constructs the canonical registry, candidate set, and manifest, derives all
> commitments and the manifest hash, freezes through the existing lifecycle,
> exports the three canonical artifacts, and round-trips through the existing
> 5A4 loader. The candidate/governance/ballot-measure distinction is modeled as
> application-local presentation (the manifest carries only
> `NON_BINDING_APPROVAL_PILOT`); no unbound proposal text is presented as
> authoritative. Post-freeze immutability is enforced in Rust. See
> `docs/reviews/PHASE5_SLICE5A6_ORGANIZER_ELECTION_CREATION_2026-08-07.md`.
> Slice 5A6 is documented as READY FOR OPUS REVIEW. No commit was created; all
> changes are staged only. Phase 5 Slice 5A8 implemented the ADR-0008
> process-hardening requirements before voter credential/proof generation:
> application-level governance source pinning (`blake3:<64 hex>` content
> digest, recommended, and `git:<40 hex>` Git commit SHA, advanced), local
> governance document selection/digesting (existing `ArchiveFileV1`
> domain-separated BLAKE3-256, 50 MiB cap, symlink/directory rejection),
> source↔document matching with honest operator-attested labeling for Git SHAs,
> archival of the governance document as supporting evidence at the
> project-controlled `governance/source.bin` path (hash-covered by the existing
> `ArchiveManifestV1` catalog, no schema change), a freeze hard gate that
> blocks a content-digest pin whose selected document does not match, and the
> first real voter confirmation boundary view model that separates
> cryptographically bound manifest fields from the non-canonical presentation
> label and explicitly states no proposal question exists. A final pre-commit
> hardening pass added paired write-time and verify-time governance pin↔document
> gates (so an internally catalog-consistent archive containing the wrong
> governance document for a bound `blake3:` pin is rejected), a distinct
> `governance_source_matches_pin` verification DTO fact, a frozen governance
> digest KAT, and the pin↔catalog digest equality regression. No canonical
> change; V1 manifest/archive bytes are byte-identical. No voter secrets, no
> network, no walletd/indexer/signing. See
> `docs/reviews/PHASE5_SLICE5A8_GOVERNANCE_SOURCE_AND_VOTER_CONFIRMATION_2026-08-07.md`.
> Slice 5A8 passed independent Opus review (APPROVE WITH NON-BLOCKING
> FOLLOW-UPS); the one MEDIUM finding (M1) and LOW/INFO follow-ups are resolved
> by the final hardening pass. READY TO COMMIT. No commit was created; all
> changes are staged only.
> Phase 5 Slice 5A9 added the first Rust-side voter governance credential
> boundary: session-only generation from the existing Triptych scalar primitive
> using `rand_core::OsRng`, public-key derivation as compressed Ristretto
> basepoint multiplication, exact frozen-registry eligibility matching, a
> Rust-managed Tauri credential slot cleared on election replacement/unload and
> explicit reset, and a Vote-screen credential/eligibility stage after the 5A8
> confirmation boundary. No private credential bytes cross into TypeScript; the
> DTO carries only public metadata and no registry index. No reviewed private
> credential persistence/import/export format exists, so import/export remains
> deferred rather than invented. No Triptych proof, nullifier, ballot package,
> vote submission, walletd/indexer/network contact, or wallet key reuse was
> added. See
> `docs/reviews/PHASE5_SLICE5A9_VOTER_CREDENTIAL_BOUNDARY_2026-08-08.md`.
> Slice 5A9 is documented as CONDITIONAL READY: focused Rust/frontend checks
> passed, the Tauri release executable built, and MSI bundling failed at WiX
> `light.exe` without a captured detailed diagnostic. No commit was created.
> Phase 5 Slice 5A10A added the safe voter ballot-session architecture needed
> before real proof generation: a Rust-owned `GuiVoterSessionV1` bound to the
> active election fingerprint, Rust-authoritative approval selection through
> the existing `ApprovalBallotPayload` validator, non-secret credential
> generation / selection revision / preparation operation identifiers, stale
> operation rejection tests using only `#[cfg(test)]` synthetic markers, Tauri
> voter workflow and selection commands, and a real Vote-screen ballot
> selection stage. It also zeroizes transient key-generation bytes in the
> existing Triptych credential primitive. No Triptych proof, nullifier,
> canonical ballot package, export bytes, canonical format change, walletd,
> indexer, Ootle submission, HTTP, telemetry, or vote submission was added. See
> `docs/reviews/PHASE5_SLICE5A10A_VOTER_SESSION_ARCHITECTURE_2026-08-08.md`.
> Focused Rust checks/tests/clippy, root workspace check/clippy, detached
> Tauri checks/clippy, frontend tests, and frontend build passed. Full root
> workspace tests passed in the final pre-commit repair pass. Native Tauri
> build previously produced the release `.exe` and failed at WiX `light.exe`
> MSI bundling. The final pre-commit repair fixed the reviewed F1 lifecycle DTO
> defect in `set_selection`, added non-open lifecycle and stale preparation
> operation tests, added narrow frontend request-generation hardening, and
> documented 5A10B secret ownership and ready-after-close policy decisions. No
> commit was created.
> Phase 5 Slice 5A10B now adds local real Triptych proof preparation, canonical
> ballot packaging, independent self-verification, Rust-only prepared bytes,
> and no-overwrite export with read-back verification. The Vote UI exposes only
> safe prepared metadata and explicitly reports local export rather than vote
> submission. No canonical format, vendored Triptych code, or network path was
> changed. Focused gui-core check and frontend build passed; the focused test
> binary timed out during compilation, so this slice remains CONDITIONAL READY
> pending the wider offline test and performance matrix. No commit was created.
> Phase 5 Slice 5A11 adds the complete local voter export to organizer ballot
> office byte-intake workflow. The explicit shared boundary is
> `GuiElectionSessionV1::intake_ballot_package_bytes(&[u8])`, which wraps the
> existing production ingestion pipeline without changing `BallotPackageV1` or
> verifier policy. The organizer UI now uses a native local ballot-package
> import picker and displays safe accepted/rejected messages without voter
> identity, raw nullifier, or intake sequence counts. Tauri proof preparation
> now releases the organizer session mutex before real proof generation by
> cloning only public immutable election artifacts and lifecycle state; the
> voter credential secret remains borrowed Rust-only. No-overwrite export
> collision messaging is clearer while retaining `create_new(true)`. Targeted
> gui-core intake tests cover valid import, exact replay, regenerated
> same-voter duplicate, second voter acceptance, wrong election, trailing bytes,
> governance-source-revision mutation, non-OPEN lifecycle rejection, and source
> metadata minimization. See
> `docs/reviews/PHASE5_SLICE5A11_LOCAL_BALLOT_OFFICE_WORKFLOW_2026-08-08.md`.
> No canonical format, vendored Triptych code, network, walletd, indexer,
> Ootle submission, relay, Tor, or OHTTP path was added.
> Phase 5 Slice 5A12A records the proposed private Internet ballot transport
> architecture, threat model, privacy-claim discipline, and ADR-0009. It
> preserves the 5A11 exact-byte intake boundary and adds no production source,
> canonical-format change, or Internet transport. Online delivery remains
> deferred pending authenticated transport configuration, implementation, and
> independent security/privacy review.
> Phase 5 Slice 5A12B adds a local-only, release-root-gated transport
> foundation: separate signed descriptor, RFC 9180 HPKE envelope, exact-byte
> gateway boundary, wire-safe receipt DTO, retry commitments, and
> accepted-unique anonymity counter. The production root remains deliberately
> unprovisioned and no online transport is enabled; see ADR-0010 and the 5A12B
> review.
> Continuation 5A12CDEF adds the first dedicated managed-Tor and opaque relay
> boundaries plus root-rotation primitives. These remain non-production until
> the documented persistence, existing-operator-anchor handoff, desktop wiring,
> packaging, and real-machine rehearsal gates are completed; see
> `docs/reviews/PHASE5_SLICE5A12CDEF_PRIVATE_TRANSPORT_IMPLEMENTATION_2026-08-09.md`.
> The authorized archive-binding continuation adds ADR-0011:
> `TransportArchiveBindingV1` is an ordinary hash-covered archive constituent,
> finalized before `ArchiveHashV1`; the frozen Phase 4 Ootle record/purpose are
> unchanged. A read-only Tauri/archive verifier reports `ANCHORED` only after
> a matching completed archive and existing verified Phase 4 evidence. This
> does not provide persistence, online submission, production roots, or a live
> network claim.
> The gateway now persists a strict versioned privacy-safe transport snapshot:
> descriptor/election binding, counters, capability commitments, digest/result
> retry records, and sealed/public batch proof material. Snapshot reload fails
> closed on corruption, incompatibility, or descriptor mismatch. Retry state is
> retained only through the active-election and configured verification-grace
> lifecycle, then deleted; raw capabilities, ballot bytes, identities, IPs,
> ingress times, headers, credentials, nullifiers, and keys are not persisted.
> `final_batch_set_commitment` remains a derived transport-level batch-root
> convenience commitment. The completed canonical archive's `ArchiveHashV1`
> remains the authoritative Phase 4 Ootle anchor commitment.

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
