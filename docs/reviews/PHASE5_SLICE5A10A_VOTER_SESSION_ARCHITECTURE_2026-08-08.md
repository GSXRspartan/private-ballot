# Phase 5 Slice 5A10A - Voter Session Architecture

Date: 2026-08-08

Starting branch: `phase5/gui-core-foundation`

Starting HEAD: `057d7041ae0aa37cad9a41ef9db15cd3c1051f55`

Mode: implemented, validated, staged; no commit.

## Why 5A10 Blocked

The original 5A10 target was too broad for the committed GUI state. The real
Triptych proof path already existed, but the GUI/Tauri voter side had only a
session-only credential slot. It lacked Rust-authoritative ballot selection,
prepared-ballot ownership, election/credential/selection generations, and
stale-operation rejection. Calling the prover directly from that state would
have risked attaching a future expensive proof result to the wrong election,
credential, or selection.

## Existing Proof Path Findings

The existing real path remains unchanged:

- `TariTriptychSecretKeyV1` owns a canonical nonzero scalar and derives the
  compressed governance public key in Rust.
- `prove_tari_triptych_prototype_v1` accepts a complete `ProofStatementV1`, a
  registry-bound `TariTriptychPrototypeVerifierV1`, and the Rust-only secret.
- The prover derives the signer key internally, finds the signer in the frozen
  canonical registry key list, creates a Triptych witness, uses OS randomness,
  and returns a Tari Triptych proof envelope with its public linking tag.
- `reconstruct_approval_proof_statement` binds manifest hash, election scope,
  registry commitment, ballot payload hash, ballot kind, and confidentiality.
- `BallotPackageV1` and its envelope are the existing canonical package types.
- `verify_approval_proof` is the existing verifier entry point.

Slice 5A10A does not call that prover and does not construct the final package.

## Rust Voter Session

`GuiVoterSessionV1` now owns the voter workflow for the loaded election:

- election binding/fingerprint;
- optional Rust-only credential session;
- optional validated canonical approval selection;
- non-secret credential generation;
- non-secret selection revision;
- non-secret preparation generation;
- prepared-ballot placeholder state.

The private credential remains inside Rust. No secret-bearing field is added to
TypeScript DTOs.

## Election Binding

The voter session binding is application-local and derived from existing stable
canonical data:

- election ID;
- manifest hash;
- registry commitment;
- candidate-set commitment.

It creates no canonical field and changes no vectors. A session bound to one
artifact triple rejects attempts to use another triple.

## Selection Model

The authoritative selection is stored as the existing
`ApprovalBallotPayload`. The Tauri command accepts only public option machine
IDs and an abstention flag. Rust decodes IDs, rejects malformed hex, and
delegates canonical rule enforcement to `ApprovalBallotPayload::new`.

Validation covers:

- unknown option;
- duplicate selection;
- below minimum;
- above maximum;
- abstention allowed/forbidden;
- abstention combined with options;
- deterministic canonical ordering.

## Lifecycle Gate

Future ballot preparation is gated on `ElectionLifecycleStateV1::Open`,
eligible credential status, and a valid selection. Selection editing can occur
outside `OPEN`; `can_prepare_ballot` remains false until the lifecycle permits
future proof work.

## Stale Operation Protection

`GuiVoterPreparationTokenV1` captures:

- operation id;
- election binding;
- credential generation;
- selection revision.

Credential replacement/reset, selection change/clear, workflow reset, election
replacement/unload, and lifecycle movement out of `OPEN` invalidate prepared
state. Tests install only a `#[cfg(test)]` synthetic marker; production has no
reachable ready ballot state in this slice.

## Concurrency Design for 5A10B

5A10B should use the token flow without holding the global voter mutex across
expensive proof work:

1. lock voter/session state briefly;
2. validate lifecycle, credential eligibility, and selection;
3. capture public election inputs plus a preparation token;
4. perform proof construction using narrowly scoped Rust-side secret access;
5. reacquire voter state;
6. install the prepared ballot only when token identities still match;
7. discard stale results without exposing proof/package data.

This slice does not clone or serialize the secret to enable that future flow.

## Tauri Commands

Added narrow commands:

- `voter_workflow_status`
- `voter_ballot_selection_status`
- `set_voter_ballot_selection`
- `clear_voter_ballot_selection`
- `reset_voter_workflow`

Existing credential commands now operate through the voter session.

No future proof command was added.

## Frontend Workflow

The Vote screen now reaches:

- review election;
- governance credential;
- eligibility;
- ballot selection;
- privacy proof not generated yet.

Ballot selection renders the real canonical options with checkbox controls,
selection count, min/max status, optional abstention, visible focus, and
`aria-live` feedback. Results, tallies, leaders, percentages, accepted counts,
proofs, nullifiers, and package bytes are not shown.

## Export Boundary

No export function was added because production cannot create a real
`PreparedBallotReady` object in 5A10A. 5A10B must keep canonical bytes
Rust-owned, write atomically, avoid overwrite, and verify read-back before
reporting export readiness.

## Zeroization Hardening

`TariTriptychSecretKeyV1::generate_os_rng` now wraps the transient random
scalar in `Zeroizing` and zeroizes the transient `[u8; 32]` after parsing into
the existing secret-key wrapper. The credential format and proof logic are
unchanged.

## Explicit Absences

- No real Triptych proof is generated.
- No nullifier or linking tag is generated.
- No canonical ballot package is generated.
- No canonical format or canonical vector changes were made.
- No walletd, indexer, Ootle submission, HTTP, telemetry, or vote submission
  was added.

## Validation

Passed:

- `cargo +stable-x86_64-pc-windows-msvc check --locked --offline -p tari-cc-private-ballot-gui-core --all-targets`
- `cargo +stable-x86_64-pc-windows-msvc check --locked --offline --workspace --all-targets`
- `cargo +stable-x86_64-pc-windows-msvc check --locked --offline --all-targets` in `gui/src-tauri`
- `cargo +stable-x86_64-pc-windows-msvc test --locked --offline -p tari-cc-private-ballot-gui-core --lib`
- `cargo +stable-x86_64-pc-windows-msvc clippy --locked --offline -p tari-cc-private-ballot-gui-core --all-targets --no-deps -- -D warnings`
- `cargo +stable-x86_64-pc-windows-msvc clippy --locked --offline --workspace --all-targets --no-deps -- -D warnings`
- `cargo +stable-x86_64-pc-windows-msvc clippy --locked --offline --all-targets --no-deps -- -D warnings` in `gui/src-tauri`
- `npm test` in `gui` (`75` tests passed)
- `npm run build` in `gui`

Cleanup note:

- During validation, `cargo fmt --all` temporarily touched unrelated Rust
  files. Those formatter-only changes were restored individually to HEAD after
  explicit user approval. No intended 5A10A implementation, tests,
  documentation, or status changes were removed.

Caveats:

- `cargo +stable-x86_64-pc-windows-msvc test --locked --offline --workspace`
  passed through the new voter-session tests and later failed in existing
  `tests/governance.rs::t24_hostile_filename_cannot_control_archive_path`
  with Windows `Access is denied` while writing the hostile filename fixture.
- `npx tauri build` produced
  `gui/src-tauri/target/release/tari-cc-private-ballot-gui.exe`, then failed in
  MSI bundling at WiX `light.exe`.

## Manual Smoke Checklist

Manual checklist not executed:

1. launch;
2. load election;
3. review bound data;
4. confirm review;
5. generate/load controlled credential;
6. eligibility shown;
7. reach ballot selection;
8. select options;
9. min/max behavior;
10. abstain behavior;
11. modify selection;
12. reset credential;
13. verify selection/prepared readiness updates;
14. unload election;
15. verify state clears;
16. load another election;
17. verify no stale voter state;
18. proof stage clearly says not generated;
19. no result information visible;
20. light/dark;
21. keyboard-only selection;
22. resize.

## Staging

Staged hashes are recorded in the final Codex response for this slice.

No commit was created.

## Independent Review Repair Pass

Opus 4.8 High returned `APPROVE WITH FOLLOW-UPS`: no blockers, no high-severity
findings, one medium lifecycle DTO finding, and low/info items for 5A10B.

F1 was repaired before commit. `GuiVoterSessionV1::set_selection` now receives
the actual `ElectionLifecycleStateV1` from its caller and returns selection DTOs
through the same lifecycle-aware status path used by `clear_selection` and
workflow refreshes. The Tauri `set_voter_ballot_selection` command obtains the
current lifecycle from the validated election session and passes it into
gui-core. A selection update during `FROZEN`, `CLOSED`, `VERIFIED`, or
`FINALIZED` therefore no longer fabricates `OPEN`, and `can_prepare_ballot`
remains false outside `OPEN`.

New direct tests cover:

- `set_selection` during `FROZEN` stores the selection but reports `FROZEN` and
  `can_prepare_ballot = false`;
- `set_selection` during `OPEN` reports `OPEN` and becomes preparation-ready
  only when the eligible credential and valid selection gates are also met;
- `set_selection` during `CLOSED` reports `CLOSED` and is not preparation-ready;
- non-open lifecycle DTOs never fabricate `OPEN`;
- competing preparation operations reject operation A after operation B starts,
  then allow B to install only the existing `#[cfg(test)]` marker;
- `begin_preparation_operation` rejects no credential, ineligible credential,
  no selection, `FROZEN`, `CLOSED`, `VERIFIED`, and `FINALIZED` with the stable
  `ELECTION_NOT_OPEN` validation code.

The optional frontend race hardening was applied narrowly. Vote-screen selection
toggles derive from the latest local draft selection IDs, and a request
generation guard prevents stale backend responses from overwriting newer
selection responses. TypeScript still does not duplicate canonical ballot
validation; Rust remains authoritative.

5A10B must choose one explicit secret ownership model before adding real proof
generation:

- Option A: hold the voter-session mutex across proof construction. This is the
  simplest model, keeps the secret in place without cloning or moving, and
  blocks stale-state mutation commands until proof generation returns. The cost
  is that voter state commands are blocked during potentially long proof work.
- Option D: introduce a dedicated generation-checked proof-job ownership
  structure. This allows broader UI/state responsiveness and token-based stale
  result rejection, but requires more architecture and must keep secret ownership
  explicit and non-cloning.

5A10B must not use an unguarded move-out/restore model for the credential
secret. A reset while the secret is temporarily absent could otherwise be
followed by accidentally restoring stale secret state.

5A10B must also explicitly decide the ready-after-close policy. The conservative
direction to evaluate is: a prepared ballot may remain inspectable after proof
completion, but export/submission readiness should be invalidated once voting is
no longer `OPEN`, unless reviewed protocol semantics explicitly allow delivery
of a ballot prepared before close.

This repair pass did not generate a real Triptych proof, did not generate a
nullifier/linking tag, did not construct a canonical ballot package, and did not
change canonical election, registry, candidate, ballot payload, proof, archive,
tally, participation, governance-source, credential, wallet, or submission
formats.

Repair validation:

- `cargo +stable-x86_64-pc-windows-msvc test --locked --offline -p tari-cc-private-ballot-gui-core --lib`: 61 passed.
- `cargo +stable-x86_64-pc-windows-msvc check --locked --offline --workspace --all-targets`: passed.
- `cargo +stable-x86_64-pc-windows-msvc clippy --locked --offline --workspace --all-targets --no-deps -- -D warnings`: passed.
- `cargo +stable-x86_64-pc-windows-msvc test --locked --offline --workspace`: passed.
- `cargo +stable-x86_64-pc-windows-msvc check --locked --offline --all-targets` in `gui/src-tauri`: passed.
- `cargo +stable-x86_64-pc-windows-msvc clippy --locked --offline --all-targets --no-deps -- -D warnings` in `gui/src-tauri`: passed.
- `npm test` in `gui`: 75 passed.
- `npm run build` in `gui`: passed.

Native Tauri packaging was not rerun for this repair pass. No network, walletd,
indexer, Ootle submission, or relay was used. No commit was created.

## 5A10B Readiness

5A10B should implement the real proof/package path only after review confirms:

- the secret can be borrowed or otherwise scoped without serializing raw
  material;
- statement reconstruction remains unambiguous;
- token comparison gates every install path;
- canonical package export includes read-back verification;
- no ready state is exposed before proof self-verification succeeds.
