# Phase 5 Slice 5A6 — Organizer Election Creation, Eligibility Registry, Freeze, and Export (2026-08-07)

## 1. Starting branch / HEAD

- **Starting branch:** `phase5/gui-core-foundation`
- **Starting HEAD:** `968660934dc656e5322d34fabb8afecd596b4b4f`
- **Working tree at start:** clean
- **Rust:** `rustc 1.97.1 (8bab26f4f 2026-07-14)` via
  `stable-x86_64-pc-windows-msvc`
- **Node:** v24.14.0, npm 11.9.0
- **No commit was created.** All changes are staged only.

Preconditions verified before any change: branch and HEAD match; working tree
clean; 5A4 real election loading (`GuiElectionArtifactsV1::from_paths` /
`from_bytes`) present and validated; 5A5 participation/result sealing present
(`SealedUntilClose` default while open; tally rejected before close); Governance
Pilot wording present; `Esmeralda Testnet` remains the current network wording.

## 2. Files changed

New:

- `crates/gui-core/src/creation.rs` — organizer creation facade (draft, preview,
  freeze, export, presentation type).
- `crates/gui-core/tests/creation.rs` — 34 deterministic creation tests
  (required cases 1–34).
- `gui/src/creation.ts` — pure frontend creation helpers (voter-list parsing,
  option validation, freeze-availability, presentation vocabulary, quorum
  statement).
- `docs/reviews/PHASE5_SLICE5A6_ORGANIZER_ELECTION_CREATION_2026-08-07.md` —
  this report.

Modified:

- `crates/gui-core/src/hex.rs` — added `from_hex` decoder and `abbreviate_hex`.
- `crates/gui-core/src/error.rs` — creation error constructors
  (`draft_already_frozen`, `draft_incomplete`, `malformed_public_key`,
  `malformed_hex_input`, `no_frozen_election`, `export_target_not_empty`,
  `export_target_invalid`).
- `crates/gui-core/src/lib.rs` — `creation` module and type exports.
- `gui/src-tauri/src/lib.rs` — draft state + creation Tauri commands
  (`start_election_draft`, `discard_election_draft`, `set_draft_basics`,
  `set_draft_rules`, `set_draft_voters`, `set_draft_options`,
  `set_draft_presentation`, `import_registry_to_draft`, `preview_draft`,
  `freeze_election`, `export_election_artifacts`).
- `gui/src/api/types.ts` — TypeScript mirrors of the creation DTOs.
- `gui/src/api/client.ts` — creation API methods + `presentationIdentifier`.
- `gui/src/api/dialog.ts` — `pickDirectory` and `pickTextFile` helpers.
- `gui/src/App.tsx` — passes `onNavigate` to `CreateElection`.
- `gui/src/screens/CreateElection.tsx` — real organizer wizard (Basics →
  Eligible voters → Ballot options → Voting rules → Review → Freeze & Export).
- `gui/src/styles/global.css` — wizard, stepper, voter textarea, option editor,
  and freeze-modal styles.
- `gui/test/pure.test.ts` — creation pure-helper tests.
- `PHASE_STATUS.md` — narrow factual update.

No Phase 1–4 crate source file was modified. No protocol, crypto, archive,
tally, registry, ballot, verification, walletd, or lifecycle logic changed. No
`Cargo.toml` or `Cargo.lock` changed (no new dependency).

## 3. Actual canonical ballot/election types discovered

The version-one canonical protocol exposes exactly:

- **One ballot kind:** `BallotKindV1::NonBindingApprovalPilot`
  (`crates/ballot/src/manifest.rs`). Its stable identifier is
  `NON_BINDING_APPROVAL_PILOT`. There is no candidate/governance/ballot-measure
  discriminator.
- **One ballot confidentiality:** `BallotConfidentialityV1::Public`.
- **One canonical option set:** `CandidateSet` — a sorted set of
  `CandidateDefinition { id: CandidateId, display_name }`. Candidate elections,
  governance proposals, and ballot measures all share this one representation.
  The set is sorted by machine ID and the commitment is computed over the
  sorted canonical CBOR (`crates/ballot/src/canonical.rs`), so input order does
  not affect the commitment.
- **One canonical registry:** `RegistrySnapshot` — a sorted set of
  `GovernancePublicKey` bytes (`crates/registry`). Entries are sorted by key
  bytes; the commitment is computed over the sorted canonical CBOR. The only
  public entry constructor is
  `RegistryEntry::from_voter_registration(VoterGovernanceKeyRegistrationV1)`,
  which accepts public key bytes plus a voter-owned provisioning attestation.
  The provisioning attestation is not serialized into canonical registry CBOR
  (only the key bytes are), so the choice of attestation has zero canonical
  effect.
- **One production proof suite:** `TARI_TRIPTYCH_PROOF_SUITE_ID_V1`
  (`"TARI_TRIPTYCH_PROTOTYPE_V1"`). `ProductionProofSuitePolicyV1` rejects
  every other suite, including `TEST_ONLY_SUITE_ID`.
- **Manifest fields (9):** protocol_version, election_id, ballot_kind,
  ballot_confidentiality, registry_commitment, candidate_set_commitment,
  proof_suite_id, approval_limits (minimum/maximum/allow_abstention),
  governance_source_revision. There is **no title, description, proposal
  question text, quorum, turnout threshold, or ballot-type discriminator.**

## 4. Candidate / governance / ballot-measure support finding

The candidate/governance/ballot-measure distinction is **UI-local presentation
only**, not canonical. The manifest carries only `NON_BINDING_APPROVAL_PILOT`
for every election. This slice therefore:

- does **not** invent a canonical discriminator;
- exposes an application-local `GuiBallotPresentationType`
  (`Candidate` / `GovernanceProposal` / `BallotMeasure`) that selects UI
  vocabulary only;
- documents it as non-canonical on the Basics screen ("This label controls
  application presentation. The current canonical protocol does not encode a
  candidate/governance/measure distinction.");
- marks `presentation_is_canonical = false` in every creation result.

## 5. Whether the distinction survives canonical export/import

**No.** The presentation type is not part of the canonical manifest and is not
serialized into any canonical file. After export, reloading the three
canonical files through the existing 5A4 loader yields a `NON_BINDING_APPROVAL
_PILOT` election with no presentation metadata. This is tested explicitly:

- `presentation_metadata_does_not_alter_canonical_bytes` — two drafts with
  different presentation types produce byte-identical manifest/registry/
  candidate CBOR and the same manifest hash.
- The frozen-result view states that the presentation type is application-local
  and will not appear when the exported files are reloaded.

A future canonical protocol decision would be required to carry the
presentation type across systems. This slice does not make that decision and
reports the gap.

## 6. Organizer creation facade

`crates/gui-core/src/creation.rs` is the application-facing organizer creation
facade. The Rust facade — not the frontend — validates every field and
constructs every canonical type:

- `GuiElectionDraftV1` — the stateful, non-secret organizer draft. Holds
  election ID bytes, governance source revision, approval limits, voter public
  key bytes, option (ID bytes + display name), and the application-local
  presentation type. After `freeze`, every mutator returns a bounded
  `GuiCoreError` (`GUI_DRAFT_ALREADY_FROZEN`), so a modified frontend cannot
  mutate a frozen election through this facade.
- `GuiElectionDraftPreviewV1` — pre-freeze review: computes the registry
  commitment, candidate-set commitment, and manifest hash for the sections that
  are complete, plus a `missing` list and a `complete` flag.
- `GuiElectionCreationResultV1` — the serializable frozen result (the frozen
  `GuiElectionSummaryV1` plus the non-canonical presentation type).
- `GuiElectionExportResultV1` / `GuiElectionExportFileV1` — export result.
- `write_election_artifacts_v1(artifacts, target_dir)` — writes the three
  canonical artifacts using the canonical filenames
  (`election-manifest.cbor`, `voter-registry.cbor`, `candidate-set.cbor`),
  never overwriting existing files, with atomic temp-file + rename writes.

`freeze()` builds the `RegistrySnapshot`, `CandidateSet`, and
`ElectionManifestV1`, encodes each to canonical CBOR, then **reloads them
through the existing `GuiElectionArtifactsV1::from_bytes` loader** (re-validating
every cross-binding and the production proof-suite policy), and finally opens a
`GuiElectionSessionV1` (which builds the registry-bound Triptych verifier and
freezes the lifecycle). This guarantees by construction that exported bytes
round-trip through the 5A4 loader and that the lifecycle is `FROZEN`.

The proof suite is fixed to the production Triptych suite and is not
selectable; the review screen shows the suite identifier as an advanced detail.

## 7. Voter registry workflow

The organizer builds the eligible-voter registry from **public governance keys
only**. The workflow supports:

- adding keys as a newline-separated hex list (one 64-hex-character / 32-byte
  key per line);
- removing/clearing by editing the list (the whole list is replaced on commit);
- importing an existing **canonical registry CBOR file**
  (`import_registry_to_draft`) which decodes via
  `RegistrySnapshot::from_canonical_cbor` and replaces the draft's key list;
- reviewing the eligible voter count and the computed registry commitment
  before freeze.

The organizer never handles voter credentials. The draft stores only public key
bytes. There is no API on the draft that accepts a scalar, seed, mnemonic, or
signing material.

## 8. Public-key validation / import behavior

Each key is validated in Rust through three layers:

1. hex decode (`from_hex`) — rejects non-hex / odd-length;
2. exact 32-byte length (`RISTRETTO_COMPRESSED_POINT_BYTES`);
3. `RistrettoPublicKeyV1::from_bytes` — rejects non-canonical encodings, the
   identity point, and non-point bytes (the same check the registry-bound
   Triptych verifier applies at session construction).

Duplicate keys are rejected with `DUPLICATE_GOVERNANCE_KEY`. An empty list is
permitted during editing; freeze rejects an empty registry
(`GUI_DRAFT_INCOMPLETE` / `EMPTY_REGISTRY` at `RegistrySnapshot::new`).

The newline-separated hex list is a **non-canonical convenience input format
only**. The canonical output is always registry CBOR via the existing encoder.
No CSV dependency was added.

## 9. Candidate / choice / response workflow

The option editor adapts vocabulary to the presentation type
(Candidates / Choices / Responses). Each option has a stable machine ID (text,
encoded as UTF-8 bytes) and a human-facing display label — the only two fields
the canonical `CandidateDefinition` supports. Add / edit / remove are available
before freeze.

**Ordering:** the canonical `CandidateSet` sorts by machine ID, so display order
in the editor is cosmetic and does not affect the commitment. This is stated on
the options screen and tested (`option_set_commitment_is_deterministic`,
`option_ordering_matches_canonical_backend_behavior`). Drag-reorder is not
exposed as authoritative.

Duplicate machine IDs (`DUPLICATE_CANDIDATE_ID`), empty IDs
(`EMPTY_CANDIDATE_ID`), and empty labels (`EMPTY_CANDIDATE_DISPLAY_NAME`) are
rejected. Ballot measures are not defaulted to Approve/Reject/Abstain; the
organizer enters the options explicitly.

## 10. Governance proposal text-binding findings

**The version-one manifest has no title, description, or proposal-question
field.** The only cryptographically bound governance text is
`governance_source_revision` (a free string pinned into the manifest). Option
display names and machine IDs are bound through the candidate-set commitment.

Per the slice's security requirement, this slice **does not** implement an
authoritative proposal-description / question-text field. Unbound text must
never be presented to a voter as the signed question. The Basics screen states
this explicitly:

> The version-one manifest has no title, description, or proposal-question
> field. Do not present unbound text to voters as the signed question; the
> governance source revision and the option display names are the binding.

This is a reported gap: a future canonical protocol decision would be required
to bind a human-readable question. No such field was invented here.

## 11. Voting-rule implementation

Only rules the protocol supports are exposed:

- minimum approvals;
- maximum approvals;
- abstention allowed.

`ApprovalLimits::new` enforces `minimum <= maximum`. At freeze, the facade also
rejects `maximum > option_count` (matching `ApprovalBallotPayload::new`'s
constraint) as `GUI_DRAFT_INCOMPLETE`. The review screen states
`NO_QUORUM_STATEMENT` ("No quorum rule is represented in this election
manifest."). No quorum, turnout threshold, passing threshold, supermajority,
weighted votes, delegation, or ranked-choice controls are exposed.

## 12. Review / freeze behavior

The Review step shows: election ID, governance source, ballot type (with the
non-canonical note), proof suite, voting rules, quorum statement, eligible
voter count, registry commitment, option count, the complete option list,
option-set commitment, and the manifest hash — all with Copy buttons.

A deliberate **Freeze Election** button (disabled until the preview is
complete) opens a confirmation modal stating that freezing locks the election
definition, registry, and options, and that changes become impossible without
creating a new election. The modal requires an explicit "Freeze Election"
confirm; "Cancel" returns to review. Text fields do not submit on Enter.

## 13. Post-freeze immutability

After `freeze`, the draft sets `frozen = true`; every `set_*` mutator returns
`GUI_DRAFT_ALREADY_FROZEN`. This is enforced in Rust (the facade), not just by
disabled React fields. Tested:

- `post_freeze_registry_mutation_is_rejected`;
- `post_freeze_option_mutation_is_rejected`;
- `post_freeze_rules_mutation_is_rejected`;
- `manifest_hash_is_stable_after_freeze`.

The loaded session is `FROZEN`; opening voting is a separate deliberate action.

## 14. Export behavior

`export_election_artifacts` writes the three canonical artifacts
(`election-manifest.cbor`, `voter-registry.cbor`, `candidate-set.cbor`) into a
chosen directory. Behavior:

- the directory is created when absent; an existing directory must be empty
  (`GUI_EXPORT_TARGET_NOT_EMPTY`); a file target is rejected
  (`GUI_EXPORT_TARGET_INVALID`);
- each file is written atomically (temp file, flush, sync, rename) and an
  existing file is never overwritten;
- the result returns the directory, per-file canonical relative path, absolute
  path, byte size, domain-separated archive-file digest (lowercase hex), and
  the manifest hash / registry commitment / candidate-set commitment.

No ZIP or single-file container was invented. The filenames match the existing
archive-writer convention.

## 15. Export / load round-trip proof

`export_then_5a4_load_round_trip_is_exact` exports a freshly frozen election,
reloads the three files through `GuiElectionArtifactsV1::from_paths`, and
asserts every canonical field matches the creation result: election ID, manifest
hash, registry commitment, candidate-set commitment, voter count, proof suite,
approval limits, abstention, governance source, ballot kind, and the ordered
option list.

Additional guarantees:

- `exported_bytes_equal_canonical_encoder_output` — the written bytes equal the
  canonical encoder output, and per-file digests equal the archive-file
  domain-separated digest;
- `same_draft_produces_identical_canonical_bytes_and_hash` — two drafts from
  identical inputs produce byte-identical artifacts;
- `creation_does_not_change_published_canonical_vectors` — the facade's output
  equals direct backend construction of the registry, candidate set, and
  manifest.

## 16. Security / secret boundary

- The draft holds only public governance key bytes and display data. It has no
  field for a scalar, seed, mnemonic, password, auth token, or signing
  material.
- `serialized_creation_result_contains_no_secret_material` serializes the
  creation result and preview through `serde_json` and asserts the fixture
  secret scalar hex and forbidden field names do not appear.
- `error_strings_contain_no_secret_material` asserts error strings carry no
  secret hex and are ASCII/bounded.
- `no_wallet_or_seed_field_exists_in_draft_dto` scans the draft DTO surface.
- The shell reads only explicitly chosen files; gui-core validates everything.
- No network, walletd, indexer, or signing activity (see §18).

## 17. Tests and counts

### Backend (gui-core)

- `crates/gui-core/tests/creation.rs` — **34 tests** covering creation (1–6),
  registry (7–12), options (13–17), freeze (18–22), export (23–29), secrets
  (30–32), and canonical invariance (33–34).
- Inline `creation.rs` unit tests — presentation round-trip, hex decode,
  abbreviate.
- gui-core total: **130 passed, 0 failed** (58 from 5A2 + 5A3 + 5A4 + 5A5 +
  34 new creation + inline).

### Frontend

- `gui/test/pure.test.ts` — **49 tests** (18 prior + 16 new creation
  pure-helper assertions across voter-list parsing, option validation,
  freeze-availability, presentation vocabulary, approval-rule preview, and the
  quorum statement).

### Workspace

- `cargo +stable-x86_64-pc-windows-msvc test --locked --offline --workspace` —
  all workspace tests pass, 0 failures (the pre-existing 7 ignored long
  Triptych suites remain).

## 18. Workspace validation

All cargo commands with `+stable-x86_64-pc-windows-msvc`, `--locked`,
`--offline`:

- `test -p tari-cc-private-ballot-gui-core` — 130 passed, 0 failed.
- `check --workspace --all-targets` — pass (only the pre-existing vendored
  Triptych `OperationTiming::Variable` dead-code warning; no project-owned
  warning).
- `test --workspace` — pass, 0 failures.
- `clippy --workspace --all-targets --no-deps -- -D warnings` — pass (only the
  pre-existing vendored Triptych warning; no project-owned warning).
- `clippy` on the Tauri shell crate (`gui/src-tauri`) — pass, no project-owned
  warning.

## 19. Frontend validation

- `npm test` (Node built-in runner) — 49 passed, 0 failed.
- `npm run build` (`tsc --noEmit && vite build`) — pass, no errors (42 modules;
  272.75 kB JS / 79.59 kB gzip; 22.48 kB CSS).

## 20. Native Tauri build

With `RUSTUP_TOOLCHAIN=stable-x86_64-pc-windows-msvc`, `npx tauri build`
completed successfully:

- Frontend production build passed (TypeScript + Vite).
- Optimized native release build compiled (offline; Tauri crate family cached).
- Native executable:
  `gui/src-tauri/target/release/tari-cc-private-ballot-gui.exe`.
- MSI installer:
  `gui/src-tauri/target/release/bundle/msi/Tari Private Ballot_0.1.0_x64_en-US.msi`.
- NSIS installer:
  `gui/src-tauri/target/release/bundle/nsis/Tari Private Ballot_0.1.0_x64-setup.exe`.

No new network fetch was required.

## 21. Network / walletd / indexer / signing status

No application network contact. No walletd contact. No indexer contact. No
Ootle transaction submission. No signing. All validation was performed offline
from local caches. The native Tauri build used only previously-cached
dependencies.

## 22. No secrets

No voter scalar, seed, mnemonic, password, auth token, or signing material
crosses the boundary. The draft, preview, creation result, and export result
DTOs contain only public keys, display data, commitments, hashes, and counts.
Error strings carry no secret material.

## 23. No canonical-format change

No protocol, crypto, archive, tally, registry, ballot, verification, or
lifecycle source file was modified. No canonical CBOR field, hash domain,
commitment, or test vector changed. The creation facade only composes existing
public constructors and encoders. `creation_does_not_change_published_canonical
_vectors` proves the facade's output equals direct backend construction.

## 24. Manual smoke-test checklist

To be performed by the human operator (not claimed to have passed unless
actually performed):

- [ ] launch the app (`tari-cc-private-ballot-gui.exe` or an installer).
- [ ] verify the toolbar badge reads "Governance Pilot".
- [ ] verify the status bar shows "Network: Esmeralda Testnet".
- [ ] open Create Election; verify a fresh draft starts.
- [ ] Basics: choose a ballot type; verify the non-canonical note appears.
- [ ] enter an election ID and governance source revision; Continue.
- [ ] Eligible voters: paste hex public keys; verify the count and malformed/
      duplicate feedback.
- [ ] import a canonical registry CBOR file; verify the keys populate.
- [ ] Ballot options: add candidates/choices/responses; verify duplicate/empty
      feedback; verify ordering note.
- [ ] Voting rules: set min/max/abstention; verify the quorum statement.
- [ ] Review: verify election ID, governance source, commitments, manifest hash.
- [ ] Freeze Election → confirm in the modal.
- [ ] verify "Election frozen" with manifest hash, registry commitment,
      option-set commitment.
- [ ] export to a chosen directory; verify the three `.cbor` files exist.
- [ ] open Manage Election; load those three files; compare all displayed
      hashes/counts/rules — they must match.
- [ ] verify the presentation type does NOT reappear after reload (it is
      non-canonical).
- [ ] return to Create Election → Freeze & Export → Open Voting.
- [ ] verify participation remains sealed while open.
- [ ] light/dark mode; keyboard-only navigation; window resize.

## 25. Staged hashes

Staged file count, per-file byte counts and SHA-256, and the full staged patch
byte count and SHA-256: see the staging transcript in the final task output
(computed at staging time after this document was written).

## 26. No commit

No commit was created. All changes are staged only. HEAD remains
`968660934dc656e5322d34fabb8afecd596b4b4f`.

## 27. Go / No-Go for the next slice

**READY FOR OPUS REVIEW.** Real organizer election creation is in place: a
backend-authoritative draft facade that validates every field, constructs the
canonical registry / candidate set / manifest, derives all commitments and the
manifest hash, freezes through the existing lifecycle, exports the three
canonical artifacts, and round-trips through the existing 5A4 loader. The
candidate/governance/ballot-measure distinction is correctly modeled as
application-local presentation; the proposal-text binding gap is reported and
no unbound text is presented as authoritative. Post-freeze immutability is
enforced in Rust. All offline validation passes with no project-owned warnings;
the native Tauri build produced the release executable and both installers. No
canonical format change, no protocol schema change, no secret-bearing field
crosses into TypeScript, no new network access, and no new dependency were
required.

Carried forward unchanged: voter key generation, credential import and proof
generation (next voter slice), live/coarse participation (deferred; small
electorates must fall back to sealed), full React render-test harness, and a
future canonical decision on ballot-type / proposal-question binding.

## 28. Pre-commit repair (independent review hardening)

An independent review of the staged 5A6 work returned an **APPROVE TO COMMIT**
verdict with four narrow pre-commit hardening fixes. These were applied on top
of the staged slice without broadening it and without resetting any existing
5A6 staging. No commit was created.

### 28.1 Independent review

- Verdict: **APPROVE TO COMMIT**.
- Scope of repair: four narrow fixes only (F1–F4 below). No canonical format
  change, no schema change, no new field, no broadening.

### 28.2 F1 — duplicate option display labels

The canonical `CandidateSet` deduplicates by machine ID only, so two options
with distinct machine IDs but identical display labels were accepted. Voters
primarily read display labels, so the organizer facade now rejects this case in
`GuiElectionDraftV1::set_options` before freeze:

- Comparison uses the same trim normalization the backend's display-label
  validation already applies (`CandidateDefinition::new` checks
  `display_name.trim().is_empty()`); canonical labels are never altered.
- No Unicode normalization was added.
- `CandidateSet` canonical behavior is unchanged.
- Stable bounded error code: `GUI_DUPLICATE_OPTION_DISPLAY_LABEL`
  (`InvalidInput`, context `options`), message:
  `"Ballot option display labels must be unique."`
- The frontend `optionValidationErrors` helper mirrors the same trim-based
  duplicate-label check for early UX; the backend re-validates authoritatively.
  Errors surface through the existing structured `ErrorCard`.

Tests added (`crates/gui-core/tests/creation.rs`):

1. `duplicate_option_id_is_still_rejected` — duplicate machine ID still
   rejected with `DUPLICATE_CANDIDATE_ID`.
2. `distinct_ids_with_duplicate_display_label_are_rejected` — distinct IDs +
   duplicate display label rejected with `GUI_DUPLICATE_OPTION_DISPLAY_LABEL`;
   no option state installed.
3. `distinct_display_labels_are_accepted` — distinct labels accepted.
4. `duplicate_display_label_rejection_happens_before_freeze_output` —
   rejection occurs at `set_options` time; the draft never reaches a complete
   state, `preview().manifest_hash_hex` is `None`, and `freeze()` returns
   `GUI_DRAFT_INCOMPLETE`.
5. `duplicate_display_label_is_detected_after_trim_normalization` —
   `"Yes"` and `"   Yes   "` collide.

### 28.3 F3 — uncastable approval configuration

The combination `min=0 / max=0 / abstention=false` was accepted by
`ApprovalLimits::new` (since `min <= max`) but permits no castable ballot (an
empty selection requires abstention; a non-empty selection exceeds the zero
maximum). The organizer facade now rejects it in
`GuiElectionDraftV1::set_rules`:

- Invariant: if `allow_abstention` is false, `approval_max` must be `>= 1`.
- The canonical `ApprovalLimits` type and protocol behavior are unchanged.
- Stable bounded error code: `GUI_UNCASTABLE_APPROVAL_LIMITS` (`InvalidInput`,
  context `rules`), message:
  `"At least one approval must be allowed when abstention is disabled."`
- The frontend `isUncastableApprovalConfig` helper mirrors the rule for early
  UX in the Rules step; the backend re-validates authoritatively.
- `min=0 / max>=1 / abstention=false` remains valid under the existing ballot
  validation semantics (a non-empty selection within `[min,max]` is castable),
  so it is not rejected.

Tests added:

1. `zero_max_with_abstention_disabled_is_rejected` — `0/0/false` rejected
   with `GUI_UNCASTABLE_APPROVAL_LIMITS`; no rules state installed.
2. `zero_max_with_abstention_enabled_is_accepted` — `0/0/true` accepted.
3. `zero_min_one_max_with_abstention_disabled_is_accepted` — `0/1/false`
   accepted.
4. `existing_min_max_validation_is_unchanged` — `min>max` still rejected with
   `INVALID_SELECTION_LIMITS`.

### 28.4 F2 — canonical registry import CBOR picker

The organizer action for importing a canonical voter registry previously used
the text/CSV-oriented picker (`pickTextFile`), so `.cbor` files were hidden by
default. Fix is UX-only:

- Added `pickRegistryCborFile` in `gui/src/api/dialog.ts` with a
  `{ name: "Canonical CBOR", extensions: ["cbor"] }` filter (plus
  "All files").
- `CreateElection.tsx::onImportRegistryFile` now uses
  `pickRegistryCborFile` for the canonical registry import.
- `pickTextFile` is preserved unchanged for the separate newline-list
  public-key text convenience input, so the two formats remain visually
  distinct.
- No parsing, filesystem permission, or dependency change. The canonical
  import is still decoded and validated exclusively in Rust via
  `RegistrySnapshot::from_canonical_cbor`.

### 28.5 F4 — canonical registry import test coverage

Direct automated coverage for `GuiElectionDraftV1::import_registry_bytes` was
added in `crates/gui-core/tests/creation.rs`. The expected registry commitment
and key bytes come from the independent canonical `RegistrySnapshot`
implementation, not the gui-core import helper under test.

- **TEST A — valid round-trip**
  (`import_registry_bytes_round_trips_and_matches_independent_commitment`):
  constructs a canonical `RegistrySnapshot` from the shared voter fixtures,
  encodes it through the canonical encoder, imports it into a fresh draft,
  completes enough state to preview/freeze, and asserts the imported registry
  commitment equals the independently constructed commitment, the voter count
  matches, and the public keys match canonical registry semantics (canonical
  order). The frozen session's registry commitment also matches.
- **TEST B — malformed CBOR**
  (`import_registry_bytes_rejects_malformed_cbor_without_corrupting_draft`):
  passes non-canonical bytes (`0xff 0xff 0xff`); asserts import is rejected
  with the stable bounded `UNEXPECTED_CBOR_TYPE` code, the draft is not
  partially corrupted, and no voter state is silently installed.
- **TEST C — mismatched/unsupported canonical registry format**
  (`import_registry_bytes_rejects_non_canonical_registry_format`): exercises an
  existing canonical format check — an out-of-order encoded registry is
  rejected with `NON_CANONICAL_CBOR`. No fake format was invented.
- `import_registry_bytes_preserves_prior_voters_on_failure`: a failed import
  leaves prior voter state intact (no silent corruption/removal).

### 28.6 Validation results

All cargo commands with `+stable-x86_64-pc-windows-msvc`, `--locked`,
`--offline`:

- `test -p tari-cc-private-ballot-gui-core` — **143 passed, 0 failed**
  (130 prior + 13 new: 5 F1 + 4 F3 + 4 F4). Inline `creation.rs` unit tests:
  3 passed.
- `check --workspace --all-targets` — pass (only the pre-existing vendored
  Triptych `OperationTiming::Variable` dead-code warning; no project-owned
  warning).
- `test --workspace` — pass, 0 failures (the pre-existing 7 ignored long
  Triptych suites remain).
- `clippy --workspace --all-targets --no-deps -- -D warnings` — pass (only the
  pre-existing vendored Triptych warning; no project-owned warning).

Frontend (`gui`):

- `npm test` (Node built-in runner) — **54 passed, 0 failed** (49 prior + 5
  new: duplicate-display-label after trim, and the four
  `isUncastableApprovalConfig` cases).
- `npm run build` (`tsc --noEmit && vite build`) — pass, no errors (42 modules;
  273.11 kB JS / 79.66 kB gzip; 22.48 kB CSS).

A native Tauri rebuild was not required (no Tauri Rust shell source change).

### 28.7 No canonical change / no network / no commit

- No `ElectionManifestV1`, `BallotKindV1`, `CandidateSet` encoding,
  `RegistrySnapshot` encoding, proof suite, canonical CBOR, archive format,
  tally, participation policy, or governance source semantics changed. No
  `Cargo.toml` / `Cargo.lock` changed. No new dependency.
- No proposal/title/question field was added. No quorum was added. No voting
  functionality was added.
- No network, walletd, indexer, or signing activity. All validation was
  offline from local caches.
- No commit was created. HEAD remains
  `968660934dc656e5322d34fabb8afecd596b4b4f`.

### 28.8 Files changed by repair

Modified:

- `crates/gui-core/src/creation.rs` — `set_options` duplicate-display-label
  rejection; `set_rules` zero-max/no-abstention rejection; doc comments.
- `crates/gui-core/src/error.rs` — `duplicate_option_display_label` and
  `uncastable_approval_limits` constructors.
- `crates/gui-core/tests/creation.rs` — 13 new tests (F1, F3, F4).
- `gui/src/api/dialog.ts` — `pickRegistryCborFile` helper.
- `gui/src/creation.ts` — duplicate-display-label check in
  `optionValidationErrors`; `isUncastableApprovalConfig` helper.
- `gui/src/screens/CreateElection.tsx` — use `pickRegistryCborFile` for
  canonical registry import; early `GUI_UNCASTABLE_APPROVAL_LIMITS` check in
  `onRulesNext`.
- `gui/test/pure.test.ts` — 5 new frontend tests.
- `docs/reviews/PHASE5_SLICE5A6_ORGANIZER_ELECTION_CREATION_2026-08-07.md` —
  this pre-commit repair section.

### 28.9 Final verdict

**READY TO COMMIT 5A6.** The four independent-review fixes are applied, all
offline validation passes with no project-owned warnings, no canonical type or
encoding changed, no proposal/title/question field was added, no
network/walletd/indexer/signing activity occurred, and no commit was created.
