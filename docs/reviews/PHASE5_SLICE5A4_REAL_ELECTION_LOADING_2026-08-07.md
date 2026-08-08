# Phase 5 Slice 5A4 — Real Election Loading and Dashboard Integration (2026-08-07)

## 1. Starting branch / HEAD

- **Starting branch:** `phase5/gui-core-foundation`
- **Starting HEAD:** `0938f73eddb3466fdccb7ecaf8a40fbfe5002d52`
- **Working tree at start:** clean
- **Rust:** `rustc 1.97.1 (8bab26f4f 2026-07-14)` via
  `stable-x86_64-pc-windows-msvc`
- **Node:** v24.14.0, npm 11.9.0
- **No commit was created.** All changes are staged only.

## 2. Files changed

Modified:

- `Cargo.lock` — one added line: `serde_json` added to the
  `tari-cc-private-ballot-gui-core` dependency list (serde_json 1.0 was already
  locked for other workspace crates; no version re-resolved, no new package
  fetched).
- `crates/gui-core/Cargo.toml` — added `serde_json = "1.0"` to
  `[dev-dependencies]` (test-only; used by the new serialization boundary
  test to exercise the exact JSON path the Tauri command boundary uses).
- `crates/gui-core/tests/serialization.rs` — new (see §13).
- `gui/src-tauri/src/lib.rs` — `binding_notice` wording corrected to the
  calm scope notice only (see §3); no new command, no DTO shape change.
- `gui/src-tauri/tauri.conf.json` — added an explicit `"label": "main"` to
  the window so the narrow capability can target it by label.
- `gui/src/api/types.ts` — unchanged (existing types cover the loaded summary).
- `gui/src/ballot/ballotTypes.ts` — neutrality updates (see §10).
- `gui/src/state/AppState.tsx` — structured error + selected paths + dismiss
  (see §7).
- `gui/src/components/ui.tsx` — `ErrorCard`, `DetailsSection`, `CopyButton`,
  structured `BackendErrorNotice` (see §11, §12).
- `gui/src/components/AppFrame.tsx` — toolbar Governance Pilot badge, election
  indicator, network status (see §3, §8).
- `gui/src/styles/global.css` — styles for error card, details, copy, file
  selection, toolbar election indicator.
- `gui/src/screens/{Home,ManageElection,CreateElection,Vote,About,Archive,
  Anchor,Evidence}.tsx` — real data, native pickers, structured errors,
  staged-state wording (see §3, §8, §9, §10, §11).
- `gui/src/App.tsx` — passes `onNavigate` to Home for the Load Election empty
  action.
- `gui/package.json` — added `test` script (Node built-in test runner).

New:

- `gui/src/api/dialog.ts` — native Tauri open-file picker (see §5).
- `gui/src/api/errorDisplay.ts` — structured error presentation mapping
  (see §11).
- `gui/src-tauri/capabilities/default.json` — narrow dialog capability
  (see §12).
- `gui/test/pure.test.ts` — frontend pure-logic tests (see §13).
- `docs/reviews/PHASE5_SLICE5A4_REAL_ELECTION_LOADING_2026-08-07.md` — this
  report.
- `PHASE_STATUS.md` — narrow factual update.

No Phase 1–4 crate source file was modified. No protocol, crypto, archive,
tally, verification, walletd, or lifecycle logic changed. The Tauri shell
commands were already present from 5A3 (`load_election`, `unload_election`,
`election_summary`); 5A4 consumes them from the frontend and corrects the
shell's static `binding_notice` wording only.

## 3. Wording corrections (Governance Pilot)

The product-status label is the short, compact text "Governance Pilot". It
appears exactly as that text in two compact product-status elements:

- the toolbar badge (`AppFrame.tsx`: `<Pill tone="brand">Governance Pilot
  </Pill>`);
- the About screen Status field (`About.tsx`: `<Pill tone="brand">Governance
  Pilot</Pill>`).

No warning sentence is appended to that badge/status label. The longer scope
notice appears exactly once, in the About screen, as a calm informational
notice:

> Scope. This release is intended for governance pilots. Binding governance
> use requires the applicable review and authorization process.

The Tauri `ShellInfoV1.binding_notice` field carries only that calm scope
wording (the DTO shape is unchanged; no new field was added, and
"Governance Pilot." was not prepended to the notice). Product status and scope
notice are conceptually separate.

All user-facing occurrences of "Non-production prototype" and equivalent
prototype-status wording were removed. No remaining user-facing occurrence
exists in `gui/src` or `gui/src-tauri/src`. The old Home footer prototype pill
was removed; Home no longer repeats any pilot-status disclaimer.

## 4. Esmeralda / Igor handling

The status bar shows `Network: Esmeralda Testnet` as the current active/test
workflow. No user-facing occurrence of "Igor" as a current network exists in
the GUI. The backend `network` value is not hardcoded into shell state; the
status bar copy is a fixed user-facing label only. Igor remains future/deferred
and is not presented as current.

## 5. Native file picker

`gui/src/api/dialog.ts` exposes `pickElectionArtifact(title)`, which calls the
Tauri `dialog` plugin's native open-file dialog (`@tauri-apps/plugin-dialog`
`open`, single file, non-recursive, `.cbor`/all-files filter). The dialog
returns a selected path string only; no file is read, copied, or modified by
this helper. Reading and validation happen in the Rust shell through
gui-core. When the frontend runs outside the desktop shell (plain browser
preview), selection resolves to `null` and screens render their neutral states.

## 6. Tauri command boundary

The 5A3 shell already exposed `load_election(manifest_path, registry_path,
option_set_path)`, `unload_election`, and `election_summary` as thin Tauri
commands delegating verbatim to gui-core (`GuiElectionArtifactsV1::from_paths`
→ `GuiElectionSessionV1::new` → `summary()`). 5A4 consumes these commands from
the frontend and adds no new command. The command:

- accepts the three selected paths;
- calls gui-core only;
- returns the structured serializable `GuiElectionSummaryV1`;
- returns structured bounded `CommandError`s (stable code, category, context,
  message);
- never decodes CBOR itself;
- never reimplements hash/commitment validation;
- never contacts a network.

The returned summary exposes every field the frontend displays: election
identifier (hex + text), lifecycle state, manifest hash, registry commitment,
candidate/option-set commitment, eligible voter count, proof suite, approval
limits, abstention policy, governance source revision, ballot kind,
confidentiality, and the ordered option list (machine IDs + display labels).

**Ballot-type discriminator gap:** the current manifest format carries only
`ballot_kind = NON_BINDING_APPROVAL_PILOT` for every election and exposes no
explicit candidate/governance/ballot-measure discriminator. 5A4 does not invent
one from filenames; the frontend uses neutral "Ballot options" vocabulary by
default and adapts only when an explicit type is chosen on the Create Election
screen (see §10).

## 7. Application state

`AppState` holds one validated loaded election:

- `election: GuiElectionSummaryV1 | null` — the real backend summary;
- `tally`, `recentActions`, `settings` — unchanged from 5A3;
- `backendError: GuiCommandError | null` — the last structured backend error
  (replaces the old plain string);
- `selectedArtifactPaths: SelectedArtifactPaths | null` — session-only record
  of the artifact paths chosen for the loaded election (not persisted; cleared
  on unload);
- `dismissError()` — clears the active backend error.

`loadElection` sets the election, clears tally, captures the selected paths,
and records a recent action. `unloadElection` clears election, tally, error,
and selected paths (no files are deleted). The state stores no voter secret
credential, walletd auth token, private key, mnemonic, seed, or raw canonical
file bytes.

## 8. Home dashboard real data

When no election is loaded, Home shows a calm empty state: "No election loaded"
with a primary "Load Election" action that navigates to Manage Election. When
an election is loaded, Home displays real backend-derived values only:

- election identifier/title, lifecycle, ballot kind, eligible voters, ballot
  options count (neutral label);
- manifest hash, registry commitment, option-set commitment (with Copy);
- proof suite, confidentiality, approval rule, abstention policy, governance
  source;
- Archive status: "Not created"; Anchor status: "Not anchored";
- Participation: "Not available" (no fabricated participation/ballot counts or
  dates).

No Governance Pilot disclaimer is repeated on Home.

## 9. Manage Election real data

Manage Election now has a real "Load Election" card with three native
file-picker controls (manifest, registry, candidate/option set). Selected
filenames are displayed before loading; the Load button is disabled until all
three files are selected. Filenames are shown for convenience only — identity
is derived from the decoded bytes by gui-core.

When an election is loaded, the screen displays:

- Election overview: identifier, lifecycle, proof suite, ballot kind,
  confidentiality, manifest hash (with Copy);
- Eligibility: voter count, registry commitment (with Copy);
- Voting rules: approval rule, abstention, governance source;
- Ballot options table: context-sensitive label (Candidates/Choices/Responses
  /Ballot options), display label, machine ID;
- Advanced Details card: manifest hash, registry commitment, option-set
  commitment, proof-suite identifier, canonical election ID (all with Copy),
  plus a collapsible canonical option IDs list;
- Loaded artifacts card (session only): the three selected basenames.

Actions in this slice: Load Election, Unload Election, Copy non-secret
hashes/IDs. The lifecycle/intake/tally/archive step cards remain from 5A3 and
call real gui-core commands. The screen never edits the frozen canonical
artifacts after loading.

## 10. Ballot-type neutrality

`ballotTypes.ts` presentation vocabulary:

- candidate election → "Candidates";
- governance proposal → "Choices";
- ballot measure → "Responses";
- loaded election with no explicit discriminator → neutral "Ballot options".

The canonical backend `CandidateSet` type was not renamed. The frontend adapts
backend candidate-set data into neutral UI language. No protocol schema
change. The loaded option set renders identically under each type, with
vocabulary adjusted only when an explicit type is chosen (Create Election).

## 11. Error handling

`errorDisplay.ts` maps `GuiCommandError` (code/category/context/message) onto
an `ErrorDisplay` (concise title derived from category, safe bounded message,
stable machine code). `ErrorCard` renders this as an alert card with an
"Advanced details" disclosure showing the machine code, category, and context.
Dismissal is keyboard accessible. Categories are visually distinguished by
title (invalid input, malformed file, version unsupported, binding mismatch,
proof-suite unsupported, file I/O). No raw Rust backtrace, secret, or
unbounded third-party text is ever rendered. All screens (Home, Manage
Election, Archive, Anchor, Evidence) now use the structured `BackendErrorNotice`
with `GuiCommandError`.

## 12. Permissions / security

- `gui/src-tauri/capabilities/default.json` grants only `dialog:allow-open`,
  scoped to the `main` window. No filesystem write, no recursive scan, no shell
  execution, no remote access.
- CSP remains strict (`default-src 'self'`, no remote origins, no inline
  styles/scripts) in both `index.html` and `tauri.conf.json`.
- `withGlobalTauri: false`.
- No secrets anywhere in state, settings, or storage.
- The shell reads only explicitly chosen files; gui-core validates everything.
- No network, walletd, indexer, or Ootle contact (see §16, §17).

## 13. Tests

### Backend / Tauri (gui-core)

Existing 5A2 tests cover required cases 2–6 (wrong registry commitment, wrong
option-set commitment, missing file, malformed canonical, no network use).
Slice 5A4 adds `crates/gui-core/tests/serialization.rs` (2 new tests):

1. `valid_load_returns_structured_summary` — valid paths return a structured
   election summary with every field the frontend displays (case 1).
2. `serialized_summary_carries_no_secret_field` — serializes the summary
   through `serde_json` exactly as the Tauri boundary does and asserts no
   secret-bearing field name or fixture secret scalar hex appears in the JSON
   (case 7).

gui-core total: 58 passed, 0 failed (56 from 5A2 + 2 new).

### Frontend / state

`gui/test/pure.test.ts` (11 tests, Node built-in test runner with TypeScript
type stripping; no heavy framework added). Covers the pure, framework-free
presentation and error-mapping logic:

- errorDisplay: binding-mismatch title/message/code; file-not-found title;
  unknown-category fallback (case 13).
- ballotTypes: Candidates label (case 17); Choices label; Responses label
  (case 18); neutral "Ballot options" default; explicit candidate override.
- approvalRuleText: range rule + abstention; exact rule; abstention-permitted.

**Deferred (require a later frontend-test harness):** render-level cases 8–12,
14–16, 19–20 (empty-state render, loaded state population, option tables,
unload clears state, selected-filenames display, load-button disabled state).
These need a React/DOM test runner; per the slice instructions, no heavy
framework was added to satisfy them. The underlying logic they exercise is
covered by the pure tests and the gui-core serialization test.

### Workspace

- `cargo +stable-x86_64-pc-windows-msvc test --locked --offline --workspace` —
  956 passed, 0 failed, 7 ignored (the pre-existing manual long Triptych
  suites; identical character to the 5A3 baseline, +2 from the new gui-core
  serialization tests).

## 14. Build validation

All cargo commands with `+stable-x86_64-pc-windows-msvc`, `--locked`,
`--offline`:

- `test -p tari-cc-private-ballot-gui-core` — 58 passed, 0 failed.
- `check --workspace --all-targets` — pass.
- `test --workspace` — 956 passed, 0 failed, 7 ignored.
- `clippy --workspace --all-targets --no-deps -- -D warnings` — pass (only the
  pre-existing vendored Triptych `OperationTiming::Variable` dead-code warning
  remains; no project-owned warning).

Frontend (`gui`):

- `npm run build` (`tsc --noEmit && vite build`) — pass, no errors (37 modules;
  244.08 kB JS / 73.20 kB gzip; 15.68 kB CSS).
- `npm test` — 11 passed, 0 failed.

## 15. Native Tauri build

With `RUSTUP_TOOLCHAIN=stable-x86_64-pc-windows-msvc`, `npx tauri build`
completed successfully:

- Frontend production build passed (TypeScript + Vite).
- Optimized native release build compiled (offline; Tauri crate family cached
  from the 5A3 one-time fetch).
- Native executable produced:
  `gui/src-tauri/target/release/tari-cc-private-ballot-gui.exe`.
- MSI installer produced:
  `gui/src-tauri/target/release/bundle/msi/Tari Private Ballot_0.1.0_x64_en-US.msi`.
- NSIS installer produced:
  `gui/src-tauri/target/release/bundle/nsis/Tari Private Ballot_0.1.0_x64-setup.exe`.

No new network fetch was required: the Tauri crate family and WiX/NSIS tooling
were already cached from the 5A3 build. The Rust shell `cargo check --locked
--offline` passes offline.

## 16. No network / walletd / indexer

No application network contact. No walletd contact. No indexer contact. No
Ootle transaction submission. No signing. All Rust/frontend validation was
performed offline from local caches. The native Tauri build used only
previously-cached dependencies.

## 17. No transaction / signing

No transaction submission, no signing, and no anchor driver invocation was
added or performed. The anchor/evidence screens remain read-only inspection
wrappers over Phase 4 artifacts.

## 18. Manual smoke-test checklist

To be performed by the human operator (not claimed to have passed unless
actually performed):

- [ ] launch the app (`tari-cc-private-ballot-gui.exe` or an installer).
- [ ] verify the Tari logo appears in the toolbar.
- [ ] verify the toolbar badge reads exactly "Governance Pilot".
- [ ] verify the status bar shows "Network: Esmeralda Testnet".
- [ ] switch light/dark mode (toolbar toggle and Settings → Automatic).
- [ ] open Manage Election → Load Election.
- [ ] select three real canonical artifacts (manifest, registry, option set)
      via the native file pickers.
- [ ] verify selected filenames display before loading.
- [ ] click "Load and Validate Election"; verify success.
- [ ] inspect Home: verify real election identifier, lifecycle, manifest hash,
      eligible voter count, ballot options count.
- [ ] inspect Manage Election: verify Election overview, Eligibility, Voting
      rules, Ballot options table, Advanced Details (hashes + Copy), Loaded
      artifacts.
- [ ] verify the voter count matches the registry.
- [ ] verify hashes copy to clipboard.
- [ ] unload the election; verify Home returns to the empty state.
- [ ] load a mismatched artifact set (e.g. a wrong registry); verify a
      friendly structured error card with title, message, and Advanced details
      (machine code).
- [ ] dismiss the error via the Dismiss button.
- [ ] resize the window; verify the layout adapts.
- [ ] keyboard-navigate: Tab through toolbar, navigation, Load Election
      controls; verify visible focus and the skip link.
- [ ] open About: verify "Status: Governance Pilot" and the single calm Scope
      notice; verify no pilot disclaimer appears on Home or the toolbar beyond
      the compact badge.

## 19. Staged hashes

Staged file count, per-file byte counts and SHA-256, and the full staged patch
byte count and SHA-256: see the staging transcript in the final task output
(computed at staging time after this document was written).

## 20. No commit

No commit was created. All changes are staged only. HEAD remains
`0938f73eddb3466fdccb7ecaf8a40fbfe5002d52`.

## 21. Go / No-Go for 5A5

**READY FOR 5A5.** Real election loading, native file selection, structured
error presentation, real Home/Manage data, ballot-type neutrality, and the
Governance Pilot / Esmeralda wording corrections are in place. All offline
validation passes with no project-owned warnings; the native Tauri build
produced the release executable and both installers. No canonical format
change, no protocol schema change, no secret-bearing field crosses into
TypeScript, no new network access, and no major new dependency were required.

Deferred items carried forward unchanged: voter key generation (own reviewed
crypto slice before 5A6), credential import and proof generation (next voter
slice), election creation (next organizer slice), full React render-test
harness, bundled Poppins binaries, and CSS minification (cosmetic).

---

## 22. Pre-commit repairs (independent 5A4 review, 2026-08-07)

An independent review of the staged 5A4 work identified a pre-existing
running-tally disclosure gap and two narrow wording findings. The repairs
below were applied on top of the staged 5A4 work. No earlier 5A4 change was
reset or discarded. No commit was created.

### F1 — HIGH: Sealed-results / tally disclosure gate

The independent review found that Manage Election enabled "Compute tally"
whenever an election was loaded, the `current_tally` Tauri command did not
enforce lifecycle, and `GuiElectionSessionV1::tally` did not enforce
lifecycle. An organizer could therefore compute and view running results
while voting was OPEN.

- **Backend lifecycle gate added.** `GuiElectionSessionV1::tally` now refuses
  to disclose any tally data while the lifecycle is `DRAFT`, `FROZEN`, or
  `OPEN`, returning a bounded `GuiCoreError` and computing nothing. Tally is
  available only after voting has closed (`CLOSED`, `VERIFIED`, `FINALIZED`),
  matching the existing append-only lifecycle semantics. No new lifecycle
  state was invented.
- **Stable error.** New constructor
  `GuiCoreError::tally_not_available_before_close` with code
  `GUI_TALLY_NOT_AVAILABLE_BEFORE_CLOSE`, category
  `INVALID_LIFECYCLE_TRANSITION` (existing lifecycle category), context
  `tally`, and bounded message
  "Tally results are not available until voting is closed." No tally data or
  accepted-option counts are exposed before the error is returned.
- **Tauri boundary.** The `current_tally` Tauri command is unchanged; it
  continues to delegate to `session.tally()`. The Rust gui-core/session gate
  remains authoritative; no lifecycle logic was duplicated in the Tauri
  command.
- **Frontend gate.** Manage Election now disables "Compute tally" unless
  `lifecycle` is `CLOSED`, `VERIFIED`, or `FINALIZED`, via a new pure helper
  `gui/src/lifecycle.ts` (`canShowTally`). While FROZEN/OPEN the tally values
  are not rendered and a restrained line "Results are sealed until voting
  closes." is shown (no warning banner). Per-option counts are never exposed
  while OPEN.
- **`direct_tally` unchanged.** The raw `GuiElectionSessionV1::direct_tally`
  remains ungated because it is the internal entry point used by archive
  replay equality checks and facade/backend equality tests; it is not exposed
  to the Tauri command. Archive replay (`verify_archive_directory_v1`)
  recomputes its tally independently and is unchanged.
- **Tally arithmetic unchanged.** No canonical format, no archive replay
  behavior, and no tally arithmetic changed.

### F1 tests added (`crates/gui-core/tests/tally.rs`)

- `tally_is_sealed_while_frozen` — FROZEN returns
  `GUI_TALLY_NOT_AVAILABLE_BEFORE_CLOSE`.
- `tally_is_sealed_while_open` — OPEN returns the same stable error.
- `tally_is_available_after_close` — CLOSED succeeds and reports the real
  leader.
- `tally_is_available_after_verified` — VERIFIED succeeds.
- `tally_is_available_after_finalized` — FINALIZED succeeds.
- `assert_no_tally_leak` — the sealed-results error carries no candidate,
  approval, accepted-ballot, or leading-result text, and uses the existing
  `INVALID_LIFECYCLE_TRANSITION` category.
- `direct_tally_remains_available_while_open_for_replay_equality` — the raw
  backend tally stays available for archive-replay equality checks.
- Existing tally correctness tests (`no_approvals…`, `single_leader…`,
  `unresolved_top_count…`, `facade_tally_equals_direct_backend_tally`) were
  updated to close the session before calling the gated `tally()`; their
  arithmetic assertions are unchanged. Archive replay tally tests
  (`archive_verify.rs`) are unchanged (they already close before tallying).

### F1 frontend tests added (`gui/test/pure.test.ts`)

A `lifecycle tally gate` suite covers `canShowTally`/`resultsAreSealed` for
DRAFT, FROZEN, OPEN, CLOSED, VERIFIED, FINALIZED, null, undefined, and an
unknown state. The pure helper mirrors the backend vocabulary so the button
state stays consistent with the authoritative Rust gate. Component-level
render gating (button disabled + sealed line) is manually smoke-tested;
backend enforcement is covered by the Rust tests above.

### F2 — MEDIUM: Home archive/anchor status wording

The loaded session does not have authoritative knowledge that no archive or
anchor exists elsewhere. The Home dashboard previously asserted "Not
created" / "Not anchored" as fact. Wording corrected to truthful
session-local unknown state:

- Archive status: "No archive loaded in this session"
- Anchor status: "No anchor state loaded in this session"

No archive or anchor behavior changed.

### F6 — Grammar

`PHASE_STATUS.md` line 12 corrected from "the sections below this header
was last maintained" to "the sections below this header were last
maintained". No other documentation was rewritten.

### Files changed by this repair

Modified:

- `crates/gui-core/src/session.rs` — `tally()` lifecycle gate.
- `crates/gui-core/src/error.rs` — `tally_not_available_before_close`.
- `crates/gui-core/tests/tally.rs` — gate tests + existing tests closed first.
- `gui/src/screens/ManageElection.tsx` — Compute tally button gate + sealed
  line.
- `gui/src/screens/Home.tsx` — archive/anchor session-local wording.
- `gui/test/pure.test.ts` — lifecycle gate pure-logic tests.
- `PHASE_STATUS.md` — F6 grammar fix.
- `docs/reviews/PHASE5_SLICE5A4_REAL_ELECTION_LOADING_2026-08-07.md` — this
  section.

New:

- `gui/src/lifecycle.ts` — pure `canShowTally` / `resultsAreSealed` helpers
  and the `TALLY_AVAILABLE_LIFECYCLE_STATES` vocabulary.

### Validation results

- `cargo +stable-x86_64-pc-windows-msvc test --locked --offline
  -p tari-cc-private-ballot-gui-core` — PASS (all suites green, including
  the 6 new gate tests and the updated correctness tests).
- `cargo +stable-x86_64-pc-windows-msvc check --locked --offline
  --workspace --all-targets` — PASS (the only warning is a pre-existing
  dead-code warning in `third_party/tari-triptych`, not project-owned).
- `cargo +stable-x86_64-pc-windows-msvc clippy --locked --offline
  --workspace --all-targets --no-deps -- -D warnings` — PASS (no
  project-owned warnings).
- `cargo +stable-x86_64-pc-windows-msvc test --locked --offline
  --workspace` — PASS (all workspace tests green, zero failures).
- `npm test` (Node built-in runner) — PASS (18 tests, including the 7 new
  lifecycle gate assertions).
- `npm run build` (`tsc --noEmit && vite build`) — PASS.
- Native Tauri rebuild was not run: no Tauri shell/Rauri source changed
  (`gui/src-tauri/**` unchanged); the `current_tally` command still
  delegates to `session.tally()`, and no DTO shape changed.

### Confirmations

- No canonical format changed; no protocol schema changed.
- Archive replay and `direct_tally` behavior unchanged.
- No network, walletd, indexer, or signing activity; fully offline and
  deterministic.
- No new major dependency; no `Cargo.lock` change from this repair.
- No secret-bearing field crosses into TypeScript.
- No commit was created; all changes are staged only.
- HEAD remains `0938f73eddb3466fdccb7ecaf8a40fbfe5002d52`.

### Final verdict

**READY TO COMMIT 5A4.**
