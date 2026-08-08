# Phase 5 Slice 5A5 — Participation Metrics, Sealed Disclosure Policy, and Dashboard Analytics (2026-08-07)

## 1. Starting branch / HEAD

- **Starting branch:** `phase5/gui-core-foundation`
- **Starting HEAD:** `dd7c3b6106c20b5816ef9964daa6b7bf108abec0`
- **Working tree at start:** clean
- **Rust:** `rustc 1.97.1 (8bab26f4f 2026-07-14)` via
  `stable-x86_64-pc-windows-msvc`
- **Node:** v24.14.0, npm 11.9.0
- **No commit was created.** All changes are staged only.

The 5A4 sealed-results gate was verified present before any change:
`GuiElectionSessionV1::tally` rejects `DRAFT`/`FROZEN`/`OPEN` with
`GUI_TALLY_NOT_AVAILABLE_BEFORE_CLOSE`; the frontend Compute-tally button is
unavailable before `CLOSED`. This slice does not weaken that gate.

## 2. Files changed

New:

- `crates/gui-core/src/participation.rs` — backend participation model and
  disclosure-policy helpers.
- `crates/gui-core/tests/participation.rs` — sealed-disclosure security tests.
- `gui/src/components/icons.tsx` — lightweight inline SVG lock/check icons.
- `gui/src/components/ParticipationTrack.tsx` — linear progress track.
- `gui/src/components/ResultBars.tsx` — horizontal per-option result bars.
- `docs/reviews/PHASE5_SLICE5A5_PARTICIPATION_AND_DISCLOSURE_2026-08-07.md` —
  this report.

Modified:

- `crates/gui-core/src/session.rs` — `participation_summary()` method.
- `crates/gui-core/src/lib.rs` — exports for the new participation types.
- `gui/src-tauri/src/lib.rs` — `participation_summary` Tauri command.
- `gui/src/api/types.ts` — TypeScript mirrors of the participation DTOs.
- `gui/src/api/client.ts` — `participationSummary` API method.
- `gui/src/lifecycle.ts` — pure formatting/policy helpers.
- `gui/src/state/AppState.tsx` — participation state + refresh wiring.
- `gui/src/screens/Home.tsx` — analytics metric cards gated by visibility.
- `gui/src/screens/ManageElection.tsx` — participation analytics + result
  bars + quorum note.
- `gui/src/styles/global.css` — analytics, progress track, result bar styles.
- `gui/test/pure.test.ts` — participation/policy/format tests.
- `PHASE_STATUS.md` — narrow factual update.

No Phase 1–4 crate source file was modified. No canonical format, protocol
schema, archive schema, cryptography, walletd semantics, or Ootle lifecycle
semantics changed.

## 3. Participation metric model

`GuiParticipationSummaryV1` (in `crates/gui-core/src/participation.rs`)
is derived authoritatively in Rust from:

- `eligible_voters` — the frozen registry size
  (`artifacts.registry().len()`, already exposed as `voter_count` in the
  election summary).
- `accepted_ballots` — the ballot-acceptance ledger length
  (`session.accepted_count()`), deduplicated by registry-scoped nullifier so
  `accepted <= eligible` is invariant through the public API.
- `participation_basis_points` — `accepted * 10000 / eligible` (integer, no
  floating point), `0` when `eligible == 0`, saturating at `10000` if
  `accepted >= eligible`.
- `remaining_eligible_capacity` — `eligible - accepted` (saturating).
- `lifecycle_state`, `participation_visibility`, `result_visibility`,
  `small_electorate`, `coarse_bucket`.

The numeric participation fields (`accepted_ballots`,
`participation_basis_points`, `remaining_eligible_capacity`) are `Option` and
set to `None` while the visibility policy seals them, so a modified frontend
cannot retrieve sealed counts by calling the command. `eligible_voters` is
always present because it is public registry information already exposed by
the election summary.

## 4. Participation visibility policy

Three variants are modeled (`ParticipationVisibility`):

- `Live` — exact accepted count and percentage may be shown (post-close).
- `Coarse` — only a coarse bucket is shown while open; exact count/percentage
  hidden.
- `SealedUntilClose` — while open, no participation numerics are disclosed.

The conservative **default resolution** (`participation_visibility_for`),
computed from lifecycle state alone because the manifest carries no
privacy-mode field:

- `DRAFT` / `FROZEN` / `OPEN` → `SealedUntilClose`
- `CLOSED` / `VERIFIED` / `FINALIZED` → `Live`

`ResultVisibility` mirrors the 5A4 tally gate: `Sealed` before close,
`Disclosed` after.

## 5. Canonical vs application-local policy

**Application-local, not canonical.** The version-one election manifest
(`crates/ballot/src/manifest.rs`) carries no participation-visibility,
privacy-mode, quorum, or threshold field. The visibility policy is computed
from lifecycle state by the gui-core session facade and is never serialized
into canonical election files or the offline archive. The `Coarse` and `Live`
variants are modeled so a future operator/manifest policy can select them
without changing the DTO shape; the current default never selects `Live` or
`Coarse` while voting is open.

This is documented in the `participation.rs` module doc and asserted by the
test `participation_summary_does_not_alter_canonical_bytes_or_archive_hash`,
which proves computing the summary twice does not change the archive hash.

## 6. Small-electorate privacy behavior

`SMALL_ELECTORATE_THRESHOLD = 25`. When the eligible electorate is below this
threshold, `small_electorate = true` is exposed in the DTO for transparency.
Because the default policy is already `SealedUntilClose` while open, small
electorates are inherently protected: no live timeline or exact count is
shown while voting is open regardless of electorate size. The dashboard shows
a calm "Small electorate: live detail is withheld while voting is open" note
after close (informational). The fixture electorate (3 voters) is below the
threshold, so the tests exercise this flag directly.

## 7. Turnout-history / event-source findings

The archive's `IngestSequenceV1` (`crates/archive/src/replay.rs:34`) is
**ordering metadata only. It is not a wall-clock timestamp** and does not
identify a voter, relay, device, or source account. No authoritative event
time is recorded anywhere in the ballot intake, ledger, or transcript.

**Decision: no turnout-over-time chart is implemented.** Fabricating a time
series from current totals would be misleading. The dashboard renders a
professional linear progress track (current disclosed percentage only) with
an explicit "trend unavailable" state when sealed. No `participation_series`
Tauri command is added because there is no authoritative series to expose.
A future backend intake-timestamp or checkpoint source would be required
before a chart is justified; that would be its own reviewed slice and must
not change deterministic archive semantics.

## 8. Exact metrics exposed in each lifecycle/policy state

| Lifecycle | Participation visibility | Result visibility | Accepted count | Participation % | Remaining capacity | Coarse bucket |
|-----------|--------------------------|-------------------|----------------|-----------------|--------------------|---------------|
| DRAFT | SealedUntilClose | Sealed | None | None | None | None |
| FROZEN | SealedUntilClose | Sealed | None | None | None | None |
| OPEN | SealedUntilClose | Sealed | None | None | None | None |
| CLOSED | Live | Disclosed | Some | Some | Some | None |
| VERIFIED | Live | Disclosed | Some | Some | Some | None |
| FINALIZED | Live | Disclosed | Some | Some | Some | None |

`eligible_voters` is always present. The `Coarse` bucket is `None` under the
default policy (it would be `Some` only if a future policy selected `Coarse`
while open).

## 9. Result-disclosure policy

Unchanged from 5A4: per-option approvals, leading option, result percentages,
and abstention distribution are sealed while `DRAFT`/`FROZEN`/`OPEN` and
disclosed only after close (`CLOSED`/`VERIFIED`/`FINALIZED`) through the
existing `GuiElectionSessionV1::tally` gate. The participation DTO carries
`result_visibility` so the frontend renders the disclosure state rather than
inventing the rule. The frontend ResultBars component renders a locked neutral
state ("Results are sealed until voting closes.") while sealed and never
renders hidden result values.

## 10. Backend enforcement

- `GuiElectionSessionV1::participation_summary()` is authoritative: it
  computes the visibility from lifecycle state and returns `None` for sealed
  numerics. A modified frontend cannot retrieve sealed counts.
- `GuiElectionSessionV1::tally()` (5A4 gate) remains authoritative for
  per-option results and is unchanged.
- The `participation_summary` Tauri command delegates verbatim to
  `session.participation_summary()`; no lifecycle logic is duplicated in the
  shell.
- The acceptance ledger enforces one acceptance per registry-scoped nullifier,
  so `accepted_ballots <= eligible_voters` is invariant; remaining capacity
  uses saturating arithmetic as a defensive bound.

## 11. Dashboard implementation

Home is upgraded with a professional analytics section (`.analytics-grid`)
containing metric cards:

- **Participation** — percentage or "Sealed" with lock icon; progress track;
  policy label; small-electorate note when applicable.
- **Accepted ballots** — count or sealed state.
- **Eligible voters** — always shown (public registry info).
- **Lifecycle** — lifecycle pill + result-visibility label.
- **Results** — locked neutral state while sealed; pointer to Manage Election
  after disclosure.

The visual target is a calm, modern governance/admin dashboard. Tari branding
is used sparingly (existing toolbar). No neon, no gradients, no animation-heavy
behavior. Light/dark support uses the existing Tari design tokens via CSS
custom properties (`--primary`, `--text`, `--text-secondary`, `--surface`,
`--border`). `prefers-reduced-motion` disables bar transitions.

## 12. Chart / progress implementation

A lightweight `ParticipationTrack` React component renders a horizontal
progress track (div-based, no chart library). The fill width is `bps / 100`%.
When sealed, the track shows an empty state with a "Sealed" label. No SVG
line chart is used because no authoritative time series exists. No new
dependency was added.

## 13. Final-result visualization

`ResultBars` renders horizontal per-option bars after disclosure. Each bar
independently represents the percentage of accepted ballots approving that
option. Abstentions are shown separately. The leading/tie state is rendered
as text (never an invented winner; a tie is called a tie). Pie charts are
intentionally not used for multi-approval ballots. While sealed, the
component renders a locked neutral state with a lock icon and the line
"Results are sealed until voting closes."

## 14. Multi-approval percentage semantics

Each option's approval percentage is labeled "Approved by X% of accepted
ballots", not "X% of the vote", because v1 approval ballots allow a voter to
approve multiple options and the bars do not sum to 100%. The denominator is
the accepted-ballot count from the tally. The pure helper `approvalBps`
computes `approvals * 10000 / acceptedBallots` (integer, saturating at 10000).
The `isMultiApprovalBallot` helper returns `true` for every v1 ballot kind,
centralizing the rule so pie charts are never used. The frontend tests assert
that two options each approved by 2 of 3 voters yield 66.6% each (bars sum to
133.2%, which is correct for multi-approval).

## 15. Quorum / threshold findings

The version-one manifest carries no quorum, minimum-participation, approval
threshold, or passing-threshold field. No governance rule is inferred from
Tari community conventions. The Manage Election Voting rules card displays
"No quorum rule defined by this election." with an explanatory note. No
threshold marker is rendered because no authoritative threshold exists.

## 16. Tests and counts

### Rust tests (`crates/gui-core/tests/participation.rs`)

18 tests covering all section-O requirements:

1. `frozen_participation_is_sealed_until_close`
2. `open_live_policy_exposes_participation_only_not_results` (default is
   sealed; documents the `Live` variant is not selected while open)
3. `open_coarse_policy_exposes_bucket_only_not_exact_count` (default is
   sealed; `coarse_bucket` stays `None`)
4. `open_sealed_exposes_neither_exact_participation_nor_trend`
5. `closed_permits_exact_participation`
6. `open_result_visibility_is_sealed`
7. `closed_result_visibility_is_disclosed`
8. `current_tally_remains_rejected_while_open`
9. `no_result_dto_returns_hidden_option_counts_while_open`
10. `no_leading_candidate_leaks_while_open`
11. `zero_eligible_voters_is_safe`
12. `zero_percent_participation_is_safe`
13. `one_hundred_percent_participation_is_safe`
14. `accepted_ballots_never_exceeds_eligible_voters`
15. `participation_visibility_and_result_visibility_are_consistent_with_tally_gate`
16. `verified_and_finalized_disclose_participation_and_results`
17. `participation_summary_does_not_alter_canonical_bytes_or_archive_hash`
18. `coarse_bucket_labels_are_stable_and_non_overlapping`

The participation module also carries 10 unit tests (basis-points rounding,
coarse buckets, visibility resolution, stable identifiers). Existing tally
tests (10) and all other gui-core tests remain green.

### Frontend tests (`gui/test/pure.test.ts`)

39 tests total (18 pre-existing + 21 new), covering:

- percentage formatting (one decimal, truncation, clamping, null)
- coarse bucket labels
- sealed presentation (no count leak, accessible text)
- disclosed presentation (exact counts in accessible text)
- coarse presentation (bucket only, no exact counts)
- multi-approval result labeling (share of accepted ballots, not the vote)
- no pie/share-of-total assumption
- zero-voter / no-fake-trend state

## 17. Workspace validation

- `cargo +stable-x86_64-pc-windows-msvc test --locked --offline
  -p tari-cc-private-ballot-gui-core` — **PASS** (all suites green,
  including the 18 new participation tests, 10 tally tests, and all
  existing suites).
- `cargo +stable-x86_64-pc-windows-msvc check --locked --offline
  --workspace --all-targets` — **PASS** (the only warning is a pre-existing
  dead-code warning in `third_party/tari-triptych`, not project-owned).
- `cargo +stable-x86_64-pc-windows-msvc clippy --locked --offline
  --workspace --all-targets --no-deps -- -D warnings` — **PASS** (no
  project-owned warnings).
- `cargo +stable-x86_64-pc-windows-msvc test --locked --offline
  --workspace` — **PASS** (all workspace tests green, zero failures).

## 18. Frontend build

- `npm test` (Node built-in runner) — **PASS** (39 tests, 0 failures).
- `npm run build` (`tsc --noEmit && vite build`) — **PASS** (41 modules,
  clean type-check, production bundle produced).

## 19. Native Tauri build

A full `npx tauri build` was not run (it rebuilds the entire Tauri framework
toolchain and exceeds the interactive time budget). The Tauri lib was checked
with `cargo check --locked --offline --manifest-path gui/src-tauri/Cargo.toml
--lib` — **PASS**, clean, no project-owned warnings. The
`participation_summary` command delegates verbatim to
`session.participation_summary()` and introduces no DTO shape change beyond
the new typed return. A full native rebuild remains the recommended
pre-release verification step.

## 20. Accessibility

- The participation track and result bars carry `role="img"` with an
  `aria-label` containing the full textual equivalent
  (`participationAccessibleText`), so a screen reader learns
  "Participation 65.2%, 163 of 250 eligible voters" without interpreting SVG
  geometry.
- Numeric values are always rendered as text alongside any visual; color is
  never the sole information channel.
- `prefers-reduced-motion` disables bar/track transitions.
- The lock icon is `aria-hidden` and always paired with a textual
  "Sealed"/"Locked" label.
- Focus visibility is inherited from the global `:focus-visible` style.

## 21. Network / socket / walletd / indexer / signing status

- No network access. No walletd contact. No indexer contact. No Ootle
  transaction submission. No signing.
- Fully offline and deterministic. The `gui-core` crate performs no network,
  walletd, or indexer I/O (asserted by the existing
  `gui_core_sources_contain_no_network_or_async_usage` security test).
- No secret-bearing field crosses into TypeScript (asserted by the existing
  `serialized_summary_carries_no_secret_field` test; the participation DTO
  carries only public registry size, lifecycle state, and ledger-derived
  counts).

## 22. Manual smoke-test checklist

Documented; not claimed human-completed:

1. Launch app.
2. Light theme.
3. Dark theme.
4. Load a real election.
5. Inspect the participation card.
6. Verify exact participation in LIVE mode where allowed (post-close).
7. Verify coarse presentation in COARSE mode (not selected by default;
   requires a future policy).
8. Verify SEALED mode hides count and percentage while OPEN.
9. Verify the result card remains locked while OPEN.
10. Verify Compute tally remains unavailable while OPEN.
11. Close the election.
12. Verify exact participation appears.
13. Compute/disclose results.
14. Inspect final result bars.
15. Verify a tie renders as a tie.
16. Verify multi-approval percentage wording ("Approved by X% of accepted
    ballots").
17. Resize the window.
18. Keyboard navigation.
19. Screen-reader accessible metric text.
20. Unload the election and verify analytics clear.

## 23. Documentation path

`docs/reviews/PHASE5_SLICE5A5_PARTICIPATION_AND_DISCLOSURE_2026-08-07.md`
(this file). `PHASE_STATUS.md` was updated narrowly (next-authorized-work
pointer only).

## 24. Staged file count / hashes

- **Staged file count:** 18
- **Staged patch size:** 107,900 bytes
- **Staged patch SHA-256:**
  `11d4ac2b74b8219f7e011eb3a207d971ff9391f4a39b2b8362f16e5240de3464`
- **Summary:** 18 files changed, 2294 insertions(+), 14 deletions(-)
- `git diff --cached --check` — clean (no whitespace errors).

Per-file git blob SHA-1 (working-tree content of each staged file):

| File | Blob SHA-1 |
|------|-----------|
| `PHASE_STATUS.md` | `c924d8f782fdb9f39ed4fb7938b669b379cd5cf5` |
| `crates/gui-core/src/lib.rs` | `b5278f2d8afa83aab5b0502bb0dc5fd5e4a46f0a` |
| `crates/gui-core/src/participation.rs` | `b7de71853504f160b318f18e511b5da8bcdc8a36` |
| `crates/gui-core/src/session.rs` | `faa39fbf7c785d70e5e056316fcc3fc591751061` |
| `crates/gui-core/tests/participation.rs` | `32e04537a8446bd83c04aa30dfc4c6fee3cf1ba7` |
| `docs/reviews/PHASE5_SLICE5A5_PARTICIPATION_AND_DISCLOSURE_2026-08-07.md` | `97f95dc5b33c4becc0bf6195c82afa132dd26a21` |
| `gui/src-tauri/src/lib.rs` | `90da7c0663afd46754e8725f7da649764ad62003` |
| `gui/src/api/client.ts` | `9c6b7c8aedafa4a2293a84dc225f4c0b7eb4aac0` |
| `gui/src/api/types.ts` | `234e751d3b44137391b18d299893571f11d34c78` |
| `gui/src/components/ParticipationTrack.tsx` | `7d0d99d8d09e1bf13ea00d8e9c76c2e4e17fa626` |
| `gui/src/components/ResultBars.tsx` | `dce42577390c7cb58d6dc2fdebe0770b50588cf8` |
| `gui/src/components/icons.tsx` | `8d83089c722492f08202dd64b6dd086d35101621` |
| `gui/src/lifecycle.ts` | `cf69113cdf7bc6811591e23a102153a2225e81e0` |
| `gui/src/screens/Home.tsx` | `4baf63182d18429cd279783e3bec06d139d6da58` |
| `gui/src/screens/ManageElection.tsx` | `aa38081d683e3902edb85be5ce21cda89668e453` |
| `gui/src/state/AppState.tsx` | `d5ea4e58c29fb66e8bcffa03015596c8d17bb79c` |
| `gui/src/styles/global.css` | `c16ccb170626dfc5886c7801d87102c0428eeff7` |
| `gui/test/pure.test.ts` | `b010382204195a2aa24cbeebe7631435b31ba8cf` |

## 25. No commit

No commit was created. All changes are staged only. HEAD remains
`dd7c3b6106c20b5816ef9964daa6b7bf108abec0`.

## 26. Go / No-Go for the next slice

**READY FOR OPUS REVIEW.** Authoritative participation metrics, a
backend-enforced sealed-disclosure policy, a professional light/dark analytics
dashboard, multi-approval-correct result bars, and strong sealed-results
security tests are in place. The 5A4 tally gate is preserved and re-asserted.
No canonical format, protocol schema, archive semantics, walletd semantics,
or Ootle lifecycle semantics changed. No network access, no new major
dependency, and no secret-bearing value crosses into TypeScript. The turnout
chart is intentionally omitted because no authoritative event-time source
exists; this is documented as a known gap for a future reviewed slice.
