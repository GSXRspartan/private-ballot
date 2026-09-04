# Performance remediation — Slice 1 report

**Repository:** `tari-ballot-organizer-anchor-deployment-gui` (worktree of `tari-cc-private-ballot`)
**Branch:** `feature/organizer-anchor-deployment-gui`
**Date:** 2026-08-29
**Inputs:** `AUDIT_ELECTION_RECONSTRUCTION_AND_CRYPTO_REPLAY.md`, `AUDIT_CRYPTO_TRIGGER_MATRIX.csv`, `AUDIT_TAURI_COMMAND_BLOCKING_MATRIX.csv`

**Scope of this slice:** remove unnecessary cryptographic replay from ordinary GUI operations and move confirmed CPU-heavy discovery off the Tauri event thread — **without** introducing the verified-session cache, **without** changing the durable workspace format, and **without** weakening any verification. All of those remain deferred.

---

## 1. Files changed

### Production — Rust (`crates/`)

| File | Change |
|---|---|
| `crates/gui-core/src/instrumentation.rs` | **New.** Dev/test observational counters (atomics only): workspace-list/summarize calls, `from_durable_snapshot` calls, historical ballots replayed, gui-core intake verifications, crypto-adapter verifications (surfaced from the crypto crate), and reconstruction/verification duration totals. Snapshot + reset. No sensitive data. |
| `crates/gui-core/src/lib.rs` | Register `pub mod instrumentation;`. |
| `crates/gui-core/src/session.rs` | Wrap `from_durable_snapshot` in a thin timing/counting shell delegating to a new `from_durable_snapshot_inner` (behaviour unchanged); count one historical replay per package in the replay loop; count one Triptych verification and record its duration per `process_intake_package`. No decision, ordering, or output changed. |
| `crates/gui-core/src/workspace.rs` | **Metadata-only `summarize_workspace`** for session workspaces: decode + cross-validate artifacts via `GuiElectionArtifactsV1::from_bytes` (no verifier, no ring, no ballot) instead of `GuiElectionSessionV1::from_durable_snapshot`; take lifecycle state and the stored-package count straight from the durable snapshot. Rename the summary field `accepted_ballot_count` → `stored_ballot_count` with explicit non-authoritative provenance docs. Count list/summarize calls. |
| `crates/crypto/src/instrumentation.rs` | **New.** Observational counter at the application's own Triptych verifier adapter. Counts invocations only — no proof/ring/nullifier/voter data. Does **not** touch `third_party/tari-triptych` or curve25519-dalek. |
| `crates/crypto/src/lib.rs` | Register `pub mod instrumentation;` and export `verify_invocation_count` / `reset_verify_invocation_count`. |
| `crates/crypto/src/triptych_verifier.rs` | One observational increment at the top of `TariTriptychPrototypeVerifierV1::verify`. No cryptographic change. |

### Production — frontend (`gui/`)

| File | Change |
|---|---|
| `gui/src/state/AppState.tsx` | `runLifecycle` no longer calls `refreshWorkspaces()`. After a successful transition it patches only the active workspace row locally (`lifecycle_state`, `finalized`) from the **authoritative summary the command returned** — no reconstruction, no fabrication. |
| `gui/src/api/types.ts` | `GuiElectionWorkspaceSummaryV1.accepted_ballot_count` → `stored_ballot_count`, documented as display-only/non-authoritative. |
| `gui/src/screens/Home.tsx` | Render `stored_ballot_count`; relabel the column "Ballots stored" with a tooltip stating it is not the verified accepted tally. |
| `gui/src-tauri/src/lib.rs` | `list_election_workspaces` and `delete_election_workspace` converted to `async` + `run_blocking_command` (off the event thread). Delete keeps its fail-closed active-workspace guard on the async thread (cheap lock reads) before dispatching the filesystem work. |

### Tests / docs

| File | Change |
|---|---|
| `crates/gui-core/tests/reconstruction_instrumentation.rs` | **New.** Proves listing does zero reconstruction/verification and resume/intake still verify. |
| `crates/gui-core/tests/workspace.rs` | Field-rename updates (`stored_ballot_count`); values unchanged (all-accepted fixtures). |
| `gui/test/performanceRemediationSlice1.test.ts` | **New.** Source-level regression pins for the frontend/shell/gui-core guarantees. |
| `PERFORMANCE_REMEDIATION_SLICE1_REPORT.md` | This report. |
| `AUDIT_CRYPTO_TRIGGER_MATRIX.POST_SLICE1.csv`, `AUDIT_TAURI_COMMAND_BLOCKING_MATRIX.POST_SLICE1.csv` | **New companion CSVs** — the originals verbatim plus one `post_slice1_status` column marking each row RESOLVED / IMPROVED / PARTIAL / DEFERRED / UNCHANGED. The original audit CSVs are left byte-for-byte intact so the findings are preserved. |

---

## 2. Exact behavioural changes

1. **Workspace listing is metadata-only.** `list_election_workspaces_v1` → `summarize_workspace` no longer reconstructs a `GuiElectionSessionV1` for session workspaces and therefore performs **no Triptych verification and no historical ballot replay**. It decodes the canonical artifacts (manifest/registry/candidates) to recover the manifest hash and proposal question, and reads the lifecycle state and stored-package count from the durable snapshot. Revision-chain integrity (digest + predecessor checks in `load_committed_history`) still runs before summarisation, so corruption/tamper detection at the durable layer is unchanged. Ballot-level verification is deferred to when the election is actually opened.

2. **Listing/delete run off the event thread.** Both commands are now `async` and execute their filesystem work through `run_blocking_command` (`spawn_blocking`). The known main-thread hang path is gone even before the crypto cost was removed.

3. **Lifecycle actions no longer re-list.** Open/Close/Verify/Finalize previously triggered a full `refreshWorkspaces()` → listing → (previously) full replay of every workspace. They now patch the single active row locally from the command's own authoritative summary. No workspace is created or removed by a lifecycle transition, so nothing else needs refreshing.

4. **The displayed count is explicitly non-authoritative.** The summary field is renamed to `stored_ballot_count` and labelled "Ballots stored". It is the durable package count (accepted + duplicate + rejected), an upper bound — never presented as the verified accepted tally. The authoritative accepted count still comes only from an opened, replay-verified session (participation/tally).

5. **A double replay was incidentally removed.** Because `summarize_workspace` is now metadata-only, `resume_election_workspace_v1` no longer reconstructs the session twice (audit finding F-5); it reconstructs exactly once — the one legitimate, required verification when opening an election.

**Not changed:** the durable format; every proof/signature/binding/nullifier/tally/finalization/anchor check; the intake and inbox-reconciliation verification paths; the archive verifier; `MAX_REGISTRY_MEMBERS`; any Triptych or curve25519 logic; any dependency.

---

## 3. Before/after trigger matrix (ordinary operations)

| Trigger | Before | After |
|---|---|---|
| **Application startup** | `AppStateProvider` mount → `list_election_workspaces` (**sync, main thread**) → `summarize_workspace` → `from_durable_snapshot` → replay **every** ballot of **every** workspace → Triptych verify (N×W). Main-thread hang. | Same entry → `list_election_workspaces` (**async, blocking pool**) → metadata-only summarise (`from_bytes` decode) → **0** `from_durable_snapshot`, **0** replays, **0** Triptych. Off the event thread. |
| **Home screen** | Renders `AppState.workspaces` (0 effects), but that array was populated by the replay-heavy listing. | Identical rendering; the underlying listing is now metadata-only. **0** replay. |
| **Tab switch away/back** | Remounts the target screen. **No** screen mount effect calls listing (only `AppStateProvider` does, and it never unmounts), so historical durable-ballot replay was already **0**. (Manage's mount fires `sync_private_intake`, which verifies only genuinely *new* inbox ballots — out of scope, unchanged.) | Identical: **0** historical durable-ballot replay from navigation. Confirmed by source: no screen imports `listElectionWorkspaces`. |
| **Lifecycle action (Open/Close/Verify/Finalize)** | `runLifecycle` → command (off-thread) → `refreshWorkspaces()` → `list_election_workspaces` (**sync, main thread**) → full replay of every workspace. **SEVERE.** | `runLifecycle` → command → local row patch from the returned authoritative summary. **No listing. 0 replay. 0 Triptych.** |
| **Manual/implicit refresh** (load / load-folder / unload / delete / freeze still call `refreshWorkspaces`) | `refreshWorkspaces` → listing → full replay of every workspace (**sync main thread** for the pre-existing sync commands). | `refreshWorkspaces` → metadata-only listing on the **blocking pool**. **0** replay, **0** Triptych. (No dedicated "refresh workspaces" button exists; these are the implicit refreshes.) |
| **Resume / open election** | Home Resume → `resume_election_workspace` (async) → `summarize_workspace` (**replay #1**) **+** `from_durable_snapshot` (**replay #2**) = double replay; then post-resume `refreshWorkspaces` → list → replay every workspace. | `resume_election_workspace` → metadata-only summarise (**0 replay**) **+** `from_durable_snapshot` (**the one required replay**); post-resume refresh is metadata-only. Net: **exactly one** required reconstruction, down from two-plus-a-full-list. |

---

## 4. Before/after verification counts

**Automated-test counts (deterministic, from `reconstruction_instrumentation.rs`).** These are the authoritative evidence for this slice; they are *not* live measurements against the user's app-data (see §9).

| Operation (fixture) | `from_durable_snapshot` | historical ballots replayed | gui-core Triptych verifications | crypto-adapter verify calls |
|---|---:|---:|---:|---:|
| List a workspace holding **15 stored** ballots (after) | **0** | **0** | **0** | **0** |
| List an empty workspace (after) | **0** | **0** | **0** | **0** |
| Two back-to-back list passes over a populated root (after) | **0** | **0** | **0** | **0** |
| Resume a workspace with **5 stored** ballots (after) | **1** | **5** | **5** | **5** |
| Intake one new ballot (after) | 0 | 0 | **1** | **1** |

**Before (same paths, from the source structure the audit confirmed):** listing a workspace with K stored ballots executed `from_durable_snapshot` once and replayed all K ballots through K Triptych verifications — per workspace, on the main thread; and `resume` did that **twice**. The regression test would fail (non-zero counts) against the pre-slice `summarize_workspace`, which is exactly its purpose.

**Two independent counters, cross-checked.** The gui-core counter is incremented in `process_intake_package`; the crypto-adapter counter is incremented inside `TariTriptychPrototypeVerifierV1::verify` itself. A future caller that reached the verifier *bypassing* the session pipeline would still bump the adapter counter, so "listing → adapter count 0" is a strong, path-independent guarantee. For valid ballots the two counts agree (resume: 5 and 5; intake: 1 and 1).

---

## 5. Commands moved off the main thread

| Command | Before | After |
|---|---|---|
| `list_election_workspaces` | sync (SEVERE) | `async` + `run_blocking_command` |
| `delete_election_workspace` | sync (SEVERE) | `async` + `run_blocking_command`, guard preserved |

Additionally, the **SEVERE main-thread Triptych-replay body was removed from the listing path entirely**, which benefits all eleven `refreshWorkspaces` triggers, not just the two converted commands.

---

## 6. Remaining synchronous blocking commands (recorded for later slices)

Not addressed here (the slice deliberately scoped to the listing/lifecycle path). From `AUDIT_TAURI_COMMAND_BLOCKING_MATRIX.csv`:

- **HIGH:** `open_voting` (still sync; no longer triggers the SEVERE listing, but still does a full revision-history re-read — the durable-I/O finding, §12), `intake_ballot_package`, `sync_private_intake`, `freeze_election`, `write_archive_with_governance_document` (no frontend caller found).
- **MEDIUM-HIGH:** `set_draft_governance_document`.
- **MEDIUM:** all `set_draft_*`, `import_registry_to_draft`, `export_election_artifacts`, `compute_governance_document_digest`, `match_governance_document`, `voter_confirmation`, `export_prepared_voter_ballot`, `inspect_template_wasm`, `configure_managed_tor_test`, `submit_prepared_voter_ballot_privately` (non-managed-tor build).
- **LOW:** the small file/keyring reads.

Recommended next: convert `open_voting`, `intake_ballot_package`, and `sync_private_intake` in an early follow-up (each does one or more required verifications and/or a history re-read that should not sit on the event thread).

---

## 7. Security invariants preserved (verified)

All verified by source inspection this slice; **none changed**.

1. **New-ballot intake verification** — `intake_ballot_package` and inbox reconciliation still run the full `ingest_approval_ballot_package_v1` → `verify_approval_proof` → Triptych `verify`. Proven still-live by the `new_ballot_intake_still_verifies_its_proof` test (adapter count = 1).
2. **Import validation** — `load_election`/`load_election_folder` still build the verifier (`GuiElectionSessionV1::new`) and re-apply signed status; unchanged.
3. **Tamper detection** — revision digest + predecessor-chain checks in `load_committed_history` run before summarisation; the hostile-resume tests in `workspace.rs` are unchanged and still pass. Artifact-decode failures in the metadata path still propagate.
4. **Manifest binding / nullifier / first-valid-ballot / tally / finalization** — all operate on the replay-verified `GuiElectionSessionV1` via the unchanged intake and lifecycle paths; the display summary is never consulted.
5. **Anchor eligibility & digest** — derived from `verify_archive_directory_v1` (full archive replay) via `live_anchor_config.rs`/`live_anchor_driver.rs`, never from the workspace summary.
6. **Durable corruption detection** — unchanged (same digest/commit-marker machinery).

**Display-vs-authoritative separation (steering invariant #1), proven exhaustively.** The renamed `stored_ballot_count` has exactly one runtime consumer: `Home.tsx` renders it in a `<td>`. No authoritative operation reads it. Every authoritative accepted count comes from a different, replay-verified source:

- participation: `GuiElectionSessionV1::accepted_count()` (the ledger of a replay-verified session);
- anchor floor/eligibility/digest: `verification.accepted_count` from a full archive replay;
- finalization/tally/lifecycle/nullifier: the replay-verified session itself.

So none of {finalization, tally, anchor eligibility, anchor digest, lifecycle transitions, nullifier state, accepted-ballot authoritative state} consume the display-only count.

**No indirect replay in `summarize_workspace` (steering invariant #2).** Helpers now reachable: `GuiElectionArtifactsV1::from_bytes` (CBOR decode + BLAKE3 commitment checks + suite-policy string check — no verifier, no Ristretto ring, no ballot), a sidecar-marker file read, and pure formatting. It does not construct `GuiElectionSessionV1`, build a Triptych verifier, call the session `from_durable_snapshot`, ingest packages, or verify proofs — confirmed by the adapter-boundary counter reading 0.

**Two distinct `from_durable_snapshot` methods (steering clarification).** These are unrelated despite the shared name:

- `GuiElectionSessionV1::from_durable_snapshot` (`session.rs`) — the **expensive** path: builds the Triptych verifier and replays every stored ballot through proof verification. **This is the one removed from listing.** It is the only one the instrumentation counts.
- `GuiElectionDraftV1::from_durable_snapshot` (`creation.rs`) — a **cheap** draft-field validator: it checks the election id, governance revision, approval limits, decodes each voter public key for well-formedness, and de-duplicates options. It constructs **no session** and processes **no ballots**. It was already used to summarise drafts before this slice and is unchanged. It performs no proof verification (adapter count stays 0 for a draft-only listing).

**Instrumentation is observational only (steering invariant #3).** Production counters are relaxed atomics; there are **no locks added around cryptographic execution**. The only mutex is `COUNTER_LOCK` inside the *test* file, serialising assertions in that one test binary — it never appears in production code. No counter records ballot/package identifiers, nullifiers, ring members, proof bytes, keys, credentials, hashes, ids, or paths.

**Conservative lifecycle-row update (steering invariant #4).** The local patch copies `lifecycle_state` and derives `finalized` **from the `GuiElectionSummaryV1` the lifecycle command already returned** — the same authoritative value the rest of the UI uses. No new authoritative state is fabricated, and no API extension was needed (the lifecycle commands already return the summary). `stored_ballot_count` is left untouched because a lifecycle transition cannot change it.

---

## 8. Tests added and results

**New Rust integration tests — `crates/gui-core/tests/reconstruction_instrumentation.rs`:**

- `listing_a_workspace_with_no_ballots_replays_nothing`
- `listing_a_workspace_with_many_stored_ballots_replays_nothing` (15 stored → 0/0/0/0)
- `repeated_startup_style_discovery_replays_no_ballots`
- `resuming_an_election_replays_every_stored_ballot_exactly_once` (F-5: exactly one `from_durable_snapshot`)
- `new_ballot_intake_still_verifies_its_proof`

**New frontend source-regression tests — `gui/test/performanceRemediationSlice1.test.ts`** (11 assertions): `runLifecycle` no longer re-lists and patches the active row locally; list/delete are async + `run_blocking_command`; `summarize_workspace` is metadata-only (`from_bytes`, no `from_durable_snapshot`); durable reconstruction still replays every package; the summary type/UI expose the non-authoritative `stored_ballot_count`.

**Results (all CONFIRMED by local runs, MSVC toolchain):**

| Suite | Result |
|---|---|
| `cargo check -p tari-cc-private-ballot-gui-core` | exit 0 / clean |
| `crypto` (all tests, incl. Triptych verifier) | **51 passed / 0 failed** |
| `gui-core` `reconstruction_instrumentation` (incl. crypto-adapter assertions) | **5 passed / 0 failed** |
| `gui-core` `workspace` (durable + hostile-resume) | **38 passed / 0 failed** |
| `gui-core` `intake` (ballot verification) | **13 passed / 0 failed** |
| Frontend `performanceRemediationSlice1.test.ts` (new) | **11 passed / 0 failed** |
| Frontend full suite (`node --test test/*.test.ts`) | **708 passed / 3 failed** |

**The 3 frontend failures are pre-existing and unrelated to this slice.** All three assert on `gui/src/screens/ManageElection.tsx` (an `api.walletdReadiness(` call in the "no new API calls" pin, and two Anchor-deployment-section layout pins). `ManageElection.tsx` was already modified (`M`) in the working tree at session start by prior branch work and was **not touched by Slice 1** (my frontend edits are confined to `AppState.tsx`, `types.ts`, `Home.tsx`, and the two test files). The only failure Slice 1 introduced was the intended `accepted_ballot_count` → `stored_ballot_count` rename pinned in `uxPolish.test.ts`, which was updated to the new field name and now passes (711 → 708+3, with the rename test moving from fail to pass).

_Note on the earlier combined run:_ a first `--test reconstruction_instrumentation --test workspace --test intake` invocation reported only `workspace` (38/38) in captured output due to build-lock contention with concurrent `cargo check` jobs; the values above are from clean, non-contended re-runs of each binary.

**Pre-existing, unrelated compile blocker in the whole-suite run.** A bare `cargo test -p tari-cc-private-ballot-gui-core` currently fails to compile one test binary — `crates/gui-core/tests/archive_writer.rs:910` — with `E0308: expected &str, found String` at `dir.join(format!("live-anchor-config-{}.cbor", endpoint.len()))`. This is **pre-existing branch WIP from the v0.39.2 Ootle-anchor migration**, not a Slice-1 change: the file was already `M` in the working tree at session start, Slice 1 never edited it (or `live_anchor_config.rs`), it references none of the symbols this slice touched, and `git show HEAD:…:910` differs from the working-tree line (the mis-typed `format!` is an uncommitted edit made before this session). Because `cargo test` aborts the whole invocation when any one test binary fails to compile, the security-relevant gui-core suites were run **individually** (they compile independently of `archive_writer`) — `security`, `participation`, `serialization`, `private_intake_inbox`, `voter_cast_lock`, `election_status` — to confirm no Slice-1 regression. Fixing the `archive_writer` WIP bug is out of scope for this slice (it is someone's in-progress anchor migration) and is left untouched; it should be resolved by that migration's owner. Individually-run security-relevant suites (all **0 failed**): `security` 7, `participation` 18, `election_status` 11, `private_intake_inbox` 16, `serialization` 3, `voter_cast_lock` 22 — **77 passed / 0 failed**. Combined with `workspace` 38, `intake` 13, `reconstruction_instrumentation` 5, and `crypto` 51, every gui-core/crypto test binary that compiles passes.

---

## 9. Measurement note (automated-test vs live)

The counts in §4 are **automated-test counts** produced by the deterministic fixtures, not live measurements against the user's real election data. A live before/after (the audit's §19 goal — record actual startup `(workspaces, ballots_replayed, duration)`) requires running the built Tauri shell against the user's app-data, which is out of scope here and was not fabricated. The instrumentation added in this slice is exactly what a later live measurement would read (`instrumentation::snapshot()` / `crypto::verify_invocation_count()`); exposing it through a dev-only Tauri command + the existing `devDiagnostics` Settings flag is a small, recommended follow-up.

Fixture limitation, stated honestly: the shared test registry has three voters (`SECRET_SCALARS`) and Triptych proving uses `OsRng`, so the tests build up to three *accepted* ballots plus additional *stored* (duplicate-nullifier) packages to exercise larger stored counts. The zero-replay-on-listing invariant is independent of the count, so this fully validates the guarantee; a live 50/500/4096-ballot timing would need a larger registry fixture and the running shell.

---

## 10. Known limitations / deferred

- **Verified-session cache** — not implemented (explicitly out of scope). Opening/resuming an election still performs the full required replay each time; the cache will make repeat opens free in a later slice.
- **Durable-format write amplification** — untouched (out of scope). `load_committed_history` still re-reads the whole revision chain on every read *and* every write, and each session revision embeds the full registry + package set. This is the audit's independent O(revisions²·registry) finding and remains the true blocker for very large electorates. Status: **open, deferred to its own slice.** See §12.
- **Remaining sync commands** — §6.
- **R-7 archive triple-replay** — the anchor flow still re-runs the archive verifier three times; deferred (needs a same-run memo keyed by archive hash).

---

## 11. Recommended Slice 2 (cache) work

1. Introduce a process-local, memory-only `VerifiedElectionSessionCacheV1` keyed by `(workspace_id, head_revision, head_revision_digest_hex, verifier_epoch)` — the head digest is already a hash-chain commitment over the entire durable state.
2. Single-flight (dedupe concurrent resumes of the same workspace); never hold the cache lock across a replay; leaf-lock ordering vs. `AppState` locks.
3. Re-read sidecar markers and persisted status on every hit (they are outside the digest).
4. Route `resume_election_workspace` through a dedicated CPU worker with progress + cancellation.
5. Consider batch verification (the vendored crate supports it; needs a blame variant to keep per-ballot decisions byte-identical).

---

## 12. Separate durable-I/O finding — status

**Open. Not addressed in this slice (by instruction).** `write_workspace_revision` calls `load_committed_history` before every write, which re-reads and decodes revisions 1..head; each session revision stores the full registry plus every accepted package. Cumulative durable I/O scales roughly as O(revisions²·registry + revisions³·package). This is independent of the cryptographic replay fixed here and must be handled by a durable-format redesign in a dedicated slice, together with a decision on `MAX_REGISTRY_MEMBERS` (4096) vs. the stated 4100-voter target. No terminology in the touched source claimed a 4100-member supported registry, so no such reference required correction in this slice.
