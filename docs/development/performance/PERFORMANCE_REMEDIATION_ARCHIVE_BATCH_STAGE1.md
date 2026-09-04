# Performance Remediation — Archive Verification Batch Stage 1
# Batch-16 Single-Threaded Independent Archive Verification

Status: **PASS** (production implementation; parity and fail-closed tests green; 1000-voter release qualification PASS at 8.19× on the full independent archive verification).

Companion audit: `AUDIT_INDEPENDENT_ARCHIVE_VERIFICATION_PERFORMANCE.md` (source-proven call graph, equivalence requirements, and projections — not repeated here).

Evidence labels: **CONFIRMED** = source inspected; **MEASURED** = wall-clock from the existing release scale-qualification harness on this machine (AVX2 active); **DERIVED** = arithmetic over measured values; **PROJECTED** = extrapolation using measured per-proof data. Projections from the audit are **never** silently replaced by measurements; each value below carries its label.

---

## 1. What changed (Stage 1 scope only)

`crates/archive/src/verifier.rs`, BALLOT_REPLAY stage only:

```
archive identity / catalog verification          (unchanged, serial, mandatory)
        ↓
canonical ordered submission bytes               (unchanged, BTreeSet path order)
        ↓
batch-16 cryptographic verification              (NEW: verify_approval_ballot_packages_batch_v1
        ↓                                         over contiguous chunks of ARCHIVE_REPLAY_BATCH_SIZE_V1=16,
                                                 shared immutable election context per batch)
ordered per-submission verification results       (NEW: fail-closed length check, in submission order)
        ↓
SERIAL canonical application                     (NEW: ArchiveReplaySessionV1::apply_verified —
        ↓                                         record_submission → ledger.accept_verified /
                                                 Rejected(code) → record_decision)
transcript / nullifier ledger / first-valid-wins / tally / lifecycle
        ↓
archive hash rebuild                             (unchanged)
        ↓
existing process-local archive memo              (unchanged)
```

- Uses the already-existing public batch API `verify_approval_ballot_packages_batch_v1` (verifier crate), whose per-submission result is guaranteed identical to the retained serial ingest — including exact rejection codes and full-blame isolation of one invalid proof inside a failed batch. No new dependency, no Cargo change, no protocol change, no on-disk change.
- Single-threaded. **No multicore scheduler was introduced** (Stage 2 is explicitly deferred; see the handoff below).
- Counter semantics preserved: a complete replay of N submissions still reports `archive_historical_replay_count == 1` and `archive_historical_triptych_verifies == N` (the counter is incremented per submission in the serial apply loop, not per batch operation).
- The exact pre-Stage-1 serial ingest is retained verbatim under `#[cfg(test)]` (`intake_ballot`, `replay_serial_for_test`, `finish_verification_serial_for_test`, `verify_archive_directory_serial_for_test`) as the parity reference; production always uses the batched path.
- Fail-closed behavior preserved: batch contract violations (`results.len() != packages.len()`), transcript-recording failures, and executor-adjacent construction failures fail the whole verification with the same stage (`STAGE_BALLOT_REPLAY`) and stable codes; nothing partially applied is ever trusted. Malformed packages are rejected during per-input preparation and never enter a shared batch. A failed batch resolves exact per-proof validity via the existing `verify_batch_with_full_blame` path, so one invalid proof rejects only itself; conservative whole-chunk rejection happens only on an unrecoverable batch error, exactly as the fail-closed batch wrapper requires.

---

## 2. Tests

New in-crate Stage 1 equivalence suite (`crates/archive/src/verifier.rs` `#[cfg(test)]`, real Triptych proofs, 3-voter ring):

| Test | Proves |
|---|---|
| `batched_replay_matches_serial_replay_transcript_decision_for_decision` | Transcript, accepted/rejected counts, and tally parity batch-vs-serial for: all-valid; one invalid proof mid-batch; malformed package; duplicate-nullifier/first-valid-wins |
| `one_invalid_proof_in_a_batch_rejects_only_itself` | Full-blame isolation: invalid proof gets `MalformedProof`, all neighbors stay accepted |
| `duplicate_nullifier_rejects_exactly_the_second_ballot` | First-valid-ballot wins; duplicate gets `DuplicateNullifier` |
| `full_verification_report_parity_serial_vs_batched` | End-to-end `ArchiveDirectoryVerificationV1` field equality (incl. transcript counts, tally, archive hash) for all four cases |
| `batched_full_verification_preserves_qualification_counter_semantics` | `archive_full_verification_count==1`, `archive_historical_replay_count==1`, `archive_historical_triptych_verifies==N`; memo miss == full replay with the same counters; memo hit == 0 Triptych verifies and identical report |

Existing suites re-run against the batched path (all green):

| Suite | Result |
|---|---|
| `tari-cc-private-ballot-archive` (lib) | 52 passed, 0 failed |
| gui-core `archive_verify` (tamper fail-closed, duplicate decisions, replay reproduction, run-to-run identity) | 12 passed |
| gui-core `archive_verification_memo` | 11 passed |
| gui-core `governance` | 38 passed |
| gui-core `live_driver_archive` | 4 passed |
| ootle-anchor-app `driver_scripted` (`--features test-support`; driver's `verify_archive_directory_v1` seam) | 31 passed |
| 1000-voter release scale qualification | **PASS** (see §3) |

Transport-bound archive verification is covered through the batched path by gui-core `live_anchor_publish` (bound-archive publish cases), `governance`, `live_driver_archive`, and the memo suite's `verify_transport_archive_anchor` equality tests. The manual Tor-managed 50-voter `final_archive_regression` fixture is `#[ignore]`d by design and was not run.

**Pre-existing failures identified (NOT from this change; left untouched):**

1. `crates/gui-core/tests/archive_writer.rs:910` does not compile (`TestDir::join(&str)` given a `String` in migration-owned test code) — the documented historical migration blocker, confirmed currently present. This session did not modify that file.
2. `gui-core live_anchor_publish`: 2 tests fail with `ANCHOR_PUBLISH_TERMINAL_INDEX_CONFLICT` — caused by a persistent terminal-index record in `LOCALAPPDATA\Tari Private Ballot\anchor-state` dated **2026-08-26** (four days before this session). Nothing in archive verification touches anchor publishing or the terminal index.

---

## 3. Performance — BEFORE / AFTER

### 1000-voter scale qualification

| Field | BEFORE (MEASURED, `scale-1000-20260830-190947.csv`, serial) | AFTER (MEASURED, `scale-1000-20260830-215015.csv`, batch-16) |
|---|---|---|
| archive verification | **80,216.243 ms** | **9,796.518 ms** — **8.19×** |
| cold resume | 3,606.187 ms | 3,667.954 ms (unchanged path; run noise) |
| warm resume | 24.560 ms | 24.632 ms |
| archive memo verify | 323.506 ms | 357.219 ms (catalog rehash only; noise) |
| archive Triptych count | 999 | **999** (preserved) |
| overall result | PASS | **PASS** |

Invariants held (AFTER): overall PASS; `archive_triptych=999`; warm historical Triptych verifies `0`; post-mutation historical verifies `0`; memo Triptych verifies `0`; private-intake linear scans `0` (index probes 997); accepted 997 / rejected 2 — identical to BEFORE; `workspace_disk_bytes=1,419,134` — byte-identical archive; `finalized` + transport binding verified; harness-asserted `first == second` (memo output equals fresh verification).

Audit projection vs measurement (not a silent replacement): the audit PROJECTED ~10.2 s single-threaded batch-16 (999 × 9.914 ms measured batch16/proof + 0.32 s catalog overhead); the MEASURED result is 9.80 s. The projection was mildly conservative; the measured 9.8 ms/proof all-inclusive wall time is consistent with the MEASURED_RELEASE batch-16 amortization at ring 1000 (8.17× vs individual 81.042 ms).

### 2048-voter scale qualification

| Field | BEFORE (MEASURED, `scale-2048-20260830-193323`, serial) | AFTER |
|---|---|---|
| archive verification | **252,736.767 ms** | **NOT RUN / USER-RUN LATER** |
| cold resume | 9,679.874 ms | NOT RUN |
| warm resume | 40.121 ms | NOT RUN |
| archive memo verify | 531.811 ms | NOT RUN |
| archive Triptych count | 2047 | expected 2047 (counter semantics proven by the in-crate test and the 1000 run) |
| overall result | PASS | — |

2048 AFTER was deliberately not run in this session: the harness is dominated by ~55 minutes of unrelated serial proof generation (3,286,192.806 ms BEFORE), which Stage 1 does not modify. Audit PROJECTED 2048 batch-16 single-core: **~35.3 s (~7.2×)** — consistent with the measured 1000-voter result (8.19×); treat strictly as a projection until the user-run 2048 qualification records an AFTER.

### Other preserved baselines

| Scale | BEFORE (MEASURED, serial) | AFTER (PROJECTED, audit) |
|---|---|---|
| 100 | 1,047.662 ms (99 ballots; `scale-100-20260830-184009.csv` / second run 1,159 ms class) | ~0.22 s (~4.8×) |
| 500 | 17,273.337 ms (499 ballots; `scale-500-20260830-185858.csv`) | ~3.1 s (~5.5×) |
| 4096 | ~911 s (DERIVED from MEASURED_RELEASE individual 222.515 ms/proof; never run unoptimized) | ~133 s PROJECTED (~6.8×) |

Stage 1 changes local verification performance only. No protocol, archive-format, or on-disk change (PROTOCOL CHANGE: NO / ON-DISK CHANGE: NO).

---

## 4. FUTURE STAGE 2 MULTICORE HANDOFF

Stage 2 (bounded multicore archive verification) is POST-BETA / OPTIONAL for the MVP unless Stage 1 measurements demonstrate it is required for practical release performance. No scheduler was moved, refactored, or introduced in this session. Everything a future implementing agent needs:

1. **Current Slice 4B scheduler source locations.** All in `crates/gui-core/src/historical_replay.rs`; the call site is `crates/gui-core/src/session.rs:302-338` (`replay_packages_parallel` → `parallel_verify_packages` → `apply_verified_packages_in_order` at `session.rs:350-388`). Module constants: `DEFAULT_HISTORICAL_REPLAY_BATCH_SIZE_V1` (:44), `DEFAULT_HISTORICAL_REPLAY_PARALLEL_THRESHOLD_V1` (:50), `HISTORICAL_REPLAY_HARD_WORKER_CAP_V1` (:56).
2. **`parallel_verify_packages` location and visibility.** `crates/gui-core/src/historical_replay.rs:110`, declared `pub(crate)` — unreachable from any other crate.
3. **`run_bounded` location.** `crates/gui-core/src/historical_replay.rs:188` (order-preserving bounded scoped-thread executor: results stored by unit index, never by completion order).
4. **`GlobalCryptoBudgetV1` location.** `crates/gui-core/src/historical_replay.rs:253` (static `GLOBAL_CRYPTO_BUDGET` :259; accessor `global_crypto_worker_budget_v1` exported via `gui-core/src/lib.rs:141`; RAII permit `HistoricalCryptoPermitV1` :326).
5. **Why the archive crate cannot depend on the current implementation.** (a) Visibility: the scheduler is `pub(crate)` in gui-core. (b) Typing: `parallel_verify_packages` takes `GuiElectionArtifactsV1` and gui-core's `HistoricalReplayConfigV1`. (c) Dependency direction: `gui-core` depends on `tari-cc-private-ballot-archive`; the archive crate cannot see gui-core at all without inverting the layering.
6. **Recommended shared lower-level home.** Extract the generic, dependency-free scheduling + global CPU-budget abstraction (`run_bounded`, `GlobalCryptoBudgetV1`, `HistoricalCryptoPermitV1`, `resolve_workers` — ≈150 lines) into a small shared crate (e.g. `crates/bounded-crypto-executor`) or into the existing `tari-cc-private-ballot-verifier` crate. gui-core's `historical_replay` migrates to it with zero behavior change; the archive crate's `replay_batched` then dispatches its `ARCHIVE_REPLAY_BATCH_SIZE_V1` (16) chunks across the bounded pool. The semantics layer (chunk split + ordered concat + serial canonical apply) stays per-crate and thin, exactly as Stage 1 did.
7. **Existing worker policy to reuse unchanged.** Batch size 16; hard worker cap 8 (`HISTORICAL_REPLAY_HARD_WORKER_CAP_V1`); process-global CPU budget ≈ `max(1, available_parallelism − 1)` with work-conserving `acquire_up_to` permits so the GUI keeps a core and concurrent verifications cannot oversubscribe the machine.
8. **Required canonical serial application boundary.** Ordered per-submission verification results (indexed by canonical submission position) must be applied strictly serially in canonical archive order: `transcript.record_submission` → `ledger.accept_verified` (nullifier insertion, duplicate rejection, first-valid-ballot wins) → `transcript.record_decision`; then `validate_complete`, tally, lifecycle transitions, archive-hash rebuild, and memo publication. The catalog/manifest/transport-binding/governance stages remain serial and unchanged. Never apply ballot state transitions in parallel.
9. **Required concurrency/parity tests.** Worker-count 1 == serial gate (identical report); multiworker equivalence (identical report for any worker count/batch completion order, mirroring `gui-core/tests/parallel_historical_replay.rs`); invariants `archive_historical_replay_count==1` and `archive_historical_triptych_verifies==N` under multicore; memo hit still 0 Triptych verifies with identical report; concurrent same-archive memo verification still single-flights one parallel replay; full-blame isolation of one invalid proof inside a 16-chunk on any worker.
10. **Memo single-flight interaction.** `ArchiveVerificationMemoV1::get_or_finish` (`crates/archive/src/verification_memo.rs:140`): one owner runs `finish_verification` — and therefore the worker pool — with NO memo lock held; waiters block on the in-flight condvar and receive the owner's immutable `Arc` report. Concurrent verifications of different archives share the single global crypto CPU budget. Stage 2 must keep the pool inside the owner's single-flight window exactly as Slice 4B kept it inside the reconstruction permit.
11. **Full-blame / invalid-proof behavior requirements.** Keep using `verify_approval_ballot_packages_batch_v1` per chunk so `verify_batch_v1`'s full-blame fallback resolves the exact invalid inputs (linear in chunk size ≤ 16); conservative whole-chunk rejection only on an unrecoverable batch error; invalid archived ballots must remain `Rejected` transcript decisions with identical validation codes; no proof skipping, sampling, or persisted trust state.
12. **Memory implications at 2048/4096.** MEASURED_RELEASE: ring-4096 election context ≈ 655 KB; one batch of 16 proofs/transcripts per worker; DERIVED crypto peak ≤ ~6 MB at 4096 with 3 workers. The archive verifier already buffers every catalog file's bytes (`EstablishedIdentityV1.files`) regardless. With batch 16 × hard cap 8 the prepared-proof working set stays bounded; not substantial at 2048/4096. Watch the ring-MSM memory bandwidth wall (batch-16 amortization regresses at 4096: 6.91× vs 9.19× at 2048).
13. **Existing measured/projection data relevant to Stage 2.** `PRODUCTION_RELEASE_CRYPTO_PERFORMANCE.csv`: individual verify 81.042 / 155.706 / 222.515 ms and batch-16 9.914 / 16.937 / 32.215 ms per proof at ring 1000/2048/4096; multicore MEASURED only at tiny ring (3.08×/4.00× at 2/3 workers, worker=1 == serial at 0.99×); 4096 projections 45–90 s. `AUDIT_TRIPTYCH_PARALLEL_REPLAY_MATRIX.csv`, `AUDIT_TRIPTYCH_VERIFIER_PERFORMANCE.csv`, `AUDIT_INDEPENDENT_ARCHIVE_VERIFICATION_PERFORMANCE.md` §9. Stage 1 MEASURED (this report): 999 proofs, batch-16 single core, full verification wall 9,796.518 ms. Stage 2 PROJECTED archive verification: 1000 → ~3.5–7 s; 2048 → ~12–25 s; 4096 → ~45–90 s.
14. **Exact minimal future implementation sequence.** (1) Extract the scheduler/budget abstraction into the shared home (item 6). (2) Migrate gui-core `historical_replay` to it; full gui-core suite green (W1 parity + multiworker equivalence unchanged). (3) In the archive crate, dispatch the contiguous 16-sized chunks of `replay_batched` across the bounded pool, concatenate results in chunk order, keep the exact Stage 1 serial apply loop and counter semantics. (4) Add the item-9 multicore parity tests plus in-crate serial-reference comparison. (5) Re-run the 1000-voter and then 2048-voter qualifications with the §3 invariants.
15. **Explicit statement.** Stage 2 changes local verification performance only. It requires **no protocol change and no archive/on-disk format change**; it does not alter archive bytes, commitments, verification conclusions, or interoperability.

---

## 5. Production change scope

**This session (Stage 1):**

- Production file changed: `crates/archive/src/verifier.rs` — BALLOT_REPLAY stage only (batch-16 verification + serial canonical application; injected replay strategy; batch constant; retained serial reference under `#[cfg(test)]`).
- Test file changed: `crates/archive/src/verifier.rs` `#[cfg(test)]` module — new Stage 1 equivalence suite (5 tests, real-proof fixtures).
- Report files created: `AUDIT_INDEPENDENT_ARCHIVE_VERIFICATION_PERFORMANCE.md`, `PERFORMANCE_REMEDIATION_ARCHIVE_BATCH_STAGE1.md`.
- No Cargo files changed. No new dependency. No commit made.

**`git diff --stat` (this session's touched file; note the working tree was already extensively dirty with pre-existing uncommitted migration work, so the git diff vs HEAD includes that prior work):**

```
crates/archive/src/verifier.rs | 808 ++++++++++++++++++++++++++++++++++++++++-
1 file changed, 793 insertions(+), 15 deletions(-)
```

(The 793/15 figure is vs HEAD `b6da1b3` and includes pre-existing uncommitted Slice 4D changes to the same file. This session's delta is the BALLOT_REPLAY batch path plus the new test module.)

**`git diff --name-only` / `git status` summary:** ~70 modified and ~50 untracked pre-existing files (anchor-transport, ootle adapters, gui-core, transport-gateway, GUI/Tauri/TypeScript, prior slice reports and harnesses) were left untouched. Only `crates/archive/src/verifier.rs` and the two report files above were changed/created by this session.

**Pre-existing failures (identified, not fixed, migration-owned):** `archive_writer.rs:910` compile error (documented blocker); `live_anchor_publish` 2 failures caused by the persistent terminal-index record in `LOCALAPPDATA\Tari Private Ballot\anchor-state\terminal-index-v1` (dated 2026-08-26).

**Not run / deferred:** 2048-voter AFTER qualification (USER-RUN LATER; BEFORE preserved at 252,736.767 ms); 4096 (never run unoptimized, per instruction); the manual Tor-managed 50-voter `final_archive_regression` fixture; Stage 2 multicore.

**NEXT:** Stage 2 bounded multicore archive verification audit/implementation after reviewing Stage 1 measurements (see §4 handoff).
