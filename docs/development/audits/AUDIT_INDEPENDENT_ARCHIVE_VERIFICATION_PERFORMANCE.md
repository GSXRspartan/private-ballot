# Audit — Independent Archive Verification Performance (Tari Private Ballot)

Read-only audit performed 2026-08-30. No source, tests, Cargo files, benchmarks, or generated results were modified during the audit; no builds, tests, benchmarks, or processes were run. A 2048-voter scale qualification was running on this machine during the audit (`scale-qualification-results/scale-2048-*.log`) and was not disturbed. All data below is from existing source, reports, and CSVs.

Evidence labels: **CONFIRMED** = source inspected; **MEASURED** = existing measured results; **DERIVED** = arithmetic over measured values; **PROJECTED** = extrapolation using measured per-proof data.

---

## 1. Executive conclusion

**Decision: A — HIGH-VALUE SAFE OPTIMIZATION.**

The first full independent finalized-archive verification performs **individual, serial, single-threaded Triptych verification**: exactly one `TariTriptychPrototypeVerifierV1::verify` (and one vendored `TriptychProof::verify`, internally a batch of one) per archived submission, with the ring/election context rebuilt on every proof, inside a plain canonical-order `for` loop in `crates/archive/src/verifier.rs:550-556`. It uses **none** of the bounded-batch / bounded-multicore machinery Slice 4B already built, proved equivalent, and shipped for cold durable reconstruction.

The qualification result confirms this arithmetically: 999 archived ballots × ~80–81 ms (release-measured individual verify at ring 1000) ≈ 80.2 s, matching `archive_verify_ms = 80,216 ms` with `archive_triptych=999`.

The exact batch machinery needed is **already public and already a dependency of the archive crate**: `verify_approval_ballot_packages_batch_v1` (`crates/verifier/src/approval_ingestion.rs:144`), whose per-input result is guaranteed identical to `ingest_approval_ballot_package_v1` up to (but excluding) ledger acceptance, with per-proof full-blame fallback already implemented inside `verify_batch_v1` (`crates/crypto/src/triptych_verifier.rs:148-179, 272-352`). The Slice 4B *scheduler* (`parallel_verify_packages`) is `pub(crate)` in gui-core and typed on gui-core types, so it cannot be reused directly — but only the scheduling layer needs a new home, not the cryptography or the semantics.

A minimum single-threaded change (batch 16, canonical serial apply) projects the 1000-voter full independent verification from **~80.2 s to ~10.2 s** (PROJECTED, ~8×), with no protocol, on-disk, or interoperability change. Adding bounded workers projects **~3.5–7 s**. No security semantic changes: proof validity results are computed out of order and applied strictly in canonical archive order, exactly the pattern already proven for historical replay.

Recommendation: **PRE-BETA**, staged (batch-only first; multicore second, pre-beta optional).

---

## 2. Current call graph (CONFIRMED)

Public entry points and consumers:

| Entry point | Location | Consumers |
|---|---|---|
| `verify_archive_directory_v1` | `crates/archive/src/verifier.rs:295` | `ootle-anchor-app` driver (`driver.rs:345`), gui-core wrapper (`archive_verify.rs:86`) |
| `ArchiveVerificationMemoV1::verify` | `crates/archive/src/verification_memo.rs:122` | gui-core `verify_archive_directory_with_memo_v1` (`archive_verify.rs:99`) |

gui-core memo consumers (all reach the same `finish_verification`):
- Tauri `verify_archive` command (`gui/src-tauri/src/lib.rs:2180-2192`, executed via `run_blocking_command` — off the Tauri event thread)
- `verify_transport_archive_anchor_with_memo_v1` (`transport_anchor.rs:59`)
- `write_live_anchor_config_from_verified_archive_with_memo_v1` (`live_anchor_config.rs:163`)
- Scale qualification harness (`crates/gui-core/tests/release_scale_qualification.rs:611`)

Stage pipeline (stage constants at `verifier.rs:51-63`):

1. **ARCHIVE_MANIFEST** — bounded read, strict canonical CBOR decode, hash-provider validation, archive hash derivation (`verifier.rs:331-360`).
2. **CATALOG_FILES** (identity establishment) — recursive disk enumeration with reparse/symlink rejection, two-way catalog set equality, bounded read + domain-separated digest per file, all bytes buffered in a `BTreeMap` (`verifier.rs:364-416`). Fail-closed on any anomaly. This stage is mandatory on every request, including memo hits.
3. **ELECTION_ARTIFACTS** — manifest/registry/candidate-set decode, cross-commitment binding, proof-suite policy (`verifier.rs:445-464, 623-665`).
4. **TRANSPORT_BINDING** — optional binding decode + manifest-hash/election-id binding check (`verifier.rs:466-496`). Cheap; serial; no per-ballot work.
5. **GOVERNANCE_PIN** — pin format + content-digest cross-check (`verifier.rs:498-533`). Cheap.
6. **BALLOT_REPLAY** — **the bottleneck** (below).
7. **ARCHIVE_HASH** — catalog rebuild, manifest equality, archive-hash comparison (`verifier.rs:570-606`). O(total bytes) rehash; small relative to crypto.

Ballot replay, exact chain (`verifier.rs:542-556, 723-750`):

```
finish_verification
  └─ for path in submission_paths (canonical BTreeSet order)      [serial loop]
       └─ instrumentation::add_historical_triptych_verifies(1)
       └─ ArchiveReplaySessionV1::intake_ballot(&files[path])
            ├─ transcript.record_submission(digest, true)
            ├─ ingest_approval_ballot_package_v1(...)               [verifier crate]
            │    ├─ prepare_approval_ballot_package_v1 (decode/binding/statement)
            │    ├─ proof_verifier.verify(statement, proof_bytes)  ← INDIVIDUAL
            │    │    └─ TariTriptychPrototypeVerifierV1::verify   [crypto crate]
            │    │         ├─ build_triptych_statement_v1(...)     ← ring context REBUILT per proof
            │    │         └─ TriptychProof::verify (batch of one)
            │    └─ ledger.accept_verified(lifecycle, ballot)      ← nullifier/first-valid-wins
            └─ transcript.record_decision(seq, digest, outcome)
  └─ transcript.validate_complete; tally; archive-hash rebuild
```

An ingest `Err` (including cryptographic proof failure) does **not** fail the verification; it is recorded as a `Rejected` transcript decision. Only transcript-recording failures fail verification.

---

## 3. Current Triptych verification behavior (CONFIRMED)

Answers to the trace questions:

- **(5) Exact function invoking Triptych verification:** `TariTriptychPrototypeVerifierV1::verify` (`crates/crypto/src/triptych_verifier.rs:84-125`), called from `ingest_approval_ballot_package_v1` (`approval_ingestion.rs:121`), called from `ArchiveReplaySessionV1::intake_ballot` (`archive/verifier.rs:734`), called from the `finish_verification` loop (`archive/verifier.rs:550-556`).
- **(6) Which API:** `TriptychProof::verify` only (individual). No `verify_batch`, no `verify_batch_v1`, no wrapper mixture.
- **(7) Calls for N archived ballots:** exactly N `TariTriptychPrototypeVerifierV1::verify` invocations, hence N `TriptychProof::verify` calls. Scale harness counted `archive_triptych=999` for 999 submissions — exact match.
- **(8) Context/ring rebuilt per proof:** YES. Individual `verify` calls `build_triptych_statement_v1` per proof, rebuilding the full `(TriptychParameters, TriptychInputSet)` including O(N) registry-key decompression each time (Slice 4A measured this at ~4–6% of per-ballot cost).
- **(9) Any batching:** NO.
- **(10) Multiple CPU workers:** NO. Single-threaded on the caller's thread (Tauri runs it on a blocking thread, so the event loop is not blocked, but only one core is used).
- **Memo behavior:** the Slice 4D memo (`verification_memo.rs`) always re-establishes identity and re-digests every catalog file (hit cost ~323.5 ms at 1000 voters, MEASURED), and skips only the replay. Memo hit performs 0 Triptych verifies. A first full verification is a guaranteed miss — the ~80 s cost is paid by every independent verifier process.

Cross-check against qualification data (MEASURED):

| Scale | `archive_verify_ms` | ÷ ballots | Release individual verify (measured) |
|---|---|---|---|
| 100 | 1,047.7 | 10.6 ms | 10.5 ms (ring 100) |
| 500 | 17,273.3 | 34.6 ms | 47.0 ms (ring 500; same order) |
| 1000 | 80,216.2 | 80.3 ms | 81.0 ms (ring 1000) |
| 2048 | 252,736.8 | 123.6 ms | 155.7 ms (ring 2048; same order) |

The ~80 s / ~253 s results are individual verification, not parsing, hashing, or another bottleneck. (The "already optimized" verdict: no.)

---

## 4. Comparison with Slice 4B (CONFIRMED)

Slice 4B (`crates/gui-core/src/historical_replay.rs`) accelerates **cold durable reconstruction** only:

```
GuiElectionSessionV1::from_durable_snapshot_parallel            [session.rs:238]
  └─ parallel_verify_packages (historical_replay.rs:110)
       ├─ batch_ranges(N, 16)                                     [bounded batches]
       ├─ resolve_workers: hard cap 8, global budget max(1, cores-1)
       ├─ run_bounded: scoped threads, results indexed by position [order-preserving]
       │    └─ verify_approval_ballot_packages_batch_v1 (verifier crate, PUBLIC)
       │         └─ ProofVerifierV1::verify_batch_v1
       │              └─ TriptychProof::verify_batch + full-blame fallback
       └─ apply_verified_packages_in_order (session.rs:350)       [serial canonical apply]
            └─ transcript.record_submission → ledger.accept_verified → record_decision
```

- **(13) Can it be reused directly?** NO. `parallel_verify_packages` is `pub(crate)` in gui-core, takes `GuiElectionArtifactsV1`, and the dependency arrow is gui-core → archive (the archive crate cannot see gui-core at all).
- **What IS directly reusable:** `verify_approval_ballot_packages_batch_v1` (public in the verifier crate, which the archive crate already depends on and imports from), and `BallotAcceptanceLedger::accept_verified` (public, already used by the archive replay session). The archive crate needs no new dependencies for batch-only acceleration.
- **(14) Minimum shared abstraction for multicore:** extract `run_bounded` + `GlobalCryptoBudgetV1` (≈150 lines, dependency-free) from gui-core into a small shared crate (or the verifier crate) used by both gui-core's `historical_replay` and the archive verifier. The semantics layer (batch split, ordered apply) is deliberately thin and is mirrored, not shared.
- **(22) Worker policy appropriateness:** the existing bounded policy (batch 16, hard cap 8, process-global budget `max(1, cores−1)` reserving one core for the GUI, single-flight via the memo's in-flight map) is appropriate for archive verification: it is an explicit, user-initiated, one-shot expensive operation already running on a blocking thread.

---

## 5. Security equivalence requirements

An optimization is acceptable only if all of the following hold (all are satisfied by the proposed design):

1. **Proof-validity semantics unchanged (Q15):** `verify_batch`'s acceptance predicate is identical to individual verification by construction — the vendored single `verify` *is* `verify_batch` of one (`third_party/tari-triptych/src/proof.rs`; Slice 4B Phase-1 analysis). Batch weights are transcript-seeded (Fiat-Shamir), deterministic, no OS entropy. The crypto-crate wrapper `verify_batch_v1` re-runs every per-input structural check (suite ID, registry commitment, envelope/proof canonical parsing, statement/transcript construction) exactly as `verify` does, and only successfully-parsed proofs enter the shared batch.
2. **(16) Out-of-order compute, canonical application:** safe and already proven. Cryptographic validity is a pure function of `(package_bytes, manifest, candidates, verifier)`; the ordered semantics are applied separately and sequentially. `GuiElectionSessionV1` already proves ballot-for-ballot equality with the serial path for any worker count/batch size/completion order.
3. **(17) Must remain serial:** manifest decode + catalog set-equality + per-file digest revalidation (fail-closed identity establishment); election-artifact cross-commitment binding; transport-binding verification; governance pin; transcript `record_submission`/`record_decision` (contiguous-order enforced by `replay.rs:198-248`); nullifier ledger (`accept_verified`: duplicate detection, first-valid-ballot wins); tally; lifecycle transitions; archive-hash rebuild; memo publication.
4. **(18) Fail-closed with batching:** preserved. Structural failures mark only their own input; a failed batch triggers `verify_batch_with_full_blame`, which re-runs individual verification per proof and returns the exact invalid set; any other batch error rejects every member of that batch (conservative direction). One invalid proof can never suppress a valid ballot and can never be accepted.
5. **(19) Identifying the failing proof:** already solved — full-blame returns exact indexes; the wrapper maps them back to original input indexes (`triptych_verifier.rs:318-352`). Moreover, in archive semantics an invalid archived ballot is not a verification *failure* at all — it becomes a `Rejected` transcript decision with the identical `ValidationCode` the serial path would produce.
6. **(20) Recursive fallback / per-proof isolation:** not required at the archive layer; the linear full-blame fallback inside `verify_batch_v1` (bounded by batch size 16) is the isolation mechanism and is already implemented and tested.
7. **(23) Memo semantics:** unchanged. The memo still performs mandatory full catalog revalidation on every request, still caches only fully-verified immutable successes, still fails closed on drift, and its output remains byte-identical to a fresh non-memo verification. Only how `finish_verification` computes the same report changes.
8. **(24) On-disk format / protocol commitments:** unchanged. Archive layout, catalog, manifest hash, transport binding, proof envelopes, tally, and the verification report are all byte-identical outputs.
9. **(25) Interoperability:** unaffected — this is local verification performance only. Third-party verifiers that do not upgrade still verify the same archives with the same results.

---

## 6. Safe parallelizable boundary vs required serial boundary

**Cryptographically independent (safe to batch/parallelize):** per-submission package decode, manifest binding, proof-suite policy, candidate-commitment check, payload decode, statement reconstruction, and the proof multiscalar check — pure over `(package_bytes, manifest, candidates, verifier)`, no `&mut`, no shared state.

**Required serial (order- and identity-sensitive):** everything in §5.3 — in particular nullifier handling, duplicate handling, first-valid-ballot wins, transcript evolution, tally, lifecycle, transport binding, and archive digest/catalog validation.

This matches the desired architecture exactly:

```
archive integrity/catalog verification          (serial, mandatory, unchanged)
        ↓
immutable proof-verification jobs              (pure per-submission)
        ↓
bounded batch/multicore Triptych verification   (verify_batch_v1, full-blame fallback)
        ↓
ordered vector of proof validity results        (indexed by canonical position)
        ↓
serial canonical archive application            (transcript + ledger, in path order)
        ↓
transcript/nullifier/tally/lifecycle checks     (unchanged)
        ↓
authoritative verified archive                 (identical report)
        ↓
existing process-local archive memo             (unchanged semantics)
```

Source proves this is practical: it is a structural clone of the already-shipped, already-tested Slice 4B split, relocated one crate down, against inputs (frozen archive bytes) that are *more* strongly pre-authenticated (every catalog file already digest-verified before replay begins).

---

## 7. Batch-failure handling design

Inherited wholesale from `TariTriptychPrototypeVerifierV1::verify_batch_v1`; the archive layer adds nothing:

1. Per-input structural checks run first; a failure returns `Err` for that input only (never enters the batch).
2. All-valid batch ⇒ every member valid.
3. Failed batch ⇒ `verify_batch_with_full_blame` re-runs individual verification per proof (linear in batch size ≤ 16) ⇒ exact invalid set; only those inputs become `Err(MalformedProof)` → `Rejected` decisions, identical to today.
4. Any other blame-path error ⇒ reject the whole batch's members (fail-closed).
5. Executor faults (poisoned slot etc.) fail the entire verification closed (`GUI_HISTORICAL_REPLAY_EXECUTOR_UNAVAILABLE` pattern) — no partially verified state is trusted.

---

## 8. Memory implications (Q21)

- Crypto memory is small and bounded by design: measured ring-4096 election context ≈ 655 KB; one batch of 16 proofs/transcripts per worker; release audit DERIVED bound "crypto peak ≤ ~6 MB at 4096 with 3 workers". At 2048/4096 this is **not substantial**.
- The archive verifier already buffers every catalog file's bytes in memory (`EstablishedIdentityV1.files`) regardless of this change; the batch layer adds only the prepared-proof vectors, bounded by batch size × worker cap.
- The existing bounds (batch 16, hard worker cap 8, process-global CPU budget) carry over unchanged and are the right knobs at 2048/4096.

---

## 9. Measured vs projected performance

Basis data (MEASURED_RELEASE, `PRODUCTION_RELEASE_CRYPTO_PERFORMANCE.csv`, this machine, AVX2 active):

| Ring | Individual verify | batch16 per-proof | Amortization |
|---|---|---|---|
| 100 | 10.458 ms | 1.917 ms | 5.46× |
| 500 | 47.012 ms | 6.052 ms | 7.77× |
| 1000 | 81.042 ms | 9.914 ms | 8.17× |
| 2048 | 155.706 ms | 16.937 ms | 9.19× |
| 4096 | 222.515 ms | 32.215 ms | 6.91× (cache/bandwidth regression) |

Full independent archive verification:

| Scale | Current | Basis | Batch16, 1 core (PROJECTED) | Batch16 + ~3 workers (PROJECTED) |
|---|---|---|---|---|
| 100 | **1.048 s** MEASURED | 99 × 10.6 ms | ~0.22 s (~4.8×) | ~0.1–0.2 s |
| 500 | **17.27 s** MEASURED | 499 × 34.6 ms | ~3.1 s (~5.5×) | ~1.5–2.5 s |
| 1000 | **80.22 s** MEASURED | 999 × 80.3 ms | ~10.2 s (~7.8×) | ~3.5–7 s |
| 2048 | **252.74 s** MEASURED | 2047 × 123.6 ms | ~35.3 s (~7.2×) | ~12–25 s |
| 4096 | ~911 s DERIVED | 4095 × 222.5 ms | ~133 s (~6.8×) | ~45–90 s |

(2048 row updated with the completed 2048-voter qualification: `archive_verify_ms = 252,736.767`, `archive_triptych = 2047`, overall PASS.)

Projection method: `ballots × measured batch16 per-proof + measured catalog overhead` (catalog overhead ≈ measured memo-hit cost: 30.2 / 130.2 / 323.5 / 531.8 ms at 100/500/1000/2048, scaled linearly to 4096). Worker column divides by 3 with wide error bars: multicore was MEASURED only at tiny rings (3.08×/4.00× at 2/3 workers); big-ring realized scaling is unmeasured and bandwidth-limited — consistent with the release audit's own 4096 projection of ~45–90 s. **Batch benchmark speedups are not guaranteed archive-verification speedups**; they are the crypto-stage component only.

**Best reasonable case at 1000 voters: ~3.5–4 s** (batch16 + 3 workers realizing near-3×). **Conservative case: ~10.2 s** (batch16, single core, no workers). **Likely bottleneck after optimization:** ring-MSM memory bandwidth (batch amortization already regresses at ring 4096), followed by the serial catalog rehash + archive-hash rebuild (~0.3–1.5 s), which becomes visible once crypto shrinks. Failure-path cost (full-blame) is linear in batch size and only paid when a proof is actually invalid.

Accounted non-crypto costs in all projections: archive parsing, catalog digest verification, transport/governance checks, canonical serial application, archive-hash rebuild, worker scheduling, batch failure handling.

---

## 10. Implementation scope estimate

**Stage 1 — batch16, single-threaded (recommended pre-beta core):**
- One file: `crates/archive/src/verifier.rs`. Refactor `ArchiveReplaySessionV1::intake_ballot` into (a) collect submission bytes in canonical order, (b) chunked `verify_approval_ballot_packages_batch_v1` (chunks of 16, results concatenated in order), (c) serial apply: `record_submission` → `accept_verified`/`Err(code)` → `record_decision`, preserving the exact per-ballot rejection-code mapping of `ingest_approval_ballot_package_v1`. Keep `add_historical_triptych_verifies(1)` per submission (the scale harness asserts `archive_triptych=N`). No new dependencies; no Cargo changes at all.
- ≈100–150 lines changed; ~1 day + tests.

**Stage 2 — bounded multicore (pre-beta optional / immediately after):**
- Extract `run_bounded` + `GlobalCryptoBudgetV1` from gui-core into a shared crate (minimum shared abstraction; gui-core's `historical_replay` migrates to it — no behavior change), and use it in the archive crate for chunk dispatch. Single-flight is already guaranteed per-archive by the memo's in-flight map.
- ≈150–250 lines moved + thin archive-side dispatch; ~2–3 days + tests.

---

## 11. Tests that would be required

1. **Output parity:** batched vs current-serial archive verification produce byte-identical `ArchiveDirectoryVerificationV1` for: all-valid archive; archive containing one cryptographically invalid proof (same `rejected_count`, same decision codes, `verified=true` unchanged); archive containing a duplicate nullifier (first-valid-wins reproduced); archive containing a malformed package.
2. **Worker=1 parity and multiworker equivalence** (mirror of `gui-core/tests/parallel_historical_replay.rs`): identical report for worker counts 1/2/forced-cap, batch sizes 1/16.
3. **Fail-closed tamper suite:** existing `archive_verify.rs` / `final_archive_regression.rs` / archive mutation tests pass unchanged (digest mismatch fails before replay; catalog anomaly fails closed).
4. **Memo suite:** existing `archive_verification_memo.rs` tests pass unchanged; memo hit still 0 Triptych verifies; memo hit output equals fresh verify.
5. **Counter semantics:** `archive_historical_replay_count == 1` and `archive_historical_triptych_verifies == N` per full verification (scale harness depends on these).
6. **Concurrency:** concurrent memo verification of the same archive still single-flights the (now parallel) replay; concurrent different archives respect the global CPU budget.
7. **Full-blame isolation:** one corrupted proof inside a 16-chunk rejects only itself; neighbors accept (covered by crypto-crate tests, re-asserted at archive level).

---

## 12. Pre-beta vs post-beta recommendation

**PRE-BETA** for Stage 1 (batch16 single-threaded). Justification: the beta target scales to 2048/4096 voters, where the current path costs a MEASURED ~4.2 minutes (2048) and a DERIVED ~15 minutes (4096) for the single most trust-critical operation an independent verifier performs; Stage 1 is ~100–150 lines in one file, uses already-shipped, already-equivalence-proven machinery, changes no protocol/on-disk artifact, and cuts that to under ~1–2.5 minutes single-core. Stage 2 (multicore) is equally safe but touches a cross-crate boundary; it can follow immediately or land post-beta without reworking Stage 1.

---

## 13. Exact next implementation step

In `crates/archive/src/verifier.rs`, restructure the `finish_verification` BALLOT_REPLAY stage:

1. After `ArchiveReplaySessionV1::new(...)` and `session.open()`, replace the per-path `intake_ballot` loop with: gather `submission_paths`' bytes (already held in `files`) into an ordered slice; for each contiguous chunk of 16 call `verify_approval_ballot_packages_batch_v1(&chunk, manifest, candidates, &provider, &self.verifier)`; concatenate results in order.
2. Add `ArchiveReplaySessionV1::apply_verified(&mut self, package_bytes, result)`: `record_submission(digest, true)` → on `Ok(verified)`: `ledger.accept_verified(lifecycle, verified)` mapping `Err` to `Rejected(code)`; on `Err(e)`: `Rejected(e.code())` → `record_decision`. Keep per-submission `add_historical_triptych_verifies(1)` and transcript-error fail-closed behavior identical to today.
3. Add the §11.1 parity test against the retained serial path before switching the default.

---

*End of audit. No files were modified during the audit.*
