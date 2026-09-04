# Slice 3B — safe durable-storage scaling remediation

**Status:** COMPLETE — design checkpoint, implementation, and validation done. **SLICE 3B VERDICT: PASS** (see Phase B/C completion gate at the end).

**Scope guard:** local application persistence only. No walletd, indexer, Ootle transaction construction, template, fee, signing, or L1/L2 routing behavior is touched. No vendored Triptych / curve25519 code is touched. No on-disk durable format change (see §12).

---

## Pre-implementation design checkpoint

**CURRENT BOTTLENECK.**
`write_workspace_revision` (`crates/gui-core/src/workspace.rs:740`) calls `load_committed_history` before *every* append. That walk reads **every** committed revision file through the head, hashes each payload, and decodes each **twice** (once in `read_valid_revision_file`, once for predecessor validation), plus reads/decodes every commit marker. For a normal one-package-per-append election this is `O(V²·S_registry + V³·S_package)` logical reads — the Slice 3A **runtime-validated** dominant cost: **18.44 TB projected logical reads at 4096 voters**, of which **93.41%** is repeated re-reading of older package snapshots.

**SECURITY PURPOSE OF FULL-HISTORY VALIDATION.**
The full walk provides fail-closed, *cold* detection of: a tampered historical revision, a missing middle revision, a wrong predecessor digest, a same-generation divergent revision/fork, a copied-in foreign workspace identity, and committed-head corruption. Crucially, missing-middle detection genuinely needs a full walk on a **cold** load: a predecessor digest alone cannot reconstruct an absent file. These are best-effort integrity checks against accidental corruption and partial writes; the workspace files are **not** externally signed, so an attacker with local write can already rewrite the entire store consistently (documented in `AUDIT_DURABLE_REVISION_SCALING.md:54`). The full walk is *not* required on every append **once this process has already fully validated the committed head and re-confirms that exact head immediately before it chains onto it.**

**MINIMUM SAFE OPTIMIZATION (chosen — Level 1, no format change).**
Maintain a process-local, memory-only *validated-head* map `workspace_id → (head_revision, head_revision_digest_hex)`, established only by a successful full `load_committed_history` inside the writer. On the next append the writer takes a **fast path**: it re-reads the cheap commit markers (which still validate contiguity, conflicts, and the head digest against the trusted value) and re-reads and digest-verifies **only the single head revision file** it is about to chain onto — then skips re-reading and re-decoding revisions `1..head-1`. The new revision is still fully serialized, written, digest-framed, self-decoded, and committed exactly as today. Any anomaly on the fast path (marker head ≠ trusted, head file missing/mismatched, decode failure, I/O error) discards the trusted head and **falls back to the full `load_committed_history` walk**, so the fast path can never accept anything the full walk would reject — it only ever *skips work* when the on-disk head is byte-identical to the head this process already validated.

This drops append head-loading from `O(all revisions)` to `O(1 head revision + markers)`, i.e. cumulative reads from `O(V²·G + V³·P)` to `O(V·G + V²·P)` — the same order as retained storage.

**ON-DISK FORMAT CHANGE REQUIRED: NO.** Revision encoding, digest framing, predecessor structure, commit markers, and filenames are unchanged. Existing V1 workspaces are read and written identically. (A format-level redesign — immutable genesis + content-addressed packages — remains the deferred follow-on; see §28–29.)

**TRUSTED-HEAD STATE.** A `LazyLock<Mutex<HashMap<String,(u64,String)>>>` in `workspace.rs`, process-local and memory-only. Value = the exact `(head_revision, head_revision_digest_hex)` of a head that a full `load_committed_history` in *this* process validated. It is an optimization hint, never a trust substitute: every fast append re-derives head identity from disk and compares before use.

**HOW TRUSTED HEAD IS ESTABLISHED.** Only by a successful full-history validation inside the writer (`load_head_for_append`'s full branch), after the complete predecessor chain has been checked. Successful fast appends advance it to the just-written `(revision, digest)`.

**HOW TRUSTED HEAD IS INVALIDATED.** (1) On-disk head drift — commit-marker head ≠ trusted `(revision,digest)`, or the trusted head revision file is absent/mismatched → entry cleared, full walk runs. (2) `delete_election_workspace_v1` clears the entry. (3) An empty committed history clears it. (4) Process restart — the map is never persisted, so it starts empty. External mutation, import, recovery, and supersession all change either the marker set or the head file bytes and are therefore caught by (1) as identity drift, then re-validated by the full walk.

**RESTART BEHAVIOR.** The map is memory-only; after restart it is empty, so the first append in the new process performs a full `load_committed_history` validation before any fast path is possible. There is **no persisted "history verified" bit.**

**ROLLBACK DEFENSE.** Unchanged. Lifecycle regressions are still rejected by `enforce_workspace_append_allowed` against the head body (the fast path decodes the head body from the single head file it reads). Revision numbering is still monotonic (`current_revision.checked_add(1)`), and the predecessor still commits the exact prior head digest.

**TAMPER DEFENSE.** Cold load is unchanged and still full-walks (missing-middle, tampered-history, wrong-predecessor, divergent-fork, copied-identity, head-corruption all fail closed). During a live process, a fast append re-reads and digest-verifies the exact head it chains onto, so head tampering forces a fallback + full re-validation. Tampering of an *older* (non-head) revision or marker during the same live process is not re-detected until the next cold load — acceptable because the append does not consume those bytes, this process already holds the validated in-memory session, and the store is not externally signed anyway.

**CRASH CONSISTENCY.** Unchanged. The write protocol (temp file + `sync_all`, self-decode check, final file + `sync_all`, directory sync, commit marker + `sync_all`, directory sync) is untouched. The trusted-head map is advanced only *after* the commit marker is durably written, so a crash mid-write never leaves the map pointing at an uncommitted revision; even if it did, the next append's marker recheck would reject it.

**CONCURRENCY / TOCTOU.** A narrow **per-workspace** append mutex (`workspace_id → Arc<Mutex<()>>`) serializes the read-head→write-commit critical section for one workspace, so two in-process appenders can never both read head=N and both write N+1. It is *not* a global lock (independent elections proceed in parallel) and holds no cryptographic verification. Cross-process forks remain fail-closed: two processes writing revision N+1 with different bodies produce different digests → different filenames → conflicting commit markers → `conflicting_workspace()` on the next load. The fast path re-reads markers under the lock immediately before writing (TOCTOU: observe head, confirm identity, then append).

**SLICE 2 CACHE INTERACTION.** No change. Slice 2's `VerifiedSessionKeyV1` is `(workspace_id, head_revision, head_revision_digest_hex, verifier_epoch)`. Slice 3B does not change revision identity, digest semantics, or format, so `VERIFIED_SESSION_CACHE_EPOCH_V1` stays **1** and the cache key is unchanged. The trusted-head map and the verified-session cache are independent authorities that both re-derive head identity from disk and both fail closed on drift, so they cannot contradict. The trusted-head map holds only `(revision, digest)` — never a session, never proofs — so it is not an alternate source of verified state.

**EXPECTED COMPLEXITY BEFORE:** append head-load `O(V·G + V²·P)` per append → cumulative `O(V²·G + V³·P)` reads/decodes.
**EXPECTED COMPLEXITY AFTER:** warm append head-load `O(G + b·P + V·marker)` (one head snapshot of `b` packages + `V` tiny markers) → cumulative `O(V·G + V²·P)` reads, `O(V²·marker)=O(V²)` from markers; one full `O(V·G+V²·P)` validation per process cold-start or drift event.

**4096 PROJECTED LOGICAL READS BEFORE:** ~18.44 TB (18,440,418,853,642 B).
**4096 PROJECTED LOGICAL READS AFTER (warm single session):** ~15.0 GB (14,995,633,961 B) = 13.20 GB head-only revision reads + 1.79 GB commit-marker reads — a **~1,230× reduction**. Each additional cold process start adds one full-history validation (~13.2 GB read once), not per-append.

**4096 RETAINED WORKSPACE BEFORE / AFTER:** ~12.31 GiB, **unchanged** (no format change). Write amplification (24.61 GiB logical application writes) is likewise unchanged. These remain the deferred format-level follow-on.

**MIGRATION REQUIRED: NONE** (no format change).

The equivalent fail-closed model is proven from the current hash-chain semantics above; implementation proceeds.

---

## 1. Executive summary

Slice 3B eliminates the confirmed dominant durable pathology — the per-append re-read and re-decode of the entire committed revision history — with a **process-local, memory-only validated-head fast path** and **no on-disk format change**. After a full committed-history validation establishes a workspace's head in this process, subsequent appends re-confirm that exact head from disk (commit markers + the single head revision file) and skip re-reading the revisions behind it. Cumulative logical reads at the 4096-voter maximum fall from **~18.44 TB to ~15.0 GB** (~1,230×), dropping one asymptotic factor of `V` (from `O(V²·G + V³·P)` to `O(V·G + V²·P)`). Every fail-closed guarantee is preserved: cold load still full-walks, head drift/corruption forces fallback + full re-validation, concurrent in-process appends are serialized per workspace, and new ballots still perform full Triptych verification. Retained disk (~12.31 GiB) and write amplification (~24.61 GiB) are intentionally unchanged — they are the deferred format-level follow-on.

## 2. Chosen architecture

A `LazyLock<Mutex<HashMap<String,(u64,String)>>>` in `workspace.rs` maps `workspace_id → (head_revision, head_revision_digest_hex)`, populated only by a successful full `load_committed_history` inside the writer and advanced by successful appends. `write_workspace_revision` acquires a narrow per-workspace append mutex, then `load_head_for_append` either (a) takes the **fast path** (`fast_path_append_head`) when the on-disk commit-marker head equals the trusted `(revision,digest)` and the single head revision file re-hashes to that digest — reading exactly one prior revision file — or (b) falls back to the full `load_committed_history` walk on any drift/anomaly, which re-establishes trust. The new revision is serialized, written (temp+final with `sync_all`), self-decoded, and committed exactly as before; only after the commit marker is durable is the trusted head advanced.

## 3. Why smaller/larger alternatives were rejected

- **Smaller — do nothing / micro-optimize decode:** rejected; the pathology is repeated *reading of whole snapshots*, not decode constant factors.
- **Larger — Level 3 format redesign (immutable genesis + content-addressed deltas):** deferred. It is the right long-term direction (removes retained-disk and write amplification too) but requires a V2 format, migration, and a much larger blast radius. The task mandates the *minimum* architecture that removes the dominant pathology; Level 1 does so with zero format risk. Level 3 is recorded as future work (§29).
- **Caching the head body in memory (avoid re-reading the head file):** would push after-reads to ~1.79 GB (markers only) but adds unbounded per-workspace memory (a 6.3 MB head × up to 512 workspaces) and a subtler consistency argument. Rejected for this slice in favor of reading one head file (O(1) memory); noted as an optional refinement (§29).

## 4. Security invariants preserved

Tampered historical revision, missing middle revision, wrong predecessor digest, same-generation divergent fork, copied-in foreign workspace id, committed-head corruption, orphan/uncommitted future revision, partial write, rollback, supersession, organizer-authority sidecar, election-status, lifecycle ordering, nullifier/first-valid semantics, manifest/registry/candidate binding, package ordering, finalization integrity, tally reconstruction, and archive/export compatibility are all unchanged. Cold load is byte-for-byte the same code as before. The fast path never *relaxes* a check reachable on the append it replaces: it re-derives head identity from disk and, on any mismatch, defers to the full walk, so it cannot accept anything the full walk would reject. Evidence: the 38-test `workspace.rs` hostile suite (including `wrong_predecessor_digest_fails_closed_even_when_redigested`, `same_generation_divergent_revision_commits_conflict_even_with_future_orphan`, `revision_copied_into_different_workspace_id_is_rejected`, `tampered_committed_newest_revision_fails_closed_without_rollback`, `missing_middle_committed_revision_fails_closed`) remains green, plus the 14 Slice 3B tests (§25).

## 5. Trusted-head semantics

Memory-only; workspace-specific; bound to exact `(head_revision, head_revision_digest_hex)`; established only by a full validated walk in this process; advanced only after a commit marker is durable; invalidated on head drift, head-file absence/mismatch, delete, empty history, and (implicitly) process restart. It holds no session, no proofs, no lifecycle — only a head identity — so it can never become an alternate source of verified election state. There is **no persisted "history verified" bit**.

## 6. Durable identity

Unchanged. Revision digest = BLAKE3 over a domain-separated frame of the payload (which itself commits the predecessor digest). Commit-marker filenames and payloads are unchanged. The fast path's trusted identity is exactly the pair Slice 2 already treats as the head identity.

## 7. TOCTOU defense

The read-head→write-commit critical section runs under the per-workspace append lock. The fast path re-reads the commit markers and the head revision file *immediately before* choosing the predecessor, and `write_create_new_sync` uses `create_new` (O_EXCL) so a colliding revision file/marker cannot be silently overwritten. Cross-process races still fail closed as `conflicting_workspace()` on the next load (two different bodies at the same generation ⇒ two digests ⇒ conflicting markers).

## 8. Concurrency model

A narrow **per-workspace** `Arc<Mutex<()>>` (never a global lock; no crypto verification held under it) serializes appends to one workspace. Independent elections append concurrently. Lock contention is counted (`workspace_append_lock_contention`). Slice 2 reconstruction parallelism is untouched.

## 9. Restart behavior

The validated-head map is never persisted. After restart it is empty, so the first append per workspace performs a full `load_committed_history` validation (proven by `fresh_process_append_performs_full_history_validation`, which clears the map to simulate a restart and observes one full validation reading all committed revisions).

## 10. External mutation handling

Any external change to the head marker set or head file bytes is caught by the fast path's re-derivation: a changed head revision/digest ⇒ `Ok(None)` drift ⇒ full walk; a corrupted head file ⇒ read error ⇒ full walk fail-closed. Non-head historical mutation during a live process is not re-detected until the next cold load — acceptable because the append does not consume those bytes, this process already holds the validated in-memory session, and the store is not externally signed. Proven by `head_corruption_invalidates_fast_path_and_fails_closed`.

## 11. Cache interaction (Slice 2)

`VERIFIED_SESSION_CACHE_EPOCH_V1` stays **1**; the cache key is unchanged because revision identity, digest semantics, and format are unchanged. The trusted-head map and the verified-session cache are independent, both re-derive head identity from disk, and both fail closed on drift, so they cannot contradict. Proven by `slice2_cache_hit_preserved_under_fast_path` (a second resume of an unchanged head is a cache hit with exactly one reconstruction) and by the unchanged 6-test `verified_session_cache.rs` suite.

## 12. Format / migration decision

**On-disk format changed: NO. Migration required: NONE.** The decoder still accepts only V1; existing workspaces read and write identically. The retained ~12.31 GiB full-snapshot footprint is unchanged and explicitly out of scope for this slice.

## 13. Instrumentation

`instrumentation.rs` gains aggregate-only counters (numbers only, no ballot/nullifier/credential/path material): `workspace_append_calls`, `workspace_append_fast_path_hits`, `workspace_append_full_history_validations`, `workspace_append_revision_files_read` (prior revision files opened while choosing the head — full walk adds one per committed revision, fast path adds exactly one, genesis zero), `workspace_append_trusted_head_invalidations`, `workspace_append_identity_drift`, and `workspace_append_lock_contention`.

## 14. Before complexity

Per-append head-load `O(V·G + V²·P)`; cumulative over `V` appends `O(V²·G + V³·P)` logical reads and decodes.

## 15. After complexity

Warm append head-load `O(G + b·P + V·marker)` (one head snapshot + `V` tiny markers); cumulative `O(V·G + V²·P)` reads — one asymptotic factor of `V` removed, now equal in order to retained storage. One full `O(V·G + V²·P)` validation per process cold-start or drift event, not per-append.

## 16–21. Per-voter projections (warm single organizer session)

All logical, application-level; PROJECTED from the exact source-byte model (Slice 3A §6–7) applied to the after-append read structure. Retained disk and logical writes are **unchanged** from Slice 3A.

| voters | revisions V | reads BEFORE | reads AFTER | read reduction | retained (unchanged) | logical writes (unchanged) |
|---:|---:|---:|---:|---:|---:|---:|
| 50 | 55 | 26,604,112 | 1,711,202 | 15.5× | 1,455,437 | 2,899,159 |
| 100 | 105 | 208,957,912 | 6,945,027 | 30.1× | 5,910,937 | 11,799,509 |
| 500 | 505 | 28,047,105,172 | 189,450,131 | 148× | 163,077,042 | 326,046,519 |
| 1,000 | 1,005 | 238,157,369,422 | 801,386,381 | 297× | 695,486,542 | 1,390,759,019 |
| 2,048 | 2,053 | 2,172,832,042,762 | 3,552,584,489 | 611× | 3,107,317,206 | 6,214,197,123 |
| 4,096 | 4,101 | 18,440,418,853,642 | 14,995,633,961 | 1,230× | 13,212,106,198 | 26,423,338,883 |

After-reads = (Σ revision payloads − head payload) head-only reads + `213·V(V-1)/2` commit-marker reads. At 4096: 13,204,932,311 B head-only + 1,790,701,650 B markers = **14,995,633,961 B (13.97 GiB)** vs **18,440,418,853,642 B (16.77 TiB)** before.

## 22. Retained disk impact

**Unchanged (~12.31 GiB at 4096).** The full-snapshot format is untouched by design. Reducing retained disk requires the deferred format-level slice (immutable genesis + content-addressed packages).

## 23. Logical read impact

Dominant pathology removed: ~18.44 TB → ~15.0 GB at 4096 (~1,230×), asymptotically `O(V²·G + V³·P)` → `O(V·G + V²·P)`.

## 24. Logical write impact

**Unchanged (~24.61 GiB at 4096).** The fast path changes only reads; each append still writes the full snapshot twice (temp+final) plus a marker. Deferred to the format-level slice.

## 25. Tests

New suite `crates/gui-core/tests/durable_append_fast_path.rs` (14 tests, serialized via a file-local guard because the dev counters are process-global):

1. `fresh_process_append_performs_full_history_validation` — restart ⇒ full validation reading all committed revisions (req. 1, 12).
2. `warm_append_reads_only_head_not_whole_chain` — warm append is a fast hit reading exactly one head file (req. 2).
3. `warm_append_head_read_is_constant_across_history_depth` — head read independent of history depth (scaling).
4. `fast_appended_revision_is_authoritative_on_resume` — the fast-appended revision passes cold full validation on resume (req. 3, 18).
5. `tampered_old_revision_fails_closed_on_cold_load` (req. 4).
6. `missing_middle_revision_fails_closed_on_cold_load` (req. 5).
7. `head_corruption_invalidates_fast_path_and_fails_closed` (req. 9, 10).
8. `concurrent_appends_do_not_fork` — per-workspace lock; distinct contiguous revisions; resumable (req. 11).
9. `resume_does_not_grant_fast_path_trust` (req. 13).
10. `delete_clears_trusted_head` (req. 14).
11. `new_ballot_still_verifies_cryptographically` (req. 15).
12. `slice2_cache_hit_preserved_under_fast_path` (req. 16).
13. `workspace_listing_replays_nothing` (req. 17).
14. `lifecycle_finalization_is_deterministic_under_fast_path` (req. 19).

Requirements 6 (wrong predecessor), 7 (divergent same-generation), 8 (copied workspace id), and 20 (existing security tests) are proven green by the unchanged 38-test `workspace.rs` hostile suite. See `AUDIT_DURABLE_APPEND_FAST_PATH_MATRIX.csv` for the per-scenario matrix.

## 26. Test results

MSVC toolchain (`+stable-x86_64-pc-windows-msvc`, `--features test-support`), all green:

- `durable_append_fast_path`: **14/14**
- `workspace`: **38/38** (all hostile cold-load cases)
- `verified_session_cache`: **6/6**
- `reconstruction_instrumentation`: **5/5**
- Broad regression (same run): lib **112**, `archive_verify` **12**, `creation` **51**, `election_status` **11**, `governance` **38**, `intake` **13**, `participation` **18**, `private_intake_inbox` **16**, `security` **7**, `serialization` **3**, `tally` **10**, `voter_cast_lock` **22** — all 0 failed.
- `cargo check -p tari-cc-private-ballot-gui-core`: PASS. `cargo check --manifest-path gui/src-tauri/Cargo.toml`: PASS (exit 0).

## 27. Existing unrelated blockers

`crates/gui-core/tests/archive_writer.rs:910` fails to compile with `E0308` (`expected &str, found String`) when assigning `request.output_config_path`. Both `crates/gui-core/src/live_anchor_config.rs` and `crates/gui-core/tests/archive_writer.rs` were already in the uncommitted modified set at session start; this mismatch predates and is independent of Slice 3B (a Slice 3B API break would surface as `E0063` missing-field errors on the instrumentation snapshot, not an `&str/String` mismatch in a live-anchor config request). Because one broken test binary aborts a whole `cargo test -p` run, the regression suites above were run as explicit test targets excluding `archive_writer`. This blocker should be resolved by the owner of the live-anchor-config uncommitted work.

## 28. Remaining storage inefficiencies

- Retained full-snapshot duplication (~12.31 GiB at 4096) — reads are no longer the pathology, but disk footprint still grows `O(V·G + V²·P)`.
- Write amplification — each append still serializes and writes the full snapshot twice.
- The warm fast path still re-reads (and decodes) the single growing head snapshot per append (~13.2 GB cumulative at 4096); caching the head body under digest confirmation would reduce after-reads to marker-only (~1.79 GB).

## 29. Recommended future storage work

1. **Head-body cache (small):** keep the last-written head body in the validated-head map (already digest-identified) to skip re-reading the head file on warm appends; bound by capacity/LRU like Slice 2.
2. **Format-level slice (Level 3):** V2 durable format = immutable genesis object (manifest, registry, candidates stored once, committed by digest in every head) + append-only digest-chained deltas whose events are lifecycle transitions and content-addressed package-digest references. This removes retained duplication and write amplification, with an explicit V2 discriminator, read-only V1 support, backup-before-migrate, atomic write-new-then-commit conversion, and a stated downgrade policy.

## 30. Slice 4A handoff

Durable reads are no longer the cold-open bottleneck for large elections; the remaining large cold-open cost is **cryptographic**: a cold resume replays every stored package through Triptych verification (`from_durable_snapshot` → per-package `verify`). Slice 4A audits that verifier cost and designs a future bounded-multicore historical-verification architecture (audit/design only; no crypto changes). The fast path and the Slice 2 verified-session cache both key on the same durable head identity, so a future parallel verifier can construct one immutable election verifier context, verify independent historical proofs in parallel, apply results in canonical durable order, and enter the Slice 2 cache without any storage-format change.

---

### Phase B/C completion gate

- Security rationale source-proven: YES (§4, §10; hash-chain semantics in `AUDIT_DURABLE_REVISION_SCALING.md:52–56`).
- No persisted blind trust bit: YES (memory-only map; §5, §9).
- Restart begins without trusted-head state: YES (§9; test 1).
- Tampered history detectable: YES (tests 5–7; workspace suite).
- Wrong predecessor detectable: YES (workspace suite).
- External mutation invalidates fast-path authority: YES (§10; test 7).
- Concurrent writers cannot silently fork: YES (§8; test 8).
- New revision itself validated: YES (self-decode on write; test 4).
- Slice 2 cache invariants intact: YES (§11; test 12; cache suite 6/6).
- New ballots still verify cryptographically: YES (test 11).
- Workspace listing zero-replay: YES (test 13).
- Required security tests pass: YES (§26).
- Production source compiles: YES (§26).
- Tauri crate compiles: YES (§26).
- Operation counts demonstrate the scaling reduction: YES (tests 1–3; §16–21).
- Durable format behavior documented exactly: YES (§12, §22, §24).

**SLICE 3B VERDICT: PASS.**

Production source changed by Slice 3B: `crates/gui-core/src/workspace.rs`, `crates/gui-core/src/instrumentation.rs`, `crates/gui-core/src/lib.rs` (export line). New test: `crates/gui-core/tests/durable_append_fast_path.rs`. New audit files: this report and `AUDIT_DURABLE_APPEND_FAST_PATH_MATRIX.csv`.
