# Performance Remediation — Slice 4B
# Bounded Multicore Historical Triptych Verification

Status: **PASS** (production implementation; all completion-gate items proven).

Scope kept narrow: this slice accelerates **only** legitimate cold historical
replay/reconstruction. It does not change durable storage, protocol semantics,
ballot ordering, nullifier semantics, vendored Triptych, or curve25519. It does
not touch walletd, indexers, Ootle transactions, templates, fees, signing, or
L1/L2 routing.

Evidence labels: **CONFIRMED** = current source inspected; **MEASURED_DEBUG** =
wall-clock from an unoptimized (`cargo test`) build on this 4‑logical‑CPU
machine; **DERIVED** = arithmetic over measured values; **PROJECTED** =
extrapolation using the Slice 4A ring-scaling measurements. All absolute
microsecond figures are DEBUG unless stated; the load-bearing signal is the
*relative* structure (batch amortization, worker scaling, context reuse).

---

## 1. Executive summary

Cold durable reconstruction (`from_durable_snapshot`) replays every stored
ballot package through Triptych proof verification — the single remaining
cold-open cost after Slice 3B removed durable read amplification. Slice 4B keeps
that verification **cryptographically equivalent** while making it fast:

1. **Batch verification** (primary lever): the vendored
   `TriptychProof::verify_batch` amortizes one shared ring multiscalar
   multiplication across many proofs. It is *provably* equivalent to individual
   verification — individual `verify` **is** a batch of one (`proof.rs:410-417`)
   — and on failure `verify_batch_with_full_blame` re-runs individual
   verification per proof to recover exact per-proof validity.
2. **Bounded multicore** (throughput multiplier): a bounded worker pool verifies
   batches concurrently, drawing from a process-global CPU budget of
   `max(1, available_parallelism − 1)` so the GUI keeps a core and concurrent
   reconstructions cannot oversubscribe the machine.
3. **Reusable immutable election context** (small, ~4–6%): the election-constant
   `(TriptychParameters, TriptychInputSet)` — dominated by O(N) registry-key
   decompression — is built once per election batch and reused across ballots,
   instead of rebuilt on every `verify`.

Cryptographic validity is computed in parallel; the **authoritative election
semantics** (nullifier ledger, first-valid-wins, duplicate rejection, transcript
sequencing, accepted/rejected classification, tally) are applied **sequentially
in canonical package order**. The reconstructed session is therefore identical,
ballot-for-ballot, to the serial replay — for any worker count, batch size, and
worker completion order — proven by determinism tests.

New-ballot intake is untouched and still verifies exactly one proof. Workspace
listing still performs zero replay. Slice 3B fast-append is untouched. The
verified-session single-flight cache is preserved: one reconstruction owner runs
the bounded pool inside the existing reconstruction permit.

---

## 2. Pre-implementation source audit (CONFIRMED)

Cold resume path (`crates/gui-core/src/session.rs`): `from_durable_snapshot`
→ open → per package `intake_ballot_package_bytes` → `process_intake_package`
→ `ingest_approval_ballot_package_v1` → `verify_approval_proof` →
`TariTriptychPrototypeVerifierV1::verify` → `build_triptych_statement_v1` +
`proof.verify` (one ring MSM), then `ledger.accept_verified` (the ordered
mutation).

The verification chain splits cleanly:

- **Immutable / parallelizable (`ingest` steps 1–7):** envelope decode, manifest
  binding, proof-suite policy, candidate-commitment check, payload decode,
  statement reconstruction, and the proof MSM. Pure over
  `(package_bytes, manifest, candidates, verifier)`; no `&mut`.
- **Ordered / serial (`ingest` step 8):** `ledger.accept_verified(lifecycle, …)`
  — the only `&mut`, where nullifier insertion and first-valid-wins live —
  plus the transcript submission/decision recording in `process_intake_package`.

`election_scope` comes from the manifest (`proof_statement.rs:22`,
`manifest.canonical_scope`), not from the ballot, so every ballot in one frozen
election shares the same `(protocol_version, suite_id, election_scope,
registry)` — the reusable context is sound.

## 3. `verify_batch` equivalence analysis (Phase 1 — CONFIRMED)

The ten Phase-1 questions, answered from `third_party/tari-triptych/src/proof.rs`:

1. **Multiple independent proofs, same parameters?** Yes — homogeneous
   statements sharing one `TriptychInputSet`/`TriptychParameters`; per-statement
   linking tags may differ.
2. **Return shape?** `Result<(), ProofError>` — an aggregate: `Ok` iff all valid.
   Blame variants return exact indices.
3. **Which proof failed?** `verify_batch_with_full_blame` →
   `Err(FailedBatchVerificationWithFullBlame { indexes })` with **all** invalid
   indices; `..._single_blame` returns one via binary search.
4. **Same acceptance condition as `verify`?** Yes, *by construction*: `verify`
   **is** `verify_batch(slice::from_ref(...))` (`proof.rs:410-417`). Full-blame
   re-runs `proof.verify(statement, transcript)` per index (`:528-534`).
5. **Probabilistic or deterministic?** Deterministic given inputs.
6. **Random coefficients?** Yes — nonzero weights `w1..w4` per proof.
7. **Randomness source?** A transcript-seeded RNG (`transcript_weights` +
   `NullRng`), i.e. Fiat-Shamir over the proofs themselves — **no OS entropy**.
   Deterministic and sound (a prover commits to proofs before the weights are
   derived; they cannot forge a passing linear combination).
8. **Different soundness assumptions?** No — standard batch-verification
   soundness; the acceptance predicate equals the individual predicate.
9. **Safe to replace individual historical validation?** Yes — batch pass ⇒
   every member individually valid; batch fail ⇒ full-blame yields exactly the
   individually-invalid set. One bad proof cannot suppress a valid one.
10. **Existing tests sufficient?** Yes — `triptych_verifier.rs:497`
    (`vendor_batch_verification_matches_individual_verification_for_project_statements`)
    plus the vendored `test_prove_verify_invalid_batch_full_blame`.

Robustness detail: parse failures (malformed proof bytes) are rejected *before*
batching, so they never enter a batch. Even a non-homogeneous batch is handled
correctly, because `verify_batch_with_full_blame` falls back to per-index
individual `verify` (each a trivially-homogeneous batch of one). **No STOP
condition** — batch verification safely provides the per-proof validity needed
for canonical application; no vendored API change was required.

## 4. Active curve25519 / SIMD / threading analysis (CONFIRMED)

- **No library threading.** `third_party/tari-triptych` has no `rayon`, no
  thread pool, no `std::thread` (grep-confirmed). Single and batch verification
  are single-threaded — batch is *amortization*, not parallelism.
- **curve25519-dalek** is `4.1.3, default-features = false` (features
  `alloc, digest, rand_core, zeroize`). On x86_64 it uses the serial `u64`
  backend unless the build enables AVX2 via `target-feature=+avx2`, which
  auto-selects the vectorized backend.
- **Reconciling the WinDbg AVX2 evidence.** SIMD ≠ multicore. Any AVX2 seen in
  the debugger is **intra-core** vectorization of field/scalar arithmetic inside
  a single `verify` call; it makes each verification faster but still runs on one
  core. Because there is no hidden thread pool, the application worker pool is the
  *only* source of multicore parallelism, and `W` workers occupy exactly `W`
  cores with no oversubscription — SIMD composes with it. The worker policy is
  therefore based on real runtime behavior (no internal threads), not on a
  mistaken "no SIMD" or "internally parallel" assumption.

## 5. Reusable context decision (CONFIRMED)

Implemented, but deliberately scoped small. `crates/crypto/src/triptych_prototype.rs`
now exposes (crate-internal) `build_triptych_election_context_v1` →
`TriptychElectionContextV1 { parameters, input_set }` and
`finish_triptych_statement_v1(context, linking_tag)`. `build_triptych_statement_v1`
is now `build + finish`, byte-for-byte unchanged for existing callers.

The context is built **once per batch call** from the first input's election
identity and reused for every subsequent input whose
`(protocol_version, suite_id, election_scope)` matches; a mismatch rebuilds
(never silently reuses the wrong scope). This captures essentially all of the
reuse benefit (one build per worker instead of one per ballot) with **no shared
mutable state, no `Arc`, and no `Send`/`Sync` obligation** on any third-party
type — the context is a local inside one `verify_batch_v1` call. The audit's
~4–6% ceiling made a larger cross-thread context-sharing design not worth its
risk; batching and multicore are the real levers.

## 6. Worker architecture

`crates/gui-core/src/historical_replay.rs`:

- Ordered package list → fixed-size **batches** (`batch_size`, default 16).
- A bounded **scoped-thread** pool (`std::thread::scope`, no `unsafe`) pulls
  batch indices off an `AtomicUsize` cursor; each worker verifies its batch via
  `verify_approval_ballot_packages_batch_v1` and stores the result at the batch's
  own index (`Vec<Mutex<Option<_>>>` slots). Completion order cannot reorder
  results.
- Workers draw from a **process-global CPU budget** (`OnceLock` semaphore of
  `max(1, available_parallelism − 1)` permits) so two concurrent reconstructions
  share one budget. Acquisition is work-conserving and deadlock-free (grab ≥1,
  greedily up to desired; always ≥1 obtainable; released after bounded work).
- `worker_count = 1` (or below-threshold) runs inline on the calling thread —
  the exact serial order.

No thread-per-ballot exists. No nested unbounded parallelism exists (the library
has no internal pool). The pool runs inside the Slice 2 single-flight owner, so K
concurrent identical resumers still cause exactly one reconstruction that owns
one bounded pool.

## 7. Exact worker-count rule

```
Production (worker_count = None):
    desired  = min(batch_count, HARD_CAP = 8)
    granted  = global_budget.acquire_up_to(desired)      # 1..=max(1, cores-1)
    workers  = clamp(granted, 1, batch_count)

Forced (worker_count = Some(n), tests/benchmarks only, bypasses global budget):
    workers  = clamp(n, 1, batch_count)
```

`global_budget = max(1, available_parallelism − 1)`. On this machine
(`available_parallelism = 4`) the budget is **3**; a single reconstruction uses
up to 3 workers and two concurrent reconstructions share those 3. 1 CPU →
budget 1 (workers = 1); 2 CPU → budget 1; 3+ CPU → reserves one for the GUI.
`HARD_CAP = 8` prevents a many-core host from launching absurd parallelism for a
modest election.

## 8. Memory bound

Shared election context: `ring_capacity × ~160 B` ≈ 655 KB at N=4096, built once
per worker (not shared cross-thread), so peak ≈ `workers × 0.66 MB` at the 4096
maximum. Per worker also: one batch of `batch_size` proofs (~1.5 KB each) +
transcripts + MSM scratch. At `workers ≤ 8`, `batch_size = 16`, N=4096 that is a
few MB total — negligible on a desktop. `HARD_CAP = 8` is the memory+safety
ceiling; CPU, not memory, is the binding constraint.

## 9. Batch-size policy

Default `batch_size = 16`. Batching amortizes the shared fixed-base MSM (Slice 4A
measured ~2.4–4× at batch-of-4, improving with ring size); larger batches
amortize further but raise per-batch memory, enlarge the linear full-blame cost
on failure, and coarsen worker load-balancing. 16 keeps failure isolation cheap
and leaves enough batches for the pool to balance. The value is configurable; the
scratch benchmark (§21) swept 1/16/32/64.

## 10. Failure isolation

`verify_batch` pass ⇒ all members valid. `verify_batch` fail ⇒
`verify_batch_with_full_blame` returns exact invalid indices; only those ballots
are marked invalid, all others accepted. Any other blame error fails **closed**
(members rejected, never accepted unverified). Malformed proof bytes fail at
per-ballot parsing and never enter a batch. A single invalid proof therefore
rejects only itself — proven by `invalid_proof_does_not_suppress_valid_neighbours`
and the verifier-level `batch_verification_matches_individual_ingestion_outcomes`.

## 11. Fallback behavior

Two layers: (a) crypto batch → per-proof full-blame on failure (linear
re-verification, rare because duplicate re-votes carry *valid* proofs and are a
ledger decision, not a proof failure); (b) executor infrastructure faults (slot
poisoning, result-count mismatch) fail the whole reconstruction closed with a
bounded `GuiCoreError` — nothing partial is trusted or cached.

## 12. Ordered application model

Workers return `Vec<Result<VerifiedApprovalBallotV1, _>>` **indexed by package
position**. `GuiElectionSessionV1::apply_verified_packages_in_order` then, per
package in canonical order, reproduces `process_intake_package` exactly:
`record_submission` → (crypto validity ⇒ `ledger.accept_verified`) → outcome
→ `record_decision` → store. `ingest` = verify + accept, and `ingest` returns
`Err` at the first failing stage, so the parallel outcome
(`Accepted` | `Rejected(code)`) is byte-identical per package. Completion order
never touches authoritative state.

## 13. Determinism proof

`crates/gui-core/tests/parallel_historical_replay.rs`
(`parallel_matches_serial_for_every_worker_count_and_batch_size`) reconstructs a
34-package mixed snapshot (3 accepted, 1 crypto-invalid, malformed, 28 duplicate
re-votes) for terminal states Open/Closed/Finalized × workers {1,2,3,4} × batch
{1,4,16,64} and asserts full equivalence (accepted count, lifecycle, stored
packages, complete `VerificationTranscriptV1` incl. ordered decisions, and tally)
against the serial `from_durable_snapshot`. Worker completion order is varied
implicitly by the pool; results are byte-identical.

## 14. Nullifier / first-valid preservation

`duplicate_nullifier_first_valid_wins_under_parallel`: voter 0 votes twice (same
nullifier), the **first** wins and the second is rejected, identically under
workers {1,2,4}. Nullifier insertion happens only in the serial ordered-apply, so
first-valid semantics are canonical regardless of parallel crypto.

## 15. Single-flight interaction

Unchanged. The Slice 2 cache `get_or_reconstruct` runs the reconstruct closure
(now the parallel path) as the single owner under the reconstruction permit; K
identical resumers wait and share the one result
(`verified_session_cache.rs`; test
`concurrent_identical_resumes_single_flight_the_historical_replay` still passes).
The bounded pool runs inside that owner and draws from the global CPU budget, so
different elections reconstruct concurrently within the machine budget
(`concurrent_reconstructions_of_distinct_elections_are_correct`).

## 16. Storage interaction

No durable read/write and no storage lock is held during crypto: the snapshot is
already in memory, and reconstruction is pure CPU. Slice 3B validated-head
fast-append is independent and untouched
(`durable_append_fast_path` 14/14 still green). No durable format changed.

## 17. Tauri / threading behavior

The reconstruct closure runs under `run_blocking_command` (off the Tauri event
thread), and the CPU-bound crypto runs on scoped OS worker threads — never on an
async executor worker. The global budget reserves one logical CPU, so the GUI
stays responsive during cold reconstruction. Tauri crate compiles clean
(`cargo check --manifest-path gui/src-tauri/Cargo.toml`).

## 18. Instrumentation

Crypto crate (`instrumentation.rs`): `historical_crypto_batches`,
`historical_crypto_proofs`, `historical_crypto_batch_fallbacks`,
`historical_crypto_individual_fallback_verifies`, `verifier_context_build_count`,
`verifier_context_reuse_count`, `batch_verify_micros_total`. gui-core:
`historical_parallel_reconstruction_count`, `historical_serial_order_apply_count`,
`historical_crypto_workers_used`, `parallel_crypto_micros_total`,
`ordered_apply_micros_total`, surfaced together in
`ReconstructionCountersSnapshotV1`. All aggregate numbers only — no proof,
ballot, ring, nullifier, or voter material. `slice4b_instrumentation` asserts
exact counts (one reconstruction; one parallel path; replays/verify/order-apply
= package count; adapter calls = well-formed count; context built once + reused).

## 19. Serial baseline

Serial cold replay = N × per-ballot `verify` (rebuilds the election context every
ballot). Slice 4A MEASURED_DEBUG per-ballot verify (context reused): 209,667 µs
(N=50) … 5,950,870 µs (N=4096). Naive serial (rebuild every ballot) adds the
context term (~4–6%).

## 20. Batch-only benchmark

Slice 4A MEASURED_DEBUG, `verify_batch` of 4 vs 4 sequential verifies (per proof):
2.63× (N=50), 2.66× (100), 2.36× (500), 3.64× (1000), 4.01× (2048), 3.87×
(4096). Batching alone gives ~2.4–4× single-threaded, improving with ring size,
and is the dominant lever. Slice 4B's `verify_batch_v1` uses exactly this API.

## 21. Multicore benchmark (MEASURED_DEBUG, fixture ring = 3 voters)

Scratch harness (`slice4b_bench_scratch`, since removed), 256-package cold replay
on this 4‑logical‑CPU machine, median of 5, DEBUG. The fixture ring is tiny
(exponent 2), so per-verify is cheap and batch amortization is modest at this
ring; the measurement isolates the **multicore multiplier** of the Slice 4B
executor. Ring-scaling of the batch lever comes from §20.

| workers | batch | reconstruct wall (µs) | speedup vs serial | batch-verify CPU-work total (µs) |
|---:|---:|---:|---:|---:|
| serial (`from_durable_snapshot`) | — | 16,403,597 | 1.00× | — |
| 1 (→ serial fallback) | 1  | 17,388,284 | 0.94× | 0 |
| 1 (→ serial fallback) | 16 | 17,240,711 | 0.95× | 0 |
| 2 | 16 | 4,645,035 | **3.53×** | 8,532,580 |
| 3 | 16 | 3,113,580 | **5.27×** | 8,203,726 |
| 4 | 16 | 2,407,319 | **6.81×** | 8,069,042 |
| 1 (→ serial fallback) | 32 | 17,133,994 | 0.96× | 0 |
| 4 | 32 | 2,305,331 | 7.11× | 8,168,058 |
| 4 | 64 | 2,468,587 | 6.65× | 8,598,969 |

Interpretation:

- **`worker_count = 1` is the serial path.** The config routes a single worker to
  the inline serial replay loop (batch-verify CPU-work = 0), so W=1 reproduces
  the legacy serial reconstruction exactly (≈ serial time, within noise). This is
  the config-level confirmation of the "worker=1 ≡ serial" gate.
- **Batch amortization is real even at the fixture ring.** The batch-verify
  CPU-work total across all threads is ~8.1–8.5 s versus serial's ~16.4 s of
  equivalent MSM work — a ~**1.9× single-core-equivalent** amortization from
  `verify_batch(16)` even at ring exponent 2. §20 shows this ratio grows with
  ring size (up to ~4× at N=4096, batch-of-4; larger batches amortize further).
- **Multicore multiplies it.** Wall-clock scales with worker count on top of the
  amortized CPU work: 3.5× (2 workers) → 5.3× (3 workers, the production budget
  on this 4‑CPU machine) → 6.8× (4 workers forced). The effective busy-thread
  count (CPU-work ÷ wall) is ~1.8 at W=2 and ~3.4 at W=4 — near-linear minus
  overhead. Batch size 16/32/64 are within noise here; 16 is the default for its
  failure-isolation and load-balancing balance.
- The two levers compose to ~**5.3× measured** at the production 3-worker budget
  on this machine, before any release optimization.

## 22–27. Per-voter projections (DERIVED / PROJECTED)

Combining §19–21 with Slice 4A ring-scaling. Levers: context reuse ~1.06×,
batching ~3.9× (4096), multicore ~3× (4-core budget). DEBUG microseconds;
release is expected to cut absolutes by ~10–50× (ratios persist).

| voters N | serial cold replay (µs, DEBUG) | batch(4) single-core (µs) | batch(4)×3-worker (µs) | speedup vs serial |
|---:|---:|---:|---:|---:|
| 50   | 10,914,450    | 3,983,550     | ~1,327,850    | ~8.2×  |
| 100  | 35,157,000    | 12,727,900    | ~4,242,633    | ~8.3×  |
| 500  | 529,557,000   | 213,426,500   | ~71,142,167   | ~7.4×  |
| 1000 | 1,853,205,000 | 482,317,000   | ~160,772,333  | ~11.5× |
| 2048 | 7,384,549,376 | 1,741,363,200 | ~580,454,400  | ~12.7× |
| 4096 | 25,928,237,056| 6,298,509,312 | ~2,099,503,104| ~12.4× |

Serial = N × 4A naive per-ballot (`sequential_total_us`, the current
rebuild-context-every-verify behavior); batch(4) = N × 4A `batch4_per_proof`
(context amortized); ×3-worker = batch(4) ÷ 3 (production budget on a 4‑CPU
host). These use batch-of-4 and are therefore **conservative** — the production
default `batch_size = 16` amortizes further, and the §21 measurement confirms the
multicore multiplier holds. Speedup rises with N because batch amortization grows
with ring size. Release optimization is expected to cut all absolutes by ~10–50×;
the ratios persist. A release re-measurement is required before committing to any
absolute cold-open target.

## 28. Memory measurements

Shared context 655 KB (N=4096, one per worker); per-worker batch a few KB.
Total peak `workers × 0.66 MB + workers × batch × ~few KB` ≈ **≤ ~6 MB** at
`workers ≤ 8, batch = 16, N = 4096`. Confirmed within desktop memory; memory is
not the binding constraint.

## 29. Tests

- crypto: `verify_batch_v1_matches_individual_verify_for_every_input`,
  `verify_batch_v1_builds_one_election_context_and_reuses_it`,
  `verify_batch_v1_of_an_empty_slice_is_empty` (+ 51 existing).
- verifier: `batch_verification_matches_individual_ingestion_outcomes` (real
  proofs) (+ 28 unit, 11 existing integration).
- gui-core: `parallel_historical_replay` (7 determinism/isolation/duplicate/
  concurrency/policy tests over the worker×batch×terminal matrix),
  `slice4b_instrumentation` (exact counts), plus `historical_replay` unit tests
  (batch ranges, order preservation, worker bounds).

## 30. Test results

| suite | result |
|---|---|
| crypto (lib) | 54 passed |
| verifier (lib + real_triptych_ballot) | 28 + 12 passed |
| gui-core lib unit | 116 passed |
| parallel_historical_replay | 7 passed |
| slice4b_instrumentation | 1 passed |
| reconstruction_instrumentation | 5 passed |
| verified_session_cache | 6 passed |
| durable_append_fast_path | 14 passed |
| workspace | 38 passed |
| intake | 13 passed |
| security | 7 passed |
| participation | 18 passed |
| election_status | 11 passed |
| private_intake_inbox | 16 passed |
| serialization | 3 passed |
| tally | 10 passed |
| voter_cast_lock | 22 passed |

**0 failures.** `cargo check -p tari-cc-private-ballot-gui-core` and
`cargo check --manifest-path gui/src-tauri/Cargo.toml` both pass.

## 31. Existing unrelated blocker

`crates/gui-core/tests/archive_writer.rs:910` — pre-existing `E0308` `&str`/
`String` mismatch from the live-anchor migration branch. It blocks building that
one test target (and thus a single `cargo test -p gui-core` that builds all
targets at once), so the required suites were run per-target. **Not fixed** (out
of scope, per prompt). All other targets compile and pass.

## 32. Remaining performance issues

The ~12.31 GiB projected retained full-snapshot workspace and ~24.61 GiB
projected logical writes at N=4096 remain (durable on-disk format), deferred by
design. Slice 4B does not change durable storage.

## 33. Slice 4C recommendation

Integration/concurrency torture (many-core hosts, many concurrent distinct
elections saturating the global budget; cancellation mid-reconstruction) and a
**release** re-measurement to set an actual cold-open target, plus a decision on
the format-level retained-storage cost.

## 34. Maximum-scale hardening recommendation

For the 4096/4096 maximum: (a) release-build re-measurement before any cold-open
promise; (b) consider a persisted, integrity-bound verified-ballot cache so a
one-time cold replay need not recur across restarts (careful trust design — the
current cache is deliberately memory-only); (c) re-check `W = cores − 1` GUI
responsiveness if a future build enables heavy AVX2; (d) address the retained
full-snapshot storage cost (Slice 4C/5).

---

## Production files changed

- `crates/crypto/src/verification.rs` — `ProofBatchInputV1` + `verify_batch_v1`
  trait method (default = individual loop).
- `crates/crypto/src/triptych_prototype.rs` — reusable election context builder
  + finisher; `build_triptych_statement_v1` = build + finish.
- `crates/crypto/src/triptych_verifier.rs` — `verify_batch_v1` override (batch +
  full-blame fallback + context reuse).
- `crates/crypto/src/instrumentation.rs` — batch counters + snapshot.
- `crates/crypto/src/lib.rs` — exports.
- `crates/verifier/src/proof_verification.rs` — `reconstruct_verification_statement`
  / `bind_verified_statement` helpers.
- `crates/verifier/src/approval_ingestion.rs` — `PreparedApprovalBallotV1`,
  `prepare_approval_ballot_package_v1`, `verify_approval_ballot_packages_batch_v1`;
  `ingest` refactored to prepare + verify + bind + accept.
- `crates/verifier/src/lib.rs` — exports.
- `crates/gui-core/src/historical_replay.rs` — **new**: config, global CPU
  budget, bounded scoped-thread executor, `parallel_verify_packages`.
- `crates/gui-core/src/session.rs` — `from_durable_snapshot_parallel` + ordered
  apply + terminal-lifecycle helper.
- `crates/gui-core/src/instrumentation.rs` — parallel counters + crypto batch
  passthrough.
- `crates/gui-core/src/lib.rs` — exports.
- `crates/gui-core/src/workspace.rs` — reconstruct closure uses the parallel path.
- `crates/gui-core/src/verified_session_cache.rs` — incidental, behavior-preserving
  lint fix on the reconstruction wait path (a pre-existing Slice 2 `expect` on an
  always-`Some` value → fail-closed `match`), so the changed crates are
  clippy-clean (`expect_used`/`unwrap_used` are workspace `deny`s). No behavior
  change. All other changed crates carry no new clippy findings.

Vendored Triptych: **not changed**. curve25519: **not changed**. Durable format:
**not changed**. Protocol semantics: **not changed**.
