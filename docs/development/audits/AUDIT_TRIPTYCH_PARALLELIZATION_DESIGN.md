# Slice 4B design — bounded multicore historical verification (DESIGN ONLY)

**This is design only. Nothing here is implemented in this run.** No third-party Triptych/curve25519 code or API, no proof/nullifier semantics, and no protocol format may be changed to realize it. All timings referenced are the **DEBUG** measurements from `AUDIT_TRIPTYCH_VERIFIER_PERFORMANCE.md`; a release re-measurement precedes any target.

## 1. Exact current verifier call path

Cold resume `from_durable_snapshot` replays each stored package sequentially through `TariTriptychPrototypeVerifierV1::verify`, which — per ballot — rebuilds the election-constant statement (`build_triptych_statement_v1`: scope generator, `TriptychParameters`, N registry-key decompressions, `TriptychInputSet`) and then runs `proof.verify` (one ring-sized multiscalar multiplication). See `AUDIT_TRIPTYCH_VERIFIER_PERFORMANCE.md` §1.

## 2. Election-constant work

Scope generator, parameters, N key decompressions, input set. Depends only on `(protocol_version, suite_id, election_scope, registry_keys)`. Measured at **~4–6%** of per-ballot cost; ~85% of that is key decompression. Currently rebuilt every ballot.

## 3. Ballot-specific work

Linking-tag decode, envelope/proof parse, transcript, and `proof.verify` MSM (the ~94% dominant term).

## 4. Registry-size scaling

`proof.verify` and the reusable context both scale ~`O(N)`; proof bytes `O(log N)`. 500→4096 members raises verify ~5.9× (roughly linear over a fixed-cost floor).

## 5. Reusable context feasibility

Safe. An immutable `(TriptychParameters, TriptychInputSet, decompressed_keys, scope_generator)` is a pure function of the frozen election and is only read during verify. Build once per election, share `Arc`-wrapped read-only across workers. Realizing this needs a **project-side** reuse path (e.g. a verifier method that accepts a prebuilt statement/context) — the current public `verify` always rebuilds internally. No third-party API change is required to build the context (the vendored constructors are public); only the project verifier would gain a reuse entry point.

## 6. Pure-crypto independence

`proof.verify` is a pure function; historical verifications are independent (confirmed by the vendored batch API and the existing equivalence test). Safe to parallelize.

## 7. Ordered election semantics (must stay deterministic)

After validity is known, apply in canonical durable (package) order, sequentially: first-valid-nullifier acceptance (`BallotAcceptanceLedger`), transcript entries (intake order), accepted/rejected outcome, and tally. Duplicate-nullifier re-votes carry valid proofs; duplicate rejection is a ledger decision, not a proof failure.

## 8. Existing SIMD/threading behavior

No `rayon`/threads in the Triptych library; single-threaded verify and batch. `curve25519-dalek` serial `u64` backend unless AVX2 is enabled at build (intra-core SIMD only). Application multi-threading does not oversubscribe a hidden pool.

## 9. Oversubscription risk

Low (no internal pool). Bound the worker count so total threads ≤ CPUs and one logical CPU stays free for the GUI/event loop.

## 10. Memory scaling

Reusable input set `ring_capacity × ~160 B` = 655 KB at N=4096. Shared read-only ⇒ one copy total. Per-worker transient: proof (~1.5 KB), transcript, MSM scratch (a few KB). A batch of size `b` holds `b` proofs/transcripts (still tiny). Total ≈ `context(0.66 MB) + workers × batch × few-KB` — well within desktop memory at the 4096 maximum.

## 11. Bounded worker design

```
load durable state (Slice 3B: warm append; cold resume full-validates once)
  → build ONE immutable election verifier context (Arc, read-only)
  → split the ordered package list into fixed-size batches (batch size b)
  → bounded worker pool (W workers) pulls batches from a queue
       each worker: TriptychProof::verify_batch(context, batch)
         on batch failure: verify_batch_with_full_blame → per-index validity
       emit (package_index, valid: bool) results
  → collect all results
  → APPLY in canonical package order, sequentially:
       first-valid-nullifier ledger, transcript, accepted/rejected, tally
  → construct VerifiedElectionSessionV1 → enter the Slice 2 cache
```

Primary lever is **batching** (measured ~2.4–4× single-threaded, improving with N); **multicore** multiplies throughput by ~`W`. Context reuse adds ~5%.

## 12. Single-flight interaction

Reuse the Slice 2 verified-session cache single-flight: exactly one reconstruction per `(workspace_id, head_revision, head_digest, verifier_epoch)` runs; concurrent resumers wait. The parallel verifier runs *inside* that single owner's reconstruction, bounded by the existing reconstruction permit so two elections cannot both saturate all cores.

## 13. Slice 2 cache interaction

Unchanged key. A successful parallel reconstruction yields the same `VerifiedElectionSessionV1` and enters the same cache. Parallelism must not change acceptance/tally results — enforced by applying ordered semantics sequentially after validity (§7). If parallel verification changes the *verifier* derivation in any observable way, bump `VERIFIED_SESSION_CACHE_EPOCH_V1`; a pure speed change that yields identical sessions needs no bump.

## 14. Slice 3B storage interaction

Slice 3B removed durable reads as the cold-open bottleneck; the remaining cost is this verification. The fast-append validated-head identity and the Slice 2 cache key are the same head identity the parallel verifier keys on. No storage-format change is needed for Slice 4B; the durable package list already provides the canonical order that the ordered-apply phase requires.

## 15. Deterministic ordering model

Verification order is irrelevant to results; **application** order is the durable package order. Workers return `(index, valid)`; the collector sorts/*indexes* by package order and applies ledger/transcript/tally sequentially, so the accepted set, first-valid outcomes, transcript, and tally are byte-identical to today's sequential replay regardless of `W` or batch size.

## 16. Failure handling

- **Invalid proof in a batch:** `verify_batch` fails ⇒ `verify_batch_with_full_blame` returns exact invalid indices (existing test `assert_full_batch_blame_indexes`); those ballots are marked rejected at their index. Rare in practice (duplicates carry valid proofs).
- **Worker panic:** convert to a bounded error like the Slice 2 `catch_unwind`; fail the whole reconstruction closed (never enter the cache with a partial result).
- **Cancellation:** if the resume is abandoned, drop the worker pool; no durable effect (verification is read-only).
- **Fail-closed:** any worker error ⇒ the reconstruction returns `Err`; no partial session is trusted.

## 17–22. Per-voter projections (PROJECTED_DEBUG; release re-measurement required)

Per-ballot µs by strategy (DEBUG), and a 4-core (3-worker) batched cold-open estimate. **DEBUG — illustrative structure only, not a target.**

| voters N | verify seq (µs) | batch(4)/proof (µs) | batch(4)×3 workers eff. (µs) | cold-open N ballots, batched×3 (s, DEBUG) |
|---:|---:|---:|---:|---:|
| 50 | 209,667 | 79,671 | ~26,557 | ~1.3 |
| 100 | 338,618 | 127,279 | ~42,426 | ~4.2 |
| 500 | 1,008,834 | 426,853 | ~142,284 | ~71 |
| 1,000 | 1,755,170 | 482,317 | ~160,772 | ~161 |
| 2,048 | 3,413,879 | 850,275 | ~283,425 | ~581 |
| 4,096 | 5,950,870 | 1,537,722 | ~512,574 | ~2,100 |

Release optimization is expected to reduce all absolute figures by roughly one order of magnitude or more; the *ratios* (batch ~4×, workers ~3×) should persist.

## 23. Recommended Slice 4B implementation

1. Add a **project-side reusable verifier context** (build the immutable `(params, input_set, decompressed_keys, scope_generator)` once per election; expose a verify entry point that accepts it). No third-party change.
2. Route cold-resume verification through **`verify_batch`** over homogeneous batches (with `verify_batch_with_full_blame` on failure). This is the biggest, lowest-risk lever — the vendored API is already proven equivalent to individual verification by an existing project test.
3. Wrap it in a **bounded worker pool** `W = min(proof_count, max(1, available_parallelism − 1), memory_bound)` (this machine: 3), pulling batches from a queue, inside the Slice 2 single-flight reconstruction.
4. **Collector applies ledger/transcript/tally sequentially in canonical package order.**
5. Keep everything fail-closed and memory-only (no durable trust from parallelism); bump the cache epoch only if the verified session derivation changes observably.

## 24. Required tests (for Slice 4B, when implemented)

- Parallel reconstruction yields byte-identical accepted set, transcript, tally, and finalization as sequential replay, for varied `W` and batch sizes.
- An invalid proof anywhere in a batch is rejected at its exact index (full-blame), others accepted.
- Duplicate-nullifier ballots: valid proof, ledger rejects the later one, deterministically, regardless of verification order.
- Worker panic / batch error fails the whole reconstruction closed; nothing enters the Slice 2 cache.
- Bounded worker count never exceeds the policy; one CPU stays free (no GUI stall).
- Single-flight: concurrent resumers of the same head cause exactly one parallel reconstruction.
- New-ballot live intake still performs exactly one verification (unchanged).
- Operation-count and (release) wall-clock benchmarks confirm the batch/multicore speedup.

## 25. Risks

- **Debug-vs-release:** targets must be set from a release measurement, not the debug figures here.
- **Batch failure blame cost:** pathological all-invalid batches cost extra log-many re-verifications; mitigated because valid proofs dominate (duplicates are ledger-level).
- **Reusable-context entry point:** requires a careful project-side API so a prebuilt context cannot be paired with a mismatched registry commitment (bind the context to the registry commitment, mirroring today's `verify` commitment check).
- **Determinism:** the ordered-apply phase is the single source of result determinism; it must never be parallelized.
- **Cache-epoch discipline:** any observable change in verified-session derivation must bump `VERIFIED_SESSION_CACHE_EPOCH_V1`.
- **Oversubscription with AVX2:** if a future build enables AVX2 and heavy SIMD, re-check that `W = cores − 1` still leaves the GUI responsive.
