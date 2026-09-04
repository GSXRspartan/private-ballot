# Slice 4A — Triptych verifier performance audit

**Scope:** AUDIT / PROFILING / DESIGN ONLY. No production source was modified. No third-party (`third_party/tari-triptych`, `curve25519-dalek`) code or API was modified. No Triptych proof semantics, nullifier semantics, or protocol format was changed. Benchmarks were disposable scratch tests, since removed after archiving their results here.

**Evidence labels:** **CONFIRMED** = current source inspected; **MEASURED_DEBUG** = wall-clock from the scratch benchmark under an **unoptimized (debug) `cargo test`** build; **PROJECTED_DEBUG** = arithmetic over MEASURED_DEBUG values; **UNKNOWN** = not measured. **All absolute timings below are DEBUG and are NOT representative of a release build** — curve25519 field/scalar operations are typically 10–50× faster with optimizations. The audit's load-bearing signal is the **relative** structure (which work is constant vs per-ballot, how batching amortizes, how cost scales with ring size), not the absolute microseconds. A release re-measurement is required before committing to any cold-open time (§ "Performance target").

## 1. Exact verifier call path (CONFIRMED)

`GuiElectionSessionV1::from_durable_snapshot` (cold resume) replays every stored package: `session.open()` then, per package, `intake_ballot_package_bytes → process_intake_package → ingest_approval_ballot_package_v1`, which reconstructs the statement and calls `TariTriptychPrototypeVerifierV1::verify`. Sources: `crates/gui-core/src/session.rs:121-183`, `:299-311`; `crates/verifier/src/approval_ingestion.rs`; `crates/verifier/src/proof_statement.rs:12`.

`verify` (`crates/crypto/src/triptych_verifier.rs:82-124`) does, **on every call**:

1. `record_verify_invocation()` (counter).
2. suite-id and `registry_commitment` equality checks (constant, cheap).
3. `TariTriptychProofEnvelopeV1::from_bytes(proof_bytes)` — envelope parse (per-ballot, cheap).
4. **`build_triptych_statement_v1(protocol_version, suite_id, election_scope, &self.registry_keys, linking_tag)`** — the election-constant reconstruction, rebuilt every ballot: `crates/crypto/src/triptych_prototype.rs:29-60`:
   - `derive_scope_generator_v1` — one BLAKE3 XOF + one `RistrettoPoint::from_uniform_bytes` (hash-to-curve). Election-constant.
   - `TriptychParameters::new_with_generators(base=2, exponent=⌈log2 N⌉, G, scope_generator)` — commitment generators. Election-constant.
   - **`parse_sorted_registry_keys_v1`** — **decompresses all N registry keys** (`CompressedRistretto::decompress` + a recompression round-trip check, `decode_non_identity_v4`). `O(N)` point operations — the dominant election-constant term. Election-constant.
   - `TriptychInputSet::new_with_padding(keys, params)` — pads the ring to `2^exponent` and builds the input set. Election-constant.
   - `decode_non_identity_v4(linking_tag)` — **per-ballot** (the nullifier).
   - `TriptychStatement::new(params, input_set, linking_tag)` — combines the constant params/input-set with the per-ballot linking tag (cheap).
5. `parse_canonical_triptych_proof_v1` — proof parse + canonical round-trip (per-ballot).
6. `triptych_transcript_v1(statement)` — merlin transcript over statement bytes (per-ballot, cheap).
7. **`proof.verify(&triptych_statement, &mut transcript)`** — the actual Triptych verification: one large fixed-base multiscalar multiplication over the ring (per-ballot, dominant cost). `third_party/tari-triptych/src/proof.rs`.
8. `VerifiedNullifier::new(linking_tag)` and return.

## 2–3. Election-constant vs ballot-specific work (CONFIRMED + MEASURED_DEBUG)

- **Election-constant (identical for every ballot in one election):** scope generator, `TriptychParameters`, the N registry-key decompressions, and the `TriptychInputSet`. These depend only on `(protocol_version, suite_id, election_scope, registry_keys)`. **The current API rebuilds all of it on every verify.**
- **Ballot-specific:** the linking-tag decode, envelope/proof parse, transcript, and `proof.verify` MSM.
- **Registry-specific:** the ring size `N` sets the input-set size and the MSM length.

## 4. Reusable immutable context (MEASURED_DEBUG)

An immutable `(TriptychParameters, TriptychInputSet)` (plus the decompressed key vector and scope generator) can safely be built once per election and shared read-only across all ballots — nothing in it depends on the ballot. Measured cost of building this context vs one `proof.verify`:

| registry N | ring cap | context build (µs) | of which key-decompress (µs) | proof.verify (µs) | context as % of per-ballot |
|---:|---:|---:|---:|---:|---:|
| 50 | 64 | 8,622 | 3,601 | 209,667 | 3.95% |
| 100 | 128 | 12,952 | 7,706 | 338,618 | 3.68% |
| 500 | 512 | 50,280 | 39,035 | 1,008,834 | 4.75% |
| 1,000 | 1,024 | 98,035 | 75,728 | 1,755,170 | 5.29% |
| 2,048 | 2,048 | 191,858 | 235,195 | 3,413,879 | 5.32% |
| 4,096 | 4,096 | 379,266 | 324,099 | 5,950,870 | 5.99% |

**Finding — the prior "≈44% election-constant" hypothesis is NOT reproduced.** In this measurement the reusable context is only **~4–6%** of per-ballot cost; the `proof.verify` MSM dominates. Reusing the context is a real but **small** (~5%) saving. (The ~44% figure may have come from a release build where the MSM is much faster relative to decompression, or from a different accounting; a release re-measurement should re-check this fraction, but the ordering — verify ≫ context — is unlikely to invert since both are curve-op bound.) Registry-key decompression is ~85% of the context cost at 4096, matching the source.

## 5. Pure-crypto independence (CONFIRMED)

`proof.verify(statement, transcript)` is a pure function of `(proof, statement, transcript)` with no shared mutable state and no nullifier/ledger logic (those live in the app/ledger layer). Historical proof verifications are therefore **independent** and safe to run concurrently. This is confirmed by the vendored batch API and the existing test `vendor_batch_verification_matches_individual_verification_for_project_statements` (`crates/crypto/src/triptych_verifier.rs:497`), which proves batch validity equals per-proof validity for project statements.

## 6. Election semantics that MUST remain ordered (CONFIRMED)

Cryptographic proof validity is order-independent, but these are applied **after** validity, deterministically, in canonical durable order and must stay sequential: first-valid-nullifier acceptance (`BallotAcceptanceLedger`), accepted/rejected decision and its transcript entry (`VerificationTranscriptV1`, intake order), and the tally over the accepted set. A duplicate-nullifier re-vote carries a **valid** proof (same linking tag) — duplicate rejection is a *ledger* decision, not a proof failure — so proof-invalid ballots are rare in practice and batching is efficient.

## 7. Internal SIMD/threading/batch behavior (CONFIRMED)

- **Threads/Rayon:** `third_party/tari-triptych/Cargo.toml` has **no** `rayon` or threading dependency. Verification (single and batch) is single-threaded.
- **Batch verification:** the vendored `TriptychProof::verify_batch` / `verify_batch_with_single_blame` / `..._full_blame` (`third_party/tari-triptych/src/parallel/proof.rs`, and the top-level proof) perform one shared multiscalar multiplication across proofs — amortization, **not** multi-threading. Requires homogeneous parameters (a cross-registry batch returns `InvalidParameter`, tested at `triptych_verifier.rs:564`); all ballots in one election share the ring, so they qualify.
- **SIMD:** `curve25519-dalek` is built `default-features = false`. On x86_64 without `-C target-feature=+avx2`, it uses the serial `u64` backend (no SIMD); with AVX2 enabled it vectorizes field ops **within one thread**. Either way, application-level multi-threading does not oversubscribe an internal thread pool (there is none).

## 8. Oversubscription risk (CONFIRMED)

Low. Because the library uses no internal thread pool, a bounded application worker pool that runs `verify` (or `verify_batch`) on independent proofs will not contend with hidden crypto threads. SIMD (if enabled) is intra-core and composes with multi-threading.

## 9. Memory per concurrent verification (MEASURED_DEBUG/DERIVED)

The reusable ring input set is `ring_capacity × ~160 bytes` (a `RistrettoPoint` ≈ 4 field elements): 10 KB (N=50) to **655 KB (N=4096)**. If the immutable context is **shared read-only** across workers, only one copy exists regardless of worker count; each worker then needs only its proof (~1.5 KB at N=4096: `8 + 32·(7+3m)`), transcript, and MSM scratch (a few KB). If instead each worker rebuilds its own context (today's per-verify behavior), memory is `W × ~0.66 MB` at 4096 — still modest for small `W`.

## 10. Recommended bounded worker policy (DERIVED)

`workers = min(proof_count, max(1, available_parallelism − 1), memory_bound)`. This machine reports `available_parallelism = 4`, so **3 workers** (leaving one logical CPU for the GUI/event loop). The Slice 2 reconstruction-permit pattern already computes a similar `clamp(available-1, 1, 2)` bound and is a good template. Prefer **batched work items** (each worker verifies a batch, not a single proof) so batch amortization and multicore multiply. Never spawn one thread per ballot.

## Batch amortization (MEASURED_DEBUG) — the largest single-threaded lever

`verify_batch` of 4 identical-ring proofs vs 4 sequential `verify`s (per-proof µs):

| registry N | sequential verify (µs) | batch-of-4 per proof (µs) | amortization |
|---:|---:|---:|---:|
| 50 | 209,667 | 79,671 | 2.63× |
| 100 | 338,618 | 127,279 | 2.66× |
| 500 | 1,008,834 | 426,853 | 2.36× |
| 1,000 | 1,755,170 | 482,317 | 3.64× |
| 2,048 | 3,413,879 | 850,275 | 4.01× |
| 4,096 | 5,950,870 | 1,537,722 | 3.87× |

Batching alone (single-threaded, batch size 4) already gives ~2.4–4× throughput and improves with ring size. Larger batches amortize the shared fixed-base MSM further, bounded by the per-proof unique work. This dwarfs the ~5% context-reuse saving and composes with multicore. **Batch verification — already vendored and already proven equivalent to individual verification by an existing project test — is the primary recommended optimization; bounded multicore is the throughput multiplier on top.**

## Scaling with ring size (MEASURED_DEBUG)

`proof.verify` grows roughly linearly with `N` above a fixed-cost floor: 500→4,096 (8.2× members) raises verify ~5.9×. The reusable-context and MSM both scale ~`O(N)`; proof size scales `O(log N)`.

## Combined-lever projection for a 4,096-ballot cold open (PROJECTED_DEBUG — illustrative only)

| strategy | per-proof (µs) | 4,096 ballots | vs naive |
|---|---:|---:|---:|
| naive (rebuild context every verify) | 6,330,136 | ~25,938 s | 1× |
| reuse context, sequential | 5,950,870 | ~24,383 s | 1.06× |
| reuse context + batch(4), single core | 1,537,722 | ~6,299 s | 4.1× |
| reuse context + batch(4) × 3 workers | ~512,574 eff. | ~2,100 s | 12.3× |

**These are DEBUG seconds and are not a target.** They exist only to show the *relative* impact of the three composed levers (context reuse ~1.06×, batching ~3.9×, multicore ~3×) ≈ **~12× combined**, plus whatever release optimization contributes (likely another order of magnitude). A release build must be measured before any cold-open promise.

## Deliverables

- This report and `AUDIT_TRIPTYCH_VERIFIER_PERFORMANCE.csv` (per-size measured rows + projected election rows).
- `AUDIT_TRIPTYCH_PARALLELIZATION_DESIGN.md` (the Slice 4B design — audit/design only; no implementation in this run).

## Method and reproducibility

The disposable scratch benchmark `crates/crypto/tests/triptych_verifier_profile_scratch.rs` (removed after archiving these results) used the vendored `triptych` crate directly to replicate the project's exact ring configuration (base 2, minimum exponent 2, election-scoped generator) and timed context construction and `proof.verify` separately, plus `verify_batch` of 4, over registry sizes 50/100/500/1000/2048/4096 (7 reps, median). It generated one real proof per size and touched no application data. Run under `cargo +stable-x86_64-pc-windows-msvc test -p tari-cc-private-ballot-crypto` (debug). To obtain release figures, re-run an equivalent scratch bench under `--release`.
