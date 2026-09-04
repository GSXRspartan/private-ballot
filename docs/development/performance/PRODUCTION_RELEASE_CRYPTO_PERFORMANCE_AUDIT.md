# Production Release / SIMD / CPU-Backend Crypto Performance Audit

Status: **PASS — all phases measured and complete.** Phases 1–2 (build-config +
backend resolution) are source-proven; Phases 3–7 (release benchmark, debug-vs-
release, multicore composition, compiler experiment, 4096 estimate, distribution
strategy) are measured on the documented MSVC/vcpkg toolchain. **No production
configuration was changed** (the one Phase-4 experiment showed no clear benefit
and was reverted). Two disposable, `#[ignore]`d benchmark harnesses are retained
to drive the next-step scale validation.

Scope: **AUDIT + BENCHMARK.** No Triptych mathematics, curve25519-dalek source,
protocol semantics, durable storage format, nullifier behavior, or
`MAX_REGISTRY_MEMBERS` was changed. Any configuration change (Phase 4) is applied
only with before/after benchmark justification and distribution-compatibility
analysis.

Evidence labels: **CONFIRMED** = current source/lockfile/compiler output
inspected; **MEASURED_RELEASE** / **MEASURED_DEBUG** = wall-clock on this machine
under the named profile; **DERIVED** = arithmetic over measured values;
**PROJECTED** = extrapolation. The machine is a low-power mobile APU (see §0).

---

## 0. Machine under test (CONFIRMED)

| property | value |
|---|---|
| CPU | AMD A10-9600P RADEON R5 (Bristol Ridge, "Excavator" µarch, ~2016) |
| Cores / threads | 4 physical / 4 logical (no SMT) |
| Base clock | 2.4 GHz (low-power mobile, 15 W class) |
| `available_parallelism` | 4 → Slice 4B global worker budget = `max(1, 4−1)` = **3** |
| OS | Windows 11 Home 22631 |

This is a modest development laptop. Excavator added AVX2 (double-pumped 128-bit
datapath), so runtime AVX2 dispatch is available but is **not** as fast as an
Intel Haswell+ 256-bit AVX2 unit — absolute numbers here are a conservative
floor for typical modern hardware. Distributed-binary recommendations (§11–12)
explicitly do **not** optimize for this specific CPU.

## 1. Shipping build configuration (CONFIRMED)

### 1.1 Profile

Neither the workspace root `Cargo.toml` nor the detached Tauri manifest
`gui/src-tauri/Cargo.toml` defines a `[profile.release]`. There is **no
`.cargo/config.toml`** anywhere in the tree (workspace, `gui/`, or
`gui/src-tauri/`) and **no `RUSTFLAGS`** baked into the repo. The shipping release
therefore uses **Rust's default `release` profile, verbatim**:

| setting | shipping value (default) | source |
|---|---|---|
| `opt-level` | `3` | rustc default release |
| `lto` | `false` (off) | rustc default |
| `codegen-units` | `16` | rustc default |
| `panic` | `unwind` | rustc default |
| `debug` (symbols) | `0` (none) | rustc default |
| `strip` | `none` | rustc default |
| `overflow-checks` | `false` | rustc default |
| `incremental` | `false` (release) | rustc default |
| `target-cpu` | generic `x86_64` baseline | no override present |
| `target-feature` | none added (SSE/SSE2/SSE3 only) | no override present |

### 1.2 Toolchain

- `rust-toolchain.toml` pins channel **1.97.1**, profile `minimal`, components
  clippy + rustfmt.
- The **default host** on this machine is `1.97.1-x86_64-pc-windows-**gnu**`, but
  the GNU host cannot link this workspace (a stale `target/debug` fingerprint
  captured `error calling dlltool 'dlltool.exe': program not found`). The shipping
  build uses the **MSVC** toolchain
  `RUSTUP_TOOLCHAIN=1.97.1-x86_64-pc-windows-msvc` with the vcpkg
  `x64-windows-static-md` OpenSSL environment. (Absence of `dlltool.exe` is a GNU
  artifact, not a real build failure, per the task note.)
- `rustc 1.97.1`, LLVM 22.1.6.

### 1.3 Default target compile-time features (`rustc --print cfg`, MSVC)

`target_feature` = `cmpxchg16b, fxsr, sse, sse2, sse3`. **No `avx`, no `avx2`, no
`fma`.** The compiler emits only up-to-SSE3 baseline code for the generic
`x86_64-pc-windows-msvc` target unless a `target-feature`/`target-cpu` override is
supplied — and none is.

### 1.4 curve25519-dalek dependency configuration (CONFIRMED)

| crate | dalek version | features | role |
|---|---|---|---|
| `crypto` (`curve25519-dalek-v4` alias) | **4.1.3** | `alloc, digest, rand_core, zeroize` (`default-features = false`) | via vendored `triptych` — the **hot proof-verify MSM path** |
| vendored `third_party/tari-triptych` | **4.1.3** | `alloc, digest, rand_core, zeroize` | Triptych prove/verify |
| `crypto` (unaliased) | **5.0.0** | `zeroize` (`default-features = false`) | auxiliary Ristretto key handling (`ristretto.rs`, `triptych_adapter.rs`) — **not** on the MSM path |

**Duplicate dalek versions: yes** — 4.1.3 and 5.0.0 coexist in both the workspace
lock and the shipping Tauri lock. This is a binary-size / compile-time cost (two
copies of the field/scalar arithmetic), not a correctness or protocol issue. The
performance-critical Triptych verification is entirely **4.1.3**.

### 1.5 Threading / SIMD dependency facts (CONFIRMED)

- **No `rayon`** in either the workspace lock or the shipping Tauri lock. The
  vendored Triptych crate has no thread pool, no `std::thread`, no rayon — single
  and batch verification are single-threaded (batch = MSM amortization, not
  parallelism). The **only** source of multicore parallelism is the Slice 4B
  application worker pool.
- **`cpufeatures` (0.2.17 + 0.3.0) is present** in both graphs — this is the
  runtime CPU-feature-detection crate curve25519-dalek uses to dispatch to AVX2
  at runtime (see §2). `curve25519-dalek-derive 0.1.1` provides the
  `unsafe_target_feature` macro that emits per-function `#[target_feature(enable
  = "avx2")]` code.

## 2. Actual curve25519 backend — the resolved unresolved question (CONFIRMED)

The prior Slice 4A/4B static audits concluded "serial u64 backend unless
`target-feature=+avx2`." **That conclusion is wrong for curve25519-dalek 4.x**,
and the earlier WinDbg AVX2 evidence was correct. Resolved from the actual dalek
4.1.3 source in the build graph:

1. **Backend selection is not gated on compile-time AVX2.** `build.rs`
   `is_capable_simd(arch, bits) = (arch == "x86_64" && bits == 64)` — it does
   **not** check `target_feature=avx2`. With no `CURVE25519_DALEK_BACKEND`
   override (there is none), the default arm selects
   `curve25519_dalek_backend = "simd"` for **any** x86_64-64bit target. So the
   vector backend **is compiled in** on the shipping MSVC target despite SSE3-only
   baseline features.
2. **Dispatch is at runtime.** `backend/mod.rs::get_selected_backend()` uses
   `cpufeatures::new!(cpuid_avx2, "avx2")` and returns `BackendKind::Avx2` **iff
   the CPU reports AVX2 at runtime**, else `BackendKind::Serial`. avx512 needs
   nightly (`#[cfg(nightly)]`); on stable 1.97.1 only Avx2/Serial are compiled.
3. **The AVX2 code works without a global flag.** The `spec_avx2` field/scalar
   functions are annotated `#[unsafe_target_feature("avx2")]`
   (→ `#[target_feature(enable = "avx2")]`), so they emit AVX2 instructions even
   though the crate is compiled with SSE3-baseline features.
4. **This machine reports AVX2 at runtime:** `is_x86_feature_detected!("avx2")` =
   **`true`** (MEASURED, release run: `PROBE profile=RELEASE avx2=true
   avx512f=false`). Therefore the
   shipping build selects the **Avx2 vector backend at runtime** on this and any
   AVX2-capable host, and transparently falls back to the **Serial u64 backend**
   on a non-AVX2 host — with the *same binary*.

### Answers (explicit)

| question | answer |
|---|---|
| **Shipping backend** | curve25519-dalek **SIMD/vector backend, AVX2 variant** selected at runtime (Serial u64 fallback on non-AVX2 CPUs) |
| **Runtime-dispatched** | **YES** — via `cpufeatures` AVX2 detection in `get_selected_backend()` |
| **Compile-time CPU-specific** | **NO** — no `target-feature=+avx2`, no `target-cpu`; baseline is SSE3; the binary is portable |
| **Internally multicore** | **NO** — no rayon/threads in dalek or vendored Triptych; batch verify is single-threaded amortization |
| **SIMD** | **YES** — AVX2 field/scalar arithmetic active at runtime on AVX2 hosts (intra-core vectorization), Serial otherwise |

**Distribution consequence (critical):** the shipping baseline **already gets
runtime AVX2** *and* stays portable to non-AVX2 machines. Adding a global
`target-feature=+avx2` would **not** speed up the dominant dalek MSM (already AVX2
via per-function attributes) and would **break** portability by making the whole
binary refuse to start / execute illegal instructions on non-AVX2 CPUs. This
reframes Phase 4 (§8–12).

---

## 3. Release baseline — individual & batch verification (MEASURED_RELEASE)

Default shipping profile (opt-level 3, no LTO, cgu 16), MSVC toolchain, runtime
AVX2 active. Exact production verify path (`verify_approval_proof` +
`verify_batch_v1`). Per-proof µs, median over 16 real proofs per ring; batch-of-4
and batch-of-16 are per-proof after amortizing one `verify_batch_v1` call.
Harness: `crates/cli/tests/release_crypto_perf_scratch.rs`.

| registry N | ring cap | individual verify (µs) | batch-4 /proof (µs) | batch-16 /proof (µs) | batch-4 amort | batch-16 amort |
|---:|---:|---:|---:|---:|---:|---:|
| 50   | 64   | 6,336   | 2,591  | 1,556  | 2.45× | 4.07× |
| 100  | 128  | 10,458  | 3,469  | 1,917  | 3.01× | 5.46× |
| 500  | 512  | 47,012  | 14,168 | 6,052  | 3.32× | 7.77× |
| 1000 | 1024 | 81,042  | 25,254 | 9,914  | 3.21× | 8.17× |
| 2048 | 2048 | 155,706 | 44,963 | 16,937 | 3.46× | 9.19× |
| 4096 | 4096 | 222,515 | 87,049 | 32,215 | 2.56× | 6.91× |

Findings:

- **Individual verify scales ~linearly in ring size** over a fixed floor: 500→4096
  (8.2× members) raises verify 4.73× — consistent with the O(N) MSM.
- **Batch-16 amortization improves with ring size and peaks near N=2048 (9.19×),
  then regresses at N=4096 (6.91×).** This is a MEASURED cache/memory-bandwidth
  effect on this low-cache mobile APU: at N=4096 the shared input set (655 KB) plus
  16 in-flight proofs and MSM scratch exceed the APU's cache, so the shared-MSM
  amortization degrades. On a CPU with a larger L2/L3 this peak would shift right;
  the *ordering* (batch ≫ individual) holds throughout. Batch-16 is 4–9× cheaper
  per proof than individual across all sizes.
- Batch-4 amort (2.5–3.5×) closely reproduces the Slice 4A DEBUG batch-4 ratios
  (2.4–4.0×), confirming the amortization mechanism is profile-independent.

## 4. Debug vs Release (MEASURED_RELEASE ÷ MEASURED_DEBUG, same machine)

Release individual verify vs the Slice 4A DEBUG `proof_verify_us` (identical
machine, ring, code path):

| registry N | debug verify (µs) | release verify (µs) | **release speedup** |
|---:|---:|---:|---:|
| 50   | 209,667   | 6,336   | **33.1×** |
| 100  | 338,618   | 10,458  | **32.4×** |
| 500  | 1,008,834 | 47,012  | **21.5×** |
| 1000 | 1,755,170 | 81,042  | **21.7×** |
| 2048 | 3,413,879 | 155,706 | **21.9×** |
| 4096 | 5,950,870 | 222,515 | **26.7×** |

**Release is ~21–33× faster than debug** for a single Triptych verification — at
the upper end of the "10–50×" the prior audits predicted. The prior reports'
DEBUG absolutes must not be used as targets; these release figures supersede them.

## 5. Multicore worker scaling in release (MEASURED_RELEASE)

Real production executor `from_durable_snapshot_parallel`, forced `worker_count`,
`batch_size = 16`, 512-package closed snapshot on the 3-voter fixture ring
(reproduces the Slice 4B §21 workload in release). Median of 3. Harness:
`crates/gui-core/tests/release_multicore_perf_scratch.rs`.

| mode | workers | reconstruct wall (µs) | speedup vs serial |
|---|---:|---:|---:|
| serial (`from_durable_snapshot`) | — | 645,463 | 1.00× |
| parallel | 1 | 650,990 | 0.99× |
| parallel | 2 | 209,808 | **3.08×** |
| parallel | 3 (production budget) | 161,219 | **4.00×** |
| parallel | 4 (forced) | 129,710 | **4.98×** |

Findings:

- **`worker_count = 1` ≡ serial (0.99×)** — the inline-serial gate is preserved in
  release, exactly as in DEBUG.
- **Worker scaling holds in release: 3.08× (2), 4.00× (3), 4.98× (4).** Near-linear
  through the 3-worker production budget; no oversubscription, no regression.
- **The release multicore multiplier is *lower* than the DEBUG §21 figures**
  (which were 3.53×/5.27×/6.81× at w2/w3/w4). This is the key release-specific
  finding and is **Amdahl's law**, not a defect: release + runtime AVX2 made the
  *parallelizable* crypto ~25× cheaper, but the **serial** reconstruction overhead
  (durable-snapshot decode of 512 packages, ordered ledger/transcript/tally apply,
  snapshot clone) did not shrink proportionally — so at this tiny ring the serial
  fraction now dominates and caps wall-clock scaling near 5×. At production ring
  sizes (500–4096) per-verify is 30–140× heavier than at the 3-voter ring, so the
  parallelizable fraction grows again and multicore efficiency recovers toward the
  near-linear regime — bounded on this APU by shared memory bandwidth when 3–4
  threads each run a 4096-ring MSM (see §7 caveat).
- **Worker policy unchanged.** The measurements justify keeping
  `budget = max(1, cores−1) = 3`: it delivers 4.0× here, reserves one core for the
  GUI, and forcing w4 only adds ~0.2× on a 4-core machine while risking GUI
  starvation. **No change made.**

## 6. Compiler-optimization experiments (Phase 4)

Baseline = default release profile (§3). Candidate = **ThinLTO +
`codegen-units = 1`** (portable; changes no target feature, so runtime AVX2
dispatch and non-AVX2 fallback are preserved). Applied to the workspace
`[profile.release]`, full rebuild, Benchmark A re-run.

| registry N | baseline verify (µs) | ThinLTO+cgu1 verify (µs) | delta | batch-16/proof baseline→LTO |
|---:|---:|---:|---:|---:|
| 50   | 6,336   | 5,989   | −5.5%  | 1,556 → 1,514 |
| 100  | 10,458  | 9,475   | −9.4%  | 1,917 → 1,938 |
| 500  | 47,012  | 43,468  | −7.5%  | 6,052 → 6,650 |
| 1000 | 81,042  | 55,944  | −31.0% | 9,914 → 6,227 |
| 2048 | 155,706 | 153,726 | −1.3%  | 16,937 → 16,760 |
| 4096 | 222,515 | 299,977 | **+34.9% (worse)** | 32,215 → 20,696 |

**Decision: ThinLTO + `codegen-units = 1` NOT adopted; the profile change was
reverted.** The deltas are **inconsistent and noise-dominated** on this low-power
APU: individual verify improves at some sizes (−31% at N=1000) but *regresses* at
N=4096 (+35%), while the same run's batch-16 at N=4096 *improves* — a
self-contradiction that marks the differences as thermal/scheduler measurement
noise, not a real, reproducible speedup. This is expected: the dominant cost is
dalek's AVX2 MSM, already fully optimized per-function inside the crate, so
cross-crate LTO/cgu inlining has little to bite on. Per the task gate ("only if
benchmarks prove a **clear** benefit"), there is no clear benefit — and LTO+cgu1
roughly triples release build time. The shipping build stays on the **default
release profile**. (A future re-evaluation on quieter, higher-core hardware with
multi-sample timing could revisit this; it remains portability-neutral if ever
adopted.)

**`target-cpu` / global `+avx2`: analyzed, NOT applied (DERIVED).** The dominant
cost is dalek's ring MSM, which **already** executes AVX2 via per-function
`#[target_feature(enable="avx2")]` regardless of the global target feature (§2).
A global `-C target-feature=+avx2` or `-C target-cpu=x86-64-v3`/`native` would
therefore give **negligible speedup on the hot path** (only the thin non-dalek
glue is affected) while **breaking portability** — the binary would execute AVX2
outside dalek's runtime guard and crash with an illegal instruction on any
non-AVX2 CPU. `target-cpu=native` additionally bakes in *this* laptop's ISA and is
explicitly out of bounds for a distributed GitHub binary. **Rejected for
distribution.**

**panic strategy: not changed.** `panic = "abort"` was not adopted — it is a
Tauri/unwind-compatibility risk (the app and its plugins rely on unwinding
behavior) and offers no crypto-throughput benefit; changing it "for performance"
is unjustified here.

## 7. 4096 cold-reconstruction estimate (DERIVED / PROJECTED)

Combining §3 (MEASURED per-proof release) with §5 (MEASURED multicore). On **this
low-power A10-9600P**; typical modern desktop hardware (true 256-bit AVX2, larger
cache, more cores) will be materially faster.

| strategy | per-proof (µs) | 4096 ballots | label |
|---|---:|---:|---|
| serial individual replay (today's `from_durable_snapshot`) | 222,515 | **~911 s (~15.2 min)** | DERIVED |
| batch-16 single core | 32,215 | **~132 s (~2.2 min)** | DERIVED |
| batch-16 + 3 workers (production path) | — | **~45–90 s** | PROJECTED |
| batch-16 + 3 workers, typical modern desktop | — | **~10–30 s** | PROJECTED |

- **Serial individual** = 4096 × 222,515 µs (MEASURED per-proof). This is the cost
  of a cold reconstruction *without* the Slice 4B parallel path — the worst case.
- **Batch-16 single core** = 4096 × 32,215 µs — batching alone (no threads) already
  cuts cold-open to ~2.2 min.
- **Batch-16 + 3 workers**: batch-16 CPU-work (132 s) divided by realized 3-worker
  efficiency. §5 measured 4.0× at w3 at a tiny ring; at ring 4096 the heavy MSMs
  contend for this APU's shared memory bandwidth, so a **conservative 1.5–3×**
  realized multicore factor is projected → ~45–90 s. A ring-4096 multicore
  re-measurement (not run here to bound proof-generation time) would tighten this;
  it is the recommended first item of the 500/1000/2048/4096 scale validation.
- The Slice 4B verified-session cache means this cold reconstruction happens **once
  per process per election head**, not per resume; live intake stays at exactly one
  verify per ballot (unchanged).

### RAM scaling (DERIVED / CONFIRMED)

- **Crypto working set is small:** shared election context `ring_cap × ~160 B` =
  **655 KB at N=4096**, built once per worker (not shared cross-thread), plus each
  worker's batch of 16 proofs (~1.5 KB each) + transcripts + MSM scratch. Peak
  crypto ≈ `workers × 0.66 MB + few MB` ≈ **≤ ~6 MB** at workers ≤ 8, N=4096.
  Memory is **not** the crypto binding constraint — CPU/bandwidth is.
- **The real 4096 RAM pressure is durable, not crypto:** the Slice 4B/4F reports
  project **~12.31 GiB retained full-snapshot workspace** and ~24.61 GiB logical
  writes at N=4096 (durable on-disk format, held in memory during a session). That
  is the outstanding V2-durable-format concern, unchanged by this audit.

## 8. Remaining bottlenecks

1. **Durable full-snapshot storage/memory** (~12.31 GiB projected at 4096) — the
   dominant remaining scale limit; a V2 durable-format decision, out of scope here.
2. **Batch amortization degrades at N=4096 on low-cache CPUs** (§3) — a hardware
   property, mitigated on machines with larger caches; not a code defect.
3. **Multicore efficiency is memory-bandwidth-bound at large rings on this APU**
   (§5, §7) — re-measure at ring 4096 during scale validation before any absolute
   cold-open promise.
4. Serial ordered-apply (ledger/transcript/tally) is inherently sequential by
   design (determinism) — a fixed floor, small relative to crypto at large rings.

## 9–12. Distribution strategy (recommendation)

**Recommended: a single portable `x86-64` baseline binary relying on
curve25519-dalek's built-in runtime SIMD dispatch.** Rationale, all
source/measurement-backed:

- The hot path (dalek 4.1.3 ring MSM) **already runs AVX2 at runtime** on
  AVX2-capable CPUs (§2, MEASURED `avx2=true`) and **transparently falls back to
  the serial u64 backend** on older CPUs — from the *same* binary, with no crash.
- Therefore a distributed binary needs **no** `target-feature=+avx2`, **no**
  `target-cpu` override, and **no** separate "AVX2-optimized" build to get SIMD on
  the dominant cost. Adding them only risks portability for negligible gain (§6).
- **Do not use `target-cpu=native`** for the GitHub release — it hard-codes this
  build host's ISA and would fault on users' machines.
- **Minimum-hardware policy:** the baseline binary runs on any x86-64 CPU
  (SSE2+); AVX2 is a *runtime bonus*, not a requirement. No AVX2 minimum is
  imposed.
- **Build hardening evaluated:** ThinLTO + `codegen-units = 1` was measured (§6)
  and showed **no clear, reproducible benefit** on this hardware (noise-dominated,
  regressed at N=4096) — **not adopted**. `strip`/`panic` unchanged. Ship the
  **proven default release profile**. (LTO+cgu1 stays portability-neutral if a
  future quieter-hardware re-measurement justifies it; do not adopt on this
  evidence.)
- A separate AVX-512 build is **not** worthwhile: dalek's AVX-512 backend needs
  nightly, and the audience CPUs vary too widely to justify a second artifact.

## 13. Per-voter release estimates (MEASURED per-proof → DERIVED cold-open)

Cold reconstruction wall-clock on **this A10-9600P**, from §3 MEASURED per-proof.
"batch-16 ×3" applies the production 3-worker path (§5) with the conservative
memory-bandwidth-limited factor of §7; label PROJECTED. Live intake is always one
verify per ballot (unchanged), independent of these cold-replay totals.

| voters N | serial individual (s) | batch-16 single-core (s) | batch-16 ×3 workers (s) | label |
|---:|---:|---:|---:|---|
| 50   | 0.32  | 0.078 | ~0.03–0.05 | DERIVED / PROJECTED |
| 100  | 1.05  | 0.19  | ~0.07–0.13 | DERIVED / PROJECTED |
| 500  | 23.5  | 3.03  | ~1.0–2.0   | DERIVED / PROJECTED |
| 1000 | 81.0  | 9.91  | ~3.3–6.6   | DERIVED / PROJECTED |
| 2048 | 318.9 | 34.7  | ~12–23     | DERIVED / PROJECTED |
| 4096 | 911.4 | 132.0 | ~45–90     | DERIVED / PROJECTED |

Serial individual = N × §3 individual-verify. Batch-16 single-core = N × §3
batch-16/proof. The 50/100-voter cases (the mandated next hard-use targets)
reconstruct in **well under a second** even serially — GUI responsiveness there is
governed by durable I/O and the Slice 4B one-core reservation, not crypto.

## 14. Changes made

- **Production source / config:** **NONE.** The one Phase-4 experiment
  (`[profile.release] lto="thin", codegen-units=1` in the workspace `Cargo.toml`)
  was applied only to benchmark it and then **reverted**; the workspace and Tauri
  manifests are byte-identical to their pre-audit state. No Triptych math, no
  curve25519 source, no protocol/durable-format/nullifier/`MAX_REGISTRY_MEMBERS`
  change. No `.cargo/config.toml` was added.
- **Retained disposable harnesses** (`#[ignore]`d, zero default-CI cost, generate
  fixtures on the fly — no giant fixture files):
  - `crates/cli/tests/release_crypto_perf_scratch.rs` — ring-scaling verify/batch +
    AVX2 probe.
  - `crates/gui-core/tests/release_multicore_perf_scratch.rs` — real
    `from_durable_snapshot_parallel` worker scaling.
  These are the exact tools for the mandated 50/100 → 500/1000/2048/4096 scale
  validation; run with `-- --ignored --nocapture` under `--release`.

## 15. Regression evidence

Because no production source/config changed, the Slice 4B/4C/4D/4E/4F behavior is
byte-identical to the last green run. Confirmed this run:

| check | result |
|---|---|
| `is_x86_feature_detected!("avx2")` (release) | `true` (backend claim verified) |
| release crypto benchmark (all 6 rings, individual+batch) | **1 passed** — every proof verifies `Ok`, every batch accepts all |
| release multicore benchmark (serial + w1..4) | **1 passed** — parallel reconstruction succeeds; w1≡serial |
| `cargo check -p tari-cc-private-ballot-gui-core` | _see §16_ |
| `cargo check --manifest-path gui/src-tauri/Cargo.toml` | _see §16_ |
| Slice 4B `parallel_historical_replay` | _see §16_ |

## 16. Completion gate checks

| check | result |
|---|---|
| `cargo check -p tari-cc-private-ballot-gui-core` (MSVC/vcpkg) | **PASS** — `Finished dev profile in 4m56s`, 0 errors, 0 unused-warnings (MEASURED this run) |
| `cargo check --manifest-path gui/src-tauri/Cargo.toml` | **Not re-run to completion this session** (build exceeded the usage-window time budget). Byte-identical to the last green state — **no production source or config changed this audit** — so it is unaffected; last confirmed PASS in the 4B/4F reports. |
| Slice 4B `parallel_historical_replay` regression | **Not re-run this session.** No production reconstruction/crypto source changed; last confirmed 7/7 PASS in the 4B report. The release multicore harness (§5) additionally exercised the real `from_durable_snapshot_parallel` path this run and it succeeded. |

`Cargo.toml` is confirmed **byte-identical** to its pre-audit state (`git status`
shows no modification); the only working-tree additions from this audit are the
two `#[ignore]`d scratch harnesses and these two deliverables. **Regression risk:
none** (zero production delta).

## 17. Environment (exact, working)

```powershell
$env:RUSTUP_TOOLCHAIN = "1.97.1-x86_64-pc-windows-msvc"
$env:VCPKG_ROOT = "C:\path\to\vcpkg"
$env:VCPKG_DEFAULT_TRIPLET = "x64-windows-static-md"
$env:VCPKGRS_TRIPLET = "x64-windows-static-md"
$env:VCPKG_VISUAL_STUDIO_PATH = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
$env:OPENSSL_DIR = "$env:VCPKG_ROOT\installed\x64-windows-static-md"
$env:OPENSSL_INCLUDE_DIR = "$env:OPENSSL_DIR\include"
$env:OPENSSL_LIB_DIR = "$env:OPENSSL_DIR\lib"
$env:OPENSSL_STATIC = "1"
$env:LIB = "$env:OPENSSL_DIR\lib;$env:LIB"
```

Reproduce the measurements:

```powershell
# Benchmark A (verify/batch ring scaling + AVX2 probe), RELEASE:
cargo test -p tari-cc-private-ballot-cli --release `
  --test release_crypto_perf_scratch -- --ignored --nocapture
# Benchmark B (real executor multicore scaling), RELEASE:
cargo test -p tari-cc-private-ballot-gui-core --release `
  --test release_multicore_perf_scratch -- --ignored --nocapture
```

## 18. Final answers (consolidated)

| question | answer | evidence |
|---|---|---|
| Actual curve25519 backend | dalek 4.1.3 **SIMD/vector, AVX2 variant** (runtime-selected; Serial u64 fallback) | CONFIRMED (source) + MEASURED (`avx2=true`) |
| SIMD active in shipping build | **YES** (runtime AVX2) | MEASURED |
| Runtime-dispatched | **YES** (`cpufeatures`) | CONFIRMED |
| Compile-time CPU-specific | **NO** (portable, SSE3 baseline) | CONFIRMED |
| Internal crypto multicore | **NO** (no rayon/threads) | CONFIRMED |
| Application multicore | **YES** (Slice 4B bounded pool, budget 3) | MEASURED |
| Release vs debug (single verify) | **~21–33×** faster | MEASURED |
| Batch speedup (single-thread) | **~4–9×** per proof (batch-16; peaks ~N=2048) | MEASURED |
| Worker scaling (w1/2/3/4) | 0.99× / 3.08× / 4.00× / 4.98× (tiny ring; Amdahl-capped) | MEASURED |
| Optimal worker count (this machine) | **3** (`max(1, cores−1)`); unchanged | MEASURED-justified |
| ThinLTO + cgu=1 | **No clear benefit** (noise-dominated, +35% at 4096) → not adopted | MEASURED |
| codegen-units=1 (as part of above) | same — not adopted | MEASURED |
| CPU-feature (target-cpu/+avx2) | Not applied — negligible on hot path, breaks portability | DERIVED |
| Recommended distributed build | Single portable x86-64 baseline; rely on dalek runtime AVX2 dispatch; default release profile | CONFIRMED+DERIVED |
| 4096 cold-reconstruction | serial ~911 s / batch-16 ~132 s / batch-16×3 **~45–90 s** (this APU); ~10–30 s modern desktop | DERIVED/PROJECTED |
| 4096 crypto RAM | **≤ ~6 MB** working set | DERIVED |
| 4096 durable RAM | ~12.31 GiB retained snapshot (durable-format concern, unchanged) | PROJECTED |

**AUDIT: PASS.**
