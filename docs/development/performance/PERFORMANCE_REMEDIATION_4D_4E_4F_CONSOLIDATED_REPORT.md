# Performance Remediation — Consolidated 4D · 4E · 4F

Status: **4D PASS · 4E PASS · 4F PASS.** All three staged, security-gated
optimizations are implemented, source-proven, and validated under the documented
MSVC/vcpkg toolchain. No durable format, protocol, ballot/nullifier, archive, or
vendored-crypto change. Work is uncommitted (per repository convention).

Per-slice detail: `PERFORMANCE_REMEDIATION_SLICE4D_REPORT.md`,
`…SLICE4E_REPORT.md`, `…SLICE4F_REPORT.md`; matrices
`AUDIT_ARCHIVE_VERIFICATION_MEMO_MATRIX.csv`,
`AUDIT_VERIFIED_SESSION_ADVANCEMENT_MATRIX.csv`,
`AUDIT_DURABLE_HEAD_BODY_CACHE_MATRIX.csv`.

---

## 1. Slice 4D — same-run archive-verification memoization

Four independent same-process Tauri operations re-verify the same finalized
archive (inspection, transport-anchor inspection, live-config creation, each live
lifecycle step), each replaying every submission through Triptych verification.
4D memoizes the verified result keyed on `(canonical directory, ArchiveHashV1)`.
Because the archive manifest's hash commits the entire catalog identity (version,
election hash, algorithm, ordered paths, every file digest), a hit is safe only
after the current catalog is **fully re-read and re-digested** — which every
request does. A hit then skips the repeated ballot replay and archive-hash
rebuild.

- Architecture: `establish_identity_and_catalog` (mandatory revalidation) +
  `finish_verification` (the memoized replay), a bounded LRU (cap 4) with per-key
  single-flight, memory-only, fail-closed, nonpersistent, all in the archive
  crate; one `AppState`-owned instance drives all four Tauri commands via
  memo-aware gui-core seams (+ a public `restore_live_with_verification` on the
  anchor-app driver).
- Result: first use = 1 full replay; subsequent unchanged uses = 0 repeated
  Triptych replay, catalog still revalidated. 8 concurrent identical callers → 1
  replay.

## 2. Slice 4E — incremental verified-session advancement

A durable mutation of an already-verified session used to invalidate the
verified-session cache, forcing a full cold reconstruction on the next resume. 4E
instead **advances** the cache to the new committed head.

- Proven-first: `session ≡ from_durable_snapshot(session.to_durable_snapshot())`
  for every mutation category (accepted / rejected / duplicate / private-intake /
  close / verified / finalized / long chains), across durable snapshot bytes,
  transcript, accepted count, and tally, against both serial and parallel
  reconstruction — before any production trust.
- Write → trust: the workspace-layer advance independently re-reads and fully
  validates the newest committed head, confirms it is exactly the expected
  revision and that its body equals the advanced session's snapshot, then installs
  the (crate-private) verified wrapper. Any drift falls back to invalidation.
- Result: a successful mutation + immediate resume performs 0 reconstruction and
  0 Triptych verification; sequential advances stay replay-free; external head
  change / revision drift fail closed; no persistent trust.

## 3. Slice 4F — warm durable-head body cache (corrected scope)

Slice 3B's warm append still read, re-hashed, and (in fact, twice) CBOR-decoded
the head body every append. Source analysis established that the head file
**read + re-hash cannot be safely skipped** — the commit marker does not attest
the current revision-file content, so skipping the re-hash would let the fast
path append onto a head the full walk would reject (a Slice 3B tamper/rollback
regression). Only the **decode** is safe to elide.

- 4F implements a byte-bounded (16 MiB), identity-bound, memory-only LRU of
  decoded head bodies (one per workspace, keyed by `(workspace_id, revision,
  digest)`), reused only after the mandatory re-hash re-confirms the identity; it
  also removes the previous double-decode.
- **Correction:** the audit's projected ~13.2 GB → ~1.79 GB warm-head **read**
  reduction is not safely achievable and is withdrawn; the read/hash I/O is
  unchanged. The delivered, safe win is eliminating the repeated **decode** (0
  decodes on a warm hit), with all Slice 3B tamper/rollback protections intact.

## 4. Security invariants (all preserved)

- Archive: full catalog rehash on every reuse; tamper/replacement/reparse/
  read-race fail closed; failed verification never cached; anchor outputs
  unchanged; single-flight; no lock during replay.
- Verified session: advanced state proven equal to cold reconstruction; new
  committed identity independently confirmed; external drift fails closed; new
  proof verification preserved; no persistent trust; Slice 2 single-flight/identity
  and restart semantics preserved.
- Durable head: read + BLAKE3 re-hash never skipped (integrity); external edit /
  rollback / head replacement / wrong predecessor / concurrent fork / corruption
  all still fail closed; byte-bounded, nonpersistent.

## 5. Operation-count / complexity summary

| flow | before | after |
|---|---|---|
| 4 archive operations + R lifecycle steps, unchanged archive | `3+R` full crypto replays | 1 full replay + `(2+R)` catalog revalidations (0 replay) |
| resume after a same-process mutation | full cold reconstruction (N replays) | 0 replay (cache advance), given confirmed head |
| warm durable append | read + hash + 2× decode | read + hash + (0 decode on hit) |

## 6. Test ledger (explicit targets, MSVC/vcpkg, `--features test-support`)

| suite | result | suite | result |
|---|---|---|---|
| archive_verification_memo (4D) | 11 | verified_session_advancement (4E) | 8 |
| verified_session_advance_cache (4E) | 4 | durable_head_body_cache (4F) | 6 |
| durable_append_fast_path (3B) | 14 | workspace | 38 |
| verified_session_cache (2) | 6 | reconstruction_instrumentation | 5 |
| parallel_historical_replay (4B) | 7 | slice4b_instrumentation | 1 |
| slice4c_private_intake (4C) | 7 | intake | 13 |
| private_intake_inbox | 16 | security | 7 |
| participation | 18 | election_status | 11 |
| serialization | 3 | tally | 10 |
| voter_cast_lock | 22 | archive_verify | 12 |
| live_driver_archive | 4 | live_anchor_publish | 8 |
| governance | 38 | gui-core lib | 116 |
| archive (lib) | 47 | crypto (lib) | 54 |
| verifier (lib + real_triptych) | 28 + 12 | ootle-anchor-app archive_independence / driver_steps | 7 / 6 |

**0 failures.** `cargo check -p tari-cc-private-ballot-gui-core` and
`cargo check --manifest-path gui/src-tauri/Cargo.toml` pass; clippy clean on the
changed crates.

## 7. Known unrelated blockers (migration-owned; NOT fixed)

- `crates/gui-core/tests/archive_writer.rs` (~line 910) — `&str`/`String`
  mismatch from the live-anchor migration branch.
- `crates/ootle-anchor-app/tests/publish_security.rs:308` — E0609, references
  `phase_is_terminal_success` on `DriverSingleStepOutcomeV1`, which has no such
  field; a pre-existing migration bug (this run's driver edits are purely
  additive). It blocks only that one test target; `archive_independence` and
  `driver_steps` pass.

Each blocks only its single test binary and prevents a whole-package `cargo test`
from building all targets at once, so every suite above was run as an explicit
target. No full-suite PASS is claimed on those two binaries.

## 8. Remaining performance limitations

- The ~12.31 GiB projected retained full-snapshot workspace / ~24.61 GiB logical
  writes at 4096 (durable on-disk format) remain deferred — a V2 durable-format
  decision, out of scope here.
- 4F reduces decode, not warm-head I/O (see §3); the safe I/O reduction would
  require a durable-format change (e.g. a separate small authenticated head
  descriptor), not attempted.

## 9. Next required stage

**Production release / SIMD / CPU-backend audit and benchmark** — determine the
actual shipping curve25519 backend and AVX2/SIMD behavior, debug-vs-release
Triptych performance, ThinLTO/codegen-unit impact, a safe CPU-feature deployment
strategy, release-mode batch+multicore scaling, and a real 4096 cold-reconstruction
estimate. Then real GUI hard-use validation at 50 and 100 voters and controlled
scale testing at 500/1000/2048/4096, and the V2-durable-format decision.

Not started in this run.
