# Performance Remediation — Slice 4D
# Same-Run Archive-Verification Memoization

Status: **PASS**.

Slice 4D eliminates repeated **complete archive proof replay** for an unchanged
archive within one process, while preserving full tamper detection: every
request still re-establishes the current on-disk archive identity and re-digests
the full catalog. It is process-local, memory-only, bounded, identity-bound,
fail-closed, and nonpersistent. No durable format, protocol, archive encoding,
Triptych math, or persistent state changed.

Evidence labels: **CONFIRMED** = current source inspected; **MEASURED** =
counter deltas from the isolated test binary under the MSVC/vcpkg toolchain.

---

## 1. Executive summary

`crates/archive/src/verifier.rs::verify_archive_directory_v1` is the single
authoritative offline verifier. Four independent same-process Tauri operations
invoke it for the same finalized archive (archive inspection, transport-anchor
inspection, live-config creation, and each live lifecycle step). Its dominant
cost is the historical **ballot replay** — one Triptych proof verification per
archived submission — plus the archive-hash rebuild.

That replayed work is a **pure function of the exact catalog bytes**, which the
archive manifest's own `ArchiveHashV1` commits (format version, election-manifest
hash, hash algorithm, canonical ordered paths, and each file's domain-separated
digest). Slice 4D therefore:

1. splits the verifier into **`establish_identity_and_catalog`** (read+decode the
   current manifest, enforce catalog set equality, and bounded-read + re-digest
   **every** catalog file — the mandatory revalidation, run on every request) and
   **`finish_verification`** (artifact decode, transport/governance, ballot
   replay, archive-hash rebuild — the expensive, memoizable remainder);
2. memoizes the finished result keyed on `(canonical directory, ArchiveHashV1)`,
   returning it only after the current catalog fully re-digests to the committed
   values.

A memo **hit** performs the full catalog rehash (I/O + BLAKE3) but **zero**
repeated Triptych proof verification. A **miss**, any mutation, replacement,
reparse substitution, or read anomaly runs (or fails closed at) the full path and
is never served a stale result. Failed verifications are never cached.

## 2. Confirmed replay topology (CONFIRMED)

Four independent full-verifier call sites (source-traced, matching the plan):

| Consumer | Source chain | Triptych replay today |
|---|---|---|
| Archive inspection | `gui/src-tauri/src/lib.rs verify_archive` → `gui-core archive_verify` → archive verifier | Yes, every submission |
| Transport-anchor inspection | `verify_transport_archive_anchor` → `gui-core transport_anchor` → archive verifier | Yes |
| Live-config creation | `write_live_anchor_config_from_verified_archive` → `gui-core live_anchor_config` → archive verifier | Yes |
| Live lifecycle step | `run_live_anchor_lifecycle_step` → `gui-core live_anchor_driver` → `ootle-anchor-app AnchorAppDriver::restore_live` → `VerifiedRuntimeArchiveFactsV1::from_archive_and_config` → archive verifier | Yes, before every network action, once per step |

A full "verify → inspect anchor → write config → run R lifecycle steps" workflow
performs `3 + R` full crypto replays of the same archive today.

## 3. Cache identity (source-proven, CONFIRMED)

`ArchiveManifestV1::canonical_hash` (`crates/archive/src/manifest.rs`) commits
the manifest version/lifecycle, election-manifest hash, hash algorithm, canonical
ordered content paths, and each file's `HashDomain::ArchiveFileV1` digest.
`ArchiveFileEntryV1` commits path + digest (not length). Classification:

| Candidate | Classification | Use in Slice 4D |
|---|---|---|
| Canonical archive directory | Scope/lookup partition | Key partition (canonicalized); not a trust input |
| `ArchiveHashV1` from freshly decoded manifest | Authoritative catalog identity | Key component; recomputed every request |
| Re-digest of every current catalog file | Authoritative current-content proof | **Required before every hit** |
| Catalog count | Derived | Consistency only |
| File sizes / mtime / inode / reparse metadata | Cheap precheck / drift signal | May force miss; **never** certifies a hit |
| Detached `archive-signatures/` | Outside content catalog | Excluded, unchanged |
| Path text / mtime / aggregate hash alone | Unsafe | Never a sole trust input |

**Memo key = `(canonical directory, ArchiveHashV1)`; a hit additionally requires
that every current catalog file re-digested to the committed value.** Reusing a
matching archive hash *without* rehashing every file is forbidden and not done.

## 4. TOCTOU and hostile-input handling (CONFIRMED)

`establish_identity_and_catalog` reuses the full verifier's exact policy:
`symlink_metadata` + `is_dir`/`is_file` checks, `enumerate_disk_files` with
`DirEntry::file_type` (no non-regular traversal), `ArchivePathV1` traversal/drive/
reserved-name rejection, bounded reads, and per-file digest verification against
the freshly decoded manifest. It runs **before** any cached result is consulted,
so:

- **Manifest mutation** → fresh decode/hash differs (new key → miss) or fails →
  fail closed; the prior result is never returned.
- **Ballot/submission mutation** → catalog rehash fails at `CATALOG_FILES` before
  any replay (MEASURED: zero Triptych verifies on the mutated-ballot path).
- **Same path replaced with a different archive** → different `ArchiveHashV1` →
  miss + full verify (+ recorded identity drift); no cross-hit.
- **Delete/recreate identical content** → the full catalog re-digests to the same
  committed values → the prior verified result is reused only after that rehash.
- **Symlink/reparse substitution, partial rewrite, read-time change** → the same
  regular-file/digest policy fails closed.

`mtime` never closes a reuse race: it is not a trust input anywhere.

## 5. Cache architecture (CONFIRMED)

`ArchiveVerificationMemoV1` (`crates/archive/src/verification_memo.rs`): a
bounded LRU (default capacity **4** immutable successful reports) with per-key
single-flight (`Condvar`). Values are `Arc<ArchiveDirectoryVerificationV1>`
(bounded reports, never archive bytes, never raw packages/proofs/nullifiers).
Only `verified == true` results are cached; failures and non-verified integrity
results are never cached. The owner runs `finish_verification` (the replay) with
**no memo lock held**, so different archives verify concurrently. Concurrent
identical callers each independently re-establish identity, then one owner runs
the replay and the waiters receive its result. An `AppState`-owned `Arc`
(mirroring the Slice 2 verified-session cache) is the single process instance;
the archive crate owns the format identity, revalidation, and memo logic.

## 6. Downstream reuse (CONFIRMED)

Live-config, transport-anchor, and the live driver already consume the verified
result's facts. The live-driver seam gained a narrow public
`VerifiedRuntimeArchiveFactsV1::from_verification_and_config` plus
`AnchorAppDriver::restore_live_with_verification`, so the driver derives its
runtime facts from the memo's verified result instead of re-running the full
verification and replay — with the identical finality/binding/privacy/count
gates. Transport-anchor keeps its post-verification manifest reread (a bounded,
fail-safe read that only tightens, never loosens, the `ANCHORED` decision), so
its output is provably unchanged.

## 7. Instrumentation (CONFIRMED)

`crates/archive/src/instrumentation.rs` (aggregate numbers only; no paths,
hashes, packages, or voter data): `archive_verification_cache_hits`,
`archive_verification_cache_misses`, `archive_full_verification_count`,
`archive_catalog_revalidations`, `archive_historical_replay_count`,
`archive_historical_triptych_verifies`, `archive_cache_evictions`,
`archive_cache_identity_drift`, `archive_single_flight_waits`, with snapshot +
reset. Full/replay/Triptych counts increment inside `finish_verification` at the
verifier boundary, so a direct (non-memoized) verify — including the live-driver
seam — is also counted.

## 8. Performance model

For N submissions and total catalog bytes B, and a workflow using all four named
operations plus R lifecycle steps:

```
Before:  (3 + R) × [ O(B) read + O(B) hash + O(N) decode/replay + N Triptych verifies ]
After :  1        × [ O(B) read + O(B) hash + O(N) decode/replay + N Triptych verifies ]
       + (2 + R)  × [ O(B) exact catalog rehash;  0 replay;  0 Triptych verifies ]
```

The eliminated work is the repeated authoritative crypto replay; the catalog
rehash deliberately remains as the current-content proof. Restart, eviction,
identity drift, or bypass returns to full replay.

## 9. Measured counter deltas (MEASURED)

Isolated test `crates/gui-core/tests/archive_verification_memo.rs`, four-ballot
archive (three accepted, one duplicate):

| Operation | hits | misses | full_verify | historical_replay | triptych_verifies | catalog_revalidations |
|---|---:|---:|---:|---:|---:|---:|
| First verification (miss) | 0 | 1 | 1 | 1 | 4 | 1 |
| Second unchanged (hit) | 1 | 0 | 0 | 0 | **0** | 1 |
| Mutated submission | 0 | — | 0 | 0 | **0** (fails at CATALOG_FILES) | 1 |
| Same-path replaced | 0 | 1 | 1 | 1 | 4 | 1 (+1 identity drift) |
| 8 concurrent identical | — | — | **1** | **1** | **4** | 8 |

A hit performs **zero** repeated historical replay and **zero** repeated Triptych
proof verification, while still revalidating the full catalog.

## 10. Tests and results

| suite | result |
|---|---|
| archive_verification_memo (new) | 11 passed |
| archive (lib) | 47 passed |
| archive_verify | 12 passed |
| live_driver_archive | 4 passed |
| live_anchor_publish | 8 passed |
| governance | 38 passed |
| security | 7 passed |
| ootle-anchor-app archive_independence | 7 passed |
| ootle-anchor-app driver_steps | 6 passed |

`cargo check -p tari-cc-private-ballot-gui-core`, `-p …-ootle-anchor-app`, and
`--manifest-path gui/src-tauri/Cargo.toml` all pass.

## 11. Known unrelated baseline blockers

- `crates/gui-core/tests/archive_writer.rs` (~line 910) — migration-owned
  `&str`/`String` compile mismatch; not fixed (out of scope), run other targets
  individually.
- `crates/ootle-anchor-app/tests/publish_security.rs:308` — E0609, the test
  references `phase_is_terminal_success` on `DriverSingleStepOutcomeV1`, which has
  no such field. This is a **pre-existing migration bug** in that test file; the
  Slice 4D driver edits are purely additive (two new methods) and never touch the
  type or the test. It blocks only that one test target; `archive_independence`
  and `driver_steps` (the driver-behavior suites) both pass.

## 12. Production files changed

- `crates/archive/src/verifier.rs` — establish/finish split + boundary counters.
- `crates/archive/src/verification_memo.rs` (new) — bounded LRU + single-flight memo.
- `crates/archive/src/instrumentation.rs` (new) — aggregate counters.
- `crates/archive/src/lib.rs` — exports.
- `crates/gui-core/src/archive_verify.rs` — memo-aware facade.
- `crates/gui-core/src/transport_anchor.rs` — shared finish helper + memo variant.
- `crates/gui-core/src/live_anchor_config.rs` — verification/derivation split + memo variant.
- `crates/gui-core/src/live_anchor_driver.rs` — memo-aware live step seam.
- `crates/gui-core/src/lib.rs` — exports.
- `crates/ootle-anchor-app/src/driver.rs` — public `from_verification_and_config` + `restore_live_with_verification` (additive).
- `gui/src-tauri/src/lib.rs` — AppState memo Arc; four commands routed through it.

## 13. PASS gate

All satisfied: 4-site replay claim source-confirmed; cache identity source-proven;
current disk identity re-established (full catalog rehash) before every reuse;
unchanged archive avoids repeated proof replay (MEASURED zero); tampered/replaced
archives fail closed; TOCTOU-safe (no metadata trust); failed verification never
cached; bounded/nonpersistent; single-flight correct (8→1); anchor outputs
unchanged (transport/config equivalence + regression); prior regressions green;
production crates compile.

**SLICE 4D: PASS.**
