# Scale Qualification Harness

A single reusable, TEST-ONLY harness that qualifies the corrected organizer
archive/anchor workflow at an operator-selected registry size, from PowerShell,
with machine-readable output. It changes no production protocol, durable format,
or crypto, and it reuses the SAME reviewed writer / verifier / anchor-config
functions the shipping `write_finalized_archive` and
`write_live_anchor_config_from_verified_archive` Tauri commands call.

- Harness test: `crates/gui-core/tests/release_scale_qualification.rs`
  (one `#[ignore]`d parameterized test: `release_scale_qualification`).
- Runner: `tools/load-test/RUN_SCALE_QUALIFICATION.ps1`.
- Results: `scale-qualification-results\` (git-ignored; timestamped CSV + log per run).

## Supported scales

`50, 100, 500, 1000, 2048, 4096`. **50** is retained for regression parity with
`release_qualification_50_voters`. The protocol maximum is **4096**
(`MAX_REGISTRY_MEMBERS`); any larger value, or any unsupported value, is
rejected by both the runner and the harness (fail-closed, defense in depth).

## Requirements

- The known working MSVC/vcpkg toolchain. `tools/load-test/RUN_SCALE_QUALIFICATION.ps1` sets all
  of it for you (`RUSTUP_TOOLCHAIN`, `VCPKG_ROOT`, `VCPKG_DEFAULT_TRIPLET`,
  `VCPKGRS_TRIPLET`, `VCPKG_VISUAL_STUDIO_PATH`, `OPENSSL_DIR`,
  `OPENSSL_INCLUDE_DIR`, `OPENSSL_LIB_DIR`, `OPENSSL_STATIC`, `LIB`). If your
  layout differs, edit `Set-BuildEnvironment` at the top of the script.
- Free disk on the OS temp drive (the harness uses per-run OS temp scratch, not
  the repo). See disk safety below.

## PowerShell commands

Run one scale:

```powershell
.\tools\load-test\RUN_SCALE_QUALIFICATION.ps1 -Voters 100
.\tools\load-test\RUN_SCALE_QUALIFICATION.ps1 -Voters 500
.\tools\load-test\RUN_SCALE_QUALIFICATION.ps1 -Voters 1000
.\tools\load-test\RUN_SCALE_QUALIFICATION.ps1 -Voters 2048
.\tools\load-test\RUN_SCALE_QUALIFICATION.ps1 -Voters 4096
```

Run every scale sequentially (100 → 500 → 1000 → 2048 → 4096), each preceded by
its own disk/runtime safety check (stops if a check aborts):

```powershell
.\tools\load-test\RUN_SCALE_QUALIFICATION.ps1 -All
```

Optional overrides:

```powershell
.\tools\load-test\RUN_SCALE_QUALIFICATION.ps1 -Voters 2048 -MaxSeconds 14400 -MinFreeGB 20
```

The runner never runs all scales unless you pass `-All`, and `-All` deliberately
excludes 50 (run it explicitly with `-Voters 50`).

### Running the harness directly (without the runner)

```powershell
$env:BALLOT_SCALE_REGISTRY = '100'
$env:BALLOT_SCALE_CSV = 'scale-qualification-results\manual-100.csv'   # optional
cargo test -p tari-cc-private-ballot-gui-core --release --features test-support `
  --test release_scale_qualification release_scale_qualification -- --ignored --nocapture --test-threads=1
```

The harness always prints one `SCALE_QUAL_HEADER` and one `SCALE_QUAL_ROW` line;
if `BALLOT_SCALE_CSV` is set it also appends the row (writing the header when the
file is new).

## Workload exercised per scale (N members)

Election creation · registry construction · **real** Triptych proof generation
(one proof per voter; the verifier is built once so generation is O(N), not
O(N²)) · direct intake · private-intake inbox reconciliation · a durable-commit +
verified-session-cache advance · duplicate + malformed rejections · private-intake
indexing over the full accepted set · durable write · cold + warm resume · tally ·
close/verify/finalize · a transport-**bound** finalized archive · independent
archive verification · archive-verification memoization · non-network live-anchor
preparation. Accepted = `N − 3`; recorded packages = `N − 1`; rejected = 2.

**No live Ootle transaction is ever published** — anchor preparation is offline
config generation only. No real user workspace or production credential is used.

## Expected runtime considerations

Per-operation Triptych cost grows with the ring (registry) size, so total time
grows super-linearly. On the low-power development APU (AMD A10-9600P, AVX2, no
AVX-512), measured/observed points:

| scale | proof-gen | archive verify | one full run (approx) |
|------:|----------:|---------------:|----------------------:|
| 100   | ~5–8 s    | ~1 s           | ~15–20 s              |
| 500   | tens of s | seconds        | ~2–5 min              |
| 1000  | ~1–2 min  | ~10–20 s       | ~5–15 min             |
| 2048  | several min | ~1–2 min     | ~20–40 min            |
| 4096  | ~10+ min  | minutes        | ~30–90 min+           |

A typical modern desktop is several times faster. Default per-scale runtime caps
(overridable with `-MaxSeconds`): 300 / 600 / 1800 / 3600 / 10800 / 21600 s for
50 / 100 / 500 / 1000 / 2048 / 4096. If a run exceeds its cap the runner kills it
and records `TIMEOUT` (scratch preserved).

## Disk safety

The harness writes scratch to the OS temp drive and cleans it on success. The
durable workspace snapshot is the dominant footprint and grows with N; the
release audit projected ~12.31 GiB retained snapshot / ~24.61 GiB logical writes
at 4096 (a deferred V2-durable-format concern). The runner rejects a scale before
starting if free space is below the per-scale minimum (default GiB: 1 / 1 / 2 / 4
/ 10 / 30 for 50 / 100 / 500 / 1000 / 2048 / 4096; override with `-MinFreeGB`).
Keep 4096 storage bounded by ensuring ample free space and letting successful
runs self-clean.

## CSV fields

One row per run. Times are milliseconds (`_ms`), 3-decimal. `NA` marks a value
this harness does not measure — never a fabricated number.

| field | meaning |
|---|---|
| `timestamp` | Unix seconds when the row was emitted. |
| `registry_size` | N (members / eligible voters). |
| `ballots_exercised` | Recorded packages (`N − 1`: accepted + duplicate + malformed). |
| `accepted` | Accepted ballots (`N − 3`). |
| `rejected` | Rejected packages (2: one duplicate, one malformed). |
| `creation_ms` | Election creation + registry/artifact construction. |
| `proof_generation_ms` | Real Triptych proof generation for all voters. |
| `intake_min_ms` / `intake_median_ms` / `intake_p95_ms` / `intake_max_ms` | Per-ballot intake latency distribution (direct + rejection intakes). |
| `cold_resume_ms` | Full durable reconstruction from an empty verified-session cache. |
| `warm_resume_ms` | Resume served from the warm verified-session cache. |
| `cold_historical_triptych_verifies` | Triptych verifies during the cold resume. |
| `warm_historical_triptych_verifies` | Triptych verifies during the warm resume (expected 0). |
| `post_mutation_historical_triptych_verifies` | Triptych verifies on the resume right after a durable mutation + cache advance (expected 0). |
| `private_intake_index_probes` | Digest-index hits during indexed private reconciliation. |
| `private_intake_linear_scans` | Linear transcript scans during that reconciliation (expected 0). |
| `tally_ms` | Closed-election tally computation. |
| `finalization_ms` | mark_verified + finalize. |
| `archive_write_ms` | Writing the transport-bound finalized archive. |
| `archive_verify_ms` | First independent archive verification (full replay). |
| `archive_memo_verify_ms` | Second, memoized archive verification. |
| `archive_memo_historical_triptych_verifies` | Triptych verifies on the memoized verify (expected 0). |
| `anchor_prepare_ms` | Non-network live-anchor config preparation from the verified bound archive. |
| `peak_ram_bytes` | `NA` — peak working set is not sampled in-process (see the release crypto audit for RAM figures). |
| `workspace_disk_bytes` | Bytes on disk in the durable workspace directory after full intake. |
| `logical_read_bytes` / `logical_write_bytes` | `NA` — not instrumented in this harness. |
| `result` | `PASS` (every assertion held) — the authoritative success signal. |
| `notes` | Space-separated extras: `archive_replay`, `archive_triptych`, `cold_replayed`. |

## Recognizing PASS / FAIL

- **PASS**: the CSV row's `result` column is `PASS` (the harness writes it only
  after every assertion passed) and the log ends with `test result: ok`. The
  runner's summary table shows `PASS`. (The runner trusts the CSV `result`
  column, because a redirected `Start-Process` can leave the process exit code
  unreadable — the blank `exit ()` in the console is cosmetic.)
- **FAIL**: no PASS row was written; the runner prints `FAIL` and the harness
  scratch is preserved (see below). Read the `.log` for the failing assertion.
- **TIMEOUT**: the run exceeded its runtime cap and was killed; scratch and the
  partial log are preserved.

## Preserving a failed fixture

On a failed (panicking) run the harness does **not** delete its scratch: it
prints `SCALE_QUAL_PRESERVED failed-run scratch retained: <path>` (an OS temp
directory named `gui-core-scale-qualification-<N>-<pid>`). The runner also keeps
the per-run `.log`. Inspect both before re-running. Nothing under
`scale-qualification-results\` is auto-deleted.

## Cleaning successful scratch

Successful runs self-clean their OS temp scratch (nothing to do). The
`scale-qualification-results\` CSV/log files are disposable and git-ignored;
delete them whenever you no longer need the measurements:

```powershell
Remove-Item .\scale-qualification-results\* -Force
```

Preserved failed-run scratch directories live under the OS temp folder; remove
them once analyzed:

```powershell
Remove-Item (Join-Path $env:TEMP 'gui-core-scale-qualification-*') -Recurse -Force
```

## Safety summary

Scratch/temp workspaces only · never touches real user election workspaces ·
never publishes a live Ootle transaction · never uses production credentials ·
prechecks disk before each run · enforces a configurable runtime cap · clearly
identifies scratch output · preserves evidence after a failure · avoids extra
giant copies · keeps 4096 storage bounded via the disk precheck and self-clean.
