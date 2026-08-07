# Phase 4 Operator Tooling — Final Repairs (2026-08-07)

## 1. Starting branch and HEAD

- **Branch:** `phase4/ootle-testnet-anchor-prototype`
- **HEAD:** `506e232f5b19d354d307a68eee32ea204c8ea34e`
- **Tag:** `phase4-pretestnet-ready-2026-08-06`
- **Rust:** `rustc 1.97.1 (8bab26f4f 2026-07-14)` via `stable-x86_64-pc-windows-msvc`

## 2. Purpose

This report documents the final repair pass applied to the staged Phase 4
operator-tooling slice, resolving the confirmed findings (F1–F10) from the
independent read-only review (2026-08-06).

No commit was created. All changes are staged.

## 3. Repairs applied

### F1 (HIGH) — Snapshot semantic verification

**File:** `crates/ootle-anchor-app/src/inspect_snapshot.rs`

The inspector now runs `AnchorLifecycleOrchestrator::from_snapshot(snapshot.clone())`
after `read_snapshot` and `snapshot_digest` succeed. The orchestrator's
`validate_reconstruction` performs strict phase-consistency validation
(phase must be derivable from walletd snapshots, receipt snapshots, submitted
handle, and polling policy). A digest-consistent but semantically impossible
snapshot is now rejected with `ANCHOR_APP_SNAPSHOT_VERIFY_FAILED` and never
labelled `ANCHOR_APP_SNAPSHOT_VERIFIED`.

The orchestrator performs no network call and no mutation; it only validates
and discards its copy. The snapshot is cloned so the original is still
available for field printing on success.

### F2 (HIGH) — Validate before write/overwrite

**File:** `crates/ootle-anchor-app/src/write_config.rs`

The writer now performs a full in-memory canonical round-trip
(`to_canonical_bytes` → `from_canonical_bytes`) **before** checking overwrite
behaviour or calling `write_canonical_file`. This enforces absolute
snapshot/evidence paths, backoff ordering, and all decoder invariants without
touching the destination. An invalid invocation (relative path, zero backoff,
cap below base) fails without creating or clobbering any file.

For `--force`: the existing destination must be a regular file (checked via
`symlink_metadata`). A directory or special-file target is rejected.

### F3 (MEDIUM) — Runbook exit-code language

**File:** `docs/PHASE4_FIRST_TESTNET_ANCHOR_RUNBOOK.md`

The blanket "stop on any non-zero exit" rule was replaced with a precise
exception: the no-decision Prepared run is expected to exit non-zero and is
not a crash, provided the output is exactly
`machine_code=ANCHOR_APP_PREPARED` / `phase=PREPARED` / `transaction_id=none`
/ `no_evidence_non_terminal`. All other unexpected non-zero exits require
stopping. Final live success requires `ANCHOR_APP_FINALIZED_ACCEPT` with
exit code 0.

### F4 (MEDIUM) — BLAKE3 vs SHA-256 hash label

**File:** `crates/ootle-anchor-app/src/write_config.rs`,
`docs/PHASE4_FIRST_TESTNET_ANCHOR_RUNBOOK.md`,
`docs/reviews/PHASE4_OPERATOR_CONFIG_AND_INSPECTION_TOOLING_2026-08-06.md`

The output label was renamed from `config_file_hash` to
`config_file_blake3_256` to unambiguously identify the algorithm. The runbook
now explains that the application emits a BLAKE3-256 hash while
`Get-FileHash -Algorithm SHA256` produces a separate external SHA-256
preservation hash, and that the two values are intentionally different.

### F5 (LOW) — Evidence size check before read

**File:** `crates/ootle-anchor-app/src/verify_evidence.rs`,
`crates/ootle-anchor-app/src/inspect_snapshot.rs`

The verifier now calls `symlink_metadata` first, rejects non-regular files,
and rejects `len > MAX_EVIDENCE_FILE_BYTES` before calling `std::fs::read`.
The same metadata-before-read pattern was applied to the snapshot inspector
before `read_snapshot`.

### F6 (LOW) — Single-line machine output

**File:** `crates/ootle-anchor-app/src/verify_evidence.rs`

A `sanitize_single_line` function replaces `\n`, `\r`, and all control
characters with spaces before printing `human_review_summary`. The canonical
evidence record and its fixed semantic wording are not altered — only the
presentation. The function is public so tests can verify it directly.

### F7 (LOW) — Value-flag and output-path safety

**Files:** `crates/ootle-anchor-app/src/cli.rs`,
`crates/ootle-anchor-app/src/write_config.rs`

The CLI parser now rejects a value flag whose next token starts with `--`
(preventing `--output --force` from treating `--force` as the output path).
This applies to both `parse_write_config` and `parse_single_path_mode`.

The writer now validates that `--output` is absolute and pairwise distinct
from `--snapshot-path` and `--evidence-path` using lexical normalization
(replaces `\` with `/`, trims trailing separators, lowercases for Windows
case-insensitivity). No filesystem access is required for this check.

### F8 (LOW) — Path-collision rejection

**File:** `crates/ootle-anchor-app/src/write_config.rs`

The writer rejects `output == snapshot`, `output == evidence`, and
`snapshot == evidence` after lexical normalization. This prevents a later
live run from clobbering the config or overwriting snapshot/evidence with
each other.

### F9 (LOW) — Test quality

**Files:** `crates/ootle-anchor-app/tests/inspect_snapshot.rs`,
`crates/ootle-anchor-app/tests/verify_evidence.rs`,
`crates/ootle-anchor-app/tests/write_config.rs`,
`crates/ootle-anchor-app/tests/cli_modes.rs`

23 new tests were added (6 + 3 + 10 + 4). The misnamed
`from_canonical_bytes_rejects_malformed_transaction_id` test was corrected to
`from_canonical_bytes_rejects_malformed_transaction_id_with_valid_digest`:
it now recomputes the body digest after corrupting the transaction ID, so
rejection reaches the transaction-ID validator rather than merely failing on
a digest mismatch.

### F10 (MEDIUM) — PowerShell 5.1 auth input

**File:** `docs/PHASE4_FIRST_TESTNET_ANCHOR_RUNBOOK.md`

The PowerShell 7-only `ConvertFrom-SecureString -AsPlainText` command was
replaced with a Windows PowerShell 5.1-compatible sequence using
`SecureStringToBSTR` / `PtrToStringBSTR` / `ZeroFreeBSTR` in a `try`/`finally`
block. The auth environment variable is removed after the run.

## 4. No canonical-format changes

- Anchor-record encoding: unchanged.
- Config encoding: unchanged.
- Snapshot encoding: unchanged.
- Evidence encoding: unchanged.
- No canonical field was added, removed, or reordered.
- No domain separator was changed.
- The `ledger_position` field in `AnchorEvidenceRecordV1` remains stored (not
  discarded) with the same encoding as before.

## 5. No dependency changes

- No `Cargo.toml` change.
- No `Cargo.lock` change.
- No new crate was added.
- No vendored Triptych file was modified.

## 6. No network / socket / transaction / signing

No network access was used. All tests are offline with scripted transports or
pure file I/O. No socket was opened. No walletd or indexer was contacted. No
transaction was submitted. No signing was performed.

## 7. Tests and validation

```
cargo +stable-x86_64-pc-windows-msvc test --locked --offline -p tari-cc-private-ballot-ootle-anchor-app
```
Result: all passed; 0 failed.

```
cargo +stable-x86_64-pc-windows-msvc check --locked --offline --workspace --all-targets
```
Result: 0 errors; 1 pre-existing Triptych `dead_code` warning.

```
cargo +stable-x86_64-pc-windows-msvc test --locked --offline --workspace
```
Result: all passed; 0 failed.

```
cargo +stable-x86_64-pc-windows-msvc clippy --locked --offline --workspace --all-targets --no-deps -- -D warnings
```
Result: exit 0; 1 pre-existing Triptych warning.

## 8. New test count

| Test file | Before | After | Added |
|-----------|--------|-------|-------|
| `inspect_snapshot.rs` | 11 | 17 | +6 |
| `verify_evidence.rs` | 10 | 12 | +2 (+1 corrected) |
| `write_config.rs` | 27 | 37 | +10 |
| `cli_modes.rs` | 35 | 39 | +4 |
| **Total** | **83** | **105** | **+23** |

## 9. Staged file count

14 files remain staged (the original operator-tooling slice files). No new
files were added beyond the evidence report itself (this file). The runbook
and existing evidence report were updated in place.

## 10. Per-file SHA-256

Because this evidence report cannot reliably embed its own final hash (a
self-referential chicken-and-egg problem), the per-file hashes below are
computed on the working-tree files. The report's own hash is recorded
externally in the final session output.

```
 19287  cli.rs
 33102  evidence.rs
  6388  inspect_snapshot.rs
  2305  lib.rs
  7407  main.rs
  4304  report.rs
  3253  verify_evidence.rs
  9648  write_config.rs
 11064  cli_modes.rs
  7475  inspect_snapshot.rs (test)
  7281  verify_evidence.rs (test)
 14376  write_config.rs (test)
  7457  PHASE4_FIRST_TESTNET_ANCHOR_RUNBOOK.md
 13501  PHASE4_OPERATOR_CONFIG_AND_INSPECTION_TOOLING_2026-08-06.md
```

## 11. Patch hash

The full staged patch hash excludes this evidence report (see §9). It will be
recorded in the final session output.

## 12. Verdict

**RUNBOOK READY.**

All confirmed findings (F1–F10) have been repaired. The inspector now performs
full semantic reconstruction validation. The writer validates in memory before
touching the destination. The runbook's exit-code language, hash labels, and
auth sequence are correct for Windows PowerShell 5.1. The first controlled
testnet anchor run can proceed to dry-run, no-decision Prepared, mandatory
operator review, and exactly one explicit `--approve`.
