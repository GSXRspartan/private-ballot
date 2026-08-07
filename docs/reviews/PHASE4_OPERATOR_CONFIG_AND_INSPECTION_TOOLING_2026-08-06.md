# Phase 4 Operator Config and Inspection Tooling — 2026-08-06

## 1. Starting branch and HEAD

- **Branch:** `phase4/ootle-testnet-anchor-prototype`
- **HEAD:** `506e232f5b19d354d307a68eee32ea204c8ea34e`
- **Tag:** `phase4-pretestnet-ready-2026-08-06`
- **Rust:** `rustc 1.97.1 (8bab26f4f 2026-07-14)` via `stable-x86_64-pc-windows-msvc`

## 2. Exact blocker resolved

The committed Phase 4 application binary could read a canonical CBOR
`AnchorAppConfig` and decode evidence and snapshots through existing public
APIs, but no operator-facing command exposed those capabilities. The first
controlled testnet run was blocked because the operator could not safely
create the required canonical config without manually fabricating CBOR bytes.

This slice adds three explicit operator modes to the existing binary
`tari-cc-private-ballot-anchor`:

1. `--write-config` — construct a validated `AnchorAppConfig` and persist it
   through the existing `AnchorAppConfig::write_canonical_file`.
2. `--verify-evidence <path>` — decode and verify a canonical evidence file
   through the existing `AnchorEvidenceRecordV1::from_canonical_bytes`.
3. `--inspect-snapshot <path>` — decode and verify a canonical snapshot file
   through the existing `read_snapshot` and `snapshot_digest`.

## 3. Files changed

### Modified source files

| File | Change |
|------|--------|
| `crates/ootle-anchor-app/src/evidence.rs` | Added `ledger_position` field to `AnchorEvidenceRecordV1`; added read-only accessors for `network`, `manifest_hash`, `archive_hash`, `anchor_digest`, `snapshot_digest`, `ledger_position`; stored `ledger_position` in `assemble` and `from_canonical_bytes` (no encoding change) |
| `crates/ootle-anchor-app/src/report.rs` | Added 6 stable machine codes: `ConfigWritten`, `ConfigWriteFailed`, `EvidenceVerified`, `EvidenceVerifyFailed`, `SnapshotVerified`, `SnapshotVerifyFailed` |
| `crates/ootle-anchor-app/src/cli.rs` | Added `CliMode` enum, `LifecycleArgs`, `WriteConfigArgs`, `parse()` function with mode detection, conflict rejection, duplicate detection, missing-value detection; kept `validate_args` and `find_flag_value` for backward compatibility; added unit tests |
| `crates/ootle-anchor-app/src/main.rs` | Dispatch to new modes via `cli::parse()` before any file or transport activity; lifecycle mode unchanged |
| `crates/ootle-anchor-app/src/lib.rs` | Re-exported `write_config`, `verify_evidence`, `inspect_snapshot` modules |

### New source files

| File | Purpose |
|------|---------|
| `crates/ootle-anchor-app/src/write_config.rs` | `--write-config` mode: parse validated strings, construct `NetworkAdapterConfig` + `AnchorAppConfig`, call `write_canonical_file`, read back, verify, print stable output |
| `crates/ootle-anchor-app/src/verify_evidence.rs` | `--verify-evidence <path>` mode: read file, call `from_canonical_bytes`, print decoded fields + human-review summary |
| `crates/ootle-anchor-app/src/inspect_snapshot.rs` | `--inspect-snapshot <path>` mode: call `read_snapshot` + `snapshot_digest`, print bounded read-only summary |

### New test files

| File | Tests |
|------|-------|
| `crates/ootle-anchor-app/tests/write_config.rs` | 27 config-writer tests |
| `crates/ootle-anchor-app/tests/verify_evidence.rs` | 10 evidence-verifier tests |
| `crates/ootle-anchor-app/tests/inspect_snapshot.rs` | 11 snapshot-inspector tests |
| `crates/ootle-anchor-app/tests/cli_modes.rs` | 35 CLI conflict tests |

### New documentation files

| File | Purpose |
|------|---------|
| `docs/reviews/PHASE4_OPERATOR_CONFIG_AND_INSPECTION_TOOLING_2026-08-06.md` | This evidence report |
| `docs/PHASE4_FIRST_TESTNET_ANCHOR_RUNBOOK.md` | First-testnet operator runbook |

## 4. Config-writer interface

```
tari-cc-private-ballot-anchor --write-config \
  --output <absolute-path> \
  --network <esmeralda|igor|localnet> \
  --walletd-endpoint <url> \
  --indexer-endpoint <url> \
  --account-reference <value> \
  --fee-component <component-address> \
  --seal-signer-kind <account|transaction|imported> \
  --seal-signer-id <unsigned-integer> \
  --max-fee <u64> \
  --manifest-hash <64-lowercase-hex> \
  --archive-hash <64-lowercase-hex> \
  --snapshot-path <absolute-path> \
  --evidence-path <absolute-path> \
  --backoff-base-secs <u64> \
  --backoff-cap-secs <u64> \
  --receipt-query-attempts <u32> \
  [--request-timeout-secs <u64>] \
  [--ttl-secs <u64>] \
  [--force]
```

Success output:
```
machine_code=ANCHOR_APP_CONFIG_WRITTEN
config_path=<absolute-path>
network=<network>
manifest_hash=<64-lowercase-hex>
archive_hash=<64-lowercase-hex>
anchor_digest=<64-lowercase-hex>
snapshot_path=<absolute-path>
evidence_path=<absolute-path>
config_file_blake3_256=<64-lowercase-hex>
config_file_bytes=<integer>
```

The `config_file_blake3_256` field is a **BLAKE3-256** hash (not SHA-256) computed
via the existing `Blake3HashProviderV1`, to avoid adding a `sha2` dependency.
The operator can independently compute SHA-256 via `Get-FileHash -Algorithm
SHA256` if required by external tooling; the two values are intentionally
different.

## 5. Supported input formats

| Input | Format |
|-------|--------|
| `--network` | Exact lowercase: `esmeralda`, `igor`, `localnet` (network.rs:25-29). Mainnet/stagenet/nextnet/aliases/uppercase rejected. |
| `--walletd-endpoint` | `http(s)://host:port[/base]`, no embedded creds, no query/fragment (endpoint.rs:73-118). |
| `--indexer-endpoint` | Same URL-safety rules as walletd. |
| `--account-reference` | Non-empty, ≤128 UTF-8 bytes, no control/whitespace (identifiers.rs:26-43). |
| `--fee-component` | `component_<hex>` or bare hex, parseable by `WalletdFeeComponentRef::parse` (identifiers.rs:112-116). |
| `--manifest-hash` | Exactly 64 lowercase hex characters (`0-9`, `a-f`). |
| `--archive-hash` | Exactly 64 lowercase hex characters. |
| `--snapshot-path` | Absolute path, ≤4096 UTF-8 bytes. |
| `--evidence-path` | Absolute path, ≤4096 UTF-8 bytes. |
| `--max-fee` | u64 > 0. |
| `--receipt-query-attempts` | u32 > 0. |
| `--backoff-base-secs` | u64 > 0. |
| `--backoff-cap-secs` | u64 ≥ backoff-base-secs. |
| `--request-timeout-secs` | Optional u64. |
| `--ttl-secs` | Optional u64. |
| `--force` | Optional bare flag; permits overwriting an existing regular file. |

## 6. Seal-signer mapping

| `--seal-signer-kind` | `--seal-signer-id` | `WalletdSealSignerRef` variant |
|----------------------|---------------------|---------------------------------|
| `account` | derivation index (u64) | `AccountKey { index }` |
| `transaction` | derivation index (u64) | `TransactionKey { index }` |
| `imported` | local key id (u64) | `ImportedKey { local_key_id }` |

Any other `--seal-signer-kind` value is rejected.

## 7. Evidence-verifier interface

```
tari-cc-private-ballot-anchor --verify-evidence <absolute-path>
```

Success output:
```
machine_code=ANCHOR_APP_EVIDENCE_VERIFIED
evidence_path=<path>
record_digest=<64-lowercase-hex>
final_status=<stable-status>
receipt_source=<stable-source>
phase=<stable-phase>
network=<network>
manifest_hash=<hex>
archive_hash=<hex>
anchor_digest=<hex>
transaction_id=<value-or-none>
ledger_position=<value-or-none>
snapshot_digest=<hex>
human_review_summary=<bounded-summary>
```

Exit 0 only when decoding and digest verification succeed. Rejected: wrong
record type, wrong hash algorithm, digest mismatch, trailing bytes, malformed
CBOR, unknown status/source/phase, malformed transaction ID, oversized file.

## 8. Snapshot-inspector interface

```
tari-cc-private-ballot-anchor --inspect-snapshot <absolute-path>
```

Success output:
```
machine_code=ANCHOR_APP_SNAPSHOT_VERIFIED
snapshot_path=<path>
snapshot_digest=<64-lowercase-hex>
phase=<stable-phase>
poll_attempts_consumed=<integer>
poll_attempts_max=<integer>
submitted_transaction_id=<value-or-none>
walletd_snapshot_count=<integer>
receipt_snapshot_count=<integer>
walletd_snapshot[0].project_request_id=...
walletd_snapshot[0].walletd_request_id=...
walletd_snapshot[0].network=...
walletd_snapshot[0].account_reference=...
walletd_snapshot[0].anchor_digest=...
walletd_snapshot[0].anchor_payload=...
walletd_snapshot[0].max_fee=...
walletd_snapshot[0].transaction_fingerprint=...
walletd_snapshot[0].decision=...
walletd_snapshot[0].submission_state=...
walletd_snapshot[0].transaction_id=...
walletd_snapshot[0].effective_status=...
walletd_snapshot[0].retry_count=...
walletd_snapshot[0].sequence=...
walletd_snapshot[0].diagnostic=...
receipt_snapshot[0].project_request_id=...
receipt_snapshot[0].walletd_request_id=...
receipt_snapshot[0].transaction_id=...
receipt_snapshot[0].network=...
receipt_snapshot[0].account_reference=...
receipt_snapshot[0].anchor_digest=...
receipt_snapshot[0].anchor_payload=...
receipt_snapshot[0].transaction_fingerprint=...
receipt_snapshot[0].query_state=...
receipt_snapshot[0].final_status=...
receipt_snapshot[0].verified=...
receipt_snapshot[0].sequence=...
receipt_snapshot[0].diagnostic=...
```

Exit 0 only when the snapshot verifies and decodes successfully. Never
reconstructs a driver, contacts a transport, mutates the snapshot, or writes
evidence.

## 9. CLI conflict rules

- Only one mode may be selected at a time (`--write-config`, `--verify-evidence`, `--inspect-snapshot`).
- `--write-config` cannot be combined with `--approve`, `--reject`, `--dry-run`, `--config`, `--auth-env`, `--verify-evidence`, or `--inspect-snapshot`.
- `--verify-evidence` cannot be combined with any lifecycle or writer mode flag.
- `--inspect-snapshot` cannot be combined with any lifecycle or writer mode flag.
- `--approve` and `--reject` together remain rejected (existing behavior).
- Unknown arguments fail closed.
- Missing values for value flags fail closed.
- Duplicate value flags fail (not silently selecting one).
- Duplicate mode flags fail.
- Argument order does not affect validation.
- Validation happens before any file or transport activity.

## 10. Stable machine codes

New codes added to `MachineReportCode` (report.rs):

| Code | `as_str()` |
|------|------------|
| `ConfigWritten` | `ANCHOR_APP_CONFIG_WRITTEN` |
| `ConfigWriteFailed` | `ANCHOR_APP_CONFIG_WRITE_FAILED` |
| `EvidenceVerified` | `ANCHOR_APP_EVIDENCE_VERIFIED` |
| `EvidenceVerifyFailed` | `ANCHOR_APP_EVIDENCE_VERIFY_FAILED` |
| `SnapshotVerified` | `ANCHOR_APP_SNAPSHOT_VERIFIED` |
| `SnapshotVerifyFailed` | `ANCHOR_APP_SNAPSHOT_VERIFY_FAILED` |

No existing machine-code string was changed.

## 11. No canonical-format changes

- Anchor-record encoding: unchanged.
- Config encoding: unchanged (same envelope, same body field order, same domain separator).
- Snapshot encoding: unchanged.
- Evidence encoding: unchanged (the `ledger_position` field was already encoded in the body; it is now stored in the struct but the CBOR encoding is identical).
- No canonical field was added, removed, or reordered.
- No domain separator was changed.

## 12. Test results

| Test file | Tests | Result |
|-----------|-------|--------|
| `write_config.rs` | 27 | all pass |
| `verify_evidence.rs` | 10 | all pass |
| `inspect_snapshot.rs` | 11 | all pass |
| `cli_modes.rs` | 35 | all pass |
| `cli.rs` unit tests | 13 | all pass |
| Existing tests | 106 | all pass |

Total: **202 tests, 0 failed.**

## 13. Workspace check

```
cargo +stable-x86_64-pc-windows-msvc check --locked --offline --workspace --all-targets
```

Result: **Finished** with 0 errors, 0 warnings (1 pre-existing Triptych `dead_code` warning).

## 14. Workspace tests

```
cargo +stable-x86_64-pc-windows-msvc test --locked --offline --workspace
```

Result: **All passed; 0 failed.**

## 15. Strict Clippy

```
cargo +stable-x86_64-pc-windows-msvc clippy --locked --offline --workspace --all-targets --no-deps -- -D warnings
```

Result: **Exit code 0.** One pre-existing warning in vendored Triptych (`variant `Variable` is never constructed`) — not introduced by this slice.

## 16. No network

No network access was used. All tests are offline with scripted transports or pure file I/O.

## 17. No socket

No socket was opened. All transports are scripted fakes or not constructed at all (the new modes never build a transport).

## 18. No walletd/indexer contact

No walletd or indexer was contacted. The new modes construct no transport.

## 19. No transaction

No transaction was submitted to a live network.

## 20. No signing

No signing was performed. The new modes hold no wallet secret and delegate nothing to the adapter layer.

## 21. Vendored Triptych untouched

Confirmed: no vendored Triptych file was modified, added, or deleted.

## 22. Staged file count

14 files staged (5 modified source + 3 new source + 4 new tests + 2 new docs).

## 23. Per-file sizes and SHA-256

```
 19287  019cb0ccd61f4f8a99fbe814ec7dc18e620725423374bab3a066a60b78b7429e  crates/ootle-anchor-app/src/cli.rs
 33102  099d3439f1f75a5a2542778b016666b8b9111616366359ba9bb9d0641ac73aed  crates/ootle-anchor-app/src/evidence.rs
  6388  75f3e24ecff469d1256c9e236684046524e3c77734690e8c717c575acc8e73af  crates/ootle-anchor-app/src/inspect_snapshot.rs
  2305  0a524398dfd369675050a64eba8a3eab2e14bc24254a90d5ea4cadf5c494d4e8  crates/ootle-anchor-app/src/lib.rs
  7407  f798f55ebd2cd1f3b04e092d19e1d9c7f88167612d81b328aa36e00780381702  crates/ootle-anchor-app/src/main.rs
  4304  48f72059098528ec939769c5cba845ccde1cbd08749eb65c8f9bd8b864e549e3  crates/ootle-anchor-app/src/report.rs
  3253  a380e6cb1e2c7aa50364695fadebb8a21a231e0247453c621dbb8a5044b679ec  crates/ootle-anchor-app/src/verify_evidence.rs
  9648  b5b1f9ea24a245b7f6ba9ce9a9187dd827c3c07c583007e2f1853b699eedbf1a  crates/ootle-anchor-app/src/write_config.rs
 11064  423ac0fd971631692178d00c83484642eaef583fe6ef90db6538b25e2fd6ef58  crates/ootle-anchor-app/tests/cli_modes.rs
  7475  88dc22eb9f55eab70acbe13aae31af9a52afd236eaa6186a58d73e31e0971d35  crates/ootle-anchor-app/tests/inspect_snapshot.rs
  7281  b6b61037eb9b3da27a9837ffa9ac2b965814bf992259b4d53d07b0aa7b337cca  crates/ootle-anchor-app/tests/verify_evidence.rs
 14376  9770af5738f9a9714cf8311c30ab0056fc5ae4dcf39b738f2ecda93debadef4e  crates/ootle-anchor-app/tests/write_config.rs
  7457  a104c7de8367990c44b1e3e6fbbcbd1e93a8c90707eeae3d89733eaaf4b930cd  docs/PHASE4_FIRST_TESTNET_ANCHOR_RUNBOOK.md
 13501  7fd72838fe7d618fa4dca75d122a15cd77a9b7f8654e566dfedc8ce0884f40a2  docs/reviews/PHASE4_OPERATOR_CONFIG_AND_INSPECTION_TOOLING_2026-08-06.md
```

## 24. Full staged patch size and SHA-256

- **Patch size:** 114,696 bytes
- **Patch SHA-256:** `5f71df981682e2773d963530ac0988f70cf5114ce8916bf773be26b6281ccc6e`

## 25. No commit created

No commit was created. All changes are staged but not committed, per instructions.

## 26. Go/no-go for generating the first real config and proceeding to dry-run

**GO.**

The config-writer blocker is resolved. The operator can now safely create a
canonical `AnchorAppConfig` through the `--write-config` command without
manually fabricating CBOR. Evidence and snapshot inspection are available for
independent offline verification. The first controlled testnet anchor run can
proceed to dry-run, no-decision Prepared, mandatory operator review, and
exactly one explicit `--approve`.
