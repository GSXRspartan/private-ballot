# Phase 4 First Testnet Anchor Runbook

This runbook provides exact PowerShell command templates for the first
controlled Ootle testnet anchor run using the committed Phase 4 application.

All paths must be absolute. All placeholders `<...>` must be replaced before
execution. Never paste secrets into the command line.

## Prerequisites

- **Repository:** `C:\Users\pdark\Documents\Codex\2026-07-30\tari-cc-private-ballot`
- **Branch:** `phase4/ootle-testnet-anchor-prototype`
- **HEAD:** `506e232f5b19d354d307a68eee32ea204c8ea34e`
- **Tag:** `phase4-pretestnet-ready-2026-08-06`
- **Rust:** `stable-x86_64-pc-windows-msvc` (1.97.1)

## 1. Verify repository state

```powershell
git -C C:\Users\pdark\Documents\Codex\2026-07-30\tari-cc-private-ballot rev-parse --abbrev-ref HEAD
git -C C:\Users\pdark\Documents\Codex\2026-07-30\tari-cc-private-ballot rev-parse HEAD
git -C C:\Users\pdark\Documents\Codex\2026-07-30\tari-cc-private-ballot describe --tags --exact-match 506e232f5b19d354d307a68eee32ea204c8ea34e
git -C C:\Users\pdark\Documents\Codex\2026-07-30\tari-cc-private-ballot status --porcelain
```

Expected: `phase4/ootle-testnet-anchor-prototype`, `506e232...`, `phase4-pretestnet-ready-2026-08-06`, clean tree.

## 2. Build release

```powershell
cargo +stable-x86_64-pc-windows-msvc build --release --locked --offline --package tari-cc-private-ballot-ootle-anchor-app
```

## 3. Locate and hash the executable

```powershell
$exe = "C:\Users\pdark\Documents\Codex\2026-07-30\tari-cc-private-ballot\target\release\tari-cc-private-ballot-anchor.exe"
Get-FileHash -LiteralPath $exe -Algorithm SHA256
Get-Item -LiteralPath $exe | Select-Object Length, FullName
```

## 4. Write the canonical config

Replace every `<...>` placeholder with the operator's actual values.

```powershell
& $exe --write-config `
  --output <CONFIG_PATH> `
  --network <TESTNET_NETWORK> `
  --walletd-endpoint <WALLETD_ENDPOINT> `
  --indexer-endpoint <INDEXER_ENDPOINT> `
  --account-reference <FEE_ACCOUNT_REFERENCE> `
  --fee-component <FEE_COMPONENT_ADDRESS> `
  --seal-signer-kind <account|transaction|imported> `
  --seal-signer-id <SEAL_SIGNER_ID> `
  --max-fee <MAX_FEE> `
  --manifest-hash <MANIFEST_HASH_64HEX> `
  --archive-hash <ARCHIVE_HASH_64HEX> `
  --snapshot-path <SNAPSHOT_PATH> `
  --evidence-path <EVIDENCE_PATH> `
  --backoff-base-secs <BACKOFF_BASE_SECS> `
  --backoff-cap-secs <BACKOFF_CAP_SECS> `
  --receipt-query-attempts <RECEIPT_QUERY_ATTEMPTS>
```

| Placeholder | Source | Format |
|-------------|--------|--------|
| `<CONFIG_PATH>` | Operator-chosen output path | Absolute, e.g. `C:\anchor\config.cbor` |
| `<TESTNET_NETWORK>` | Selected testnet | `esmeralda`, `igor`, or `localnet` |
| `<WALLETD_ENDPOINT>` | walletd JSON-RPC URL | `http(s)://host:port` |
| `<INDEXER_ENDPOINT>` | indexer REST URL | `http(s)://host:port` |
| `<FEE_ACCOUNT_REFERENCE>` | Project account label | Non-empty, no whitespace |
| `<FEE_COMPONENT_ADDRESS>` | walletd-printed component address | `component_<hex>` or bare hex |
| `<SEAL_SIGNER_ID>` | walletd key derivation index or imported key id | Unsigned integer (u64) |
| `<MAX_FEE>` | Max fee ceiling | Integer > 0 |
| `<MANIFEST_HASH_64HEX>` | Election manifest hash | 64 lowercase hex chars |
| `<ARCHIVE_HASH_64HEX>` | Completed archive hash | 64 lowercase hex chars |
| `<SNAPSHOT_PATH>` | Operator-chosen snapshot path | Absolute |
| `<EVIDENCE_PATH>` | Operator-chosen evidence path | Absolute |
| `<BACKOFF_BASE_SECS>` | Poll backoff base | Integer > 0 |
| `<BACKOFF_CAP_SECS>` | Poll backoff cap | Integer >= base |
| `<RECEIPT_QUERY_ATTEMPTS>` | Max poll attempts | Integer > 0 |

Expected output: `machine_code=ANCHOR_APP_CONFIG_WRITTEN` + config details + `config_file_blake3_256=<64-lowercase-hex>` + `config_file_bytes=<int>`.

The `config_file_blake3_256` field is a **BLAKE3-256** whole-file hash emitted by the application using the project's existing BLAKE3 provider. The separate `Get-FileHash -Algorithm SHA256` in step 5 produces a **different** SHA-256 value for external preservation. Both values are intentional; record both.

## 5. Verify config file hash

```powershell
Get-FileHash -LiteralPath <CONFIG_PATH> -Algorithm SHA256
Get-Item -LiteralPath <CONFIG_PATH> | Select-Object Length, FullName
```

Record the SHA-256 hash and byte count.

## 6. Dry-run (no network, no transport)

```powershell
& $exe --dry-run --config <CONFIG_PATH>
```

Record: `network`, `manifest_hash`, `archive_hash`, `anchor_digest`, `snapshot_path`, `evidence_path`.

## 7. No-decision Prepared run (stops at Prepared, contacts walletd)

Set walletd auth without printing or persisting the credential. The following
sequence is compatible with Windows PowerShell 5.1 (it does not use the
PowerShell 7-only `-AsPlainText` parameter):

```powershell
$secure = Read-Host "Walletd bearer token" -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    $env:WALLETD_JWT = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
}
finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
}
```

The managed environment-variable string remains in process memory until
removed. A proper secret store is preferable where available. Never echo the
token or place it in command history.

Run with no approval or rejection flag:

```powershell
& $exe --config <CONFIG_PATH> --auth-env WALLETD_JWT
```

Expected: `machine_code=ANCHOR_APP_PREPARED`, `phase=PREPARED`, `transaction_id=none`, `no_evidence_non_terminal`. **Exit non-zero.**

This expected non-zero exit is **not a crash**. It is the normal behaviour for
a no-decision Prepared run because `NotYetFinalized` is intentionally
non-success. Proceed to step 8 **only** when the output is exactly:

```
machine_code=ANCHOR_APP_PREPARED
phase=PREPARED
transaction_id=none
no_evidence_non_terminal
```

After the run, remove the auth environment variable:

```powershell
Remove-Item Env:WALLETD_JWT
```

## 8. Inspect the prepared snapshot

```powershell
& $exe --inspect-snapshot <SNAPSHOT_PATH>
```

Record all walletd snapshot fields:
- `project_request_id`, `walletd_request_id`
- `network`, `account_reference`, `anchor_digest`, `anchor_payload`
- `max_fee`, `transaction_fingerprint`
- `decision` (must be `PREPARED`), `submission_state` (must be `NOT_SUBMITTED`)
- `transaction_id` (none at this stage), `effective_status`
- `retry_count`, `sequence`, `diagnostic`

## 9. Mandatory operator review checkpoint

Before approving, confirm ALL immutable values match expectations:

- `<TESTNET_NETWORK>` is `esmeralda`, `igor`, or `localnet`
- `manifest_hash` matches the committed election manifest
- `archive_hash` matches the completed archive
- `anchor_digest` matches the dry-run output
- `anchor_payload` derived from the digest
- `fee account` = `<FEE_ACCOUNT_REFERENCE>`
- `fee component` = `<FEE_COMPONENT_ADDRESS>`
- `max_fee` = `<MAX_FEE>`
- unsigned transaction `fingerprint`
- `walletd_request_id`

**Do not approve if any value is unexpected.** Use `--reject` instead, or stop.

## 10. Approve (exactly one explicit --approve)

```powershell
& $exe --config <CONFIG_PATH> --auth-env WALLETD_JWT --approve
```

Uses the same config and same `<SNAPSHOT_PATH>`. Success only if:
`machine_code=ANCHOR_APP_FINALIZED_ACCEPT`, `phase=FINALIZED_ACCEPT`,
real `transaction_id=`, evidence block present, exit 0.

## 11. Resume after interruption

All recovery uses the same `<CONFIG_PATH>` and same `<SNAPSHOT_PATH>`. Never
delete an Unknown/Submitted snapshot. Never run two instances concurrently.

```powershell
& $exe --config <CONFIG_PATH> --auth-env WALLETD_JWT --approve
```

The driver restores the snapshot and continues from the current phase.

## 12. Verify evidence

```powershell
& $exe --verify-evidence <EVIDENCE_PATH>
```

Expected: `machine_code=ANCHOR_APP_EVIDENCE_VERIFIED` + all decoded fields +
`human_review_summary=...` (contains the non-binding pilot disclaimer).

## Stop conditions

STOP immediately if:
- Branch/HEAD/tag/tree mismatch.
- Build fails.
- Dry-run returns unexpected locators.
- Prepared identifiers do not match expectations.
- Snapshot phase is `Unknown`/`Submitted` and you are tempted to delete or resubmit.
- Poll exhaustion recurs after one resume.
- Any terminal non-success code.
- The no-decision Prepared run produces output **other** than exactly `ANCHOR_APP_PREPARED` / `phase=PREPARED` / `transaction_id=none` / `no_evidence_non_terminal`.
- The final live run produces any code other than `ANCHOR_APP_FINALIZED_ACCEPT` with exit code 0.

**Exception:** the no-decision Prepared run (step 7) is expected to exit
non-zero. This is not a crash and does not require stopping, **provided** the
output matches the exact Prepared checkpoint above. All other unexpected
non-zero exits require stopping.

## Files to preserve

Before any retry or escalation, copy and hash:
- `<CONFIG_PATH>` — SHA-256
- `target\release\tari-cc-private-ballot-anchor.exe` — SHA-256
- `<SNAPSHOT_PATH>` — SHA-256
- `<EVIDENCE_PATH>` — SHA-256
- All stdout transcripts
- The `transaction_id` from the approve/finalize run
