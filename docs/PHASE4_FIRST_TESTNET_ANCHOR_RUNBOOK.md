# Phase 4 First Testnet Anchor Runbook

This is CONTROLLED TESTNET VALIDATION, not production certification.

The first live Ootle anchor is organizer-side only. Voters never use walletd,
never sign Ootle transactions, and never place voter wallet addresses, voting
keys, credentials, nullifiers, ballot bodies, ballot choices, or per-voter
substates on Ootle.

All paths must be absolute. Never paste walletd secrets into command history.

## Prerequisites

- Repository: `C:path	o	ari-private-ballot`
- Branch: `phase5/gui-core-foundation`
- Baseline tag: `single-pc-smoke-pass-2026-08-11`
- Rust: `stable-x86_64-pc-windows-msvc`
- Dedicated organizer-only walletd profile: required
- Accepted-ballot floor: explicit operator value, greater than zero
- Final archive: independently verified with `verified=true` and `finalized=true`

## Lifecycle Order

1. Create/open/vote.
2. Close.
3. Compute tally.
4. Mark verified.
5. Finalize.
6. Write FINAL archive.
7. Independently verify archive: `verified=true`, `finalized=true`.
8. Generate live anchor config from the verified finalized archive.
9. Inspect/dry prepare.
10. Approve.
11. Submit.
12. Verify evidence.
13. Verify aggregate archive as `ANCHORED`.

## Build

```powershell
git -C C:path	o	ari-private-ballot rev-parse --abbrev-ref HEAD
git -C C:path	o	ari-private-ballot status --porcelain
cargo +stable-x86_64-pc-windows-msvc build --release --locked --offline --package tari-cc-private-ballot-ootle-anchor-app
```

Do not add `--features offline-test-raw-hashes` to the release build.

```powershell
$exe = "C:path	o	ari-private-ballot\target\release\tari-cc-private-ballot-anchor.exe"
Get-FileHash -LiteralPath $exe -Algorithm SHA256
```

## Verify Final Archive

Use the Rust archive verifier before generating any live config. The verifier
must derive the manifest hash, archive hash, finality, accepted count, transport
accepted count, and reduced-anonymity state from archive bytes.

Required result:

- `verified=true`
- `finalized=true`
- transport binding verified
- `accepted_count >= <REQUIRED_ACCEPTED_BALLOT_FLOOR>`
- transport accepted count equals replay accepted count
- if `reduced_anonymity=true`, explicit operator acknowledgement is required

Do not continue from a legacy/pre-finality archive, even if ordinary offline
verification succeeds.

## Generate Live Config

Default builds must not use raw `--write-config`; raw hash config creation is
test-only behind `offline-test-raw-hashes` and is not live-approved.

Generate config through the Rust/Tauri command:
`write_live_anchor_config_from_verified_archive`.

Frontend/operator input may provide only public/operator values:

- archive directory
- output config path
- walletd/indexer/network locators
- fee account and exact fee component
- declared public seal key
- dedicated organizer wallet attestation
- max fee and polling/backoff values
- explicit accepted-ballot floor
- reduced-anonymity acknowledgement
- snapshot and evidence paths

Frontend/operator input must not provide authoritative manifest hash, archive
hash, finality, or accepted count. Rust derives those from the verified final
archive.

Record the producer result:

- input provenance: `ArchiveVerified`
- derived manifest hash
- derived archive hash
- anchor digest
- accepted ballot count
- required accepted-ballot floor
- reduced anonymity and acknowledgement
- fee component
- declared seal public key
- seal assurance: `ATTESTED`
- dedicated organizer wallet attestation
- config file BLAKE3-256 and byte count

## Dry Prepare And Review

```powershell
& $exe --dry-run --config <CONFIG_PATH>
```

Record and compare:

- input provenance is `ArchiveVerified`
- manifest hash and archive hash equal the verifier output
- anchor digest recomputes locally
- snapshot path and evidence path are absolute
- fee component is the reviewed component
- max fee is the reviewed ceiling

Before approval, inspect the prepared walletd request/allowlist:

- exactly one canonical `pay_fee`
- exactly one anchor `EmitLog`
- no other instructions
- no inputs
- no stealth input
- no confidential input
- no resource transfer
- no bucket
- no blob
- no workspace operation
- no project component call
- no extra signer
- no voter data

The fee component is VERIFIABLE from the frozen unsigned transaction. The
declared seal public key is ATTESTED only, not verified.

## Walletd Auth

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

Remove the variable after each run:

```powershell
Remove-Item Env:WALLETD_JWT
```

## No-Decision Prepare

```powershell
& $exe --config <CONFIG_PATH> --archive <FINALIZED_ARCHIVE_DIR> --auth-env WALLETD_JWT
```

Expected non-success checkpoint:

```text
machine_code=ANCHOR_APP_PREPARED
phase=PREPARED
transaction_id=none
no_evidence_non_terminal
```

This is not a crash. It is the mandatory review pause.

## Approve And Submit

```powershell
& $exe --config <CONFIG_PATH> --archive <FINALIZED_ARCHIVE_DIR> --auth-env WALLETD_JWT --approve
```

Success requires:

- `machine_code=ANCHOR_APP_FINALIZED_ACCEPT`
- `phase=FINALIZED_ACCEPT`
- real `transaction_id=...`
- evidence block present
- exit code 0

## Terminal Index Checks

The live app stores a manifest-scoped terminal index under the user's durable
application state, independent of the executable, snapshot, and evidence paths.
On Windows the default root is:

```powershell
$terminalIndexRoot = Join-Path $env:LOCALAPPDATA "Tari Private Ballot\anchor-state\terminal-index-v1"
```

On macOS the equivalent root is
`$HOME/Library/Application Support/Tari Private Ballot/anchor-state/terminal-index-v1`.
On Linux/Unix it is
`$XDG_STATE_HOME/tari-private-ballot/anchor-state/terminal-index-v1`, or
`$HOME/.local/state/tari-private-ballot/anchor-state/terminal-index-v1` when
`XDG_STATE_HOME` is unset.

For the same election and same accepted anchor digest, rerunning with changed
evidence, snapshot, or config-output paths must return idempotent success and
must not prepare, approve, or submit a new transaction.

For the same election/manifest and a different archive hash or anchor digest,
the app must fail closed before preparation with a terminal-index conflict.

If the terminal index is corrupted or its referenced evidence no longer matches,
the app must fail closed before preparation.

Interrupted nonterminal snapshots for the same intended anchor remain
recoverable when no terminal index exists yet.

This terminal index is a supported-app durability guard within this
application's durable anchor state for the same user/host profile. It is not a
global cryptographic impossibility proof against a separate machine, separate
user profile, modified software, or independent wallet implementation.

## Verify Evidence And Archive Anchoring

```powershell
& $exe --verify-evidence <EVIDENCE_PATH>
```

Then verify the aggregate archive as `ANCHORED` only when the finalized archive
and Phase 4 evidence independently prove the exact archive hash and anchor
digest. Organizer aggregate verification may report `INCLUDED` or `ANCHORED`;
voter transport receipts are limited to `RECEIVED`, `ACCEPTED`, and `REJECTED`.

## Capture Checklist

- multiple accepted ballots
- explicit accepted-ballot floor
- dedicated organizer-only walletd profile
- fee component displayed and verified
- seal public key displayed as `ATTESTED`
- dedicated wallet attestation
- transaction allowlist inspection
- full receipt/event/substate capture
- validator/indexer/explorer capture
- local transaction fingerprint recomputation
- anchor digest recomputation
- evidence verification
- public-data privacy inspection
- idempotent retry check
- conflicting-anchor rejection check

## Stop Conditions

Stop immediately on any branch/build/config mismatch, archive verification
failure, `finalized=false`, missing transport aggregate proof, accepted count
below floor, unacknowledged reduced anonymity, fee-component mismatch, missing
dedicated-wallet attestation, unexpected walletd request, terminal-index
conflict/corruption, or any terminal code other than
`ANCHOR_APP_FINALIZED_ACCEPT`.

## Preserve

- final archive directory and verifier output
- generated config and config hashes
- release executable SHA-256
- snapshot and evidence files
- terminal-index file
- stdout transcripts
- walletd request id and transaction id
- validator/indexer/explorer captures
