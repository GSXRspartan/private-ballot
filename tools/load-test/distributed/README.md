# Distributed Voter Load Driver — Physical Multi-Machine Runner

`RUN_DISTRIBUTED_VOTER_LOAD.ps1` orchestrates ONE distributed voter cohort
submission on ONE Windows host (desktop or VPS) using
`tari-cc-private-ballot-cli distributed-submit`. Run it once per host; each
host runs its own independent Tor instance and its own credential partition.

This is the PHYSICAL distributed test. It is **not** the offline scale
benchmark (`tools\load-test\RUN_SCALE_QUALIFICATION.ps1`), which is in-process,
uses no Tor, and performs no physical networking.

## Tor Modes (exactly one, fail-closed)

### MODE A — Managed Tor (recommended)

```
-TorExe "C:\Tor\tor.exe"
```

The CLI (not PowerShell) owns all security-sensitive mechanics:

1. validates the executable with the **same shared policy as production**
   managed Tor (absolute path only, real regular file, no
   symlinks/reparse points, no control characters, no PATH lookup, no shell);
2. reserves a fresh loopback SOCKS port (never a fixed 9050 assumption);
3. creates an isolated per-run Tor `DataDirectory` under the run output
   directory — never the production Private Ballot Tor state, no onion
   service, no control port;
4. spawns the operator-supplied `tor.exe` directly (no shell, no download,
   no bundling — the operator installed it);
5. waits for REAL SOCKS5 readiness (spawn success is never readiness);
6. submits the whole cohort through that Tor instance only;
7. stops/reaps ONLY the Tor process it started (never taskkill by image
   name, never your Tor Browser or production Tor);
8. removes the disposable runtime on success; preserves bounded failure
   evidence (`tor-stderr.log`) next to the results file on failure.

If Tor fails, the run fails. There is **no clearnet fallback**.

### MODE B — Existing SOCKS (legacy, preserved)

```
-TorSocks 127.0.0.1:9050
```

The operator runs Tor themselves (Tor Expert Bundle on 9050, Tor Browser on
9150) and the driver uses the already-running listener. This is the exact
workflow of the prior physical 500-voter test; nothing about the protocol or
submissions changes.

Supplying **both** `-TorExe` and `-TorSocks` is rejected as ambiguous.

## Prerequisites Per Voter Host

* An installed `tor.exe` (MODE A) or a running local SOCKS listener (MODE B).
* The organizer's private intake service already running, sharing:
  election manifest, voter registry, candidate set, and the voter-public
  transport bundle (onion v3 hidden service — see the organizer docs).
* The test passphrase in `TARI_BALLOT_LOAD_PASSPHRASE`.
* A credential partition generated on a trusted machine:

```powershell
$env:TARI_BALLOT_LOAD_PASSPHRASE = "test-only passphrase"
cargo run -p tari-cc-private-ballot-cli -- distributed-cohort --count 500 --out C:\distributed-election
cargo run -p tari-cc-private-ballot-cli -- distributed-partition --credentials C:\distributed-election\voters --out C:\desktop-voters --start-index 1 --count 250
cargo run -p tari-cc-private-ballot-cli -- distributed-partition --credentials C:\distributed-election\voters --out C:\vps-voters --start-index 251 --count 250
```

Only `C:\distributed-election\organizer\voter-registry.cbor` goes to the
organizer. Credential partitions stay on their hosts.

## Desktop Cohort (Host A)

```powershell
$env:TARI_BALLOT_LOAD_PASSPHRASE = "test-only passphrase"
.\tools\load-test\distributed\RUN_DISTRIBUTED_VOTER_LOAD.ps1 `
    -TorExe "C:\Tor\tor.exe" `
    -Manifest "C:\election\election-manifest.cbor" `
    -Registry "C:\election\voter-registry.cbor" `
    -Candidates "C:\election\candidate-set.cbor" `
    -VoterPublicBundle "C:\transport\voter-public-bundle.cbor" `
    -Credentials "C:\desktop-voters" `
    -Partition "desktop" `
    -CohortSize 250 `
    -OutputDir "C:\PrivateBallotLoadRuns\desktop"
```

## VPS Cohort (Host B)

```powershell
$env:TARI_BALLOT_LOAD_PASSPHRASE = "test-only passphrase"
.\RUN_DISTRIBUTED_VOTER_LOAD.ps1 `
    -TorExe "C:\Tor\tor.exe" `
    -Manifest "C:\election\election-manifest.cbor" `
    -Registry "C:\election\voter-registry.cbor" `
    -Candidates "C:\election\candidate-set.cbor" `
    -VoterPublicBundle "C:\transport\voter-public-bundle.cbor" `
    -Credentials "C:\vps-voters" `
    -Partition "vps" `
    -CohortSize 250 `
    -StartIndex 251 `
    -OutputDir "C:\PrivateBallotLoadRuns\vps"
```

The two hosts run fully independently: separate Tor processes, separate SOCKS
ports, separate run directories, separate results. The organizer intake
aggregates both cohorts.

## Legacy Manual SOCKS (backward compatible)

Advanced operators may keep the prior 500-voter-test workflow and run their
own Tor listener, passing `-TorSocks 127.0.0.1:9050` instead of `-TorExe`.
Equivalent raw CLI:

```powershell
cargo run -p tari-cc-private-ballot-cli --release -- distributed-submit `
    --manifest C:\election\election-manifest.cbor `
    --registry C:\election\voter-registry.cbor `
    --candidates C:\election\candidate-set.cbor `
    --voter-public-bundle C:\transport\voter-public-bundle.cbor `
    --credentials C:\desktop-voters `
    --tor-socks 127.0.0.1:9050 `
    --results C:\runs\desktop-250.json `
    --concurrency 1
```

Managed-Tor mode is an orchestration convenience with the SAME submission
protocol; it is not a protocol change.

## Output / Evidence

Per run, the output directory contains:

* `results.json` — `TARI_CC_PRIVATE_BALLOT_DISTRIBUTED_LOAD_REPORT_V1`
  (accepted/rejected counts, receipts, timings, expected vs observed counts).
* `results.managed-tor-metadata.json` — non-secret CLI metadata: Tor mode,
  UTC start/end, SOCKS endpoint, organizer onion hostname, Tor executable
  **basename** (never the full path), bounded `tor --version` line, and
  whether the runner stopped the Tor child.
* `run-metadata.json` — runner metadata: commit SHA, partition, cohort size,
  CLI exit status.
* On managed-Tor failure only: `results.managed-tor-runtime\run-*\` with the
  bounded `tor-stderr.log` for diagnosis.

No onion private keys, voter credentials, passphrases, API keys, or Tor
private state are ever recorded. Voter hosts never run an onion service and
never need walletd.

## Hard Safety Rules Enforced

* Tor is never bundled, downloaded, auto-installed, or looked up on `PATH`.
* Only the single validated executable path the operator supplied is used.
* No shell, no `taskkill /IM tor.exe`, no process-list scanning.
* SOCKS endpoint is always loopback; the carrier rejects anything else.
* No clearnet/relay fallback: Tor failure ⇒ run failure, nothing submitted.

## FUTURE REBASE NOTE (do not resolve until main qualification lands)

WAIT FOR MAIN LINUX QUALIFICATION BEFORE REBASING OR PHYSICAL VALIDATION.

The main Private Ballot branch is completing Linux portability qualification,
including a deterministic fix for a transport-network parallel-test
temporary-directory race. This feature branch also changes
`crates/transport-network/src/lib.rs` (shared managed-Tor primitives:
`validate_tor_executable_v1`, `reserve_loopback_socks_port_v1`,
`create_fresh_run_directory_v1`, `StderrLogFileTorSpawnerV1`), so that file is
a KNOWN REBASE HOTSPOT. After Linux qualification is committed to main, the
rebase must preserve BOTH:

1. the main-branch Linux/test-race portability fix, and
2. this branch's shared managed-Tor primitives.

Do not rebase onto main yet. Do not run the physical 250+250 validation until
the rebase onto the new main checkpoint is complete and re-qualified.
