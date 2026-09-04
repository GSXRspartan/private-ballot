# Distributed Voter Load Driver

This is controlled stress-test tooling for simulated independent voter
credentials across separate voter hosts. It does not create a new ballot
format, proof verifier, registry format, nullifier path, envelope, or
organizer intake path.

**Transport:** the driver submits each ballot through
`TorSocksPrivateReleaseCarrierV1`, the same private-transport carrier the
GUI uses for voter submissions. That carrier requires a **local Tor SOCKS
listener** on each voter host. The driver supports two mutually exclusive
ways to get one:

* **Managed Tor (`--tor-exe <absolute path to tor.exe>`)** — the CLI validates
  the executable with the SAME shared policy as the production managed-Tor
  feature, reserves a fresh loopback SOCKS port, starts an ISOLATED Tor
  process (its own DataDirectory; no onion service; no control port), waits
  for REAL SOCKS5 readiness, submits the cohort through it, and then
  stops/reaps ONLY the child it launched. Tor is NOT bundled, downloaded, or
  auto-installed; the operator supplies the executable path. If Tor fails,
  the run fails — there is no clearnet fallback.
* **Existing SOCKS (`--tor-socks <ip:port>`)** — the operator runs Tor
  themselves (the original physical 500-voter workflow) and passes the
  listener address, typically `127.0.0.1:9050`.

Supplying both is rejected as ambiguous. See
[tools/load-test/distributed/README.md](../tools/load-test/distributed/README.md)
for the per-host PowerShell runner that wraps this.

The `RUN_SCALE_QUALIFICATION.ps1` harness under `tools/load-test/` is a
different benchmark. It is an in-process integration test at a chosen
registry size and does not use Tor, walletd, or a real network. Do not
conflate the two.

## Generate A Cohort

Set a test passphrase in your shell. Do not commit it.

```powershell
$env:TARI_BALLOT_LOAD_PASSPHRASE = "test-only passphrase"
cargo run -p tari-cc-private-ballot-cli -- distributed-cohort --count 10 --out C:\distributed-election
```

Copy only `C:\distributed-election\organizer\voter-registry.cbor` to the
organizer machine. The `voters` directory contains encrypted `.tcbcred`
files and stays only on voter hosts.

## Split 5 + 5

```powershell
cargo run -p tari-cc-private-ballot-cli -- distributed-partition --credentials C:\distributed-election\voters --out C:\computer-b-voters --start-index 1 --count 5
cargo run -p tari-cc-private-ballot-cli -- distributed-partition --credentials C:\distributed-election\voters --out C:\vps-voters --start-index 6 --count 5
```

## Submit From A Voter Host

### Managed Tor (recommended)

Every voter host needs an installed `tor.exe` whose absolute path you supply
to `--tor-exe`. The driver starts, waits for, and stops an isolated Tor
process on its own; you do NOT need to open Tor first, and no fixed SOCKS
port (9050) is assumed.

The organizer must already be running the existing private intake service
(the GUI's ballot-office flow, or the `private-ballot-tor-intake`
binary) and must have shared the voter public transport bundle.

```powershell
$env:TARI_BALLOT_LOAD_PASSPHRASE = "test-only passphrase"
cargo run -p tari-cc-private-ballot-cli -- distributed-submit `
    --manifest C:\election\election-manifest.cbor `
    --registry C:\election\voter-registry.cbor `
    --candidates C:\election\candidate-set.cbor `
    --voter-public-bundle C:\transport\voter-public-bundle.cbor `
    --credentials C:\computer-b-voters `
    --tor-exe C:\Tor\tor.exe `
    --results C:\runs\computer-b-5.json `
    --choice round-robin `
    --concurrency 1
```

Or use the convenience wrapper
(`tools\load-test\distributed\RUN_DISTRIBUTED_VOTER_LOAD.ps1`) shown in the
[runner README](../tools/load-test/distributed/README.md) for desktop/VPS
examples.

### Existing SOCKS (legacy, backward compatible)

Every voter host can alternatively have a Tor SOCKS listener already running
before the submit call. Confirm the SOCKS port is listening (default
`127.0.0.1:9050` for Tor Expert Bundle, `127.0.0.1:9150` for Tor Browser)
before you run the CLI; the driver never spawns Tor in this mode.

```powershell
$env:TARI_BALLOT_LOAD_PASSPHRASE = "test-only passphrase"
cargo run -p tari-cc-private-ballot-cli -- distributed-submit `
    --manifest C:\election\election-manifest.cbor `
    --registry C:\election\voter-registry.cbor `
    --candidates C:\election\candidate-set.cbor `
    --voter-public-bundle C:\transport\voter-public-bundle.cbor `
    --credentials C:\computer-b-voters `
    --tor-socks 127.0.0.1:9050 `
    --results C:\runs\computer-b-5.json `
    --choice round-robin `
    --concurrency 1
```

Run the same command on the VPS with its credential partition and its own
results path.

For 128 + 128, use `--count 128 --start-index 1` on Computer B and
`--count 128 --start-index 129` on the VPS, or partition first into
separate directories. The 250 + 250 configuration used for the
"500-voter" physical run partitions the same way; in managed-Tor mode each
host runs its OWN independent Tor process (the driver reserves an ephemeral
loopback SOCKS port per host — never a shared 9050), and in existing-SOCKS
mode each host's `--tor-socks` points at that host's own local Tor SOCKS
listener.

Each submit also writes a non-secret
`<results>.managed-tor-metadata.json` next to the results file (Tor mode,
UTC start/end, SOCKS endpoint, organizer onion hostname, Tor executable
basename, bounded `tor --version`, and process stop status). No secrets,
onion private keys, voter credentials, or full operator paths are recorded.

## Interpret Results

Each host writes `TARI_CC_PRIVATE_BALLOT_DISTRIBUTED_LOAD_REPORT_V1` JSON
with requested count, credentials loaded, proof generation counts,
submission/receipt counts, elapsed time, average proof/submission timing,
and expected vs observed successful submission counts.

Privacy limitation: 100 simulated voters on one physical host are 100
distinct cryptographic voter credentials, not 100 independent physical
users or 100 independent Tor users. If the goal of the run is to reason
about voter anonymity rather than intake throughput, each simulated voter
must be a genuinely independent physical user with an independent Tor
circuit; that is out of scope for this driver.

## What this driver does NOT test

* It does not exercise the `RUN_SCALE_QUALIFICATION.ps1` code path — that
  is an offline cryptographic + I/O benchmark.
* It does not exercise walletd, Ootle anchor publication, or tTARI. Anchor
  publication is organizer-side and fee-bearing; it is not part of a voter
  load run.
* It does not verify the finalized archive. Run `verify_archive` after the
  organizer finalizes.
