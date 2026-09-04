# Distributed Voter Load Driver

This is controlled stress-test tooling for simulated independent voter
credentials across separate voter hosts. It does not create a new ballot
format, proof verifier, registry format, nullifier path, envelope, or
organizer intake path.

**Transport:** the driver submits each ballot through
`TorSocksPrivateReleaseCarrierV1`, the same private-transport carrier the
GUI uses for voter submissions. That carrier requires a **local Tor SOCKS
listener** on each voter host; the driver does **not** start Tor for you.
Install Tor separately on every voter host (Tor Browser or Tor Expert
Bundle — see [OPERATOR_SETUP.md](OPERATOR_SETUP.md)) and pass its SOCKS
address in `--tor-socks`.

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

Every voter host must have `tor.exe` installed and a Tor SOCKS listener
running locally before the submit call. Confirm the SOCKS port is
listening (default `127.0.0.1:9050` for Tor Expert Bundle, `127.0.0.1:9150`
for Tor Browser) before you run the CLI. The driver never spawns Tor.

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
"500-voter" physical run partitions the cohort the same way and points
each host's `--tor-socks` at that host's own local Tor SOCKS listener.

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
