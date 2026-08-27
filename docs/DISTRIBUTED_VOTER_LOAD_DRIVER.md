# Distributed Voter Load Driver

This is controlled stress-test tooling for simulated independent voter credentials across separate voter hosts. It does not create a new ballot format, proof verifier, registry format, nullifier path, envelope, or organizer intake path.

## Generate A Cohort

Set a test passphrase in your shell. Do not commit it.

```powershell
$env:TARI_BALLOT_LOAD_PASSPHRASE = "test-only passphrase"
cargo run -p tari-cc-private-ballot-cli -- distributed-cohort --count 10 --out C:\distributed-election
```

Copy only `C:\distributed-election\organizer\voter-registry.cbor` to the organizer machine. The `voters` directory contains encrypted `.tcbcred` files and stays only on voter hosts.

## Split 5 + 5

```powershell
cargo run -p tari-cc-private-ballot-cli -- distributed-partition --credentials C:\distributed-election\voters --out C:\computer-b-voters --start-index 1 --count 5
cargo run -p tari-cc-private-ballot-cli -- distributed-partition --credentials C:\distributed-election\voters --out C:\vps-voters --start-index 6 --count 5
```

## Submit From A Voter Host

The organizer must already be running the existing private intake service and must have shared the voter public transport bundle. Each voter host uses one existing Tor SOCKS endpoint.

```powershell
$env:TARI_BALLOT_LOAD_PASSPHRASE = "test-only passphrase"
cargo run -p tari-cc-private-ballot-cli -- distributed-submit --manifest C:\election\election-manifest.cbor --registry C:\election\voter-registry.cbor --candidates C:\election\candidate-set.cbor --voter-public-bundle C:\transport\voter-public-bundle.cbor --credentials C:\computer-b-voters --tor-socks 127.0.0.1:9050 --results C:\runs\computer-b-5.json --choice round-robin --concurrency 1
```

Run the same command on the VPS with its credential partition and its own results path.

For 128 + 128, use `--count 128 --start-index 1` on Computer B and `--count 128 --start-index 129` on the VPS, or partition first into separate directories.

## Interpret Results

Each host writes `TARI_CC_PRIVATE_BALLOT_DISTRIBUTED_LOAD_REPORT_V1` JSON with requested count, credentials loaded, proof generation counts, submission/receipt counts, elapsed time, average proof/submission timing, and expected vs observed successful submission counts.

Privacy limitation: 100 simulated voters on one physical host are 100 distinct cryptographic voter credentials, not 100 independent physical users or 100 independent Tor users.
