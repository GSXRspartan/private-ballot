# Local Hosted Mode Quickstart (Stage 2)

Run the full locally-runnable hosted prototype on one machine: backend +
browser frontend + synthetic election. All commands from the repo root.
Use the MSVC toolchain on Windows (`$env:RUSTUP_TOOLCHAIN="stable-x86_64-pc-windows-msvc"`,
`$env:CARGO_TARGET_DIR="C:\pb-target"`).

## 1. Build backend

    cargo build -p tari-cc-private-ballot-hosted --bin private-ballot-hosted

## 2. Build browser WASM + frontend

    wasm-pack build crates/hosted-wasm --target web --out-dir ../../hosted-web/src/wasm --release
    npm --prefix hosted-web install
    npm --prefix hosted-web run build

WASM output (`hosted-web/src/wasm/`) is generated and git-ignored; rebuild
it after any `crates/hosted-wasm` change.

## 3. Generate synthetic election (local demo ONLY)

    cargo run -p tari-cc-private-ballot-hosted --example synthetic_demo -- C:\pb-target\synthetic-demo.json

This prints/imports election `hosted-synthetic-001` with synthetic voter
secrets (scalars 1, 2, 3 hex). NEVER use these for a real election.

## 4. Start backend (localhost only, default 127.0.0.1:8788)

    $env:PRIVATE_BALLOT_HOSTED_DB="C:\pb-target\hosted.db"
    $env:PRIVATE_BALLOT_HOSTED_ADMIN_TOKEN="local-demo-token"
    C:\pb-target\debug\private-ballot-hosted.exe

Import the synthetic election (from another shell):

    curl -X POST http://127.0.0.1:8788/api/v1/admin/elections/import \
      -H "content-type: application/json" -H "x-admin-token: local-demo-token" \
      -d '{"election_id":"hosted-synthetic-001","manifest_cbor_hex":"...","registry_cbor_hex":"...","candidate_cbor_hex":"..."}'

(Use the hex values from the demo JSON; a scripted alternative is the e2e
test below.)

## 5. Start frontend

    npm --prefix hosted-web run dev

Open http://127.0.0.1:5173, load `hosted-synthetic-001`, generate a
credential, choose a candidate, create the ballot locally, review, submit.

## 6. Automated end-to-end (recommended)

    node hosted-web/scripts/e2e.mjs C:\pb-target\synthetic-demo.json C:\pb-target\debug\private-ballot-hosted.exe

Runs: import -> public package -> browser WASM proof -> submit -> exact
retry (same stable receipt) -> distinct same-nullifier rejection -> voter B
-> malformed/tampered/wrong-election rejection -> close -> finalize ->
results -> archive. The Rust test
`end_to_end_hosted_flow_and_desktop_archive_verifier` additionally writes
the archive to disk and verifies it with the existing Desktop verifier
(`verify_archive_directory_v1`): DESKTOP VERIFIER = PASS.

## Organizer controls (localhost admin, token-gated)

- Import: `POST /api/v1/admin/elections/import`
- Close: `POST /api/v1/admin/elections/{id}/close`
- Finalize: `POST /api/v1/admin/elections/{id}/finalize`

Admin routes are token-gated when `PRIVATE_BALLOT_HOSTED_ADMIN_TOKEN` is
set and must be blocked at the Cloudflare edge in Stage 3 (they are only
reachable on loopback by default). There is no public admin panel.

## Privacy

See the on-page notice and `docs/hosted/HOSTED_MODE_THREAT_MODEL.md`.
Hosted Mode is NOT anonymous; Desktop/Tor Mode remains the network-anonymity mode.
