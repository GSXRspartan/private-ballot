# Private Ballot — Operator Setup

This document is for a technically competent operator who wants to run
Private Ballot for the first time. It is not a build manual: if you want to
build from source, see the top-level [README](../README.md) and
[docs/CONTROLLED_ALPHA_PACKAGE_CHECKLIST.md](CONTROLLED_ALPHA_PACKAGE_CHECKLIST.md).

Status: v0.1.0 Alpha, Esmeralda testnet. Independent Open-Source Project;
not affiliated with or endorsed by Tari Labs. Not for binding governance,
treasury, charter, or legal decisions.

## Quick start

Choose the role you are here to perform:

| Role | You need |
| --- | --- |
| A. Organizer (ballot office) | Private Ballot installer, an installed `tor.exe`, an installed Tari Ootle `walletd` (only if you want to publish the optional public anchor), enough tTARI to pay the anchor transaction fee. |
| B. Voter | Private Ballot installer, an installed `tor.exe`. No walletd, no tTARI. |
| C. Developer / load tester | Everything an organizer needs, plus the Rust toolchain pinned in `rust-toolchain.toml`, Node.js/npm for the frontend, and (on Windows) MSVC BuildTools + vcpkg. |

The rest of this document walks each of these through step by step.

## Downloads

Every external component below is installed by the operator, not by the
Private Ballot installer. Nothing else is downloaded silently.

| Component | Where to get it | Verify | Required for |
| --- | --- | --- | --- |
| Private Ballot | GitHub Release (MSI, NSIS setup, or portable `.exe`) once one is published, or a source build. | Compare the release-asset `SHA256SUMS` against your own `Get-FileHash` before running the installer. | Organizer, Voter, Developer |
| Tari Ootle `walletd` | Upstream Tari Ootle project (v0.39.2 is the currently pinned Esmeralda-compatible release). Get it from the official tari-project distribution channel. | Compare SHA-256 against the value published by upstream. | Organizer (only if publishing an anchor) |
| Tor | [Tor Browser](https://www.torproject.org/download/) or the [Tor Expert Bundle](https://www.torproject.org/download/tor/). Either provides an unmodified `tor.exe`. | Compare SHA-256 against the value published on `torproject.org`. On Windows, also confirm the digital signature. | Organizer (private intake) and Voter (private submission). Not required for developer scale benchmarks. |
| tTARI (Esmeralda testnet TARI) | The current Tari Esmeralda testnet faucet or your existing testnet balance. | n/a | Organizer, only for publishing the optional Ootle anchor. |
| MSVC Build Tools, vcpkg, Node.js, Rust `1.97.1-x86_64-pc-windows-msvc` | Vendor sites. | Vendor-published checksums. | Developer only. |

If you are just voting, you only need the Private Ballot installer and
`tor.exe`.

## A. Organizer setup

### A1. Install Private Ballot

Run the release MSI or NSIS setup, or place the portable `.exe` somewhere
you control. First launch creates a per-user data directory under
`%LOCALAPPDATA%` and initialises an empty workspace. No election is created
until you drive **Create election** in the app.

### A2. Install Tor

Private Ballot does not bundle `tor.exe`. Install Tor separately:

1. Download the Tor Expert Bundle (recommended for organizer machines
   because it does not launch a browser UI) or Tor Browser.
2. Verify the download's SHA-256 and, on Windows, the digital signature.
3. Extract / install to a stable absolute path you will not delete, e.g.
   `C:\Program Files\Tor Expert Bundle\tor\tor.exe`.

Private Ballot needs the absolute path to `tor.exe`. It never resolves
`tor` from `PATH`, never scans the disk, and never downloads Tor for you.

### A3. Configure Tor in the app

Open the app, choose the ballot-office workflow, and provide the absolute
`tor.exe` path in the Tor configuration panel. On first use the path is
validated (must be an absolute path to a real regular file, no symlinks, no
control characters) and stored in the app's local config; you will not be
asked again unless the file moves. The application then launches Tor as a
child process with:

* a fresh per-run `DataDirectory` under the app's `%LOCALAPPDATA%` scratch,
* a per-run ephemeral loopback SOCKS port (organizer intake uses SOCKS `0` and
  a `HiddenServicePort` mapping to a fixed virtual port 80),
* a persistent hidden-service key directory under the app's private-tor
  storage.

The app never writes to your Tor installation directory, never modifies your
`torrc`, and never edits `PATH` or environment variables outside its own
process.

### A4. Verify Tor bootstrap and intake readiness

After you start the ballot-office intake, the app shows a live status card:

* Starting Tor — child process spawned.
* Waiting for hidden-service hostname — Tor is bootstrapping and building
  the onion descriptor.
* Ready — the hidden-service hostname is available and the collector is
  serving `/v1/opaque-envelope` (private ballot submissions) and
  `/v1/election-status` (read-only status).

If Tor fails to bootstrap, the app classifies the failure into a bounded
error (`GUI_TOR_START_FAILED`, `GUI_TOR_DATADIR_LOCKED`, and similar) so you
can fix the underlying condition without reading Tor logs.

### A5. Install and start walletd (only if you want to publish an anchor)

Anchor publication is optional. You can complete an entire pilot without
walletd; the finalized archive is the authoritative verification artifact.

If you do want a public Ootle anchor:

1. Install Tari Ootle `walletd`. The currently pinned Esmeralda-compatible
   version is `0.39.2`.
2. Start `walletd` on the Esmeralda network with its JSON-RPC endpoint on
   loopback. The application expects the endpoint at
   `http://127.0.0.1:5100/json_rpc` (the `/json_rpc` route is required —
   a bare host URL is not the RPC endpoint).
3. In walletd's own web UI, create or select an organizer account and issue
   an API key with the minimum permissions the app requests (see the app's
   **Connect Tari Wallet** panel; the permission list is displayed there).
4. Fund the account with enough tTARI on Esmeralda to pay the anchor
   transaction fee.
5. In Private Ballot, click **Connect Tari Wallet** and paste the API
   key. The key is stored in your OS credential store (Windows Credential
   Manager / macOS Keychain). It never crosses into `gui-core`, never appears
   in the election archive, never appears in evidence sidecars, and never
   appears in log output. You will not be asked for it again.
6. Confirm the app shows the walletd account and network in the anchor
   panel. The default indexer is
   `https://ootle-indexer-a.tari.com/`; you may override this to your own
   indexer if you run one, subject to the network policy the app enforces.

To rotate the key, click **Reconnect walletd**. To remove it, click
**Forget walletd**. Both are idempotent and never leak the key.

### A6. Publish the anchor (optional)

After the election is finalized:

1. Run **Verify archive** to confirm the finalized archive is well-formed
   and self-consistent.
2. Open the anchor panel. Preflight validates the operator configuration and
   reports a specific `GUI_LIVE_ANCHOR_*` or
   `GUI_PRODUCTION_TRANSPORT_AUTHORITY_*` code if anything is off.
3. Run V1 **Prepare** (read-only) or drive V2 **Prepare → Submit → Confirm**
   as documented in the runbook. See
   [templates/ootle-anchor-event-template-v2/DEPLOYMENT_RUNBOOK.md](../templates/ootle-anchor-event-template-v2/DEPLOYMENT_RUNBOOK.md).

## B. Voter setup

### B1. Install Private Ballot

Same installer as the organizer. First launch initialises an empty
workspace.

### B2. Install Tor

Same as A2. Voter machines need their own `tor.exe`. Voter machines do
**not** need walletd, do not need tTARI, and do not touch the Ootle chain.

### B3. Load the election package

The organizer distributes a public election package (manifest, candidate
set, voter registry, and voter-public transport bundle) plus your issued
voter credential. Import each of these through the app.

### B4. Cast a ballot over Tor

1. Choose a route (managed Tor is the private-by-default route).
2. Configure `tor.exe` (same absolute-path picker as the organizer flow).
3. Prepare the ballot.
4. Submit. The submission goes to the organizer's onion hidden service over
   your local Tor SOCKS listener; the local OS never resolves the `.onion`
   hostname.
5. Keep your receipt and credential private.

## C. Developer / load-test setup

### C1. Toolchain

* Rust: install the pinned Windows MSVC toolchain
  `1.97.1-x86_64-pc-windows-msvc`.
* Node.js: any current LTS suitable for the Tauri 2 frontend toolchain.
* Windows: MSVC BuildTools + vcpkg with triplet `x64-windows-static-md`
  and the `openssl` vcpkg port installed.

The build recipe is in the [README](../README.md).

### C2. Frontend and Rust tests

```powershell
cd gui
npx tsc --noEmit
npm test
```

```powershell
cargo +stable-x86_64-pc-windows-msvc test --workspace --features test-support
```

### C3. Scale-qualification benchmark (no Tor)

`tools/load-test/RUN_SCALE_QUALIFICATION.ps1` runs an in-process integration
test at a chosen registry size (50, 100, 500, 1000, 2048, 4096) against
per-run OS-temp scratch. It measures cryptographic and archive throughput.
It does **not** use Tor, does not open a network socket, and does not talk
to walletd or the Ootle chain.

```powershell
.\tools\load-test\RUN_SCALE_QUALIFICATION.ps1 -Voters 500
```

### C4. Physical multi-machine voter load driver (uses Tor)

`docs/DISTRIBUTED_VOTER_LOAD_DRIVER.md` describes the CLI-based physical
multi-machine driver used to produce results like the "500-voter run" (250
voters on a desktop + 250 voters on a VPS + one organizer). The voter host
uses the existing `distributed-submit` subcommand of
`tari-cc-private-ballot-cli` and requires a **local Tor SOCKS listener** on
each voter host (default `--tor-socks 127.0.0.1:9050`). The driver never
starts Tor for you — you install and start `tor.exe` yourself (Tor Expert
Bundle or Tor Browser), then point the driver at its SOCKS port.

## What Private Ballot does not bundle

The current installer does **not** include:

* `tor.exe` — every organizer, voter, and physical-multi-machine load-test
  host installs Tor separately.
* `walletd` — organizers publishing anchors install walletd separately.
* tTARI — obtain testnet TARI from the current Esmeralda faucet.
* The Ootle indexer — the app defaults to the hosted
  `https://ootle-indexer-a.tari.com/` unless you point it elsewhere.
* Rust, Node.js, MSVC BuildTools, vcpkg — developer prerequisites only,
  never used by a normal operator.

If a future release changes any of the above (for example, by adding an
official companion Tor bundle), it must be recorded in
[../THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) before the release
ships.

## Troubleshooting

Short pointer list; the app itself surfaces specific machine codes for most
of these.

* Tor path rejected → the path must be an absolute path to a real regular
  file; symlinks and reparse points are rejected.
* `GUI_WALLETD_ACCOUNTS_UNAVAILABLE` after connecting → walletd is running
  but the API key does not have the requested account permissions, or the
  endpoint URL is missing the `/json_rpc` route.
* `GUI_TRANSPORT_ARCHIVE_BINDING_REQUIRED` on finalize → no production
  transport authority is configured. See
  [docs/transport/PRODUCTION_TRANSPORT_AUTHORITY_PROVISIONING_V1.md](transport/PRODUCTION_TRANSPORT_AUTHORITY_PROVISIONING_V1.md).
* Anchor preflight error `GUI_LIVE_ANCHOR_OPERATOR_CONFIG_INVALID` → the
  preflight now reports a specific code per field; read the code, not the
  category.

For anything not covered here, see the full runbook in
[docs/CONTROLLED_ALPHA_RUNBOOK.md](CONTROLLED_ALPHA_RUNBOOK.md) and the
threat-model notes under [docs/transport/](transport/).
