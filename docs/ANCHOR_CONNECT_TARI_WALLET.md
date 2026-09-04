# Connect Tari Wallet — Anchor UX simplification

Author: 2026-08-29 · Scope: Private Ballot desktop shell.

## What changed for a normal organizer

* **Before**: on every launch the organizer had to open PowerShell and
  export `WALLETD_AUTH_TOKEN=…` before running the app, otherwise the
  Publish Tari Anchor path failed with a bearer error.
* **After**: the organizer clicks **Connect Tari Wallet** once, pastes
  the walletd API key issued by their Tari Wallet's own web UI, and
  never sees the token again. Subsequent launches read the key from
  OS-backed secure storage (Windows Credential Manager / macOS Keychain
  / Secret Service) and auto-attach it to the publish step.

## Boundary contract

* The raw walletd API key **never** leaves the shell layer. It never
  crosses into gui-core, into the anchor config, into snapshots,
  evidence, election archives, logs, error strings, or any Tauri
  command return value. The `connect_walletd` / `reconnect_walletd`
  commands take it as a write-only argument; the only credential-facing
  return type is `WalletdCredentialStatusV1`, which carries presence
  and metadata only.
* All buffers holding raw key material are `Zeroizing<String>` — heap
  allocations are wiped on drop.
* Env-var path (`WALLETD_AUTH_TOKEN`) is retained solely as a dev/CI
  fallback. It is consulted only when the OS store has no credential.

## Commands added

| Command | Purpose |
|---|---|
| `walletd_credential_status` | Presence + store name; never the key. |
| `connect_walletd` (arg: `key`) | Store or replace the credential. |
| `reconnect_walletd` (arg: `key`) | Alias — same action as `connect`. |
| `forget_walletd` | Remove the credential (idempotent). |

Existing `run_live_anchor_lifecycle_step` now resolves the walletd
bearer via `walletd_credential_store::load()` (OS store → env-fallback)
instead of reading the env directly.

## Files touched

* `gui/src-tauri/Cargo.toml` — add `keyring = "3"`
  (Windows / macOS native features only).
* `gui/src-tauri/src/walletd_credential_store.rs` — new module.
* `gui/src-tauri/src/lib.rs` — module registration, four commands,
  publish-step credential resolution, handler wiring.
* `gui/src/api/types.ts` — `WalletdCredentialStatusV1`.
* `gui/src/api/client.ts` — four API bindings.
* `gui/src/screens/ManageElection.tsx` — Connect / Reconnect / Forget
  panel replacing the misleading env-var checkbox; auto-attach when a
  credential is present.
* `gui/src/styles/global.css` — panel styling.

## What was intentionally NOT changed

Everything covered by the memory line
`ootle-anchor-security-remediation`:

* Archive re-verification, privacy floor, endpoint policy, publish
  lock, template deployment binding, receipt semantics, anchor digest
  algorithm — unchanged.
* Hosted Esmeralda indexer default — unchanged
  (`https://ootle-indexer-a.tari.com/`).
* Walletd loopback-only endpoint contract — unchanged
  (`http://127.0.0.1:5100`).
* Trusted `TariPrivateBallotAnchor` deployment — unchanged.
* Managed walletd — deliberately NOT implemented; see
  `ANCHOR_WALLETD_AUTOSTART_INVESTIGATION.md`.
