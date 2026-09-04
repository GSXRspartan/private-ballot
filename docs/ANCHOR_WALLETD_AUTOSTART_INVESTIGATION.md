# Walletd auto-launch — investigation (Phase 8)

Author: 2026-08-29 · Scope: Private Ballot desktop shell + pinned
Ootle v0.39.2 walletd.

This report answers the Phase 8 questions from the "Connect Tari Wallet
UX" task. It is **investigation only** — no walletd lifecycle code has
been added or changed by this report.

## 1. Classification

**REQUIRES SIGNIFICANT ARCHITECTURAL WORK — NOT RECOMMENDED for the
current milestone.**

The path is technically feasible but the safety envelope needed to make
it a normal-user default is large. The evidence for that classification
is below.

## 2. How v0.39.2 tari_walletd starts

* Binary: `applications/tari_walletd` (workspace crate in the Ootle repo).
* Entry point: `main.rs::main()`.
* Config: layered `tari_common` file (`config.toml`) + CLI overrides in
  `applications/tari_walletd/src/cli.rs`. Key fields:
  * `network` (`esmeralda`, `mainnet`, …)
  * `authentication` = `None` | `WebAuthn`
  * `json_rpc_address` (default not published; the current app expects
    `127.0.0.1:5100`)
  * `indexer_api_url`
  * `webauthn.rp_id` / `webauthn.rp_origin`
  * `override_keyring_password` — an optional password used to encrypt
    the wallet's own SDK-owned material when the OS keyring is not
    available.
* Persistent state (`config.to_data_dir()`, i.e. `base_path/data/`):
  * `wallet.sqlite` — the SQLite wallet store
  * `pid` — an advisory pid file written by `main.rs`
  * `burn_proofs/`
  * (see `SqliteWalletStore::try_open` — no advisory OS lock on Windows;
    SQLite's own file locking is the only guard)
* The **wallet's own encryption password** is normally stored in the OS
  keyring by the walletd process itself (`init_os_keyring_store()` at
  `applications/tari_walletd/src/lib.rs`, using
  `windows_native_keyring_store::Store::new()` on Windows). If the
  keyring is unavailable, walletd requires `--password` /
  `override_keyring_password`.

## 3. Concurrent access is unsafe by default

* No `flock` / advisory PID guard prevents a second walletd process from
  opening the same `wallet.sqlite`. SQLite's own busy-timeout gives
  short-window serialisation, not exclusion.
* The `pid` file is written on startup and removed on clean shutdown
  (see `main.rs:248`). On a crash it goes stale; walletd does not use
  it to refuse a start.
* Result: two walletd processes pointed at the same `base_path` will
  race on `wallet.sqlite` and can corrupt or lose transactions.

## 4. What Private Ballot could detect today

By probing `http://127.0.0.1:5100`:

* `auth.get_method` (unauthenticated) tells us whether a walletd is
  running and which auth mode it is in.
* `indexer.get_status` / `wallet.get_summary` with our stored bearer
  tells us whether we can authenticate.
* No supported API tells us **which** walletd we reached — we cannot
  distinguish "the user's own walletd" from "an unrelated walletd on
  the same port". The port alone is the identity.
* If the port is bound but rejects our probe, we cannot tell whether it
  is starting, wrong-network, or somebody else's process.

## 5. Managed-sidecar options considered

### A. Use an already-running user walletd (**status quo**)

* Pros: no lifecycle to own; the user chooses the network, data-dir,
  and auth mode; user-installed walletd version stays authoritative.
* Cons: user must start walletd themselves (double-click / shortcut /
  service). Nothing to automate.
* This is what today's app assumes.

### B. Start a dedicated Private-Ballot walletd sidecar

* Pros: one-click launch; user never has to open a terminal.
* Cons — safety envelope required before this is a normal default:
  1. **Version pin**. The bundled walletd binary must match the app's
     pinned `dd1d731…` revision or the JSON-RPC / event contract may
     drift. This forces us to redistribute walletd, keep it up to date
     during security releases, and sign it in our installer.
  2. **Dedicated data dir**. Must be a Private-Ballot-owned
     `base_path` (e.g. `%LOCALAPPDATA%/tari-private-ballot/walletd/`)
     that we NEVER share with the user's own walletd, to keep the
     wallet database exclusive and to avoid touching a wallet with
     other funds.
  3. **Exclusivity gate**. Before spawning, verify the target port is
     free AND (via an advisory file lock we own inside the sidecar
     data-dir) that no other Private-Ballot sidecar is up. Refuse
     the start if either check fails.
  4. **Ownership boundary**. We may kill only the pid we spawned,
     recorded in-memory. Never a global "kill walletd" (would trash
     the user's other wallets). On startup, if the sidecar data-dir's
     lock file records a live pid we did not spawn, refuse to start;
     surface a "recover walletd sidecar" screen.
  5. **Auth bootstrap**. Even a bundled walletd cannot self-mint an
     API key: `handle_create_api_key` is `authorize_user_only` (rejects
     `tw_`-prefixed bearers), so an interactive session is required.
     Two sub-options:
     - Spawn walletd in `WalletDaemonAuth::None`. This is the
       simplest, but any other process running as the user can then
       drive the sidecar with no credential at all. Not acceptable
       for a wallet holding TARI.
     - Spawn walletd in `WebAuthn` mode. Then the user still has to
       do the same "open walletd web UI in a real browser → register
       a passkey → mint an API key → paste into Private Ballot"
       dance on first use, at which point the *only* thing we saved
       compared to today's UX is the walletd install step.
  6. **Wallet lifecycle**. A dedicated sidecar means Tari Private
     Ballot now owns a wallet database. Backup, recovery, funding,
     wallet-password lifecycle, and re-provisioning all become our
     UX problem, not the user's Tari Wallet's problem.
  7. **stdout/stderr / logging**. We must handle the walletd process's
     stdout/stderr without letting them into our own logs (a stray
     seed print in walletd would be catastrophic), and never expose
     the child's stderr in our GUI.
  8. **Shutdown**. We must cleanly stop the sidecar on app quit AND
     on unclean quit (Job Object on Windows / process group on Unix).
     Job Object support is not currently wired into the Tari Private
     Ballot Tauri shell (see [`organizer-tor-hardkill-recovery`]
     memory note; the same limitation applies to managed walletd).
  9. **Upgrade story**. When Private Ballot pins a new Ootle
     revision, the sidecar binary bundled in the installer changes,
     and the on-disk `wallet.sqlite` schema may need a
     forward-migration. That's a shipping and support burden.

### C. Support both (auto-detect existing, fall back to sidecar)

* Combines the cons of A and B, plus a decision UI ("your walletd on
  5100 is a different version; use it, replace it, or spawn ours?").
  Very high UX and support cost for a feature the current user base
  can already work around by starting walletd once.

## 6. Isolated Private-Ballot-only wallet?

* `WalletDaemonConfig::network` and `base_path` fully isolate one
  walletd instance from another. There is no shared account/keys
  concept across walletd instances in v0.39.2.
* So option B could in principle run its own account with its own
  funds, distinct from the user's primary Tari wallet. But:
  * The user still has to fund that isolated account to publish an
    anchor. That is not a UX simplification — it is a new step
    ("send TARI from your Tari Wallet to the Private Ballot
    wallet").
  * A dedicated sidecar wallet with a separate seed is another
    backup target the user must not lose.

## 7. Recommendation

Keep option A (already-running user walletd) as the current path.
Investment in option B should wait until:

1. Ootle upstream provides a supported programmatic API-key
   bootstrap that a non-browser process can complete (removing the
   WebAuthn RP-origin blocker), **OR**
2. Ootle upstream provides a lightweight "publish-only" wallet mode
   whose auth surface is scoped enough that `WalletDaemonAuth::None`
   on loopback is defensible.

Until then, the Connect Tari Wallet + OS credential-store path
implemented in this task removes the operator's PowerShell burden
without owning any walletd lifecycle. Adding option B on top later
is additive.

## 8. If you decide to implement option B anyway

The exact proposed architecture I would want to review before
writing code:

1. New crate `crates/managed-walletd` with a `ManagedWalletdHandle`
   pattern mirroring the existing `ManagedTor` design.
2. Data dir: `%LOCALAPPDATA%/tari-private-ballot/walletd/{network}/`.
3. Advisory file lock in that data dir (`walletd.lock` with pid);
   startup path refuses on stale-lock without operator
   acknowledgement.
4. Config always writes `authentication = WebAuthn`,
   `json_rpc_address = 127.0.0.1:5100`, `enable_permissive_cors =
   false`, `rp_id = "localhost"`.
5. Child is spawned with `CREATE_NO_WINDOW` on Windows and attached
   to a Job Object marked kill-on-job-close so app crash cleans up.
6. Stdout/stderr routed to a rotating file in the sidecar data-dir;
   NEVER surfaced in our own logs or GUI.
7. On first launch after install, open the walletd Web UI at
   `http://localhost:5100/` in the user's real browser (the only
   context where WebAuthn can succeed) with a Private Ballot
   panel that instructs them to register a passkey and mint an API
   key, then paste it back into Connect Tari Wallet.
8. Never kill walletd based on port occupancy; only via our tracked
   pid.

This is at least 2–3 focused slices of work (managed-walletd crate,
installer changes, lifecycle UX). It is out of scope for the
Connect-Tari-Wallet UX task.
