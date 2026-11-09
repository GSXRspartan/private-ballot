# Private Ballot: Two Deployment Modes (Phase 18)

## PRIVATE BALLOT DESKTOP / TOR — strongest privacy

- **Local application** (Tauri GUI + local core). Offline-first.
- **Network anonymity via Tor:** managed/external Tor transport, SOCKS-only onion routing, no OS DNS for onion traffic, no clearnet fallback (see `DESKTOP_PRIVACY_INVARIANTS.md`).
- **Current qualified mode.** This is the mode delivered by `origin/main` and preserved by Stage 1.
- **Cryptography:** ballot cryptography and election verification are fully client-verifiable.

## PRIVATE BALLOT HOSTED / WEB — future zero-install mode

- **Browser-accessible,** frontend hosted through Cloudflare, backend on a Linux VPS behind Cloudflare Tunnel (`docs/hosted/CLOUDFLARE_VPS_ARCHITECTURE.md`).
- **Cryptographic ballot privacy preserved:** the server never sees plaintext; proofs, nullifiers, and envelopes are created in the browser (`docs/hosted/HOSTED_MODE_THREAT_MODEL.md`).
- **Lower network-metadata privacy:** Cloudflare/VPS may observe connection metadata (timing, IP-derived). This tradeoff is disclosed in the UI before first use.
- **Status:** **not production-ready.** Stage 1 delivers the architecture, threat model, API design, storage model, browser-portability assessment, and a localhost skeleton (`crates/hosted`). No hosted ballot ingestion exists yet.

## What not to claim

- Do not call Hosted Mode “equally anonymous,” “Tor-equivalent,” or “private” without the metadata qualifier.
- Do not market unfinished Hosted Mode as production-ready.
- Do not describe Hosted Mode as anonymous unless a future measurement proves it.

## Choosing a mode

Users who need network anonymity use Desktop/Tor. Users who prioritize zero-install accessibility choose Hosted knowing the metadata tradeoff. Both modes verify the same archives and anchors with the same domain core, so an election can be *created* in one mode and *verified* in the other — the verification result is identical; only the network path differs.
