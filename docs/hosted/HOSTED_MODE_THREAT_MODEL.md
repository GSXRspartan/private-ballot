# Hosted Mode Threat Model (Phase 9)

Hosted/Web Mode is a **different privacy profile**, not an anonymous mode. It is easier to adopt (zero-install, browser-accessible) at the cost of network-metadata privacy.

## Actors

| Actor | Capability | Assumption |
|---|---|---|
| Voter browser | Creates ballot envelopes, Triptych proofs | Trusted for the voter's own secrets |
| Cloudflare (edge + Tunnel) | TLS terminator, WAF, rate limiting, caching | May observe connection metadata (timing, IP-derived, request sizes); must not see ballot plaintext (TLS + browser-side cryptography) |
| Hosted frontend (static/Worker) | Delivers UI + WASM | Untrusted for secrecy; all sensitive ops run in the browser |
| VPS backend (`private-ballot-hosted`) | Routes envelopes, serves packages, Ootle adapter | May be malicious; must never need ballot plaintext to accept/route a ballot |
| VPS operator | Controls the VPS + Ootle wallet/indexer | May be curious/malicious; backend verification must catch invalid envelopes |
| Ootle wallet/indexer | Anchor publication, receipt reads | Trusted for finality only when receipts verify; indexer reads are verified (`IndexerTrust::Verify` posture) |
| Election organizer | Defines election, publishes packages | May be malicious toward voters; clients verify election binding independently |
| Network observer | Sees Cloudflare edge traffic | Sees HTTPS metadata, not Tor-level anonymity |
| Malicious client | Submits arbitrary envelopes | Backend independently verifies all cryptographic/election invariants |
| Malicious backend | Alters/replays envelopes | Browser clients verify receipts, tallies, and anchors independently |
| Malicious organizer | Equivocates election packages | Package hashes/registry binding detect equivocation |

## Core principles

1. **The hosted backend must NEVER need ballot plaintext to accept or route a ballot.** It stores and forwards opaque envelopes only.
2. **Sensitive operations run in the browser where technically possible** (proof generation, nullifier construction, envelope creation) — see `BROWSER_PORTABILITY.md`. Secrets never leave the browser to “avoid a WASM port.”
3. **Content privacy ≠ network-metadata privacy.** The cryptography (Triptych, nullifiers, deterministc tally, verifiable anchors) preserves ballot secrecy. It does **not** provide network anonymity: Cloudflare/VPS may observe timing and IP-derived metadata. Desktop/Tor Mode provides stronger network anonymity; Hosted Mode explicitly trades it for accessibility.
4. **Hosted Mode is not anonymous** and must never be marketed as “equally anonymous.” The UI must disclose the tradeoff before first use (see `docs/architecture/DUAL_MODE_ARCHITECTURE.md`).

## Content privacy (preserved)

- Ballot choices, voter credentials, Triptych witness material, wallet keys.
- Enforced by: browser-side cryptography, opaque envelopes (`docs/hosted/HOSTED_API_V1.md`), no-secret logging rules, storage model that forbids plaintext (`docs/hosted/HOSTED_STORAGE_MODEL.md`).
- Verified by: archive verification + anchor verification, both client-runnable.

## Network-metadata privacy (weakened — disclosed)

- IP address (as seen by Cloudflare), connection timing, request sizes, access patterns.
- Mitigations available (rate limiting, no-cache on ballots/receipts, graceful degradation) do not restore Tor anonymity. A user who needs network anonymity must use Desktop/Tor Mode.

## What the backend can do (and how it is caught)

| Backend attack | Detection |
|---|---|
| Accept an invalid ballot envelope | Independent cryptographic verification (Stage 2) — the backend itself must reject invalid envelopes; clients additionally verify tallies/archives |
| Silently alter voter intent | Envelope is signed/encrypted in the browser; alteration breaks verification and receipt binding |
| Bind an election to the wrong template | Deployment registry `CURRENT` check + ABI/hash verification (client-side) |
| Replay / duplicate | Idempotency keys, nullifier uniqueness, append-only semantics (Stage 2) |
| Censor valid ballots | Client receipt + organizer comparison (same as Tor mode) |

## Non-goals

- No anonymous-hosting claim.
- No server-side ballot decryption.
- No Cloudflare-specific cryptography in the domain core (see `CLOUDFLARE_VPS_ARCHITECTURE.md`).
- No production ballot ingestion in Stage 1 (skeleton only).
