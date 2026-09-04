# Private Ballot — Controlled-Alpha Release Notes

**Channel:** Controlled alpha (trusted, supervised operators only). **Not** public
testnet beta. Do not distribute publicly.

## Highlights

- Organizer + voter GUI with the guided private-ballot flow and independently
  verifiable finalized archives.
- **V1 Ootle anchor**: read-only Prepare with field-specific preflight, walletd
  account auto-fill, and cross-screen form persistence. Publish remains a
  manual, explicitly-approved step through the operator's own walletd.
- **V2 public anchor**: richer public payload (aggregate counts, commitments,
  tally, template binding) reduced to an on-chain **digest + detached evidence**;
  an active leak guard rejects any per-voter data or local paths in the payload.
- **Production transport authority**: real operator public-root loading; default
  and release builds **fail closed** when unconfigured. The default Tauri
  release additionally enables the `managed-tor` feature so the organizer's
  in-process private-intake service can issue a self-signed per-election
  transport authority; that self-signed path is separate from the
  production-authority public-pin path in
  `docs/transport/PRODUCTION_TRANSPORT_AUTHORITY_PROVISIONING_V1.md`, and
  neither one is a fallback for the other.

## Security posture

- No secrets, private keys, or bearer tokens in the tree.
- V2 public payload is aggregate-only; no nullifiers, receipts, or individual
  ballot packages.
- Anchor is a public transparency/commitment record — it does **not** by itself
  prove ballot validity or tally correctness (see runbook §11–§12).

## Known limitations / not included

- No key ceremony/custody tooling; no production private signer; no real-Tor
  collector production binding; no signed pin distribution manifest.
- No managed walletd — operators run their own Tari Ootle wallet daemon.

See [CONTROLLED_ALPHA_RUNBOOK.md](CONTROLLED_ALPHA_RUNBOOK.md) for operation and
[§13](CONTROLLED_ALPHA_RUNBOOK.md#13-remaining-blockers-before-public-beta) for
the public-beta blockers.

## Verification gates (this build)

- Frontend: `npm test` 730/730 pass; `tsc --noEmit` clean.
- Rust: workspace `--lib` check clean; Tauri shell `--lib` check clean.
- gui-core lib 135/135; V1 preflight, V2 anchor, archive writer/verifier,
  production-authority, and transport-gateway (`managed-tor`) suites green.
- V2 template WASM builds reproducibly; digests recorded in the package checklist.
