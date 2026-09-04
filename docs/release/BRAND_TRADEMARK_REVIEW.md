# Brand / Trademark Review — Private Ballot

Status: HUMAN DECISION RECORDED (2026-09-03). This document records the
project's current use of Tari and Ootle brand terms/assets and the
maintainer's decision for the initial public release.

## Position (recorded decision)

Private Ballot is an **independent open-source project**. It is **not
affiliated with or endorsed by Tari Labs**. The word "Tari" has been
removed from the current public product name; the disclaimer wording used
in the app (`gui/src/branding/identity.ts`) and in public docs is:

> Private Ballot is an independent open-source project.
> It is not affiliated with or endorsed by Tari Labs.

The software may potentially be adopted officially in the future, but that
is not the current status and must not be represented as such. Do not
claim trademark approval, official endorsement, or "Official Tari X",
"Powered by Tari", or "Tari-approved" without a separate written
statement from the trademark holder.

## Current uses of protected/associated terms

- Public product name: **Private Ballot** — the word "Tari" is deliberately
  not part of the current public product identity.
- The word **Tari** still appears as a factual technical integration term
  wherever it accurately describes the underlying technology — e.g.
  "Tari Ootle", "Tari Ootle walletd", "Tari Ootle indexer", "Tari
  Triptych", and the "Tari Project" BSD-3-Clause attribution.
- The word **Ootle** appears extensively in code and documentation to name
  the Tari Ootle runtime this project publishes optional public anchors to
  (`crates/ootle-*`, `templates/ootle-anchor-event-template-v2/`, etc.).
- Historical, protocol-critical identifiers such as
  `TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_PUBLIC_V2`,
  `TARI_CC_PRIVATE_BALLOT_V2_ANCHOR_EVIDENCE_V1`,
  `TARI_CC_PRIVATE_BALLOT_V2_ANCHOR_LIFECYCLE_V1`,
  `tari_private_ballot_anchor_v2`, `TariPrivateBallotAnchorV2`,
  the existing on-chain module/function/topic identifiers, canonical
  hashing frame prefixes, and archive/evidence schema tags are treated as
  **stable protocol identifiers**. They are frozen and must not be renamed
  merely for branding, because changing them would break canonical bytes,
  digest computation, existing archive verification, and the currently
  deployed V2 Ootle template.
- Internal Cargo package names in the workspace (`tari-cc-private-ballot-*`)
  remain unchanged for v0.1.0-alpha to avoid a repository-wide dependency
  edit that would balloon scope; the public product surface never renders
  these names to a normal user.

## Framing

The visible app strings, `README.md`, and public setup documentation now
consistently name this an **Independent Open-Source Project**, currently
qualifying on **Esmeralda testnet** at **Alpha** maturity. `SECURITY.md`
and `docs/SECURITY_MODEL.md` continue to qualify it as non-binding
governance pilot software.

## Artwork

- `gui/src-tauri/icons/`: multiple icon files. Only artwork already derived
  from the approved Private Ballot design reference (see
  `gui/design/private-ballot-logo-reference.png`) is treated as the
  application identity; the official Tari logo is not used as the
  application identity. If any tray/installer icon still needs a source of
  origin recorded, capture it here before a public release.
- In-app Guide diagrams under `gui/src/assets/guide/` are original project
  work unless a specific file is annotated otherwise.

## Recorded decisions

1. Public product name: **Private Ballot** (Tari removed from the product
   identity).
2. Status label: **Independent Open-Source Project** (replaces the earlier
   "Community Project" wording everywhere it was public-facing).
3. Tari and Tari Ootle references remain as descriptive technical
   integration references; nothing implies Tari Labs endorsement.
4. Protocol identifiers, event topics, hashing prefixes, template CBOR
   metadata, archive/evidence schemas, and canonical test vectors are
   frozen — treated as historical stable identifiers, not as public
   branding.
5. The already-deployed and qualified V2 anchor template
   (`template_f49e19743d7f9a92f7c675619412ce2b50efe55514ee9012f2e9cdab25f8e214`,
   SHA-256
   `022beeaea7805775192623c87970c03cd384732b37666d1d95a79a967fa44d49`,
   BLAKE3
   `475421a448be977dbf13c37d91b0ed9ef9c4d43f75da438ec64ea9cff38c66cc`)
   is not rebuilt or republished for this branding pass. Public release
   packaging **does** publish the exact same bytes under a generic
   Private Ballot filename (`private_ballot_ootle_anchor_v2.wasm`) — a
   file rename only, with both hashes verified unchanged. See
   [docs/CONTROLLED_ALPHA_PACKAGE_CHECKLIST.md](../CONTROLLED_ALPHA_PACKAGE_CHECKLIST.md#release-asset-filename-bytes-must-remain-identical).
6. `%LOCALAPPDATA%\Tari Private Ballot\anchor-state\...` and the equivalent
   macOS/Linux paths remain unchanged for v0.1.0-alpha to avoid orphaning
   existing V2 evidence/lifecycle sidecars on operator machines.

This review does not authorize any trademark use; it just records the
maintainer's current, considered position.
