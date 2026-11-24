# November 2026 Tari Mainnet contest update — DRAFT (human review required)

Not posted anywhere. Factual summary for a human to review and submit.
Reviewed again on 2026-11-24: all transaction, fee, template, election and
staging claims below remain consistent with the repository evidence and the
read-only Mainnet verification report. No new funded transaction was made.

Private Ballot shipped its first real funded Tari Ootle **Mainnet** V2 anchor
from the hosted browser application using the Sapient wallet.

- **Mainnet V2 template:** `template_ef4d7f348a4c3db7b6f9a9c30ac4fcbfdfb73e8bec59a808258861fcbbdc6cdb`,
  artifact digest `6ea3448e1beae71920a5ee5ce0cf51057a135a1f3a4e05dd26717a310e076830`.
- **Election:** `pb-staging-browser-e2e-1795362392453` — a two-voter,
  `NON_BINDING_APPROVAL_PILOT` with `PUBLIC` confidentiality mode; result
  `No=2`, `Yes=0`. No larger anonymity set or binding outcome is claimed.
- **Anchor transaction:**
  `28c789e60e696a4bcfe56a4b9ff3b6b69d4c1d38deebe71273e18a80a2bf01f2`
  ([explorer](https://explorer.tari.mw/tx/28c789e60e696a4bcfe56a4b9ff3b6b69d4c1d38deebe71273e18a80a2bf01f2)).
- **Verified chain evidence:** both public Mainnet indexers served the durable
  receipt; the result was `Finalized/Commit` with a full `accept` execution
  result and a proven receipt. The exact event topic
  `TariPrivateBallotAnchorV2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2` carried
  anchor digest `a6cb28b68e8e821c6257183bb16b29bc9d0e42f4e20bdc771cdf55dfd7528588`,
  archive hash `c3112b3b6a14acbb95a3ff021e0a9ffca67df54c0d55ceef26f4e3fa040c0bd7`,
  the election id, `mainnet`, and the canonical public aggregate summary.
  Exactly one matching anchor publication was found on each indexer.
- **Fee actually paid:** 3477 µT (0.003477 TARI), within the unchanged
  5000 µT authorization cap.
- **Hosted Web lifecycle exercised:** election creation, enrollment and
  credential import, WASM Triptych proof generation, ballot submission,
  browser-only organizer finalization, authoritative transport binding,
  final archive, canonical anchor payload, fee preflight, funded Sapient
  Mainnet publication, and finalized receipt/recovery. Triptych proofs and
  archive replay are additionally covered by automated tests.
- **Staging site:** https://private-ballot-staging.ghostgate.boo
- **Public repository:** https://github.com/GSXRspartan/private-ballot
  (audited branch in PR #1).

Scope caveats to keep in the submission:

- Tari Universe integration is implemented and test-covered but **not live
  qualified** with a funded wallet.
- The browser cannot re-replay the archive; that trust is in the Hosted
  backend replay and removable by offline Desktop verification.
- Production (`ballot.ghostgate.boo`) is a design target, not deployed.
- The Desktop installer is not release-qualified; no new binary was published.
