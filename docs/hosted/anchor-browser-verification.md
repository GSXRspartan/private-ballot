# Anchor browser verification scope

This note defines exactly what the Hosted web Anchor page (`hosted-web/src/anchor.ts`)
verifies on its own, what it takes on trust, and what it refuses to do. It exists so
that no UI copy or audit claim overstates the guarantee.

## Summary

| Property | Verified by the browser page | Source of truth |
|---|---|---|
| Canonical public-summary encoding | **Yes** | `parseCanonicalPublicSummaryV2` re-encodes and byte-compares |
| Response internal consistency (digest, archive hash, election id, args, template) | **Yes** | `bundleIdentityError` cross-checks every field |
| Released Mainnet deployment identity (address, module, function, event topic, artifact digest) | **Yes** | `anchorDeploymentConfig.ts` constants, checked against the bundle |
| Anchor network is `mainnet` | **Yes** | `deploymentError` + `networkVerdict` |
| Wallet network is Mainnet | **Yes** | `networkVerdict(bundle.network, wallet.network)` at connect and before every action |
| Account/provider pinning | **Yes** | `windowTariProvider.pin()` + `ensurePinnedProviderIsCurrent` |
| Fee cap | **Yes (bounded, not read back)** | `maxFee` sent on `tari_createTransactionRequest`; see limitation 2 |
| On-chain anchor event / durable receipt | **Yes** | `verifyBrowserAnchorEvidence` (indexer proxy + wallet result agreement) |
| Archive-to-tally provenance (tally matches the true ballots) | **No** | Hosted backend archive replay |
| Archive hash matches an independently held archive | **No** | Hosted backend archive replay |

## 1. What is independently verified

1. **Canonical encoding.** `parseCanonicalPublicSummaryV2` parses the summary, then
   re-serializes it in the canonical key order and requires byte-for-byte equality
   with the received text. Reordered, duplicated, or extra fields are rejected.
2. **Cross-field identity.** `bundleIdentityError` requires the canonical summary,
   the outer bundle, the anchor arguments, and the response fields to agree:
   `anchorDigestHex`, `archiveHashHex`, `electionId`, `network`, template address,
   module, function, canonical event topic, and artifact digest.
3. **Deployment binding.** `deploymentError` requires the bundle to equal the single
   `current` Mainnet entry of the browser-side release registry
   (`gui/src/wallet/anchorDeploymentConfig.ts`). A superseded or historical template
   (e.g. the pre-reset Esmeralda deployment) is refused.
4. **Event topic canonicalization.** The endpoint returns the ABI binding topic
   (`tari_private_ballot_anchor_v2.<SUFFIX>`); the page converts it with the audited
   `canonicalEventTopicFromBindingTopic` to the emitted receipt topic
   (`TariPrivateBallotAnchorV2.<SUFFIX>`). Without this the receipt check would
   compare the wrong topic.
5. **Chain evidence.** `verifyBrowserAnchorEvidence` requires the indexer proxy to
   prove `network == "mainnet"` and byte 0, requires a durable receipt, and requires
   the wallet result, the transient indexer result, and the durable receipt to agree.
   A fee-only commit (`AcceptFeeRejectRest`) is never treated as success.

## 2. What is taken on trust, and why

The browser does not hold the finalized archive, so it cannot re-replay proofs or
recompute the tally. The archive-to-summary provenance is established by the Hosted
backend's canonical replay inside `build_v2_public_payload_from_verified_archive_v1`,
which is the same code the Desktop application uses. Anyone who needs to remove that
trust can download the archive from `/api/v1/elections/{id}/archive` and verify it
offline with the Desktop application.

### Recommended follow-up (not implemented here)

`crates/hosted-wasm` could expose a small export that parses a detached
`OotleAnchorPublicPayloadV2`, runs `assert_v2_public_payload_is_leak_free`, and checks
`payload.verify_digest(&Blake3HashProviderV1, expected)`. That would let the page
recompute the canonical anchor digest from the canonical summary bytes and verify it
against the digest that will go on chain — removing the last digest-level trust in the
server response. It requires rebuilding the committed WASM artifact, which is why it is
not part of this change set.

## 3. Fee policy and its limitation

- The page authorizes at most `ANCHOR_MAX_FEE_UNITS` (1000) fee units and never more
  than `ANCHOR_MAX_FEE_CEILING_UNITS` (10,000,000), mirroring the Desktop default and
  the release ceiling.
- The cap is sent to the wallet as the `maxFee` parameter of
  `tari_createTransactionRequest` (documented in `docs/tari/wallet-integration.md`);
  the **wallet** enforces it.
- **Limitation:** the provider contract exposes no way to read the fee back from an
  approved request, and there is no dry-run method. The page therefore cannot prove
  that the wallet honoured `maxFee`; it can only refuse to proceed without it and rely
  on the wallet's own approval UI plus the on-chain receipt check. Any adapter that
  silently drops `maxFee` would defeat this control. This is a provider-API gap, not a
  page-level choice, and is the reason the cap is sent on every request rather than
  only on the first.

## 4. Privacy and data handling

- The page sends only the election id to `/anchor-payload` (plus an explicit
  reduced-anonymity acknowledgement flag).
- No voter credential, invitation, organizer capability, or ballot material is read,
  stored, or transmitted by this page.
- Recovery state is stored under a key derived from the bundle digest, so a saved
  request can only ever resolve the exact transaction it was created for.