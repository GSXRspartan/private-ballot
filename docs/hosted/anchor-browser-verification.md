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
6. **Transient receipt availability.** The durable receipt is addressed by the
   transaction id and may be 404 for a short window after a funded Mainnet
   submission while the indexer syncs the receipt substate. A 404/5xx/fetch
   failure on that route is a retryable "pending" status; it never becomes
   "verified" without a valid receipt and never becomes a terminal "rejected"
   status. Once the receipt is indexed, the same saved transaction verifies
   without any resubmission. Malformed or conflicting evidence remains terminal.

See `docs/hosted/mainnet-anchor-verification-report.md` for the observed first
Mainnet transaction and its independent evidence.

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

- The page authorizes at most `ANCHOR_MAX_FEE_UNITS` (5000 microTARI) and never more
  than `ANCHOR_MAX_FEE_CEILING_UNITS` (10,000,000 microTARI), mirroring the release
  ceiling. Real Sapient Mainnet evidence measured `total_fees_required = 3477`
  microTARI; the allowance-adjusted minimum is 3489 microTARI.
- Every publish attempt runs a fresh non-spending
  `tari_signAndSubmitTransaction` dry run for the exact canonical instructions before
  reserving recovery state or creating a request. The required fee and the
  allowance-adjusted minimum must both fit the cap; unsupported, malformed, over-cap,
  or provider-error estimates fail closed with no request.
- The cap is sent to the wallet as the `maxFee` parameter of
  `tari_createTransactionRequest` (documented in `docs/tari/wallet-integration.md`);
  the **wallet** enforces it.
- **Limitation:** the provider contract exposes no way to read the realized fee back
  from an approved request. The dry run proves what the transaction should cost, not
  that the wallet honoured `maxFee` on the real request. The page therefore relies on
  the wallet's own approval UI plus the on-chain receipt check. Any adapter that
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