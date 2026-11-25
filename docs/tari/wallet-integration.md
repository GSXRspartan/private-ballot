# Tari wallet integration (browser Sapient / Tari Universe)

How Private Ballot connects to a Tari wallet from a normal web browser, and how
an organizer publishes the V2 election anchor without the desktop walletd path.
The desktop (Tauri) application keeps its existing walletd-based anchor flow
unchanged; everything here is an additional browser route.

## Wallet providers

Two browser wallets speak the same `window.tari` contract; only discovery
differs. Private Ballot feature-detects capabilities and never wallet-detects.

| Wallet | Where it lives | Discovery |
|---|---|---|
| Sapient | a browser extension | `window.tari` with `isTariWallet === true`, `isEmbedded` falsy, and not the Universe bridge |
| Tari Universe | dApps embedded in Universe's own iframe | embedded provider from `window.tariUniverse`, then `window.tariProviders`, then `window.tari` |

The reviewed Universe connector intentionally publishes `tariUniverse` and
`tariProviders` as fallbacks when an extension owns or makes `window.tari`
non-writable. The browser selects an embedded provider only for the Universe
path; it will not mistake the non-embedded connector bridge for Sapient.

In a plain browser tab with neither wallet present, both adapters report an
honest "no wallet answered" state. Inside the Tauri desktop shell the browser
wallet UI is hidden entirely (`isDesktopShell()`), because the desktop
application already has its own wallet connection.

Provider contract (methods used):

- `tari_getNetwork` — network name, answerable without a connection.
- `tari_requestAccounts` — prompts for connection; the FIRST wallet interaction
  per click, and requested exactly once per click.
- `tari_getCapabilities` — capability discovery; a real Sapient refuses this
  before connection with code `4100` ("available, needs connect" — never
  treated as "no wallet").
- `tari_createTransactionRequest` — `{ kind: "instructions", instructions }`
  (plus optional `maxFee`); returns `{ requestId }` without blocking on the
  human approval.
- `tari_getTransactionRequest` — polled until the status leaves
  `pending`/`submitting`; the poll is bounded (10 minutes).
- `tari_submitTransactionRequest` — submits an approved request; returns
  `{ transactionId }`.
- `tari_getTransactionResult` — the indexer result for a submitted transaction
  (the same shape `GET /transactions/{id}/result` returns on the indexer).
- `accountsChanged` events are only observed; the page never auto-reconnects.

Error codes are mapped to bounded human text (4001 declined, 4100 needs
connect, 4200 unsupported, -32601 unrecognized, -32603 internal).

## Where it appears in the UI

- **Settings → Tari Wallet (browser)**: connection status per wallet, connect
  buttons, and the wallet's reported network. Browser mode only — the section
  is not rendered inside the desktop shell. It never displays balances, UTXOs,
  or wallet contents and never persists wallet addresses or accounts.
- **Manage Election → Tari Anchor → Advanced: publish this anchor from a
  browser wallet** (desktop only): after the V2 anchor call has been prepared
  from the verified archive, this exports the anchor bundle (see below) to the
  clipboard as JSON.
- **Manage Election → Tari Anchor** (browser only): the publish panel. It
  imports a bundle file, connects a wallet, asks the wallet to review and
  approve the anchor transaction, submits it, and verifies the on-chain anchor
  event before claiming success.

## Trust boundaries

- The organizer capability and the browser wallet account are separate
  domains. The browser page never receives organizer secrets, and the wallet
  never receives them either: no organizer credential, key, or capability is
  ever sent to `window.tari` or to the indexer proxy.
- Wallet ownership is not organizer authorization. The wallet can only move
  the organizer's own funds to pay the anchor transaction fee; every
  submission requires an explicit wallet approval prompt that the page cannot
  suppress or fake.
- No voter keys, credentials, nullifiers, ballots, or selections enter the
  anchor transaction. The transaction is exactly one instruction:
  `CallFunction(template_<address>, "publish_anchor_v2",
  [anchor_digest, network, election_id, public_summary])` — the four public
  argument strings carried verbatim from the desktop pipeline.
- The browser never re-canonicalizes anything. The desktop application, which
  has verified the final archive, builds the canonical public payload; the
  bundle carries those exact argument strings, and the browser only encodes
  them as CBOR text literals in the instruction (transaction formation, not
  canonicalization).

## The anchor bundle

A desktop export ("Export browser anchor bundle", after the anchor call is
prepared) copies a JSON document containing only public data:

```json
{
  "schemaVersion": 1,
  "network": "mainnet",
  "template": {
    "address": "template_…",
    "module": "tari_private_ballot_anchor_v2",
    "function": "publish_anchor_v2",
    "eventTopic": "TariPrivateBallotAnchorV2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2",
    "artifactDigestHex": "…"
  },
  "anchorArgs": {
    "anchorDigestHex": "…",
    "network": "mainnet",
    "electionId": "…",
    "publicSummary": "…exact canonical one-line JSON…"
  }
}
```

Import validation is strict (fail closed): schema version, address/digest hex
forms, and bounded strings. On import the workflow additionally checks:

1. the bundle's template binding matches the deployment configured for the
   bundle's network, and
2. the connected wallet's network matches the bundle's network **by byte**
   (`tari_getNetwork` name → Ootle network byte), and
3. the bundle must match the unique `Current` Mainnet V2 release entry. The
   prior Esmeralda deployment remains in the registry as `Historical` evidence
   only and can never be used as a fallback or a new publish target.

## Verification

Terminal success is never claimed without verifying the chain. After
submission the page fetches the transaction result (wallet
`tari_getTransactionResult`, or the read-only indexer proxy when configured)
and parses the indexer envelope:

- `result: "Pending"` → keep polling; nothing is resubmitted.
- `result: {"Rejected": …}` or an aborted final decision → terminal failure,
  reported as such.
- `result: {"Finalized": { final_decision: "Commit", execution_result: <base64
  CBOR> }}` → the CBOR `ExecuteResult` is decoded (a small dependency-free
  decoder, pinned byte-for-byte against Rust-generated vectors from the
  repository's tari-ootle revision) and the V2 anchor event must:
  - be emitted by the configured template address with the canonical event
    topic,
  - appear exactly once,
  - carry exactly the four metadata keys `anchor_digest_v2`, `network`,
    `election_id`, `public_summary` with exactly the bundle's values.

Any mismatch is a terminal failure. A fee-only commit (`AcceptFeeRejectRest`)
is rejected as terminal ("only the fee intent committed"). If verification
cannot conclude (network unreachable, still pending), the state stays
"unresolved" — it never resubmits.

Recovery after a page reload uses only non-sensitive identifiers (request id,
transaction id) persisted under a bundle-derived key in `localStorage`. A
saved state is re-verified against the chain on resume; the page never
recreates a wallet request or submits a second fee-bearing transaction merely
because local state was lost.

## The read-only indexer proxy

`deploy/indexer-proxy/` contains a separately configured Cloudflare Worker that forwards a fixed
allowlist of read-only indexer routes to a server-configured upstream. It
serves no write path, forwards no query strings, caps response size and time,
never caches, and enables CORS only for the exact server-configured origin.
Its staging Worker configuration is `deploy/indexer-proxy/wrangler.toml`; it
is not the organizer-capability API proxy in `hosted-web/wrangler.toml`. No
production deployment was performed; see `deploy/indexer-proxy/README.md`.

## Mainnet requirements and readiness

- Mainnet publishing resolves only the checked-in Current V2 deployment. The
  template artifact is the reviewed mainnet artifact (BLAKE3-256
  `6ea3448e1beae71920a5ee5ce0cf51057a135a1f3a4e05dd26717a310e076830`); the
  browser additionally requires the exact released template address, matching
  wallet network byte, provider capabilities, and absence of ambiguous local
  recovery before it can create a request.
- Real **Sapient** Mainnet qualification IS complete: the first anchor
  transaction `28c789e60e696a4bcfe56a4b9ff3b6b69d4c1d38deebe71273e18a80a2bf01f2`
  was funded, published and verified read-only (fee 3477 µT, within the 5000 µT
  cap). No second transaction was submitted.
- Real **Tari Universe** LIVE NON-SPENDING qualification: **PASSED
  (2026-11-25, human-observed)**. After the staging COEP/CORP repair the app
  renders inside the real wallet iframe; the wallet connected; Ootle Mainnet
  was identified; exactly one authorized account was discovered; and one
  non-spending `tari_signAndSubmitTransaction { dryRun: true }` fee quote
  succeeded on finalized election `pb-staging-browser-e2e-1795362392453`:
  estimated fee 3466 µT (0.003466 TARI), allowance-adjusted recommended
  minimum 3478 µT (0.003478 TARI), authorized maximum 5000 µT (0.005 TARI),
  release ceiling 10 TARI. The estimate was within the authorized cap. No
  approval popup, funded transaction, or new anchor occurred.
  This classification is **limited to the non-spending quote path**. Funded
  transaction authorization for Universe remains **UNQUALIFIED**: no approval
  or submit was exercised, and the provider exposes no fee read-back after
  approval, so the quote does not prove a funded execution will succeed or
  that the wallet enforces `maxFee` on-chain.
- The earlier `indexer-a.ootle.tari.com` 404 for `component_2a6b…` is not the
  reviewed Mainnet V2 template (`template_ef4d…`). A read-only GET of
  `/substates/component_2a6b…` returned HTTP 200 with a verified `Up` substate,
  while `/components/component_2a6b…` returned 404. It was a background lookup
  against an unsupported endpoint shape, not a missing anchor template and not
  a cause of the fee simulation. No source fix was required.

### Remaining non-spending Universe failure-path tests (requires the user)

A condensed operator checklist with PASS/FAIL expectations is in
`docs/release/OPERATOR_QUALIFICATION_CHECKLIST.md`.

| Check | Status |
|---|---|
| Real iframe load in Tari Universe | PASS (human, 2026-11-25) |
| Wallet connection and authorized account discovery | PASS (human, 2026-11-25) |
| Ootle Mainnet identification | PASS (human, 2026-11-25) |
| Non-spending `dryRun: true` fee simulation | PASS (human, 2026-11-25) |
| Decline connection / wallet rejection (4001) | PENDING human |
| Disconnect / `accountsChanged` clear | PENDING human |
| Reload and re-probe; no auto-connect or resubmission | PENDING human |
| Wrong-network and wrong-account protections | PENDING human |

1. Decline a connection in the wallet popup. Expected: bounded `4001` message,
   no retained "connected" state, and no automatic reconnect.
2. Disconnect in the wallet (or change the authorized account), then attempt a
   new quote. Expected: bounded `4100`/`4001` error, wallet cleared, no
   automatic request resubmission.
3. Reload the dApp inside Universe and re-probe. Expected: wallet requires a
   fresh manual connect; recovery is status-only and cannot resubmit.
4. If the user has a non-Mainnet wallet/network available, switch to it and
   attempt a quote. Expected: publishing and quoting blocked with a Mainnet
   mismatch message.
5. Stop before any "publish", "approve" or "submit" action. No funded
   transaction, no new Mainnet anchor, no recovery phrase or private key.
- The desktop walletd path is unchanged by this work. For mainnet walletd
  usage, use walletd v0.53.x in a separate environment (do not migrate or
  overwrite an existing wallet database); see the runbook for the exact
  procedure.

## Code map

| Module | Role |
|---|---|
| `gui/src/wallet/provider.ts` | the shared `window.tari` adapter (probe/connect/create/poll/submit/lookup) |
| `gui/src/wallet/network.ts` | Ootle network byte table and fail-closed network verdicts |
| `gui/src/wallet/errors.ts` | provider error taxonomy |
| `gui/src/wallet/settingsState.ts` + `browserWalletRuntime.ts` | Settings connection-card state and runtime |
| `gui/src/wallet/cbor.ts`, `cborLiteral.ts`, `executeResult.ts` | dependency-free CBOR encode/decode, pinned against Rust vectors (`gui/test/anchorVectors.generated.ts`) |
| `gui/src/wallet/verifyReceipt.ts`, `verifyPoll.ts` | indexer-envelope parsing and the V2 anchor event verifier |
| `gui/src/wallet/anchorBundle.ts` | bundle parse/validation, instruction building, desktop export composition |
| `gui/src/wallet/anchorDeploymentConfig.ts` | Current/Historical browser release registry projection |
| `gui/src/wallet/anchorWorkflow.ts`, `recoveryStore.ts` | fail-closed workflow gates and id-only recovery |
| `gui/src/anchor/browserAnchorPublish.ts` | publish driver (approval → submit → verify) and recovery writer |
| `gui/src/screens/anchor/BrowserAnchorPublishPanel.tsx` | the browser publish panel |
| `deploy/indexer-proxy/worker.js` | the read-only indexer proxy |
