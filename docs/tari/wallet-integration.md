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
| Sapient | a browser extension | `window.tari` with `isTariWallet === true` and `isEmbedded` falsy |
| Tari Universe | dApps embedded in Universe's own iframe | `window.tari` with `isTariWallet === true` and `isEmbedded === true` |

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
3. mainnet publishing stays disabled until a configured mainnet V2 template
   address exists (`MAINNET_V2_TEMPLATE_ADDRESS` in
   `gui/src/wallet/anchorDeploymentConfig.ts` is empty in this build). The
   Esmeralda template address and artifact digest are pinned from the
   verified deployment record; the two networks' configurations are kept
   separate and one is never used as a fallback for the other.

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

`deploy/indexer-proxy/` contains a Cloudflare Worker that forwards a fixed
allowlist of read-only indexer routes to a server-configured upstream. It
serves no write path, forwards no query strings, caps response size and time,
never caches, and enables CORS only for the exact server-configured origin.
With `INDEXER_UPSTREAM` unset it fails closed (503). No production deployment
was performed; see `deploy/indexer-proxy/README.md`.

## Mainnet requirements and readiness

- Publishing to mainnet is hard-disabled in this build until a mainnet V2
  template address is released and configured. The template artifact must be
  the qualified mainnet artifact (BLAKE3-256
  `6ea3448e1beae71920a5ee5ce0cf51057a135a1f3a4e05dd26717a310e076830`); the
  post-publish substitutions pending in the backend are listed in the
  deployment runbook (`templates/ootle-anchor-event-template-v2/DEPLOYMENT_RUNBOOK.md`).
- Real-wallet testing with Sapient or Tari Universe has NOT been performed in
  this task (no real transactions, no template publish, no production
  infrastructure). Before mainnet use, run the full flow once on Esmeralda
  with a real wallet: export the bundle on desktop, import it in the browser
  build, connect, approve, submit, and confirm the verified state; also
  exercise the failure paths (declined approval, network mismatch, bundle
  from a different network).
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
| `gui/src/wallet/anchorDeploymentConfig.ts` | per-network template configuration (mainnet disabled) |
| `gui/src/wallet/anchorWorkflow.ts`, `recoveryStore.ts` | fail-closed workflow gates and id-only recovery |
| `gui/src/anchor/browserAnchorPublish.ts` | publish driver (approval → submit → verify) and recovery writer |
| `gui/src/screens/anchor/BrowserAnchorPublishPanel.tsx` | the browser publish panel |
| `deploy/indexer-proxy/worker.js` | the read-only indexer proxy |
