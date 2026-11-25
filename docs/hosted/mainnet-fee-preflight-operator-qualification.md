# Mainnet anchor fee preflight — operator-assisted live wallet qualification

Status: **implementation complete; real Sapient Mainnet dry-run evidence recorded;
live Tari Universe qualification NOT performed.**

This document describes the non-spending Mainnet fee preflight added to the
Hosted Anchor page, and the operator-assisted procedure to qualify it against a
**real** Sapient extension and a **real** Web Tari Universe wallet. No mock or
simulated test in this repository constitutes live wallet qualification.

## What was implemented

- `gui/src/wallet/provider.ts`
  - `WindowTariProvider.signAndSubmitTransactionDryRun(instructions, maxFee?)`
    calls `tari_signAndSubmitTransaction` with `dryRun: true` and a
    decimal-string `maxFee`. It never calls `tari_createTransactionRequest`,
    `tari_getTransactionRequest`, or `tari_submitTransactionRequest`.
  - `extractDryRunFeeEstimate(result)` reads the evidence-backed field
    `result.finalize.total_fees_required` as a decimal string / integer /
    bigint. Anything else resolves to `{ kind: "unsupported" }`. It never
    invents a figure.
  - `TariCapabilities.dryRunIsLocal` is surfaced (optional, `null` when the
    wallet does not report it).
- `gui/src/anchor/browserAnchorPublish.ts`
  - `PublishDriver.estimateFee(adapter, bundle, maxFee?)` reuses the exact
    canonical anchor instructions and calls the dry-run adapter method.
- `hosted-web/src/anchor.ts`
  - "Estimate Mainnet Fee" action, available whenever a Mainnet wallet is
    connected and the deployment is valid. Every publish attempt also runs the
    same preflight internally before creating a request. It displays the
    estimated transaction fee in **TARI** (primary
    denomination), the maximum authorized fee in TARI, the release fee ceiling in
    TARI, an over-cap warning in TARI, and an explicit caveat that the estimate
    neither proves a funded transaction will succeed nor proves the wallet enforces
    `maxFee`. Protocol µT values are shown only in parentheses for operators.
    `gui/src/wallet/feeFormat.ts` does exact bigint integer formatting (no float).

## Documented contract and its limits

- `tari_signAndSubmitTransaction { instructions, maxFee?, inputs?, dryRun? }`
  — with `dryRun: true` it **never prompts and spends nothing**
  (https://universe.tari.com/reference/fees/ and the Universe integration docs).
- `tari_getCapabilities().dryRunIsLocal: boolean` — the wallet's statement that
  dry runs never leave the wallet (Sapient currently reports `false`; dry runs
  round-trip to the indexer's `/transactions/dry-run`).
- **Actual Sapient dry-run schema (evidence: chironbuilds/tari-wallet @ master):**
  the provider resolves to `{ transaction_id, result }` where `result` is an
  `ExecuteResult`. The authoritative fee is **`result.finalize.total_fees_required`**
  (a decimal STRING in microTARI). All bigints are stringified by the wallet's
  `sanitizeForMessage`. The engine name `required_fees()` is NOT on the wire; the
  page reads **only** `result.finalize.total_fees_required` and requires an
  explicit `Accept` outcome. It deliberately does NOT fall back to
  `fee_receipt.total_fees_paid` and fails closed as unsupported when the
  authoritative field is absent. A resolved dry run is a successful simulation;
  the wallet rejects on `Reject`/`AcceptFeeRejectRest`, so the page refuses to
  report a fee for a rejected simulation. All display is in TARI.

## Qualifying a REAL Sapient wallet (operator, manual)

1. Install the Sapient browser extension (Chrome/Brave/Edge) and create/unlock a
   wallet. Ensure it is on **Mainnet** (`tari_getNetwork` → `mainnet`).
2. Fund it with enough TARI to cover the fee cap (start on a test deployment with
   test funds; never risk mainnet funds for the first dry run).
3. Open `https://<staging-host>/anchor.html`, load a **finalized** election, and
   confirm the bundle reads `mainnet · publish_anchor_v2 · template_ef4d…`.
4. Click **Connect Sapient**. Approve the connection in the extension. Confirm the
   page shows the account and `Mainnet`.
5. Click **Estimate Mainnet Fee**. The wallet receives a `dryRun: true`
   `tari_signAndSubmitTransaction`. **It must not prompt for approval and must
   not move funds.** Confirm in the wallet's own history that no transaction was
   created.
6. Record exactly what the page displays in **TARI**: the estimated transaction
   fee, the maximum authorized fee, the release fee ceiling, and whether an
   over-cap warning appears. If the page shows "Fee estimate unavailable", capture
   the wallet's actual `result` JSON (devtools → the `tari_signAndSubmitTransaction`
   response) so the extractor can be extended.
7. Confirm **Ask wallet to publish anchor** appears after a valid bundle and
   Mainnet wallet connection. Do not click it for a dry-run-only qualification.
8. **User-rejection path:** click publish in a reviewed build and decline the
   wallet approval. Confirm the page reports the rejection and never calls
   submit. The dry run itself must never prompt.

## REAL Web Tari Universe (operator, manual) — live result

Human-observed on 2026-11-25 after the staging COEP/CORP iframe repair:

1. The dApp rendered inside the real Tari Universe iframe — **PASS**. A plain
   tab still reports "Not running inside Tari Universe" by design.
2. Wallet connected, Ootle Mainnet identified, and exactly one authorized
   account detected — **PASS**.
3. Non-spending fee preflight on finalized election
   `pb-staging-browser-e2e-1795362392453` — **PASS**: one
   `tari_signAndSubmitTransaction { dryRun: true }`, no approval popup.
   Observed: estimated 3466 µT (0.003466 TARI), allowance-adjusted minimum
   3478 µT (0.003478 TARI), authorized maximum 5000 µT (0.005 TARI), release
   ceiling 10 TARI; the estimate was within the authorized cap.
4. The live `dryRunIsLocal` boolean was **not recorded** by the operator. The
   adapter reads that capability and the official docs state dry runs never
   prompt and spend nothing, but the observed value remains unrecorded.
5. **No fee read-back:** the Universe provider exposes no post-approval fee
   read-back. The quote therefore does not prove funded execution will succeed
   and does not independently verify that the wallet enforces `maxFee`. The
   UI states this caveat explicitly (`hosted-web/src/anchor.ts`).

## What "qualified" means

Two distinct classifications are kept separate:

- **LIVE NON-SPENDING QUALIFIED (Tari Universe, 2026-11-25):** a human observed
  real iframe loading, wallet connection, Mainnet identification, authorized
  account discovery, and a successful non-spending `dryRun: true` fee quote
  within the 5000 µT cap. This is the classification used in the release matrix.
- **FUNDED TRANSACTION AUTHORIZATION QUALIFIED: NO for Tari Universe.** No
  approval, submit, or on-chain fee read-back was exercised. The separate
  Sapient funded qualification (real 3477 µT transaction) is unchanged.

The remaining human failure paths — declined connection (4001), disconnect and
`accountsChanged`, reload/re-probe, wrong network and wrong account — are still
pending observation. Adapter logic was audited and focused regressions were
added; those checks do not replace human browser evidence.

## Explicit non-goals

- No runtime toggle, storage read, or query-string bypass is added.
- A failed or unsupported dry run never falls back to a live submission.
- A stale displayed quote never authorizes a new request; every publish attempt
  re-runs the preflight.