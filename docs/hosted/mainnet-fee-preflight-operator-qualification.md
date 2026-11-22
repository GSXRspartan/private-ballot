# Mainnet anchor fee preflight — operator-assisted live wallet qualification

Status: **implementation complete; live wallet qualification NOT performed.**

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
  - `extractDryRunFeeEstimate(result)` recognizes only documented-style fee
    fields (`result.required_fees`, `requiredFees`, `finalize.required_fees`,
    `finalize.requiredFees`) as decimal strings / integers / bigints. Anything
    else resolves to `{ kind: "unsupported" }`. It never invents a figure.
  - `TariCapabilities.dryRunIsLocal` is surfaced (optional, `null` when the
    wallet does not report it).
- `gui/src/anchor/browserAnchorPublish.ts`
  - `PublishDriver.estimateFee(adapter, bundle, maxFee?)` reuses the exact
    canonical anchor instructions and calls the dry-run adapter method.
- `hosted-web/src/anchor.ts`
  - "Estimate Mainnet Fee" action, available whenever a Mainnet wallet is
    connected and the deployment is valid, **even while Mainnet submission is
    disabled**. It displays the estimated transaction fee in **TARI** (primary
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
  page reads `result.finalize.total_fees_required` (with a conservative
  `fee_receipt.total_fees_paid` fallback). A resolved dry run is a successful
  simulation; the wallet rejects on `Reject`/`AcceptFeeRejectRest`, so the page
  refuses to report a fee for a rejected simulation. All display is in TARI.

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
7. Confirm **Ask wallet to publish anchor** is still absent (submission disabled).
8. **User-rejection path:** with the gate still disabled, there is no publish
   action; to exercise a decline you must enable the gate in a **separate,
   reviewed** build (see the enablement runbook) — do NOT enable it for this
   qualification. Record that the dry run itself never prompts.

## Qualifying a REAL Web Tari Universe wallet (operator, manual)

1. Open the dApp **inside Tari Universe** (`universe.tari.mw`) so `window.tari` is
   Universe's bridge (`isEmbedded === true`). A plain tab is not Universe.
2. Repeat steps 3–8 above. Confirm the wallet is on **Mainnet** and the dry run
   is local (`dryRunIsLocal === true`).
3. In Universe, verify the app is embedded (the page's `frame-ancestors`
   includes `https://universe.tari.mw`) and the estimate behaves identically.

## What "qualified" means

A wallet is qualified only when an operator has, on that real wallet:
- confirmed the dry run never prompts and spends nothing,
- confirmed the network is Mainnet (byte-exact),
- recorded the estimate figure and units, and
- confirmed the over-cap warning and the submission-disabled state.

Until then, both wallets remain **NOT TESTED**.

## Explicit non-goals

- This change does not enable Mainnet submission.
- It does not add a runtime toggle, storage read, or query-string bypass.
- It never falls back to a live submission if a dry run fails.