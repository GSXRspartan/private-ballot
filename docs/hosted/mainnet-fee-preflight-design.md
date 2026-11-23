# Mainnet wallet fee preflight (adapter and mandatory per-publish gate implemented)

Status: **adapter implemented; preflight wired; submission enabled in source;
staging deployment pending audit and operator authorization.** This document
records the investigation into using the wallets' documented `dryRun` to
estimate the fee of the exact anchor transaction, and the mandatory preflight
that runs before every request creation. `MAINNET_ANCHOR_SUBMISSION_ENABLED` is
`true` in `hosted-web/src/anchorSubmissionPolicy.ts`; the transaction guard
blocks `createRequest`/`submit` if the gate is false.

The non-spending dry-run adapter (`signAndSubmitTransactionDryRun`) and the
"Estimate Mainnet Fee" UI are implemented and unit-tested; see
`mainnet-fee-preflight-operator-qualification.md` for the operator procedure to
qualify a real wallet. Real Sapient Mainnet dry-run evidence is recorded below.
The mocked tests are not a substitute for the remaining live qualification.

## 1. What the official integration documents say

Source: `https://universe.tari.mw/integration/` and
`https://universe.tari.com/reference/fees/`.

- `tari_signAndSubmitTransaction` accepts `{ instructions, maxFee?, inputs?, dryRun? }`
  and returns `{ transactionId, result }`. With `dryRun: true` it **never prompts
  and spends nothing**; it returns a quote for pricing.
- `tari_createTransactionRequest` is the persistent request trio
  (`create` → `getTransactionRequest` poll → `submitTransactionRequest`). It
  **prompts** (opens the approval) and does not block on it. This is what the
  current anchor page uses.
- Capabilities expose `dryRunIsLocal` ("dry runs never leave the wallet").
- Both Sapient (extension) and Tari Universe (web wallet) implement the full
  surface, including the transaction-request trio and `dryRun`.
- `maxFee` is documented as a **decimal string** in every example
  (`maxFee: "5000"`, `maxFee: "100000"`). The adapter now sends the documented
  string form (see §4).

## 2. Dry-run response format and the required fee field

The fee reference specifies the engine-level estimation contract:

> Submit a transaction as a **dry run** and the engine meters it exactly as it
> would for real, but never aborts for insufficient payment. Read
> `FinalizeResult::required_fees()` from the result and use it as the `max_fee`.

At the **engine** level, `required_fees() = total_fees_required + FEE_ESTIMATE_ALLOWANCE`
(12 µT). However, the **wallet JSON response does not expose `required_fees()`** — that
is an engine/TS-binding name on `FeeCostBreakdown`, not on the `ExecuteResult` returned
to a dApp. Evidence from `chironbuilds/tari-wallet` (master): a dry run resolves to
`{ transaction_id, result }` where `result.finalize` is a `FinalizeResult` whose fee
field is **`total_fees_required`** (a decimal STRING in microTARI; all bigints are
stringified by the wallet's `sanitizeForMessage`). The extractor reads
`result.finalize.total_fees_required`, with a conservative `fee_receipt.total_fees_paid`
fallback. A resolved dry run is a successful simulation; the wallet rejects on
`Reject`/`AcceptFeeRejectRest`, so a rejected simulation never yields a fee estimate.

All user-facing display is in **TARI** (`gui/src/wallet/feeFormat.ts`, exact bigint
integer formatting); protocol accounting stays in integer µT. 1 TARI = 1,000,000 µT.
The dry-run estimate does **not** depend on the exhaust-burn rate, so it is stable
across the burn-rate schedule.

All fees are in microtari (µT); 1 TARI = 1,000,000 µT. The configured anchor
cap is `ANCHOR_MAX_FEE_UNITS = 5000` µT (0.005 TARI) with a release ceiling of
`ANCHOR_MAX_FEE_CEILING_UNITS = 10_000_000` µT (10 TARI). The engine adds a
12 µT `FEE_ESTIMATE_ALLOWANCE` to a dry-run's `total_fees_required` to derive the
recommended `max_fee` (`FEE_ESTIMATE_ALLOWANCE_UNITS = 12`).

**Real Sapient Mainnet evidence (finalized two-voter election
`pb-staging-browser-e2e-1795362392453`):** `result.finalize.total_fees_required
= 3477 µT`. The allowance-adjusted minimum is 3477 + 12 = **3489 µT**. The 5000 µT
cap sits safely above that while remaining far below the 10 TARI ceiling.

## 3. What dry-run does and does NOT establish

- **DOES establish:** a fee estimate for the exact instructions, metered by the
  engine, with no spend and no approval prompt. It can be mapped to the
  transaction-request workflow as a preflight quote before
  `tari_createTransactionRequest`.
- **Does NOT establish fee-cap enforcement.** A dry run proves what the
  transaction *should* cost; it does not prove that a given wallet release
  refuses to submit a request whose realized fee exceeds `maxFee`. Fee-cap
  enforcement still depends on the wallet honoring the `maxFee` parameter on the
  real `tari_createTransactionRequest` / `tari_signAndSubmitTransaction` call.
  The provider contract exposes **no fee read-back** and no dry-run method on
  the transaction-request trio, so the page cannot prove post-approval that the
  wallet honored `maxFee`.

## 4. Schema correction applied

The adapter previously forwarded the numeric cap verbatim
(`params.maxFee = 1000`). The documented schema is a decimal string. The publish
driver now stringifies the cap before calling the wallet
(`gui/src/anchor/browserAnchorPublish.ts`), and a regression test
(`gui/test/browserAnchorPublish.test.ts`) pins `maxFee: "1000"`. Desktop callers
that pass no cap are unchanged.

## 5. Mandatory per-publish preflight (wired)

Both Hosted browser entry points (`anchor.ts` and the Manage advanced panel in
`browserAnchor.ts`) call `runMandatoryFeePreflight` before they reserve durable
recovery state or create a wallet request:

1. Call `tari_signAndSubmitTransaction` with the exact canonical anchor
   instructions, `maxFee = ANCHOR_MAX_FEE_UNITS` (string), and `dryRun: true`.
2. Read `result.finalize.total_fees_required` and normalize it as exact integer
   microTARI.
3. Compute the allowance-adjusted minimum as `required + 12` microTARI.
4. Refuse to proceed unless both values fit inside `ANCHOR_MAX_FEE_UNITS`
   (5000 microTARI). Unsupported, malformed, over-cap, or provider-error
   estimates fail closed with **no reservation and no transaction request**.
5. Revalidate the pinned wallet, account, provider, and network after the dry
   run and immediately before the durable reservation.
6. Send the same explicit `maxFee` on the real
   `tari_createTransactionRequest`.

The displayed quote is informational. A stale displayed estimate can never
authorize a publish: every publish attempt runs the preflight again, and any
wallet/account/network/payload/acknowledgement change clears the displayed
estimate.

**Never** silently fall back to an unbounded fee. The dry run is a quote only;
the real submission still goes through `tari_createTransactionRequest` with an
explicit `maxFee`, and the existing on-chain receipt verification remains the
terminal check.

## 6. Is the 5,000 µT default sufficient?

Per the fee table, a single `CallFunction` instantiates the anchor template
(~150–200 µT instantiation) plus storage/substate-create for the event and
receipt. The fee reference notes a four-call transaction pays ~600–800 µT of
instantiation alone; the anchor is a single `CallFunction`. **Real Sapient
Mainnet dry-run evidence** for a finalized two-voter election measured
`total_fees_required = 3477 µT`; with the 12 µT allowance the recommended
`max_fee` is **3489 µT**. The 5000 µT cap exceeds that with headroom and stays
far below the 10 TARI ceiling. Actual funded sufficiency still requires a live
funded-wallet test.

## 7. Qualification status

- **DRY-RUN FEE ESTIMATION:** IMPLEMENTED and verified against real Sapient
  Mainnet dry-run evidence (`total_fees_required = 3477` microTARI); display is
  in TARI.
- **MAX FEE ENFORCEMENT:** PROVEN at the engine level (a funded `maxFee` becomes a
  `pay_fee(maxFee)` payment; the engine commits in full only if `total_charges <=
  maxFee`, else `AcceptFeeRejectRest`/`Reject`; unused fee is refunded) but NOT
  proven for a specific live funded transaction — requires a live funded-wallet
  test.
- **MANDATORY PREFLIGHT:** IMPLEMENTED for both Hosted browser entry points;
  blocks reservation and request creation unless a fresh estimate is recognized
  and fits the 5000 microTARI cap.
- **Submission:** enabled in source
  (`MAINNET_ANCHOR_SUBMISSION_ENABLED = true`); staging deployment pending
  independent audit and operator authorization.