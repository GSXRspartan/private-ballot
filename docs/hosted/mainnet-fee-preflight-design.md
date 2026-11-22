# Mainnet wallet fee preflight design (design only — NOT wired into submission)

Status: **design + investigation**. This document records the investigation into
using the wallets' documented `dryRun` to estimate the fee of the exact anchor
transaction, and the preflight design that would show an estimate + explicit
maximum before approval. It does **not** enable Mainnet submission:
`MAINNET_ANCHOR_SUBMISSION_ENABLED` stays `false`, and the transaction guard
(`hosted-web/src/anchor.ts`) still blocks `createRequest`/`submit` for both
Sapient and Web Tari Universe.

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

The fee reference specifies the exact estimation contract:

> Submit a transaction as a **dry run** and the engine meters it exactly as it
> would for real, but never aborts for insufficient payment. Read
> `FinalizeResult::required_fees()` from the result and use it as the `max_fee`.

`required_fees() = total_fees_required + FEE_ESTIMATE_ALLOWANCE` (12 µT). The
wallet's dry-run response carries the finalized result; `required_fees()` is the
authoritative figure to map onto `maxFee`. The dry-run estimate does **not**
depend on the exhaust-burn rate, so it is stable across the burn-rate schedule.

All fees are in microtari (µT); 1 TARI = 1,000,000 µT. The configured anchor
cap is `ANCHOR_MAX_FEE_UNITS = 1000` µT with a release ceiling of
`ANCHOR_MAX_FEE_CEILING_UNITS = 10_000_000` µT (10 TARI).

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

## 5. Preflight design (NOT wired)

When submission is eventually enabled, the anchor page would, before creating a
request:

1. Feature-detect `dryRunIsLocal` (or fall back gracefully if unsupported).
2. Call `tari_signAndSubmitTransaction` with the exact anchor instructions,
   `maxFee = ANCHOR_MAX_FEE_UNITS` (string), and `dryRun: true`.
3. Parse the finalized result and read `required_fees()` (µT).
4. Display both the **estimated fee** and the **explicit maximum authorized
   fee** (`ANCHOR_MAX_FEE_UNITS`) before the user approves the real request.
5. If `required_fees()` exceeds `ANCHOR_MAX_FEE_UNITS` but is within
   `ANCHOR_MAX_FEE_CEILING_UNITS`, refuse to proceed automatically and require an
   explicit operator decision to raise the cap (a deliberate, reviewed action —
   never a silent fallback).
6. If `required_fees()` exceeds the ceiling, refuse outright.

**Never** silently fall back to an unbounded fee. The dry run is a quote only;
the real submission still goes through `tari_createTransactionRequest` with an
explicit `maxFee`, and the existing on-chain receipt verification remains the
terminal check.

## 6. Is the 1,000 µT default sufficient?

Per the fee table, a single `CallFunction` instantiates the anchor template
(~150–200 µT instantiation) plus storage/substate-create for the event and
receipt. The fee reference notes a four-call transaction pays ~600–800 µT of
instantiation alone; the anchor is a single `CallFunction`, so 1,000 µT is
plausible but tight. The preflight in §5 is what determines sufficiency for the
real template; until a real dry run against the published Mainnet template is
performed, 1,000 µT must be treated as unqualified. The release ceiling
(10,000,000 µT) bounds any authorized increase.

## 7. Qualification status

- **DRY-RUN FEE ESTIMATION:** UNSUPPORTED (design only; not wired; no live
  wallet qualification performed).
- **MAX FEE ENFORCEMENT:** UNVERIFIED (provider contract cannot prove it; no
  real-wallet test).
- **Submission:** remains disabled (`MAINNET_ANCHOR_SUBMISSION_ENABLED = false`).