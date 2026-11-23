# Mainnet anchor submission — release enablement runbook

Status: **enabled in source; staging deployment pending audit and operator
authorization; live Tari Universe qualification pending**. The Hosted browser
entry points ship with
`MAINNET_ANCHOR_SUBMISSION_ENABLED = true` in
`hosted-web/src/anchorSubmissionPolicy.ts`. This is a build-time constant, not a
runtime toggle: there is no browser checkbox, no storage read, and no API path
that can enable submission. The transaction guard
(`driver.createRequest` / `waitForApproval` / `submit` wrappers in
`anchorSubmissionPolicy.ts`) applies to both the public Anchor page and the
Manage Election advanced panel. Recovery paths verify only; they never submit.

## What enabling changed

- The gate is a reviewed source change plus a rebuild; it is never an operator
  UI action.
- Every publish attempt runs a **fresh non-spending fee preflight** for the exact
  canonical anchor instructions before it reserves durable recovery state or
  asks the wallet to create a request.
- The preflight must be recognized, well-formed, and fit both the required fee
  and the allowance-adjusted minimum inside `ANCHOR_MAX_FEE_UNITS = 5000`
  microTARI (0.005 TARI). Unsupported, malformed, over-cap, or provider-error
  estimates fail closed with no transaction request.
- The `maxFee` cap is sent to the wallet on every real create request. The page
  still cannot read the realized fee back from an approved request; the
  on-chain receipt check remains the terminal evidence.
- The Hosted backend response must match the election ID the operator requested
  at both `election_id` and `anchor_args.election_id`; a valid payload for a
  different election is rejected.
- A publish attempt pins one immutable bundle snapshot. Loading or importing a
  different payload invalidates the attempt before the durable reservation or
  wallet request. Changing the reduced-anonymity acknowledgement after loading
  also blocks publishing until the payload is reloaded.
- Wallet, account, provider, and network are revalidated after the dry run and
  immediately before the durable reservation / request creation.

## Live evidence

- Election: `pb-staging-browser-e2e-1795362392453` (finalized, 2 eligible,
  2 accepted, `No=2`, `Yes=0`).
- Sapient Mainnet dry run: `result.finalize.total_fees_required = 3477`
  microTARI; allowance-adjusted minimum `3489` microTARI; authorized cap
  `5000` microTARI.
- Independent archive replay: archive hash consistent, 6/6 file digests
  verified, transport binding verified, reduced anonymity `false`.
- Canonical payload verification against the archive:
  `v2_anchor_digest_hex = a6cb28b68e8e821c6257183bb16b29bc9d0e42f4e20bdc771cdf55dfd7528588`,
  template `template_ef4d7f348a4c3db7b6f9a9c30ac4fcbfdfb73e8bec59a808258861fcbbdc6cdb`,
  artifact digest `6ea3448e1beae71920a5ee5ce0cf51057a135a1f3a4e05dd26717a310e076830`.

## Prerequisites that must be complete before deployment

1. Browser-only finalization passes the staging E2E
   (`hosted_two_voter_browser_only_e2e_no_desktop`).
2. Wallet qualification covers Sapient and Tari Universe, including declined
   approval, network mismatch, and the verified path. Sapient Mainnet dry-run
   evidence is recorded; live Tari Universe qualification remains pending.
3. The fee policy is verified: a dry-run estimate for the exact anchor
   instructions is shown alongside the explicit maximum authorized fee, and the
   configured cap is confirmed against the published Mainnet template.
4. The canonical payload success path is tested end to end on staging.
5. An independent security audit approves the release.
6. The operator explicitly authorizes enabling Mainnet submission.

## Deliberate re-enable procedure (if the gate is ever disabled)

Re-enabling is a reviewed code change, never an operator UI action:

1. Confirm every prerequisite above is met and recorded.
2. Change **only** `MAINNET_ANCHOR_SUBMISSION_ENABLED` to `true` in
   `hosted-web/src/anchorSubmissionPolicy.ts`. Do not add any runtime toggle,
   storage read, or query parameter.
3. Rebuild the Hosted Web bundle (`npm run build`) and re-run the full
   `hosted-web` and `gui` suites.
4. Re-run the independent security audit on the new diff.
5. Deploy through the normal reviewed pipeline (staging first, then production
   per `docs/hosted/production-deployment-design.md`).

## Guarantees

- No path can enable submission without a code change + rebuild + audit.
- No transaction request is created unless a fresh preflight passed in the same
  publish attempt, after the exact payload loaded and the current wallet,
  account, provider, and network were pinned.
- Recovery/resume paths (`checkRecoveryUnlocked`) never submit; they verify only.
- The `driver` wrappers enforce the gate even if a future UI path forgets its
  own check.
- Desktop publishing is unaffected by this gate.
