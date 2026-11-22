# Mainnet anchor submission — release enablement runbook

Status: **submission disabled**. The Hosted Anchor page ships with
`MAINNET_ANCHOR_SUBMISSION_ENABLED = false`
(`hosted-web/src/anchor.ts`). This is a build-time constant, not a runtime
toggle: there is no browser checkbox, no storage read, and no API path that can
enable submission. The transaction guard (`driver.createRequest` /
`waitForApproval` / `submit` wrappers in `anchor.ts`) throws for both Sapient
and Web Tari Universe while the gate is false, so publish, recovery, and any
future UI path fail closed.

## Why it is disabled

- The provider contract exposes no fee read-back and no dry-run method on the
  transaction-request trio, so `maxFee` enforcement cannot be proven from the
  page (see `docs/hosted/mainnet-fee-preflight-design.md`).
- Real-wallet qualification (Sapient + Tari Universe) has not passed.
- The browser trusts the Hosted backend for archive-to-tally provenance; that
  trust model must be explicitly accepted for a Mainnet release
  (see `docs/hosted/anchor-browser-verification.md`).

## Prerequisites to enable (ALL required)

1. Browser-only finalization passes a real staging E2E
   (`hosted_two_voter_browser_only_e2e_no_desktop` + a live staging run).
2. Wallet qualification passes for **both** Sapient and Tari Universe,
   including declined approval, network mismatch, and the verified path.
3. The fee policy is verified: a dry-run estimate for the exact anchor
   instructions is shown alongside the explicit maximum authorized fee, and the
   configured `ANCHOR_MAX_FEE_UNITS` is confirmed sufficient against the
   published Mainnet template (or deliberately raised within
   `ANCHOR_MAX_FEE_CEILING_UNITS`).
4. The canonical payload success path is tested end to end on staging.
5. An independent security audit approves the release.
6. The operator explicitly authorizes enabling Mainnet submission.

## Deliberate enablement procedure (release-controlled)

Enabling is a reviewed code change, never an operator UI action:

1. Confirm every prerequisite above is met and recorded.
2. Change **only** `MAINNET_ANCHOR_SUBMISSION_ENABLED` to `true` in
   `hosted-web/src/anchor.ts`. Do not add any runtime toggle, storage read, or
   query parameter.
3. Rebuild the Hosted Web bundle (`npm run build`) and re-run the full
   `hosted-web` and `gui` suites.
4. Re-run the independent security audit on the new diff.
5. Deploy through the normal reviewed pipeline (staging first, then production
   per `docs/hosted/production-deployment-design.md`).

## Guarantees

- No path can enable submission without a code change + rebuild + audit.
- Recovery/resume paths (`checkRecoveryUnlocked`) never submit; they verify only.
- The `driver` wrappers enforce the gate even if a future UI path forgets its
  own check.
- Desktop publishing is unaffected by this gate.