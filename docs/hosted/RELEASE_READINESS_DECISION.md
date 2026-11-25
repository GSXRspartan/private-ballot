# Release readiness decision — current state (2026-11-24)

This supersedes earlier "blocked" notes in this file. Those notes described the
state before the staging deployment and recovery qualification completed.

## Verified milestones

| Area | Status | Evidence |
|---|---|---|
| Hosted staging security deployment | COMPLETE | Worker `f8015e7c-3796-4613-b995-9517a4d4d8dd`; backend SHA-256 `799cc1cfcd9f198980e58cbd18893b8cc99ab4a3267b5617b2f1bbe66e1a1e5e` (built from `6df3088`); `docs/hosted/BACKEND_SECURITY_DEPLOYMENT_2026-11-24.md` |
| First Mainnet V2 anchor | COMPLETE | Transaction `28c789e60e696a4bcfe56a4b9ff3b6b69d4c1d38deebe71273e18a80a2bf01f2`, fee 3477 µT, `Finalized/Commit`, exact event verified by both indexers |
| Sapient real-wallet path | QUALIFIED LIVE | Funded Mainnet publication and receipt recovery completed; no second transaction submitted |
| Web Tari Universe (non-spending) | QUALIFIED LIVE | Real iframe, wallet connection, Mainnet, one authorized account, one `dryRun: true` quote of 3466 µT (≤ 5000 µT cap); no approval or submit; `docs/tari/wallet-integration.md` |
| SQLite v7 backup/recovery | QUALIFIED | `cebdff9`; 18/18 script regressions, isolated restore drill with byte-identical API responses; `docs/hosted/STAGING_RECOVERY_QUALIFICATION.md` |
| Source security fixes in this branch | MERGE-READY | Hard rate-map cap + registry-scrub fail-closed + tests; stale schema constant removed; no production `expect()` in anchor encoder; scoped PR CI added |

## Gate decisions

- **A — merge source to `main`: READY.** The full PR diff was independently
  reviewed against `origin/main`. No Critical or High code findings remain.
  The previously identified unbounded rate-map growth and fail-open enrollment
  scrub were real defects and are fixed with regression tests in this branch.
  One unwired legacy React panel (`BrowserAnchorPublishPanel.tsx`) still calls
  the publish driver without a fee preflight; it has no import in the shipped
  app and is explicitly guarded by `isDesktopShell()`. It is deferred cleanup,
  not a shipped bypass.
- **B — hosted staging release: READY.** The staging deployment is live and
  validated, and the two reviewed backend corrections were rebuilt from
  `6df3088` and deployed at 20:09 UTC. Public election/archive/anchor/receipt
  responses remained byte-identical to the pre-swap baseline. No further
  staging redeploy is required for the currently reviewed source.
- **C — Windows Desktop installer release: NOT READY.** Compilation, installer
  build, launch smoke and 105/105 Rust tests pass, but the 13-step manual
  organizer/voter workflow has never been executed. Installers are unsigned,
  and organizer transport secrets remain plaintext at rest (MEDIUM-1).
- **D — dedicated production deployment: NOT READY.** All previously listed
  production prerequisites remain open: distinct Worker/route/origin token,
  isolated database, key-custody ceremony, monitoring and alerting, live
  Universe funded-transaction authorization (non-spending qualification is
  complete), independent audit sign-off and explicit operator authorization,
  Desktop release qualification, and privacy/security sign-off.
  The Mainnet transaction capability is intentionally present in reviewed
  source and must not be enabled in production before those gates close.

## Release-readiness matrix

| Track | Status | Evidence / remaining gate |
|---|---|---|
| Hosted Staging | READY (live) | Worker + backend hashes above; health 200; admin paths 404; edge hardening active; reviewed backend fixes deployed 20:09 UTC |
| Sapient | READY (live) | One real Mainnet anchor, exact receipt verification, fee 3477 µT ≤ 5000 µT cap |
| Web Tari Universe | LIVE NON-SPENDING QUALIFIED | Human-observed iframe load, connect, Mainnet, one account and one `dryRun: true` quote (3466 µT ≤ 5000 µT cap); FUNDED authorization NOT qualified; rejection/disconnect/reload/network/account paths pending human |
| Windows Desktop | NOT RELEASE-READY | 105/105 Rust, 1147/1147 node, `tsc` clean, launch smoke pass; manual 13-step workflow, unsigned installer and plaintext transport secrets outstanding |
| GitHub Main | READY TO MERGE PR #1 | Reviewed source, no Critical/High findings, scoped PR CI added; do not merge automatically without operator decision |
| Dedicated Production | NOT READY | Design only; no deployment, no DNS, no authority keys, no production database |

## Live wallet qualification (Web Tari Universe)

A real Universe wallet connection has now been performed and the non-spending
path is qualified. The human operator observed the app rendering in Universe's
iframe, wallet connection, Ootle Mainnet, one authorized account, and one
`dryRun: true` fee quote of 3466 µT (0.003466 TARI), below the 5000 µT cap.
No approval, submit, funded transaction, or new anchor occurred. The provider
exposes no fee read-back, so the quote does not prove funded execution or
on-chain `maxFee` enforcement. Remaining human-only failure paths are listed in
`docs/tari/wallet-integration.md`; adapter logic was audited and covered by
regressions. Never request recovery data and never run a funded transaction to
close those paths.

## Release decision

Do not deploy production. Do not publish Desktop installers. Do not post the
contest draft automatically. PR #1 is merged; the remaining release gates are
Desktop manual qualification, Universe funded-transaction authorization and
human failure-path observation, installer signing, and production-specific
infrastructure.
