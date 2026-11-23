# Release readiness decision — staging fix and production

## Staging receipt-recovery fix — BLOCKED (operator action required)

The receipt/recovery defect was verified against the real Mainnet transaction
and fixed in commit `b2fd842` (unindexed durable receipt = retryable pending,
never terminal failed; verified only with exact event/transaction agreement;
no resubmission). The fix is covered by `gui/test/chainEvidence.test.ts` and
the real-chain fixture tests in `gui/test/mainnetAnchorReceipt.test.ts`, and is
included in the pushed branch / PR #1.

Deploying it to staging was **not** performed:

- No Cloudflare API token/account is present in this environment
  (`CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID` unset); `wrangler whoami`
  requires an interactive login and cannot be completed autonomously.
- The current Worker therefore could not be backed up or version-pinned, and
  no rollback point was captured. Deploying without that would violate the
  "retain rollback" requirement.

Exact operator sequence (after authenticating with the staging-only account):

```powershell
cd hosted-web
npx wrangler whoami
npx wrangler deployments list --name private-ballot-staging
npx wrangler versions list --name private-ballot-staging
npm ci
npm test
npm run build
npx wrangler versions upload                 # captures a new immutable version
npx wrangler deploy                          # staged rollout / promote
```

Then verify recovery in a browser against the **already submitted** transaction
`28c789e60e696a4bcfe56a4b9ff3b6b69d4c1d38deebe71273e18a80a2bf01f2`
using **Check saved request / transaction** only. Do not submit a new funded
transaction. Retain the previous version id for `wrangler rollback`.

The backend Worker (`deploy/indexer-proxy`) needs no change: its allowlist and
response schema were correct and the live receipt now serves HTTP 200 there.

## Production (`ballot.ghostgate.boo`) — NOT READY / NOT DEPLOYED

Outstanding requirements, all still open:

1. Distinct production Worker, route, origin token, and dedicated indexer
   proxy binding (per `production-deployment-design.md` §1–3).
2. Isolated production SQLite database; no staging records or secrets copied;
   verified migrations and integrity check.
3. Production authority/anchor key custody under a documented ceremony; no
   reuse of staging keys; secrets injected as secret references only.
4. Backup + restore drill (`integrity_check`, binary/config backups, rehearsed
   restore), monitoring on `/health` and `/api/v1/status`, alerting, rate
   limits, and rollback rehearsal.
5. Wallet qualification: Sapient evidence exists; **live Tari Universe
   qualification is outstanding** (dry-run, declined approval, network
   mismatch, verified path, funded sufficiency).
6. Independent security audit sign-off and explicit operator authorization
   for the production gate; current `docs/hosted/mainnet-submission-enablement.md`
   still records these as pending.
7. Desktop installer release qualification is not met (six stale native
   source-snapshot tests fail); no Desktop binary should be published.
8. Production privacy/security model sign-off, including the reduced-anonymity
   warning path and the unchanged 5000 µT fee cap.

Release decision: **do not deploy production**. Staging is the only live
environment, and the reviewed staging fix still needs an authorized,
rollback-preserving deployment.
