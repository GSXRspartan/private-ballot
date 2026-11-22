# Production hosting design — ballot.ghostgate.boo (DESIGN ONLY — NOT DEPLOYED)

Status: **design**. This document specifies a separate public production
deployment for Private Ballot at `ballot.ghostgate.boo`. It is **not** deployed
by this task. The existing staging site
(`https://private-ballot-staging.ghostgate.boo`) remains the only live
environment. The staging transport environment and the Ootle Mainnet anchor
network remain independent concepts: the Hosted *transport environment*
(`staging`, `production`, ...) never determines the anchor network (always
`mainnet`).

## 1. Separation from staging

| Concern | Staging (existing) | Production (this design) |
|---|---|---|
| Worker | `private-ballot-staging` | `private-ballot` (new, distinct) |
| Hostname | `private-ballot-staging.ghostgate.boo` | `ballot.ghostgate.boo` |
| Backend origin | staging Tunnel + origin token | separate production Tunnel + separate origin token |
| SQLite DB | staging file | separate production file (never copied from staging) |
| Origin token | staging secret | distinct production secret (injected into the Worker) |
| Authority signing key | staging key | production key, managed separately |
| Elections | test/synthetic records | production elections only (no staging records imported) |

No staging secret, origin token, database, or test-election record is copied
into production.

## 2. Cloudflare Worker

- New Worker `private-ballot` with its own `wrangler.toml` (a production
  variant of `hosted-web/wrangler.toml`).
- Bindings: a dedicated `INDEXER_PROXY` Worker (production indexer read proxy),
  `ASSETS`, and a `STAGING_ORIGIN`-equivalent production origin variable.
- The Worker code is the same reviewed `hosted-web` bundle; only configuration
  (origin, bindings, routes) differs.
- Strict CSP unchanged: `default-src 'self'`, no analytics, no third-party
  scripts; `frame-ancestors` limited to the intended dApp embedding origins.

## 3. Backend

- Separate `private-ballot-hosted.service` instance on a distinct port/origin,
  fronted by a dedicated Cloudflare Tunnel (outbound-only).
- Own SQLite database at a production path; migrations run on startup;
  schema-version recorded in `meta`.
- `PRIVATE_BALLOT_HOSTED_ORIGIN_TOKEN` set to the production value, injected by
  the production Worker; direct origin hits fail closed.
- Rate limiting configured per the backend defaults
  (`PRIVATE_BALLOT_HOSTED_RATE_LIMIT_PER_MIN`).

## 4. Authority / key management

- The transport authority root key and the anchor signing key are provisioned
  for production through the release authority process, never reused from
  staging.
- Secrets (origin token, admin token, signing keys) are injected as
  environment/secret references, never committed or printed.
- The organizer self-service capability secret is generated client-side and only
  its verifier is stored (unchanged model).

## 5. Backup and restore

- Scheduled SQLite `.backup` (safe online mechanism) to a production backup
  path, with `PRAGMA integrity_check` verification.
- Binary + config backups before every deploy.
- A documented restore drill: stop service → place verified `.backup` →
  start → health + integrity check. No destructive reset.

## 6. Mainnet anchor binding

- The anchor network is always `mainnet`, resolved from the checked-in release
  registry (unique `CURRENT` entry, release-pinned artifact digest), independent
  of the Hosted transport environment (`production`).
- Mainnet submission remains gated by `MAINNET_ANCHOR_SUBMISSION_ENABLED`
  (see `docs/hosted/mainnet-submission-enablement.md`); production does not
  enable it without the full prerequisite + audit + operator authorization.

## 7. Health, monitoring, rollback

- `GET /health` and `GET /api/v1/status` monitored; alerting on non-200.
- Rollback: redeploy the previous Worker version (`wrangler rollback`) and
  restore the previous backend binary + database backup; the public plane has
  no separate admin surface to roll back (admin plane is loopback-only).
- No on-chain state is altered by a rollback (no template republish).

## 8. Explicit non-goals for this task

- No production deployment, DNS cutover, or Worker creation is performed here.
- No staging data/secrets are copied.
- No Mainnet submission is enabled.