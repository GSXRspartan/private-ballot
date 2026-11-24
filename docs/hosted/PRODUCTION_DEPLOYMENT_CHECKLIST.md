# Production deployment checklist — ballot.ghostgate.boo

Status: **checklist only — NOT executed**. This phase prepares the runbook for a
separate production deployment; it does not create DNS, Workers, keys, databases,
or deploy anything. Staging (`https://private-ballot-staging.ghostgate.boo`)
remains the only live environment.

Design basis: `docs/hosted/production-deployment-design.md`. Gate status:
`docs/hosted/RELEASE_READINESS_DECISION.md`. Never reuse staging secrets,
origin tokens, database records, elections, or authority keys. The Hosted
*transport environment* (`production`) is independent of the anchor network
(always `mainnet`).

## 0. Go / no-go before any production action

- [ ] Gate C closed: Windows Desktop 13-step manual workflow passed on a clean
      profile and installer signing decision recorded (`docs/release/DESKTOP_QUALIFICATION_STATUS.md`).
- [ ] Gate D inputs closed: live Web Tari Universe qualification (non-spending),
      key-custody ceremony, monitoring/alerts, independent audit sign-off,
      explicit operator authorization (`RELEASE_READINESS_DECISION.md` §Gate D).
- [ ] Written operator authorization for the deployment window exists.
- [ ] Confirm no staging material is copied: `grep` deployment env/DB paths and
      record that production values are distinct.

## 1. Production Cloudflare Worker and DNS

- [ ] Create a **new** Worker `private-ballot` with its own `wrangler.toml`
      (production variant of `hosted-web/wrangler.toml`); do not reuse
      `private-ballot-staging` or its bindings.
- [ ] Bindings: dedicated production `INDEXER_PROXY` Worker
      (`deploy/indexer-proxy/wrangler.toml`, `ALLOWED_ORIGIN =
      https://ballot.ghostgate.boo`, pinned `INDEXER_UPSTREAM`), `ASSETS`, and a
      production origin variable (the `STAGING_ORIGIN` equivalent).
- [ ] DNS: create the `ballot.ghostgate.boo` route to the production Worker only;
      verify no overlap with the staging tunnel route. Confirm with
      `npx wrangler whoami` and a dry-run deploy before the real deploy.
- [ ] Set the production `ORIGIN_TOKEN` with `wrangler secret put ORIGIN_TOKEN`
      (human step; never in Git, never printed). Set the matching value in the
      backend `EnvironmentFile` (root-owned `0600`).
- [ ] Security headers: same reviewed bundle; dApp document routes get
      `frame-ancestors 'self' https://universe.tari.mw`, API/admin/assets get
      `frame-ancestors 'none'` (`hosted-web/src-edge/worker.ts`,
      `docs/hosted/CLOUDFLARE_STAGE3.md` §Security headers). Verify HSTS,
      `nosniff`, referrer policy, `private, no-store` on API.
- [ ] Public verification curls: admin paths return 404 at the edge; direct
      origin ingress returns 401 without the token (`CLOUDFLARE_STAGE3.md` §7).
- [ ] Record production Worker version id and bundle hash in the deployment log.

## 2. Isolated backend and database

- [ ] Separate backend instance/service on a distinct port and origin, fronted
      by a dedicated outbound-only Cloudflare Tunnel (e.g. `pb-production`);
      no public app port.
- [ ] Fresh SQLite database at a production-only path. `migrate()` writes
      `schema_version = 7`; verify `meta.schema_version` and critical tables.
      **Never** copy the staging database or any staging election record.
- [ ] Harden the unit from `deploy/private-ballot-hosted.service`: root-owned
      `0600` EnvironmentFile, service account, `NoNewPrivileges`, `PrivateTmp`,
      `ProtectSystem=strict`, loopback-only planes (`ALLOW_PUBLIC_BIND` forbidden).
- [ ] Populate `deploy/hosted.env.example` schema with production-only values,
      including `PRIVATE_BALLOT_HOSTED_TRANSPORT_ENVIRONMENT=production`,
      distinct admin/origin tokens, and the rate-limit setting.
- [ ] Health checks pass: public `/health`, public `/api/v1/status`, loopback
      admin health (`deploy/staging/health-check.sh`).

## 3. Production authority keys

- [ ] Generate the Ed25519 transport root in an out-of-band HSM/offline ceremony
      (`docs/transport/PRODUCTION_TRANSPORT_AUTHORITY_PROVISIONING_V1.md`).
      The private key never enters the repo, app, or archive.
- [ ] Publish/verify the public pin file
      (`production-transport-authority-root-v1.json`) with an integrity-checked
      distribution path; confirm the fail-closed sentinel is replaced only after
      the ceremony.
- [ ] Provision the anchor signing key via the release authority process; store
      in the OS credential store (Credential Manager/Keychain/Secret Service),
      never reused from staging (`docs/OPERATOR_SETUP.md` §A5).
- [ ] Set `PRIVATE_BALLOT_HOSTED_TRANSPORT_ROOT_KEY_ID`,
      `..._TRANSPORT_ROOT_PUBLIC_KEY_HEX`, and `..._AUTHORITY_SIGNING_KEY_HEX`
      (`crates/hosted/src/lib.rs`); confirm startup fails closed on a mismatch.
- [ ] Organizer capability secrets remain client-generated with only verifiers
      stored (unchanged model).

## 4. Key custody and recovery

- [ ] Name custodians, offline storage location, and ceremony quorum; record the
      rotation procedure (`add_historical_root` / `revoke_root_id`) and rehearse
      it in staging before production.
- [ ] Keep sealed `0600` backups of env and authority material, separated from
      database backups; never print their contents (`BACKEND_SECURITY_DEPLOYMENT_2026-11-24.md`).
- [ ] Document lost/compromised-key handling (ADR-0002; `docs/OPERATOR_SETUP.md`
      §A5: rotate with **Reconnect**, remove with **Forget**).
- [ ] Prove recovery from sealed material in an isolated drill; record hashes.

## 5. Rate limiting and security controls

- [ ] Cloudflare WAF rates per `docs/hosted/STAGING_DEPLOYMENT.md` §4: ballots
      60/min/IP, receipt + public-package 120/min/IP, health/status 300/min/IP.
- [ ] Backend `PRIVATE_BALLOT_HOSTED_RATE_LIMIT_PER_MIN` (default 120), hard-bounded
      rate map (4096 entries), per-route buckets (`results-read`, `archive-read`,
      `enroll`), `429` + `Retry-After`.
- [ ] Body caps: 64 KiB global / 32 KiB per route; constant-time token compare;
      no wildcard CORS; CSRF policy; `private, no-store` on API.
- [ ] Verify spoofed `x-private-ballot-origin` / `x-admin-token` headers are
      stripped and the Worker secret is injected (`hosted-web/src-edge/headers.mjs`).
- [ ] No-secret logging tripwire: logs contain only
      `method=… path=… status=… duration_ms=…`; no bodies, headers, query strings,
      voter identities, or fee/secret material.

## 6. Backup and restore

- [ ] Scheduled SQLite online `.backup` (never copy live `-wal`/`-shm`) with
      `PRAGMA integrity_check`, schema-version allowlist `7`, critical-table
      check, mode `0600`, and EXIT-trap removal of unverified backups
      (`deploy/staging/backup.sh`).
- [ ] Run `deploy/staging/restore-verify.sh` against a production backup in a
      temp directory: integrity, `journal_mode=wal`, schema version, ballot
      UNIQUE constraints, election count; live DB untouched.
- [ ] Isolated restore drill (the `pb-recovery-drill` pattern) with byte-identical
      API responses; record the evidence (`STAGING_RECOVERY_QUALIFICATION.md`).
- [ ] Binary + config backup before every deploy; defined retention and offsite copy.

## 7. Monitoring and alerts

- [ ] Monitor `GET /health` and `GET /api/v1/status`; alert on non-200 from more
      than one region (`production-deployment-design.md` §7).
- [ ] Alert on tunnel/service failure, certificate expiry, backup job failure,
      429 spikes, admin-404/direct-ingress-401 anomalies, and Worker errors.
- [ ] Assign alert routing, on-call owner, and escalation path; ensure alert and
      log payloads contain no secrets.
- [ ] Note: no Grafana/Prometheus/Sentry/Logpush/Tail Workers configuration
      exists yet in the repo — add it before go-live.

## 8. Public operator documentation

- [ ] Publish operator docs for enrollment/invitations, organizer capability
      handling, voter credential custody, freeze/open/close/finalize, archive
      verification, and receipt lookup (`docs/OPERATOR_SETUP.md`).
- [ ] Public release notes and artifact hashes using
      `docs/release/RELEASE_ARTIFACT_NAMING.md`; resolve the installer signing
      decision; preserve the five README screenshots unmodified.
- [ ] Status page and incident disclosure process; do not claim production
      security or anonymity before audit sign-off.
- [ ] Keep the contest draft unpublished until explicit operator decision
      (`docs/release/NOVEMBER_2026_CONTEST_UPDATE_DRAFT.md`).

## 9. Production wallet authorization

- [ ] Authorized wallet is the operator's production wallet only; verify the
      authorized account set before every anchor action (`hosted-web/src/anchor.ts`
      `revalidate()`; `browserAnchor.ts` `revalidate()`).
- [ ] Mainnet identification: `tari_getNetwork` → `mainnet` (byte `0x00`), and a
      unique `CURRENT` Mainnet V2 deployment with the release-pinned digest
      (`anchorDeploymentConfig.ts`).
- [ ] Required capabilities present; record `dryRunIsLocal`; mandatory per-publish
      fee preflight (`dryRun: true`, cap 5000 µT, +12 µT allowance) and guarded
      publish driver block `createRequest`/`waitForApproval`/`submit` until it passes.
- [ ] Do **not** enable `MAINNET_ANCHOR_SUBMISSION_ENABLED` until all prerequisites,
      audit, and operator authorization are complete
      (`docs/hosted/mainnet-submission-enablement.md`).
- [ ] Live Web Tari Universe must be qualified first, non-spending dry run only
      (`docs/tari/wallet-integration.md`,
      `docs/hosted/mainnet-fee-preflight-operator-qualification.md` §Real Web
      Tari Universe qualification).
- [ ] Never request a recovery phrase, seed, private key, or password; no funded
      qualification transaction and no second Mainnet anchor.

## 10. Deployment and rollback

- [ ] Record the authorized deployment window and operator.
- [ ] Deploy order: backup DB → build reviewed source → deploy production Worker
      → atomic backend binary swap → health/public curls → record version ids and
      hashes.
- [ ] Rollback: `npx wrangler rollback` to the previous Worker; restore the previous
      backend binary plus the verified DB backup; keep the same database (schema is
      additive-only — never migrate backwards). The public plane has no separate
      admin surface; no on-chain change occurs (`production-deployment-design.md` §7).
- [ ] Keep exact stop/install/start commands and rollback points from
      `docs/hosted/BACKEND_SECURITY_DEPLOYMENT_2026-11-24.md` §7 available.
- [ ] Run post-rollback health and public verification curls; record the result.

## 11. Explicit non-goals of this phase

No production deployment, DNS creation, Worker creation, key generation/rotation,
funded Mainnet transaction, installer publication, contest draft publication, or
copying of staging secrets/election data. All items above remain unchecked until
performed and evidenced by an operator.

## Sign-off

| Gate | Owner | Evidence | Status |
|---|---|---|---|
| Go/no-go preconditions | | | NOT STARTED |
| Worker + DNS | | | NOT STARTED |
| Backend + database | | | NOT STARTED |
| Authority keys + custody | | | NOT STARTED |
| Rate limits + security | | | NOT STARTED |
| Backup + restore | | | NOT STARTED |
| Monitoring + alerts | | | NOT STARTED |
| Operator docs | | | NOT STARTED |
| Wallet authorization | | | NOT STARTED |
| Deployment + rollback drill | | | NOT STARTED |
