# Hosted Private Ballot — Staging Deployment (Stage 3)

STAGING ONLY. Not production. No production DNS. No release tag.

## 0. Stage 3 status in this branch

Implemented and proven locally:

- Ootle cohort stays at **v0.51.0** (`9f03f90...`). v0.52.0 (2026-11-09)
  only changes L1 `ClaimBurn` bucket semantics (#3633); Private Ballot
  does not use `ClaimBurn` and Stage 3 spends no Ootle funds. Rationale
  recorded here and in `docs/security/`; no migration, no HEAD pin, no
  mixed cohorts.
- Two control planes hardened in `crates/hosted/src/lib.rs`: public plane
  on `127.0.0.1:8788` serves only voter routes and has **no admin routes
  at all** (404); admin plane on `127.0.0.1:8789` is loopback-only and
  token-gated. Optional `PRIVATE_BALLOT_HOSTED_ORIGIN_TOKEN` makes the
  public plane require the Worker-injected `x-private-ballot-origin`
  header on `/api/*` (`/health` exempt for Tunnel checks). Tests:
  `public_plane_never_serves_admin_mutations`,
  `admin_plane_requires_token_when_configured`,
  `origin_token_enforced_on_public_plane_when_configured`.
- Edge artifacts ready in `hosted-web/`: `wrangler.toml` (Worker +
  Static Assets, `run_worker_first = true`, SPA fallback) and
  `src-edge/worker.ts` (edge 404 for `/api/v1/admin/*`, origin-token
  injection with spoof stripping, security headers, cache policy).
- Backup/restore/health scripts in `deploy/staging/`.

Infrastructure access (previously blocked, resolved on 2026-11-24):

- **VPS SSH**: the existing `~/.ssh/ghostgate_vps` key authenticates as
  `ubuntu@40.160.90.9` (documented in the Ghost Gate staging deployment
  script). The `pdark@` and `root@` users are rejected. The live ED25519
  host key matches the trusted `known_hosts` record.
- **Cloudflare login**: local Wrangler OAuth is authenticated for the
  staging account; `wrangler whoami` and `wrangler deployments list` work.
  The staging Worker remains at `f8015e7c-3796-4613-b995-9517a4d4d8dd`.

## 1. Architecture

```
browser
  ---HTTPS--->
Cloudflare Worker + Static Assets (private-ballot-staging, workers.dev)
  /api/v1/admin/*  -> 404 at the edge (never proxied)
  /api/*           -> Worker -> injected x-private-ballot-origin -> Tunnel
  static assets    -> edge (immutable) / index.html (no-cache, SPA fallback)
Cloudflare Tunnel (outbound from VPS; no inbound firewall exception)
  ---> 127.0.0.1:8788 private-ballot-hosted  (PUBLIC plane, voter routes)
        127.0.0.1:8789                          (ADMIN plane, localhost only)
        ---> SQLite WAL /var/lib/private-ballot-hosted/hosted.sqlite3
```

- `8788`/`8789` MUST NOT be opened in the VPS firewall. The Tunnel is
  outbound-only from the VPS.
- The Tunnel ingress hostname (see `wrangler.toml` `STAGING_ORIGIN`)
  exists so the named Tunnel can route; with an origin token configured,
  direct hits to it fail closed on the backend.

## 2. Manual path (operator, once infra access exists)

### VPS layout (Phases 4–6)

```bash
# 1) Build the backend from the exact Stage 3 commit on the VPS (preferred).
git clone <private-ballot> && cd private-ballot && git checkout hosted-v2-stage3
cargo build --release -p tari-cc-private-ballot-hosted
sha256sum target/release/private-ballot-hosted | tee /tmp/SHA256SUMS
sudo useradd --system --no-create-home --shell /usr/sbin/nologin private-ballot-hosted || true
sudo install -d -o root -g root /opt/private-ballot-hosted
sudo install -m 0755 target/release/private-ballot-hosted /opt/private-ballot-hosted/
sudo install -d -o private-ballot-hosted -g private-ballot-hosted /var/lib/private-ballot-hosted /var/lib/private-ballot-hosted/backups /etc/private-ballot-hosted
sudo install -m 0644 deploy/private-ballot-hosted.service /etc/systemd/system/
sudo install -m 0600 /dev/stdin /etc/private-ballot-hosted/hosted.env  # fill from deploy/hosted.env.example
sudo systemctl daemon-reload && sudo systemctl enable --now private-ballot-hosted
curl -fsS http://127.0.0.1:8788/health
bash deploy/staging/health-check.sh
```

Record: source commit, `SHA256SUMS`, binary size, `rustc --version`,
target triple (`x86_64-unknown-linux-gnu` expected).

### Tunnel (Phase 9) and Worker (Phases 8/10/11)

```bash
npx wrangler login
npx wrangler secret put ORIGIN_TOKEN   # SAME value as VPS PRIVATE_BALLOT_HOSTED_ORIGIN_TOKEN
npx wrangler deploy                    # from hosted-web/, after npm run build
# VPS: cloudflared tunnel create pb-staging; cloudflared tunnel route dns create <tunnel> <ingress-host>
# VPS: cloudflared service install <token>; sudo systemctl enable --now cloudflared
```

### Backup (Phase 14)

```bash
bash deploy/staging/backup.sh
bash deploy/staging/restore-verify.sh /var/lib/private-ballot-hosted/backups/<latest>.sqlite3
```

### Proof (Phases 16–20)

Create a synthetic election via the **localhost admin plane** (never the
public plane), vote from a browser outside the VPS, close/finalize via
the admin plane, export the archive JSON, write it to a directory, and
verify with the existing Desktop verifier. Then run restart/recovery and
failure tests from `docs/hosted/OPERATIONS.md`.

## 3. Staging hostname and edge

- Worker: `private-ballot-staging` on the Cloudflare-provided
  `*.workers.dev` hostname (no custom production hostname).
- Admin block: Worker returns 404 for `/api/v1/admin` and
  `/api/v1/admin/*` before proxying (verified by a public curl in
  `CLOUDFLARE_STAGE3.md`). Backend plane split is the second layer.
- Origin bypass: the ingress hostname is protected by the Worker-injected
  origin token; the backend fails closed when it is configured. For
  stricter isolation the Tunnel hostname can be moved behind a Cloudflare
  Access service token in a later hardening pass — documented as a
  Stage 4 candidate.

## 4. WAF / rate limit outer layer (Phase 13)

Backend correctness never depends on the edge: the app enforces 64 KiB /
32 KiB body limits and a per-election fixed-window limit
(`PRIVATE_BALLOT_HOSTED_RATE_LIMIT_PER_MIN`, default 120/min). The edge
policy is defense in depth for abusive traffic. Recommended Cloudflare
WAF rules (account UI, no Terraform in this prototype):

- `POST /api/v1/elections/{id}/ballots` — 60 req/min per IP (generous
  headroom over idempotent retries; retries reuse the same receipt so
  they are counted once logically). IP is transport metadata only, never
  voter identity.
- `GET /api/v1/elections/{id}/receipt/{receipt_id}` — 120 req/min per IP.
- `GET /api/v1/elections/{id}/public-package` — 120 req/min per IP.
- `GET /health` and `GET /api/v1/status` — 300 req/min per IP.

If the account cannot attach WAF rate limiting, staging relies on the
backend limit alone; that is acceptable for a bounded synthetic electorate
and must be re-evaluated before any public hostname.

## 5. Rollback

1. Stop the Worker (disable route / delete worker) — public plane goes
   dark; voter data is unaffected (SQLite is local to the VPS).
2. `sudo systemctl stop private-ballot-hosted` on the VPS.
3. The public plane has no separate admin surface to roll back; the
   admin plane never leaves the VPS.
4. No Ootle template was republished; no on-chain state to revert.

Backend-only rollback (does not touch the database or the Worker):

```bash
sudo systemctl stop private-ballot-hosted
sudo install -o root -g root -m 0755 \
  /opt/private-ballot-hosted/private-ballot-hosted.rollback-20261124T143637Z \
  /opt/private-ballot-hosted/private-ballot-hosted
sudo systemctl start private-ballot-hosted
curl -fsS http://127.0.0.1:8788/health
```

## 6. Deployment log

| Date (UTC) | Component | Version / tag | Source | Rollback point |
|---|---|---|---|---|
| 2026-11-23 21:45 | Worker | `22708f68-abbe-4ef6-a882-a0faf881fef1` (`receipt-recovery-b2fd842`) | `b2fd842` | `c3747db8` (`f6b9ba5` frontend) |
| 2026-11-24 04:09 | Worker + static assets | `f8015e7c-3796-4613-b995-9517a4d4d8dd` (`edge-hardening-fa54902`) | `fa54902` (branch `review/web-mainnet-anchor-6a936d9`) | `22708f68` via `npx wrangler rollback` |
| 2026-11-24 15:05 | Backend (hosted Rust) | binary SHA-256 `a23cef08703c7e6c19d7f3b92984e2a38b099ed79c3b777662835056b3707600` | `e6fc580` + later approved changes through `75ac3d7`, built on VPS with Rust 1.97.1 | previous binary preserved as `private-ballot-hosted.rollback-20261124T143637Z` (SHA-256 `0aaed7e1e440f5884162eef0202371ddfd13c912e45d247c3835e3ff4f8d8c7e`) |

2026-11-24 deployment notes (Worker at 04:09; backend at 15:05):

- Fixes: edge admin-path normalization (percent-encoded and multi-slash
  variants of `/api/v1/admin*` are blocked at the edge with the canonical
  42-byte edge 404; malformed percent-encoding is rejected by Cloudflare
  before the Worker) and `tari-connector.js` wallet-reply origin pinning to
  `https://universe.tari.mw`.
- Live-verified after deploy: all encoded admin-path variants edge-blocked;
  `/api/v1/status`, anchored-election results/archive/public-package/
  anchor-payload all 200; `/chain/network` mainnet; durable receipt endpoints
  for the anchored transaction both 200; anchor-page CSP still
  `frame-ancestors https://universe.tari.mw`.
- DEPLOYED (backend, 2026-11-24 15:05 UTC): commit `e6fc580` —
  High-severity unauthenticated full-ledger replay mitigation
  (manifest-hash-guarded verified-ledger cache + per-route rate limits,
  election-scoped results-read/archive-read/enroll buckets, bounded
  rate-map state, Ristretto enrollment validation, admin-void ownership
  check). The VPS backend was rebuilt from the exact reviewed HEAD
  `75ac3d7`, the binary was atomically replaced, and only the staging
  service was restarted. Evidence, hashes, rollback commands and the
  stale backup-runbook schema caveat are recorded in
  `docs/hosted/BACKEND_SECURITY_DEPLOYMENT_2026-11-24.md`.
- Backend upgrade procedure: follow `docs/hosted/OPERATIONS.md` (backup DB,
  build from the exact commit on the VPS, copy-then-replace the binary,
  health-check, keep the old binary as the rollback point).
