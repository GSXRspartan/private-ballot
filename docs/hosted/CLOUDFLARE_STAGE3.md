# Cloudflare Stage 3 — Worker, Tunnel, and Edge Policy

Staging only. No production hostname, no DNS changes to production zones.

## What is in the repository

- `hosted-web/wrangler.toml` — Worker `private-ballot-staging`, Static
  Assets from `dist/`, SPA fallback, `run_worker_first = ["/api/*"]`,
  `STAGING_ORIGIN` placeholder (must be replaced with the real Tunnel
  ingress hostname before deploy).
- `hosted-web/src-edge/worker.ts` — edge logic; builds with `npx wrangler
  deploy` (esbuild, no new npm dependencies; the browser bundle stays
  zero-runtime-dependency).
- `hosted-web/_headers` — documentation parity only; Workers Static
  Assets does not read `_headers`. The Worker sets the same headers.

## Required human steps (in order)

1. `npx wrangler login` (Cloudflare account with staging scope).
2. Create a named Tunnel and DNS record for the ingress hostname:
   - `cloudflared tunnel create pb-staging` (run on the VPS).
   - `cloudflared tunnel route dns create pb-staging <ingress-host>`.
   - Configure the Tunnel ingress to `http://127.0.0.1:8788` for that
     hostname in the Cloudflare dashboard (ingress must point ONLY at the
     public plane, never at `8789`).
3. Replace `STAGING_ORIGIN` in `hosted-web/wrangler.toml` with
   `https://<ingress-host>`.
4. Generate one random origin token and set it in BOTH places:
   - Worker secret: `npx wrangler secret put ORIGIN_TOKEN`
   - VPS env: `PRIVATE_BALLOT_HOSTED_ORIGIN_TOKEN` in
     `/etc/private-ballot-hosted/hosted.env` (0600), then restart the
     backend. The backend fails closed without the token afterwards.
5. `npm --prefix hosted-web run build` then `npx wrangler deploy`.

No secret belongs in Git. The token value is never printed by
`deploy/staging/health-check.sh`.

## Edge behaviours to verify publicly

```bash
# 1. Static HTML loads with security headers (CSP, nosniff, HSTS, ...).
curl -sI https://<staging-workers-dev>/ | grep -i "content-security-policy"
# 2. Hashed assets are immutable.
curl -sI https://<staging-workers-dev>/assets/<hashed>.js | grep -i cache-control
# 3. API health via the edge (origin token injected by the Worker).
curl -s https://<staging-workers-dev>/api/v1/status
# 4. Edge admin block: MUST be 404 and must NOT reach the backend.
curl -s -o /dev/null -w "%{http_code}\n" https://<staging-workers-dev>/api/v1/admin/elections/import
curl -s -o /dev/null -w "%{http_code}\n" https://<staging-workers-dev>/api/v1/admin/elections/<id>/close
curl -s -X POST -o /dev/null -w "%{http_code}\n" https://<staging-workers-dev>/api/v1/admin/elections/import
# 5. Direct ingress bypass: MUST be 401 when the origin token is set.
curl -s -o /dev/null -w "%{http_code}\n" https://<ingress-host>/api/v1/status
```

## Security headers / CSP decision

- CSP identical to the Stage 2 policy: `default-src 'self'; script-src
  'self'; style-src 'self'; img-src 'self' data:; connect-src 'self';
  font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors
  'none'`.
- `nosniff`, `strict-origin-when-cross-origin`, minimal
  `Permissions-Policy` (`camera/mic/geolocation` off).
- HSTS `max-age=31536000; includeSubDomains` on HTTPS staging.
- COOP/COEP intentionally omitted (single-threaded WASM; see worker
  comment).
- Cache: `private, no-store` for `/api/*` (Worker + backend), immutable
  for `/assets/*`, `no-cache` for HTML.

## Troubleshooting

- `401 origin authentication required` on `/api/*`: Worker secret and VPS
  env token do not match. Re-set both from the same generated value.
- `502` from the edge: Tunnel is down or ingress host mismatch. Check
  `systemctl status cloudflared` on the VPS and the Tunnel dashboard.
- Static 404s for `/assets/*`: rebuild with `npm run build` before
  `npx wrangler deploy`; the assets directory is `dist/`.
