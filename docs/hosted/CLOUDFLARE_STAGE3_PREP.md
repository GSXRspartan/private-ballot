# Cloudflare Stage 3 Preparation (NOT deployed in Stage 2)

Intended future shape (unchanged from Stage 1):

```
Browser -> Cloudflare Worker / Static Assets -> Cloudflare Tunnel
        -> VPS localhost:8788 (private-ballot-hosted)
```

Prepared in Stage 2 (no Cloudflare resource created):

- Static production build: `npm --prefix hosted-web run build` -> `hosted-web/dist/`
  (SPA fallback: serve `index.html` for unknown paths; app has no client routing beyond `/`).
- Headers: `hosted-web/_headers` (CSP, `nosniff`, immutable asset caching,
  `private, no-store` on `/api/*`).
- API hostname/path: same-origin `/api/v1/*` behind the edge; Vite dev proxy
  targets `127.0.0.1:8788`. Cloudflare Tunnel origin must be `http://127.0.0.1:8788`.
- Admin routes `/api/v1/admin/*` MUST be blocked at the Cloudflare edge
  (return 404/403 before reaching the Tunnel) in Stage 3. They are additionally
  token-gated (`PRIVATE_BALLOT_HOSTED_ADMIN_TOKEN`) and loopback-only by default.
- Cache policy: public packages are content-addressed by `package_hash_hex`
  (immutable); ballot submission + receipts are `private, no-store` (backend sets
  this; edge must not cache `/api/v1/elections/*/ballots` or `/receipt/*`).
- Rate limiting / WAF: backend has an application-level fixed-window limit
  (default 120/min/election); Cloudflare WAF/rate-limit rules are an *additional*
  outer layer in Stage 3, never the sole protection.
- Staging checklist for Stage 3: (1) deploy backend on staging VPS loopback-only,
  (2) create Tunnel to origin, (3) deploy static frontend, (4) block admin at edge,
  (5) run the Stage 2 e2e suite against staging, (6) verify archive with Desktop
  verifier, (7) multi-device browser qualification.

NOT created in Stage 2: DNS records, Tunnel resources, Worker deployments,
secrets, Access applications. Those are Stage 3.
