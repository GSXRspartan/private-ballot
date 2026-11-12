# Read-only Tari Ootle indexer proxy

A minimal Cloudflare Worker that forwards a fixed allowlist of read-only
indexer GET requests to a server-configured upstream. The browser application
uses it as an independent cross-check of a submitted anchor transaction (the
wallet's own `tari_getTransactionResult` remains the primary source).

## What it serves

Exactly these routes, nothing else (all read-only):

| Route | Purpose |
|---|---|
| `GET /network` | indexer identity/network check |
| `GET /transactions/{64 lowercase hex}/result` | finalized result incl. the base64-CBOR execution result the anchor verifier parses |
| `GET /transaction-receipts/{object key}` | persisted receipt substate |

Every other path returns 404 without contacting the upstream. Query strings
are never forwarded. Only `GET`/`HEAD` (plus `OPTIONS` preflight) are accepted;
writes return 405.

## Configuration (worker environment variables)

| Variable | Meaning |
|---|---|
| `INDEXER_UPSTREAM` | the upstream indexer base URL (e.g. `https://ootle-indexer-a.tari.com/`). **Required**; without it the worker answers 503 to everything. |
| `ALLOWED_ORIGIN` | the exact browser origin allowed to read responses (CORS). Optional; when unset no cross-origin page can read any response. |

Never put secrets in client-visible configuration. The upstream URL and the
allowed origin are worker configuration, not application settings, and are not
sent to or derivable by the browser beyond what CORS reveals.

## Guarantees

- Fixed allowlist; no write path, no walletd surface, no proxying of arbitrary
  paths.
- Upstream responses are capped (512 KiB) and time-bounded (10 s); oversized
  or timed-out upstream answers become 502, never partial data.
- Responses are `Cache-Control: no-store`; the proxy never caches chain data.
- Failure responses are bounded JSON; the upstream's error bodies are not
  forwarded.

## Tests

```
node --test deploy/indexer-proxy/worker.test.js
```

The routing, URL-building, size/timeout capping, method gating, and CORS
behaviour are all covered without a Workers runtime.

## Deployment (not authorized by this task)

No production deployment is included or performed. Deploying this worker to
production infrastructure requires explicit authorization; use
`wrangler deploy` with the two environment variables above set in the
worker's configuration (never hard-code them).
