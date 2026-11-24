# Cloudflare / VPS Architecture (Phase 13 — preparation only, no deployment)

Target topology:

```
Browser → HTTPS → Cloudflare (TLS, WAF, rate limit, cache rules)
           → Static frontend / Worker edge
           → HTTPS (Cloudflare Tunnel)
           → VPS localhost hosted backend (127.0.0.1:8788, private-ballot-hosted)
           → Private local services / Ootle adapters (walletd, indexer clients)
```

The VPS backend requires **no publicly exposed application port**. Cloudflare Tunnel connects the edge to the loopback service. The skeleton enforces this at the code level (`HostedConfig::validate` rejects non-loopback binds with `HOSTED_CONFIG_NON_LOOPBACK_BIND`).

## Plan (Stage 2, not Stage 1)

- **Frontend:** Cloudflare Worker + Static Assets (or the current recommended Cloudflare application hosting model at Stage 2 time). No Cloudflare-specific APIs in the cryptographic/domain core.
- **Tunnel:** Cloudflare Tunnel (outbound from VPS; origin protected; no inbound firewall exception).
- **TLS:** terminated at Cloudflare; backend speaks plain HTTP on loopback only.
- **Rate limiting:** Cloudflare rule + backend per-IP/per-election limits (`HOSTED_API_V1.md`).
- **WAF:** Cloudflare WAF rules for the API paths; ballot/receipt routes get strict rules.
- **Cache rules:** public packages immutable/cacheable by hash; ballot submissions and receipts `no-store` (see API doc).
- **Origin protection:** Cloudflare Authenticated Origin Pulls (or equivalent) so direct VPS IPs cannot bypass the edge.
- **Health checks:** Cloudflare Tunnel health check against `/health`; backend returns `{"status":"ok"}`.
- **Secrets:** production secrets (Ootle wallet credentials, registry signing material) live **only** server-side (VPS env / secret store), never in the frontend or the domain core.

## Stage 1 state

No Cloudflare resource is deployed. No DNS is modified. No VPS is configured. This document is the preparation artifact the Stage 2 implementer will execute against.

## Core isolation rule

No Cloudflare API, Worker binding, or edge concept appears in `crates/protocol`, `crates/crypto`, `crates/ballot`, `crates/archive`, `crates/tally`, `crates/verifier`, or `crates/deployment-registry`. The hosted crate depends on domain + registry only; the edge is replaceable.
