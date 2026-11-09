# Hosted API v1 (IMPLEMENTED in Stage 2, locally runnable)

All endpoints below except Ootle anchor publication are implemented in
`crates/hosted`. Ootle publication (`/api/v1/ootle/status` reports
`not_configured_in_stage2_prototype`) is wired to the Stage 1 deployment
registry abstraction but performs no live transaction in Stage 2.
Admin routes (`/api/v1/admin/elections/*`) are localhost + token-gated
organizer controls (import/close/finalize), not public voter APIs.

Versioned, minimal-cryptographic-envelope API. The server receives the minimum necessary to accept and route a ballot. **It never receives ballot plaintext.**

## Endpoints (conceptual; paths mirror Private Ballot concepts)

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Liveness (implemented in skeleton) |
| GET | `/api/v1/status` | Service + API version (implemented in skeleton) |
| GET | `/api/v1/elections/{id}` | Election definition (package hash, thresholds, ABI) |
| GET | `/api/v1/elections/{id}/public-package` | Public election package (canonical bytes + hash) |
| POST | `/api/v1/elections/{id}/ballots` | Submit one opaque ballot envelope (Stage 2) |
| GET | `/api/v1/elections/{id}/receipt/{receipt_id}` | Submission receipt (Stage 2) |
| GET | `/api/v1/elections/{id}/results` | Tallied results once finalized (Stage 2) |
| GET | `/api/v1/elections/{id}/archive` | Finalized archive reference (Stage 2) |
| GET | `/api/v1/ootle/status` | Ootle adapter status (network, registry CURRENT, no secrets) (Stage 2) |

## Ballot submission (Stage 2 design)

- **Request:** one canonical ballot envelope: `{ election_id, nullifier_commitment, proof, ciphertext_or_envelope, receipt_id (client-generated UUIDv4), api_version: "v1" }`. No plaintext, no voter secret, no Triptych witness.
- **Server verification (independent, non-optional):** canonical encoding validation, election binding, nullifier uniqueness, Triptych verification (shared domain core), size and rate checks. A hostile frontend cannot trick the backend into accepting an invalid ballot — the backend runs the same verifiers the clients do.
- **Idempotency:** `receipt_id` is the idempotency key. Retrying the same `receipt_id` with the same envelope returns the same receipt; same `receipt_id` with a different envelope is a conflict error (`409`). Duplicate nullifiers from *different* receipts are rejected (`409` + `duplicate_nullifier`).
- **Replay:** envelopes are single-use by nullifier; replay of an accepted envelope is deduplicated by `receipt_id` and by nullifier.
- **Rate limiting:** per-IP and per-election (Cloudflare + backend); unauthenticated writes are budgeted low; abuse returns `429` with `Retry-After`.

## Transport rules

- **Maximum request sizes:** global 64 KiB (skeleton `MAX_BODY_BYTES`); per-route ballot envelope limit enforced in Stage 2 (payload cap mirrors the on-chain `MAX_PUBLIC_SUMMARY_LEN` concept).
- **Canonical encoding:** deterministic CBOR/JSON as in the domain core (`crates/protocol`); non-canonical encodings are rejected.
- **Error taxonomy:** `{ code, message }` with stable codes (`ballot_invalid`, `duplicate_nullifier`, `duplicate_receipt`, `rate_limited`, `payload_too_large`, `election_not_found`, `election_closed`, `service_unavailable`). Messages carry no secrets, paths, or third-party text.
- **No-secret logging:** request bodies are never logged; logs carry method, path, status, and bounded sizes only. A tripwire test asserts this (skeleton).
- **CORS:** same-origin by default; no wildcard `Access-Control-Allow-Origin: *` on sensitive routes. Any cross-origin allowance in Stage 2 is an explicit, reviewed exception.
- **CSRF:** state-changing routes require `Content-Type: application/json` + anti-CSRF token where cookies are used; the design prefers bearer receipts without ambient cookie auth for ballot submission.
- **Caching:** `Cache-Control: private, no-store` on ballot submission and receipts; public packages are immutable and cacheable by hash.
- **API versioning:** `/api/v1/*` is frozen at Stage 2 launch; breaking changes create `/api/v2/*`. Clients pin `api_version` in every request.
