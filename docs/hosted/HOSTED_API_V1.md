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
| GET | `/api/v1/elections/{id}/anchor-payload` | Canonical Mainnet V2 anchor payload for browser publishing |
| GET | `/api/v1/ootle/status` | Ootle adapter status (network, registry CURRENT, no secrets) (Stage 2) |

## Anchor payload (browser Mainnet publishing)

`GET /api/v1/elections/{id}/anchor-payload` returns the canonical V2 public anchor
payload for a **finalized** election so a browser wallet can publish it without a
Desktop-generated bundle.

- **Preconditions:** the election is finalized; a finalized transport binding is
  stored and re-validated against the election id, manifest hash, and accepted
  ballot count; the released Mainnet V2 deployment resolves from the release
  registry. The anchor network is always `mainnet`; the Hosted *transport
  environment* (`staging`, `local`, ...) is never used as the anchor network.
- **Derivation:** the full finalized archive is rebuilt from Hosted's canonical
  ledger, re-verified by the shared gui-core archive verifier (manifest, catalog
  digests, election artifacts, transport binding, Triptych proof replay, tally,
  archive-hash rebuild), then converted by
  `build_v2_public_payload_from_verified_archive_v1` and
  `prepare_v2_anchor_publish_from_verified_evidence_v1`. No client-supplied
  digest, path, or template identity is accepted.
- **Privacy policy:** a cohort below
  `GUI_OOTLE_ANCHOR_PUBLISH_MIN_ACCEPTED_BALLOT_FLOOR_V1` is refused with
  `anchor_privacy_floor_not_met`. A binding whose batch reports
  `reduced_anonymity` requires `?acknowledge_reduced_anonymity=true`, otherwise
  `anchor_reduced_anonymity_ack_required`.
- **Response:** public data only (election id, archive hash, V2 digest, canonical
  payload, deployment identity, four anchor arguments). No ballot, nullifier,
  credential, organizer secret, or filesystem path is returned.
- **Errors:** stable codes only — `election_not_found`,
  `election_not_finalized`, `anchor_not_eligible`, `anchor_binding_invalid`,
  `anchor_binding_unavailable`, `anchor_privacy_floor_not_met`,
  `anchor_reduced_anonymity_ack_required`, `anchor_deployment_unavailable`,
  `anchor_deployment_invalid`, `anchor_payload_unavailable`,
  `anchor_payload_too_large`, `anchor_identity_mismatch`,
  `anchor_payload_inconsistent`, `anchor_rate_limited`.
- **Abuse control:** per-election/per-IP rate limit (`anchor`) applied before the
  archive replay; archive staging uses a private randomly-named directory that
  is removed when the request ends and is never derived from the election id.

## Hosted transport-binding derivation (browser-only finalization)

`POST /api/v1/organizer/elections/{id}/transport-binding/derive` lets an organizer
finalize an **HTTPS-only** election without a Desktop handoff.

- **Auth:** election-scoped organizer capability header
  (`x-private-ballot-organizer`), constant-time verified.
- **Body:** `{ "confirm": "derive-from-hosted-ledger", "acknowledge_reduced_anonymity": <bool> }`.
  No binding bytes are accepted; any client-supplied `transport_binding_cbor_hex`
  is ignored.
- **Preconditions:** election state is `closed`; exactly one authoritative
  descriptor issuance exists, is signature-verified against the configured
  transport authority root, and matches the election id; the accepted-package
  ledger replays to a non-empty set.
- **Derivation:** `finalized_transport_archive_binding_from_accepted_digests_v1`
  over the stored descriptor and the accepted-package digests — the same
  deterministic function the Desktop handoff is validated against, so the two
  paths produce byte-identical bindings, archives, and anchor payloads for
  equivalent evidence.
- **Policy:** accepted cohort below
  `GUI_OOTLE_ANCHOR_PUBLISH_MIN_ACCEPTED_BALLOT_FLOOR_V1` →
  `anchor_privacy_floor_not_met`; a derived binding reporting
  `reduced_anonymity` requires `acknowledge_reduced_anonymity: true`, otherwise
  `anchor_reduced_anonymity_ack_required`.
- **Immutability:** first-writer-wins. A second derive (or a Desktop handoff)
  returns `transport_binding_already_recorded`.
- **Errors:** `invalid_confirmation`, `invalid_state`, `anchor_privacy_floor_not_met`,
  `anchor_reduced_anonymity_ack_required`, `transport_binding_required`,
  `transport_binding_already_recorded`, `election_not_found`.
- **Trust model:** for HTTPS-only elections the ballot office's accepted-package
  ledger is authoritative for the accepted set; the Desktop remains authoritative
  for elections that include Desktop/Tor ballots. `do_finalize` is unchanged.

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
