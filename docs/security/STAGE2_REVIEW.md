# Stage 2 Security Review (Hosted/Web Mode prototype)

Scope: `crates/hosted`, `crates/hosted-wasm`, `hosted-web/`, `deploy/`.
Protocol crates (`protocol`, `ballot`, `crypto`, `verifier`, `archive`,
`tally`, `registry`) unchanged.

## BLOCKER: none

- Voter secret leaves browser: NO. Secrets are accepted only by
  `hosted-wasm::create_ballot_package` in-memory, zeroized on drop
  (`TariTriptychSecretKeyV1` Drop), never returned/logged/sent. Frontend
  keeps secret in a JS variable + password input only; no localStorage,
  no URL, no analytics (no third-party runtime deps at all).
- Backend requires ballot plaintext: NO beyond protocol design. The only
  confidentiality mode is PUBLIC; the canonical package (proof + public
  payload) is what Desktop archives also contain. No secret/witness/plaintext
  beyond that is accepted; storage trait cannot accept secrets.
- Proof generated server-side with voter secret: NO. Only
  `crates/hosted-wasm` calls `prove_tari_triptych_prototype_v1`; the backend
  only calls verification (`ingest_approval_ballot_package_v1`).
- Hosted archive incompatible with Desktop verifier: NO. Hosted finalization
  builds the canonical finalized archive (`ArchiveManifestV1::finalized_for_provider`
  over election-manifest/candidate-set/voter-registry/submissions) and
  `end_to_end_hosted_flow_and_desktop_archive_verifier` proves
  `verify_archive_directory_v1` = PASS.
- Duplicate HTTP request double-counts: NO. `PRIMARY KEY (election_id, receipt_id)`
  + envelope-hash comparison returns the same stable receipt for exact retry;
  ingestion lock + ledger replay prevent concurrent double-accept (tested).
- Same nullifier accepted twice: NO. `UNIQUE (election_id, nullifier)` +
  canonical `BallotAcceptanceLedger` first-valid-wins (tested, including
  distinct-receipt same-nullifier -> 409 duplicate_nullifier).
- Backend silently changes voter intent: NO. Altering package bytes breaks
  canonical decode or Triptych verification (tampered test -> 422).
- Unauthenticated public admin operation: NO. Admin routes are loopback-only
  by default bind and token-gated when configured; Stage 3 must block them
  at the edge (documented).
- Persistent secret logging: NO. Middleware logs method/path/status/duration
  only; error bodies never echo package/secret (tested); DB contains no secret
  (tested).
- Fail-open proof verification: NO. Every submission runs
  `ingest_approval_ballot_package_v1` (decode, manifest binding, suite policy,
  candidate commitment, payload limits, statement reconstruction, Triptych
  verify, lifecycle, nullifier ledger) before persistence.

## HIGH: none open

- Race in duplicate enforcement: closed (global ingestion Mutex + DB UNIQUE).
- Unbounded DB/request growth: closed (64 KiB global / 32 KiB ballot limits,
  indexed PK lookups, replay O(n) per submission is prototype-acceptable and documented).
- Wildcard sensitive CORS: closed (no CORS layer; same-origin only).
- Public bind by default: closed (`127.0.0.1:8788`; non-loopback rejected
  unless explicit `PRIVATE_BALLOT_HOSTED_ALLOW_PUBLIC_BIND=1`).
- Idempotency collision ambiguity: closed (same receipt_id + different envelope
  -> 409 duplicate_receipt; same envelope -> same stable receipt).
- Replay ambiguity: closed (nullifier UNIQUE + receipt PK).
- Unsafe browser secret storage: closed (memory-only; session lifetime documented).
- Missing election-binding verification: closed (manifest hash + scope in
  reconstructed statement; wrong-election test -> 422 wrong_election).

## MEDIUM (accepted, documented)

- M1: Per-submission ledger replay is O(n^2) for an election. Acceptable for
  prototype electorates; a production backend should persist the ledger or
  shard ingestion. No correctness impact.
- M2: Rate limiting is a single-process fixed window keyed by election
  (no IP identity in crypto). Adequate for local/staging; Cloudflare WAF is
  the future outer layer, documented.
- M3: Admin token is a shared localhost token, not per-operator auth. The
  future organizer web control plane needs real auth (documented in quickstart);
  Stage 2 deliberately has no admin panel.
- M4: Browser zeroization is best-effort (WASM memory cannot be guaranteed
  wiped; JS strings are immutable). Documented in BROWSER_PORTABILITY update;
  secret lifetime is the active tab session.

## LOW / INFO

- Vite dev-server audit advisories were dev-only; vite bumped to 8.3.7, audit clean.
- Ootle v0.52.0 (released 2026-11-09 14:35 UTC, after Stage 1's v0.51.0):
  breaking change is ClaimBurn bucket semantics (#3633). Private Ballot does
  not use ClaimBurn (grep empty) and Stage 2 spends no Ootle funds, so
  migration is not required for correctness. v0.51.0 cohort retained.
  Re-evaluate at Stage 3 live-deployment time.
- No production deployment, DNS, Cloudflare, or VPS changes were made.

## Verdict

No BLOCKER or HIGH findings. Stage 2 H3 (idempotency/duplicate) from Stage 1
is CLOSED.
