# Desktop Privacy Invariants (Phase 7 freeze)

Hosted Mode is **not** allowed to weaken these properties. They are the qualified Desktop/Tor baseline (post-v0.42 qualification; Stage 1 preserves them under the v0.51.0 cohort).

## Invariants

1. **No clearnet fallback in Tor mode.** `crates/transport-network/src/tor.rs`: “there is **no** direct/clearnet/relay fallback — Tor or a bounded error.” The carrier holds only a validated loopback SOCKS endpoint; any failure is a `TransportError`, never a direct TCP dial.
2. **Onion/domain passed literally through SOCKS.** `socks5_connect_onion` uses `ATYP = 0x03` (`SOCKS_ATYP_DOMAINNAME`); “the local OS never resolves `.onion`.” SOCKS endpoint validation (`tor.rs:88-90`) requires an IP loopback `SocketAddr`, never a hostname — proxy-endpoint DNS is structurally prevented.
3. **No OS DNS for onion traffic.** Readiness probes “never resolve DNS, never reach clearnet, never open the onion service” (`tor.rs:128`). The probe performs one SOCKS5 greeting (`05 01 00`) and stops.
4. **Organizer `ManagedLocal` owns its Tor process; `ExternalRemote` never owns/kills external Tor.** `crates/transport-network/src/organizer_hidden_service.rs` + `remote_socks.rs` + `crates/transport-gateway` (`provision.rs`, `remote_organizer_external_tor` tests). The remote path carries only an endpoint; process lifecycle stays with the operator.
5. **Descriptor/onion equality is fail-closed.** `onion_route_from_descriptor_v1` binds the destination to the verified descriptor before any SOCKS connect (`tor.rs:310-314`); `validate_onion_hostname_v1` enforces exactly 56 lowercase base32 + `.onion`. `TransportDescriptorV1` binds the discovered onion (`provision.rs:6`).
6. **Existing archive verification.** `crates/archive` + `crates/verifier`: recomputed tally, nullifier/duplicate rejection, deterministic archive hashes. Anchor publication never mutates archive artifacts (`crates/ootle-receipt-anchor-adapter/tests/archive_independence.rs`, `crates/ootle-walletd-anchor-adapter/tests/archive_independence.rs`, `crates/ootle-anchor-network-adapters/tests/archive_independence.rs`).
7. **Deterministic tally; duplicate/nullifier rejection; election-bound proof semantics.** `crates/tally`, `crates/crypto` (Triptych), `crates/ballot`. Unchanged by Stage 1 (no source edits to these crates).
8. **Anchor publication failure never invalidates the election.** `crates/ootle-anchor-lifecycle` + `crates/gui-core`: fee failures are retryable `InsufficientFeesPaid` transport errors; `AnchorLifecycleState` keeps `NotFound`/`Pending`/`Timeout` resumable, never a permanent election failure (`safety_mutation.rs` test `not_found_pending_timeout_are_resumable_never_permanent_failure`).
9. **Retries preserve anchor digest.** `canonicalize_transaction_id` + fingerprint binding; `duplicate_drive_never_creates_second_distinct_transaction`, `transaction_id_stable_across_recovery`.
10. **No sensitive ballot/proof logging.** Bounded errors only (`TransportError`, `ReceiptConversionError`, `RegistryError`, hosted `ConfigError`); `transport_error_does_not_leak_third_party_text` test; hosted skeleton logs no request bodies (see `crates/hosted/src/main.rs`).

## Regression tripwires (existing, kept green)

- `crates/transport-network` + `crates/transport-gateway` Tor tests (managed Tor, remote SOCKS, descriptor binding).
- `crates/ootle-anchor-network-adapters/tests/{parity,malformed,indexer_network_verification}.rs`.
- `crates/ootle-receipt-anchor-adapter/tests/{agreement,retrieval_verification,recovery_state}.rs`.
- `crates/gui-core/tests/trusted_anchor_deployment.rs` (lock validation), `live_anchor_v2*.rs` (live path, gated by env; never spends in Stage 1).

## Hosted Mode boundary (explicit)

Hosted/Web Mode is a **different privacy profile** (see `docs/hosted/HOSTED_MODE_THREAT_MODEL.md`). It must never claim these invariants. In particular, invariants 1–4 are Desktop/Tor-only; hosted traffic traverses Cloudflare + VPS and is observable at the content-delivery layer for timing/IP-derived metadata. That tradeoff is disclosed, not hidden.

## Freeze rule

Any change that weakens 1–10 requires the same qualification that protected the v0.42 baseline: full workspace tests, Tor regression suite, and an explicit security review. Stage 1 ends with all tripwires green (see final report, §10).
