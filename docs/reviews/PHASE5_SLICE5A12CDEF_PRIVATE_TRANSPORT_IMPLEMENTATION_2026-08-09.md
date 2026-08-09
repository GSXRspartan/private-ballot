# Phase 5 Slice 5A12CDEF private transport implementation

## Implemented

- Dedicated `transport-network` process/carrier boundary, with managed-Tor
  configuration validation, deterministic config generation, injected readiness,
  fakeable child process, timeout/crash handling, and no direct-route fallback.
- Strict opaque relay forwarding contract that discards proxy identity headers.
- Checkpoint-E admission gate, accepted-only deterministic Merkle batches,
  inclusion proofs, descriptor-authorized receipt verification, and distinct
  acceptance/inclusion/anchor semantics.
- Release-pinned root-set lookup with historical verification roots and explicit
  root-ID revocation.
- Canonical `TransportArchiveBindingV1` at a fixed hash-covered archive path,
  plus independent archive verification and a read-only Tauri/UI check of the
  binding -> completed archive -> existing Phase 4 evidence chain. It does not
  create a new Ootle protocol; `ANCHORED` requires verified final evidence for
  the exact completed archive.
- Versioned deterministic gateway persistence. A snapshot binds election,
  manifest, authenticated descriptor fingerprint/generation, counters,
  retry-capability commitments, package digests, terminal safe receipt results,
  pending/sealed batch proof material, and lifecycle retention state. It is
  written through a flushed temporary file and atomic rename; corrupt,
  unsupported, non-canonical, or wrong-descriptor state fails closed.
- Retry records live only for the active election plus an explicitly entered
  post-finalization verification grace. Expiry deletes retry commitments and
  records while retaining public sealed batches for archive verification. No
  raw retry capability, ballot plaintext, credential, nullifier, intake
  sequence, timestamp, IP/address, proxy header, receiver secret, or authority
  private key is represented by this format.
- The Tauri voter flow borrows only the existing Rust-owned Ready canonical
  package, authenticates the configured descriptor/root before carrier/key
  use, selects only an explicit Managed Tor or split-trust relay route, and
  returns reduced receipt DTOs. Production starts with no provisioned root,
  so both online choices fail closed while the pre-existing offline export
  stays available. Tests inject a visibly named TEST root only through the
  Rust coordinator constructor.

`final_batch_set_commitment` is a derived transport-level convenience
commitment over batch roots. `ArchiveHashV1` over the complete canonical
archive is the authoritative Phase 4 Ootle-anchor commitment. Local Phase 4
evidence verification is not an independent live-ledger finality claim (AE-1).

## Locally tested

Focused gateway tests passed before this continuation. The new network crate is
checked offline; its focused fake-process/relay tests are pending the final
combined validation pass.

## Requires real-machine rehearsal / release blockers

- production authority-root ceremony;
- Tor executable packaging, license, update, and hostile-path rehearsal;
- real multi-machine Tor and relay exercise;
- production carrier installation after the authority-root ceremony;
- durable voter credential persistence/import format;
- release-mode ~250-voter Triptych performance; and
- Windows installer packaging diagnostics (the gateway MSVC test is not blocked
  by the earlier dlltool report).

The archive-binding handoff, local coordinator, and production-fail-closed UI
are locally tested. Production transport provisioning and real-machine carrier
rehearsal remain incomplete. F3: PARTIAL. F7: PARTIAL. This is not a
public-MVP approval.
