# Portable Core Mapping (Phase 8)

Stage 1 does **not** rewrite proven cryptographic code for aesthetics. The existing crate layout already separates portable domain logic from desktop/platform concerns; this document freezes the mapping and records the one dependency-boundary caveat (the `UnsignedTransaction` type).

## Portable domain logic (browser-safe in principle; see `docs/hosted/BROWSER_PORTABILITY.md` for WASM assessment)

| Crate | Contents |
|---|---|
| `crates/protocol` | Canonical serialization, `HashProvider` (BLAKE3-256), domain frames, `MAX_*` bounds |
| `crates/crypto` | Triptych proof system (via `third_party/tari-triptych`), nullifiers, election-bound proofs |
| `crates/ballot` | Ballot structures, eligibility checks |
| `crates/archive` | Finalized archive format, verification, deterministic tally input |
| `crates/tally` | Deterministic tally |
| `crates/verifier` | Archive/tally verification entry points |
| `crates/registry` | Frozen electorate registry (governance keys), canonical CBOR |
| `crates/anchor` | `OotleNetworkIdV1`, anchor digest/record types |
| `crates/anchor-transport` | `AnchorTemplateBindingV1/V2`, `AnchorEventProofV2`, `verify_anchor_receipt`, lifecycle DTOs |

Verified: none of these depend on Tauri, Windows APIs, process spawning, filesystem UI, or managed Tor (`rg "tari_|tauri|windows" crates/{protocol,crypto,ballot,archive,tally,verifier,registry,anchor,anchor-transport}/Cargo.toml` — empty for desktop crates).

## Platform / desktop logic (never imported by portable core or hosted backend)

| Crate / path | Concerns |
|---|---|
| `gui/src-tauri/` | Tauri commands, Windows Credential Manager (`walletd_credential_store.rs`), filesystem dialogs, native paths, OS notifications |
| `crates/gui-core` | GUI state machine, `trusted_anchor_deployment.rs` (filesystem lock), live anchor config |
| `crates/transport-network` | Managed Tor process ownership, SOCKS dialing, onion probes |
| `crates/transport-gateway` | Organizer gateway, descriptor provisioning, remote organizer hosting |
| `crates/cli` | Local CLI, walletd lifecycle, local paths |
| `crates/ootle-anchor-app` | Async app driver (Tokio runtime bridge); creates the runtime, adapters do not |

## Ootle adapter (boundary, not portable core)

`crates/ootle-anchor-adapter`, `crates/ootle-walletd-anchor-adapter`, `crates/ootle-receipt-anchor-adapter`, `crates/ootle-anchor-network-adapters`, `crates/ootle-anchor-lifecycle`, plus the two new crates:

- `crates/deployment-registry` — reset-safe deployment resolution (pure data + fail-closed checks; portable).
- `crates/hosted` — future hosted backend; depends on `deployment-registry` only, never on Tauri/Tor/desktop crates.

**Caveat:** `crates/ootle-anchor-adapter` depends on `tari_ootle_transaction::UnsignedTransaction` (to build/inspect the fee-less anchor transaction and derive its CBOR fingerprint). That single type is the WASM-portability blocker for the *builder* half of the adapter; the *inspector/verifier* half (event decoding, receipt conversion) is portable (see `BROWSER_PORTABILITY.md`).

## Target layout (unchanged in Stage 1)

```
crates/protocol, crypto, ballot, archive, tally, verifier, registry, anchor, anchor-transport  → portable domain
crates/deployment-registry, hosted                                                              → hosted boundary (new)
crates/ootle-anchor-{adapter,app,lifecycle}, ootle-{walletd,receipt}-anchor-adapter,
  ootle-anchor-network-adapters                                                                  → Ootle adapter
crates/transport-*, crates/{gui-core,cli}, gui/src-tauri                                          → desktop/platform
```

No crate was renamed. The hosted skeleton links the shared domain core (dependency direction is `hosted → domain`, never `domain → hosted`).
