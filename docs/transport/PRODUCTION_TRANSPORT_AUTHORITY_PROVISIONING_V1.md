# Production transport authority provisioning (V1)

Status: **partial — provisioning primitive landed; operator config wiring is a
remaining release blocker.** See "Remaining work" below.

This note describes the trust root that authenticates the private-transport
descriptor and the authenticated election-status statement, how a shipping build
behaves before it is provisioned, and how a release ceremony installs a genuine
production root. It complements
[ADR-0010](../decisions/ADR-0010-transport-crypto-and-trust-root.md) and
[ADR-0011](../decisions/ADR-0011-transport-commitment-archive-binding.md).

## What the transport authority root is

The transport authority root is a single Ed25519 key pair that signs the
**transport descriptor** (route, gateway public key, receipt-verification keys,
padding/batch policy, manifest binding) and the **authenticated election-status
statement**. Voters and the organizer GUI verify those artifacts against a
*pinned public key* selected by `root_key_id`; a descriptor can only ever
*select* an already-known pinned root, never install a new one
(`TransportAuthorityRootSetV1::lookup_root`).

### Public vs private material

| Material | Secret? | Where it lives |
|---|---|---|
| Root **public** key + `root_key_id` | No | Embedded in the app, exported, and archived as part of verification |
| Root **private** signing key | **Yes** | Held out-of-band by the release custody process; never in this repo, never in the app, never in an archive |
| Descriptor / status signatures | No | Public artifacts, verified against the pinned public key |

This code path (`provision_production_transport_authority_root_v1`) only ever
handles the **public** key. No private/secret material is generated, read, or
stored by it.

## Default (unprovisioned) build behavior — fail closed

The workspace default build (used by non-Tauri callers such as the CLI's
verifier path) compiles without the `managed-tor` feature. The default Tauri
desktop release enables `managed-tor`, but does NOT enable an in-app
production authority; the two authority paths are independent, and neither
one falls back to the other. Any recipient of a descriptor or an
election-status statement bound to a production authority still evaluates
that binding against the sentinel below whenever the operator has not
provisioned a real public-pin root:

```
production_transport_authority_root_v1()
  -> TransportAuthorityRootV1::ProductionNotProvisioned {
       key_id: "PRODUCTION_TRANSPORT_ROOT_NOT_YET_PROVISIONED"
     }
```

The sentinel has **no public key**, so `verifying_key()` returns the specific,
actionable error `TransportError::ProductionAuthorityNotProvisioned` ("the
production transport authority root is not provisioned; run the release
provisioning ceremony..."). Every descriptor / status verification therefore
fails closed until a real root is installed. This is distinct from
`UntrustedRoot`, which means a *real but unrecognized or revoked* pin.

## Provisioning a production root (public pin)

A release ceremony generates the root key pair in its own custody environment
(HSM / offline signer — out of scope for this repo) and publishes only the
**public** key and a stable `root_key_id`. The application installs it with:

```rust
let root = provision_production_transport_authority_root_v1(
    "prod-root-2026-q3",     // stable, human-auditable id; NOT the reserved sentinel id
    public_key_bytes_32,     // the ceremony's PUBLIC Ed25519 key
)?;                          // Err(UntrustedRoot) on empty/reserved id or unusable key
let roots = TransportAuthorityRootSetV1::new(root);
```

The constructor rejects: an empty id, reuse of the reserved sentinel id
(`PRODUCTION_TRANSPORT_ROOT_UNPROVISIONED_KEY_ID`), an all-zero key, and any key
that does not decode to a valid Ed25519 verification point — so an unusable pin
is caught at provisioning time, not silently at every later verification.

## Configured public-pin loading (wired)

The application now loads an operator-supplied **public** pin from a local config
file, so a default/release build can use a genuine production root — while still
failing closed when nothing valid is configured.

- **Config type / file.** `ProductionTransportAuthorityRootConfigV1`, stored as
  `production-transport-authority-root-v1.json` in the app data directory (never
  inside an election archive). It holds only public material: schema, network,
  `root_key_id`, `root_public_key_hex` (64 lower-hex = 32-byte Ed25519 public
  key), an optional label, and a timestamp. It is plaintext because the root is
  public; integrity is enforced by strict format validation, not secrecy.
- **Loader.** `production_transport_authority_root_set_v1(app_data_dir,
  expected_network)` builds the production `TransportAuthorityRootSetV1` via
  `provision_production_transport_authority_root_v1`. Descriptor and
  election-status verification consume this same configured pin.
- **Fail-closed behavior.**
  - unconfigured → `GUI_PRODUCTION_TRANSPORT_AUTHORITY_NOT_PROVISIONED`;
  - malformed → a FIELD-SPECIFIC code: `..._CONFIG_SCHEMA_INVALID`,
    `..._KEY_ID_EMPTY`, `..._KEY_ID_INVALID`, `..._KEY_ID_RESERVED`,
    `..._PUBLIC_KEY_INVALID`, `..._NETWORK_INVALID`, `..._NETWORK_MISMATCH`;
  - never a fake root or a silent substitution of the in-app self-signed
    per-election transport authority the `managed-tor` intake generates.
- **No silent replacement.** `configure_...` refuses to overwrite an existing
  config (`..._ALREADY_CONFIGURED`); the operator must explicitly
  `forget_production_transport_authority_root_v1(confirm = true)` first.
  `ensure_configured_root_matches_v1(key_id, public_key)` fails closed with
  `..._ROOT_MISMATCH` if the configured root differs from the one an election was
  bound to.
- **Operator UX.** The organizer GUI (Advanced anchor settings) shows the
  readiness state (unprovisioned / configured / malformed), the configured key
  id, network, and public-key fingerprint, a "Load production public root" form
  that accepts only a **public** key (no private-key field, no password input),
  and states plainly that the private signing authority is not stored in the app
  and that fake/test roots are rejected in release builds.
- **What is NOT wired.** Producing a *new* transport binding still requires the
  out-of-band private signer plus a running collector (the ceremony / real-Tor
  path); the configured public pin is the **verification** root, and the archive
  transport binding remains commitment-based (it binds a descriptor fingerprint,
  which the configured root authenticates).

## Rotation and revocation

`TransportAuthorityRootSetV1` supports rotation without breaking historical
verification:

- `add_historical_root(root)` — keep a superseded public root available for
  verifying artifacts signed under it (verification only; it never becomes the
  current signer).
- `revoke_root_id(key_id)` — reject a compromised id *before* any signature
  processing (`lookup_root` checks the revocation set first).
- The current root is set at construction; a rotation installs the new current
  root and moves the previous one to historical.

## Verifying transport roots from an archive / evidence

The pinned public root that authenticated an election's transport is public and
travels with the verification artifacts. An independent verifier reconstructs
the `TransportAuthorityRootSetV1` from the published `root_key_id` +
`root_public_key` and re-runs `verify_descriptor` / `verify_by_root_id` over the
archived descriptor and status statements. Because the root is public, this is
fully reproducible offline.

## Warning: self-signed managed-Tor archives

Archives produced by the `managed-tor` in-app organizer intake (including the
earlier controlled two-PC and 500-voter test runs) are bound to a **self-signed
per-election transport authority**, not a genuine production-ceremony root.
They demonstrate the transport pipeline and are internally consistent, but
must **not** be presented as production-authenticated. A production release
must be provisioned with a genuine ceremony root as above.

## Remaining work (release blockers)

1. **Ceremony tooling & custody.** The private-key generation, HSM/offline
   signing, and descriptor/status signing ceremony live outside this repo and are
   not yet documented as an operator runbook here. (The application side —
   loading and verifying against the public pin — is now wired; see "Configured
   public-pin loading" above.)
2. **Binding production wiring.** Producing a new production transport binding
   still requires the out-of-band private signer plus a running collector; only
   the in-app `managed-tor` intake produces a binding today, and it is a
   self-signed per-election binding. The public-pin path
   enables verification, not production.
3. **Root-pin distribution & pinning integrity.** How the public pin reaches the
   operator config and voters (and how tampering with it is detected) needs an
   explicit design — e.g. a signed release manifest — tracked with the
   descriptor-consistency work. Today the config file is trusted as an
   operator-reviewed local input.
