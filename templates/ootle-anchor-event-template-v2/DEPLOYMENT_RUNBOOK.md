# V2 Public-Summary Anchor — Deployment Runbook

> **Network generation: Tari Ootle mainnet, current cohort (walletd/indexer
> v0.53.x, `tari_template_lib = "=0.40.0"`).** All esmeralda/v0.42-generation
> addresses, artifacts, and digests below are retained as **HISTORICAL**
> evidence only: that generation was a testnet and its deployment address is no
> longer authoritative for anything.
>
> Status: **V2 template published on Ootle mainnet.** The mainnet deployment
> address and provenance are recorded below. This repository does not itself
> perform, authorize, or verify a second on-chain publish.
>
> **Controlled-alpha only.** The V2 live path is a controlled-alpha capability.
> V2 template publish is allowed **only after** the V1/V2 isolation blocker is
> fixed — while the V2 anchor version is selected, no V1 publish/status/reject/
> approve control may be triggered from any visible or advanced UI control
> (enforced both at each disabled button and at the shared `onAnchorStep` /
> `onPublishTariAnchor` entry points; guard-tested in
> `gui/test/anchorVersionGating.test.ts`). This blocker is fixed. The mainnet
> publish recorded below was performed by the operator after review.

The V2 anchor publishes a richer *public election summary* derived only from the
independently verified, finalized archive. It uses the **digest + detached
evidence** strategy: the compact V2 public-payload digest and a small scalar
summary go on-chain; the full canonical payload travels in a detached evidence
file, and the offline verifier proves the detached payload hashes to the
on-chain digest.

## Identity (matches the code and the built ABI)

| Field | Value |
| --- | --- |
| Template crate | `templates/ootle-anchor-event-template-v2` |
| Module | `tari_private_ballot_anchor_v2` |
| Function | `publish_anchor_v2` |
| Event topic | `TariPrivateBallotAnchorV2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2` |
| Network | `mainnet` (Tari Ootle mainnet, v0.53.x cohort) |
| Mainnet deployment address | `template_ef4d7f348a4c3db7b6f9a9c30ac4fcbfdfb73e8bec59a808258861fcbbdc6cdb` |
| Mainnet publish transaction | `a898f8daaa0ae25095a02f69e5753e38dfe4a9c99c546d26297e08b81a3aa79c` |
| Mainnet publish timestamp | `2026-11-12T22:15:46Z` |
| Mainnet publish fee | 583883 microTARI |
| Qualified source commit | `c3ad6e6` |
| Qualified pre-walletd-optimization WASM | 61605 bytes |
| Mainnet SHA256 | `67e995cdbc0077967e8ed55ac6f33b6c7df0a369938b4a40bc45e3fe7b2778c7` |
| Mainnet BLAKE3-256 | `6ea3448e1beae71920a5ee5ce0cf51057a135a1f3a4e05dd26717a310e076830` |
| Historical esmeralda address (v0.42 cohort, reference only) | `template_bb539bddc9c264e4744ec462647b076fb97e2bdedb8692ea435804a6eb1eddee` |

The V2 function signature (compact on-chain summary):

```
publish_anchor_v2(
  anchor_digest: String,   // 64 lowercase hex — the V2 public-payload digest
  network: String,         // "mainnet"
  election_id: String,     // lowercase hex
  public_summary: String,  // exact canonical public-summary bytes (deterministic JSON)
)
```

The template emits exactly four metadata fields: `anchor_digest_v2`,
`network`, `election_id`, and `public_summary`. The full canonical summary is
placed on-chain verbatim so an independent observer can reproduce
`anchor_digest_v2` as `blake3(frame || public_summary)` without any detached
artifact. The `eligible_voters` / `accepted_ballots` / `rejected_ballots`
scalars and the counts they imply live *inside* `public_summary`, not as separate
arguments — an earlier six-argument draft of this document was wrong about that
and has been corrected.

Note the topic prefix: the on-chain event topic is prefixed by the **struct
name** `TariPrivateBallotAnchorV2` (as observed on-chain on esmeralda), not the
Rust module name. Every V2 receipt verifier in this repository matches that
form.

## 1. Build the template WASM

Build the four-argument V2 template against the **current mainnet cohort**
(walletd/indexer v0.53.x — every tagged v0.53.0–v0.53.3 release pins
`tari_template_lib = "=0.40.0"`) and emit it path-clean so no local build path
(cargo home, repository checkout) is baked into the published artifact. From
the template crate directory:

```bash
# Remap the cargo registry home out of embedded panic-location strings.
# <CARGO_HOME> is the builder's cargo home (e.g. the default ~/.cargo).
RUSTFLAGS="--remap-path-prefix=<CARGO_HOME>=cargo-home" \
  cargo build --release --target wasm32-unknown-unknown
```

The artifact is
`$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/tari_cc_private_ballot_ootle_anchor_event_template_v2.wasm`
(or `target/...` when `CARGO_TARGET_DIR` is unset).

Why `0.40.0`: v0.53.x changed how well-known types are decoded (`Type::WellKnown`
in `tari_template_abi` 0.24.x), so definitions built against the 0.33.0 family
cannot be read by a v0.53 wallet/indexer. This template uses only `String`
arguments and a `Unit` return — no well-known types — so its on-chain ABI is
unchanged between the 0.33.0 and 0.40.0 builds (verified by decoding the
`tari_tdef` section of both artifacts). The pin is exact (`=`) because
`tari_template_lib` 0.40.1 exists on crates.io but no tagged tari-ootle release
references it; it is treated as unreleased development.

Tests before any publish (host-runnable, no chain required):

```bash
cargo test -p tari-cc-private-ballot-ootle-anchor-event-template-v2
cargo test -p tari-cc-private-ballot-ootle-anchor-event-template-v2 \
  --test abi_contract -- --ignored   # decodes the built artifact's tari_tdef section
```

(Historical: the pre-v0.42 artifacts were built against `tari_template_lib`
0.31.1 and 0.33.0 for the esmeralda cohorts; see §2a. They are not deployable
on mainnet.)

## 2. Compute and confirm artifact digests

Compute both SHA256 and BLAKE3-256 over the exact release WASM. The qualified
artifact for the **mainnet v0.53.x cohort** is 61605 bytes:

| Algorithm | Digest |
| --- | --- |
| SHA256 | `67e995cdbc0077967e8ed55ac6f33b6c7df0a369938b4a40bc45e3fe7b2778c7` |
| BLAKE3-256 | `6ea3448e1beae71920a5ee5ce0cf51057a135a1f3a4e05dd26717a310e076830` |

The build was verified **byte-identical across rebuilds** with the same
toolchain and the same `--remap-path-prefix` flag. A path-clean scan of the
artifact (no `pdark`, no `.cargo`, no repository checkout paths; only the
sanitized `cargo-home` prefix appears) was performed before recording these
digests. Any changed build must be re-audited and re-recorded before anything
publishes.

> **The deployed template is not these exact bytes — and that is expected.**
> Before publishing, `walletd` runs the binary through its WASM optimizer
> (`optimize_wasm_template`, Binaryen `wasm-opt` optimize-for-size; see
> `applications/tari_walletd/src/handlers/transaction.rs` →
> `services/wasm_optimizer.rs` in tari-ootle). On the esmeralda cohort this was
> proven by measurement: re-running the exact pipeline over the reviewed
> artifact reproduced the deployed bytes byte-for-byte (61479 → 43913 bytes).
> Identity on mainnet is therefore established by (a) the reviewed
> pre-optimisation digests above, and (b) the **template address** recorded at
> publish plus a `templates.get` definition check (§3 step 6) — not by re-hashing
> the published binary.

> **Fail-closed lock note (do not skip).** The GUI's V2 publish lock pins the
> reviewed BLAKE3-256 in
> `TRUSTED_OOTLE_DEPLOYMENT_V2_ARTIFACT_DIGEST_HEX`
> (`crates/gui-core/src/trusted_anchor_deployment.rs`). At the time of this
> rewrite that constant still pins the historical esmeralda artifact
> (`ce5334df…`), so **the app will refuse to publish the new artifact until that
> constant is updated to `6ea3448e…`** (see §3a). This is intentional:
> substitution happens only after the publish below is reviewed.

## 2a. Historical qualification evidence (esmeralda testnet, v0.42.0 cohort — HISTORICAL)

The v0.42-era esmeralda deployment was qualified live end to end. It is retained
because it established the fee pipeline and the receipt-verifier evidence that
the mainnet procedure reuses; it is **not** a mainnet deployment record.

| Item | Value |
| --- | --- |
| Template | `TariPrivateBallotAnchorV2` at `template_bb539bddc9c264e4744ec462647b076fb97e2bdedb8692ea435804a6eb1eddee` |
| Live ABI (on-chain) | `publish_anchor_v2`, four `String` arguments (`anchor_digest`, `network`, `election_id`, `public_summary`), output `Unit`, `is_mut: false` |
| Anchor transaction | `13cac2ff1a6d108304bffc58ae4d1e5bb10266731bf35aa7910eef7a5ba5b571` |
| Outcome | `Commit` (`RECEIPT_VERIFIED`) |
| Emitted event | `TariPrivateBallotAnchorV2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2` with all four metadata fields |
| Dry-run estimate | 3324 units |
| Authorised max fee | 100000 units (authorisation ceiling, not a charge) |
| Actual fee paid | **3312** units (`total_fee_overcharge: 0`) |
| Election id | `gui-core-test-election` (disposable synthetic smoke-test election) |
| Expected anchor digest | `d8cd6ec6fe1cca0cd53b52795bf78b8a0198c0b89eafd8d6a12e4a3d762f9fc9` |
| Observed on-chain digest | `d8cd6ec6fe1cca0cd53b52795bf78b8a0198c0b89eafd8d6a12e4a3d762f9fc9` — **equal** |

The digest was additionally recomputed **independently of this codebase** by
hashing the on-chain `public_summary` bytes under the V2 domain frame
(`TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_PUBLIC_FRAME_V2` 0x00
`tari-cc-private-ballot/ootle-anchor-public-payload/v2` 0x00 ‖ canonical bytes)
with plain BLAKE3-256, and matched the emitted `anchor_digest_v2` exactly.

### Historical artifact digests (esmeralda cohort — superseded)

| Artifact | Bytes | SHA256 | BLAKE3-256 |
| --- | --- | --- | --- |
| Reviewed 0.33.0 build (v0.42 cohort) | 61479 | `76532c3c703aa2e755c8f436b0055a30b42caab2d803bbbc762af0eee9bbcfce` | `ce5334dfc0cdbfe74726accfe7201a778331bf2020865a2fc2b24a68a971d908` |
| Deployed post-`wasm-opt` (what `template_bb539bdd…` runs) | 43913 | `b87594d974bea1c4ea2e2c0e0df6c80ee99722b8a31cb7d9eb7fb65779b1ef5c` | `aa7ae07869f32b496dc8f6f6d88a61e9a8bac3fdc6c0cab7d27c41e1864d6297` |
| Pre-reset 0.31.1 build (v0.39.2 cohort) | 60714 | `022beeaea7805775192623c87970c03cd384732b37666d1d95a79a967fa44d49` | `475421a448be977dbf13c37d91b0ed9ef9c4d43f75da438ec64ea9cff38c66cc` |

The deployed 43913-byte binary was extracted from the esmeralda publish
transaction `612ff931c70ec1b85f08bf57f9b6939a88834e1bf4b0c9fee5f33c5458e83347`
(`std.template.publish`, `template_byte_size: 43913`, outcome `Commit`, fee
541818).

### Fee qualification history (esmeralda, retained deliberately)

| Attempt | Authorised max | Required | Result |
| --- | --- | --- | --- |
| 1 | 761 (derived from a 691 dry-run estimate × 11/10) | 1143 | `Abort` / `InsufficientFeesPaid`, tx `fca149bd2cad21ac554a9ea49964a1d5d8ab28a5ef5af056b1d5204414e0e992` |
| 2 | 2500 | 3324 (dry run) | stopped at preflight by `GUI_ANCHOR_V2_MAX_FEE_BELOW_ESTIMATE`, before any approval request or submission |
| 3 | 100000 | 3312 (actual) | **`Commit`** — see above |

Attempt 1 exposed the defect that `request.max_fee` was being replaced by an
estimate-derived fee. The fix makes `max_fee` authoritative and treats the
dry-run estimate as advisory evidence only. A fee failure is a **retryable
publication** failure: the finalized election, its result, and the anchor digest
are unaffected, and nothing is ever resubmitted without proof that the previous
attempt did not commit.

## 3. Publish the V2 template to Ootle mainnet (fee-bearing — operator only)

> This step spends real fees and is a live, irreversible outward action on
> mainnet. It is the operator's manual decision, performed only after review of
> this runbook, the audit trail of §1–§2, and the deploy wallet's balance. No
> one is to publish on the project's behalf without an explicit operator
> instruction.

Prerequisites, all verified against the **live mainnet** walletd before any
publish:

1. **Cohort check.** The target walletd/indexer is a current mainnet release
   (v0.53.x). A pre-0.53 wallet/indexer cannot read 0.40-built template
   definitions (`Type::WellKnown` decoding change in v0.53.0).
2. **Network check (fail closed).** walletd serves JSON-RPC at `/json_rpc`
   (path-normalize the base URL first). Verify the daemon is actually on
   mainnet before publishing — an endpoint URL is never proof of network:
   - `wallet.get_info` (unauthenticated) → `{ version, network, network_byte }`;
     require `network == "mainnet"`.
   - Since v0.53.2, walletd's `--network` defaults to **mainnet**; if the
     operator intended a testnet rehearsal instead, they must pass the network
     explicitly — never assume a default.
   - The app-side adapters additionally verify the indexer's own reported
     network (`get_network_info`) and epoch before every V2 publish step; the
     GUI lifecycle (§6a) does this automatically and refuses to prepare on a
     network mismatch.
3. **Balance check.** `accounts.get_balances` on the fee account: the balance
   must cover a bounded fee ceiling (see fee discipline below) with margin.
   Mainnet fees are real money — never publish from an account whose balance
   has not been checked.

Publish procedure (walletd JSON-RPC at `<walletd>/json_rpc`):

1. **Dry run first.** `transactions.publish_template` with
   `dry_run: true`, `binary` = the 61605-byte artifact (base64),
   `detect_inputs: true`, and the intended `fee_account`. The response returns
   `dry_run_fee` — record it.
2. **Set a bounded `max_fee`.** Choose a `max_fee` comfortably above the
   dry-run estimate (the esmeralda pipeline used a 100000-unit authorisation
   ceiling against a ~3324-unit estimate; pick a mainnet ceiling after seeing
   the mainnet dry run). `max_fee` is an authorisation ceiling, not a charge;
   the validator charges the actual fee. walletd rejects `max_fee` above its
   configured limit, and `max_fee: 0` is invalid (minimum 1).
3. **Publish.** `transactions.publish_template` with the same request but
   `dry_run: false` and the chosen `max_fee`. Capture the returned
   `transaction_id`, then confirm the outcome with
   `transactions.get_result` / `transactions.wait_result` (outcome must be
   `Commit`; on `Abort`, do **not** blindly retry — see the fee-discipline
   note below).
4. **Record the template address.** From the committed publish transaction,
   record the `template_<hex>` address, the transaction id, the exact
   published WASM byte size (`template_byte_size` — this is the post-`wasm-opt`
   size, expected to differ from 61605), the actual fee paid, and the timestamp.
   This is the identity that every V2 payload will pin.
5. **Fee discipline.** A fee failure (`InsufficientFeesPaid` or an over-ceiling
   dry run) is a retryable publication failure: the election and its digest are
   unaffected. Never re-derive `max_fee` from an estimate automatically; the
   operator always chooses the ceiling explicitly.
6. **Verify the on-chain definition.** `templates.get` (or
   `templates.list_authored`) on the new address must return
   `TariPrivateBallotAnchorV2` with exactly one function `publish_anchor_v2`
   taking four `String` arguments and returning `Unit`, `is_mut: false`. Any
   mismatch is a hard stop.

## 3a. Post-publish substitutions (applied)

The following substitutions have been applied in a single reviewed change after the
mainnet publish was confirmed. The GUI's fail-closed posture now accepts the
mainnet artifact and network:

1. **Artifact digest lock.**
   `crates/gui-core/src/trusted_anchor_deployment.rs`:
   `TRUSTED_OOTLE_DEPLOYMENT_V2_ARTIFACT_DIGEST_HEX` →
   `6ea3448e1beae71920a5ee5ce0cf51057a135a1f3a4e05dd26717a310e076830`
   (BLAKE3-256 of the reviewed pre-optimisation build).

2. **Mainnet network mapping.**
   `crates/ootle-anchor-adapter/src/network.rs`: extended
   `map_ootle_network` to accept `mainnet` (was deliberately testnet-only:
   esmeralda/igor/localnet). Every caller of the mapping was audited before the
   change; the indexer endpoint mapping landed together with it.

3. **Mainnet indexer endpoint.**
   `crates/ootle-anchor-network-adapters/src/endpoint.rs` now pins
   `TRUSTED_MAINNET_INDEXER_ENDPOINT_V1`. The GUI verifies the indexer's
   reported network fail-closed, so a wrong endpoint is refused, not mis-trusted.

4. **Deployment registry entry.**
   The mainnet deployment is recorded in `crates/deployment-registry`
   (`TARI_CC_PRIVATE_BALLOT_DEPLOYMENT_REGISTRY_V1`): network `mainnet`,
   template address `template_ef4d7f348a4c3db7b6f9a9c30ac4fcbfdfb73e8bec59a808258861fcbbdc6cdb`,
   artifact BLAKE3-256 `6ea3448e1beae71920a5ee5ce0cf51057a135a1f3a4e05dd26717a310e076830`,
   status `Current`, with the esmeralda address marked `Historical`.

## 4. Lock the V2 deployment

Lock the V2 deployment identity (network, template address, artifact digest) the
same way the V1 deployment is locked, so future V2 payloads pin the exact
deployed identity. (The V2 deployment lock is a separate record from V1; the V1
deployment remains untouched.)

## 5. Build and verify detached V2 evidence from the verified archive

In the GUI: select the verified finalized archive → **Anchor version → V2 public
summary → Build V2 public summary**. Review the public fields (question, tally,
counts, commitments) and the **V2 anchor digest**. This step is read-only: it
writes nothing, contacts no wallet, and spends no fees.

The build result includes `payload_cbor_hex` — the full canonical detached
evidence — and `v2_anchor_digest_hex` — the value to publish on-chain. Verify
that detached evidence against the archive before preparing the transaction.

## 6. Prepare and manually approve one V2 anchor (fee-bearing)

Prepare a `publish_anchor_v2` call with the digest and the canonical
`public_summary` (plus `network` and `election_id`) from the build result. Save
the full `payload_cbor_hex` as the detached evidence file alongside the archive
sidecars.

Do not publish until the operator has manually reviewed the detached evidence,
the V2 lock, and the resulting transaction. The V1 lock and V1 publish path are
not substitutes for any V2 value.

## 6a. Durable, manually-gated lifecycle (how the GUI drives it)

The GUI drives the fee-bearing publish as a **durable, single-step state
machine** (`run_v2_live_anchor_lifecycle_step`). Each call performs at most one
transition and never sleeps, so the UI stays responsive and every step is an
explicit operator action. State is persisted in sibling sidecar files next to
the archive directory (never inside it):

| Sidecar | Purpose |
| --- | --- |
| `<archive>.v2-anchor-lifecycle.json` | mutable lifecycle snapshot (atomic replace: temp + fsync + rename + dir fsync) |
| `<archive>.v2-anchor-evidence.json` | immutable success evidence, written **once** only after a receipt verifies |
| `<archive>.v2-anchor-failure.json` | immutable failure/debug artifact, written on a rejected transaction or a receipt that does not verify |

Phases: `WAITING_FOR_WALLET_APPROVAL → APPROVED → POLLING_RECEIPT →
RECEIPT_VERIFIED`, with terminal `REJECTED`/`FAILED`.

- **Preparation** (`decision: none`, no snapshot yet) replays the detached
  evidence against the verified archive, confirms the walletd/indexer network
  and current epoch, builds the exact four-argument `publish_anchor_v2` call,
  runs walletd input detection, re-inspects the detected transaction, and
  creates a frozen walletd approval request. It never approves or submits.
- **Approval** requires an explicit `decision: approve`. There is no
  auto-approval; the wallet approval gate is the operator's.
- **Submit** happens only from `APPROVED` and never resubmits: on every step the
  machine first reconciles against walletd's live status, so a crash between
  submit and snapshot persistence is recovered by **adopting the already-sealed
  transaction id** rather than issuing a second submit. An expired approval
  window maps to a terminal `FAILED`; a wallet rejection maps to `REJECTED`.
- **Receipt polling** retrieves the receipt through the indexer and verifies it
  with the V2 receipt verifier **only** (`verify_v2_event_receipt`) against the
  locked V2 deployment binding and the **all four** event fields (`anchor_digest_v2`,
  `network`, `election_id`, `public_summary`). A verifier failure or
  a rejected transaction is terminal and writes the failure artifact; a
  not-yet-available receipt keeps polling without failing.
- **Evidence-exists crash recovery.** If a success-evidence sidecar already
  exists when success is re-reached — a crash after the evidence write but before
  the snapshot advanced — the existing record is **re-validated** (request
  bindings, locked deployment, independent archive replay, and, when the snapshot
  is entirely absent, a freshly re-fetched and re-verified on-chain receipt) and
  then **adopted idempotently**, never overwritten and never re-published. A
  record that does not match fails closed (`GUI_ANCHOR_V2_EVIDENCE_CONFLICT`); a
  transient indexer condition returns `GUI_ANCHOR_V2_EVIDENCE_RECHECK_UNAVAILABLE`
  (retry). A `…v2-anchor-failure.json` artifact is never read as success.

This lifecycle is offline-tested end to end with scripted walletd/indexer
transports (`crates/gui-core/tests/live_anchor_v2_lifecycle.rs`): manual
approval, submit, verified receipt, wallet rejection, approval expiry,
crash-recovery duplicate-submit prevention, receipt-verifier failure, rejected
and pending receipts, sidecar placement, request-binding mismatch, and the
evidence-exists crash-recovery paths (adopt valid, fail closed on mismatch, no
success from a failure sidecar, no silent overwrite). Every V2 event scalar has
an independent mutation test in
`crates/anchor-transport/tests/receipt_verification.rs`.

## 7. Verify the V2 receipt

Retrieve the transaction receipt/event through the indexer and verify the exact
V2 template address/topic plus `anchor_digest_v2`, `network`, `election_id`, and
`public_summary` against the detached evidence and archive replay.

## 8. Verify the evidence (offline)

In the GUI (or via the `verify_v2_public_anchor_evidence` command), provide the
archive directory, the detached `payload_cbor_hex`, and the on-chain
`expected_digest_hex`. The verifier:

1. decodes the payload and runs the privacy guard,
2. confirms the payload hashes to the on-chain digest,
3. independently rebuilds the payload from an archive replay and requires an
   exact field-by-field match,

failing on any tamper (changed question, tally, commitment, count, archive or
manifest hash, or template binding).

## Pre-publish safety gates (checklist)

Every item must be checked immediately before §3; any unchecked item is a stop.

- [ ] Toolchain: `rust-toolchain.toml` respected; `tari_template_lib = "=0.40.0"`
      in the template's `Cargo.lock` (v0.53.x cohort pin).
- [ ] `cargo test` for the template crate passes (unit + `abi_contract`,
      including the `-- --ignored` artifact-ABI test).
- [ ] Artifact built with `--remap-path-prefix=<CARGO_HOME>=cargo-home`;
      path-clean scan finds no builder-local paths.
- [ ] Rebuild reproducibility: a second build is byte-identical (same SHA-256).
- [ ] SHA-256 and BLAKE3-256 match §2 exactly (61605 bytes).
- [ ] walletd `wallet.get_info` reports `network == "mainnet"` (v0.53.x cohort);
      indexer `get_network_info` agrees (app lifecycle enforces both).
- [ ] Fee account balance covers the chosen `max_fee` ceiling with margin.
- [ ] Dry-run publish succeeded and `dry_run_fee` is recorded; `max_fee`
      ceiling set explicitly by the operator (never estimate-derived).
- [ ] Post-publish substitution list (§3a) reviewed and scheduled — the app
      stays fail-closed until they land.

## Privacy guarantees

The V2 payload contains only public fields. It never includes voter public keys,
nullifiers, credentials, per-voter packages/receipts, transport routing, wallet
tokens, private keys, local filesystem paths, or machine/user names. Both a
structural bound and a textual leak guard
(`assert_v2_public_payload_is_leak_free`) enforce this, and are covered by tests.

