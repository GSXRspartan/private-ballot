# V2 Public-Summary Anchor — Deployment Runbook

> **Network generation: post-Ootle-v0.42 esmeralda testnet reset.** The
> v0.39.2-era network was wiped; every address, artifact, and digest from that
> generation is historical and is marked as such below.
>
> Status: **V2 template source ready and built for the current cohort.** The
> post-reset deployment address is recorded in the Identity table below. This
> repository does not itself perform, authorize, or verify an on-chain publish:
> step 3 is a fee-bearing outward action that only the operator may take.
>
> **Controlled-alpha only.** The V2 live path is a controlled-alpha capability.
> V2 template publish is allowed **only after** the V1/V2 isolation blocker is
> fixed — while the V2 anchor version is selected, no V1 publish/status/reject/
> approve control may be triggered from any visible or advanced UI control
> (enforced both at each disabled button and at the shared `onAnchorStep` /
> `onPublishTariAnchor` entry points; guard-tested in
> `gui/test/anchorVersionGating.test.ts`). This blocker is fixed. No live
> publish was performed by that fix.

The V2 anchor publishes a richer *public election summary* derived only from the
independently verified, finalized archive. It uses the **digest + detached
evidence** strategy: the compact V2 public-payload digest and a small scalar
summary go on-chain; the full canonical payload travels in a detached evidence
file, and the offline verifier proves the detached payload hashes to the
on-chain digest.

## Identity (preferred, matches the code)

| Field | Value |
| --- | --- |
| Template crate | `templates/ootle-anchor-event-template-v2` |
| Module | `tari_private_ballot_anchor_v2` |
| Function | `publish_anchor_v2` |
| Event topic | `tari_private_ballot_anchor_v2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2` |
| Network | `esmeralda` (post-Ootle-v0.42 testnet reset) |
| Current deployment address | `template_bb539bddc9c264e4744ec462647b076fb97e2bdedb8692ea435804a6eb1eddee` |

The V2 function signature (compact on-chain summary):

```
publish_anchor_v2(
  anchor_digest: String,   // 64 lowercase hex — the V2 public-payload digest
  network: String,         // e.g. "esmeralda"
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

## 1. Build the template WASM

Build the four-argument V2 template against the **Tari Ootle v0.42.0
testnet-reset (esmeralda) cohort** — `tari_template_lib = "=0.33.0"` — and emit
it path-clean so no local build path (cargo home, repository checkout) is baked
into the published artifact. From the template crate directory:

```bash
# Remap the cargo registry home out of embedded panic-location strings.
# <CARGO_HOME> is the builder's cargo home (e.g. the default ~/.cargo).
RUSTFLAGS="--remap-path-prefix=<CARGO_HOME>=cargo-home" \
  cargo build --release --target wasm32-unknown-unknown
```

The artifact is `target/wasm32-unknown-unknown/release/tari_cc_private_ballot_ootle_anchor_event_template_v2.wasm`.

(Historical: the pre-reset artifact was built against `tari_template_lib`
`=0.31.1` on the v0.39.2 cohort; that build is not valid on the reset network.)

## 2. Compute and confirm artifact digests

Compute both SHA256 and BLAKE3-256 over the exact release WASM. The reviewed
artifact for the **current esmeralda v0.42.0 cohort** is 61479 bytes:

| Algorithm | Digest |
| --- | --- |
| SHA256 | `76532c3c703aa2e755c8f436b0055a30b42caab2d803bbbc762af0eee9bbcfce` |
| BLAKE3-256 | `ce5334dfc0cdbfe74726accfe7201a778331bf2020865a2fc2b24a68a971d908` |

The V2 lock accepts only this reviewed BLAKE3-256 value (the constant
`TRUSTED_OOTLE_DEPLOYMENT_V2_ARTIFACT_DIGEST_HEX` in
`crates/gui-core/src/trusted_anchor_deployment.rs`). A changed build must be
audited before the lock policy is updated. The build is reproducible: rebuilding
with the same toolchain and the same `--remap-path-prefix` yields byte-identical
output.

> **Proven linkage (supersedes the former "unproven linkage" caveat).**
> The deployed template is **not** these exact bytes, and that difference is now
> fully explained and reproduced. Before publishing, `walletd` runs the binary
> through `wasm-opt` (`OptimizationOptions::new_optimize_for_size()` plus
> `BulkMemory`/`ReferenceTypes` enabled, `Simd`/`RelaxedSimd` disabled, and the
> `StripDebug`/`StripProducers`/`StripTargetFeatures` passes — see
> `applications/tari_walletd/src/services/wasm_optimizer.rs` in tari-ootle
> `a43773e`). The deployed binary is therefore the deterministic optimised form
> of the reviewed artifact.
>
> This was proven by measurement, not assumed: re-running that exact pipeline
> (Binaryen **116**, matching tari-ootle's `wasm-opt 0.116.1`) over the reviewed
> 61479-byte artifact reproduces the deployed bytes **byte-for-byte**.
>
> | Artifact | Bytes | SHA-256 | BLAKE3-256 |
> | --- | --- | --- | --- |
> | Reviewed pre-optimisation build (this repository) | 61479 | `76532c3c703aa2e755c8f436b0055a30b42caab2d803bbbc762af0eee9bbcfce` | `ce5334dfc0cdbfe74726accfe7201a778331bf2020865a2fc2b24a68a971d908` |
> | Deployed, post-`wasm-opt` (what `template_bb539bdd…` runs) | 43913 | `b87594d974bea1c4ea2e2c0e0df6c80ee99722b8a31cb7d9eb7fb65779b1ef5c` | `aa7ae07869f32b496dc8f6f6d88a61e9a8bac3fdc6c0cab7d27c41e1864d6297` |
>
> The deployed 43913-byte binary was extracted from the publish transaction
> `612ff931c70ec1b85f08bf57f9b6939a88834e1bf4b0c9fee5f33c5458e83347`
> (`std.template.publish`, `template_byte_size: 43913`, outcome `Commit`, fee
> 541818). The V2 lock still pins the **pre-optimisation** BLAKE3-256
> (`ce5334df…`), which is the value this repository builds and reviews.

## 2a. Live qualification evidence (esmeralda, v0.42.0 cohort)

The deployed template has been qualified live end to end:

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

Reproduce with the repository harness:

```bash
PRIVATE_BALLOT_V2_MAX_FEE=100000 \
PRIVATE_BALLOT_V2_FEE_COMPONENT=component_<hex> \
WALLETD_AUTH_TOKEN=<token> \
cargo test -p tari-cc-private-ballot-gui-core --test live_v2_anchor_esmeralda \
  -- --ignored --nocapture --test-threads=1
```

### Fee qualification history (retained deliberately)

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

Historical (pre-reset v0.39.2 / `tari_template_lib` 0.31.1 artifact, 60714 bytes,
retained for provenance only): SHA256
`022beeaea7805775192623c87970c03cd384732b37666d1d95a79a967fa44d49`, BLAKE3-256
`475421a448be977dbf13c37d91b0ed9ef9c4d43f75da438ec64ea9cff38c66cc`. That
network generation was wiped by the v0.42 reset, so this artifact is no longer
deployable.

## 3. Publish the V2 template to Ootle

Publish the WASM through walletd exactly as the V1 template was published, on
`esmeralda`. Record the returned **template address** (`template_<hex>`).

> This step spends fees and is a live outward action. It is the operator's
> manual decision, performed only after review of this runbook.

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

## Privacy guarantees

The V2 payload contains only public fields. It never includes voter public keys,
nullifiers, credentials, per-voter packages/receipts, transport routing, wallet
tokens, private keys, local filesystem paths, or machine/user names. Both a
structural bound and a textual leak guard
(`assert_v2_public_payload_is_leak_free`) enforce this, and are covered by tests.
