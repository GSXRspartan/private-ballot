# V2 Public-Summary Anchor — Deployment Runbook

> Status: **template source ready, NOT deployed.** No live publish has been
> performed. Do not deploy or publish live until explicitly approved.
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
| Network | `esmeralda` |

The V2 function signature (compact on-chain summary):

```
publish_anchor_v2(
  anchor_digest: String,     // 64 lowercase hex — the V2 public-payload digest
  network: String,           // e.g. "esmeralda"
  election_id: String,       // lowercase hex
  eligible_voters: String,   // decimal
  accepted_ballots: String,  // decimal
  rejected_ballots: String,  // decimal
)
```

## 1. Build the template WASM

Build exactly as the V1 template is built (same pinned `tari_template_lib`
`=0.31.1`, same release profile). From the template crate directory:

```bash
cargo build --release --target wasm32-unknown-unknown
```

The artifact is `target/wasm32-unknown-unknown/release/tari_cc_private_ballot_ootle_anchor_event_template_v2.wasm`.

## 2. Compute and confirm artifact digests

Compute both SHA256 and BLAKE3-256 over the exact release WASM. The reviewed
artifact currently has:

| Algorithm | Digest |
| --- | --- |
| SHA256 | `022beeaea7805775192623c87970c03cd384732b37666d1d95a79a967fa44d49` |
| BLAKE3-256 | `475421a448be977dbf13c37d91b0ed9ef9c4d43f75da438ec64ea9cff38c66cc` |

The V2 lock accepts only this reviewed BLAKE3-256 value. A changed build must
be audited before the lock policy is updated.

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

Prepare a `publish_anchor_v2` call with the digest and the compact scalar summary
(`network`, `election_id`, `eligible_voters`, `accepted_ballots`,
`rejected_ballots`) from the build result. Save the full `payload_cbor_hex` as
the detached evidence file alongside the archive sidecars.

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
  and current epoch, builds the exact six-argument `publish_anchor_v2` call,
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
  locked V2 deployment binding and the **all six** scalar event fields (digest,
  network, election id, eligible/accepted/rejected counts). A verifier failure or
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
V2 template address/topic plus `anchor_digest_v2`, `network`, `election_id`,
`eligible_voters`, `accepted_ballots`, and `rejected_ballots` against the
detached evidence and archive replay.

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
