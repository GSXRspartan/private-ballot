# Performance remediation — Slice 2 verified-session cache

## 1. Executive summary

IMPLEMENTATION STATUS:
implemented but Rust validation pending

The implementation is complete at source level. The pending validation is an
environment/toolchain blocker: this Codex Windows environment cannot locate
`dlltool.exe` while compiling a dependency. It is not a Slice-2 behavioral
failure and no source workaround has been made for it.

Slice 2 adds a bounded, process-local, memory-only cache for a durable
workspace session only after that session has completed the existing full
`GuiElectionSessionV1::from_durable_snapshot` replay. The Tauri resume command
uses it from `run_blocking_command`; an unchanged second resume has no
historical ballot replay or Triptych verification.

The cache does not change durable data, proof verification, verifier policy,
the protocol, `MAX_REGISTRY_MEMBERS`, archive verification, or any Ootle,
walletd, indexer, signing, fee, or network behavior.

## 2. Pre-implementation cache-key adversarial analysis

The audit proposal `(workspace_id, head_revision, head_revision_digest_hex,
verifier_epoch)` is sufficient for the replay-verified durable session only
when the head digest is read through the existing full committed-history
validator. It is not sufficient for authority or signed-status sidecars, so
those are deliberately outside the cached value.

`revision_digest_hex` is BLAKE3 over a domain-separated complete serialized
revision record. A session record contains its workspace id, revision,
predecessor revision/digest, update time, lifecycle state, manifest bytes,
registry bytes, candidate bytes, and exact stored ballot-package bytes. The
loader verifies every commit marker, revision filename digest, record digest,
record workspace id, contiguous revision number, and predecessor link through
the head. The head therefore commits the current session semantics and the
prior revision chain.

The committed manifest supplies protocol version and proof-suite policy;
registry and candidate commitments are validated from the committed canonical
artifact bytes. A changed manifest, registry, candidate set, package list,
package bytes, lifecycle/finalization state, or predecessor changes the head
identity or is rejected while validating it.

## 3. Final cache identity

`VerifiedSessionKeyV1` contains:

1. `workspace_id` — binds the cache entry to the validated direct-child
   workspace directory and prevents cross-workspace aliasing.
2. `head_revision` — makes monotonic durable transitions distinct, including
   rollback/recovery to an earlier head.
3. `head_revision_digest_hex` — commits all current serialized session inputs
   and, through the predecessor chain, the validated history.
4. `VERIFIED_SESSION_CACHE_EPOCH_V1` — explicit local policy/version boundary
   for a code change that changes reconstruction or verifier semantics without
   changing durable bytes.

The cache key is formed only after `load_committed_history` has authenticated
the entire chain. A raw filename, parsed metadata, or display summary can
never form a cache entry.

### 3.1 Verifier-policy epoch source proof and maintenance contract

The epoch is defined by Slice 2 in
`crates/gui-core/src/verified_session_cache.rs` as:

```rust
pub const VERIFIED_SESSION_CACHE_EPOCH_V1: u32 = 1;
```

It did not exist before Slice 2; the containing cache source file is new in
this slice. `VerifiedSessionKeyV1::new` writes this constant into its private
`verifier_epoch: u32` field. The key derives `PartialEq`, `Eq`, and `Hash`, so
that field participates in every cache lookup. The sole production key builder
is `verified_session_key_for_committed` in `crates/gui-core/src/workspace.rs`;
it is reached only after committed-history validation.

The epoch represents the local, in-process semantics of what it means for a
durable session to be replay-verified: `GuiElectionSessionV1::from_durable_snapshot`,
its manifest/proof-suite-policy handling, and the replayed normal intake path
that invokes the Triptych verifier adapter. It is not a network protocol
version, durable-format field, external runtime dependency, or claim about
Tari/Ootle behavior.

This is deliberately a manual maintenance contract, not a source-derived
runtime identity. Increment it in a future source change that changes the
accept/reject semantics of durable-session reconstruction without necessarily
changing the serialized head: verifier or Triptych-adapter policy, manifest
or proof-suite-policy interpretation, canonical replay behavior, or another
reconstruction invariant. A durable manifest/protocol change already changes
the validated head digest and therefore misses independently.

There is no pre-existing independent, canonical verifier-semantics identifier
in this application from which a safer identity could be derived. Deriving one
from a crate version, source hash, or an invented runtime dependency would be
less stable or would create a new protocol coupling. The maintenance contract
is therefore the smallest explicit fence. Omitting it would let a long-lived
process reuse an entry whose durable bytes match but whose newly changed local
verification semantics do not. Changing the constant makes every newly built
key unequal to and differently hashed from all entries built with the old
value; because entries are process-local, no old entry can alias the new
semantics.

## 4. State intentionally outside the key and hit revalidation

- The `organizer-authority` marker is an app-owned sidecar capability, not
  session data. It is read while the post-load workspace summary is created
  and read again in the Tauri resume worker after persisted-status replay. A
  missing or malformed marker remains voter-only.
- The draft `superseded` marker is a sidecar used only for draft resumption.
  It is checked before a draft resumes and is not cached.
- Persisted authenticated election-status records live in the status directory.
  They are re-read, signature/binding-verified, and applied to the per-call
  session clone after every cached or uncached resume.
- Filesystem replacement with exactly the same validated workspace id and
  head digest is semantically the same replay input. Replacement with changed
  bytes/digest misses or fails validation; a rollback to a different head
  misses. There is no persistent trusted bit.

## 5. TOCTOU defense

The cache loader first fully reads and validates a committed head, then
reconstructs from that already-loaded snapshot. On a miss it reads and
validates the head again before insertion; a different key returns
`GUI_WORKSPACE_IDENTITY_CHANGED` and inserts nothing. On a hit it performs the
same final head validation before returning the cached session. Thus a disk
change cannot cause a session reconstructed from one head to be cached under
another head. The cached session itself is immutable and cloned for the
caller, so status replay or later mutations cannot alter the entry.

## 6. Cache architecture, ownership, and concurrency

`VerifiedElectionSessionV1` has no public constructor. Only the durable replay
boundary constructs it. `VerifiedElectionSessionCacheV1` stores `Arc` values
of that wrapper and never accepts a decoded snapshot or display metadata.
Callers receive a transactional clone, not a shared mutable session.

The LRU has four entries by default. This is deliberately small: each session
owns full artifact bytes, packages, acceptance ledger, transcript, and
verifier state; it is a convenience cache, not a second durable store.

Per-key in-flight records use a condition variable. One request is the owner;
same-key requests wait for its result. Success inserts one entry and wakes all
waiters. Failure or a caught reconstruction panic wakes all waiters but is not
cached; a later request retries. No cache mutex is held while proof replay
runs. Different keys are permitted at once, subject to the exact rule in
`default_reconstruction_parallelism`:

`available_parallelism().get().saturating_sub(1).clamp(1, 2)`.

Thus one reconstruction is permitted when the runtime reports one or two
available CPUs; two are permitted when it reports three or more; and one is
used if CPU availability cannot be queried. This reserves one reported CPU
where possible and caps simultaneous expensive replays at two.

## 7. Invalidation and operations

Revision identity is the authoritative invalidation boundary. Successful
organizer session mutations invalidate their workspace cache entry after the
new revision commits; this covers lifecycle transitions and offline new-ballot
intake through `mutate_session_transactionally`. Accepted inbox reconciliation
does the same. Freeze and deletion invalidate too. External import/recovery,
replacement, corruption, manifest/registry/candidate changes, and rollback
are protected by the freshly read key and verify-before/after checks even if
they bypass local invalidation.

No incremental cache advance is implemented. After a newly accepted ballot,
the new proof is verified by the unchanged intake path, the old entry is
discarded, and the next authoritative durable resume replays the new head once.

The cache is used only for durable workspace resume/open. Tally,
participation, lifecycle operations, and archive writing already use the
currently installed verified session, so they do not reconstruct or look up
the durable cache. Workspace listing remains metadata-only. Archive replay is
intentionally separate: archive inputs, digest, and trust domain differ.

## 8. Instrumentation and trigger audit

The existing aggregate atomics now include lookup, hit, miss, insertion,
eviction, invalidation, single-flight owner/waiter/failure, reconstruction,
historical replay, adapter verification, and reconstruction duration. They
contain no workspace ids, paths, hashes, proofs, ballots, nullifiers, voter
keys, or secrets.

Final source audit:

- Tauri production resume calls
  `resume_election_workspace_with_verified_session_cache_v1` inside
  `run_blocking_command`.
- The only production `GuiElectionSessionV1::from_durable_snapshot` call is
  inside that cache miss closure. The public compatibility resume helper uses
  a fresh ephemeral cache and therefore preserves full replay for callers that
  do not retain process cache state.
- `TariTriptychPrototypeVerifierV1::verify` remains invoked through the
  unchanged session intake/replay path. New-ballot intake has not been routed
  through the cache.
- No archive verifier uses this workspace cache.

Before Slice 2, each explicit resume replayed N stored packages. After Slice
2, first resume is one reconstruction/N replays/N adapter calls; second
unchanged resume is one cache hit/zero reconstruction/zero replays/zero calls.
Listing remains zero/zero/zero from Slice 1.

## 9. Tests and validation

Added `crates/gui-core/tests/verified_session_cache.rs` covering:

- first and second unchanged resume counts;
- durable revision change miss;
- preserved new-ballot one-proof verification and next-head replay;
- eight concurrent identical resumes with one reconstruction;
- failed reconstruction is neither trusted nor negative-cached;
- bounded LRU eviction and re-verification.

`node --test test/performanceRemediationSlice1.test.ts` passed: **11/11**.
It confirms listing remains metadata-only and off the event thread.

The focused Rust test command is pending because it could not begin compiling
project code in this environment: the Windows toolchain cannot find
`dlltool.exe` while building `getrandom`. This is an environment/toolchain
blocker, not a test failure attributed to Slice 2. `rustfmt --check` passed
for both new Slice 2 Rust files. The known pre-existing whole-suite
`archive_writer.rs` String vs `&str` branch-WIP compile blocker remains
untouched; it could not be reached until `dlltool.exe` is available.

## 10. Security invariants and remaining risks

Preserved: cryptographic replay before cache insertion; new-ballot proof
verification; fail-closed durable chain validation; sidecar fail-closed
authority; signed-status verification; metadata/authoritative-state separation;
memory-only lifetime; archive independence; and off-event-thread CPU replay.

Remaining risk: the cache avoids repeated proof replay but does not solve the
separate revision-chain read/decode write amplification. It also cannot make
external filesystem mutation atomic with a process that does not cooperate;
the verify-before/verify-after design fails closed on observed identity drift.

## 11. Recommended Slice 3

Forensic durable revision-chain/write-amplification audit. No durable-format
or protocol redesign was attempted here.

SLICE 2 VERDICT:
IMPLEMENTATION STATUS:
implemented but Rust validation pending

Final cache key:
workspace_id, head_revision, head_revision_digest_hex, verifier_epoch

Cache lifetime:
Process-local, memory-only AppState field; empty after restart

First open historical replays:
N required (asserted by the new focused test)

Second unchanged open historical replays:
0 required

Second unchanged open Triptych calls:
0 required

Concurrent identical opens reconstructions:
1 required

Stale-state reuse tests:
Revision-change, explicit invalidation, and eviction tests added; pre/post identity checks are source-enforced; Rust execution pending because dlltool.exe is unavailable

New-ballot verification:
PRESERVED

Workspace-list Slice 1 regression:
PASS

Tests:
Frontend Slice 1 source regression 11/11 PASS; Slice 2 Rust target pending before compilation because dlltool.exe is unavailable

Production files changed:
crates/gui-core/src/verified_session_cache.rs; crates/gui-core/src/instrumentation.rs; crates/gui-core/src/workspace.rs; crates/gui-core/src/lib.rs; gui/src-tauri/src/lib.rs

Security invariants changed:
NONE

Durable format changed:
NO

Remaining redundant replay paths:
First durable workspace resume after restart/head change, and the intentionally separate archive verification flows

Recommended Slice 3:
Forensic durable revision-chain/write-amplification audit
