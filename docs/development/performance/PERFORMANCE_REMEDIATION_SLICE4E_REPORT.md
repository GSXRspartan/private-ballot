# Performance Remediation — Slice 4E
# Incremental Verified-Session Advancement

Status: **PASS**.

Slice 4E turns a durable mutation of an already-verified election session into an
in-place advancement of the verified-session cache, instead of invalidating it
and later replaying all history on the next resume. It preserves the Slice 2
cache identity and all its fail-closed/TOCTOU protections, introduces no
persistent trust, and is guarded by a proven semantic-equivalence invariant plus
an independent re-read of the new committed durable head.

---

## 1. Problem and target

Before 4E: `VerifiedSession(head N)` + an authoritatively-processed mutation +
durable commit `N+1` → the cache is **invalidated**, so the next resume performs
a full cold reconstruction (replaying every ballot through Triptych verification),
even though the process just held the correct post-mutation verified session.

After 4E: the same flow **advances** the cache to `VerifiedSession(head N+1)` with
zero historical proof replay, provided the new committed durable head is
independently confirmed.

## 2. Absolute-requirement equivalence proof (load-bearing)

The advanced session must be semantically identical to a fresh authoritative
reconstruction of the exact committed state. Because the committed durable body
**is** `session.to_durable_snapshot()`, the invariant is:

```
session  ≡  from_durable_snapshot(session.to_durable_snapshot())  =  session.replayed_clone()
```

`crates/gui-core/tests/verified_session_advancement.rs` **proves** this before any
production trust, for every durable mutation category, comparing **all**
authoritative state — durable snapshot bytes, lifecycle state, accepted count,
the full `VerificationTranscriptV1` (submissions + ordered decisions), and the
deterministic tally — against **both** the serial and the Slice 4B parallel
reconstruction path:

| Mutation category | Proven equal to fresh reconstruction |
|---|---|
| Accepted ballot | yes |
| Rejected (malformed) ballot, durably stored | yes |
| Duplicate-nullifier rejection | yes |
| Private-intake reconciliation | yes |
| Close transition | yes |
| Mark-verified transition | yes |
| Finalization | yes |
| Long chain of sequential mutations (every intermediate head) | yes |

Had any category failed, incremental advancement would be unsound and Slice 4E
would STOP. All eight pass. This equivalence is a consequence of the existing
design: live intake and reconstruction share the identical per-package pipeline
(`process_intake_package`), applied in the same canonical order, and the derived
private-intake index is a deterministic function of the transcript. The only
difference between an advanced session and a fresh reconstruction is the
process-local inbox-file validation cache (a pure optimization that is a superset
in the advanced session and does not affect authoritative state).

## 3. Cache identity (unchanged)

The Slice 2 identity is preserved exactly:
`(workspace_id, head_revision, head_revision_digest_hex, VERIFIED_SESSION_CACHE_EPOCH_V1)`.
No weaker identity is invented and the epoch is **not** bumped: reconstruction and
verifier semantics are unchanged (the advance installs a session equal to what
reconstruction would produce), so the durable identity remains sufficient.

## 4. Write → trust ordering

`crates/gui-core/src/workspace.rs::advance_verified_session_after_commit_v1` is
the sole trust boundary. It runs strictly after the caller has (1) applied the
mutation in memory and (2) committed the new durable revision, and then:

3. **independently re-reads the newest committed head from disk** via
   `load_newest_committed_workspace`, which runs the same full chain validation
   (commit markers, per-revision digests, contiguous revisions, predecessor
   links) a cold resume uses;
4. derives the head's authoritative `VerifiedSessionKeyV1`;
5. confirms the re-read head is **exactly** `expected_new_revision` **and** its
   committed body equals `advanced_session.to_durable_snapshot()`;
6. only then installs the advanced session (a `VerifiedElectionSessionV1` whose
   constructor is crate-private — there is no public "trust this session" API).

By (5), the committed body equals the advanced session's own snapshot, so the
proven invariant (§2) makes the advanced session identical to a fresh
reconstruction of that head. Any mismatch, non-session head, missing head, or
read error fails closed to plain invalidation (cold reconstruction on the next
resume).

## 5. External drift, crash, and concurrency

- **External mutation / head change between write and re-read** → the re-read
  head is a different revision or body → refused, fall back to invalidation
  (MEASURED: `external_head_change_after_write_is_not_advanced`).
- **Revision mismatch** → refused (MEASURED: `revision_drift_refuses_to_advance_and_falls_back`).
- **Crash before durable commit** → no new cache authority (the advance never
  runs). **Crash after commit, before advance** → memory is lost on restart; the
  next launch cold-replays. **Crash after advance** → the cache is memory-only and
  empty on restart. No persistent trust ever exists.
- **Single-flight** (Slice 2) is unchanged. `install_advanced` is a bounded,
  LRU-managed insert that supersedes older heads for the workspace; a concurrent
  reconstruction of the same head would only ever publish an equal value.
- The advance is **best-effort**: a failure never fails the mutation (the durable
  commit already succeeded); it only forgoes the optimization and invalidates.

## 6. New-ballot verification preserved

The optimization changes only the *historical replay* after a successful
authoritative mutation. Each new incoming ballot is still verified exactly once
through the unchanged intake pipeline before acceptance (the mutation itself is
that verification); advancement never turns "was in an in-memory session" into a
bypass of new-proof verification. `reconstruction_instrumentation`'s
new-ballot-verifies test remains green.

## 7. Complexity

For a navigation-heavy, long-running election of N ballots processed in the same
process: before, repeated resume-after-mutation could accumulate O(N²) cumulative
historical replay; after, it is O(N) cumulative new-ballot verification (each
ballot verified once at intake) plus O(1) same-process verified resume per head.
This is not O(1) total election work — the one-time per-ballot verification
remains — but it eliminates the quadratic re-replay.

## 8. Instrumentation

gui-core counters: `verified_session_cache_advances`,
`verified_session_cache_advance_failures`,
`verified_session_cache_advance_identity_drift`,
`verified_session_cache_advance_unsupported_mutation` (reserved),
`verified_session_cache_advance_fallback_replays`.

## 9. Measured behavior (MEASURED)

`crates/gui-core/tests/verified_session_advance_cache.rs`:

| scenario | from_durable_snapshot | historical_ballots_replayed | triptych_adapter | cache_hits | advances |
|---|---:|---:|---:|---:|---:|
| Advance then immediate resume | 0 | 0 | 0 | 1 | ≥1 |
| Each of 4 sequential advances + resume | 0 | 0 | 0 | 1 | 1 |
| Revision drift | (fallback) | — | — | 0 | 0 (drift+fallback recorded) |
| External head change | (fallback) | — | — | 0 | 0 (drift recorded) |

An advanced resume performs zero reconstruction and zero Triptych verification.

## 10. Production files changed

- `crates/gui-core/src/verified_session_cache.rs` — `from_incremental_advance` +
  `install_advanced`.
- `crates/gui-core/src/workspace.rs` — `advance_verified_session_after_commit_v1`.
- `crates/gui-core/src/instrumentation.rs` — advancement counters.
- `crates/gui-core/src/lib.rs` — export.
- `gui/src-tauri/src/lib.rs` — `mutate_session_transactionally` and the
  private-intake reconciliation path advance instead of only invalidating.

## 11. Tests and results

| suite | result |
|---|---|
| verified_session_advancement (equivalence proof, new) | 8 passed |
| verified_session_advance_cache (integration, new) | 4 passed |
| verified_session_cache (Slice 2) | 6 passed |
| reconstruction_instrumentation | 5 passed |
| slice4c_private_intake | 7 passed |

`cargo check -p tari-cc-private-ballot-gui-core` and Tauri check pass.

## 12. PASS gate

All satisfied: advanced session proven equal to fresh reconstruction (8
categories, serial + parallel); new durable identity independently re-read and
confirmed (revision + body); external mutation / revision drift fail closed; new
proof verification preserved; no persistent trust; Slice 2 single-flight/identity
preserved; restart semantics preserved (memory-only); the advance API cannot
arbitrarily trust state (workspace-layer confirmation + crate-private wrapper);
regressions green.

**SLICE 4E: PASS.**
