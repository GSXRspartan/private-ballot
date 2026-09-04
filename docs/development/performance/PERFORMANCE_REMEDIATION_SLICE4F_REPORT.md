# Performance Remediation — Slice 4F
# Warm Durable-Head Body Cache

Status: **PASS** (with a corrected, source-proven scope: the safe win is
eliminating repeated head **decode**, not the head **read/hash**).

---

## 1. Source question and finding (CONFIRMED)

Slice 3B caches the validated head **identity** but the warm-append fast path
still processes the full head **body** on every append. Source inspection of
`crates/gui-core/src/workspace.rs` confirmed the warm path
(`fast_path_append_head`) did, per append:

1. read the head revision file (`fs::read`),
2. BLAKE3 re-hash the payload and reject unless it equals the trusted digest
   (`read_valid_revision_file`),
3. **CBOR-decode the payload** to validate `revision`/`workspace_id` (inside
   `read_valid_revision_file`), then
4. **CBOR-decode it AGAIN** in `fast_path_append_head` to obtain `record.body`.

So the head body was in fact decoded **twice** per warm append, on top of the
read and hash.

## 2. The load-bearing TOCTOU question (source-proven)

**Can a cached decoded body be reused while still detecting external durable
mutation cheaply?** The answer determines what is safe to skip.

The commit marker is a separate small file committing `(revision, digest)`. It
does **not** attest that the current head revision file's *content* still hashes
to that digest — an attacker can edit the revision file and leave the marker
intact. Slice 3B specifically defends against this by re-hashing the head file on
every warm append and failing closed on mismatch (its invariant: "the fast path
can never accept anything the full walk would reject").

Therefore **the head file read + BLAKE3 re-hash cannot be safely skipped**:
skipping it would let the fast path append onto a head whose on-disk file the
full walk would reject — a Slice 3B tamper/rollback regression. Only the **CBOR
decode** is safe to elide, because a body cached under a digest that the current
file freshly re-hashes to is byte-identical to the current head (BLAKE3 is
collision-resistant).

**Correction to the prior audit.** The projected "~13.2 GB → ~1.79 GB" cumulative
warm-head **read** reduction is **not safely achievable**: it presumes not
re-reading/re-hashing the body, which drops the integrity check. The read/hash
volume is unchanged. Slice 4F therefore delivers a **decode** reduction (and
removes the double-decode), not an I/O reduction. This is the honest, safe scope;
manufacturing the I/O speedup would require weakening Slice 3B.

## 3. Implementation

- **Byte-bounded, identity-bound body cache** (`WarmHeadBodyCacheV1`): a
  process-local, memory-only LRU of `Arc<DurableElectionWorkspaceBodyV1>`, at
  most one entry per workspace, keyed by `(workspace_id, revision, digest)`,
  bounded by a **total byte cap** (`DURABLE_HEAD_BODY_CACHE_MAX_BYTES_V1 = 16
  MiB`) with LRU eviction. A single body larger than the cap is not cached. Not
  persisted → empty after restart.
- **Warm path** (`fast_path_append_head`): still reads and re-hashes the head
  file every time (`read_head_payload_verified`, the mandatory integrity check);
  then reuses the cached decoded body iff it is bound to the just-confirmed
  `(revision, digest)`, otherwise decodes once and caches it. This also removes
  the previous **double-decode** (the read helper no longer decodes).
- **Seeding**: the write path caches the just-committed head body from the
  round-trip decode it already performs (no extra decode); the full walk seeds
  from the fully-validated head. So the next warm append is a cache hit.
- **Invalidation**: bound to the head identity — `clear_trusted_append_head`
  (drift, delete, import/recovery), workspace deletion, and the restart helper
  all drop the cached body; a superseding write replaces it; LRU eviction and the
  byte cap bound memory.

## 4. Memory bound

Estimated decoded head body ≈ artifact bytes + Σ ballot-package bytes:
~tens of KB (50 voters) up to a few MiB (4096 voters). Total cap 16 MiB holds one
or a few hot heads (or many small ones). Per-entry accounting uses the exact
encoded length on the write path and a proportional estimate on the full-walk
seed. Eviction is LRU by total bytes; the cap is not a per-workspace object store
(two workspaces cannot each pin an unbounded body).

## 5. Instrumentation

`durable_head_body_cache_hits`, `durable_head_body_cache_misses`,
`durable_head_body_cache_bytes` (gauge), `durable_head_body_cache_evictions`,
`durable_head_body_identity_drift`, `durable_head_body_disk_reads`,
`durable_head_body_decodes`.

## 6. Measured operation counts (MEASURED)

`crates/gui-core/tests/durable_head_body_cache.rs`, per warm append after seeding:

| counter | delta on a warm hit |
|---|---:|
| `durable_head_body_disk_reads` | **1** (read + hash always run — integrity preserved) |
| `durable_head_body_cache_hits` | **1** |
| `durable_head_body_decodes` | **0** (repeated decode eliminated) |
| `workspace_append_fast_path_hits` | 1 (Slice 3B fast path intact) |
| `workspace_append_revision_files_read` | 1 |

So the warm append still reads and re-hashes the head (I/O unchanged) but skips
the CBOR decode.

## 7. Security / regression preservation

- Slice 3B hostile suite green (`durable_append_fast_path` 14/14, `workspace`
  38/38): external edit, rollback, head replacement, wrong predecessor,
  concurrent-writer fork, corruption all still fail closed.
- 4F-specific proofs: warm reuse still reads+rehashes; a tampered head file fails
  closed and is never served from the cache; delete clears the cache; distinct
  workspaces never cross-hit; the byte cap evicts LRU and refuses oversize
  bodies; a restart empties the cache and the next append full-walks.
- Slice 4E advancement remains correct (advance tests green).

## 8. Production files changed

- `crates/gui-core/src/workspace.rs` — byte-bounded warm-head body cache;
  `read_head_payload_verified` (read+hash, no decode); `fast_path_append_head`
  reuses the cached body (double-decode removed); write/full-walk seeding;
  identity-bound invalidation; `AppendHead.body` → `Arc`.
- `crates/gui-core/src/instrumentation.rs` — 4F counters.
- `crates/gui-core/src/lib.rs` — exports.

## 9. Tests and results

| suite | result |
|---|---|
| durable_head_body_cache (new) | 6 passed |
| durable_append_fast_path (Slice 3B) | 14 passed |
| workspace | 38 passed |
| verified_session_advance_cache (Slice 4E) | 4 passed |

`cargo check -p tari-cc-private-ballot-gui-core` and Tauri check pass; clippy
clean on the changed crates.

## 10. PASS gate

Body reuse is identity-bound (workspace+revision+digest, re-confirmed by the
mandatory re-hash); external mutation detection preserved (read+hash never
skipped — this is the corrected, safe scope); rollback/tamper security preserved
(Slice 3B suite green); memory bounded (16 MiB byte cap, LRU); cache nonpersistent;
concurrent-writer safety preserved (per-workspace append lock unchanged); measured
counts show a **decode** reduction (0 decodes on a warm hit) with reads unchanged;
prior slices regress cleanly.

**SLICE 4F: PASS** — implemented as a safe decode-elimination cache. The proposed
read/I-O reduction was declined as unsafe (it would weaken Slice 3B), and the
audit's read projection is corrected accordingly.
