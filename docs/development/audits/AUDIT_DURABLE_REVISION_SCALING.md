# Durable workspace revision scaling audit — Slice 3A

**Scope:** forensic measurement/design only. No production Rust or TypeScript source was modified, no durable format was changed, and no Tari/Ootle route or wallet behavior was changed.

**Evidence labels:** **CONFIRMED** = current source or existing test inspected; **DERIVED** = exact arithmetic over the current serializers; **MEASURED** = an on-disk logical byte count observed by the Slice 3A-R runtime harness at a bounded checkpoint that actually ran; **PROJECTED** = model output, not an on-disk run; **UNKNOWN** = unavailable in this environment. Runtime measurement is logical (application-level file sizes and read/decode/write accounting); it is never device/physical I/O.

## 1. Executive summary and prior-claim verdict

**CONFIRMED:** session revisions are complete snapshots, not deltas. Every one includes the full canonical registry, full manifest and candidate bytes, lifecycle state, and the complete ordered stored-package list. `write_workspace_revision` validates the committed history before an append, then serializes and durably writes the new full snapshot twice (temporary file, then final file), followed by a commit marker. Sources: `crates/gui-core/src/session.rs:59-66`, `:191-214`; `crates/gui-core/src/workspace.rs:740-809`, `:1426-1455`.

**CONFIRMED:** the registry and all prior stored packages are duplicated into every later session revision. The history loader reads every commit marker and every revision through the committed head, hashes every revision payload, decodes it once during file validation and again during predecessor validation. Sources: `crates/gui-core/src/workspace.rs:846-935`, `:937-1052`.

**VERDICT — prior “petabyte-scale” claim: OVERSTATED.** The structural finding is correct: for one normal one-package-per-append election, cumulative history reads are `O(V²·S_registry + V³·S_package)` and retained storage is `O(V·S_registry + V²·S_package)`. But the exact current 4096-member model yields **18,440,418,853,642 bytes (16.77 TiB) cumulative reads**, not petabytes. The earlier petabyte headline is approximately three orders of magnitude too high for the stated 4096-voter, one-write-per-ballot model.

The primary bottleneck is full-snapshot duplication plus re-reading the whole committed chain before each append. This is independent of Triptych verification: organizer mutations use `transactional_clone`, so they do not replay old proofs before writing. `crates/gui-core/src/session.rs:218-230`; `gui/src-tauri/src/lib.rs:1004-1040`.

## 2. Exact durable data model

`DurableElectionWorkspaceV1` is a private record containing `workspace_id: String`, `revision: u64`, `predecessor: RevisionPredecessorV1`, `updated_at_unix_secs: Option<u64>`, and either a draft or session body. `RevisionPredecessorV1` is `Genesis` or `{ revision: u64, digest_hex: String }`. `crates/gui-core/src/workspace.rs:135-179`.

For a **session** body, `GuiElectionSessionSnapshotV1` contains:

| Field | Rust type / boundary | Scaling class | Stored in every later revision? |
|---|---|---|---|
| lifecycle | `ElectionLifecycleStateV1`, binary string | constant | yes |
| manifest | `Vec<u8>` canonical CBOR | constant per election | yes |
| registry | `Vec<u8>` canonical CBOR | `S_registry(R)` | yes |
| candidates | `Vec<u8>` canonical CBOR | candidate/manifest dependent | yes |
| packages | `Vec<Vec<u8>>` canonical package CBOR | `B·S_package` | yes, complete history |
| record metadata | id, revision, timestamp, predecessor digest | constant per revision | yes |

The durable snapshot intentionally excludes the verifier, nullifier ledger and transcript; a cold session must rebuild those by replaying packages. `crates/gui-core/src/session.rs:40-66`, `:109-177`. The session serializer clones the whole `packages` vector and re-encodes all three canonical artifacts. `crates/gui-core/src/session.rs:191-214`.

The binary revision encoder writes the workspace magic/version, revision, predecessor, timestamp, workspace id, body kind, then the session fields above. Each variable field has a four-byte big-endian length; packages are a four-byte count followed by each package’s four-byte length and bytes. `crates/gui-core/src/workspace.rs:1236-1319`, `:1426-1455`, `:1770-1864`.

External sidecars are not in the revision hash chain: `organizer-authority`, draft `superseded`, and persisted election-status records. They require their own revalidation. `crates/gui-core/src/workspace.rs:64-80`, `:487-735`; `PERFORMANCE_REMEDIATION_SLICE2_CACHE_REPORT.md:100-124`.

## 3. Exact append path: one verified ballot

1. `intake_ballot_package` reads the bounded file and calls `mutate_session_transactionally`; a new package is proof-verified once, the outcome is recorded, and the exact bytes are appended to `packages`. `gui/src-tauri/src/lib.rs:1833-1847`; `crates/gui-core/src/session.rs:375-415`.
2. The mutation is a structural clone of the already-verified in-memory session. There is no historical proof replay at this point. `crates/gui-core/src/session.rs:218-230`.
3. `write_session_workspace_revision_v1` builds the complete durable snapshot and calls `write_workspace_revision`. `crates/gui-core/src/workspace.rs:271-277`.
4. The writer calls `load_committed_history` before choosing the new revision and predecessor. This reads all `.commit` files, all committed `.workspace` files through the head, hashes each payload, decodes each once in `read_valid_revision_file`, then decodes it again during the contiguous predecessor walk. `crates/gui-core/src/workspace.rs:740-779`, `:846-935`, `:984-1052`.
5. It serializes the full new record, hashes `domain || 0x00 || payload`, writes and `sync_all`s a temporary revision, locally decodes it, writes and `sync_all`s the final revision, deletes the temporary file, best-effort syncs the revision directory, writes/syncs the commit marker, and best-effort syncs the commit directory. It does **not** rename the temp file into place. `crates/gui-core/src/workspace.rs:779-809`, `:1517-1599`, `:1640-1646`.

For a batch inbox reconciliation, a revision is written only if `newly_accepted > 0`; one batch can therefore amortize the durable write across packages, but the snapshot still contains the whole accumulated history. `gui/src-tauri/src/lib.rs:1911-1966`.

## 4. Security purpose and hash-chain properties

The full chain loader rejects malformed/oversized files, unsafe paths, missing commit generations, missing committed revisions, filename/payload digest mismatch, workspace-id/revision mismatch, wrong predecessor, and same-generation conflicts. `crates/gui-core/src/workspace.rs:846-1112`. Existing hostile tests cover uncommitted orphans, damaged newest revisions, missing middle revisions, wrong predecessor digests, divergent same-generation revisions, copied-workspace identities, and malformed authority markers. `crates/gui-core/tests/workspace.rs:937-1448`, `:1873-1934`.

`revision_digest_hex(payload)` is BLAKE3 of a domain-separated frame. The payload includes its predecessor digest; therefore a head digest transitively commits to all predecessor digest values and to the head snapshot’s own exact fields. `crates/gui-core/src/workspace.rs:1236-1274`, `:1640-1646`.

**Important boundary:** a head digest is a strong commitment only when the caller already has a trusted expected head identity. An attacker cannot alter an old revision while preserving the existing head digest without a BLAKE3 collision/preimage break. They can, however, replace every successor and every unauthenticated local commit marker with a new internally consistent history; the current files are not externally signed. The current full walk detects internal inconsistency and partial failure, not an attacker who can consistently rewrite the entire local store. No stronger external trust anchor was found in the workspace format.

The current full walk is necessary for **cold** detection of a missing middle revision because a predecessor digest alone cannot reconstruct a missing file. It is not necessary on every append after this process has already validated and retained `(workspace_id, head_revision, head_digest)` and observes the same head immediately before committing. Slice 2 already uses that identity for an in-memory verified-session cache, while deliberately re-reading sidecars outside the key. `crates/gui-core/src/workspace.rs:353-424`; `crates/gui-core/src/verified_session_cache.rs`; `PERFORMANCE_REMEDIATION_SLICE2_CACHE_REPORT.md:25-124`.

## 5. Formal complexity derivation

Let:

- `R` = registry members (maximum 4096: `crates/protocol/src/limits.rs:15`);
- `B` = stored packages; `V` = revisions;
- `G(R) = S_registry(R)`;
- `P(R) = S_package(R)`; `q(R) = 4 + P(R)` for the workspace package length;
- `A(R)` = a non-genesis OPEN revision’s bytes before package entries.

For a session revision containing `i` packages:

`S_i(R) = A(R) + i·q(R)`.

Ignoring the five constant lifecycle revisions, retained revision bytes after `V` appends are:

`Σ S_i = V·A(R) + q(R)·V(V+1)/2`.

Before append `v`, the loader reads `Σ(i=1..v-1) S_i`. Across all writes:

`Σ(v=1..V) Σ(i=1..v-1) S_i`
`= A(R)·V(V-1)/2 + q(R)·V(V-1)(V+1)/6`.

This proves `O(V²·G(R) + V³·P(R))` logical revision-read and decode work, and `O(V·G(R) + V²·P(R))` retained and serialized-write work. The cubic term is a direct summation, not an assertion by analogy.

Per append CPU is `O(history bytes)` for scanning, hashing and decoding plus `O(S_i)` serialization; **logical bytes written by application code** are `2·S_i` because the payload is passed to the file API for both temporary and final paths. Commit-marker work is `O(V²)` bytes with a small 213-byte representative marker. Decode work is approximately two passes over each revision payload per history load; marker bytes are decoded once. Hashing is one BLAKE3 of each loaded revision plus one BLAKE3 of the new payload.

Cold resume first loads the committed head, then a cache miss rechecks it before insertion, then rechecks again before return: three full-history loads. An unchanged cache hit still performs two full-history loads. `crates/gui-core/src/workspace.rs:353-424`. Metadata listing does no proof replay after Slice 1, but still one full committed-history load per workspace. `crates/gui-core/src/workspace.rs:294-337`, `:1152-1232`.

## 6. Source-derived size model

Runtime measurement could not compile because `cargo test` stopped in `getrandom` before project compilation: `dlltool.exe` is absent from this environment. The temporary helper and all temporary OS workspaces were removed. The values below are therefore **DERIVED**, not measured, from the exact current serializers.

The registry serializer is an array of 32-byte public-key byte strings. Its exact byte sizes are listed below. `crates/registry/src/canonical.rs:12-32`; `crates/protocol/src/cbor.rs:31-49`, `:76-104`.

For a representative one-selection package (`candidate-a`, current 26-byte Triptych suite id), the source gives a two-byte-base ring with minimum exponent 2 and a 34-byte project envelope. Triptych proof bytes are `8 + 32·(7 + 3m)`, so package bytes are exactly `82 + 266 + 96m`, where `m = max(2, ceil(log2 R))`. `crates/crypto/src/triptych_prototype.rs:21-60`, `:140-169`; `third_party/tari-triptych/src/proof.rs:900-955`; `crates/crypto/src/triptych_adapter.rs:17-132`; `crates/ballot/src/package.rs:105-127`.

| R | registry bytes | m | representative package bytes |
|---:|---:|---:|---:|
| 2 | 69 | 2 | 540 |
| 50 | 1,702 | 6 | 924 |
| 100 | 3,402 | 7 | 1,020 |
| 500 | 17,003 | 9 | 1,212 |
| 1,000 | 34,003 | 10 | 1,308 |
| 2,048 | 69,635 | 11 | 1,404 |
| 4,096 | 139,267 | 12 | 1,500 |

Using the existing three-candidate test fixture’s 185-byte manifest and 76-byte candidate set as representative fixed inputs, a 4096-member OPEN revision is 139,772 bytes at zero packages and grows by 1,504 bytes/package:

| packages | revision payload | committed head (payload + marker) |
|---:|---:|---:|
| 0 | 139,772 | 139,985 |
| 1 | 141,276 | 141,489 |
| 10 | 154,812 | 155,025 |
| 50 | 214,972 | 215,185 |
| 100 | 290,172 | 290,385 |
| 500 | 891,772 | 891,985 |
| 1,000 | 1,643,772 | 1,643,985 |
| 2,048 | 3,219,964 | 3,220,177 |
| 4,096 | 6,300,156 | 6,300,369 |

These values vary with election id, candidate IDs/display names, governance revision, actual selection count and package envelope. The scaling coefficients do not.

### Accounting-category boundary

All byte totals in this audit use one of these explicit categories:

- **logical bytes read by application code:** bytes passed from revision/marker file reads into the loader;
- **logical bytes decoded:** bytes presented to the binary decoders (a revision payload is normally decoded twice per history load);
- **logical bytes serialized:** bytes produced by the workspace/commit encoders;
- **logical bytes written by application code:** bytes passed to the file API, including both temporary and final revision payload writes and commit-marker writes;
- **retained workspace bytes:** finalized revision and marker bytes present after the stated sequence; and
- **actual physical disk I/O:** device/filesystem bytes after caching, allocation, journaling, writeback and any compression. This is **UNKNOWN** without runtime/device instrumentation.

`sync_all` establishes the application-level durability request; it does not measure device-sector writes. Accordingly, no derived figure below is labeled “physical write” or “physical disk I/O.”

## 7. Cumulative I/O model

The following uses a normal election sequence: FROZEN, OPEN, one committed snapshot per stored package, CLOSED, VERIFIED, FINALIZED (`V = B + 5`). It includes 213-byte commit markers, two payload writes per revision, and the exact pre-append full-history scan. It excludes filesystem allocation-unit overhead and unrelated app-data files. All rows are **PROJECTED from the exact source-byte model**.

| voters/packages | revisions | final logical state | retained workspace | cumulative logical reads | cumulative logical decodes | cumulative logical serialized | cumulative logical application writes | read/final amplification |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 50 | 55 | 48,825 B | 1,455,437 B | 26,604,112 B | 52,891,919 B | 1,455,437 B | 2,899,159 B | 545× |
| 100 | 105 | 106,525 B | 5,910,937 B | 208,957,912 B | 416,752,844 B | 5,910,937 B | 11,799,509 B | 1,962× |
| 500 | 505 | 625,726 B | 163,077,042 B | 28,047,105,172 B | 56,067,103,964 B | 163,077,042 B | 326,046,519 B | 44,823× |
| 1,000 | 1,005 | 1,346,726 B | 695,486,542 B | 238,157,369,422 B | 476,207,278,214 B | 695,486,542 B | 1,390,759,019 B | 176,842× |
| 2,048 | 2,053 | 2,953,942 B | 3,107,317,206 B | 2,172,832,042,762 B | 4,345,215,427,010 B | 3,107,317,206 B | 6,214,197,123 B | 735,570× |
| 4,096 | 4,101 | 6,300,374 B | 13,212,106,198 B | 18,440,418,853,642 B | 36,879,047,005,634 B | 13,212,106,198 B | 26,423,338,883 B | 2,926,877× |

At 4096: retained workspace is **12.31 GiB**, cumulative logical reads **16.77 TiB**, cumulative logical decoded bytes **33.54 TiB**, and cumulative logical bytes written by application code **24.61 GiB**. Actual physical disk I/O is **UNKNOWN**. Thus retained disk footprint is material but not the source of the 16.77-TiB logical-read total; repeated read/decode amplification is the dominant cost.

### 4096-ballot recurrence and read-source proof

For the representative 4096-member package above, `P = 1,500` B and `q = 4 + P = 1,504` B per package entry. Let the zero-package OPEN snapshot be `A = 139,772` B and its representative marker be `M = 213` B. During the `k`th package append, the full-history validation reads the OPEN snapshot and the `k - 1` preceding package snapshots. The package-history part of the logical reads is:

`q · Σ(k=1..B) Σ(j=0..k-1) j = q · B(B-1)(B+1)/6`.

At `B = 4,096`:

`1,504 · 4,096 · 4,095 · 4,097 / 6 = 17,225,681,141,760` logical bytes.

The fixed-snapshot/marker component of those same package-appends is:

`(A + M) · Σ(k=1..B) k = 139,985 · 4,096 · 4,097 / 2 = 1,174,565,980,160` logical bytes.

Together they are `18,400,247,121,920` logical bytes. The remaining `40,171,731,722` bytes in the complete `18,440,418,853,642`-byte model arise from the FROZEN and four terminal lifecycle writes, their predecessors, and their markers. The cubic package-history term alone is **93.41%** of the complete logical-read total. The total is **1,395.72×** the 13,212,106,198-byte retained workspace. This proves, within the stated source-byte model, that the ~18.4-TB figure is overwhelmingly repeated application-level re-reading of older snapshots during append validation—not retained disk footprint and not measured device I/O.

## 8. Runtime validation (Slice 3A-R) and wall-clock

The byte model in §§5–7 now has **runtime support** from a disposable Slice 3A-R harness (`crates/gui-core/tests/durable_revision_scaling_runtime_scratch.rs`, since removed — see below). It wrote only bounded temporary OS workspaces, never application data, and drove the **unchanged** production writer `write_session_workspace_revision_v1` once per checkpoint. It measured the actual on-disk revision/commit file sizes immediately before each append and reconstructed the writer's full committed-history read/decode/write accounting from those sizes.

**Execution result (Windows MSVC, `cargo +stable-x86_64-pc-windows-msvc test … -- --nocapture`):**

- `test result: ok. 1 passed; 0 failed` in **430.15 s** (prior run ≈427 s; both under the harness's hard 10-minute cap).
- Fixtures that ran to completion: registry sizes **50, 100, 500** through 100 stored packages, and **1000** through 50 stored packages. The harness then emitted `SLICE3A_R_SAFETY_STOP … projected_runtime_exceeds_cap` and exited cleanly (`status=INCOMPLETE_SAFETY_STOP`) **before** the 2048 and 4096 fixtures. A safety stop is a passing, bounded early exit by design — the larger fixtures are deliberately never generated.
- **MEASURED at every checkpoint that ran:** `actual_payload_bytes == expected_payload_bytes` (e.g. R=50, package_count=1, revision=2 → 3142 == 3142), `retained_workspace_bytes` matched the triangular retained-size recurrence, and `cumulative_history_read_bytes == expected_cumulative_history_read_bytes` at all points (asserted by the test, not merely printed). No mismatch occurred at any reached checkpoint.
- The **cubic package-history share** rises with package count toward the §7 asymptote: at R=50 it reaches 0.9265 (926 508 ppm) by 100 packages; the analytical 4096 share is 0.9341. This confirms the dominant cost is repeated historical re-reading, exactly as derived.

**What runtime validation does and does not establish.** It confirms the source-derived recurrence at bounded points with real serialized bytes (logical, application-level). It does **not** measure the 2048/4096 fixtures — those rows in §7 and the CSV remain **PROJECTED** — and it does **not** convert any figure into device/physical I/O, which remains **UNKNOWN**. Wall-clock per-append timings were recorded for the safety forecaster only and are not used as a correctness signal (they vary with filesystem cache, antivirus, and CPU state).

### Genesis vs Previous predecessor: the 76-byte term (runtime-confirmed)

The zero-package baseline is revision 1 and carries the one-byte `Genesis` predecessor (`PREDECESSOR_GENESIS`). Every later revision carries a `Previous { revision, digest_hex }` predecessor, whose V1 encoding is `1` tag byte `+ 8` revision bytes `+ 4` digest-length-prefix bytes `+ 64` digest-hex bytes `= 77` bytes, i.e. **exactly 76 bytes more** than Genesis. The harness prints this decomposition (`SLICE3A_R_PAYLOAD_DIAGNOSTIC … previous_predecessor_bytes=77 predecessor_delta_bytes=76`) and asserts the payload equals `genesis_zero_package_baseline + 76 + package_entry_bytes·package_count` at every non-genesis checkpoint. This is a format-derived fixture-sequence term, not a fitted tolerance. It does **not** change the §7 4096 projections: the analytical `A(R)` already models a non-genesis OPEN revision (the 4096 sequence's OPEN snapshot is revision ≥ 2 and already includes the Previous predecessor).

## 9. Safe optimization classes and recommendation

| Class | Preserves / risk | Assessment |
|---|---|---|
| A. delta revisions | preserves hash chain when each delta commits predecessor; cold replay grows with deltas | necessary foundation |
| B/C/I. snapshot + delta + periodic checkpoints | bounded cold load after a trusted checkpoint; checkpoint semantics/migration must be specified | useful follow-on, not first shortcut |
| D. process-local trusted head | safe only after full validated load plus identity recheck; never persistent trust | already compatible with Slice 2 |
| E. content-addressed packages | removes repeated package-byte retention; references must commit digest and ordering | recommended with deltas |
| F/H. immutable genesis/artifacts stored once | removes repeated registry/manifest/candidates; genesis digest must be in every head chain | recommended |
| G. Merkle package history | enables efficient inclusion commitments but adds proof and migration complexity | optional later enhancement |

**Recommended Slice 3B architecture:** a versioned immutable genesis object (manifest, registry, candidates) plus an append-only, digest-chained event journal whose events are lifecycle transitions and ordered package-digest references. Store immutable package bytes content-addressed once. Keep the current commit-marker ordering and fail-closed filename/digest checks. Within a process, append from an already verified `(workspace_id, head_revision, head_digest)` only after re-reading the current head/sidecars; after restart or identity drift, validate the complete chain and replay proofs before issuing a `VerifiedElectionSessionV1`. This removes the repeated full snapshot and per-append full-history scan without weakening new-ballot verification, rollback observation, crash consistency, or Slice 2’s identity semantics.

Do **not** make a checkpoint a permanent proof-verification bypass unless it is independently authenticated and its ledger/transcript derivation can be fail-closed verified. Cold archive verification remains independent.

## 10. Compatibility, Slice 2, and multicore constraints

Current decoder accepts only workspace format version 1 and returns `GUI_WORKSPACE_UNSUPPORTED_VERSION` otherwise. There is no migration code. `crates/gui-core/src/workspace.rs:1289-1319`, `:1334-1355`.

Slice 3B needs an explicit V2 discriminator, read-only V1 support, explicit backup/export before conversion, atomic write-new-then-commit conversion, recoverable interruption handling, and a stated downgrade policy. Do not migrate automatically on a merely metadata-only listing.

Slice 2’s cache key is `workspace_id + head_revision + head_revision_digest_hex + verifier_epoch`; a V2 head must preserve an equally strong complete-state identity, and status/authority/supersession sidecars must still be re-read. `PERFORMANCE_REMEDIATION_SLICE2_CACHE_REPORT.md:25-124`. Storage changes must not conflate metadata with a verified session.

Durable I/O and Triptych verification are separate. A new format should keep canonical package order so future batched/multicore verification can produce deterministic ordered decisions. It must not treat faster storage as proof verification.

## 11. Final verdict

SLICE 3A VERDICT:
COMPLETE — the source audit and byte-model are complete, and the Slice 3A-R runtime harness now supports them: `1 passed; 0 failed` in 430.15 s, with `actual_payload_bytes == expected_payload_bytes` and `cumulative_history_read_bytes == expected_cumulative_history_read_bytes` at every bounded checkpoint that ran (registry sizes 50/100/500 through 100 packages; 1000 through 50 packages), followed by a clean by-design safety stop before the 2048/4096 fixtures. Those two fixtures were never generated, so their §7/CSV rows remain PROJECTED, and actual physical device I/O remains UNKNOWN. The temporary harness has been removed after its result was archived here (§8).

- Full-snapshot revisions: YES
- Full-history read on append: YES
- Registry duplicated per revision: YES
- Package history duplicated per revision: YES
- Derived cumulative complexity: `O(V²·S_registry + V³·S_package)` reads/decodes; `O(V·S_registry + V²·S_package)` retained/serialized writes
- 4096-voter retained workspace: 13,212,106,198 B PROJECTED (12.31 GiB)
- 4096-voter cumulative logical reads: 18,440,418,853,642 B PROJECTED (16.77 TiB)
- 4096-voter cumulative logical bytes written by application code: 26,423,338,883 B PROJECTED (24.61 GiB); actual physical disk I/O: UNKNOWN
- Petabyte-scale prior claim: OVERSTATED
- Primary bottleneck: repeated full-history read/decode plus full-snapshot duplication
- Security reason for current design: fail-closed internal chain/corruption detection and reconstruction from canonical package bytes; not a requirement to re-walk an already trusted unchanged in-process head
- Runtime validation: Slice 3A-R harness passed 1/1 in 430.15 s; logical byte model MEASURED-confirmed at all reached bounded checkpoints; 2048/4096 remain PROJECTED; physical device I/O UNKNOWN
- Recommended Slice 3B: process-local validated-head fast append first (removes the dominant repeated full-history re-read with no on-disk format change); immutable genesis + digest-chained deltas + content-addressed packages remain the later format-level follow-on
- Production source modified by this audit: NO
- Scratch artifacts remaining: NONE (`durable_revision_scaling_runtime_scratch.rs` removed after archiving its result)
- Files written: `AUDIT_DURABLE_REVISION_SCALING.md`, `AUDIT_DURABLE_REVISION_SCALING.csv`, `AUDIT_DURABLE_REVISION_WRITE_PATH.csv`
