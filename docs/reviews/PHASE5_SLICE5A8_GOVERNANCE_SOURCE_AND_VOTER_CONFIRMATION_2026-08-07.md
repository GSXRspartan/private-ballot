# Phase 5 Slice 5A8 — Governance Source Pinning, Document Archival, and Voter Confirmation Boundary

- **Date:** 2026-08-07
- **Branch:** `phase5/gui-core-foundation`
- **Starting HEAD:** `fa26816a7ea124c715fffa379b26e268ebb33161`
- **Mode:** Implement, validate, document, and stage. **No commit.**
- **Toolchain:** `stable-x86_64-pc-windows-msvc` (rustc 1.97.1)

## 1. Starting HEAD

`fa26816a7ea124c715fffa379b26e268ebb33161` on `phase5/gui-core-foundation`. Working
tree clean before edits. ADR-0008 (`docs/decisions/ADR-0008-ballot-semantic-binding.md`)
and the 5A6 organizer creation / freeze / export work and 5A5 sealed
participation / result protections are committed at this HEAD.

## 2. ADR-0008 requirements implemented

ADR-0008 concluded that the current `ElectionManifestV1` is sufficient for the
harmless non-binding Governance Pilot, subject to four process-hardening
conditions before the voter slice:

1. `governance_source_revision` must pin **immutable** content. — Implemented
   as an application-level pin validator (`validate_governance_source_pin`)
   that accepts only `blake3:<64 hex>` (content digest) and `git:<40 hex>`
   (Git commit SHA). Pin format validity is surfaced in the organizer preview
   and voter confirmation. No canonical change.
2. The referenced governance document is **archived as a content file** so the
   archive hash covers it. — Implemented via
   `write_archive_directory_v1_with_governance_document`, which writes the
   document to the project-controlled `governance/source.bin` path and adds it
   to the hash-covered `ArchiveFileCatalogV1`. No archive schema change.
3. Voter and organizer UI clearly distinguish **bound from unbound** data and
   never present unbound text as the signed question. — The new voter
   confirmation view model separates `bound` fields (reconstructed from the
   manifest) from the non-canonical `presentation` label, and explicitly states
   no proposal question exists.
4. The presentation type remains explicitly non-canonical. — Preserved from
   5A6; `presentation_is_canonical` is always `false` in every DTO.

## 3. `governance_source_revision` current protocol semantics

Unchanged. It remains a canonical, manifest-hash-bound, opaque, non-empty
(`trim().is_empty()` rejected), bounded (`MAX_GOVERNANCE_REVISION_BYTES = 256`)
UTF-8 string. The protocol does not cryptographically interpret it. The
9-field `ElectionManifestV1` canonical CBOR array and `HashDomain::ElectionManifestV1`
hash are byte-identical to before. Slice 5A8 adds **application-level** policy
only; it never reinterprets arbitrary user text and never changes the canonical
type.

## 4. Accepted immutable pin formats

Two typed/prefixed forms, both normalized to lowercase hex:

| Form | Syntax | Locally verifiable? |
|------|--------|---------------------|
| Content digest (recommended) | `blake3:<64 lowercase hex>` | Yes — the hex is the project domain-separated `ArchiveFileV1` BLAKE3-256 digest of the document's raw bytes, recomputable from the file. |
| Git commit SHA (advanced) | `git:<40 lowercase hex>` | Format only — correspondence to a selected file is operator-attested, not cryptographically provable locally. |

Mutable phrases (`latest`, `main`, `forum post`, `HEAD`, …), whitespace
ambiguity, malformed digest length, and non-hex characters are rejected as
`UNRECOGNIZED` (`format_valid = false`). Hex digits are normalized to lowercase
so the canonical string is preserved exactly after a deterministic
normalization rule.

## 5. Recommended pilot pin format

**Content digest (`blake3:<64 hex>`)** is the recommended/default path: it is
locally and deterministically verifiable, and because it reuses the existing
`ArchiveFileV1` domain-separated BLAKE3-256 digest, the pin, the document
evidence, and the archive's own per-file digest share **one digest identity**.
The organizer "Use this document digest" action populates
`governance_source_revision` from the computed digest without manual
copy-paste. The Git SHA path is labelled "Advanced".

## 6. Governance document hashing implementation

`compute_governance_document_digest(path)` / `read_governance_document(path)` in
`crates/gui-core/src/governance.rs`:

- Uses the existing project-owned `Blake3HashProviderV1` under
  `HashDomain::ArchiveFileV1` (no new hash algorithm, no new domain).
- Returns `GuiGovernanceDocumentDigestV1 { display_filename, bytes,
  digest_algorithm_id, digest_hex }`.
- The digest is application evidence; it is **not** injected into
  `ElectionManifestV1` and does not alter manifest canonical bytes.
- `content_digest_pin_for_bytes(bytes)` builds the canonical `blake3:<hex>`
  pin string from raw bytes.

## 7. File-size / symlink / path policy

- **Size cap:** `MAX_GOVERNANCE_DOCUMENT_BYTES = 50 MiB` (allows ordinary PDFs;
  rejects absurd inputs). The metadata length is checked via `symlink_metadata`
  **before** any byte is read; the read length is re-checked defensively.
- **Symlinks:** rejected (`is_symlink()` → `GUI_GOVERNANCE_DOCUMENT_SYMLINK`).
  Pilot policy treats a symlinked governance document as unsafe because its
  target can change after freezing.
- **Directories:** rejected (`GUI_GOVERNANCE_DOCUMENT_IS_DIRECTORY`).
- **Special devices / non-regular files:** rejected (`GUI_IO_ERROR`).
- **`symlink_metadata`** is used throughout (never follows symlinks).
- **Archive path:** the document is always written to the project-controlled
  constant `governance/source.bin` (satisfies the portable `ArchivePathV1`
  profile). The original organizer filename is sanitized for display only and
  never used as the archive path.

## 8. Reference ↔ document matching behavior

`match_governance_document(revision, Option<&digest>)` returns a
`GuiGovernanceDocumentStatusV1`:

- `MATCHED` — only when the pin is `blake3:` and `pin.digest_hex == doc.digest_hex`.
- `MISMATCH` — `blake3:` pin with a selected document whose digest differs.
- `OPERATOR_ATTESTED` — `git:` pin with a selected document (correspondence
  not independently verified).
- `UNVERIFIED_REFERENCE` — immutable-format pin with no document selected.
- `NOT_APPLICABLE` — bound revision is not a recognized immutable pin format.

A green "Matched" status is reported **only** on `MATCHED`. Format validity is
never called "verified".

## 9. Git SHA / operator-attestation behavior

A `git:` pin is syntactically validated only. The application performs no
network/Git access and cannot cryptographically prove a selected local file
corresponds to that commit. The status label states: *"Reference is
immutable-format; document correspondence is not independently verified by this
application."* No green "Verified" badge is used for operator-attested
correspondence.

## 10. Organizer workflow changes

The 5A6 Create Election wizard gains a dedicated **Governance source** step
(between Basics and Eligible voters):

1. Edit the governance source revision (with live pin-format feedback).
2. Select a governance document via a native file picker
   (`pickGovernanceDocument`).
3. See filename, byte size, digest algorithm, and digest hex.
4. Click "Use this document digest as the pin" →
   `use_governance_document_digest_as_revision` sets
   `governance_source_revision` to `blake3:<digest>` deterministically (no
   manual 64-char copy).
5. See the source ↔ document status (Matched / Operator-attested / etc.).
6. The Review step shows the pin format, document metadata, and match status.

A **freeze hard gate** is the only new application-level freeze block: if the
bound revision is a `blake3:` content-digest pin and a document has been
selected, the document digest **must** match (`GUI_GOVERNANCE_DIGEST_MISMATCH`
otherwise). Pin format validity is advisory and does not block freeze, so
existing V1 fixtures and vectors remain valid.

## 11. Canonical manifest impact

**None.** `ElectionManifestV1`, `to_canonical_cbor`, `canonical_hash`, the
9-field CBOR array, and `HashDomain::ElectionManifestV1` are unchanged.
`ArchiveManifestV1` and `ArchiveFileCatalogV1` are unchanged. Test
`t19_manifest_bytes_byte_identical_whether_or_not_document_support_enabled`
proves the manifest bytes are byte-identical whether or not a governance
document is attached.

## 12. Archive supporting-document implementation

`write_archive_directory_v1_with_governance_document(session, target_dir,
Option<&[u8]>)` adds the document at `governance/source.bin` to the
`BTreeMap` of content files alongside the manifest, registry, candidate-set,
and submissions. The existing catalog sort/path-validation/digest logic covers
it automatically. The original `write_archive_directory_v1` delegates with
`None` (unchanged behavior). The governance document is **supporting governance
evidence**, not a fourth canonical election artifact: the three-file V1 loader
(`GuiElectionArtifactsV1::from_paths`) does not require it.

## 13. Archive tamper detection

Because the governance document is a hash-covered content entry, the existing
offline replay verifier (`verify_archive_directory_v1`) checks its digest and
includes it in the rebuilt archive hash. Test `t22` flips one byte of the
archived `governance/source.bin` and asserts verification fails at
`CATALOG_FILES` with `ARCHIVE_FILE_DIGEST_MISMATCH`. The verifier's
`read_bounded_archive_file` applies the 50 MiB governance cap to the
governance path and the 1 MiB canonical-object cap to all other content files,
so large governance documents verify correctly.

## 14. Voter confirmation DTO

`GuiVoterElectionConfirmationV1` (`crates/gui-core/src/voter_confirmation.rs`)
built by `build_voter_election_confirmation(artifacts, Option<&digest>)`:

- `bound: GuiVoterBoundFieldsV1` — election ID, canonical ballot kind,
  manifest hash, governance_source_revision, option display labels, approval
  rules, proof-suite ID.
- `advanced: GuiVoterAdvancedDetailsV1` — option machine IDs, registry
  commitment, candidate-set commitment, voter count/anonymity-set size.
- `governance_document_status: GuiGovernanceDocumentStatusV1`.
- `presentation_is_canonical: false` + `presentation_notice`.
- `next_stage_placeholder` (deferred credential/proof stage).
- `no_proposal_question_notice`.

No secret-bearing field exists (test `u12`).

## 15. Cryptographically Bound UI contents

The Vote screen "Cryptographically bound" card shows: election ID, canonical
ballot kind, manifest hash, governance source revision, bound option display
labels, approval rules, and proof-suite ID — all reconstructed from the
manifest. The card is labelled: *"These values are cryptographically bound by
the election manifest."* A governance document card lets the voter optionally
select a local document and see the match status honestly. Advanced details
(option machine IDs, registry/candidate-set commitments, voter count) are
collapsed under a `<details>` disclosure.

## 16. Non-canonical / informational UI contents

The "Presentation" card shows the neutral ballot-options label and an explicit
**Informational** notice: *"This presentation label is application-local and is
not part of ElectionManifestV1."* The Candidate/Governance/Ballot-Measure
distinction remains application-local presentation only; it is visually
separated from bound data, not hidden in a footnote.

## 17. No unbound proposal question

No title, description, or proposal-question field was added to
`ElectionManifestV1` or to any DTO. The voter confirmation states: *"The
version-one manifest carries no title, description, or proposal-question field.
The governance source revision and the option display names are the binding."*
Test `u9` asserts no `question`/`title`/`description` field exists in the
serialized DTO.

## 18. Tests and counts

- **Rust (gui-core lib):** 32 unit tests (governance module).
- **Rust integration `governance.rs`:** 29 tests (T1-T26 + 3 bonus).
- **Rust integration `voter_confirmation.rs`:** 13 tests (U1-U12 + next-stage).
- **Existing gui-core tests:** all still pass (creation 47, archive_writer 5,
  archive_verify 11, etc.).
- **Frontend `governance.test.ts`:** 16 tests. **`pure.test.ts`:** 51 tests.
  Total frontend: 67 tests pass.

## 19. Canonical vector results

`t25_existing_v1_canonical_vectors_unchanged` freezes a legacy opaque revision
(`creation-rev-1`) and confirms the manifest still encodes the exact string.
`t19` proves manifest bytes are byte-identical with/without a governance
document. The existing `manifest_canonical.rs` and `archive` crate vectors are
unchanged (no source edits to those crates).

## 20. Workspace validation

```
cargo +stable-x86_64-pc-windows-msvc check  --locked --offline --workspace --all-targets   # PASS
cargo +stable-x86_64-pc-windows-msvc test   --locked --offline --workspace                   # PASS (all suites)
cargo +stable-x86_64-pc-windows-msvc clippy --locked --offline --workspace --all-targets --no-deps -- -D warnings  # PASS
```

## 21. Frontend validation

```
cd gui
npm test      # 67 tests pass
npm run build # tsc --noEmit + vite build PASS
```

## 22. Native Tauri build

```
$env:RUSTUP_TOOLCHAIN = "stable-x86_64-pc-windows-msvc"
npx tauri build
```

Produced the release executable, the MSI installer
(`Tari Private Ballot_0.1.0_x64_en-US.msi`), and the NSIS installer
(`Tari Private Ballot_0.1.0_x64-setup.exe`).

## 23. Network / walletd / indexer / signing status

None. Governance-source pinning is completely local. No GitHub, forum, IPFS,
HTTP, walletd, indexer, or signing contact. "Esmeralda Testnet" wording is
preserved. No network identity was inserted into `ElectionManifestV1`.

## 24. Voter-secret status

**None.** No voter private scalar, credential import, mnemonic/seed handling,
Triptych proof generation, ballot selection submission, nullifier generation
from secret, cast vote, or network submission was implemented. The voter
"Continue" action advances only to a deferred placeholder:
*"Credential and proof workflow will be enabled in the next reviewed slice."*

## 25. Documentation path

This document:
`docs/reviews/PHASE5_SLICE5A8_GOVERNANCE_SOURCE_AND_VOTER_CONFIRMATION_2026-08-07.md`.

`PHASE_STATUS.md` updated narrowly.

## 26. Manual smoke-test checklist

Documented (not claimed human-completed):

1. launch GUI; 2. Create Election; 3. select local governance document; 4.
digest computed; 5. click/use digest as immutable source reference; 6. source
shows matched; 7. change one byte in a copy and confirm mismatch; 8. malformed
source reference rejected; 9. Git SHA mode labelled operator-attested; 10.
review/freeze; 11. verify manifest hash; 12. export canonical election
artifacts; 13. create/archive election (optionally with governance document);
14. verify governance document listed as supporting content; 15. verify archive
integrity; 16. mutate archived governance document copy; 17. verify archive
fails; 18. load election; 19. open Vote; 20. inspect Cryptographically Bound
section; 21. inspect Advanced Details; 22. presentation type clearly labelled
informational/non-canonical; 23. no unbound proposal question shown; 24. voter
confirmation checkbox/action; 25. confirm next stage remains placeholder; 26.
light/dark; 27. keyboard navigation; 28. resize.

## 27. Staged file count / hashes

See the staging section below; computed at stage time. HEAD remains
`fa26816a7ea124c715fffa379b26e268ebb33161`.

## 28. No commit

No commit was created. All changes are staged only.

## 29. Final verdict

**READY FOR OPUS REVIEW.**

No canonical schema change was required; no `ArchiveManifestV1` change was
required; no new hash algorithm was added; the voter confirmation screen
distinguishes canonical from informational data; archive integration reuses
the existing container; no secret-bearing voter value crosses the boundary; no
V2 proposal/question semantics were implemented.

---

## 30. Final pre-commit repair (Slice 5A8 hardening, 2026-08-08)

This section documents a narrow final hardening pass applied on top of the
staged 5A8 work after the independent Opus review verdict
`APPROVE WITH NON-BLOCKING FOLLOW-UPS`. It resolves the one MEDIUM finding
(M1) and several LOW/INFO findings while touching the same code, without
broadening the slice. No earlier historical section is rewritten. The existing
staged 5A8 work is preserved; the repair is staged on top. No commit is
created. HEAD remains `fa26816a7ea124c715fffa379b26e268ebb33161`.

### 30.1 Opus M1 finding

Archive verification checked that `governance/source.bin` matches the digest
recorded in the archive catalog, but did **not** also prove that this archived
governance document matches the manifest's bound
`governance_source_revision` `blake3:` pin. Therefore an internally consistent
archive could verify successfully while containing the wrong governance
document. This is resolved by paired write-time and verify-time gates plus a
distinct verification DTO fact.

### 30.2 Write-time pin/document gate

`write_archive_directory_v1_with_governance_document`
(`crates/gui-core/src/archive_writer.rs`) now, when a governance document is
being archived and the manifest binds a valid `blake3:` content-digest pin,
computes the document's project domain-separated `ArchiveFileV1` BLAKE3-256
digest (the same digest the catalog will record) and compares it to the digest
encoded in the pin, rejecting with the stable `GUI_GOVERNANCE_DIGEST_MISMATCH`
code before finalizing the archive if they differ. Git SHA pins are not
cryptographically matchable to a local file and remain operator-attested (no
write-time rejection). This complements the existing freeze-time gate in
`creation.rs`: the freeze gate checks the organizer's selected document
digest; this gate checks the bytes that actually land in the archive.

### 30.3 Verify-time pin/document gate

`verify_archive_directory_v1` (`crates/gui-core/src/archive_verify.rs`) now
runs a new `GOVERNANCE_PIN` stage after canonical manifest validation and
archive catalog verification. It inspects the bound
`governance_source_revision` and the `governance/source.bin` catalog entry:

- For a `blake3:` content-digest pin: `governance/source.bin` MUST be present;
  its verified archive catalog digest is compared to the pin digest. Unequal
  fails with the distinct stable code `GUI_GOVERNANCE_ARCHIVE_PIN_MISMATCH`.
  A missing pinned document fails explicitly with
  `GUI_GOVERNANCE_ARCHIVE_DOCUMENT_MISSING` (not a generic optional-content
  omission).
- For a `git:` pin: reported as `OperatorAttested` (not "verified").
- Otherwise: `NotApplicable`.

This is application-level verification using already-bound manifest data plus
the existing generic archive catalog. `ArchiveManifestV1`, archive catalog
encoding, and canonical election artifacts are unchanged. No fourth canonical
election artifact is added.

### 30.4 New verification DTO fact

`GuiArchiveVerificationV1` gained a distinct field
`governance_source_matches_pin: GuiGovernanceArchivePinFactV1` (new typed
enum: `Matched` / `Mismatch` / `Missing` / `OperatorAttested` /
`NotApplicable`, with `as_str()`, `label()`, `is_matched()`). Archive
integrity (`verified`) and governance-source correspondence are deliberately
separate facts so the UI must not collapse them into one ambiguous green
badge. The TypeScript mirror `GuiGovernanceArchivePinFactV1` was added to
`gui/src/api/types.ts`.

### 30.5 Archive UI distinction

`gui/src/screens/Archive.tsx` now displays distinct facts: archive integrity
("Verified"/"Failed"), governance supporting document ("Present"/"Absent"),
and governance source pin ("Matched"/"Mismatch"/"Missing"/"Operator-attested"/
"Not applicable"), with explicit notes that Git correspondence is not
independently verified and that an unrecognized reference makes the
cross-check not applicable. "Verified" is never used for Git document
correspondence.

### 30.6 Frozen governance digest KAT

A frozen known-answer test (`kat_governance_document_digest_is_frozen`) pins
the project domain-separated `ArchiveFileV1` BLAKE3-256 digest of
`b"tari-governance-document-kat-v1"` to the hard-coded constant
`9d1ba26f69b6e1af1f6c3a687139eb3110cc9289a97aa22806f65a652fc60053`. This is
the project-owned domain-separated `ArchiveFileV1` digest
(`blake3(HASH_FRAME_PREFIX || 0x00 || "tari-cc-private-ballot/archive-file/v1"
|| 0x00 || bytes)`), NOT plain `b3sum`. The expected value is NOT recomputed
at runtime with the production function; the test fails if the ArchiveFileV1
hash domain, domain framing, algorithm, or byte interpretation changes. A
one-byte mutation is asserted not to match the KAT.

### 30.7 Explicit pin ↔ archive-catalog digest regression

`content_pin_digest_equals_archive_catalog_digest` locks the "single digest
identity" property: the content-digest pin derived by the production pin
helper equals the archive catalog digest recorded for the exact same bytes,
and verification reports `Matched`.

### 30.8 Wrong-but-internally-consistent archive test

`verify_rejects_internally_consistent_archive_with_wrong_governance_document`
constructs an archive that is internally catalog-consistent (every catalog
digest matches its on-disk bytes, archive hash rebuilds) but contains the
WRONG governance document for the bound `blake3:` pin, by bypassing the
production writer's write-time gate. The verify-time `GOVERNANCE_PIN`
cross-check itself catches it with `GUI_GOVERNANCE_ARCHIVE_PIN_MISMATCH` at
stage `GOVERNANCE_PIN` (not the ordinary `ARCHIVE_FILE_DIGEST_MISMATCH` path).
A missing-document case
(`verify_rejects_missing_governance_document_for_blake3_pin`) fails with
`GUI_GOVERNANCE_ARCHIVE_DOCUMENT_MISSING`. A Git SHA archive
(`verify_git_sha_archive_reports_operator_attested_not_matched`) verifies and
reports `OperatorAttested`. An unrecognized-revision archive
(`verify_unrecognized_revision_archive_reports_not_applicable`) verifies and
reports `NotApplicable`.

### 30.9 Single-read document refactor (L1)

`read_governance_document` (`crates/gui-core/src/governance.rs`) was refactored
to perform safety metadata checks first, read the bounded file once, and
compute the digest metadata from those exact in-memory bytes (previously it
read bytes once and then re-stat/re-read the file via
`compute_governance_document_digest` to derive metadata). This removes a double
allocation/read and a pathological local race where returned bytes and a
displayed digest could correspond to different file versions. Symlink
rejection, regular-file check, the 50 MiB cap, and the post-read size sanity
check are preserved.

### 30.10 Comment/unit cleanup (L2, L4, L5)

- **L2:** Corrected the misleading `GuiGovernanceSourcePinV1::normalized`
  doc comment, which falsely claimed the canonical manifest carries the
  normalized form. `normalized` is now documented as an advisory/parsed
  normalized representation for display and matching only; the exact
  user-supplied `governance_source_revision` string remains the canonical
  manifest field and is not rewritten. The `validate_governance_source_pin`
  doc was corrected similarly. No persistence behavior changed.
- **L4:** Corrected the inaccurate `50 MB` label to `50 MiB` (the actual limit
  is `50 * 1024 * 1024` bytes). No behavior change.
- **L5:** Removed the identical-branch presentation ternary in
  `gui/src/screens/Vote.tsx` (both branches returned `"Ballot options
  (neutral)"`). Presentation remains informational and non-canonical; no
  presentation semantics changed.

### 30.11 Validation results

- `cargo +stable-x86_64-pc-windows-msvc check --locked --offline --workspace
  --all-targets`: clean (only the pre-existing third-party `triptych`
  `dead_code` warning).
- `cargo +stable-x86_64-pc-windows-msvc test --locked --offline --workspace`:
  all green. gui-core `governance` integration suite: 38 passed (9 new
  hardening tests added).
- `cargo +stable-x86_64-pc-windows-msvc clippy --locked --offline --workspace
  --all-targets --no-deps -- -D warnings`: clean.
- `gui`: `npm test` 67 passed; `npm run build` clean.
- `npx tauri build` (DTO changed): succeeded; MSI and NSIS bundles produced.

### 30.12 No canonical/archive-schema/proof change

`ElectionManifestV1`, its nine-field canonical CBOR, the manifest hash domain,
`CandidateSet`, `RegistrySnapshot`, `ArchiveManifestV1`, the archive catalog
encoding, the ballot package, proof binding, Triptych, tally, participation,
Phase 4 anchor formats, ADR-0008, and the proposed V2 design are all
unchanged. No new hash algorithm or domain was introduced. No fourth canonical
election artifact was added.

### 30.13 No network / no voter secrets

No network, walletd, indexer, or signing access was performed. No voter
secret, wallet seed, mnemonic, or signing material is read or returned by any
new code. All new errors are bounded, stable-code, ASCII, and carry no raw
file bytes, secret values, unbounded OS/debug strings, or unnecessary full
path leakage.

### 30.14 No commit

No commit was created. All repair changes are staged on top of the existing
staged 5A8 work. HEAD remains `fa26816a7ea124c715fffa379b26e268ebb33161`.
