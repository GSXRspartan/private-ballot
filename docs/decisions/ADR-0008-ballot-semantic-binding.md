# ADR-0008: Ballot semantic binding for the Governance Pilot

## Status

Proposed

## Context

Phase 5A6 delivered a real organizer election-creation workflow and surfaced a
semantic question that must be answered before Phase 5 introduces voter private
credentials and Triptych proof generation:

- The canonical protocol exposes exactly one ballot kind,
  `BallotKindV1::NonBindingApprovalPilot`.
- "Candidate Election", "Governance Proposal", and "Ballot Measure" are
  **application-local presentation labels only** (`GuiBallotPresentationType`).
  They are never serialized into canonical election files and do not survive
  export/import.
- `ElectionManifestV1` carries no canonical human-readable title, description,
  proposal/question text, quorum, threshold, or presentation discriminator.
- Candidate/option **display labels are canonical** (bound through the
  candidate-set commitment), but the overall **question framing is not**.

This ADR decides whether the existing binding is sufficient for the non-binding
Governance Pilot, and separately what a future binding-governance revision would
require. It is a design decision; no implementation is performed.

## Current V1 binding (verified against source)

`ElectionManifestV1::to_canonical_cbor` (`crates/ballot/src/manifest_canonical.rs`)
emits a closed **9-field** CBOR array, hashed under
`HashDomain::ElectionManifestV1` with the project BLAKE3-256 provider:

1. `protocol_version` (u16 = 1)
2. `election_id` (byte string)
3. `ballot_kind` text — always `NON_BINDING_APPROVAL_PILOT`
4. `ballot_confidentiality` text — always `PUBLIC`
5. `registry_commitment` (32 bytes)
6. `candidate_set_commitment` (32 bytes)
7. `proof_suite_id` (text)
8. `approval_limits` = `[minimum, maximum, allow_abstention]`
9. `governance_source_revision` (text)

The **candidate set is not embedded**; only its 32-byte commitment
(`HashDomain::CandidateSetV1` over `[id, display_name]` pairs in canonical
machine-ID order) is bound. Therefore:

- Candidate **machine IDs** are canonical.
- Candidate **display labels** are canonical (a label change changes the
  commitment — `canonical.rs::candidate_changes_produce_different_commitments`).
- Option **ordering** is canonical (sorted by machine ID; input order is
  irrelevant).
- `governance_source_revision` is canonical, but it is a **free-form UTF-8
  string**: validated only as non-empty (after trim) and `<= 256` bytes
  (`MAX_GOVERNANCE_REVISION_BYTES`). It is **not** cryptographically
  interpreted, and no external document content is hashed or embedded.

**Proof binding.** `ProofStatementV1` (`crates/protocol/src/proof_statement.rs`)
is a 9-field statement hashed under `HashDomain::ProofStatementV1` and consumed
as the Triptych transcript. It binds: statement version, protocol version,
proof-suite ID, **`manifest_hash`**, `election_scope` (derived from
`manifest_hash`), `registry_commitment`, `ballot_payload_hash`, `ballot_kind_id`,
`ballot_confidentiality_id`. The verifier **reconstructs** every bound field from
the manifest and payload (`verifier/src/proof_statement.rs`); no transcript field
is accepted from the submitter. Because the statement binds `manifest_hash`, it
transitively binds **all nine manifest fields**, including
`governance_source_revision` and `candidate_set_commitment`.

**Archive binding.** `ArchiveManifestV1` (`crates/archive/src/manifest.rs`) binds
the `election_manifest_hash` plus a canonical `(path, digest)` catalog of content
files. It is agnostic to manifest content and to which content files exist: any
additional content file is automatically covered by the final archive hash.

### Exact semantic statement provable today

A verifier can prove:

> "Ballot X is a well-formed, proof-authenticated approval selection over the
> canonical option set C (with its bound machine IDs **and** display labels),
> cast by a distinct anonymous member of frozen registry R, for election E under
> manifest M, whose approval rules and `governance_source_revision` string are
> exactly those bound in M."

It **cannot** prove:

> "Ballot X approved the human-readable proposition 'Should proposal Y pass?'"

— because no authoritative question/title text exists in the protocol. The
binding is to option labels and to an opaque revision string, not to a signed
question.

## Threat model: semantic substitution

| # | Scenario | Classification |
|---|----------|----------------|
| 1 | UI shows "Should Proposal A pass?" but artifacts bind only option labels (`approve`/`reject`) | **Process/UX risk.** No integrity break for a non-binding pilot, but unbound framing must never be presented as the signed question. |
| 2 | Two clients display different descriptions for the same manifest | **Governance/UX risk.** The manifest hash is identical; only unbound chrome differs. Bound data (option labels) is identical and auditable. |
| 3 | A forum post / governance document changes after the manifest is frozen | **Real risk iff `governance_source_revision` is mutable.** Mitigated entirely by pinning to immutable content. |
| 4 | `governance_source_revision` points to mutable/ambiguous content | **Real risk.** The protocol does not guarantee immutability of the referenced source; today this is purely operator discipline. |
| 5 | One client labels the artifacts "Governance Proposal", another "Candidate Election" | **Cosmetic.** Presentation type is explicitly non-canonical; it has no cryptographic or tally meaning. |
| 6 | Option labels canonical but question framing not | **Acceptable limitation for a non-binding pilot; a blocker for binding governance.** |

None of these is an integrity vulnerability **for a harmless, non-binding
pilot**, provided the referenced governance source is immutable and the voter UI
is honest about what is and is not bound. Scenarios 3–4 become genuine integrity
problems for any **binding** use.

## `governance_source_revision` analysis

- Max size 256 bytes; non-empty after trim; otherwise opaque.
- Not hashed, parsed, or resolved by the protocol. No embedded document content.
- Intended (per ADR-0003) to carry an immutable revision — e.g. a Git commit
  SHA, RFC PR revision, or document digest — but **the code enforces no such
  format or immutability**. `creation.rs::validate_governance_revision` checks
  only emptiness and length.
- ADR-0003 §Decision(2) already requires: "Before an election is frozen, the
  manifest must pin an immutable commit hash or equivalent immutable revision."
  This is an **accepted-but-unenforced** decision. The gap is procedural and can
  be closed without any schema change.

To be trustworthy today, an operator must, out of band: pin an immutable Git
commit SHA (or a content-addressed digest of a frozen document export), and
archive the exact referenced document alongside the election artifacts so the
archive hash covers it.

## Options considered

### Presentation discriminator (Candidate / Governance / Ballot Measure)
- **Option 1 — keep one canonical ballot kind; presentation stays UI-local.**
  (recommended for now)
- Option 2 — add a canonical `presentation_kind` discriminator.
- Option 3 — add separate canonical ballot kinds only where **tally/validation
  semantics** differ (per ADR-0003 §5).

A presentation discriminator carries **no** cryptographic or verifier security
meaning for approval tally; it is metadata. A distinct `BallotKind` is justified
only when validation or tallying differs, which approval-presentation labels do
not. If ever bound, it belongs as a `presentation_kind` field inside a future
semantic descriptor — not as a new `BallotKind` variant.

### Human-readable question/title binding
- **Option A — no bound question text** (governance_source_revision + candidate
  set only). *Pilot choice.*
- Option B — canonical UTF-8 title/question embedded directly in the manifest.
- Option C — manifest binds a **digest** of an external governance document.
- **Option D — bounded short title + external document digest/reference.**
  *Future binding-governance choice.*

Embedding long free UTF-8 text (Option B) invites canonicalization hazards
(Unicode normalization form, line-ending normalization, bidi/confusables) and
localization ambiguity, with no immutability guarantee for the underlying
document. A domain-separated **digest of an immutable, content-addressed
document** (Option C/D) is the sound design: it binds meaning by reference to a
frozen artifact and defers rendering to the archived document.

### External governance-document digest
Preferred over embedding text. It should bind the **raw bytes of one immutable
artifact** (e.g. a frozen Markdown or PDF export, or a canonical CBOR document),
under a new domain-separated label using the existing BLAKE3-256 provider (no new
hash algorithm). The document should be stored as an **archive content file** so
the archive hash already covers it. Hashing a bare mutable URL without hashing
content is worthless and must be rejected.

## Decision — Governance Pilot

**Selected: B — current V1 is sufficient, with a small process/hardening step;
no canonical schema change is required.**

Conditions before the pilot proceeds:

1. `governance_source_revision` must pin **immutable** content — a Git commit SHA
   at a fixed revision, or a content digest of a frozen document. (Procedural
   now; a validated format may be added later without a V1 encoding change.)
2. The exact referenced governance document is **archived as a content file**
   alongside the election artifacts, so the archive hash covers it. This reuses
   the existing archive; no schema change.
3. The voter and organizer UI must **clearly distinguish bound from unbound**
   data and must never present unbound free text as the signed question.
4. The presentation type remains explicitly non-canonical (already implemented
   and tested in 5A6).

No integrity problem exists for a harmless non-binding pilot under these
conditions, so Option C (canonical change before the pilot) is **not** selected.

## Decision — future binding governance

**V1 is NOT sufficient for binding use.** Binding governance requires:

- a canonical, immutably bound proposition (title + question and/or a digest of a
  content-addressed governance document), delivered as a **new manifest version**
  (`ElectionManifestV2`) carrying a semantic-descriptor commitment; and
- the separately reviewed **sealed-ballot** design already mandated by ADR-0003
  §11 (public-ballot anonymity is permitted only for a harmless pilot).

Both are explicitly deferred; neither blocks the non-binding voter slice.

## Consequences

- The pilot proceeds on the existing, tested canonical formats with zero schema
  churn and zero risk to published vectors.
- The trust gap (mutable governance reference) is closed by operator procedure +
  archiving, matching an already-accepted ADR-0003 decision.
- Binding governance carries a clearly scoped, deferred protocol cost.

## Compatibility

- `NonBindingApprovalPilot` V1 elections remain verifiable forever: the manifest
  encoder is a closed 9-field array and `ElectionManifestV1::new` rejects any
  `protocol_version != 1`.
- No existing canonical vector is invalidated by this decision (nothing changes).
- A future verifier distinguishes V1 from later semantics by protocol/manifest
  version and by object type; V1 bytes are never reinterpreted.

## Migration / versioning (for the deferred V2, when justified)

- **Do not mutate the V1 encoding in place.** Introduce a distinct
  `ElectionManifestV2` type with its own `HashDomain::ElectionManifestV2` label,
  leaving V1 encoding, hashing, and vectors byte-identical.
- A new semantic field is bound to proofs **automatically through
  `manifest_hash`**: `ProofStatementV1` need not change its schema, because it
  already binds the manifest hash and the verifier recomputes it. The only proof
  change is teaching the verifier to compute the V2 manifest hash.
- `ArchiveManifestV1` needs **no** change: it binds `election_manifest_hash`
  generically and its content-file catalog already covers any archived governance
  document. Phase 4 anchor behavior remains valid because it commits to
  archive/manifest hashes generically, not to a fixed field set.
- Migration surface for V2 is therefore narrow: manifest encoder/decoder/hash,
  the GUI creation flow, the election loader, and new published V2 vectors —
  additive, alongside the untouched V1 path.

Proposed V2 shape (design-level only; narrow the fields to the threat model when
actually built):

```
ElectionManifestV2
  ... all existing V1 fields ...
  semantic_descriptor_commitment   # 32 bytes, HashDomain::SemanticDescriptorV1

SemanticDescriptorV1
  presentation_kind                # CANDIDATE | GOVERNANCE_PROPOSAL | BALLOT_MEASURE
  short_title                      # bounded canonical UTF-8, normalized
  governance_source                # { kind, immutable_reference, content_digest }
```

## Voter UX requirements

The voter confirmation screen must show, from **canonical** data only:

- election ID, `governance_source_revision`, manifest hash;
- option display labels (bound via the candidate-set commitment);
- approval rules (min/max/abstention) and proof-suite ID.

Under "Advanced details" (auditor-facing): option machine IDs, registry
commitment, candidate-set commitment, election scope, and (when V2 exists) the
bound question/title and governance-document digest.

Confirmation boundary: the voter confirms only data that is cryptographically
bound. Any unbound narrative context must be visibly labeled as **not signed**.

## Verifier requirements

- The verifier continues to reconstruct the entire proof statement from the
  manifest and payload; no semantic field is trusted from the submitter.
- For any future V2 field, the verifier inherits binding through `manifest_hash`;
  it must additionally be able to render the bound title/question and confirm the
  governance-document digest against the archived document.

## Deferred implementation

Deferred until after the non-binding pilot: `ElectionManifestV2`,
`SemanticDescriptorV1`, any canonical bound question/title, the external
document-digest field, canonicalization of the presentation discriminator, the
localization model, and the binding-governance sealed-ballot design. Voter
secret handling and Triptych proof generation for the pilot proceed on V1.
