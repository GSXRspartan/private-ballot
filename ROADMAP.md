# Roadmap

## Phase 1 — Specification

Deliver:
- threat model
- election lifecycle
- governance-key registry rules
- canonical manifest schema
- ballot schemas
- archive format
- Ootle anchor boundary
- tally and dispute rules
- cryptographic construction decision record

### Governance election schemas

The Tari forum discussion and RFC PR #185 identify several distinct
governance election types. Phase 1 records them as separate versioned schemas
because they may use different electorates, thresholds, privacy modes, and
tally rules:

- `NON_BINDING_APPROVAL_PILOT`
- `CC_ADMISSION`
- `CC_CATEGORY_EXPANSION`
- `CC_REMOVAL_APPEAL`
- `COUNCIL_SINGLE_SEAT_IRV`
- `TIP_AMENDMENT`

The first schema that is implemented and tested is
`NON_BINDING_APPROVAL_PILOT`. The others are specified but not implemented in
the MVP.

The following are explicitly deferred until Tari governance formally approves
an exact method:

- multi-seat STV
- simultaneous multi-seat Council elections
- delegated voting
- weighted voting
- token-weighted voting

Exit gate:
- no unresolved ambiguity that would change signed bytes or election results

## Phase 2 — Offline Rust implementation

Build in this order:
1. `protocol`: canonical IDs, hashes, manifests, versioning
2. `registry`: immutable snapshots and validation
3. `ballot`: schema validation and canonical encoding
4. `tally`: referendum, approval, then single-seat IRV
5. `archive`: deterministic archive generation and verification
6. `verifier`: full public verification report
7. `crypto`: reviewed anonymous-membership interface and implementation
8. `cli`: create, cast, collect, verify, tally, archive

No Ootle dependency in Phase 2.

### Manifest binding requirements

Every election manifest must bind:

- election schema
- electorate type
- registry snapshot hash
- governance source repository
- governance source pull request or RFC identifier
- exact reviewed source commit or immutable revision identifier
- privacy mode
- tally algorithm
- tie policy
- duplicate-ballot policy

A missing exact source commit may use a visible draft placeholder during
development, but no election may be frozen or finalized while that placeholder
is still in place.

## Phase 3 — Pilot

Run a harmless election with volunteers. Publish the complete archive,
receipts, verification report, and retrospective. The pilot remains
non-binding.

## Phase 4 — Ootle anchor

Implement append-only component state:
- election header commitments
- batch-chain commitments
- close state
- verification/tally commitments
- final archive commitment
- reset re-anchoring record

## Phase 5 — Review and release

Require independent review of:
- cryptography
- canonical serialization
- registry governance
- privacy metadata
- tally rules
- Ootle authorization/state transitions
- archive preservation and re-anchoring
