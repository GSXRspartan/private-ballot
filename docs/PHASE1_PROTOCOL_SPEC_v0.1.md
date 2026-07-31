# Tari CC Private Ballot
## Phase 1 Protocol and Architecture Specification v0.1

**Status:** Draft for public review<br>
**Date:** 2026-07-30<br>
**Author / project lead:** GSXRspartan<br>
**Intended use:** Non-binding prototype and testnet pilot only until independent review is complete

### Revision note

This draft was aligned with the Tari governance sources:

- the Tari Core Contributor Program forum post #47 and the surrounding
  discussion;
- the tari-project/rfcs pull request PR #185.

PR #185 remains a moving governance source. It is not merged or approved, and
its wording may change. Each frozen election must pin the governance source to
an immutable revision (see the governance-source pinning section) so the
election preserves the exact rules it used.

---

## 1. Purpose

Tari Core Contributor votes should be verifiable without forcing every voter to publicly attach their identity to their ballot.

This project will provide:

1. a dedicated governance-key system separate from Tari wallet and spending keys;
2. a frozen, authenticated electorate snapshot for each election;
3. anonymous proof that a ballot came from one eligible voter;
4. election-scoped duplicate-vote detection without cross-election tracking;
5. deterministic, independently reproducible tallying;
6. an append-only Tari Ootle anchor for election commitments and results;
7. a complete offline election archive that remains authoritative and verifiable if the testnet resets.

The Ootle layer is a public commitment and timestamping layer. It is not the only copy of the election and is not required to reconstruct or verify the result.

---

## 2. Scope

### 2.1 Phase 1 scope

This specification defines:

- security and privacy goals;
- threat model;
- election lifecycle;
- registry and key-management requirements;
- canonical election and ballot data;
- offline archive requirements;
- Ootle anchor responsibilities;
- tallying and dispute requirements;
- acceptance criteria for Phases 2 through 5.

### 2.2 Election type matrix

The protocol must support distinct election schemas rather than assuming every
vote uses ranked choice. The Tari forum discussion and RFC PR #185 identify
several governance election types. Each is a separate versioned schema and may
use a different electorate, threshold, privacy mode, and tally rule. The exact
electorates, thresholds, and negative-vote behavior are supplied by the pinned
governance source and the election manifest, not hard-coded here.

1. **`NON_BINDING_APPROVAL_PILOT`**
   - volunteer or synthetic electorate;
   - approval ballot (one or more selections from an allowed set);
   - harmless and non-binding;
   - anonymous signer / public ballot permitted.

2. **`CC_ADMISSION`**
   - CC and possibly bootstrap Council electorate, according to the pinned
     governance source;
   - YES, NO, ABSTAIN or no-ballot semantics;
   - threshold and negative-vote behavior supplied by the manifest;
   - anonymous constructive-feedback handling is unresolved.

3. **`CC_CATEGORY_EXPANSION`**
   - threshold referendum schema;
   - rules supplied by the manifest.

4. **`CC_REMOVAL_APPEAL`**
   - potentially separate CC and Council electorates;
   - separate authenticated tally results;
   - combined governance outcome determined by the pinned rules.

5. **`COUNCIL_SINGLE_SEAT_IRV`**
   - CC electorate;
   - ranked ballot;
   - sealed-ballot privacy required before any binding use;
   - exact IRV and tie rules must be approved and versioned before binding use.

6. **`TIP_AMENDMENT`**
   - potentially separate Council and CC electorates;
   - separate results;
   - final outcome determined from both according to the pinned rules.

Multi-seat elections (multi-seat STV, simultaneous multi-seat Council
elections), weighted voting, delegated voting, and token-weighted voting are
out of scope until Tari governance approves an exact method. The first schema
that is implemented and tested is `NON_BINDING_APPROVAL_PILOT`.

### 2.3 Privacy modes

Two privacy modes are defined so the project does not pretend anonymity and ballot secrecy are the same thing.

#### Mode A: anonymous signer, public ballot

The ballot contents may be published when accepted. The eligible signer remains hidden.

Mode A is easier to verify and audit. It is acceptable for the harmless MVP
pilot only, and for votes where early disclosure is acceptable.

#### Mode B: anonymous signer, sealed ballot

The ballot contents remain encrypted until the election closes. After closing, the election package publishes enough material for anyone to decrypt or verify the tally.

Mode B is the target for sensitive or binding Council elections. Its key
ceremony, threshold decryption, failure recovery, and proofs require a separate
reviewed design.

#### Clarifications

- The word "confidential" must not be used ambiguously. The manifest must
  explicitly identify whether ballot contents are public during voting, public
  only after closing, or never individually published.
- Early ballot visibility can influence later voters. Publishing ballots while
  voting is open is a property of the schema, not an accident.
- Anonymous signer identity does not automatically provide ballot secrecy. A
  hidden signer with a public ballot is still a public ballot.
- Timing and relay metadata can weaken practical anonymity even when the
  cryptographic proof reveals nothing.

### 2.4 Governance source pinning

Governance rules come from an external, changing source (a forum discussion and
an RFC pull request). An election must record which version of those rules it
used so its behavior does not silently change when the proposal changes.

A `GovernanceSource` record has fields equivalent to:

- source type (for example RFC, TIP, PR, or forum discussion);
- repository or forum identifier;
- RFC, TIP, PR, or discussion identifier;
- immutable commit or revision;
- retrieval or recording date;
- optional human-readable reference;
- source-document hash if the source is archived locally.

Rules:

- A draft election may temporarily use an unresolved revision marker, shown
  visibly as unresolved.
- A frozen election may not use an unresolved marker. It must pin an immutable
  commit or revision.
- The immutable source revision becomes part of the signed and hashed manifest.
- Later governance edits do not alter an already frozen election.

This project cites PR #185 as a moving source and does not claim it is merged or
approved. See `docs/decisions/ADR-0003-governance-source-and-mvp-scope.md`.

---

## 3. Non-goals

The MVP will not:

- use a CC's Tari wallet key, seed phrase, account key, or spending key;
- move, lock, mint, burn, or custody funds;
- treat ownership of XTM or any token as voting eligibility;
- place a voter's name, handle, wallet address, IP address, or device identifier in a ballot package;
- claim resistance to compromised voter devices;
- claim protection against coercion or a voter voluntarily revealing their ballot;
- claim production-grade anonymity merely because functional tests pass;
- make the Ootle testnet the sole authoritative archive;
- conduct a binding CC or Council election before independent review.

---

## 4. Security and privacy goals

### G1. Eligibility

Only a holder of a governance private key represented in the frozen election registry may create an accepted ballot.

### G2. One accepted ballot per eligible voter per election

A second valid ballot produced by the same governance key in the same election must be detected through an election-scoped nullifier or key image.

The manifest must define whether the first valid ballot or the last valid ballot counts. The MVP uses **first valid ballot counts** because it is simple and deterministic.

### G3. Signer anonymity

A valid ballot must prove membership in the electorate snapshot without revealing which registry member created it.

### G4. Cross-election unlinkability

Public ballot material from different elections must not contain a stable voter tag that permits routine linking across elections.

This is a protocol requirement, not something considered proven merely because two generated tags differ in a test.

### G5. Public verifiability

Anyone with the published archive must be able to:

- authenticate the election manifest;
- reconstruct the registry snapshot;
- verify every submitted proof;
- identify duplicate nullifiers;
- reproduce accepted and rejected ballot sets;
- reproduce every tally round;
- verify the final result;
- compare archive commitments with the Ootle anchor.

### G6. Canonical interpretation

Every conforming implementation must sign, hash, verify, reject, and tally the same bytes in the same way.

Human-readable JSON may be included for convenience, but protocol commitments use a canonical binary encoding.

### G7. No wallet-key coupling

Governance keys must be generated, stored, backed up, rotated, and revoked independently from Tari wallets.

### G8. Reset survivability

Loss of Ootle testnet history must not prevent election verification. A reset may require re-anchoring, but must not change the election package, accepted ballots, or result.

### G9. Censorship evidence

A voter who submits a ballot must receive a receipt that allows them to demonstrate that a specific ballot commitment was submitted before closing without publicly proving which human cast it.

The design cannot guarantee that a relay includes every submission. It must make omission detectable and allow multiple relays or fallback publication.

### G10. Bounded verification

Registry size, ballot size, candidate count, signature size, batch size, and processing time must have explicit limits to prevent memory and CPU exhaustion.

---

## 5. Threat model

### 5.1 Potential attackers

The design assumes any of the following may behave maliciously:

- an ineligible outsider;
- an eligible voter attempting to vote twice;
- a voter submitting malformed data;
- a ballot relay censoring, delaying, reordering, duplicating, or altering submissions;
- an election administrator publishing a false registry or manifest;
- a tallier omitting ballots or publishing an incorrect result;
- an Ootle anchor operator posting incorrect commitments;
- an indexer returning stale or incomplete state;
- a public observer correlating ballot timing, ranking patterns, and network metadata;
- a testnet reset removing on-chain history.

### 5.2 Out of scope for the MVP

The MVP does not fully protect against:

- malware on the voting device;
- a voter revealing their governance private key;
- a voter photographing or publishing their ballot;
- traffic analysis against a voter submitting directly without an anonymity relay;
- coercion, vote buying, or receipt-based proof of vote choice;
- compromise of every archive mirror and every participant backup;
- flaws in an unreviewed cryptographic construction.

### 5.3 Trust minimization

No single party should be able to both:

1. identify a voter; and
2. alter that voter's accepted ballot without detection.

The public verifier, archive, relay, and Ootle anchor are separate roles even when one person operates several of them during a pilot.

---

## 6. Roles

### Election authority

Creates and signs the election manifest and registry snapshot.

The authority does not receive voter private keys.

### Registry maintainers

Publish the current set of dedicated governance public keys and the evidence or process authorizing additions, rotations, suspensions, and removals.

### Voter

Generates or imports a dedicated governance key, verifies the manifest and snapshot, creates a ballot, and retains a submission receipt.

### Relay

Accepts opaque or signed ballot packages, performs basic validation, returns receipts, and publishes batches.

Multiple relays are preferred.

### Anchor operator

Submits election and archive commitments to the Ootle component.

An anchor operator cannot create a valid voter proof.

### Tallier / verifier

Uses only public election data to validate and reproduce the result.

### Archive mirrors

Retain byte-for-byte copies of the finalized election package.

---

## 7. Election lifecycle

The lifecycle is append-only:

1. **DRAFT**
   - manifest under discussion;
   - registry not yet frozen;
   - no ballots accepted.

2. **FROZEN**
   - canonical manifest created;
   - registry snapshot frozen;
   - manifest hash and registry root fixed;
   - Ootle election component may be created.

3. **OPEN**
   - ballots accepted;
   - relays issue receipts;
   - batches may be anchored.

4. **CLOSED**
   - no new ballots accepted after the defined cutoff;
   - final submitted-ballot set committed.

5. **VERIFIED**
   - all proofs and nullifiers processed;
   - accepted and rejected ballot transcript published;
   - tally reproduced.

6. **FINALIZED**
   - result, tally transcript, archive hash, and verification report anchored;
   - dispute window complete or explicitly waived for a harmless pilot.

A state transition may add new information but must never replace an earlier manifest, registry root, batch root, or finalized result.

---

## 8. Governance keys and registry

### 8.1 Dedicated keys

Each CC creates one dedicated governance keypair.

The software must display a prominent warning:

> This is a governance key. Do not import a Tari wallet seed, account key, or spending key.

### 8.2 Registry entry

A registry entry contains at minimum:

- stable member identifier;
- governance public key;
- key-suite identifier;
- activation time or election;
- status;
- optional replacement-key reference;
- authorization evidence reference.

The public mapping between CC identifier and governance public key is expected to be known before an election. Anonymity comes from proving membership without revealing which entry signed a ballot.

### 8.3 Snapshot

A snapshot is immutable protocol data and must use immutable collections.

It contains:

- registry version;
- ordered member identifiers;
- ordered governance public keys;
- key-suite identifier;
- snapshot creation time;
- authorizing signatures;
- canonical snapshot hash;
- Merkle root or equivalent registry commitment.

Duplicate public keys are invalid.

Empty registries are invalid.

The MVP must refuse to claim anonymity below a configured minimum electorate size. A one-member ring is not anonymous merely because the math still verifies.

### 8.4 Rotation and revocation

Key changes after an election is frozen do not alter that election's snapshot.

The registry process must distinguish:

- routine key rotation;
- lost key;
- suspected compromise;
- CC departure;
- temporary suspension;
- emergency invalidation before election opening.

If a key is compromised after voting opens, the election authority must follow a predeclared incident rule rather than improvising a result.

---

## 9. Election manifest

The manifest is canonical CBOR. A human-readable JSON rendering may accompany it.

Required fields:

- `protocol_version`
- `election_id` using at least 256 bits of unpredictable uniqueness
- `title`
- `description_hash`
- `election_type`
- `privacy_mode`
- `crypto_suite_id`
- `registry_snapshot_hash`
- `registry_root`
- `candidate_manifest_hash`
- `opens_at_utc`
- `closes_at_utc`
- optional Ootle opening and closing epochs
- `first_or_last_valid_ballot_rule`
- `tally_algorithm_id`
- `tie_break_rule_id`
- `ballot_validation_rule_id`
- `maximum_ballot_bytes`
- `maximum_candidate_count`
- `relay_public_keys`
- `anchor_network`
- `anchor_template_version`
- `archive_format_version`
- `dispute_window`
- `governance_source`
- `electorate_type`
- `electorate_registry_hashes`
- `election_schema_id`
- `ballot_visibility_policy`
- `negative_feedback_policy`
- `duplicate_ballot_policy`
- `governance_outcome_rule_id`
- election-authority signatures

`governance_source` is the pinned `GovernanceSource` record from section 2.4. A
frozen manifest may not carry an unresolved source revision.

`electorate_registry_hashes` allows multiple registry snapshots, because some
elections (for example `CC_REMOVAL_APPEAL` and `TIP_AMENDMENT`) use separate
Council and CC electorates. Each registry snapshot and each per-electorate
result remains separately verifiable, and `governance_outcome_rule_id`
identifies how the separate results combine into a single governance outcome.

The election scope used by the anonymous-membership proof must derive from the complete manifest hash, not merely a human-readable election name.

---

## 10. Ballot package

A ballot package contains no human identity or wallet address.

Required fields:

- `protocol_version`
- `manifest_hash`
- `ballot_schema_id`
- canonical ballot payload or ciphertext
- anonymous membership proof
- election-scoped nullifier or key image
- proof-suite identifier

Optional fields must be tightly controlled. The MVP should avoid unique client metadata and high-resolution timestamps because they create fingerprinting opportunities.

### 10.1 Canonical ballot encoding

Candidate IDs are fixed byte strings from the candidate manifest.

The encoding must be length-delimited or canonical CBOR. Delimiter-joined text is forbidden because distinct logical ballots can encode to identical bytes.

Unicode display names are presentation data and are not signed as candidate identifiers.

### 10.2 Validation

Before proof verification, the verifier rejects:

- unknown protocol versions;
- wrong manifest hashes;
- oversized packages;
- unsupported proof suites;
- malformed encodings;
- duplicate candidate IDs in a ranking;
- unknown candidate IDs;
- invalid number of selections;
- empty ballots where not explicitly permitted.

The following MVP ballot rules are locked:

- Candidate identifiers are stable machine identifiers.
- Display names are presentation data and are not signed identifiers.
- Duplicate selections are rejected.
- Unknown selections are rejected.
- Invalid encoding is rejected.
- An unresolved tie is reported as a tie. There is no alphabetical political
  tie-breaking.
- First valid ballot counts for the MVP.
- A later ballot reusing the same election-scoped nullifier is rejected.

### 10.3 Receipt

A relay receipt contains:

- manifest hash;
- ballot package hash;
- relay identifier;
- relay sequence or batch identifier;
- received-before-close assertion;
- relay signature.

The receipt does not contain the voter's human identity.

---

## 11. Cryptographic construction selection

Phase 1 defines requirements, not a home-grown production primitive.

Candidate approaches may include:

- a reviewed scope-linkable ring-signature construction;
- a reviewed anonymous-credential system with election nullifiers;
- a reviewed zero-knowledge set-membership construction.

The selected construction must provide:

- proof of membership in the frozen registry;
- election-scoped duplicate detection;
- no stable cross-election public tag;
- canonical point and scalar parsing;
- rejection of identity, small-order, malformed, and noncanonical values;
- domain separation binding the protocol version, complete manifest hash, registry commitment, ballot bytes, and proof commitments;
- published test vectors;
- a security rationale applicable to the exact construction;
- an independent review before binding use.

The existing Python LSAG proof of concept is reference material only. It must not become the production cryptographic backend by gradual accident.

---

## 12. Offline authoritative archive

Every finalized election produces a self-contained directory:

```text
election-<id>/
  README.md
  manifest.cbor
  manifest.json
  registry.cbor
  registry.json
  candidate-manifest.cbor
  candidate-manifest.json
  submissions/
  relay-receipts/
  batches/
  accepted-ballots.cbor
  rejected-ballots.cbor
  tally-transcript.cbor
  tally-transcript.json
  result.cbor
  result.json
  verification-report.json
  ootle-anchor-records.json
  SHA256SUMS
  archive-signatures/
```

The archive must be sufficient for a clean computer with the verifier and no Tari connection to reproduce the result.

### 12.1 Archive commitment

The finalized archive has:

- canonical file ordering;
- hashes for every file;
- one top-level archive manifest;
- a final archive hash;
- signatures from the election authority and available independent verifiers.

### 12.2 Mirrors

For a pilot, maintain at least three independent copies:

1. project release archive;
2. Tari forum or governance archive;
3. local/offline preserved backup.

IPFS or another content-addressed mirror may be added but is not required for the MVP.

---

## 13. Ootle anchor

### 13.1 Purpose

The Ootle component provides an append-only public record of commitments and lifecycle transitions.

It does not need to contain:

- voter identities;
- governance private keys;
- raw ballot bodies;
- wallet addresses belonging to voters;
- encrypted archives large enough to reconstruct the election.

### 13.2 Immutability definition

For this project, **immutable** means:

- the template exposes no method to edit or delete an existing commitment;
- each transition references the previous state;
- finalized fields cannot be replaced;
- anyone can compare the component state and events with the offline archive.

A testnet reset can erase the ledger. Therefore, testnet immutability is conditional on the surviving chain history, not permanent archival existence.

### 13.3 Proposed component state

```text
protocol_version
template_version
election_id
manifest_hash
registry_root
candidate_manifest_hash
privacy_mode
status
opens_at
closes_at
batch_chain_head
submitted_ballot_count
final_submission_root
verification_report_hash
tally_transcript_hash
result_hash
final_archive_hash
reanchor_of
```

### 13.4 Proposed methods

#### `create_election`

Creates the immutable election header from manifest commitments.

#### `append_batch`

Appends:

- batch index;
- previous batch-chain head;
- Merkle root of ballot package hashes;
- number of ballot packages;
- relay identifier;
- batch archive hash.

It cannot edit an older batch.

#### `close_election`

Fixes the final batch-chain head and submitted-ballot count.

#### `publish_verification`

Adds the verification report hash, accepted/rejected transcript commitment, and tally transcript hash.

#### `finalize_result`

Adds the result hash and final archive hash, then permanently closes the component.

#### `record_reanchor`

Creates a new component after a reset or network migration and references:

- prior network identifier;
- prior template and component addresses;
- prior transaction identifiers if available;
- the unchanged manifest, registry, result, and archive hashes.

### 13.5 Authorization

The MVP uses a small manifest-declared set of anchor or relay keys.

No single anchor key can create or modify a valid ballot proof.

A later version may allow permissionless batch anchoring with anti-spam controls, but that is not required for the first pilot.

### 13.6 Testnet reset procedure

If the testnet resets:

1. preserve the complete offline archive and old anchor evidence;
2. verify the archive locally;
3. publish the same template version or an explicitly documented successor;
4. create a re-anchor component using unchanged election commitments;
5. publish a re-anchor record in the archive;
6. never rewrite the original election package to pretend the new component was the original anchor.

---

## 14. Tally requirements

Every tally algorithm is identified by a versioned algorithm ID.

The manifest must define:

- valid ballot forms;
- treatment of incomplete rankings;
- treatment of duplicate choices;
- exhausted ballots;
- majority threshold;
- tie-breaking;
- candidate withdrawal;
- deterministic round ordering;
- output transcript format.

The verifier must reject malformed ballots before tallying rather than silently interpreting them.

The MVP supports:

- approval voting as the first implemented pilot tally;
- referendum and threshold rules that are manifest-driven and versioned;
- single-seat IRV only after its exact rules receive governance approval and a
  versioned rule identifier;
- multi-seat STV or another system is deferred.

An election that requires two electorates (for example `CC_REMOVAL_APPEAL` or
`TIP_AMENDMENT`) produces two independent tally transcripts before applying a
governance outcome rule. Each transcript remains separately verifiable.

Multi-seat Council elections require a separately approved method such as
defined multi-seat races or STV.

---

## 15. Disputes and failure handling

A finalized archive includes:

- every submitted package available to the archive;
- every relay receipt;
- rejection reason codes;
- duplicate-nullifier decisions;
- every tally round;
- software versions;
- test-vector results;
- anchor comparison results.

A dispute may concern:

- registry eligibility;
- omitted receipt-backed submission;
- invalid proof classification;
- duplicate handling;
- tally implementation;
- archive mismatch;
- anchor mismatch.

Cryptographic validity cannot decide political eligibility disputes. Those remain governance decisions and must be documented separately.

---

## 16. Attribution and project neutrality

The project may state in its README and About screen:

> Built by GSXRspartan, creator of Purrivacy Swap, as an open-source contribution to Tari governance.

The ballot-casting screen, ballot receipt, verifier result, and election outcome must not ask voters to support the developer's CC candidacy or donate.

Purrivacy Swap may be linked from the project About page and release announcement. The voting mechanism itself must remain politically neutral so participants do not wonder whether using the tool is also a campaign endorsement.

The finished pilot can fairly be cited as evidence of sustained Tari contribution. That is stronger than putting “please make me a CC” next to the Cast Ballot button, which would have the subtlety of a campaign sticker on a jury form.

---

## 17. Phase plan and acceptance gates

# Phase 1 — Specification and threat model

### Deliverables

- this specification;
- public issue list;
- cryptographic-construction decision record;
- governance-rule questions for Tari reviewers;
- data-format test-vector plan.

### Exit criteria

- no unresolved ambiguity about MVP ballot type;
- agreement that governance keys are separate from wallet keys;
- agreement that the offline archive is authoritative during testnet;
- agreement on Ootle anchor responsibilities;
- review comments recorded rather than silently edited away.

# Phase 2 — Offline reference implementation

### Recommended workspace

```text
tari-cc-private-ballot/
  docs/
  crates/
    protocol/
    crypto/
    registry/
    ballot/
    tally/
    verifier/
    archive/
    cli/
  test-vectors/
  fuzz/
  examples/
```

### Requirements

- Rust implementation;
- canonical CBOR;
- immutable data structures;
- explicit error types;
- dependency lockfile;
- deterministic vectors;
- property tests;
- fuzz targets;
- no walletd, indexer, Ootle, or network dependency;
- complete archive generation and verification;
- synthetic cohort tests;
- hostile malformed-input corpus.

### Exit criteria

- fresh offline machine reproduces the complete result;
- all edge cases have explicit expected outcomes;
- no custom cryptographic claim exceeds what tests and review support;
- at least one reviewer can run the verifier independently.

# Phase 3 — Non-binding pilot

### Pilot subject

Use a harmless question such as:

- project codename;
- testnet mascot choice;
- README cover design;
- preferred demo ballot style.

### Requirements

- no binding CC admission, removal, Council, or treasury decision;
- volunteer electorate;
- public manifest and registry snapshot;
- ballot receipts;
- complete archive;
- public verification report;
- documented privacy limitations.

### Exit criteria

- every included voter can verify inclusion;
- independent reproduction matches;
- omissions and invalid ballots are explained;
- pilot retrospective published.

# Phase 4 — Ootle testnet anchor

### Requirements

- Rust/WASM Ootle template;
- append-only lifecycle;
- local template tests;
- batch commitment chain;
- finalized archive commitment;
- reset and re-anchor drill;
- client that compares component state with the offline archive.

### Exit criteria

- local tests prove old commitments cannot be edited;
- testnet pilot anchors match the archive;
- simulated reset preserves verifiability;
- no voter wallet identity is required for ballot creation or relay submission.

# Phase 5 — Independent review and MVP release

### Required review areas

- exact cryptographic construction;
- canonical serialization;
- registry governance;
- privacy and metadata leakage;
- tally rules;
- Ootle template access control and state transitions;
- archive and re-anchor process;
- user-interface safety.

### MVP release requirements

- tagged source release;
- reproducible build instructions;
- published threat model;
- published test vectors;
- independent verifier or independently implemented verification path;
- review findings and fixes;
- explicit non-binding status unless Tari governance formally approves binding use.

Only after Phase 5 should the community consider a binding election.

---

## 18. Locked decisions for v0.1

The following decisions are accepted for the initial build:

1. Governance keys are separate from wallet and spending keys.
2. The offline archive is sufficient to verify the election.
3. Ootle stores commitments and lifecycle state, not voter identities.
4. Testnet reset recovery uses re-anchoring without rewriting history.
5. The MVP begins with anonymous-signer/public-ballot mode.
6. The first real-world pilot is harmless and non-binding.
7. Production cryptography will not be copied directly from the Python proof of concept.
8. Project attribution belongs in documentation and About surfaces, not inside ballot decisions.
9. Binding use requires independent review.
10. The first pilot is a non-binding approval poll.
11. First valid ballot counts.
12. Candidate identifiers are stable machine identifiers.
13. Duplicate and unknown choices are rejected.
14. Unresolved ties are reported.
15. The exact governance source revision is pinned before freezing.
16. Public-ballot mode is limited to harmless pilot use.
17. Binding Council elections require a reviewed sealed-ballot design.
18. The multi-seat Council election method remains deferred.

---

## 19. Open review questions

These questions must be answered or explicitly deferred before Phase 2 signs or
hashes protocol data. The canonical, categorized list lives in
`docs/OPEN_QUESTIONS.md`; this section summarizes it and must stay consistent
with it.

### Governance

- Who authorizes each electorate registry, and who signs the registry snapshot?
- How are Council-only, CC-only, and mixed governance votes represented?
- What happens if a governance key is lost or compromised before opening, or
  compromised after voting opens?
- Who may void or restart an election, and what dispute period applies?
- How is an omitted receipt-backed ballot handled?

### Ballot privacy

- How are Council ranked ballots sealed until closing?
- Is threshold decryption required, who holds decryption authority, and what
  happens if a decryption participant is unavailable?
- How is anonymous constructive feedback attached to a negative CC-admission
  vote, and is it revealed only after closing or only during an appeal?
- How are timing and relay metadata reduced?

### Tallying

- What exact single-seat IRV rules apply, are incomplete rankings allowed, and
  how are exhausted ballots and final ties handled?
- How are simultaneous multi-seat Council vacancies handled — separate seat
  elections, STV, or another approved system?

### Cryptography

- Which reviewed anonymous-membership construction, group, and canonical
  encoding rules are used?
- What minimum electorate size triggers an anonymity warning or refusal?
- What independent reviewer or second implementation, and what deterministic
  test vectors and fuzzing criteria, are required?

### Ootle

- Who may create, append, close, verify, and finalize an anchor?
- Are batch submissions single-relay, multi-relay, or permissionless?
- What evidence is preserved before a testnet reset, and how is a re-anchor
  linked to the original component and archive?
- What prevents an anchor operator from publishing a false final result hash,
  and how does the verifier distinguish a valid archive from a merely anchored
  but invalid archive?

---

## 20. Source basis

### 20.1 Governance sources

- Tari Core Contributor Program forum post #47 and the surrounding discussion:
  https://community.tari.com/t/the-core-contributor-program/204/47
- tari-project/rfcs pull request PR #185:
  https://github.com/tari-project/rfcs/pull/185

PR #185 is under review and is not merged or approved. It is a moving source and
must be pinned to an immutable revision for each frozen election (section 2.4).

### 20.2 Additional inputs

This draft is also informed by:

- the Tari Community Charter requirement for recorded Core Contributor voting and published election procedures;
- Tari Ootle documentation describing templates as WASM logic with on-chain component state and atomic transaction execution;
- Tari Ootle documentation noting that client APIs remain under active development;
- the submitted Python LSAG/election proof of concept and its stated limitations;
- initial adversarial review identifying empty-ring acceptance, ambiguous ballot encoding, mutable snapshots, insufficient malformed-ballot validation, and overbroad test claims.

### 20.3 Distinguishing requirements from decisions

- **Requirements directly derived from the governance sources:** the set of
  governance election types and their electorates, thresholds, and outcome
  rules, which this project treats as manifest-governed and pinned rather than
  hard-coded.
- **Engineering decisions made by this project:** canonical CBOR encoding,
  election-scoped nullifiers, offline-archive authority, the Ootle anchor
  boundary, first-valid-ballot-counts for the MVP, stable machine candidate IDs,
  and reporting rather than breaking ties.
- **Unresolved questions requiring Tari governance or cryptographic review:**
  the items tracked in `docs/OPEN_QUESTIONS.md`, including the exact
  anonymous-membership construction, sealed-ballot design, registry-authorizing
  body, and exact IRV and multi-seat rules.

The specification deliberately separates protocol requirements from the final cryptographic construction so public review can occur before implementation choices harden into accidental consensus.
