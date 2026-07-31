# ADR-0004: MVP ballot validation and tally policy

## Status

Accepted for the Phase 1 draft.

These decisions apply to the first harmless, non-binding pilot. They do not
settle the rules for binding Core Contributor or Council elections.

## Context

The first pilot must test the election lifecycle, registry snapshot,
anonymous-membership proof, duplicate-vote detection, receipts, archive,
public verification, and Ootle commitments without depending on unresolved
ranked-choice or multi-seat governance rules.

Ballot validity and tally behavior must be defined before implementation.
Otherwise different clients may accept, reject, or count the same bytes
differently.

## Decision

### 1. Pilot election schema

The first implemented election schema is:

`NON_BINDING_APPROVAL_PILOT`

It is used only for a harmless pilot question with a volunteer or synthetic
electorate.

### 2. Candidate identifiers

- Protocol ballots use stable machine candidate identifiers.
- Display names, capitalization, formatting, and emoji are presentation data.
- Candidate identifiers must appear in the pinned candidate manifest.
- Unknown candidate identifiers are invalid.
- Duplicate candidate identifiers in one ballot are invalid.

### 3. Selection limits

The election manifest defines:

- the minimum permitted number of selections;
- the maximum permitted number of selections;
- whether an empty selection is permitted as abstention.

A ballot outside those limits is invalid and is not silently corrected.

### 4. Duplicate-ballot policy

The MVP uses:

`FIRST_VALID_BALLOT_COUNTS`

After the first valid ballot for an election-scoped nullifier is accepted,
later ballots carrying the same nullifier are rejected as duplicates.

The verifier records duplicate rejections in the public verification
transcript without revealing the voter identity.

The MVP does not support ballot replacement or revoting.

### 5. Validation policy

A ballot is rejected if any of the following applies:

- unsupported protocol version;
- wrong election manifest hash;
- unsupported ballot schema;
- malformed or noncanonical encoding;
- oversized ballot package;
- unknown candidate identifier;
- duplicate candidate identifier;
- too few or too many selections;
- invalid anonymous-membership proof;
- duplicate election-scoped nullifier.

Implementations must publish deterministic rejection reason codes.

### 6. Approval tally

- Each valid ballot contributes one approval to each selected candidate.
- A ballot cannot contribute more than one approval to the same candidate.
- Counts are calculated only from accepted ballots.
- Candidate output ordering is canonical and independent of hash-map or set
  iteration order.
- The complete tally transcript is included in the offline archive.

### 7. Tie handling

An unresolved tie is reported as a tie.

The software does not select a winner alphabetically, randomly, by submission
time, or through another undeclared convenience rule.

A later governance process may resolve the tie only through a rule explicitly
identified in the election manifest.

### 8. Other election types

Referendum thresholds, CC admission rules, removal appeals, TIP amendments,
single-seat IRV, and elections involving multiple electorates remain separate
versioned schemas.

Single-seat IRV is implemented only after its exact validation, exhaustion,
majority, elimination, and tie rules are approved.

Multi-seat Council elections remain deferred until Tari governance formally
selects separate seat elections, STV, or another method.

## Consequences

- The first pilot can test the full system without settling binding governance.
- Every conforming verifier must classify and count the same ballot identically.
- Duplicate voting is deterministic, but ballot correction is not available in
  the MVP.
- Ties remain visible instead of being hidden behind implementation behavior.
- More complex election schemas can be added without changing the meaning of
  archived pilot elections.

## Deferred questions

- Whether binding elections allow ballot replacement.
- Exact single-seat IRV rules.
- Exact multi-seat Council election method.
- Binding-election tie resolution.
- Sealed-ballot and threshold-decryption design.
- Anonymous constructive feedback for negative CC-admission votes.
