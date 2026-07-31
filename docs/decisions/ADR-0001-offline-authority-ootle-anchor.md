# ADR-0001: Offline archive is authoritative; Ootle is an anchor

## Status

Accepted for Phase 1 draft.

## Decision

The complete offline election archive is sufficient to verify the election.
The Tari Ootle component stores append-only commitments and lifecycle
transitions. It does not store voter identities and is not the only copy.

## Reasons

- Tari testnets may reset.
- Verification should not require walletd, an indexer, or a surviving network.
- Raw ballots and proofs are easier to archive, mirror, and independently test
  outside consensus.
- Ootle still provides useful public timestamping and tamper-evident commitments.

## Consequences

A reset requires transparent re-anchoring of unchanged hashes. It must never
require rebuilding or rewriting the historical election package.
