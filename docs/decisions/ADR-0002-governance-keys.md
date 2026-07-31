# ADR-0002: Dedicated governance keys

## Status

Accepted for Phase 1 draft.

## Decision

Voters use dedicated governance keypairs. Tari wallet seeds, account keys, and
spending keys are never imported or used by the voting protocol.

## Reasons

- Voting cannot move or expose funds.
- Eligibility and key rotation remain governance concerns rather than wallet
  ownership concerns.
- A compromised voting key does not directly compromise a Tari wallet.
