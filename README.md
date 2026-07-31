# Tari CC Private Ballot

An offline-verifiable anonymous voting system for Tari governance, with an
optional append-only Tari Ootle anchor.

## Design principle

The complete offline election archive must be sufficient to verify an election.
Ootle records immutable commitments and lifecycle transitions, but it is not
the only copy and is not trusted to survive testnet resets.

## Project phases

1. Protocol specification and threat model
2. Offline Rust reference implementation
3. Harmless non-binding pilot
4. Ootle testnet anchoring template
5. Independent review and MVP release

## Safety status

This repository is not production election software. It must not be used for a
binding Core Contributor, Council, treasury, or charter vote before Phase 5.
