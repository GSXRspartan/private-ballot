# Eligibility Security Model

## Core Guarantee

**ONE ENROLLED CREDENTIAL, ONE ACCEPTED VOTE PER ELECTION.**

## What Private Ballot Guarantees

### Only enrolled credentials can produce valid membership proofs

A Triptych membership proof is valid only if the prover holds the secret key
corresponding to a public key in the frozen registry. Because the registry is
committed in the election manifest, and the manifest commitment is embedded in
every ballot's proof statement, a proof against any other set of keys is
cryptographically rejected.

A credential that was never enrolled cannot produce a valid proof for that
election. No invitation, no enrollment, no ballot.

### One credential produces a stable election-specific nullifier

Triptych derives a deterministic key image (nullifier) from the voter's secret
key and the election scope. The nullifier is the same for any two ballots
produced from the same secret key in the same election, regardless of:

- which device generated the proof
- which browser context is used
- which IP address or VPN is in use
- what randomness was used for the Triptych proof (the proof bytes may differ;
  the nullifier does not)

### The same credential cannot cast two accepted votes in one election

The backend enforces `UNIQUE (election_id, nullifier)` in SQLite. If two ballot
packages carry identical nullifiers, only the first stored wins. The second
returns `duplicate_nullifier` (HTTP 409). Concurrent submissions with the same
nullifier are serialised through the ingest lock; exactly one is accepted.

### Changing browser/device/IP/VPN does not change this

The nullifier is derived from the secret key and election scope only. Transport
metadata, device fingerprints, and network addresses play no role. An adversary
who copies the secret credential to a second device obtains the same nullifier
and cannot cast a second accepted ballot.

### Concurrent duplicate submissions cannot both be accepted

The `ingest_lock` serialises ballot ingestion. After the lock is acquired, the
backend replays the full acceptance ledger before ingesting the new ballot. If
the nullifier is already present in the ledger or in storage, the new ballot is
rejected before the storage write. Even if two requests race before the lock,
only one can hold the lock at a time, so only one can win the unique constraint.

### Registry membership cannot change after freeze

Once the eligibility state reaches `REGISTRY_FROZEN`:
- No new slots can be added.
- No enrolled credential can be replaced or removed.
- No new enrollment can succeed (enrollment endpoint returns 409).
- The `frozen_registries` table stores the canonical CBOR, commitment, and
  counts as a permanent audit record.

The election manifest is built from the frozen registry commitment. Because the
manifest is immutable, the registry commitment it embeds is immutable for the
life of the election.

### Final archive identifies the frozen registry used for verification

The archive includes `registry.cbor` — the canonical CBOR of the frozen
registry — and `manifest.cbor` — the manifest that commits to it. The Desktop
verifier re-derives the commitment from `registry.cbor` and cross-checks it
against the manifest. Any substitution of the registry is detected.

## What Private Ballot Does NOT Guarantee

### The organizer gave only one slot to each human

Private Ballot enforces that each slot produces at most one enrolled credential,
and each credential casts at most one accepted vote. It has no knowledge of
whether the organizer assigned multiple slots to the same human.

**This is intentional**. Making Private Ballot aware of human identity would
require surveillance infrastructure incompatible with voter anonymity.

The correct solution is external governance: the body authorising the election
must enforce the policy "one human, one slot" at the roster level.

### The organizer's external roster corresponds to unique humans

Private Ballot accepts an optional `external_roster_commitment_hex` that
governance bodies may publish before enrollment opens. This allows auditors to
confirm that the election used the roster the governance body approved. It does
not make Private Ballot responsible for verifying that the roster contains
unique humans.

### A person did not obtain multiple legitimate eligibility slots

If a person legitimately received two slots (through any external process),
they can enroll two credentials and cast two accepted ballots. Private Ballot
treats each slot independently and correctly. The governance/enrollment process
is responsible for preventing this.

### Hosted Mode provides network anonymity

The hosted backend operates over HTTPS. A network-level observer may correlate
ballot submissions with IP addresses. For stronger network anonymity, voters
should use Tor or a VPN. The Desktop mode supports native Tor integration;
the hosted mode does not currently route through Tor.

## The Phrase to Use

> ONE ENROLLED CREDENTIAL, ONE ACCEPTED VOTE PER ELECTION.

Do not use "one person, one vote" unless clearly labelled as an external
governance/enrollment policy rather than a cryptographic guarantee.

## Eligibility States

```
DRAFT
  │  (organizer establishes slot count and optional external roster commitment)
  ▼
ENROLLMENT_OPEN
  │  (invitations issued per slot; voters enroll public credentials)
  ▼
REGISTRY_FROZEN
  │  (registry committed, manifest built, no further enrollment)
  ▼
VOTING_OPEN
  │  (ballots accepted, Triptych proofs verified against frozen registry)
  ▼
VOTING_CLOSED
  │  (ballot acceptance window closed)
  ▼
FINALIZED
     (archive generated, Desktop verifier can verify)
```

## Invitation Lifecycle

```
(slot created)
    │
    ▼
ACTIVE invitation issued  ──── [reissue] ──→ old: VOIDED, new: ACTIVE
    │
    ├── voter enrolls successfully ──→ CONSUMED, slot consumed
    │
    └── organizer voids ──→ VOIDED
```

A slot can have at most one ACTIVE invitation at a time. A consumed slot cannot
have new invitations issued against it.

## Idempotency Cases

| Case | Invitation | Public Key | Result |
|------|-----------|------------|--------|
| A (retry) | same | same | Returns same receipt; no second registry entry |
| B (conflict) | same | different | Rejected; slot not consumed a second time |
| C (dup key) | different | already enrolled | Rejected; second invitation NOT consumed |
| D (concurrent) | same | same | Exactly one wins; other resolves as Case A |
