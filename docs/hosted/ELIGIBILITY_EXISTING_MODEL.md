# Eligibility Existing Model

## What Desktop Private Ballot Already Guarantees

### Frozen Electorate Registry

The core protocol operates on a `RegistrySnapshot`: a canonically sorted, deduplicated
set of `GovernancePublicKey` entries. This snapshot is:

- Frozen before any ballot is accepted (`DRAFT → FROZEN` lifecycle transition).
- Serialised as canonical CBOR (sorted ascending by key bytes; duplicates rejected).
- Committed via BLAKE3 with domain separation `HashDomain::RegistrySnapshotV1`.
- Included in the `ElectionManifest` as `registry_commitment` (32-byte digest).
- Bound to every ballot's `ProofStatementV1` via that same commitment.

The lifecycle enforces `DRAFT → FROZEN → OPEN → CLOSED → VERIFIED → FINALIZED`.
Once frozen, the registry commitment is immutable for the life of the election.
No ballot can be verified unless its embedded commitment matches the frozen one.

### Triptych Anonymous Membership Proof

Each voter proves membership in the frozen registry using Triptych
(`TARI_TRIPTYCH_PROTOTYPE_V1`), a linkable ring signature scheme.
The proof demonstrates that the signer holds the secret key corresponding to
one of the public keys in the registry, without revealing which one.

### Election-Bound Nullifier — One Accepted Vote Per Credential

Triptych derives a deterministic **key image** (nullifier) from the voter's
secret key and the election scope. For any given (secret key, election) pair,
the nullifier is identical regardless of:

- Which device generates the proof.
- Which randomness is used for Triptych's internal proof randomness.
- Which browser context, IP address, or VPN is used.

The backend enforces a `UNIQUE (election_id, nullifier)` constraint in SQLite.
If two ballots carry the same nullifier, only the first is accepted.
Concurrent submissions with the same nullifier resolve safely via the unique
constraint: exactly one wins, the other is a `StorageError::DuplicateNullifier`.

### Archive and Desktop Verifier

The canonical archive contains:
- `manifest.cbor` — frozen election manifest with registry commitment
- `registry.cbor` — canonical registry CBOR
- `candidates.cbor` — candidate set CBOR
- `submissions/` — all accepted ballot packages

The Desktop verifier replays all ballots against the archived registry and
confirms tally correctness. Any mutation of the registry is detectable because:
- The manifest commits to the registry via `registry_commitment`.
- Each ballot's proof statement embeds the same commitment.
- The archive manifest hashes every file and is committed via BLAKE3.

## What Hosted Mode Already Reuses

The hosted backend (`crates/hosted`) reuses the full Desktop protocol core:
- `tari-cc-private-ballot-registry` — `RegistrySnapshot`, canonical CBOR, commitment
- `tari-cc-private-ballot-ballot` — `ElectionManifest`, `ElectionLifecycleV1`, ballot packages
- `tari-cc-private-ballot-crypto` — Triptych prover/verifier
- `tari-cc-private-ballot-verifier` — `BallotAcceptanceLedger`, nullifier uniqueness
- `tari-cc-private-ballot-archive` — archive format, Desktop verifier compatibility

The hosted backend enforces:
- `ElectionLifecycleV1` state at ballot ingestion time
- Nullifier uniqueness in SQLite (`UNIQUE (election_id, nullifier)`)
- Receipt idempotency (`UNIQUE (election_id, receipt_id)`)
- Registry commitment cross-check during ballot verification
- Two control planes (public `8788`, admin `8789`) with no admin routes on the public plane

## What Was Missing Before This Milestone

The Stage 2 hosted backend provided no enrollment machinery:
- **No eligibility lifecycle**: the registry was imported as a pre-built package
  via `POST /api/v1/admin/elections/import` (which set state to "open" immediately).
- **No authorized slot count**: no concept of an organizer-approved participant
  count that becomes immutable before enrollment opens.
- **No invitation system**: no mechanism to issue, revoke, or reissue per-slot
  one-time enrollment credentials.
- **No enrollment endpoint**: voters had no way to submit public credentials
  to the hosted backend; the registry had to be built externally.
- **No DRAFT → ENROLLMENT_OPEN → REGISTRY_FROZEN → VOTING_OPEN lifecycle**:
  enrollment and voting were collapsed into a single import-then-open step.
- **No external roster commitment**: no mechanism for external governance bodies
  to commit to an approved eligibility roster before enrollment opens.
- **No concurrent enrollment safety**: no idempotency handling for lost-response
  retries during the enrollment phase.
- **No registry freeze evidence**: no stored audit record of when the registry
  was frozen and what it contained.

This milestone adds all of the above.
