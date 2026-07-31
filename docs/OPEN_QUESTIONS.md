# Open Questions

This document separates decisions that are already locked for the MVP from
questions that still require Tari governance or cryptographic review. Open
questions must be answered or explicitly deferred before Phase 2 signs or
hashes protocol data.

## Locked MVP decisions

- The first pilot uses non-binding approval voting.
- First valid ballot counts.
- Candidate choices use stable machine identifiers; display names are
  presentation data only.
- Unknown and duplicate selections are rejected.
- Unresolved ties are reported as ties, not resolved alphabetically.
- Pilot mode may use anonymous-signer/public-ballot privacy.
- Binding Council elections should require sealed ballots until closing,
  subject to a reviewed design.
- The complete offline archive remains independently verifiable.
- Ootle stores commitments and lifecycle state, not voter identities.
- Each election pins an exact governance source revision before freezing.

## Open review questions

### Governance

1. Who authorizes each electorate registry?
2. Who signs the registry snapshot?
3. How are Council-only, CC-only, and mixed governance votes represented?
4. What happens if a governance key is lost or compromised before opening?
5. What happens if it is compromised after voting opens?
6. Who may void or restart an election?
7. What dispute period applies?
8. How is an omitted receipt-backed ballot handled?

### Ballot privacy

1. How are Council ranked ballots sealed until closing?
2. Is threshold decryption required?
3. Who holds decryption authority?
4. What happens if a decryption participant is unavailable?
5. How is anonymous constructive feedback attached to a negative CC-admission
   vote?
6. Is that feedback revealed only after closing or only during an appeal?
7. How are timing and relay metadata reduced?

### Tallying

1. What exact single-seat IRV rules apply?
2. Are incomplete rankings allowed?
3. How are exhausted ballots handled?
4. What happens in a final tie?
5. How are simultaneous multi-seat Council vacancies handled?
6. Will Tari use separate seat elections, STV, or another approved system?

### Cryptography

1. Which reviewed anonymous-membership construction is used?
2. Which group and canonical encoding rules apply?
3. What minimum electorate size triggers an anonymity warning or refusal?
4. What independent reviewer or second implementation is required?
5. What deterministic test vectors and fuzzing criteria are mandatory?

### Ootle

1. Who may create, append, close, verify, and finalize an anchor?
2. Are batch submissions single-relay, multi-relay, or permissionless?
3. What evidence is preserved before a testnet reset?
4. How is a re-anchor linked to the original component and archive?
5. What prevents an anchor operator from publishing a false final result hash?
6. How does the verifier distinguish a valid archive from a merely anchored
   but invalid archive?
