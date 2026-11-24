# Sybil Resistance and Eligibility Trust Boundary

## The Sybil Problem Private Ballot Does Not Solve

A Sybil attack in an election is when one human obtains multiple valid
credentials and casts multiple ballots that are each individually valid.

Private Ballot cryptographically prevents one credential from casting two
accepted votes in the same election (via the election-bound nullifier). It does
not cryptographically prevent one human from obtaining two separate, legitimately
enrolled credentials.

**This is not a software defect. It is a deliberate design boundary.**

Solving the Sybil problem at the cryptographic layer requires either:
1. Linking voter identities to credentials (destroying anonymity), or
2. Some form of biometric or document uniqueness proof (introducing surveillance
   infrastructure incompatible with the system's threat model), or
3. A central identity provider that knows which human holds which credential
   (creating a deanonymisation oracle).

None of these are acceptable. The correct solution is **governance**.

## Example: Alice Gets Two Slots

Suppose an organiser conducts an election with 100 eligible participants.
The external governance body approves the roster and publishes a commitment.

If the organiser (accidentally or intentionally) grants Alice two separate
eligibility slots:

1. Alice enrolls **credential A** via invitation for slot 1.
2. Alice enrolls **credential B** via invitation for slot 2.
3. Alice votes with credential A → accepted, nullifier NA recorded.
4. Alice votes with credential B → accepted, nullifier NB recorded.

Both votes are accepted. Private Ballot sees two different valid credentials.
It cannot cryptographically infer that credential A and credential B belong to
the same human.

This is not a protocol failure. Alice legitimately received two slots from the
organiser. Private Ballot's guarantee is:

> Credential A casts at most one vote. Credential B casts at most one vote.
> ONE ENROLLED CREDENTIAL, ONE ACCEPTED VOTE PER ELECTION.

The protocol guarantee holds. The governance failure is that the organiser gave
Alice two slots, not one.

## What the Software Can and Should Do

Private Ballot provides the tools to make organiser enrollment behaviour
**bounded and auditable**:

1. **Authorized slot count is set before enrollment opens and becomes
   immutable.** If the governance body approved 100 participants, the software
   prevents credential 101 without an explicit, auditable revision to the
   configuration.

2. **Each slot can produce at most one enrolled credential.** A consumed slot
   cannot issue a second invitation that enrolls a second credential.

3. **The registry commitment is computed at freeze time and included in the
   archive.** An auditor can verify that the frozen registry used for vote
   verification matches the slot count and enrolled count on record.

4. **The optional `external_roster_commitment_hex`** allows governance bodies
   to publish a commitment to their approved roster before enrollment opens.
   This creates an auditable link between the external approval process and the
   election's eligibility configuration.

5. **Aggregate enrollment progress is visible to the organiser** (slot count,
   issued invitations, enrolled count, unused slots) but no voter identities
   are stored or required.

## What External Governance Must Guarantee

The governance body conducting the election must enforce:

- **One externally approved participant → one eligibility slot → one enrolled
  credential.**
- The roster submitted to the software corresponds to unique individuals
  (or unique entities, as defined by the governing rules of the election).
- Invitation secrets are delivered to the correct participant and not shared.
- The external roster commitment (if used) is published and verifiable by
  election observers before enrollment opens.

Private Ballot does not and cannot verify these properties. It provides the
machinery to make violations detectable after the fact (via the audit trail)
but cannot prevent a governance authority from intentionally granting
double-slots.

## Security Model Phrasing

| Claim | Accurate? |
|-------|-----------|
| One enrolled credential, one accepted vote per election | ✅ Cryptographic guarantee |
| Same credential from two devices cannot vote twice | ✅ Cryptographic guarantee |
| Registry cannot change after freeze | ✅ Cryptographic guarantee |
| One human, one vote | ❌ External governance responsibility only |
| Organiser cannot give two slots to one person | ❌ Not a software guarantee |
| Invitation delivery is secure end-to-end | ❌ Operational/organisational responsibility |

## Why Not Link Voter Identities?

Adding even weak identity linkage (email, phone, wallet address) would:

1. Create a deanonymisation oracle accessible to operators, auditors, or
   adversaries who compromise the backend.
2. Make the system non-compliant with use cases where voter anonymity is a
   legal or ethical requirement.
3. Encourage scope creep toward surveillance infrastructure.
4. Not actually solve the Sybil problem for a determined organiser who controls
   the enrollment process.

The correct approach is auditability of organiser behaviour, not surveillance
of voter identity. This is why Private Ballot stores aggregate counts but not
the linkage between invitation slots and enrolled public keys after freeze.
