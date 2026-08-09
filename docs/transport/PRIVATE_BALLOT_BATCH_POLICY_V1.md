# Private Ballot Batch Policy V1

An anonymity threshold counts only `accepted_unique_count`, never received or
merely structurally verified ciphertext. The local simulator tracks all three
counters and exposes threshold status only from accepted unique ballots. One
valid ballot plus 99 junk envelopes is not a 100-ballot set.

Below the configured floor, valid ballots remain valid but must not be described
as meeting a batching anonymity threshold. Later inclusion evidence is delayed
to close where practical; a permanent singleton is explicitly reduced-anonymity.

Future operator policy is periodic accepted-batch-root anchoring where enabled,
plus a final archive/root anchor. No voter wallet or transaction participates;
fees are not assumed zero. The collector accepts bounded authenticated envelopes
only before a coarse public cutoff epoch, then a bounded drain may verify already
admitted ciphertexts. This does not weaken the core OPEN-only file intake rule.
The present slice has no wall-clock admission implementation or Ootle epoch
authority; those are required before a live transport.

## Admission and close semantics

The gateway admission gate is authoritative for online cutoff. It begins `OPEN`.
On close it moves to `CLOSING`, rejects new admissions, and lets only already
admitted delivery finish. The core election is closed only after every admitted
delivery finishes or the operator's bounded drain expires; then the gate is
`CLOSED`. A delivery that misses the drain must return a generic unavailable or
closed result and must not call the core intake after close. Voter clocks,
collector receipt time, and relay arrival time are not cutoff authority.

## Deterministic commitments

Only accepted canonical package digests enter a pending batch. At sealing they
are sorted lexicographically and de-duplicated, then leaf and internal-node
BLAKE3 inputs use separate project hash domains. An odd Merkle level duplicates
its final node. Inclusion proofs contain only the package digest, root, and
sibling direction/hash pairs; they contain no ingress position or time. A final
close batch below its configured floor remains valid but is explicitly marked
reduced anonymity. A final batch-set commitment sorts sealed roots before hashing.

`ANCHORED` is not implied by a batch root. It can be emitted only after the
existing operator-side Ootle anchor verification reports a verified result.
