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
