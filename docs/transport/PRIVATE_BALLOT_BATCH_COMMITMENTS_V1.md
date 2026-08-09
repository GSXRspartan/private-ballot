# Private ballot batch commitments V1

Only accepted unique package digests enter pending batches. Sealing sorts and
deduplicates digests lexicographically; it does not use ingress order. Leaf,
internal-node, and final batch-set hashes have separate protocol domains. Odd
Merkle levels duplicate the last node. A final below-floor batch is valid and
marked reduced-anonymity. A batch root alone is not an Ootle anchor.
