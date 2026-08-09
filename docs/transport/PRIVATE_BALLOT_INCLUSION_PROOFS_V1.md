# Private ballot inclusion proofs V1

An inclusion proof contains a package digest, batch root, and directional
sibling hashes. Verification uses the domain-separated Merkle construction and
does not disclose ingress position or timing. `ACCEPTED`, `INCLUDED`, and
`ANCHORED` are distinct states. `ANCHORED` must not be emitted unless an
existing operator anchor workflow returns verified evidence.
