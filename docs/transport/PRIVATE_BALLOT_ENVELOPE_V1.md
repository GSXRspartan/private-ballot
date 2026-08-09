# Private Ballot Envelope V1

The local `PrivateBallotEnvelopeV1` uses RFC 9180 HPKE Base mode only:
`DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`, and `ChaCha20Poly1305`.
No sender identity, PSK, or authentication mode is used. Before encryption the
exact canonical `BallotPackageV1` bytes are length-prefixed then zero padded to
the descriptor's fixed bounded size. HPKE info is versioned; canonical AAD binds
version/protocol, manifest hash, descriptor fingerprint, gateway key ID, and
padding policy ID. Opening requires all bindings and recovers byte-identical
inner bytes; it then calls the existing 5A11 intake boundary.

The envelope itself is strict canonical CBOR with bounded ciphertext. It is
transport encryption only: no packet-level indistinguishability or ballot
confidentiality claim is made. No Tor, onion, relay, HTTP, or socket exists.
