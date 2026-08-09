# ADR-0010: transport crypto and trust root

Status: accepted for local simulator only.

Transport descriptors use Ed25519 (RFC 8032) through `ed25519-dalek 3.0.0`.
Envelopes use RFC 9180 `hpke 0.14.0` Base mode with
X25519/HKDF-SHA256, HKDF-SHA256, and ChaCha20Poly1305. This is the `hpke` crate,
not the separate `hpke-rs` package family. Minimal features are `alloc`,
`getrandom`, `x25519`, and `chacha`; no PQ/default suite is enabled.

`TransportAuthorityRootV1` is a release-pinned public Ed25519 verification key
for transport configuration only. Its private key is offline and is neither
generated nor committed here. The production pin is intentionally unprovisioned
until a reviewed release ceremony inserts it, and online transport stays disabled.
Rotation needs a released new root/key ID, overlap/revocation record, and archive
retention for old-election verification. A descriptor never authenticates itself.
