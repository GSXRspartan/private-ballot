# Voter Credential Container V1

This file format stores one Tari governance voter credential. It is not a Tari
wallet seed, wallet backup, mnemonic, organizer key, or recovery escrow.

The credential is reusable across elections. Its public governance key is public
metadata and may be used in a default filename. The 32-byte Triptych signing
scalar is encrypted at rest with a voter-supplied passphrase. The organizer
cannot recover a lost file or passphrase.

Copying the encrypted credential file to another computer does not enable
double voting. When the same credential is used in the same election, the real
Triptych proof path produces the same election-scoped nullifier/linking tag, and
the verifier ledger accepts only the first valid ballot. Across different
election scopes, the nullifiers differ.

Passphrases are accepted as arbitrary Unicode and normalized to NFC in Rust
before Argon2id input. This normalization applies only to the passphrase. It
does not change credential secret bytes, public governance keys, election data,
or proposal-question rules.

At-rest encryption does not protect an already-compromised or already-unlocked
machine. The unlocked scalar exists briefly in process memory for decryption and
proof construction, with zeroizing scratch buffers used for normalized
passphrase material, derived keys, decrypted scalar bytes, and temporary
plaintext buffers.

## Algorithms

V1 accepts exactly these parameters:

| Field | Value |
| --- | --- |
| KDF | Argon2id |
| Argon2 memory | 64 MiB |
| Argon2 time cost | 3 |
| Argon2 parallelism | 4 |
| Salt | 16 random bytes |
| AEAD | XChaCha20-Poly1305 |
| Nonce | 24 random bytes |
| Plaintext | exactly 32 credential-scalar bytes |
| Ciphertext and tag | exactly 48 bytes |

V1 containers do not carry arbitrary KDF work factors. Any change to these
parameters requires a new credential-container format version.

## Binary Layout

All integer fields are little-endian. The exact V1 length is 144 bytes.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | magic: `TCB-CRED` |
| 8 | 2 | format version: `1` |
| 10 | 1 | KDF ID: Argon2id |
| 11 | 1 | AEAD ID: XChaCha20-Poly1305 |
| 12 | 4 | Argon2 memory MiB: `64` |
| 16 | 4 | Argon2 time cost: `3` |
| 20 | 4 | Argon2 parallelism: `4` |
| 24 | 16 | salt |
| 40 | 24 | XChaCha20-Poly1305 nonce |
| 64 | 32 | public governance key |
| 96 | 48 | ciphertext and Poly1305 tag |

The authenticated associated data is the entire 96-byte header, from magic
through public governance key. There are no variable fields, no CBOR, no
trailing bytes, and no election ID or manifest hash in the credential file.
