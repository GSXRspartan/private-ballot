# Security Model — Private Ballot (v0.1.0 Alpha)

Community project, non-binding governance pilot, Esmeralda testnet. This
document describes the security model of the implementation as it exists in
this repository. It is not a formal audit, not a certification, and not a
production election guarantee. It intentionally does not oversell any property
that the code has not been shown to enforce.

For the reporting process and the release gate checklist, see
[`SECURITY.md`](../SECURITY.md).

## 1. Roles

- **Organizer** (also "ballot office"): a person operating a desktop instance
  of the app to create an election, run the intake service, finalize the
  archive, and optionally publish a public V2 aggregate anchor.
- **Voter**: a person operating a desktop instance of the app to unlock a
  voter credential, prepare a ballot, and submit it privately over Tor to an
  advertised organizer onion address.
- **Verifier**: any third party who receives the finalized archive and
  independently recomputes the tally with the shipped verifier code.

## 2. Voter credential secrecy

Voter credentials are stored encrypted with Argon2id-derived material and are
unlocked/created/imported/backed-up off the UI thread. The credential
plaintext is never written to disk, environment, log, or command line. The
credential secret is used to derive:

- the voter's Triptych proving witness,
- the voter's election-scoped nullifier.

The passphrase itself never leaves the voter's machine.

## 3. Public enrollment set

Every eligible voter's public enrollment key is published to all voters (and
to the archive) so that the anonymity set for the Triptych ring-membership
proof is the full electorate rather than a per-voter subset. This is what makes
"eligible member" the anonymity guarantee: a valid proof proves membership
in the published set, not identity within it.

## 4. Ballot proof — Triptych eligibility anonymity

Each valid ballot carries a Triptych zero-knowledge proof of membership in the
published enrollment set (the "TARI_TRIPTYCH v1" prototype suite, vendored from
the Tari `triptych` crate). A verifier can independently check every ballot's
proof against the enrollment set with no information about which voter cast it,
beyond the guarantee that some enrolled voter did.

## 5. Nullifiers — one ballot per election per voter

Each ballot also carries an election-scoped nullifier derived from the voter's
credential secret and the election id. Two ballots from the same voter in the
same election produce the same nullifier; the verifier and the organizer's
intake enforce single-use per nullifier per election. The nullifier is
linkable within a single election so double-voting is detectable; it is not
linkable across elections.

## 6. First-valid semantics

The organizer intake accepts the first valid, unique-nullifier ballot for each
voter in each election. Subsequent submissions by the same nullifier are
rejected. The reject reason is exposed to the voter so a legitimate retry (for
example after a transport error) can be distinguished from an intentional
double-submit.

## 7. Ballot-office authentication and trust

The organizer publishes a signed ballot-office identity ("transport bundle")
that voters must configure before they can submit. This binds voters' traffic
to a specific ballot-office onion address and public key. In default and
release builds this is a real operator-provisioned "production" transport
authority; the app fails closed if the required binding is not provisioned.

## 8. Tor / private intake

Ballot submission is carried over Tor onion services managed in-process by
the app. The organizer runs an intake hidden service; each voter's client uses
its own SOCKS port. The Tor executable is user-selected on first run and its
absolute path is validated (real regular file, no symlinks or reparse points,
no control characters) every time it is spawned. Public source contains **no
developer-machine Tor path** in the allowlist.

The transport model is documented in more detail in
`docs/transport/PRIVATE_BALLOT_TRANSPORT_THREAT_MODEL_V1.md`. In particular,
network-level anonymity depends on Tor assumptions, route choice, operator
logging, and timing/volume characteristics; it is not a blanket promise that
nobody can correlate participation.

## 9. Encrypted offline fallback

Ballots that cannot reach an intake (offline, transport error) are held in an
encrypted per-voter draft state. The voter can re-attempt submission later
without re-preparing the ballot.

## 10. Finalized archive — authoritative result

The finalized archive is the authoritative artifact. It contains:

- the election manifest,
- the enrollment set,
- every accepted ballot package (proof + nullifier),
- the transport-binding evidence,
- the tally.

A third-party verifier can independently:

- verify every ballot's Triptych proof,
- verify uniqueness of nullifiers,
- recompute the tally,
- verify the transport-binding provenance.

The archive verifier is the source of truth for the election outcome.

## 11. Optional non-binding V2 Ootle anchor

The organizer may optionally publish a public aggregate anchor to Tari Ootle
via the V2 event template. This is:

- optional,
- organizer-side only (voters never submit Ootle transactions),
- fee-bearing (operator's wallet pays the fee),
- limited to public aggregate evidence (no per-voter data, no ballot data),
- non-authoritative — the archive remains the authoritative result even if the
  anchor publish fails or is skipped.

## 12. walletd signer boundary

Anchor publish involves a locally installed `walletd` process (external to
this repository — see
`docs/development/WALLETD_DISTRIBUTION_RECOMMENDATION.md`) reached over an
authenticated JSON-RPC route. The walletd API key is held in the OS-backed
secure credential store (Windows Credential Manager / macOS Keychain via the
`keyring` crate). It is never in an env var, a file on disk, a log line, or a
command line.

## 13. Known Alpha limitations

- The project is Alpha for a non-binding governance pilot; it is not a
  hardened, audited production election system.
- Windows is the primary tested target; Linux and macOS builds have not yet
  been validated against this tree.
- Some transport / anonymity properties depend on operator configuration and
  Tor's own assumptions (see the transport threat model document).
- Some third-party attribution and licensing decisions remain open (see
  `THIRD_PARTY_NOTICES.md` and `docs/development/PUBLIC_REPOSITORY_CURATION_PLAN.md`).
- No formal audit has been performed.

## 14. Never publish

- Real voter credentials, credential files, or passphrases.
- Wallet API keys, wallet databases, wallet state, seed phrases, mnemonics,
  or private keys.
- Tor onion-service private keys or private transport-authority keys.
- Live election archives, LocalAppData runtime state, or Ootle evidence
  sidecars from a real run.
