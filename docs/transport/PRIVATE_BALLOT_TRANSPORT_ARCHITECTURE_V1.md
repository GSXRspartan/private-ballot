# Private ballot Internet transport architecture V1

## Status and invariant

**Proposed design only.** This document adds neither network code nor a
production privacy claim. BallotPackageV1 is immutable: a future transport
delivers exact canonical bytes to GuiElectionSessionV1::intake_ballot_package_bytes,
then existing strict decode, verifier, lifecycle gate, and election-scoped
nullifier duplicate detection decide acceptance. No network metadata, filename,
path, or voter identity enters the package, accepted record, tally, transcript,
or archive.

The present V1 ballot is a NON_BINDING_APPROVAL_PILOT with PUBLIC ballot
confidentiality. Transport encryption can protect bytes in transit; it does not
make the package secret from the decrypting gateway or later public archive.

## Normal-user policy

The only normal action is **Submit privately**. The app verifies locally, then
chooses the strongest authenticated healthy route: managed Tor to an onion
collector, then an explicitly configured OHTTP/HPKE split-trust relay, then
permanent offline .cbor export. There is no production direct
HTTPS-to-decrypting-gateway fallback. Failure says “Your ballot has not been
sent” and offers Retry, explicit alternate private route, or Export.

No user needs Tor Browser configuration, an onion URL, username, email, OAuth,
voter API key, unique client certificate, Tari/Ootle account, wallet, tTARI, or
voter Ootle transaction. Eligibility remains existing Triptych proof, the frozen
registry, and the election-scoped nullifier.

## Common envelope

A later versioned envelope surrounds, and never edits, exact package bytes. It
uses an audited standard hybrid public-key construction: HPKE in the common
model and OHTTP's registered mechanisms for relay delivery. It binds manifest
hash, authenticated descriptor hash, envelope version, gateway key ID, fixed
padding profile, bounded ciphertext, and a fresh client-generated receipt secret
commitment. The secret is a one-submission capability held locally, not a voter
identity or durable tracking token.

The descriptor declares one fixed padded submission size (or a small reviewed
set only if unavoidable). All valid packages pad before encryption; oversized
ones fail locally. Fixed reply shapes and generic errors accompany it. This
reduces choice/selection-count size leakage but cannot hide a submission's
existence, timing, endpoint choice, packet loss, or client compromise.

## Mode 1: managed Tor and onion collector

    Private Ballot App -> managed local Tor -> Tor network -> onion collector
      -> encrypted batch queue -> decrypting ballot gateway -> existing byte intake

The app manages the Tor component; voters do not configure it. The onion
endpoint is a collector, rather than the gateway, so it sees an opaque padded
envelope and arrival/circuit-facing data while the gateway receives sealed
batches and readable ballot data only after the batching boundary. Onion traffic
does not use a Tor exit. Tor normally hides direct voter IP from the ballot
service; it does not defeat timing correlation, a global observer, endpoint or
client compromise, malware, blocking, or bad logs.

The implementation must independently review the Tor client/sidecar choice,
bootstrap and update model, sandboxing, onion-service keys, bridge/censorship
behavior, crash recovery, and library selection. This design does not select a
library from memory.

## Mode 2: non-Tor split-trust relay

    App -> OHTTP relay (source address, opaque request) -> gateway
           (relay connection, decryptable package) -> existing byte intake

The client uses standard OHTTP/HPKE-style delivery for the gateway's published
key configuration. The relay must not decrypt, add X-Forwarded-For, forward
PROXY source metadata, set cookies, or assign stable client tokens. The gateway
sees a relay connection, not the voter’s direct connection. This requires
independent relay and gateway operators that do not collude; relay+gateway
collusion defeats the separation. Multiple relays are future descriptor data:
they improve choice but add fingerprinting, malicious-relay, availability, and
configuration-authenticity risk. Routing is not implemented here.

## Mode 3: offline export

Existing exact-byte .cbor export/import remains permanent: fallback,
disaster-recovery path, independent manual delivery route, and the choice for
voters who distrust Internet transport. It has no network-anonymity claim. Tor
plus offline export remains sufficient if nobody operates an optional relay.

## Batching and state ownership

The collector holds opaque envelopes and ephemeral batch slots only; it must
not carry source IP, high-resolution time, circuit ID, connection ID, or
forwarding data into election records. A batch closes after both a configured
hold time and configured population target, except at a documented election
close maximum wait.

    ReceivedCiphertext -> BatchPending -> BatchSealed -> Shuffled
      -> Decrypted/Decoded -> Verified -> Accepted or Rejected
      -> CommitmentBuilt -> InclusionAvailable

In Tor mode the onion collector owns receipt through shuffle, and the gateway
owns decrypt/decode through commitment. In relay mode the relay conveys opaque
requests only; a gateway-side collector owns the same states. A hardened profile
can give the collector/mix a separate operator in either mode.

Batch policy needs both time and population. At close, a below-target batch is
sealed with a public reduced-anonymity marker, never represented as having met
the target. Roots, accepted packages, and tally evidence should be delayed to
close where practical. One-ballot batches, voter announcements, a small
remaining electorate, and distinctive results remain statistical disclosure
risks, not cryptographic failures.

## Receipt, retry, and suppression evidence

| State | Meaning |
| --- | --- |
| Not sent | No collector evidence. |
| Received | Signed acknowledgement of opaque receipt only; not validity or acceptance. |
| Accepted | Existing canonical intake accepted after decode, proof, lifecycle, and nullifier checks. |
| Included | Signed batch statement and independently verifiable inclusion proof bind an accepted package digest to a published root. |
| Anchored | Operator-side Ootle evidence later binds completed archive evidence; it is not a voter transaction. |

The acknowledgement binds descriptor hash, election, batch epoch, receipt
capability commitment, and collector signature. The holder later requests
status/inclusion through a private route. An unsigned immediate success is never
proof. Repeating the same package is safe: the first valid nullifier wins. With
matching retained receipt capability, a retry may return previous delivery
accepted. A different package using the nullifier returns a generic duplicate.
If the voter lost the secret or received no acknowledgement, it is not possible
to distinguish prior success from another credential use without an identifying
account; the UI must say so.

Acknowledgement followed by missing acceptance/inclusion lets a voter detect
likely suppression. It cannot compel a silent gateway to communicate. The voter
keeps local bytes/evidence, may use another authenticated private route or
offline export, and can make an operational complaint.

## Commitments, publication, and Ootle

After verification, a future batch commitment uses the project's
domain-separated BLAKE3 style over exact canonical package bytes. Before code,
BatchCommitmentV1 needs reviewed new domain labels and canonical encoding. It
binds manifest hash, descriptor/padding/batch-policy identifiers, batch number,
and a Merkle root of accepted package digests. Leaves use lexicographic digest
order after sealing, not ingress order; duplicate leaves reject. An independent
verifier can reproduce the root and a minimal inclusion path without a name, IP,
or ingress time.

The final evidence archive later binds manifest, frozen registry/candidates/
governance evidence, accepted anonymous packages, unique nullifiers as needed
for replay audit, batch roots, deterministic tally, and final archive digest.
It excludes network source, exact arrival times, and ingress ordering. Existing
Phase 4 generic archive anchoring can commit to this completed archive;
operators make periodic/final Ootle transactions, at low frequency and with no
assumption that fees are zero. Voters never do.

## Authenticated configuration and keys

ElectionManifestV1 has no transport field and will not be mutated. A proposed
separately canonical signed TransportDescriptorV1 binds manifest hash,
onion/relay endpoints, OHTTP key config, gateway public encryption key/key ID,
collector and inclusion receipt verification keys, padding and batch policy,
permitted routes, validity interval, and version. Its hash appears in every
envelope and receipt and its fingerprint is visible in advanced UI.

It needs a distinct offline transport-configuration signing key authenticated
to voters through election distribution and retained in the final archive. It
is not a Triptych credential, organizer wallet key, or voter identity key. Use
per-election encryption/signing keys, a reviewable generation ceremony, signed
rotation with overlap, archived old public keys/descriptors, and documented
private-key destruction only after recovery/retention obligations.

V1 does not currently canonically bind this signer or descriptor hash. Until a
reviewed separate authentication root is implemented, production online
submission remains disabled. A future manifest version binding the descriptor
hash is the stronger long-term solution.

## Deployment profiles and next slices

The low-cost profile is one existing server with managed Tor/onion collector,
batch queue, gateway, bounded append-only storage, and strict process/key/log
separation. It needs no website, database cluster, dedicated Ootle node, or
voter payment. Proof verification is CPU-heavy; encrypted batches drive
bandwidth/storage. One administrator can still correlate components.

The hardened profile separates ingress/mix and gateway operators, keys, logs,
and storage, with optional independent relays. Under non-collusion no one
operator has both network origin and readable ballot; collusion, global traffic
analysis, or compromise removes that assurance. The protocol remains the same.

- **5A12B:** envelope/descriptor design, local collector-gateway simulator; no public Internet.
- **5A12C:** reviewed managed Tor/onion transport and failure UX.
- **5A12D:** standards-based split-trust relay after operator/authentication review.
- **5A12E:** batching, receipts, commitments, inclusion verification, archive and operator anchor integration.
- **5A12F:** deployment hardening, privacy logging tests, and review runbooks.
