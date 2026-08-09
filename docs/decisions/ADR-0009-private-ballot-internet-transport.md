# ADR-0009: Private ballot Internet transport

## Status

Proposed design; implementation deferred after Phase 5 Slice 5A12A.

## Context

5A11 established a transport-independent canonical byte-intake boundary. The
project needs normal-user delivery that avoids pairing a direct source connection
with a readable ballot, while retaining offline export and avoiding voter
accounts, wallets, tTARI, or Ootle transactions. ElectionManifestV1 has no
transport endpoint/key field and cannot change in this slice.

## Decision

1. Treat BallotPackageV1 as immutable carrier bytes. Future transport calls the
   5A11 intake boundary; network metadata never becomes canonical election data.
2. Prefer managed Tor to an onion collector, then encrypted batched handoff to a
   decrypting gateway. Tor is not a claim against timing/global-observer risk.
3. Support a future standards-based OHTTP/HPKE split-trust relay only with
   independent operators and authenticated configuration. Retain offline export.
4. Forbid silent direct HTTPS fallback. Failure requires Retry, explicit private
   alternative, or offline export.
5. Require bounded padded envelopes, two-stage signed receipts,
   population-plus-time batching, deterministic post-seal commitments, and
   privacy-preserving logging.
6. Specify a separately canonical signed TransportDescriptorV1, manifest-hash
   bound, with distinct transport signing/decryption keys.
7. Keep production online submission disabled until a reviewed descriptor-signer
   authentication root exists. A future manifest version binding descriptor hash
   is the stronger resolution.
8. Reuse Phase 4 generic completed-archive anchoring later. Operators, never
   voters, make minimized-frequency Ootle evidence transactions.

## Consequences

A low-cost deployment can run collector, gateway, bounded store, and managed Tor
on one existing server, but one administrator can correlate components. A
hardened profile separates ingress/mix and gateway keys/logs/storage; its
protection requires non-collusion. Current public ballot-content status remains
unchanged. Individual inclusion verification is planned; receipt-freeness and
coercion resistance are not.

## Rejected alternatives

- Direct HTTPS to decrypting gateway: pairs source connection with readable ballot.
- Voter accounts/API keys/wallet authentication: defeats anonymous eligibility.
- Per-voter Ootle transactions: adds cost/chain metadata without network privacy.
- Changing ElectionManifestV1 or BallotPackageV1: breaks this slice's compatibility boundary.
- Immediate unsigned HTTP success: proves neither acceptance nor inclusion.

## Deferred work

5A12B through 5A12F own envelope/descriptor prototyping, Tor, relay,
batching/commitments, inclusion verification, archive integration, deployment,
logging, and independent security/privacy review.
