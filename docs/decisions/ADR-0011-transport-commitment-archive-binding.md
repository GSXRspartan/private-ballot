# ADR-0011: Transport commitment archive binding

## Status

Accepted for Phase 5A12CDEF. This decision adds an archive constituent; it
does not alter the Phase 4 Ootle anchor protocol.

## Decision

`TransportArchiveBindingV1` is canonical CBOR stored only at
`transport/archive-binding-v1.cbor`. It binds the canonical election ID,
manifest hash, authenticated transport-descriptor fingerprint and generation,
canonical sealing batch identities, batch roots, accepted-unique counts,
reduced-anonymity flags, and the deterministic final batch-set commitment.

The final batch-set commitment is recomputed from lexicographically sorted
batch roots in the existing `TransportBatchSetV1` hash domain. Batch entries
are canonicalized by their monotonic sealing identity. Neither ordering form
is voter ingress order.

`final_batch_set_commitment` is a derived transport-level convenience
commitment over the batch roots. It does not bind every transport field.
`ArchiveHashV1`, over the completed canonical archive that contains the full
`TransportArchiveBindingV1`, is the authoritative final commitment used by the
existing Phase 4 Ootle anchor.

The binding includes no IP/source/relay data, timestamps, retry capability,
gateway or transport-root secret, voter credential, Triptych member index,
nullifier, or organizer intake sequence.

The archive writer validates the binding against the loaded election and adds
its exact canonical bytes to the ordinary `ArchiveManifestV1` catalog before
calculating `ArchiveHashV1`. The independent archive verifier requires strict
canonical decode and the same election/manifest binding before reporting the
binding verified. Archive catalog paths and file digests are themselves
hash-covered; mutation or late addition invalidates archive verification.

The public final verification sequence is:

`sealed batches -> TransportArchiveBindingV1 -> archive catalog -> ArchiveHashV1 -> existing OotleAnchorRecordV1 -> existing canonical Phase 4 evidence`.

`ANCHORED` requires every link plus `FINALIZED_ACCEPT`/`ACCEPTED` existing
Phase 4 evidence for the exact archive hash and reconstructed anchor-record
digest. Submitted, missing, rejected, fee-only, or unverified anchor evidence
remains `INCLUDED`.

The frozen Phase 4 evidence format is locally/deterministically verified. That
is not, by itself, independent live-ledger confirmation; real Ootle/testnet
verification remains a 5A13/release rehearsal item.

## Consequences

`OotleAnchorRecordV1`, `ArchiveHashV1`, and the fixed Phase 4 purpose
`NON_BINDING_APPROVAL_PILOT_ARCHIVE_ANCHOR` are unchanged. A transport root is
never cast as `ArchiveHashV1`, and no second ledger payload or voter Ootle path
exists. Periodic batches are locally/publicly included commitments only; the
final completed archive is the sole V1 authoritative Ootle anchor route.

There is no circular hash: transport commitments determine the binding bytes;
the binding bytes determine one archive-file digest; the catalog determines
`ArchiveHashV1`; only then does the existing Phase 4 anchor record commit to
that archive hash.
