#![forbid(unsafe_code)]

//! Offline canonical Ootle anchor record.
//!
//! This crate defines a small, project-owned, versioned wrapper record that
//! binds one completed Phase 3 archive commitment ([`ArchiveHashV1`]) to a
//! future Tari Ootle testnet transaction. It is deliberately a leaf crate: it
//! consumes the immutable protocol and archive commitments and adds no ballot,
//! proof, nullifier, registry, voter, or tally information.
//!
//! The record is offline-only. It contains no networking, wallet, indexer,
//! transaction-builder, or receipt logic; those boundaries are owned by later
//! Phase 4 slices. Constructing an anchor record is a pure deterministic
//! transformation of already-frozen values and cannot modify any election
//! artifact, so a failure to construct or later submit an anchor never changes
//! the authoritative offline archive.
//!
//! [`ArchiveHashV1`]: tari_cc_private_ballot_archive::ArchiveHashV1

mod canonical;
mod digest;
mod public_payload_v2;
mod record;

pub use digest::{
    OOTLE_ANCHOR_HASH_FRAME_PREFIX, OOTLE_ANCHOR_RECORD_DOMAIN_LABEL_V1, OotleAnchorRecordHashV1,
};
pub use public_payload_v2::{
    MAX_BALLOT_QUESTION_BYTES_V2, MAX_OOTLE_ANCHOR_PUBLIC_PAYLOAD_BYTES_V2,
    OOTLE_ANCHOR_PUBLIC_PAYLOAD_DOMAIN_LABEL_V2, OOTLE_ANCHOR_PUBLIC_PAYLOAD_FRAME_PREFIX_V2,
    OOTLE_ANCHOR_PUBLIC_PAYLOAD_SCHEMA_VERSION_V2, OOTLE_ANCHOR_PUBLIC_PAYLOAD_TYPE_ID_V2,
    OotleAnchorPublicPayloadV2, OotleAnchorTallyEntryV2, OotleAnchorTemplateBindingV2,
    assert_v2_public_payload_is_leak_free,
};
pub use record::{
    MAX_OOTLE_ANCHOR_RECORD_BYTES, MAX_OOTLE_NETWORK_ID_BYTES, OOTLE_ANCHOR_PURPOSE_ID_V1,
    OOTLE_ANCHOR_RECORD_FIELD_COUNT_V1, OOTLE_ANCHOR_RECORD_TYPE_ID_V1, OotleAnchorRecordV1,
    OotleNetworkIdV1,
};
