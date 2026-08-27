//! Immutable, stateless aggregate-anchor event template for Tari Private Ballot.
//!
//! This template intentionally has no component constructor, resource builder,
//! vault, bucket, or persistent application state. Its sole callable function
//! validates and emits the already-derived aggregate anchor digest. It never
//! receives ballots, credentials, voter data, archive bytes, or any other
//! election material.

use tari_template_lib::prelude::*;

/// The custom event topic before Tari prefixes it with the template module.
pub const ANCHOR_EVENT_TOPIC_V1: &str = "TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V1";
/// The sole metadata key in the anchor event payload.
pub const ANCHOR_DIGEST_KEY_V1: &str = "anchor_digest";

#[template]
mod tari_private_ballot_anchor {
    use super::*;

    /// Stateless ABI carrier. Calling `publish_anchor` never creates an
    /// instance of this type, so it cannot create a component or store state.
    pub struct TariPrivateBallotAnchor;

    impl TariPrivateBallotAnchor {
        /// Emits exactly one deterministic aggregate-anchor event.
        ///
        /// `anchor_digest` must be exactly the existing canonical 32-byte
        /// `OotleAnchorRecordV1` digest encoded as 64 lowercase hexadecimal
        /// characters. The template deliberately does not recalculate or
        /// redefine that digest.
        pub fn publish_anchor(anchor_digest: String) {
            assert!(
                is_canonical_anchor_digest(&anchor_digest),
                "anchor_digest must be 64 lowercase hexadecimal characters"
            );

            emit_event(
                ANCHOR_EVENT_TOPIC_V1,
                metadata!(ANCHOR_DIGEST_KEY_V1 => anchor_digest),
            );
        }
    }

    fn is_canonical_anchor_digest(value: &str) -> bool {
        value.len() == 64
            && value
                .as_bytes()
                .iter()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    }
}
