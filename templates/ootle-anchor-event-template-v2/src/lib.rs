//! Immutable, stateless V2 public-summary anchor event template.
//!
//! Like the V1 template, this has no component constructor, resource, vault, or
//! persistent state. Its sole callable function validates and emits the
//! human-readable public aggregate election result plus its authoritative
//! domain-separated digest.
//!
//! On-chain event shape (corrected V2): the template puts the readable
//! canonical public summary on-chain verbatim. Independent observers can
//! display the election question, per-option counts, hashes, and commitments
//! directly from the emitted event, and can hash the emitted `public_summary`
//! bytes under the V2 domain frame to reproduce `anchor_digest_v2`. The
//! template never receives ballots, credentials, voter data, or archive bytes.

use tari_template_lib::prelude::*;

/// The custom event topic before Tari prefixes it with the template module.
pub const ANCHOR_EVENT_TOPIC_V2: &str = "TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2";

/// Metadata keys in the V2 event payload.
pub const V2_DIGEST_KEY: &str = "anchor_digest_v2";
pub const V2_NETWORK_KEY: &str = "network";
pub const V2_ELECTION_ID_KEY: &str = "election_id";
pub const V2_PUBLIC_SUMMARY_KEY: &str = "public_summary";

/// Bounds on the on-chain arguments. `public_summary` is bounded to match the
/// off-chain canonical payload cap in `tari_cc_private_ballot_anchor` and the
/// transport-side event metadata cap.
const MAX_NETWORK_LEN: usize = 32;
/// Matches `MAX_ELECTION_ID_BYTES_V2` in the canonical payload crate and the
/// transport-side event validator.
const MAX_ELECTION_ID_LEN: usize = 128;
const MAX_PUBLIC_SUMMARY_LEN: usize = 256 * 1024;

#[template]
mod tari_private_ballot_anchor_v2 {
    use super::*;

    /// Stateless ABI carrier. Calling `publish_anchor_v2` never creates an
    /// instance of this type, so it cannot create a component or store state.
    pub struct TariPrivateBallotAnchorV2;

    impl TariPrivateBallotAnchorV2 {
        /// Emits exactly one deterministic V2 public-summary anchor event.
        ///
        /// * `anchor_digest` — the canonical 32-byte V2 public-payload digest as
        ///   64 lowercase hex characters. The template does not recompute it;
        ///   the caller has verified `blake3(frame || public_summary) ==
        ///   anchor_digest` off-chain, and independent observers can reproduce
        ///   that using the emitted `public_summary` bytes.
        /// * `network` — the Ootle network id (short bounded identifier).
        /// * `election_id` — the election id as lowercase hex (bounded).
        /// * `public_summary` — the exact canonical public-summary bytes
        ///   (deterministic JSON) that the anchor digest commits to. Placed
        ///   on-chain verbatim so indexers/explorers can display the full
        ///   public election result without any detached artifact.
        pub fn publish_anchor_v2(
            anchor_digest: String,
            network: String,
            election_id: String,
            public_summary: String,
        ) {
            assert!(
                is_canonical_digest(&anchor_digest),
                "anchor_digest must be 64 lowercase hexadecimal characters"
            );
            assert!(
                is_bounded_nonempty(&network, MAX_NETWORK_LEN),
                "network must be a short non-empty identifier"
            );
            assert!(
                is_bounded_printable(&election_id, MAX_ELECTION_ID_LEN),
                "election_id must be a bounded, printable, non-empty string"
            );
            assert!(
                is_bounded_printable(&public_summary, MAX_PUBLIC_SUMMARY_LEN),
                "public_summary must be a bounded, printable canonical string"
            );

            emit_event(
                ANCHOR_EVENT_TOPIC_V2,
                metadata!(
                    V2_DIGEST_KEY => anchor_digest,
                    V2_NETWORK_KEY => network,
                    V2_ELECTION_ID_KEY => election_id,
                    V2_PUBLIC_SUMMARY_KEY => public_summary
                ),
            );
        }
    }

    fn is_canonical_digest(value: &str) -> bool {
        value.len() == 64
            && value
                .as_bytes()
                .iter()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    }

    /// Bounded printable-string check reused by any argument that must survive
    /// on-chain verbatim (election id, canonical public summary): non-empty,
    /// bounded, and free of raw C0 control bytes.
    fn is_bounded_printable(value: &str, max_len: usize) -> bool {
        if value.is_empty() || value.len() > max_len {
            return false;
        }
        for byte in value.as_bytes() {
            if *byte < 0x20 {
                return false;
            }
        }
        true
    }

    fn is_bounded_nonempty(value: &str, max_len: usize) -> bool {
        !value.is_empty()
            && value.len() <= max_len
            && value
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_')
    }

}
