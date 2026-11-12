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

    /// Host-only regression locks on the argument validators. These run before
    /// any engine call, so invalid inputs are testable on the host target; the
    /// successful emission path is exercised by the embedded-definition decode
    /// test in `tests/abi_contract.rs` and by on-network qualification.
    #[cfg(test)]
    mod tests {
        use super::{
            TariPrivateBallotAnchorV2, is_bounded_nonempty, is_bounded_printable,
            is_canonical_digest,
        };
        use crate::{
            ANCHOR_EVENT_TOPIC_V2, MAX_ELECTION_ID_LEN, MAX_NETWORK_LEN, MAX_PUBLIC_SUMMARY_LEN,
            V2_DIGEST_KEY, V2_ELECTION_ID_KEY, V2_NETWORK_KEY, V2_PUBLIC_SUMMARY_KEY,
        };

        #[test]
        fn event_topic_is_stable() {
            assert_eq!(
                ANCHOR_EVENT_TOPIC_V2,
                "TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2"
            );
        }

        #[test]
        fn metadata_keys_are_stable() {
            assert_eq!(V2_DIGEST_KEY, "anchor_digest_v2");
            assert_eq!(V2_NETWORK_KEY, "network");
            assert_eq!(V2_ELECTION_ID_KEY, "election_id");
            assert_eq!(V2_PUBLIC_SUMMARY_KEY, "public_summary");
        }

        #[test]
        fn argument_bounds_are_stable() {
            assert_eq!(MAX_NETWORK_LEN, 32);
            assert_eq!(MAX_ELECTION_ID_LEN, 128);
            assert_eq!(MAX_PUBLIC_SUMMARY_LEN, 256 * 1024);
        }

        #[test]
        fn canonical_digest_accepts_64_lowercase_hex() {
            assert!(is_canonical_digest(&"0123456789abcdef".repeat(4)));
            assert!(is_canonical_digest(&"0".repeat(64)));
        }

        #[test]
        fn canonical_digest_rejects_everything_else() {
            assert!(!is_canonical_digest(""));
            // 63 / 65 characters
            assert!(!is_canonical_digest(&"a".repeat(63)));
            assert!(!is_canonical_digest(&"a".repeat(65)));
            // uppercase hex
            assert!(!is_canonical_digest(&"A".repeat(64)));
            // non-hex characters
            assert!(!is_canonical_digest(&"g".repeat(64)));
            assert!(!is_canonical_digest(&format!("{}-", "a".repeat(63))));
        }

        #[test]
        fn network_accepts_bounded_identifier_charset() {
            assert!(is_bounded_nonempty("mainnet", MAX_NETWORK_LEN));
            assert!(is_bounded_nonempty("esmeralda", MAX_NETWORK_LEN));
            assert!(is_bounded_nonempty("net-1_2", MAX_NETWORK_LEN));
        }

        #[test]
        fn network_rejects_empty_oversized_and_foreign_charset() {
            assert!(!is_bounded_nonempty("", MAX_NETWORK_LEN));
            assert!(!is_bounded_nonempty(
                &"a".repeat(MAX_NETWORK_LEN + 1),
                MAX_NETWORK_LEN
            ));
            assert!(!is_bounded_nonempty("esmeralda testnet", MAX_NETWORK_LEN));
            assert!(!is_bounded_nonempty("ésmeralda", MAX_NETWORK_LEN));
        }

        #[test]
        fn election_id_accepts_bounded_printable() {
            assert!(is_bounded_printable(
                "0123456789abcdef0123456789abcdef",
                MAX_ELECTION_ID_LEN
            ));
            assert!(is_bounded_printable(
                &"x".repeat(MAX_ELECTION_ID_LEN),
                MAX_ELECTION_ID_LEN
            ));
        }

        #[test]
        fn election_id_rejects_empty_oversized_and_control_bytes() {
            assert!(!is_bounded_printable("", MAX_ELECTION_ID_LEN));
            assert!(!is_bounded_printable(
                &"x".repeat(MAX_ELECTION_ID_LEN + 1),
                MAX_ELECTION_ID_LEN
            ));
            assert!(!is_bounded_printable("\u{0}", MAX_ELECTION_ID_LEN));
            assert!(!is_bounded_printable("id\u{1f}", MAX_ELECTION_ID_LEN));
        }

        #[test]
        fn public_summary_accepts_the_full_cap_and_multibyte_utf8() {
            assert!(is_bounded_printable(
                &"a".repeat(MAX_PUBLIC_SUMMARY_LEN),
                MAX_PUBLIC_SUMMARY_LEN
            ));
            assert!(is_bounded_printable("summary 中 é", MAX_PUBLIC_SUMMARY_LEN));
        }

        #[test]
        fn public_summary_rejects_over_cap_and_control_bytes() {
            assert!(!is_bounded_printable(
                &"a".repeat(MAX_PUBLIC_SUMMARY_LEN + 1),
                MAX_PUBLIC_SUMMARY_LEN
            ));
            assert!(!is_bounded_printable("", MAX_PUBLIC_SUMMARY_LEN));
            assert!(!is_bounded_printable(
                "summary\u{7}",
                MAX_PUBLIC_SUMMARY_LEN
            ));
        }

        #[test]
        #[should_panic(expected = "anchor_digest must be 64 lowercase hexadecimal characters")]
        fn publish_rejects_non_canonical_digest() {
            TariPrivateBallotAnchorV2::publish_anchor_v2(
                "NOT-A-DIGEST".to_owned(),
                "mainnet".to_owned(),
                "0123456789abcdef".to_owned(),
                "{}".to_owned(),
            );
        }

        #[test]
        #[should_panic(expected = "network must be a short non-empty identifier")]
        fn publish_rejects_invalid_network() {
            TariPrivateBallotAnchorV2::publish_anchor_v2(
                "a".repeat(64),
                "esmeralda testnet".to_owned(),
                "0123456789abcdef".to_owned(),
                "{}".to_owned(),
            );
        }

        #[test]
        #[should_panic(expected = "election_id must be a bounded, printable, non-empty string")]
        fn publish_rejects_invalid_election_id() {
            TariPrivateBallotAnchorV2::publish_anchor_v2(
                "a".repeat(64),
                "mainnet".to_owned(),
                "\u{2}".to_owned(),
                "{}".to_owned(),
            );
        }

        #[test]
        #[should_panic(expected = "public_summary must be a bounded, printable canonical string")]
        fn publish_rejects_invalid_public_summary() {
            TariPrivateBallotAnchorV2::publish_anchor_v2(
                "a".repeat(64),
                "mainnet".to_owned(),
                "0123456789abcdef".to_owned(),
                format!("{}\u{3}", "x".repeat(64)),
            );
        }
    }
}
