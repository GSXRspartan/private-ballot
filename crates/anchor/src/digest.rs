//! Domain-separated production hashing of the canonical anchor record.
//!
//! The anchor-record digest uses its own frame prefix and domain label, both
//! distinct from every protocol domain in
//! [`tari_cc_private_ballot_protocol::HashDomain`]. The distinct prefix
//! guarantees the anchor-record digest can never collide with an archive,
//! manifest, registry, candidate-set, ballot, scope, or proof-statement digest,
//! even though it reuses the same production BLAKE3 provider.
//!
//! This digest commits to the wrapper record. It does not replace or reinterpret
//! [`ArchiveHashV1`], which remains the commitment to the completed archive.
//!
//! [`ArchiveHashV1`]: tari_cc_private_ballot_archive::ArchiveHashV1

use tari_cc_private_ballot_protocol::{
    BLAKE3_256_HASH_ALGORITHM_ID_V1, HashProvider, ProtocolError, ValidationCode,
};

use crate::record::OotleAnchorRecordV1;

/// Frame prefix placed before the anchor-record domain label.
///
/// This differs from the protocol frame prefix, so an anchor-record digest is
/// domain-separated from every protocol object digest.
pub const OOTLE_ANCHOR_HASH_FRAME_PREFIX: &[u8] = b"TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_FRAME_V1";

/// Unique domain label for the version-one anchor record.
pub const OOTLE_ANCHOR_RECORD_DOMAIN_LABEL_V1: &str =
    "tari-cc-private-ballot/ootle-anchor-record/v1";

/// Domain-separated production digest of one canonical anchor record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OotleAnchorRecordHashV1([u8; 32]);

impl OotleAnchorRecordHashV1 {
    /// Wraps an already derived anchor-record digest.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consumes the wrapper and returns the exact raw digest bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Builds the exact bytes hashed for one canonical anchor record.
///
/// The frame is: `prefix || 0x00 || domain-label || 0x00 || canonical-record`.
fn anchor_domain_input(canonical_record_bytes: &[u8]) -> Vec<u8> {
    let label = OOTLE_ANCHOR_RECORD_DOMAIN_LABEL_V1.as_bytes();

    let mut framed = Vec::with_capacity(
        OOTLE_ANCHOR_HASH_FRAME_PREFIX.len() + 1 + label.len() + 1 + canonical_record_bytes.len(),
    );

    framed.extend_from_slice(OOTLE_ANCHOR_HASH_FRAME_PREFIX);
    framed.push(0);
    framed.extend_from_slice(label);
    framed.push(0);
    framed.extend_from_slice(canonical_record_bytes);

    framed
}

impl OotleAnchorRecordV1 {
    /// Derives the domain-separated production anchor-record digest.
    pub fn canonical_hash<H: HashProvider>(
        &self,
        provider: &H,
    ) -> Result<OotleAnchorRecordHashV1, ProtocolError> {
        self.validate_hash_provider(provider)?;

        let encoded = self.to_canonical_cbor()?;
        let framed = anchor_domain_input(&encoded);

        Ok(OotleAnchorRecordHashV1::new(provider.hash(&framed)))
    }

    /// Verifies one expected anchor-record digest.
    pub fn verify_hash<H: HashProvider>(
        &self,
        provider: &H,
        expected: OotleAnchorRecordHashV1,
    ) -> Result<(), ProtocolError> {
        if self.canonical_hash(provider)? != expected {
            return Err(ProtocolError::new(
                ValidationCode::ArchiveManifestHashMismatch,
                "canonical anchor record does not match the expected anchor digest",
            ));
        }

        Ok(())
    }

    /// Confirms the selected provider is the production hash suite.
    pub fn validate_hash_provider<H: HashProvider>(
        &self,
        provider: &H,
    ) -> Result<(), ProtocolError> {
        if provider.algorithm_id() != BLAKE3_256_HASH_ALGORITHM_ID_V1 {
            return Err(ProtocolError::new(
                ValidationCode::UnsupportedHashAlgorithm,
                "anchor-record hashing requires the production hash provider",
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        OOTLE_ANCHOR_HASH_FRAME_PREFIX, OOTLE_ANCHOR_RECORD_DOMAIN_LABEL_V1,
        OotleAnchorRecordHashV1, anchor_domain_input,
    };
    use tari_cc_private_ballot_archive::ArchiveHashV1;
    use tari_cc_private_ballot_protocol::{
        Blake3HashProviderV1, HASH_FRAME_PREFIX, HashProvider, ManifestHash, ValidationCode,
    };

    use crate::record::{OotleAnchorRecordV1, OotleNetworkIdV1};

    #[derive(Debug, Clone, Copy)]
    struct OtherHasher;

    impl HashProvider for OtherHasher {
        fn algorithm_id(&self) -> &'static str {
            "OTHER_TEST_HASH"
        }

        fn hash(&self, _framed_input: &[u8]) -> [u8; 32] {
            [0x99; 32]
        }
    }

    fn record(network_value: &str, manifest_byte: u8, archive_byte: u8) -> OotleAnchorRecordV1 {
        let Ok(network) = OotleNetworkIdV1::new(network_value.to_owned()) else {
            panic!("test network identifier must be valid");
        };

        OotleAnchorRecordV1::new(
            network,
            ManifestHash::new([manifest_byte; 32]),
            ArchiveHashV1::new([archive_byte; 32]),
        )
    }

    #[test]
    fn anchor_frame_is_distinct_from_protocol_frame() {
        assert_ne!(OOTLE_ANCHOR_HASH_FRAME_PREFIX, HASH_FRAME_PREFIX);
    }

    #[test]
    fn anchor_domain_frame_has_stable_boundaries() {
        let framed = anchor_domain_input(&[1_u8, 2_u8, 3_u8]);

        let mut expected = OOTLE_ANCHOR_HASH_FRAME_PREFIX.to_vec();
        expected.push(0);
        expected.extend_from_slice(OOTLE_ANCHOR_RECORD_DOMAIN_LABEL_V1.as_bytes());
        expected.push(0);
        expected.extend_from_slice(&[1_u8, 2_u8, 3_u8]);

        assert_eq!(framed, expected);
    }

    #[test]
    fn identical_records_hash_identically() {
        let provider = Blake3HashProviderV1;

        let Ok(first) = record("esmeralda", 0x11, 0x22).canonical_hash(&provider) else {
            panic!("first digest should succeed");
        };

        let Ok(second) = record("esmeralda", 0x11, 0x22).canonical_hash(&provider) else {
            panic!("second digest should succeed");
        };

        assert_eq!(first, second);
    }

    #[test]
    fn field_changes_change_the_digest() {
        let provider = Blake3HashProviderV1;

        let Ok(base) = record("esmeralda", 0x11, 0x22).canonical_hash(&provider) else {
            panic!("base digest should succeed");
        };

        let Ok(changed_network) = record("igor", 0x11, 0x22).canonical_hash(&provider) else {
            panic!("changed-network digest should succeed");
        };

        let Ok(changed_manifest) = record("esmeralda", 0x12, 0x22).canonical_hash(&provider) else {
            panic!("changed-manifest digest should succeed");
        };

        let Ok(changed_archive) = record("esmeralda", 0x11, 0x23).canonical_hash(&provider) else {
            panic!("changed-archive digest should succeed");
        };

        assert_ne!(base, changed_network);
        assert_ne!(base, changed_manifest);
        assert_ne!(base, changed_archive);
    }

    #[test]
    fn non_production_provider_is_rejected() {
        assert!(matches!(
            record("esmeralda", 0x11, 0x22).canonical_hash(&OtherHasher),
            Err(error) if error.code() == ValidationCode::UnsupportedHashAlgorithm
        ));
    }

    #[test]
    fn verify_hash_accepts_matching_and_rejects_mismatched_digests() {
        let provider = Blake3HashProviderV1;
        let record = record("esmeralda", 0x11, 0x22);

        let Ok(digest) = record.canonical_hash(&provider) else {
            panic!("digest should succeed");
        };

        assert!(record.verify_hash(&provider, digest).is_ok());

        assert!(matches!(
            record.verify_hash(&provider, OotleAnchorRecordHashV1::new([0x00; 32])),
            Err(error) if error.code() == ValidationCode::ArchiveManifestHashMismatch
        ));
    }
}
