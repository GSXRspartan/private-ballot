//! Versioned Ootle anchor-record model and bounded network identifier.

use tari_cc_private_ballot_archive::ArchiveHashV1;
use tari_cc_private_ballot_protocol::{
    BLAKE3_256_HASH_ALGORITHM_ID_V1, HashProvider, ManifestHash, ProtocolError, ValidationCode,
};

/// Stable record-type and version identifier for a version-one anchor record.
///
/// The identifier both marks the object as this project's Ootle anchor record
/// and pins its version, so it cannot be confused with an unrelated ledger log
/// line or with a future anchor-record version.
pub const OOTLE_ANCHOR_RECORD_TYPE_ID_V1: &str = "TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V1";

/// Stable purpose identifier for a completed-election archive commitment.
///
/// The purpose is a fixed protocol constant rather than caller-supplied text.
/// This structurally prevents the record from carrying prose, titles, or any
/// arbitrary memo content, and makes the harmless, non-binding pilot scope
/// legible directly from the ledger.
pub const OOTLE_ANCHOR_PURPOSE_ID_V1: &str = "NON_BINDING_APPROVAL_PILOT_ARCHIVE_ANCHOR";

/// Maximum UTF-8 byte length of one bounded Ootle network identifier.
pub const MAX_OOTLE_NETWORK_ID_BYTES: usize = 32;

/// Maximum canonical encoded size of one version-one anchor record.
///
/// The largest well-formed record (a maximum-length network identifier) encodes
/// to exactly 224 bytes, so this bound leaves comfortable headroom while staying
/// far below the locally confirmed Ootle `EmitLog` budget of 32 KiB.
pub const MAX_OOTLE_ANCHOR_RECORD_BYTES: usize = 512;

/// Number of canonical fields in a version-one anchor record.
pub const OOTLE_ANCHOR_RECORD_FIELD_COUNT_V1: usize = 6;

/// Bounded canonical identifier for the intended Ootle network.
///
/// The identifier is a non-empty, length-bounded string restricted to ASCII
/// letters, digits, `-`, and `_`. The bound and restricted character set keep
/// the only free-form field small and prevent it from carrying binary secrets
/// or whitespace that could cause cross-network receipt confusion.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OotleNetworkIdV1(String);

impl OotleNetworkIdV1 {
    /// Validates and freezes one bounded network identifier.
    pub fn new(value: String) -> Result<Self, ProtocolError> {
        if value.is_empty() {
            return Err(ProtocolError::new(
                ValidationCode::InvalidData,
                "ootle network identifier must not be empty",
            ));
        }

        if value.len() > MAX_OOTLE_NETWORK_ID_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "ootle network identifier exceeds the anchor size limit",
            ));
        }

        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(ProtocolError::new(
                ValidationCode::InvalidData,
                "ootle network identifier contains an unsupported character",
            ));
        }

        Ok(Self(value))
    }

    /// Returns the validated network identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Frozen version-one Ootle anchor record.
///
/// The record binds exactly three caller-supplied values: the intended network,
/// the frozen election-manifest hash, and the completed archive hash. The
/// record type, hash-algorithm identifier, and purpose are fixed protocol
/// constants and are therefore not stored as mutable fields. This leaves no
/// field capable of carrying a ballot, proof, nullifier, registry key, voter
/// identifier, tally value, or arbitrary memo text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OotleAnchorRecordV1 {
    network: OotleNetworkIdV1,
    election_manifest_hash: ManifestHash,
    archive_hash: ArchiveHashV1,
}

impl OotleAnchorRecordV1 {
    /// Creates one version-one anchor record from already-frozen commitments.
    ///
    /// Every input is a pre-validated protocol or archive value, so this
    /// constructor cannot fail. The hash-algorithm identifier is fixed to the
    /// production identifier and is never caller-supplied.
    #[must_use]
    pub const fn new(
        network: OotleNetworkIdV1,
        election_manifest_hash: ManifestHash,
        archive_hash: ArchiveHashV1,
    ) -> Self {
        Self {
            network,
            election_manifest_hash,
            archive_hash,
        }
    }

    /// Creates a record after confirming the provider is the production suite.
    ///
    /// This rejects the test-only deterministic hash provider (and any other
    /// non-production provider), so a completed archive hashed with a test-only
    /// provider cannot be wrapped in a production anchor record.
    pub fn for_provider<H: HashProvider>(
        network: OotleNetworkIdV1,
        election_manifest_hash: ManifestHash,
        archive_hash: ArchiveHashV1,
        provider: &H,
    ) -> Result<Self, ProtocolError> {
        if provider.algorithm_id() != BLAKE3_256_HASH_ALGORITHM_ID_V1 {
            return Err(ProtocolError::new(
                ValidationCode::UnsupportedHashAlgorithm,
                "ootle anchor records require the production hash provider",
            ));
        }

        Ok(Self::new(network, election_manifest_hash, archive_hash))
    }

    /// Returns the fixed record-type and version identifier.
    #[must_use]
    pub const fn record_type_id(&self) -> &'static str {
        OOTLE_ANCHOR_RECORD_TYPE_ID_V1
    }

    /// Returns the bounded intended-network identifier.
    #[must_use]
    pub const fn network(&self) -> &OotleNetworkIdV1 {
        &self.network
    }

    /// Returns the frozen election-manifest hash identifying the election.
    #[must_use]
    pub const fn election_manifest_hash(&self) -> ManifestHash {
        self.election_manifest_hash
    }

    /// Returns the completed archive hash being anchored.
    #[must_use]
    pub const fn archive_hash(&self) -> ArchiveHashV1 {
        self.archive_hash
    }

    /// Returns the fixed production hash-algorithm identifier.
    #[must_use]
    pub const fn hash_algorithm_id(&self) -> &'static str {
        BLAKE3_256_HASH_ALGORITHM_ID_V1
    }

    /// Returns the fixed non-binding pilot purpose identifier.
    #[must_use]
    pub const fn purpose_id(&self) -> &'static str {
        OOTLE_ANCHOR_PURPOSE_ID_V1
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_OOTLE_NETWORK_ID_BYTES, OotleNetworkIdV1};
    use tari_cc_private_ballot_protocol::ValidationCode;

    #[test]
    fn valid_network_identifiers_are_accepted() {
        for value in ["esmeralda", "igor", "localnet", "next-net", "test_net-1"] {
            let Ok(network) = OotleNetworkIdV1::new(value.to_owned()) else {
                panic!("network identifier should be valid");
            };

            assert_eq!(network.as_str(), value);
        }
    }

    #[test]
    fn empty_network_identifier_is_rejected() {
        assert!(matches!(
            OotleNetworkIdV1::new(String::new()),
            Err(error) if error.code() == ValidationCode::InvalidData
        ));
    }

    #[test]
    fn maximum_length_network_identifier_is_accepted() {
        let value = "n".repeat(MAX_OOTLE_NETWORK_ID_BYTES);

        let Ok(network) = OotleNetworkIdV1::new(value.clone()) else {
            panic!("maximum-length identifier should be valid");
        };

        assert_eq!(network.as_str().len(), MAX_OOTLE_NETWORK_ID_BYTES);
    }

    #[test]
    fn oversized_network_identifier_is_rejected() {
        let value = "n".repeat(MAX_OOTLE_NETWORK_ID_BYTES + 1);

        assert!(matches!(
            OotleNetworkIdV1::new(value),
            Err(error) if error.code() == ValidationCode::ProtocolLimitExceeded
        ));
    }

    #[test]
    fn network_identifier_rejects_whitespace_and_control_characters() {
        for value in ["esmer alda", "igor\n", " localnet", "net\0"] {
            assert!(matches!(
                OotleNetworkIdV1::new(value.to_owned()),
                Err(error) if error.code() == ValidationCode::InvalidData
            ));
        }
    }

    #[test]
    fn network_identifier_rejects_non_ascii_bytes() {
        assert!(matches!(
            OotleNetworkIdV1::new("esmeraldá".to_owned()),
            Err(error) if error.code() == ValidationCode::InvalidData
        ));
    }
}
