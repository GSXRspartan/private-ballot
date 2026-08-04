//! Canonical serialization and strict decoding for the anchor record.

use tari_cc_private_ballot_archive::ArchiveHashV1;
use tari_cc_private_ballot_protocol::{
    BLAKE3_256_HASH_ALGORITHM_ID_V1, CanonicalCborReader, CanonicalCborWriter, ManifestHash,
    ProtocolError, ValidationCode,
};

use crate::record::{
    MAX_OOTLE_ANCHOR_RECORD_BYTES, OOTLE_ANCHOR_PURPOSE_ID_V1, OOTLE_ANCHOR_RECORD_FIELD_COUNT_V1,
    OOTLE_ANCHOR_RECORD_TYPE_ID_V1, OotleAnchorRecordV1, OotleNetworkIdV1,
};

fn invalid_cbor(message: &'static str) -> ProtocolError {
    ProtocolError::new(ValidationCode::InvalidCbor, message)
}

fn read_digest(
    reader: &mut CanonicalCborReader<'_>,
    message: &'static str,
) -> Result<[u8; 32], ProtocolError> {
    <[u8; 32]>::try_from(reader.read_byte_string()?).map_err(|_| invalid_cbor(message))
}

impl OotleAnchorRecordV1 {
    /// Encodes the complete anchor record using canonical CBOR.
    ///
    /// The encoding is a fixed six-element definite-length array in fixed field
    /// order. The record-type, hash-algorithm, and purpose fields are always
    /// written as their fixed protocol constants.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut writer = CanonicalCborWriter::new();

        writer.write_array_len(OOTLE_ANCHOR_RECORD_FIELD_COUNT_V1)?;
        writer.write_text_string(OOTLE_ANCHOR_RECORD_TYPE_ID_V1)?;
        writer.write_text_string(self.network().as_str())?;
        writer.write_byte_string(self.election_manifest_hash().as_bytes())?;
        writer.write_byte_string(self.archive_hash().as_bytes())?;
        writer.write_text_string(BLAKE3_256_HASH_ALGORITHM_ID_V1)?;
        writer.write_text_string(OOTLE_ANCHOR_PURPOSE_ID_V1)?;

        let encoded = writer.into_bytes();

        if encoded.len() > MAX_OOTLE_ANCHOR_RECORD_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "canonical ootle anchor record exceeds the anchor object limit",
            ));
        }

        Ok(encoded)
    }

    /// Strictly decodes one canonically encoded anchor record.
    ///
    /// The decoder requires the exact field count, the fixed record-type,
    /// hash-algorithm, and purpose constants, exact 32-byte digests, and no
    /// trailing bytes.
    pub fn from_canonical_cbor(encoded: &[u8]) -> Result<Self, ProtocolError> {
        if encoded.len() > MAX_OOTLE_ANCHOR_RECORD_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "encoded ootle anchor record exceeds the anchor object limit",
            ));
        }

        let mut reader = CanonicalCborReader::new(encoded);

        if reader.read_array_len()? != OOTLE_ANCHOR_RECORD_FIELD_COUNT_V1 {
            return Err(invalid_cbor(
                "ootle anchor record must contain exactly six fields",
            ));
        }

        if reader.read_text_string()? != OOTLE_ANCHOR_RECORD_TYPE_ID_V1 {
            return Err(ProtocolError::new(
                ValidationCode::UnsupportedProtocolVersion,
                "unsupported ootle anchor record type or version",
            ));
        }

        let network = OotleNetworkIdV1::new(reader.read_text_string()?.to_owned())?;

        let election_manifest_hash = ManifestHash::new(read_digest(
            &mut reader,
            "election manifest hash must contain exactly 32 bytes",
        )?);

        let archive_hash = ArchiveHashV1::new(read_digest(
            &mut reader,
            "archive hash must contain exactly 32 bytes",
        )?);

        if reader.read_text_string()? != BLAKE3_256_HASH_ALGORITHM_ID_V1 {
            return Err(ProtocolError::new(
                ValidationCode::UnsupportedHashAlgorithm,
                "ootle anchor record does not use the production hash algorithm",
            ));
        }

        if reader.read_text_string()? != OOTLE_ANCHOR_PURPOSE_ID_V1 {
            return Err(ProtocolError::new(
                ValidationCode::InvalidData,
                "unsupported ootle anchor purpose identifier",
            ));
        }

        reader.finish()?;

        Ok(Self::new(network, election_manifest_hash, archive_hash))
    }
}

#[cfg(test)]
mod tests {
    use tari_cc_private_ballot_archive::ArchiveHashV1;
    use tari_cc_private_ballot_protocol::{
        BLAKE3_256_HASH_ALGORITHM_ID_V1, CanonicalCborWriter, MAX_CANONICAL_OBJECT_BYTES,
        ManifestHash, ValidationCode,
    };

    use crate::record::{
        MAX_OOTLE_ANCHOR_RECORD_BYTES, MAX_OOTLE_NETWORK_ID_BYTES, OOTLE_ANCHOR_PURPOSE_ID_V1,
        OOTLE_ANCHOR_RECORD_TYPE_ID_V1, OotleAnchorRecordV1, OotleNetworkIdV1,
    };

    const TEST_ONLY_HASH_ALGORITHM_ID: &str = "TEST_ONLY_DETERMINISTIC_HASH_NOT_CRYPTOGRAPHIC";

    fn network(value: &str) -> OotleNetworkIdV1 {
        let Ok(network) = OotleNetworkIdV1::new(value.to_owned()) else {
            panic!("test network identifier must be valid");
        };

        network
    }

    fn record(network_value: &str, manifest_byte: u8, archive_byte: u8) -> OotleAnchorRecordV1 {
        OotleAnchorRecordV1::new(
            network(network_value),
            ManifestHash::new([manifest_byte; 32]),
            ArchiveHashV1::new([archive_byte; 32]),
        )
    }

    /// Rebuilds the exact canonical encoding independently of the encoder so the
    /// decoder tests exercise crafted byte sequences with substituted fields.
    fn encode_fields(
        record_type: &str,
        network_value: &str,
        manifest_hash: &[u8],
        archive_hash: &[u8],
        hash_algorithm_id: &str,
        purpose: &str,
    ) -> Vec<u8> {
        let mut writer = CanonicalCborWriter::new();

        assert!(writer.write_array_len(6).is_ok());
        assert!(writer.write_text_string(record_type).is_ok());
        assert!(writer.write_text_string(network_value).is_ok());
        assert!(writer.write_byte_string(manifest_hash).is_ok());
        assert!(writer.write_byte_string(archive_hash).is_ok());
        assert!(writer.write_text_string(hash_algorithm_id).is_ok());
        assert!(writer.write_text_string(purpose).is_ok());

        writer.into_bytes()
    }

    fn valid_encoding() -> Vec<u8> {
        encode_fields(
            OOTLE_ANCHOR_RECORD_TYPE_ID_V1,
            "esmeralda",
            &[0x11; 32],
            &[0x22; 32],
            BLAKE3_256_HASH_ALGORITHM_ID_V1,
            OOTLE_ANCHOR_PURPOSE_ID_V1,
        )
    }

    #[test]
    fn canonical_record_vector_is_exact() {
        let Ok(encoded) = record("esmeralda", 0x11, 0x22).to_canonical_cbor() else {
            panic!("anchor record encoding should succeed");
        };

        let mut expected = vec![0x86, 0x78, 0x26];
        expected.extend_from_slice(OOTLE_ANCHOR_RECORD_TYPE_ID_V1.as_bytes());
        expected.extend_from_slice(&[0x69]);
        expected.extend_from_slice(b"esmeralda");
        expected.extend_from_slice(&[0x58, 0x20]);
        expected.extend_from_slice(&[0x11; 32]);
        expected.extend_from_slice(&[0x58, 0x20]);
        expected.extend_from_slice(&[0x22; 32]);
        expected.extend_from_slice(&[0x78, 0x24]);
        expected.extend_from_slice(BLAKE3_256_HASH_ALGORITHM_ID_V1.as_bytes());
        expected.extend_from_slice(&[0x78, 0x29]);
        expected.extend_from_slice(OOTLE_ANCHOR_PURPOSE_ID_V1.as_bytes());

        assert_eq!(encoded, expected);
        assert_eq!(encoded, valid_encoding());
    }

    #[test]
    fn record_round_trip_preserves_exact_bytes() {
        let original = record("igor", 0x33, 0x44);

        let Ok(encoded) = original.to_canonical_cbor() else {
            panic!("anchor record encoding should succeed");
        };

        let Ok(decoded) = OotleAnchorRecordV1::from_canonical_cbor(&encoded) else {
            panic!("anchor record decoding should succeed");
        };

        let Ok(reencoded) = decoded.to_canonical_cbor() else {
            panic!("anchor record re-encoding should succeed");
        };

        assert_eq!(decoded, original);
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn expected_and_maximum_sizes_are_bounded() {
        let Ok(typical) = record("esmeralda", 0x11, 0x22).to_canonical_cbor() else {
            panic!("typical encoding should succeed");
        };

        let widest = "n".repeat(MAX_OOTLE_NETWORK_ID_BYTES);
        let Ok(widest_record) = OotleNetworkIdV1::new(widest).map(|network| {
            OotleAnchorRecordV1::new(
                network,
                ManifestHash::new([0x11; 32]),
                ArchiveHashV1::new([0x22; 32]),
            )
        }) else {
            panic!("widest network identifier must be valid");
        };

        let Ok(widest_encoding) = widest_record.to_canonical_cbor() else {
            panic!("widest encoding should succeed");
        };

        assert_eq!(typical.len(), 200);
        assert_eq!(widest_encoding.len(), 224);
        assert!(widest_encoding.len() <= MAX_OOTLE_ANCHOR_RECORD_BYTES);
        const {
            assert!(MAX_OOTLE_ANCHOR_RECORD_BYTES < MAX_CANONICAL_OBJECT_BYTES);
        }
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut encoded = valid_encoding();
        encoded.push(0x00);

        assert!(matches!(
            OotleAnchorRecordV1::from_canonical_cbor(&encoded),
            Err(error) if error.code() == ValidationCode::TrailingCborData
        ));
    }

    #[test]
    fn truncated_input_is_rejected() {
        let encoded = valid_encoding();
        let truncated = &encoded[..encoded.len() - 1];

        assert!(matches!(
            OotleAnchorRecordV1::from_canonical_cbor(truncated),
            Err(error) if error.code() == ValidationCode::InvalidCbor
        ));
    }

    #[test]
    fn wrong_field_count_is_rejected() {
        let mut writer = CanonicalCborWriter::new();
        assert!(writer.write_array_len(5).is_ok());

        assert!(matches!(
            OotleAnchorRecordV1::from_canonical_cbor(&writer.into_bytes()),
            Err(error) if error.code() == ValidationCode::InvalidCbor
        ));
    }

    #[test]
    fn wrong_record_type_is_rejected_as_unsupported_version() {
        let encoded = encode_fields(
            "TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2",
            "esmeralda",
            &[0x11; 32],
            &[0x22; 32],
            BLAKE3_256_HASH_ALGORITHM_ID_V1,
            OOTLE_ANCHOR_PURPOSE_ID_V1,
        );

        assert!(matches!(
            OotleAnchorRecordV1::from_canonical_cbor(&encoded),
            Err(error) if error.code() == ValidationCode::UnsupportedProtocolVersion
        ));
    }

    #[test]
    fn test_only_hash_identifier_is_rejected() {
        let encoded = encode_fields(
            OOTLE_ANCHOR_RECORD_TYPE_ID_V1,
            "esmeralda",
            &[0x11; 32],
            &[0x22; 32],
            TEST_ONLY_HASH_ALGORITHM_ID,
            OOTLE_ANCHOR_PURPOSE_ID_V1,
        );

        assert!(matches!(
            OotleAnchorRecordV1::from_canonical_cbor(&encoded),
            Err(error) if error.code() == ValidationCode::UnsupportedHashAlgorithm
        ));
    }

    #[test]
    fn unsupported_purpose_is_rejected() {
        let encoded = encode_fields(
            OOTLE_ANCHOR_RECORD_TYPE_ID_V1,
            "esmeralda",
            &[0x11; 32],
            &[0x22; 32],
            BLAKE3_256_HASH_ALGORITHM_ID_V1,
            "ARBITRARY_MEMO",
        );

        assert!(matches!(
            OotleAnchorRecordV1::from_canonical_cbor(&encoded),
            Err(error) if error.code() == ValidationCode::InvalidData
        ));
    }

    #[test]
    fn malformed_manifest_hash_length_is_rejected() {
        let encoded = encode_fields(
            OOTLE_ANCHOR_RECORD_TYPE_ID_V1,
            "esmeralda",
            &[0x11; 31],
            &[0x22; 32],
            BLAKE3_256_HASH_ALGORITHM_ID_V1,
            OOTLE_ANCHOR_PURPOSE_ID_V1,
        );

        assert!(matches!(
            OotleAnchorRecordV1::from_canonical_cbor(&encoded),
            Err(error) if error.code() == ValidationCode::InvalidCbor
        ));
    }

    #[test]
    fn malformed_archive_hash_length_is_rejected() {
        let encoded = encode_fields(
            OOTLE_ANCHOR_RECORD_TYPE_ID_V1,
            "esmeralda",
            &[0x11; 32],
            &[0x22; 33],
            BLAKE3_256_HASH_ALGORITHM_ID_V1,
            OOTLE_ANCHOR_PURPOSE_ID_V1,
        );

        assert!(matches!(
            OotleAnchorRecordV1::from_canonical_cbor(&encoded),
            Err(error) if error.code() == ValidationCode::InvalidCbor
        ));
    }

    #[test]
    fn wrong_field_type_is_rejected() {
        // Field zero (record type) encoded as an unsigned integer instead of text.
        let mut writer = CanonicalCborWriter::new();
        assert!(writer.write_array_len(6).is_ok());
        writer.write_unsigned(1);

        assert!(matches!(
            OotleAnchorRecordV1::from_canonical_cbor(&writer.into_bytes()),
            Err(error) if error.code() == ValidationCode::UnexpectedCborType
        ));
    }

    #[test]
    fn noncanonical_array_length_is_rejected() {
        // Array header for six elements written with a non-shortest length.
        let mut encoded = vec![0x98, 0x06];
        encoded.extend_from_slice(&valid_encoding()[1..]);

        assert!(matches!(
            OotleAnchorRecordV1::from_canonical_cbor(&encoded),
            Err(error) if error.code() == ValidationCode::NonCanonicalCbor
        ));
    }

    #[test]
    fn empty_network_identifier_in_bytes_is_rejected() {
        let encoded = encode_fields(
            OOTLE_ANCHOR_RECORD_TYPE_ID_V1,
            "",
            &[0x11; 32],
            &[0x22; 32],
            BLAKE3_256_HASH_ALGORITHM_ID_V1,
            OOTLE_ANCHOR_PURPOSE_ID_V1,
        );

        assert!(matches!(
            OotleAnchorRecordV1::from_canonical_cbor(&encoded),
            Err(error) if error.code() == ValidationCode::InvalidData
        ));
    }

    #[test]
    fn oversized_encoded_record_is_rejected() {
        let encoded = vec![0_u8; MAX_OOTLE_ANCHOR_RECORD_BYTES + 1];

        assert!(matches!(
            OotleAnchorRecordV1::from_canonical_cbor(&encoded),
            Err(error) if error.code() == ValidationCode::ProtocolLimitExceeded
        ));
    }
}
