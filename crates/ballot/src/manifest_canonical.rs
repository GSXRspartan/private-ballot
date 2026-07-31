//! Canonical election-manifest serialization and hashing.

use tari_cc_private_ballot_protocol::{
    CandidateSetCommitment, CanonicalCborReader, CanonicalCborWriter, HashDomain, HashProvider,
    MAX_CANONICAL_OBJECT_BYTES, ManifestHash, ProtocolError, RegistryCommitment, ValidationCode,
    hash_domain_separated,
};

use crate::{
    ApprovalLimits, BallotConfidentialityV1, BallotKindV1, ElectionId, ElectionManifestV1,
    ElectionManifestV1Input,
};

const MANIFEST_FIELD_COUNT_V1: usize = 9;
const APPROVAL_LIMIT_FIELD_COUNT_V1: usize = 3;

fn invalid_cbor(message: &'static str) -> ProtocolError {
    ProtocolError::new(ValidationCode::InvalidCbor, message)
}

fn read_commitment(
    reader: &mut CanonicalCborReader<'_>,
    message: &'static str,
) -> Result<[u8; 32], ProtocolError> {
    let bytes = reader.read_byte_string()?;

    <[u8; 32]>::try_from(bytes).map_err(|_| invalid_cbor(message))
}

impl ElectionManifestV1 {
    /// Encodes the complete frozen manifest using canonical CBOR.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut writer = CanonicalCborWriter::new();

        writer.write_array_len(MANIFEST_FIELD_COUNT_V1)?;
        writer.write_unsigned(u64::from(self.protocol_version()));
        writer.write_byte_string(self.election_id().as_bytes())?;
        writer.write_text_string(self.ballot_kind().as_str())?;
        writer.write_text_string(self.ballot_confidentiality().as_str())?;
        writer.write_byte_string(self.registry_commitment().as_bytes())?;
        writer.write_byte_string(self.candidate_set_commitment().as_bytes())?;
        writer.write_text_string(self.proof_suite_id())?;

        writer.write_array_len(APPROVAL_LIMIT_FIELD_COUNT_V1)?;
        writer.write_unsigned(
            u64::try_from(self.approval_limits().minimum()).map_err(|_| {
                ProtocolError::new(
                    ValidationCode::ProtocolLimitExceeded,
                    "minimum approval count exceeds the encoding limit",
                )
            })?,
        );
        writer.write_unsigned(
            u64::try_from(self.approval_limits().maximum()).map_err(|_| {
                ProtocolError::new(
                    ValidationCode::ProtocolLimitExceeded,
                    "maximum approval count exceeds the encoding limit",
                )
            })?,
        );
        writer.write_bool(self.approval_limits().allow_abstention());

        writer.write_text_string(self.governance_source_revision())?;

        let encoded = writer.into_bytes();

        if encoded.len() > MAX_CANONICAL_OBJECT_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "canonical manifest exceeds the protocol object limit",
            ));
        }

        Ok(encoded)
    }

    /// Strictly decodes and validates one version-one manifest.
    pub fn from_canonical_cbor(encoded: &[u8]) -> Result<Self, ProtocolError> {
        if encoded.len() > MAX_CANONICAL_OBJECT_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "encoded manifest exceeds the protocol object limit",
            ));
        }

        let mut reader = CanonicalCborReader::new(encoded);

        if reader.read_array_len()? != MANIFEST_FIELD_COUNT_V1 {
            return Err(invalid_cbor(
                "version-one manifest must contain exactly nine fields",
            ));
        }

        let protocol_version = u16::try_from(reader.read_unsigned()?)
            .map_err(|_| invalid_cbor("protocol version does not fit in u16"))?;

        let election_id = ElectionId::new(reader.read_byte_string()?.to_vec())?;

        let ballot_kind = BallotKindV1::from_identifier(reader.read_text_string()?)?;

        let ballot_confidentiality =
            BallotConfidentialityV1::from_identifier(reader.read_text_string()?)?;

        let registry_commitment = RegistryCommitment::new(read_commitment(
            &mut reader,
            "registry commitment must contain exactly 32 bytes",
        )?);

        let candidate_set_commitment = CandidateSetCommitment::new(read_commitment(
            &mut reader,
            "candidate-set commitment must contain exactly 32 bytes",
        )?);

        let proof_suite_id = reader.read_text_string()?.to_owned();

        if reader.read_array_len()? != APPROVAL_LIMIT_FIELD_COUNT_V1 {
            return Err(invalid_cbor(
                "approval limits must contain exactly three fields",
            ));
        }

        let minimum_selections = usize::try_from(reader.read_unsigned()?)
            .map_err(|_| invalid_cbor("minimum approval count is too large"))?;

        let maximum_selections = usize::try_from(reader.read_unsigned()?)
            .map_err(|_| invalid_cbor("maximum approval count is too large"))?;

        let allow_abstention = reader.read_bool()?;

        let approval_limits =
            ApprovalLimits::new(minimum_selections, maximum_selections, allow_abstention)?;

        let governance_source_revision = reader.read_text_string()?.to_owned();

        reader.finish()?;

        Self::new(ElectionManifestV1Input {
            protocol_version,
            election_id,
            ballot_kind,
            ballot_confidentiality,
            registry_commitment,
            candidate_set_commitment,
            proof_suite_id,
            approval_limits,
            governance_source_revision,
        })
    }

    /// Derives the canonical manifest hash.
    pub fn canonical_hash<H: HashProvider>(
        &self,
        provider: &H,
    ) -> Result<ManifestHash, ProtocolError> {
        let encoded = self.to_canonical_cbor()?;
        let digest = hash_domain_separated(provider, HashDomain::ElectionManifestV1, &encoded);

        Ok(ManifestHash::new(digest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tari_cc_private_ballot_protocol::{
        MAX_CANONICAL_OBJECT_BYTES, PROTOCOL_VERSION_V1, ValidationCode,
        test_only::TestOnlyDeterministicHasher,
    };

    fn election_id(value: &[u8]) -> ElectionId {
        let Ok(id) = ElectionId::new(value.to_vec()) else {
            panic!("test election ID must be valid");
        };

        id
    }

    fn approval_limits(minimum: usize, maximum: usize, allow_abstention: bool) -> ApprovalLimits {
        let Ok(limits) = ApprovalLimits::new(minimum, maximum, allow_abstention) else {
            panic!("test approval limits must be valid");
        };

        limits
    }

    fn simple_input() -> ElectionManifestV1Input {
        ElectionManifestV1Input {
            protocol_version: PROTOCOL_VERSION_V1,
            election_id: election_id(b"e"),
            ballot_kind: BallotKindV1::NonBindingApprovalPilot,
            ballot_confidentiality: BallotConfidentialityV1::Public,
            registry_commitment: RegistryCommitment::new([1_u8; 32]),
            candidate_set_commitment: CandidateSetCommitment::new([2_u8; 32]),
            proof_suite_id: "test-suite".to_owned(),
            approval_limits: approval_limits(1, 2, true),
            governance_source_revision: "rev-1".to_owned(),
        }
    }

    fn simple_manifest() -> ElectionManifestV1 {
        let Ok(manifest) = ElectionManifestV1::new(simple_input()) else {
            panic!("test manifest must be valid");
        };

        manifest
    }

    fn encoded_with_identifiers(
        ballot_kind: &str,
        confidentiality: &str,
        registry_commitment: &[u8],
    ) -> Vec<u8> {
        let mut writer = CanonicalCborWriter::new();

        assert!(writer.write_array_len(MANIFEST_FIELD_COUNT_V1).is_ok());
        writer.write_unsigned(u64::from(PROTOCOL_VERSION_V1));
        assert!(writer.write_byte_string(b"e").is_ok());
        assert!(writer.write_text_string(ballot_kind).is_ok());
        assert!(writer.write_text_string(confidentiality).is_ok());
        assert!(writer.write_byte_string(registry_commitment).is_ok());
        assert!(writer.write_byte_string(&[2_u8; 32]).is_ok());
        assert!(writer.write_text_string("test-suite").is_ok());
        assert!(
            writer
                .write_array_len(APPROVAL_LIMIT_FIELD_COUNT_V1)
                .is_ok()
        );
        writer.write_unsigned(1);
        writer.write_unsigned(2);
        writer.write_bool(true);
        assert!(writer.write_text_string("rev-1").is_ok());

        writer.into_bytes()
    }

    #[test]
    fn manifest_cbor_vector_is_exact() {
        let manifest = simple_manifest();

        let Ok(encoded) = manifest.to_canonical_cbor() else {
            panic!("manifest encoding should succeed");
        };

        let mut expected = vec![
            0x89, 0x01, 0x41, b'e', 0x78, 0x1a, b'N', b'O', b'N', b'_', b'B', b'I', b'N', b'D',
            b'I', b'N', b'G', b'_', b'A', b'P', b'P', b'R', b'O', b'V', b'A', b'L', b'_', b'P',
            b'I', b'L', b'O', b'T', 0x66, b'P', b'U', b'B', b'L', b'I', b'C', 0x58, 0x20,
        ];

        expected.extend_from_slice(&[1_u8; 32]);
        expected.extend_from_slice(&[0x58, 0x20]);
        expected.extend_from_slice(&[2_u8; 32]);
        expected.extend_from_slice(&[
            0x6a, b't', b'e', b's', b't', b'-', b's', b'u', b'i', b't', b'e', 0x83, 0x01, 0x02,
            0xf5, 0x65, b'r', b'e', b'v', b'-', b'1',
        ]);

        assert_eq!(encoded, expected);
    }

    #[test]
    fn manifest_round_trip_preserves_exact_bytes() {
        let manifest = simple_manifest();

        let Ok(encoded) = manifest.to_canonical_cbor() else {
            panic!("manifest encoding should succeed");
        };

        let Ok(decoded) = ElectionManifestV1::from_canonical_cbor(&encoded) else {
            panic!("manifest decoding should succeed");
        };

        let Ok(reencoded) = decoded.to_canonical_cbor() else {
            panic!("manifest re-encoding should succeed");
        };

        assert_eq!(decoded, manifest);
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn identical_manifest_hashes_are_deterministic() {
        let manifest = simple_manifest();
        let provider = TestOnlyDeterministicHasher;

        let Ok(first) = manifest.canonical_hash(&provider) else {
            panic!("first manifest hash should succeed");
        };

        let Ok(second) = manifest.canonical_hash(&provider) else {
            panic!("second manifest hash should succeed");
        };

        assert_eq!(first, second);
    }

    #[test]
    fn semantic_manifest_changes_change_the_hash() {
        let provider = TestOnlyDeterministicHasher;
        let base_manifest = simple_manifest();

        let Ok(base_hash) = base_manifest.canonical_hash(&provider) else {
            panic!("base manifest hash should succeed");
        };

        let mut variants = Vec::new();

        let mut changed_election = simple_input();
        changed_election.election_id = election_id(b"other-election");
        variants.push(changed_election);

        let mut changed_registry = simple_input();
        changed_registry.registry_commitment = RegistryCommitment::new([3_u8; 32]);
        variants.push(changed_registry);

        let mut changed_candidates = simple_input();
        changed_candidates.candidate_set_commitment = CandidateSetCommitment::new([4_u8; 32]);
        variants.push(changed_candidates);

        let mut changed_suite = simple_input();
        changed_suite.proof_suite_id = "other-suite".to_owned();
        variants.push(changed_suite);

        let mut changed_limits = simple_input();
        changed_limits.approval_limits = approval_limits(0, 1, true);
        variants.push(changed_limits);

        let mut changed_revision = simple_input();
        changed_revision.governance_source_revision = "rev-2".to_owned();
        variants.push(changed_revision);

        for input in variants {
            let Ok(manifest) = ElectionManifestV1::new(input) else {
                panic!("changed test manifest must remain valid");
            };

            let Ok(hash) = manifest.canonical_hash(&provider) else {
                panic!("changed manifest hash should succeed");
            };

            assert_ne!(hash, base_hash);
        }
    }

    #[test]
    fn unknown_ballot_kind_is_rejected() {
        let encoded = encoded_with_identifiers("UNKNOWN_BALLOT_KIND", "PUBLIC", &[1_u8; 32]);

        let result = ElectionManifestV1::from_canonical_cbor(&encoded);

        assert!(matches!(
            result,
            Err(error) if error.code() == ValidationCode::InvalidData
        ));
    }

    #[test]
    fn unknown_confidentiality_mode_is_rejected() {
        let encoded = encoded_with_identifiers(
            "NON_BINDING_APPROVAL_PILOT",
            "SEALED_BUT_NOT_REALLY",
            &[1_u8; 32],
        );

        let result = ElectionManifestV1::from_canonical_cbor(&encoded);

        assert!(matches!(
            result,
            Err(error) if error.code() == ValidationCode::InvalidData
        ));
    }

    #[test]
    fn malformed_commitment_length_is_rejected() {
        let encoded = encoded_with_identifiers("NON_BINDING_APPROVAL_PILOT", "PUBLIC", &[1_u8; 31]);

        let result = ElectionManifestV1::from_canonical_cbor(&encoded);

        assert!(matches!(
            result,
            Err(error) if error.code() == ValidationCode::InvalidCbor
        ));
    }

    #[test]
    fn wrong_manifest_field_count_is_rejected() {
        let mut writer = CanonicalCborWriter::new();

        assert!(writer.write_array_len(8).is_ok());

        let result = ElectionManifestV1::from_canonical_cbor(&writer.into_bytes());

        assert!(matches!(
            result,
            Err(error) if error.code() == ValidationCode::InvalidCbor
        ));
    }

    #[test]
    fn oversized_encoded_manifest_is_rejected() {
        let encoded = vec![0_u8; MAX_CANONICAL_OBJECT_BYTES + 1];
        let result = ElectionManifestV1::from_canonical_cbor(&encoded);

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::ProtocolLimitExceeded
        ));
    }
}
