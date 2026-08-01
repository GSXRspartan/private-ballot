//! Versioned ballot package, canonical persistence, and manifest-binding checks.

use tari_cc_private_ballot_protocol::{
    CanonicalCborReader, CanonicalCborWriter, HashDomain, HashProvider, MAX_CANONICAL_OBJECT_BYTES,
    MAX_PROOF_BYTES, MAX_PROOF_SUITE_ID_BYTES, ManifestHash, PROTOCOL_VERSION_V1, ProtocolError,
    ValidationCode, hash_domain_separated,
};

use crate::{ApprovalBallotPayload, ApprovalLimits, CandidateSet};

/// Number of fields in the closed version-one ballot-package schema.
const BALLOT_PACKAGE_V1_FIELD_COUNT: usize = 5;

/// Unvalidated fields used to construct a version-one ballot package.
///
/// Duplicate-detection material is deliberately absent. A nullifier or
/// key image becomes authoritative only after successful proof verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BallotPackageV1Input {
    pub protocol_version: u16,
    pub manifest_hash: ManifestHash,
    pub proof_suite_id: String,
    pub proof: Vec<u8>,
    pub payload: ApprovalBallotPayload,
}

/// Version-one proof-bearing ballot transport object.
///
/// The canonical CBOR schema is a closed five-field array:
///
/// 1. protocol version as an unsigned integer;
/// 2. raw 32-byte election-manifest hash;
/// 3. proof-suite identifier as UTF-8 text;
/// 4. canonical approval-payload CBOR wrapped in a byte string;
/// 5. proof bytes.
///
/// No nullifier, wallet address, human identity, client metadata, or receipt
/// metadata is present. Duplicate-detection material becomes authoritative
/// only after successful proof verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BallotPackageV1 {
    protocol_version: u16,
    manifest_hash: ManifestHash,
    proof_suite_id: String,
    proof: Vec<u8>,
    payload: ApprovalBallotPayload,
}

impl BallotPackageV1 {
    /// Validates and freezes a version-one ballot package.
    pub fn new(input: BallotPackageV1Input) -> Result<Self, ProtocolError> {
        if input.protocol_version != PROTOCOL_VERSION_V1 {
            return Err(ProtocolError::new(
                ValidationCode::UnsupportedProtocolVersion,
                "ballot package does not use protocol version one",
            ));
        }

        if input.proof_suite_id.trim().is_empty() {
            return Err(ProtocolError::new(
                ValidationCode::EmptyProofSuiteId,
                "proof suite identifier must not be empty",
            ));
        }

        if input.proof_suite_id.len() > MAX_PROOF_SUITE_ID_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "proof suite identifier exceeds the protocol limit",
            ));
        }

        if input.proof.len() > MAX_PROOF_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "proof bytes exceed the protocol limit",
            ));
        }

        Ok(Self {
            protocol_version: input.protocol_version,
            manifest_hash: input.manifest_hash,
            proof_suite_id: input.proof_suite_id,
            proof: input.proof,
            payload: input.payload,
        })
    }

    /// Encodes the complete package as one deterministic CBOR item.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ProtocolError> {
        let payload_bytes = self.payload.to_canonical_cbor()?;
        let mut writer = CanonicalCborWriter::new();

        writer.write_array_len(BALLOT_PACKAGE_V1_FIELD_COUNT)?;
        writer.write_unsigned(u64::from(self.protocol_version));
        writer.write_byte_string(self.manifest_hash.as_bytes())?;
        writer.write_text_string(&self.proof_suite_id)?;
        writer.write_byte_string(&payload_bytes)?;
        writer.write_byte_string(&self.proof)?;

        let encoded = writer.into_bytes();

        if encoded.len() > MAX_CANONICAL_OBJECT_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "canonical ballot package exceeds the protocol object limit",
            ));
        }

        Ok(encoded)
    }

    /// Strictly decodes one canonical version-one ballot package.
    ///
    /// Candidate and approval-limit context remains external because it is
    /// fixed by the election manifest and candidate set, not repeated as
    /// attacker-controlled package metadata.
    pub fn from_canonical_cbor(
        encoded: &[u8],
        candidates: &CandidateSet,
        limits: ApprovalLimits,
    ) -> Result<Self, ProtocolError> {
        if encoded.len() > MAX_CANONICAL_OBJECT_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "encoded ballot package exceeds the protocol object limit",
            ));
        }

        let mut reader = CanonicalCborReader::new(encoded);

        if reader.read_array_len()? != BALLOT_PACKAGE_V1_FIELD_COUNT {
            return Err(ProtocolError::new(
                ValidationCode::InvalidCbor,
                "ballot package must contain exactly five fields",
            ));
        }

        let protocol_version = u16::try_from(reader.read_unsigned()?).map_err(|_| {
            ProtocolError::new(
                ValidationCode::InvalidCbor,
                "ballot package protocol version exceeds the u16 range",
            )
        })?;

        let manifest_hash_bytes = reader.read_byte_string()?;
        let manifest_hash_array: [u8; 32] = manifest_hash_bytes.try_into().map_err(|_| {
            ProtocolError::new(
                ValidationCode::InvalidData,
                "ballot package manifest hash must contain exactly 32 bytes",
            )
        })?;

        let proof_suite_id = reader.read_text_string()?;

        if proof_suite_id.len() > MAX_PROOF_SUITE_ID_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "proof suite identifier exceeds the protocol limit",
            ));
        }

        let payload_bytes = reader.read_byte_string()?;
        let proof_bytes = reader.read_byte_string()?;

        if proof_bytes.len() > MAX_PROOF_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "proof bytes exceed the protocol limit",
            ));
        }

        reader.finish()?;

        let payload =
            ApprovalBallotPayload::from_canonical_cbor(payload_bytes, candidates, limits)?;

        let package = Self::new(BallotPackageV1Input {
            protocol_version,
            manifest_hash: ManifestHash::new(manifest_hash_array),
            proof_suite_id: proof_suite_id.to_owned(),
            proof: proof_bytes.to_vec(),
            payload,
        })?;

        if package.to_canonical_cbor()? != encoded {
            return Err(ProtocolError::new(
                ValidationCode::NonCanonicalCbor,
                "ballot package bytes are not the canonical encoding",
            ));
        }

        Ok(package)
    }

    /// Derives the package hash from its exact canonical CBOR bytes.
    pub fn canonical_hash<H: HashProvider>(&self, provider: &H) -> Result<[u8; 32], ProtocolError> {
        let encoded = self.to_canonical_cbor()?;

        Ok(hash_domain_separated(
            provider,
            HashDomain::BallotPackageV1,
            &encoded,
        ))
    }

    /// Verifies binding to the expected manifest and proof suite.
    pub fn validate_manifest_binding(
        &self,
        expected_manifest_hash: ManifestHash,
        expected_proof_suite_id: &str,
    ) -> Result<(), ProtocolError> {
        if self.manifest_hash != expected_manifest_hash {
            return Err(ProtocolError::new(
                ValidationCode::WrongManifestHash,
                "ballot package is bound to a different election manifest",
            ));
        }

        if self.proof_suite_id != expected_proof_suite_id {
            return Err(ProtocolError::new(
                ValidationCode::UnsupportedProofSuite,
                "ballot proof suite differs from the election manifest",
            ));
        }

        Ok(())
    }

    #[must_use]
    pub const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    #[must_use]
    pub const fn manifest_hash(&self) -> ManifestHash {
        self.manifest_hash
    }

    #[must_use]
    pub fn proof_suite_id(&self) -> &str {
        &self.proof_suite_id
    }

    #[must_use]
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }

    #[must_use]
    pub const fn payload(&self) -> &ApprovalBallotPayload {
        &self.payload
    }
}

#[cfg(test)]
mod tests {
    use super::{BALLOT_PACKAGE_V1_FIELD_COUNT, BallotPackageV1, BallotPackageV1Input};
    use crate::{
        ApprovalBallotPayload, ApprovalLimits, CandidateDefinition, CandidateId, CandidateSet,
    };
    use tari_cc_private_ballot_protocol::{
        CanonicalCborWriter, MAX_CANONICAL_OBJECT_BYTES, MAX_PROOF_BYTES, MAX_PROOF_SUITE_ID_BYTES,
        ManifestHash, PROTOCOL_VERSION_V1, TEST_ONLY_SUITE_ID, ValidationCode,
        test_only::TestOnlyDeterministicHasher,
    };

    fn candidate(identifier: &[u8], display_name: &str) -> CandidateDefinition {
        let Ok(id) = CandidateId::new(identifier.to_vec()) else {
            panic!("test candidate ID must be valid");
        };

        let Ok(candidate) = CandidateDefinition::new(id, display_name.to_owned()) else {
            panic!("test candidate must be valid");
        };

        candidate
    }

    fn candidates() -> CandidateSet {
        let Ok(candidates) = CandidateSet::new(vec![
            candidate(b"candidate-b", "Candidate B"),
            candidate(b"candidate-a", "Candidate A"),
        ]) else {
            panic!("test candidate set must be valid");
        };

        candidates
    }

    fn limits() -> ApprovalLimits {
        let Ok(limits) = ApprovalLimits::new(1, 1, false) else {
            panic!("test limits must be valid");
        };

        limits
    }

    fn payload_for(identifier: &[u8]) -> ApprovalBallotPayload {
        let candidates = candidates();

        let Ok(id) = CandidateId::new(identifier.to_vec()) else {
            panic!("test candidate ID must be valid");
        };

        let Ok(payload) = ApprovalBallotPayload::new(vec![id], &candidates, limits()) else {
            panic!("test payload must be valid");
        };

        payload
    }

    fn package_with_payload_and_proof(
        payload: ApprovalBallotPayload,
        proof: Vec<u8>,
    ) -> BallotPackageV1 {
        let input = BallotPackageV1Input {
            protocol_version: PROTOCOL_VERSION_V1,
            manifest_hash: ManifestHash::new([5_u8; 32]),
            proof_suite_id: TEST_ONLY_SUITE_ID.to_owned(),
            proof,
            payload,
        };

        let Ok(package) = BallotPackageV1::new(input) else {
            panic!("test ballot package must be valid");
        };

        package
    }

    fn package_with_proof(proof: Vec<u8>) -> BallotPackageV1 {
        package_with_payload_and_proof(payload_for(b"candidate-a"), proof)
    }

    fn package() -> BallotPackageV1 {
        package_with_proof(b"TEST_ONLY_PROOF".to_vec())
    }

    fn decode_hex(input: &str) -> Vec<u8> {
        assert!(input.len().is_multiple_of(2));

        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let Ok(pair) = core::str::from_utf8(pair) else {
                    panic!("test vector must contain UTF-8 hexadecimal");
                };

                let Ok(value) = u8::from_str_radix(pair, 16) else {
                    panic!("test vector must contain valid hexadecimal");
                };

                value
            })
            .collect()
    }

    #[test]
    fn matching_manifest_and_suite_are_accepted() {
        let package = package();

        assert!(
            package
                .validate_manifest_binding(ManifestHash::new([5_u8; 32]), TEST_ONLY_SUITE_ID)
                .is_ok()
        );
    }

    #[test]
    fn wrong_manifest_hash_is_rejected() {
        let package = package();
        let result =
            package.validate_manifest_binding(ManifestHash::new([6_u8; 32]), TEST_ONLY_SUITE_ID);

        assert!(matches!(
            result,
            Err(error) if error.code() == ValidationCode::WrongManifestHash
        ));
    }

    #[test]
    fn mismatched_proof_suite_is_rejected() {
        let package = package();
        let result =
            package.validate_manifest_binding(ManifestHash::new([5_u8; 32]), "OTHER_SUITE");

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::UnsupportedProofSuite
        ));
    }

    #[test]
    fn proof_and_payload_are_preserved_without_nullifier_metadata() {
        let package = package();

        assert_eq!(package.proof(), b"TEST_ONLY_PROOF");
        assert_eq!(package.payload().selections()[0].as_bytes(), b"candidate-a");
    }

    #[test]
    fn empty_proof_is_left_for_the_verifier_boundary_to_reject() {
        let package = package_with_proof(Vec::new());

        assert!(package.proof().is_empty());
    }

    #[test]
    fn package_cbor_vector_is_exact() {
        let Ok(encoded) = package().to_canonical_cbor() else {
            panic!("test package encoding must succeed");
        };

        let expected = decode_hex(concat!(
            "85015820",
            "05050505050505050505050505050505",
            "05050505050505050505050505050505",
            "7831",
            "544553545f4f4e4c595f4e4f545f41",
            "4e4f4e594d4f55535f4e4f545f464f",
            "525f42494e44494e475f454c45435449",
            "4f4e53",
            "4d814b63616e6469646174652d61",
            "4f544553545f4f4e4c595f50524f4f46",
        ));

        assert_eq!(encoded, expected);
    }

    #[test]
    fn package_round_trip_preserves_exact_bytes() {
        let candidates = candidates();
        let original = package();

        let Ok(encoded) = original.to_canonical_cbor() else {
            panic!("test package encoding must succeed");
        };

        let Ok(decoded) = BallotPackageV1::from_canonical_cbor(&encoded, &candidates, limits())
        else {
            panic!("canonical test package must decode");
        };

        let Ok(reencoded) = decoded.to_canonical_cbor() else {
            panic!("decoded test package must re-encode");
        };

        assert_eq!(decoded, original);
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn package_hash_is_deterministic_and_field_sensitive() {
        let provider = TestOnlyDeterministicHasher;
        let baseline = package();

        let Ok(first_hash) = baseline.canonical_hash(&provider) else {
            panic!("first package hash must succeed");
        };

        let Ok(second_hash) = baseline.canonical_hash(&provider) else {
            panic!("second package hash must succeed");
        };

        assert_eq!(first_hash, second_hash);

        let mut changed_manifest = baseline.clone();
        changed_manifest.manifest_hash = ManifestHash::new([6_u8; 32]);

        let mut changed_suite = baseline.clone();
        changed_suite.proof_suite_id = "OTHER_TEST_SUITE".to_owned();

        let mut changed_proof = baseline.clone();
        changed_proof.proof.push(0xff);

        let changed_payload =
            package_with_payload_and_proof(payload_for(b"candidate-b"), baseline.proof.clone());

        for changed in [
            changed_manifest,
            changed_suite,
            changed_proof,
            changed_payload,
        ] {
            let Ok(changed_hash) = changed.canonical_hash(&provider) else {
                panic!("changed package hash must succeed");
            };

            assert_ne!(changed_hash, first_hash);
        }
    }

    #[test]
    fn oversized_proof_suite_is_rejected() {
        let result = BallotPackageV1::new(BallotPackageV1Input {
            protocol_version: PROTOCOL_VERSION_V1,
            manifest_hash: ManifestHash::new([5_u8; 32]),
            proof_suite_id: "s".repeat(MAX_PROOF_SUITE_ID_BYTES + 1),
            proof: Vec::new(),
            payload: payload_for(b"candidate-a"),
        });

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::ProtocolLimitExceeded
        ));
    }

    #[test]
    fn oversized_proof_is_rejected() {
        let result = BallotPackageV1::new(BallotPackageV1Input {
            protocol_version: PROTOCOL_VERSION_V1,
            manifest_hash: ManifestHash::new([5_u8; 32]),
            proof_suite_id: TEST_ONLY_SUITE_ID.to_owned(),
            proof: vec![0_u8; MAX_PROOF_BYTES + 1],
            payload: payload_for(b"candidate-a"),
        });

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::ProtocolLimitExceeded
        ));
    }

    #[test]
    fn oversized_encoded_package_is_rejected_before_decoding() {
        let candidates = candidates();
        let encoded = vec![0_u8; MAX_CANONICAL_OBJECT_BYTES + 1];

        let result = BallotPackageV1::from_canonical_cbor(&encoded, &candidates, limits());

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::ProtocolLimitExceeded
        ));
    }

    #[test]
    fn malformed_manifest_hash_is_rejected() {
        let candidates = candidates();
        let Ok(payload_bytes) = payload_for(b"candidate-a").to_canonical_cbor() else {
            panic!("test payload encoding must succeed");
        };

        let mut writer = CanonicalCborWriter::new();

        assert!(
            writer
                .write_array_len(BALLOT_PACKAGE_V1_FIELD_COUNT)
                .is_ok()
        );
        writer.write_unsigned(u64::from(PROTOCOL_VERSION_V1));
        assert!(writer.write_byte_string(&[5_u8; 31]).is_ok());
        assert!(writer.write_text_string(TEST_ONLY_SUITE_ID).is_ok());
        assert!(writer.write_byte_string(&payload_bytes).is_ok());
        assert!(writer.write_byte_string(b"TEST_ONLY_PROOF").is_ok());

        let result =
            BallotPackageV1::from_canonical_cbor(&writer.into_bytes(), &candidates, limits());

        assert!(matches!(
            result,
            Err(error) if error.code() == ValidationCode::InvalidData
        ));
    }

    #[test]
    fn wrong_package_field_count_is_rejected() {
        let candidates = candidates();
        let mut writer = CanonicalCborWriter::new();

        assert!(
            writer
                .write_array_len(BALLOT_PACKAGE_V1_FIELD_COUNT - 1)
                .is_ok()
        );

        let result =
            BallotPackageV1::from_canonical_cbor(&writer.into_bytes(), &candidates, limits());

        assert!(matches!(
            result,
            Err(error) if error.code() == ValidationCode::InvalidCbor
        ));
    }

    #[test]
    fn noncanonical_package_version_is_rejected() {
        let candidates = candidates();
        let Ok(mut encoded) = package().to_canonical_cbor() else {
            panic!("test package encoding must succeed");
        };

        assert_eq!(encoded[0], 0x85);
        assert_eq!(encoded[1], 0x01);

        encoded.splice(1..2, [0x18, 0x01]);

        let result = BallotPackageV1::from_canonical_cbor(&encoded, &candidates, limits());

        assert!(matches!(
            result,
            Err(error) if error.code() == ValidationCode::NonCanonicalCbor
        ));
    }
}
