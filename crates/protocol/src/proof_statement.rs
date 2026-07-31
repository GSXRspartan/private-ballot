//! Canonical proof statements reconstructed from validated election data.

use crate::{
    BallotPayloadHash, CanonicalCborWriter, ElectionScope, HashDomain,
    MAX_BALLOT_CONFIDENTIALITY_ID_BYTES, MAX_BALLOT_KIND_ID_BYTES, MAX_PROOF_STATEMENT_BYTES,
    MAX_PROOF_SUITE_ID_BYTES, ManifestHash, PROTOCOL_VERSION_V1, ProtocolError, RegistryCommitment,
    ValidationCode, domain_separated_input,
};

/// Version encoded into every version-one proof statement.
pub const PROOF_STATEMENT_VERSION_V1: u16 = 1;

/// Validated values used to construct a version-one proof statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofStatementV1Input {
    pub protocol_version: u16,
    pub proof_suite_id: String,
    pub manifest_hash: ManifestHash,
    pub election_scope: ElectionScope,
    pub registry_commitment: RegistryCommitment,
    pub ballot_payload_hash: BallotPayloadHash,
    pub ballot_kind_id: String,
    pub ballot_confidentiality_id: String,
}

/// Complete public statement authenticated by an anonymous proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofStatementV1 {
    protocol_version: u16,
    proof_suite_id: String,
    manifest_hash: ManifestHash,
    election_scope: ElectionScope,
    registry_commitment: RegistryCommitment,
    ballot_payload_hash: BallotPayloadHash,
    ballot_kind_id: String,
    ballot_confidentiality_id: String,
}

impl ProofStatementV1 {
    /// Validates and freezes one complete proof statement.
    pub fn new(input: ProofStatementV1Input) -> Result<Self, ProtocolError> {
        if input.protocol_version != PROTOCOL_VERSION_V1 {
            return Err(ProtocolError::new(
                ValidationCode::UnsupportedProtocolVersion,
                "proof statement does not use protocol version one",
            ));
        }

        validate_identifier(
            &input.proof_suite_id,
            MAX_PROOF_SUITE_ID_BYTES,
            ValidationCode::EmptyProofSuiteId,
            "proof suite identifier must not be empty",
            "proof suite identifier exceeds the protocol size limit",
        )?;

        validate_identifier(
            &input.ballot_kind_id,
            MAX_BALLOT_KIND_ID_BYTES,
            ValidationCode::InvalidData,
            "ballot-kind identifier must not be empty",
            "ballot-kind identifier exceeds the protocol size limit",
        )?;

        validate_identifier(
            &input.ballot_confidentiality_id,
            MAX_BALLOT_CONFIDENTIALITY_ID_BYTES,
            ValidationCode::InvalidData,
            "ballot confidentiality identifier must not be empty",
            "ballot confidentiality identifier exceeds the protocol size limit",
        )?;

        Ok(Self {
            protocol_version: input.protocol_version,
            proof_suite_id: input.proof_suite_id,
            manifest_hash: input.manifest_hash,
            election_scope: input.election_scope,
            registry_commitment: input.registry_commitment,
            ballot_payload_hash: input.ballot_payload_hash,
            ballot_kind_id: input.ballot_kind_id,
            ballot_confidentiality_id: input.ballot_confidentiality_id,
        })
    }

    /// Returns the protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    /// Returns the proof-suite identifier.
    #[must_use]
    pub fn proof_suite_id(&self) -> &str {
        &self.proof_suite_id
    }

    /// Returns the canonical manifest hash.
    #[must_use]
    pub const fn manifest_hash(&self) -> ManifestHash {
        self.manifest_hash
    }

    /// Returns the manifest-derived election scope.
    #[must_use]
    pub const fn election_scope(&self) -> ElectionScope {
        self.election_scope
    }

    /// Returns the frozen-registry commitment.
    #[must_use]
    pub const fn registry_commitment(&self) -> RegistryCommitment {
        self.registry_commitment
    }

    /// Returns the canonical ballot-payload hash.
    #[must_use]
    pub const fn ballot_payload_hash(&self) -> BallotPayloadHash {
        self.ballot_payload_hash
    }

    /// Returns the stable ballot-kind identifier.
    #[must_use]
    pub fn ballot_kind_id(&self) -> &str {
        &self.ballot_kind_id
    }

    /// Returns the stable ballot-confidentiality identifier.
    #[must_use]
    pub fn ballot_confidentiality_id(&self) -> &str {
        &self.ballot_confidentiality_id
    }

    /// Encodes all proof-bound fields using canonical CBOR.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut writer = CanonicalCborWriter::new();

        writer.write_array_len(9)?;
        writer.write_unsigned(u64::from(PROOF_STATEMENT_VERSION_V1));
        writer.write_unsigned(u64::from(self.protocol_version));
        writer.write_text_string(&self.proof_suite_id)?;
        writer.write_byte_string(self.manifest_hash.as_bytes())?;
        writer.write_byte_string(self.election_scope.as_bytes())?;
        writer.write_byte_string(self.registry_commitment.as_bytes())?;
        writer.write_byte_string(self.ballot_payload_hash.as_bytes())?;
        writer.write_text_string(&self.ballot_kind_id)?;
        writer.write_text_string(&self.ballot_confidentiality_id)?;

        let encoded = writer.into_bytes();

        if encoded.len() > MAX_PROOF_STATEMENT_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "canonical proof statement exceeds the protocol size limit",
            ));
        }

        Ok(encoded)
    }

    /// Returns the domain-separated transcript bytes consumed by a proof suite.
    pub fn transcript_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        let canonical = self.to_canonical_cbor()?;

        Ok(domain_separated_input(
            HashDomain::ProofStatementV1,
            &canonical,
        ))
    }
}

fn validate_identifier(
    value: &str,
    maximum_bytes: usize,
    empty_code: ValidationCode,
    empty_message: &'static str,
    oversized_message: &'static str,
) -> Result<(), ProtocolError> {
    if value.trim().is_empty() {
        return Err(ProtocolError::new(empty_code, empty_message));
    }

    if value.len() > maximum_bytes {
        return Err(ProtocolError::new(
            ValidationCode::ProtocolLimitExceeded,
            oversized_message,
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        MAX_BALLOT_CONFIDENTIALITY_ID_BYTES, MAX_BALLOT_KIND_ID_BYTES, MAX_PROOF_SUITE_ID_BYTES,
    };

    fn input() -> ProofStatementV1Input {
        ProofStatementV1Input {
            protocol_version: PROTOCOL_VERSION_V1,
            proof_suite_id: "suite".to_owned(),
            manifest_hash: ManifestHash::new([1_u8; 32]),
            election_scope: ElectionScope::new([2_u8; 32]),
            registry_commitment: RegistryCommitment::new([3_u8; 32]),
            ballot_payload_hash: BallotPayloadHash::new([4_u8; 32]),
            ballot_kind_id: "KIND".to_owned(),
            ballot_confidentiality_id: "PUBLIC".to_owned(),
        }
    }

    fn statement() -> ProofStatementV1 {
        let Ok(statement) = ProofStatementV1::new(input()) else {
            panic!("test statement must be valid");
        };

        statement
    }

    #[test]
    fn proof_statement_vector_is_exact() {
        let Ok(encoded) = statement().to_canonical_cbor() else {
            panic!("statement encoding should succeed");
        };

        let mut expected = vec![
            0x89, 0x01, 0x01, 0x65, b's', b'u', b'i', b't', b'e', 0x58, 0x20,
        ];

        expected.extend_from_slice(&[1_u8; 32]);
        expected.extend_from_slice(&[0x58, 0x20]);
        expected.extend_from_slice(&[2_u8; 32]);
        expected.extend_from_slice(&[0x58, 0x20]);
        expected.extend_from_slice(&[3_u8; 32]);
        expected.extend_from_slice(&[0x58, 0x20]);
        expected.extend_from_slice(&[4_u8; 32]);
        expected.extend_from_slice(&[
            0x64, b'K', b'I', b'N', b'D', 0x66, b'P', b'U', b'B', b'L', b'I', b'C',
        ]);

        assert_eq!(encoded, expected);
    }

    #[test]
    fn transcript_bytes_use_the_proof_statement_domain() {
        let statement = statement();

        let Ok(canonical) = statement.to_canonical_cbor() else {
            panic!("statement encoding should succeed");
        };

        let expected = domain_separated_input(HashDomain::ProofStatementV1, &canonical);

        let Ok(actual) = statement.transcript_bytes() else {
            panic!("transcript construction should succeed");
        };

        assert_eq!(actual, expected);
    }

    #[test]
    fn repeated_transcript_construction_is_deterministic() {
        let statement = statement();

        let Ok(first) = statement.transcript_bytes() else {
            panic!("first transcript construction should succeed");
        };

        let Ok(second) = statement.transcript_bytes() else {
            panic!("second transcript construction should succeed");
        };

        assert_eq!(first, second);
    }

    #[test]
    fn changing_any_bound_field_changes_canonical_bytes() {
        let Ok(base) = statement().to_canonical_cbor() else {
            panic!("base statement encoding should succeed");
        };

        let mut variants = Vec::new();

        let mut changed_suite = input();
        changed_suite.proof_suite_id = "other-suite".to_owned();
        variants.push(changed_suite);

        let mut changed_manifest = input();
        changed_manifest.manifest_hash = ManifestHash::new([9_u8; 32]);
        variants.push(changed_manifest);

        let mut changed_scope = input();
        changed_scope.election_scope = ElectionScope::new([9_u8; 32]);
        variants.push(changed_scope);

        let mut changed_registry = input();
        changed_registry.registry_commitment = RegistryCommitment::new([9_u8; 32]);
        variants.push(changed_registry);

        let mut changed_payload = input();
        changed_payload.ballot_payload_hash = BallotPayloadHash::new([9_u8; 32]);
        variants.push(changed_payload);

        let mut changed_kind = input();
        changed_kind.ballot_kind_id = "OTHER_KIND".to_owned();
        variants.push(changed_kind);

        let mut changed_confidentiality = input();
        changed_confidentiality.ballot_confidentiality_id = "SEALED".to_owned();
        variants.push(changed_confidentiality);

        for variant in variants {
            let Ok(statement) = ProofStatementV1::new(variant) else {
                panic!("changed statement must remain valid");
            };

            let Ok(encoded) = statement.to_canonical_cbor() else {
                panic!("changed statement encoding should succeed");
            };

            assert_ne!(encoded, base);
        }
    }

    #[test]
    fn empty_identifiers_are_rejected() {
        let mut empty_suite = input();
        empty_suite.proof_suite_id = String::new();

        assert!(ProofStatementV1::new(empty_suite).is_err());

        let mut empty_kind = input();
        empty_kind.ballot_kind_id = " ".to_owned();

        assert!(ProofStatementV1::new(empty_kind).is_err());

        let mut empty_confidentiality = input();
        empty_confidentiality.ballot_confidentiality_id = String::new();

        assert!(ProofStatementV1::new(empty_confidentiality).is_err());
    }

    #[test]
    fn oversized_identifiers_are_rejected() {
        let mut oversized_suite = input();
        oversized_suite.proof_suite_id = "s".repeat(MAX_PROOF_SUITE_ID_BYTES + 1);

        assert!(matches!(
            ProofStatementV1::new(oversized_suite),
            Err(error)
                if error.code() == ValidationCode::ProtocolLimitExceeded
        ));

        let mut oversized_kind = input();
        oversized_kind.ballot_kind_id = "k".repeat(MAX_BALLOT_KIND_ID_BYTES + 1);

        assert!(matches!(
            ProofStatementV1::new(oversized_kind),
            Err(error)
                if error.code() == ValidationCode::ProtocolLimitExceeded
        ));

        let mut oversized_confidentiality = input();
        oversized_confidentiality.ballot_confidentiality_id =
            "c".repeat(MAX_BALLOT_CONFIDENTIALITY_ID_BYTES + 1);

        assert!(matches!(
            ProofStatementV1::new(oversized_confidentiality),
            Err(error)
                if error.code() == ValidationCode::ProtocolLimitExceeded
        ));
    }
}
