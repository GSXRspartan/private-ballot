//! Versioned ballot package and manifest-binding checks.

use tari_cc_private_ballot_protocol::{
    ManifestHash, PROTOCOL_VERSION_V1, ProtocolError, ValidationCode,
};

use crate::ApprovalBallotPayload;

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

        Ok(Self {
            protocol_version: input.protocol_version,
            manifest_hash: input.manifest_hash,
            proof_suite_id: input.proof_suite_id,
            proof: input.proof,
            payload: input.payload,
        })
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
    use super::{BallotPackageV1, BallotPackageV1Input};
    use crate::{
        ApprovalBallotPayload, ApprovalLimits, CandidateDefinition, CandidateId, CandidateSet,
    };
    use tari_cc_private_ballot_protocol::{
        ManifestHash, PROTOCOL_VERSION_V1, TEST_ONLY_SUITE_ID, ValidationCode,
    };

    fn candidate_id() -> CandidateId {
        let Ok(id) = CandidateId::new(b"candidate-a".to_vec()) else {
            panic!("test candidate ID must be valid");
        };

        id
    }

    fn payload() -> ApprovalBallotPayload {
        let id = candidate_id();

        let Ok(candidate) = CandidateDefinition::new(id.clone(), "Candidate A".to_owned()) else {
            panic!("test candidate must be valid");
        };

        let Ok(candidates) = CandidateSet::new(vec![candidate]) else {
            panic!("test candidate set must be valid");
        };

        let Ok(limits) = ApprovalLimits::new(1, 1, false) else {
            panic!("test limits must be valid");
        };

        let Ok(payload) = ApprovalBallotPayload::new(vec![id], &candidates, limits) else {
            panic!("test payload must be valid");
        };

        payload
    }

    fn package_with_proof(proof: Vec<u8>) -> BallotPackageV1 {
        let input = BallotPackageV1Input {
            protocol_version: PROTOCOL_VERSION_V1,
            manifest_hash: ManifestHash::new([5_u8; 32]),
            proof_suite_id: TEST_ONLY_SUITE_ID.to_owned(),
            proof,
            payload: payload(),
        };

        let Ok(package) = BallotPackageV1::new(input) else {
            panic!("test ballot package must be valid");
        };

        package
    }

    fn package() -> BallotPackageV1 {
        package_with_proof(b"TEST_ONLY_PROOF".to_vec())
    }

    #[test]
    fn matching_manifest_and_suite_are_accepted() {
        let package = package();

        assert!(
            package
                .validate_manifest_binding(ManifestHash::new([5_u8; 32]), TEST_ONLY_SUITE_ID,)
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
}
