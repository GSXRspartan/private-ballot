//! Versioned election-manifest model.

use tari_cc_private_ballot_protocol::{
    CandidateSetCommitment, MAX_ELECTION_ID_BYTES, MAX_GOVERNANCE_REVISION_BYTES,
    MAX_PROOF_SUITE_ID_BYTES, PROTOCOL_VERSION_V1, ProtocolError, RegistryCommitment,
    ValidationCode,
};

use crate::ApprovalLimits;

/// Stable identifier for one election.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ElectionId(Vec<u8>);

impl ElectionId {
    /// Creates a bounded non-empty election identifier.
    pub fn new(bytes: Vec<u8>) -> Result<Self, ProtocolError> {
        if bytes.is_empty() {
            return Err(ProtocolError::new(
                ValidationCode::EmptyElectionId,
                "election identifier must not be empty",
            ));
        }

        if bytes.len() > MAX_ELECTION_ID_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "election identifier exceeds the protocol size limit",
            ));
        }

        Ok(Self(bytes))
    }

    /// Returns the stable identifier bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Ballot method supported by the first manifest version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BallotKindV1 {
    NonBindingApprovalPilot,
}

impl BallotKindV1 {
    /// Returns the stable machine-readable ballot-kind identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NonBindingApprovalPilot => "NON_BINDING_APPROVAL_PILOT",
        }
    }

    /// Parses one supported stable ballot-kind identifier.
    pub fn from_identifier(value: &str) -> Result<Self, ProtocolError> {
        match value {
            "NON_BINDING_APPROVAL_PILOT" => Ok(Self::NonBindingApprovalPilot),
            _ => Err(ProtocolError::new(
                ValidationCode::InvalidData,
                "unsupported ballot-kind identifier",
            )),
        }
    }
}

/// Ballot confidentiality mode supported by the first manifest version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BallotConfidentialityV1 {
    /// Ballot selections are present in the authoritative ballot payload.
    Public,
}

impl BallotConfidentialityV1 {
    /// Returns the stable machine-readable confidentiality identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "PUBLIC",
        }
    }

    /// Parses one supported stable confidentiality identifier.
    pub fn from_identifier(value: &str) -> Result<Self, ProtocolError> {
        match value {
            "PUBLIC" => Ok(Self::Public),
            _ => Err(ProtocolError::new(
                ValidationCode::InvalidData,
                "unsupported ballot confidentiality identifier",
            )),
        }
    }
}

/// Unvalidated fields used to construct a version-one manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElectionManifestV1Input {
    pub protocol_version: u16,
    pub election_id: ElectionId,
    pub ballot_kind: BallotKindV1,
    pub ballot_confidentiality: BallotConfidentialityV1,
    pub registry_commitment: RegistryCommitment,
    pub candidate_set_commitment: CandidateSetCommitment,
    pub proof_suite_id: String,
    pub approval_limits: ApprovalLimits,
    pub governance_source_revision: String,
}

/// Frozen version-one election manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElectionManifestV1 {
    protocol_version: u16,
    election_id: ElectionId,
    ballot_kind: BallotKindV1,
    ballot_confidentiality: BallotConfidentialityV1,
    registry_commitment: RegistryCommitment,
    candidate_set_commitment: CandidateSetCommitment,
    proof_suite_id: String,
    approval_limits: ApprovalLimits,
    governance_source_revision: String,
}

impl ElectionManifestV1 {
    /// Validates and freezes a version-one election manifest.
    pub fn new(input: ElectionManifestV1Input) -> Result<Self, ProtocolError> {
        if input.protocol_version != PROTOCOL_VERSION_V1 {
            return Err(ProtocolError::new(
                ValidationCode::UnsupportedProtocolVersion,
                "election manifest does not use protocol version one",
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
                "proof suite identifier exceeds the protocol size limit",
            ));
        }

        if input.governance_source_revision.trim().is_empty() {
            return Err(ProtocolError::new(
                ValidationCode::EmptyGovernanceSourceRevision,
                "governance source revision must not be empty",
            ));
        }

        if input.governance_source_revision.len() > MAX_GOVERNANCE_REVISION_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "governance revision exceeds the protocol size limit",
            ));
        }

        Ok(Self {
            protocol_version: input.protocol_version,
            election_id: input.election_id,
            ballot_kind: input.ballot_kind,
            ballot_confidentiality: input.ballot_confidentiality,
            registry_commitment: input.registry_commitment,
            candidate_set_commitment: input.candidate_set_commitment,
            proof_suite_id: input.proof_suite_id,
            approval_limits: input.approval_limits,
            governance_source_revision: input.governance_source_revision,
        })
    }

    #[must_use]
    pub const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    #[must_use]
    pub const fn election_id(&self) -> &ElectionId {
        &self.election_id
    }

    #[must_use]
    pub const fn ballot_kind(&self) -> BallotKindV1 {
        self.ballot_kind
    }

    #[must_use]
    pub const fn ballot_confidentiality(&self) -> BallotConfidentialityV1 {
        self.ballot_confidentiality
    }

    #[must_use]
    pub const fn registry_commitment(&self) -> RegistryCommitment {
        self.registry_commitment
    }

    #[must_use]
    pub const fn candidate_set_commitment(&self) -> CandidateSetCommitment {
        self.candidate_set_commitment
    }

    #[must_use]
    pub fn proof_suite_id(&self) -> &str {
        &self.proof_suite_id
    }

    #[must_use]
    pub const fn approval_limits(&self) -> ApprovalLimits {
        self.approval_limits
    }

    #[must_use]
    pub fn governance_source_revision(&self) -> &str {
        &self.governance_source_revision
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BallotConfidentialityV1, BallotKindV1, ElectionId, ElectionManifestV1,
        ElectionManifestV1Input,
    };
    use crate::ApprovalLimits;
    use tari_cc_private_ballot_protocol::{
        CandidateSetCommitment, MAX_ELECTION_ID_BYTES, MAX_GOVERNANCE_REVISION_BYTES,
        MAX_PROOF_SUITE_ID_BYTES, PROTOCOL_VERSION_V1, RegistryCommitment, TEST_ONLY_SUITE_ID,
        ValidationCode,
    };

    fn election_id() -> ElectionId {
        let Ok(id) = ElectionId::new(b"pilot-election-001".to_vec()) else {
            panic!("test election ID must be valid");
        };

        id
    }

    fn approval_limits() -> ApprovalLimits {
        let Ok(limits) = ApprovalLimits::new(1, 2, true) else {
            panic!("test approval limits must be valid");
        };

        limits
    }

    fn valid_input() -> ElectionManifestV1Input {
        ElectionManifestV1Input {
            protocol_version: PROTOCOL_VERSION_V1,
            election_id: election_id(),
            ballot_kind: BallotKindV1::NonBindingApprovalPilot,
            ballot_confidentiality: BallotConfidentialityV1::Public,
            registry_commitment: RegistryCommitment::new([1_u8; 32]),
            candidate_set_commitment: CandidateSetCommitment::new([2_u8; 32]),
            proof_suite_id: TEST_ONLY_SUITE_ID.to_owned(),
            approval_limits: approval_limits(),
            governance_source_revision: "rfc-pr-185:f9e86cca".to_owned(),
        }
    }

    #[test]
    fn valid_manifest_preserves_versioned_fields() {
        let Ok(manifest) = ElectionManifestV1::new(valid_input()) else {
            panic!("manifest should be valid");
        };

        assert_eq!(manifest.protocol_version(), PROTOCOL_VERSION_V1);
        assert_eq!(manifest.election_id().as_bytes(), b"pilot-election-001");
        assert_eq!(
            manifest.ballot_kind().as_str(),
            "NON_BINDING_APPROVAL_PILOT"
        );
        assert_eq!(manifest.ballot_confidentiality().as_str(), "PUBLIC");
        assert_eq!(manifest.proof_suite_id(), TEST_ONLY_SUITE_ID);
    }

    #[test]
    fn empty_election_id_is_rejected() {
        let result = ElectionId::new(Vec::new());

        assert!(matches!(
            result,
            Err(error) if error.code() == ValidationCode::EmptyElectionId
        ));
    }

    #[test]
    fn unsupported_manifest_version_is_rejected() {
        let mut input = valid_input();
        input.protocol_version = 2;

        let result = ElectionManifestV1::new(input);

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::UnsupportedProtocolVersion
        ));
    }

    #[test]
    fn empty_proof_suite_is_rejected() {
        let mut input = valid_input();
        input.proof_suite_id = " ".to_owned();

        let result = ElectionManifestV1::new(input);

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::EmptyProofSuiteId
        ));
    }

    #[test]
    fn empty_governance_revision_is_rejected() {
        let mut input = valid_input();
        input.governance_source_revision = String::new();

        let result = ElectionManifestV1::new(input);

        assert!(matches!(
            result,
            Err(error)
                if error.code()
                    == ValidationCode::EmptyGovernanceSourceRevision
        ));
    }

    #[test]
    fn oversized_election_id_is_rejected() {
        let result = ElectionId::new(vec![7_u8; MAX_ELECTION_ID_BYTES + 1]);

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::ProtocolLimitExceeded
        ));
    }

    #[test]
    fn oversized_proof_suite_is_rejected() {
        let mut input = valid_input();
        input.proof_suite_id = "p".repeat(MAX_PROOF_SUITE_ID_BYTES + 1);

        let result = ElectionManifestV1::new(input);

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::ProtocolLimitExceeded
        ));
    }

    #[test]
    fn oversized_governance_revision_is_rejected() {
        let mut input = valid_input();
        input.governance_source_revision = "r".repeat(MAX_GOVERNANCE_REVISION_BYTES + 1);

        let result = ElectionManifestV1::new(input);

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::ProtocolLimitExceeded
        ));
    }
}
