//! Canonical manifest-derived election scope.

use tari_cc_private_ballot_protocol::{
    ElectionScope, HashProvider, ProtocolError, derive_election_scope,
};

use crate::{ElectionManifest, ElectionManifestV1, ElectionManifestV2};

impl ElectionManifestV1 {
    /// Hashes the complete canonical manifest and derives its election scope.
    pub fn canonical_scope<H: HashProvider>(
        &self,
        provider: &H,
    ) -> Result<ElectionScope, ProtocolError> {
        let manifest_hash = self.canonical_hash(provider)?;

        Ok(derive_election_scope(provider, &manifest_hash))
    }
}

impl ElectionManifestV2 {
    /// Hashes the complete canonical manifest and derives its election scope.
    pub fn canonical_scope<H: HashProvider>(
        &self,
        provider: &H,
    ) -> Result<ElectionScope, ProtocolError> {
        let manifest_hash = self.canonical_hash(provider)?;

        Ok(derive_election_scope(provider, &manifest_hash))
    }
}

impl ElectionManifest {
    /// Hashes the complete canonical manifest and derives its election scope.
    pub fn canonical_scope<H: HashProvider>(
        &self,
        provider: &H,
    ) -> Result<ElectionScope, ProtocolError> {
        match self {
            Self::V1(manifest) => manifest.canonical_scope(provider),
            Self::V2(manifest) => manifest.canonical_scope(provider),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ApprovalLimits, BallotConfidentialityV1, BallotKindV1, ElectionId, ElectionManifestV1Input,
        ElectionManifestV2, ElectionManifestV2Input,
    };
    use tari_cc_private_ballot_protocol::{
        CandidateSetCommitment, PROTOCOL_VERSION_V1, RegistryCommitment, TEST_ONLY_SUITE_ID,
        derive_election_scope, test_only::TestOnlyDeterministicHasher,
    };

    fn election_id() -> ElectionId {
        let Ok(id) = ElectionId::new(b"same-human-election-id".to_vec()) else {
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

    fn base_input() -> ElectionManifestV1Input {
        ElectionManifestV1Input {
            protocol_version: PROTOCOL_VERSION_V1,
            election_id: election_id(),
            ballot_kind: BallotKindV1::NonBindingApprovalPilot,
            ballot_confidentiality: BallotConfidentialityV1::Public,
            registry_commitment: RegistryCommitment::new([1_u8; 32]),
            candidate_set_commitment: CandidateSetCommitment::new([2_u8; 32]),
            proof_suite_id: TEST_ONLY_SUITE_ID.to_owned(),
            approval_limits: approval_limits(),
            governance_source_revision: "revision-1".to_owned(),
        }
    }

    fn manifest(input: ElectionManifestV1Input) -> ElectionManifestV1 {
        let Ok(manifest) = ElectionManifestV1::new(input) else {
            panic!("test manifest must be valid");
        };

        manifest
    }

    fn v2_manifest(question: &str) -> ElectionManifestV2 {
        let Ok(manifest) = ElectionManifestV2::new(ElectionManifestV2Input {
            protocol_version: PROTOCOL_VERSION_V1,
            election_id: election_id(),
            ballot_kind: BallotKindV1::NonBindingApprovalPilot,
            ballot_confidentiality: BallotConfidentialityV1::Public,
            registry_commitment: RegistryCommitment::new([1_u8; 32]),
            candidate_set_commitment: CandidateSetCommitment::new([2_u8; 32]),
            proof_suite_id: TEST_ONLY_SUITE_ID.to_owned(),
            approval_limits: approval_limits(),
            governance_source_revision: "revision-1".to_owned(),
            proposal_question: question.to_owned(),
        }) else {
            panic!("test manifest must be valid");
        };

        manifest
    }

    #[test]
    fn canonical_scope_matches_manifest_hash_derivation() {
        let provider = TestOnlyDeterministicHasher;
        let manifest = manifest(base_input());

        let Ok(manifest_hash) = manifest.canonical_hash(&provider) else {
            panic!("manifest hash should succeed");
        };

        let expected = derive_election_scope(&provider, &manifest_hash);

        let Ok(actual) = manifest.canonical_scope(&provider) else {
            panic!("scope derivation should succeed");
        };

        assert_eq!(actual, expected);
    }

    #[test]
    fn repeated_manifest_scope_derivation_is_deterministic() {
        let provider = TestOnlyDeterministicHasher;
        let manifest = manifest(base_input());

        let Ok(first) = manifest.canonical_scope(&provider) else {
            panic!("first scope derivation should succeed");
        };

        let Ok(second) = manifest.canonical_scope(&provider) else {
            panic!("second scope derivation should succeed");
        };

        assert_eq!(first, second);
    }

    #[test]
    fn same_election_id_with_changed_registry_changes_scope() {
        let provider = TestOnlyDeterministicHasher;

        let first_manifest = manifest(base_input());

        let mut changed = base_input();
        changed.registry_commitment = RegistryCommitment::new([9_u8; 32]);
        let second_manifest = manifest(changed);

        assert_eq!(first_manifest.election_id(), second_manifest.election_id());

        let Ok(first_scope) = first_manifest.canonical_scope(&provider) else {
            panic!("first scope derivation should succeed");
        };

        let Ok(second_scope) = second_manifest.canonical_scope(&provider) else {
            panic!("second scope derivation should succeed");
        };

        assert_ne!(first_scope, second_scope);
    }

    #[test]
    fn changed_governance_revision_changes_scope() {
        let provider = TestOnlyDeterministicHasher;

        let first_manifest = manifest(base_input());

        let mut changed = base_input();
        changed.governance_source_revision = "revision-2".to_owned();
        let second_manifest = manifest(changed);

        let Ok(first_scope) = first_manifest.canonical_scope(&provider) else {
            panic!("first scope derivation should succeed");
        };

        let Ok(second_scope) = second_manifest.canonical_scope(&provider) else {
            panic!("second scope derivation should succeed");
        };

        assert_ne!(first_scope, second_scope);
    }

    #[test]
    fn same_election_with_changed_v2_question_changes_hash_and_scope() {
        let provider = TestOnlyDeterministicHasher;
        let first_manifest = v2_manifest("Question A?");
        let second_manifest = v2_manifest("Question B?");

        assert_eq!(first_manifest.election_id(), second_manifest.election_id());

        let Ok(first_hash) = first_manifest.canonical_hash(&provider) else {
            panic!("first hash should succeed");
        };
        let Ok(second_hash) = second_manifest.canonical_hash(&provider) else {
            panic!("second hash should succeed");
        };
        let Ok(first_scope) = first_manifest.canonical_scope(&provider) else {
            panic!("first scope should succeed");
        };
        let Ok(second_scope) = second_manifest.canonical_scope(&provider) else {
            panic!("second scope should succeed");
        };

        assert_ne!(first_hash, second_hash);
        assert_ne!(first_scope, second_scope);
    }
}
