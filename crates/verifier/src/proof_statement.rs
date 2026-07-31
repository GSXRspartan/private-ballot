//! Verifier-owned proof-statement reconstruction.

use tari_cc_private_ballot_ballot::{ApprovalBallotPayload, ElectionManifestV1};
use tari_cc_private_ballot_protocol::{
    HashProvider, ProofStatementV1, ProofStatementV1Input, ProtocolError,
};

/// Reconstructs the complete approval-ballot proof statement.
///
/// No transcript, message, manifest hash, election scope, registry
/// commitment, or ballot hash is accepted from the ballot submitter.
pub fn reconstruct_approval_proof_statement<H: HashProvider>(
    manifest: &ElectionManifestV1,
    payload: &ApprovalBallotPayload,
    provider: &H,
) -> Result<ProofStatementV1, ProtocolError> {
    let manifest_hash = manifest.canonical_hash(provider)?;
    let election_scope = manifest.canonical_scope(provider)?;
    let ballot_payload_hash = payload.canonical_hash(provider)?;

    ProofStatementV1::new(ProofStatementV1Input {
        protocol_version: manifest.protocol_version(),
        proof_suite_id: manifest.proof_suite_id().to_owned(),
        manifest_hash,
        election_scope,
        registry_commitment: manifest.registry_commitment(),
        ballot_payload_hash,
        ballot_kind_id: manifest.ballot_kind().as_str().to_owned(),
        ballot_confidentiality_id: manifest.ballot_confidentiality().as_str().to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tari_cc_private_ballot_ballot::{
        ApprovalLimits, BallotConfidentialityV1, BallotKindV1, CandidateDefinition, CandidateId,
        CandidateSet, ElectionId, ElectionManifestV1Input,
    };
    use tari_cc_private_ballot_protocol::{
        CandidateSetCommitment, PROTOCOL_VERSION_V1, RegistryCommitment, TEST_ONLY_SUITE_ID,
        test_only::TestOnlyDeterministicHasher,
    };

    fn candidate_id(value: &[u8]) -> CandidateId {
        let Ok(id) = CandidateId::new(value.to_vec()) else {
            panic!("test candidate ID must be valid");
        };

        id
    }

    fn candidate(value: &[u8], name: &str) -> CandidateDefinition {
        let Ok(candidate) = CandidateDefinition::new(candidate_id(value), name.to_owned()) else {
            panic!("test candidate must be valid");
        };

        candidate
    }

    fn candidate_set() -> CandidateSet {
        let Ok(candidates) = CandidateSet::new(vec![
            candidate(b"a", "Candidate A"),
            candidate(b"b", "Candidate B"),
        ]) else {
            panic!("test candidate set must be valid");
        };

        candidates
    }

    fn approval_limits() -> ApprovalLimits {
        let Ok(limits) = ApprovalLimits::new(1, 1, false) else {
            panic!("test approval limits must be valid");
        };

        limits
    }

    fn manifest_input() -> ElectionManifestV1Input {
        let Ok(election_id) = ElectionId::new(b"proof-election".to_vec()) else {
            panic!("test election ID must be valid");
        };

        ElectionManifestV1Input {
            protocol_version: PROTOCOL_VERSION_V1,
            election_id,
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

    fn payload(candidates: &CandidateSet, selection: &[u8]) -> ApprovalBallotPayload {
        let Ok(payload) = ApprovalBallotPayload::new(
            vec![candidate_id(selection)],
            candidates,
            approval_limits(),
        ) else {
            panic!("test payload must be valid");
        };

        payload
    }

    #[test]
    fn verifier_reconstruction_matches_all_validated_inputs() {
        let provider = TestOnlyDeterministicHasher;
        let manifest = manifest(manifest_input());
        let candidates = candidate_set();
        let payload = payload(&candidates, b"a");

        let Ok(actual) = reconstruct_approval_proof_statement(&manifest, &payload, &provider)
        else {
            panic!("statement reconstruction should succeed");
        };

        let Ok(manifest_hash) = manifest.canonical_hash(&provider) else {
            panic!("expected manifest hash should succeed");
        };

        let Ok(election_scope) = manifest.canonical_scope(&provider) else {
            panic!("expected election scope should succeed");
        };

        let Ok(ballot_payload_hash) = payload.canonical_hash(&provider) else {
            panic!("expected ballot payload hash should succeed");
        };
        let Ok(expected) = ProofStatementV1::new(ProofStatementV1Input {
            protocol_version: manifest.protocol_version(),
            proof_suite_id: manifest.proof_suite_id().to_owned(),
            manifest_hash,
            election_scope,
            registry_commitment: manifest.registry_commitment(),
            ballot_payload_hash,
            ballot_kind_id: manifest.ballot_kind().as_str().to_owned(),
            ballot_confidentiality_id: manifest.ballot_confidentiality().as_str().to_owned(),
        }) else {
            panic!("expected statement should be valid");
        };

        assert_eq!(actual, expected);
    }

    #[test]
    fn changing_a_ballot_choice_changes_the_statement() {
        let provider = TestOnlyDeterministicHasher;
        let manifest = manifest(manifest_input());
        let candidates = candidate_set();

        let first_payload = payload(&candidates, b"a");
        let second_payload = payload(&candidates, b"b");

        let Ok(first) = reconstruct_approval_proof_statement(&manifest, &first_payload, &provider)
        else {
            panic!("first statement should succeed");
        };

        let Ok(second) =
            reconstruct_approval_proof_statement(&manifest, &second_payload, &provider)
        else {
            panic!("second statement should succeed");
        };

        assert_ne!(first, second);
        assert_ne!(first.ballot_payload_hash(), second.ballot_payload_hash());
    }

    #[test]
    fn changing_the_registry_changes_the_statement() {
        let provider = TestOnlyDeterministicHasher;
        let candidates = candidate_set();
        let payload = payload(&candidates, b"a");

        let first_manifest = manifest(manifest_input());

        let mut changed = manifest_input();
        changed.registry_commitment = RegistryCommitment::new([9_u8; 32]);
        let second_manifest = manifest(changed);

        let Ok(first) = reconstruct_approval_proof_statement(&first_manifest, &payload, &provider)
        else {
            panic!("first statement should succeed");
        };

        let Ok(second) =
            reconstruct_approval_proof_statement(&second_manifest, &payload, &provider)
        else {
            panic!("second statement should succeed");
        };

        assert_ne!(first, second);
        assert_ne!(first.registry_commitment(), second.registry_commitment());
        assert_ne!(first.election_scope(), second.election_scope());
    }

    #[test]
    fn changing_the_governance_revision_changes_the_statement() {
        let provider = TestOnlyDeterministicHasher;
        let candidates = candidate_set();
        let payload = payload(&candidates, b"a");

        let first_manifest = manifest(manifest_input());

        let mut changed = manifest_input();
        changed.governance_source_revision = "revision-2".to_owned();
        let second_manifest = manifest(changed);

        let Ok(first) = reconstruct_approval_proof_statement(&first_manifest, &payload, &provider)
        else {
            panic!("first statement should succeed");
        };

        let Ok(second) =
            reconstruct_approval_proof_statement(&second_manifest, &payload, &provider)
        else {
            panic!("second statement should succeed");
        };

        assert_ne!(first.manifest_hash(), second.manifest_hash());
        assert_ne!(first.election_scope(), second.election_scope());
        assert_ne!(first, second);
    }

    #[test]
    fn suite_and_ballot_semantics_come_only_from_the_manifest() {
        let provider = TestOnlyDeterministicHasher;
        let manifest = manifest(manifest_input());
        let candidates = candidate_set();
        let payload = payload(&candidates, b"a");

        let Ok(statement) = reconstruct_approval_proof_statement(&manifest, &payload, &provider)
        else {
            panic!("statement reconstruction should succeed");
        };

        assert_eq!(statement.proof_suite_id(), manifest.proof_suite_id());
        assert_eq!(statement.ballot_kind_id(), manifest.ballot_kind().as_str());
        assert_eq!(
            statement.ballot_confidentiality_id(),
            manifest.ballot_confidentiality().as_str()
        );
    }
}
