//! Proof invocation using verifier-reconstructed statements.

use tari_cc_private_ballot_ballot::{ApprovalBallotPayload, ElectionManifestV1};
use tari_cc_private_ballot_crypto::{ProofVerifierV1, VerifiedProofV1};
use tari_cc_private_ballot_protocol::{
    HashProvider, MAX_PROOF_BYTES, ProtocolError, ValidationCode,
};

use crate::reconstruct_approval_proof_statement;

/// Reconstructs and verifies one approval-ballot proof.
///
/// Proof suites receive only verifier-reconstructed statement bytes.
/// Successful results are rejected if they refer to any other statement.
pub fn verify_approval_proof<H, V>(
    manifest: &ElectionManifestV1,
    payload: &ApprovalBallotPayload,
    proof_bytes: &[u8],
    hash_provider: &H,
    proof_verifier: &V,
) -> Result<VerifiedProofV1, ProtocolError>
where
    H: HashProvider,
    V: ProofVerifierV1,
{
    if proof_bytes.is_empty() {
        return Err(ProtocolError::new(
            ValidationCode::InvalidData,
            "proof bytes must not be empty",
        ));
    }

    if proof_bytes.len() > MAX_PROOF_BYTES {
        return Err(ProtocolError::new(
            ValidationCode::ProtocolLimitExceeded,
            "proof bytes exceed the protocol size limit",
        ));
    }

    if manifest.proof_suite_id() != proof_verifier.proof_suite_id() {
        return Err(ProtocolError::new(
            ValidationCode::InvalidData,
            "manifest proof suite does not match the selected verifier",
        ));
    }

    let statement = reconstruct_approval_proof_statement(manifest, payload, hash_provider)?;

    let verified = proof_verifier.verify(&statement, proof_bytes)?;

    if verified.statement() != &statement {
        return Err(ProtocolError::new(
            ValidationCode::InvalidData,
            "proof verifier returned a result for a different statement",
        ));
    }

    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tari_cc_private_ballot_ballot::{
        ApprovalLimits, BallotConfidentialityV1, BallotKindV1, CandidateDefinition, CandidateId,
        CandidateSet, ElectionId, ElectionManifestV1Input,
    };
    use tari_cc_private_ballot_crypto::test_only_verifier::TestOnlyProofVerifierV1;
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

    fn manifest_with_suite(proof_suite_id: &str) -> ElectionManifestV1 {
        let Ok(election_id) = ElectionId::new(b"proof-election".to_vec()) else {
            panic!("test election ID must be valid");
        };

        let Ok(manifest) = ElectionManifestV1::new(ElectionManifestV1Input {
            protocol_version: PROTOCOL_VERSION_V1,
            election_id,
            ballot_kind: BallotKindV1::NonBindingApprovalPilot,
            ballot_confidentiality: BallotConfidentialityV1::Public,
            registry_commitment: RegistryCommitment::new([1_u8; 32]),
            candidate_set_commitment: CandidateSetCommitment::new([2_u8; 32]),
            proof_suite_id: proof_suite_id.to_owned(),
            approval_limits: approval_limits(),
            governance_source_revision: "revision-1".to_owned(),
        }) else {
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
    fn successful_verification_returns_authenticated_nullifier() {
        let provider = TestOnlyDeterministicHasher;
        let manifest = manifest_with_suite(TEST_ONLY_SUITE_ID);
        let candidates = candidate_set();
        let payload = payload(&candidates, b"a");

        let Ok(statement) = reconstruct_approval_proof_statement(&manifest, &payload, &provider)
        else {
            panic!("statement reconstruction should succeed");
        };

        let Ok(proof) = TestOnlyProofVerifierV1::proof_for(&statement) else {
            panic!("test proof construction should succeed");
        };

        let Ok(verifier) = TestOnlyProofVerifierV1::new(b"authenticated-nf".to_vec()) else {
            panic!("test verifier must be valid");
        };

        let Ok(result) = verify_approval_proof(&manifest, &payload, &proof, &provider, &verifier)
        else {
            panic!("proof verification should succeed");
        };

        assert_eq!(result.statement(), &statement);
        assert_eq!(result.nullifier().as_bytes(), b"authenticated-nf");
    }

    #[test]
    fn proof_for_one_ballot_is_rejected_for_another() {
        let provider = TestOnlyDeterministicHasher;
        let manifest = manifest_with_suite(TEST_ONLY_SUITE_ID);
        let candidates = candidate_set();
        let first_payload = payload(&candidates, b"a");
        let second_payload = payload(&candidates, b"b");

        let Ok(first_statement) =
            reconstruct_approval_proof_statement(&manifest, &first_payload, &provider)
        else {
            panic!("first statement reconstruction should succeed");
        };

        let Ok(proof) = TestOnlyProofVerifierV1::proof_for(&first_statement) else {
            panic!("test proof construction should succeed");
        };

        let Ok(verifier) = TestOnlyProofVerifierV1::new(b"nf".to_vec()) else {
            panic!("test verifier must be valid");
        };

        assert!(
            verify_approval_proof(&manifest, &second_payload, &proof, &provider, &verifier,)
                .is_err()
        );
    }

    #[test]
    fn mismatched_proof_suite_is_rejected_before_verification() {
        let provider = TestOnlyDeterministicHasher;
        let manifest = manifest_with_suite("different-suite");
        let candidates = candidate_set();
        let payload = payload(&candidates, b"a");

        let Ok(verifier) = TestOnlyProofVerifierV1::new(b"nf".to_vec()) else {
            panic!("test verifier must be valid");
        };

        let result = verify_approval_proof(&manifest, &payload, b"not-used", &provider, &verifier);

        assert!(matches!(
            result,
            Err(error) if error.code() == ValidationCode::InvalidData
        ));
    }

    #[test]
    fn empty_proof_is_rejected_at_the_verifier_boundary() {
        let provider = TestOnlyDeterministicHasher;
        let manifest = manifest_with_suite(TEST_ONLY_SUITE_ID);
        let candidates = candidate_set();
        let payload = payload(&candidates, b"a");

        let Ok(verifier) = TestOnlyProofVerifierV1::new(b"nf".to_vec()) else {
            panic!("test verifier must be valid");
        };

        assert!(verify_approval_proof(&manifest, &payload, &[], &provider, &verifier,).is_err());
    }

    #[test]
    fn oversized_proof_is_rejected_before_crypto_verification() {
        let provider = TestOnlyDeterministicHasher;
        let manifest = manifest_with_suite(TEST_ONLY_SUITE_ID);
        let candidates = candidate_set();
        let payload = payload(&candidates, b"a");

        let Ok(verifier) = TestOnlyProofVerifierV1::new(b"nf".to_vec()) else {
            panic!("test verifier must be valid");
        };

        let proof = vec![0_u8; MAX_PROOF_BYTES + 1];

        let result = verify_approval_proof(&manifest, &payload, &proof, &provider, &verifier);

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::ProtocolLimitExceeded
        ));
    }
}
