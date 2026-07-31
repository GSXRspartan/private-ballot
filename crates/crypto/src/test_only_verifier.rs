//! Explicitly non-anonymous proof verifier for protocol tests only.

use tari_cc_private_ballot_protocol::{
    MAX_PROOF_BYTES, ProofStatementV1, ProtocolError, TEST_ONLY_SUITE_ID, ValidationCode,
};

use crate::{ProofVerifierV1, VerifiedNullifier, VerifiedProofV1, verification::Sealed};

/// Marker embedded in every test-only proof.
pub const TEST_ONLY_PROOF_MARKER: &str = "TEST_ONLY_NOT_ANONYMOUS_NOT_FOR_BINDING_ELECTIONS";

/// Deterministic and forgeable verifier used only for plumbing tests.
///
/// This is not an anonymous membership proof and must never be accepted
/// for a binding or consequential election.
#[derive(Debug, Clone)]
pub struct TestOnlyProofVerifierV1 {
    nullifier: VerifiedNullifier,
}

impl TestOnlyProofVerifierV1 {
    /// Creates the test verifier with a deterministic fake nullifier.
    pub fn new(nullifier: Vec<u8>) -> Result<Self, ProtocolError> {
        Ok(Self {
            nullifier: VerifiedNullifier::new(nullifier)?,
        })
    }

    /// Creates forgeable test proof bytes bound to one exact statement.
    pub fn proof_for(statement: &ProofStatementV1) -> Result<Vec<u8>, ProtocolError> {
        let transcript = statement.transcript_bytes()?;
        let marker = TEST_ONLY_PROOF_MARKER.as_bytes();

        let Some(total_length) = marker.len().checked_add(transcript.len()) else {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "test-only proof length overflowed",
            ));
        };

        if total_length > MAX_PROOF_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "test-only proof exceeds the protocol size limit",
            ));
        }

        let mut proof = Vec::with_capacity(total_length);
        proof.extend_from_slice(marker);
        proof.extend_from_slice(&transcript);

        Ok(proof)
    }
}

impl Sealed for TestOnlyProofVerifierV1 {}

impl ProofVerifierV1 for TestOnlyProofVerifierV1 {
    fn proof_suite_id(&self) -> &'static str {
        TEST_ONLY_SUITE_ID
    }

    fn verify(
        &self,
        statement: &ProofStatementV1,
        proof_bytes: &[u8],
    ) -> Result<VerifiedProofV1, ProtocolError> {
        if statement.proof_suite_id() != TEST_ONLY_SUITE_ID {
            return Err(ProtocolError::new(
                ValidationCode::InvalidData,
                "test-only verifier received a different proof suite",
            ));
        }

        let expected = Self::proof_for(statement)?;

        if proof_bytes != expected {
            return Err(ProtocolError::new(
                ValidationCode::InvalidData,
                "test-only proof does not authenticate the statement",
            ));
        }

        Ok(VerifiedProofV1::new(
            statement.clone(),
            self.nullifier.clone(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tari_cc_private_ballot_protocol::{
        BallotPayloadHash, ElectionScope, ManifestHash, PROTOCOL_VERSION_V1, ProofStatementV1Input,
        RegistryCommitment,
    };

    fn statement(payload_byte: u8) -> ProofStatementV1 {
        let Ok(statement) = ProofStatementV1::new(ProofStatementV1Input {
            protocol_version: PROTOCOL_VERSION_V1,
            proof_suite_id: TEST_ONLY_SUITE_ID.to_owned(),
            manifest_hash: ManifestHash::new([1_u8; 32]),
            election_scope: ElectionScope::new([2_u8; 32]),
            registry_commitment: RegistryCommitment::new([3_u8; 32]),
            ballot_payload_hash: BallotPayloadHash::new([payload_byte; 32]),
            ballot_kind_id: "TEST_KIND".to_owned(),
            ballot_confidentiality_id: "PUBLIC".to_owned(),
        }) else {
            panic!("test proof statement must be valid");
        };

        statement
    }

    #[test]
    fn matching_test_only_proof_returns_verified_result() {
        let statement = statement(4);

        let Ok(verifier) = TestOnlyProofVerifierV1::new(b"nf-1".to_vec()) else {
            panic!("test verifier must be valid");
        };

        let Ok(proof) = TestOnlyProofVerifierV1::proof_for(&statement) else {
            panic!("test proof construction should succeed");
        };

        let Ok(result) = verifier.verify(&statement, &proof) else {
            panic!("matching test proof should verify");
        };

        assert_eq!(result.statement(), &statement);
        assert_eq!(result.nullifier().as_bytes(), b"nf-1");
    }

    #[test]
    fn proof_for_one_statement_is_rejected_for_another() {
        let first = statement(4);
        let second = statement(9);

        let Ok(verifier) = TestOnlyProofVerifierV1::new(b"nf-2".to_vec()) else {
            panic!("test verifier must be valid");
        };

        let Ok(proof) = TestOnlyProofVerifierV1::proof_for(&first) else {
            panic!("test proof construction should succeed");
        };

        assert!(verifier.verify(&second, &proof).is_err());
    }

    #[test]
    fn invalid_test_nullifier_is_rejected_before_verification() {
        assert!(TestOnlyProofVerifierV1::new(Vec::new()).is_err());
    }
}
