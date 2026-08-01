//! Explicitly non-anonymous proof verifier for protocol tests only.

use tari_cc_private_ballot_protocol::{
    MAX_NULLIFIER_BYTES, MAX_PROOF_BYTES, ProofStatementV1, ProtocolError, TEST_ONLY_SUITE_ID,
    ValidationCode,
};

use crate::{ProofVerifierV1, VerifiedNullifier, VerifiedProofV1, verification::Sealed};

/// Marker embedded in every test-only proof.
pub const TEST_ONLY_PROOF_MARKER: &str = "TEST_ONLY_NOT_ANONYMOUS_NOT_FOR_BINDING_ELECTIONS";

const SELF_CONTAINED_NULLIFIER_LENGTH_BYTES: usize = 2;

/// Deterministic and forgeable verifier used only for plumbing tests.
///
/// This is not anonymous and must never be used for a binding election.
/// Legacy callers may still supply an external fake nullifier. New archive
/// replay code must use [`Self::replay`] and
/// [`Self::proof_for_with_nullifier`].
#[derive(Debug, Clone)]
pub struct TestOnlyProofVerifierV1 {
    legacy_nullifier: Option<VerifiedNullifier>,
}

impl TestOnlyProofVerifierV1 {
    /// Creates the compatibility verifier with an external fake nullifier.
    pub fn new(nullifier: Vec<u8>) -> Result<Self, ProtocolError> {
        Ok(Self {
            legacy_nullifier: Some(VerifiedNullifier::new(nullifier)?),
        })
    }

    /// Creates a verifier that accepts only self-contained test proofs.
    #[must_use]
    pub const fn replay() -> Self {
        Self {
            legacy_nullifier: None,
        }
    }

    /// Creates the legacy proof used by existing plumbing tests.
    pub fn proof_for(statement: &ProofStatementV1) -> Result<Vec<u8>, ProtocolError> {
        let transcript = statement.transcript_bytes()?;
        let marker = TEST_ONLY_PROOF_MARKER.as_bytes();

        let Some(total_length) = marker.len().checked_add(transcript.len()) else {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "legacy test-only proof length overflowed",
            ));
        };

        if total_length > MAX_PROOF_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "legacy test-only proof exceeds the protocol size limit",
            ));
        }

        let mut proof = Vec::with_capacity(total_length);
        proof.extend_from_slice(marker);
        proof.extend_from_slice(&transcript);
        Ok(proof)
    }

    /// Creates a self-contained forgeable proof envelope.
    ///
    /// Format:
    /// `marker || nullifier_length_u16_be || nullifier || statement_transcript`
    pub fn proof_for_with_nullifier(
        statement: &ProofStatementV1,
        nullifier: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        let verified_nullifier = VerifiedNullifier::new(nullifier.to_vec())?;
        let nullifier_bytes = verified_nullifier.as_bytes();
        let nullifier_length = u16::try_from(nullifier_bytes.len()).map_err(|_| {
            ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "test-only nullifier length exceeds the envelope field",
            )
        })?;

        let transcript = statement.transcript_bytes()?;
        let marker = TEST_ONLY_PROOF_MARKER.as_bytes();

        let Some(total_length) = marker
            .len()
            .checked_add(SELF_CONTAINED_NULLIFIER_LENGTH_BYTES)
            .and_then(|length| length.checked_add(nullifier_bytes.len()))
            .and_then(|length| length.checked_add(transcript.len()))
        else {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "self-contained test-only proof length overflowed",
            ));
        };

        if total_length > MAX_PROOF_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "self-contained test-only proof exceeds the protocol size limit",
            ));
        }

        let mut proof = Vec::with_capacity(total_length);
        proof.extend_from_slice(marker);
        proof.extend_from_slice(&nullifier_length.to_be_bytes());
        proof.extend_from_slice(nullifier_bytes);
        proof.extend_from_slice(&transcript);
        Ok(proof)
    }

    fn verify_self_contained(
        statement: &ProofStatementV1,
        proof_bytes: &[u8],
        transcript: &[u8],
    ) -> Result<VerifiedProofV1, ProtocolError> {
        let marker_length = TEST_ONLY_PROOF_MARKER.len();
        let Some(length_end) = marker_length.checked_add(SELF_CONTAINED_NULLIFIER_LENGTH_BYTES)
        else {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "test-only proof offset overflowed",
            ));
        };

        if proof_bytes.len() < length_end {
            return Err(ProtocolError::new(
                ValidationCode::InvalidData,
                "self-contained test-only proof is truncated",
            ));
        }

        let nullifier_length = usize::from(u16::from_be_bytes([
            proof_bytes[marker_length],
            proof_bytes[marker_length + 1],
        ]));

        if nullifier_length > MAX_NULLIFIER_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "self-contained test-only nullifier exceeds the protocol limit",
            ));
        }

        let Some(nullifier_end) = length_end.checked_add(nullifier_length) else {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "self-contained test-only nullifier offset overflowed",
            ));
        };

        let Some(expected_length) = nullifier_end.checked_add(transcript.len()) else {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "self-contained test-only proof length overflowed",
            ));
        };

        if proof_bytes.len() != expected_length {
            return Err(ProtocolError::new(
                ValidationCode::InvalidData,
                "self-contained test-only proof has an invalid length",
            ));
        }

        let nullifier = VerifiedNullifier::new(proof_bytes[length_end..nullifier_end].to_vec())?;

        if &proof_bytes[nullifier_end..] != transcript {
            return Err(ProtocolError::new(
                ValidationCode::InvalidData,
                "test-only proof does not authenticate the statement",
            ));
        }

        Ok(VerifiedProofV1::new(statement.clone(), nullifier))
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

        if proof_bytes.len() > MAX_PROOF_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "test-only proof exceeds the protocol size limit",
            ));
        }

        if !proof_bytes.starts_with(TEST_ONLY_PROOF_MARKER.as_bytes()) {
            return Err(ProtocolError::new(
                ValidationCode::InvalidData,
                "test-only proof marker is invalid",
            ));
        }

        let transcript = statement.transcript_bytes()?;
        let legacy_expected = Self::proof_for(statement)?;

        if proof_bytes == legacy_expected {
            let Some(nullifier) = self.legacy_nullifier.clone() else {
                return Err(ProtocolError::new(
                    ValidationCode::InvalidData,
                    "legacy test-only proof has no replayable nullifier",
                ));
            };

            return Ok(VerifiedProofV1::new(statement.clone(), nullifier));
        }

        if self.legacy_nullifier.is_some() {
            return Err(ProtocolError::new(
                ValidationCode::InvalidData,
                "legacy test-only proof does not authenticate the statement",
            ));
        }

        Self::verify_self_contained(statement, proof_bytes, &transcript)
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
            panic!("test proof construction must succeed");
        };
        let Ok(result) = verifier.verify(&statement, &proof) else {
            panic!("matching test-only proof must verify");
        };

        assert_eq!(result.statement(), &statement);
        assert_eq!(result.nullifier().as_bytes(), b"nf-1");
    }

    #[test]
    fn proof_for_one_statement_is_rejected_for_another() {
        let first = statement(4);
        let second = statement(5);
        let Ok(verifier) = TestOnlyProofVerifierV1::new(b"nf-2".to_vec()) else {
            panic!("test verifier must be valid");
        };
        let Ok(proof) = TestOnlyProofVerifierV1::proof_for(&first) else {
            panic!("test proof construction must succeed");
        };

        assert!(verifier.verify(&second, &proof).is_err());
    }

    #[test]
    fn invalid_test_nullifier_is_rejected_before_verification() {
        assert!(TestOnlyProofVerifierV1::new(Vec::new()).is_err());
    }

    #[test]
    fn self_contained_proof_replays_without_external_nullifier() {
        let statement = statement(6);
        let verifier = TestOnlyProofVerifierV1::replay();
        let Ok(proof) =
            TestOnlyProofVerifierV1::proof_for_with_nullifier(&statement, b"archived-nullifier")
        else {
            panic!("self-contained test proof construction must succeed");
        };
        let Ok(result) = verifier.verify(&statement, &proof) else {
            panic!("self-contained test proof must replay");
        };

        assert_eq!(result.statement(), &statement);
        assert_eq!(result.nullifier().as_bytes(), b"archived-nullifier");
    }

    #[test]
    fn replay_verifier_rejects_legacy_proof_without_external_nullifier() {
        let statement = statement(7);
        let verifier = TestOnlyProofVerifierV1::replay();
        let Ok(proof) = TestOnlyProofVerifierV1::proof_for(&statement) else {
            panic!("legacy test proof construction must succeed");
        };

        assert!(matches!(
            verifier.verify(&statement, &proof),
            Err(error) if error.code() == ValidationCode::InvalidData
        ));
    }

    #[test]
    fn self_contained_proof_for_another_statement_is_rejected() {
        let first = statement(8);
        let second = statement(9);
        let verifier = TestOnlyProofVerifierV1::replay();
        let Ok(proof) =
            TestOnlyProofVerifierV1::proof_for_with_nullifier(&first, b"statement-bound-nullifier")
        else {
            panic!("self-contained test proof construction must succeed");
        };

        assert!(matches!(
            verifier.verify(&second, &proof),
            Err(error) if error.code() == ValidationCode::InvalidData
        ));
    }

    #[test]
    fn empty_self_contained_nullifier_is_rejected() {
        assert!(matches!(
            TestOnlyProofVerifierV1::proof_for_with_nullifier(&statement(10), &[]),
            Err(error) if error.code() == ValidationCode::EmptyNullifier
        ));
    }

    #[test]
    fn oversized_self_contained_nullifier_is_rejected() {
        assert!(matches!(
            TestOnlyProofVerifierV1::proof_for_with_nullifier(
                &statement(11),
                &[0_u8; MAX_NULLIFIER_BYTES + 1],
            ),
            Err(error) if error.code() == ValidationCode::ProtocolLimitExceeded
        ));
    }

    #[test]
    fn truncated_self_contained_proof_is_rejected() {
        let statement = statement(12);
        let verifier = TestOnlyProofVerifierV1::replay();
        let Ok(mut proof) =
            TestOnlyProofVerifierV1::proof_for_with_nullifier(&statement, b"truncated-nullifier")
        else {
            panic!("self-contained test proof construction must succeed");
        };

        assert!(proof.pop().is_some());

        assert!(matches!(
            verifier.verify(&statement, &proof),
            Err(error) if error.code() == ValidationCode::InvalidData
        ));
    }
}
