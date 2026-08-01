#![forbid(unsafe_code)]

//! Verified-ballot acceptance and duplicate-nullifier handling.

mod proof_statement;
mod proof_verification;

pub use proof_statement::reconstruct_approval_proof_statement;
pub use proof_verification::{VerifiedApprovalBallotV1, verify_approval_proof};

use std::collections::BTreeSet;

use tari_cc_private_ballot_ballot::ApprovalBallotPayload;
use tari_cc_private_ballot_crypto::{VerifiedNullifier, VerifiedProofV1};
use tari_cc_private_ballot_protocol::{ProtocolError, ValidationCode};

/// One accepted ballot together with its successful proof result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedBallot {
    verified_proof: VerifiedProofV1,
    payload: ApprovalBallotPayload,
}

impl AcceptedBallot {
    /// Returns the complete successful proof-verification result.
    #[must_use]
    pub const fn verified_proof(&self) -> &VerifiedProofV1 {
        &self.verified_proof
    }

    /// Returns the proof-authenticated nullifier.
    #[must_use]
    pub const fn verified_nullifier(&self) -> &VerifiedNullifier {
        self.verified_proof.nullifier()
    }

    /// Returns the authenticated nullifier bytes.
    #[must_use]
    pub fn election_scoped_nullifier(&self) -> &[u8] {
        self.verified_nullifier().as_bytes()
    }

    /// Returns the exact payload authenticated by the proof statement.
    #[must_use]
    pub const fn payload(&self) -> &ApprovalBallotPayload {
        &self.payload
    }
}

/// Acceptance-order ledger implementing first-valid-ballot-counts.
#[derive(Debug, Default)]
pub struct BallotAcceptanceLedger {
    seen_nullifiers: BTreeSet<VerifiedNullifier>,
    accepted_ballots: Vec<AcceptedBallot>,
}

impl BallotAcceptanceLedger {
    /// Creates an empty acceptance ledger.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            seen_nullifiers: BTreeSet::new(),
            accepted_ballots: Vec::new(),
        }
    }

    /// Accepts a proof-authenticated ballot if its nullifier is new.
    pub fn accept_verified(
        &mut self,
        ballot: VerifiedApprovalBallotV1,
    ) -> Result<(), ProtocolError> {
        let (verified_proof, payload) = ballot.into_parts();
        let nullifier = verified_proof.nullifier().clone();

        if !self.seen_nullifiers.insert(nullifier) {
            return Err(ProtocolError::new(
                ValidationCode::DuplicateNullifier,
                "the first valid ballot for this nullifier already counts",
            ));
        }

        self.accepted_ballots.push(AcceptedBallot {
            verified_proof,
            payload,
        });

        Ok(())
    }

    /// Returns accepted ballots in acceptance order.
    #[must_use]
    pub fn accepted_ballots(&self) -> &[AcceptedBallot] {
        &self.accepted_ballots
    }

    /// Returns the number of accepted ballots.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.accepted_ballots.len()
    }

    /// Returns whether no ballot has been accepted.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.accepted_ballots.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BallotAcceptanceLedger, VerifiedApprovalBallotV1, reconstruct_approval_proof_statement,
        verify_approval_proof,
    };
    use tari_cc_private_ballot_ballot::{
        ApprovalBallotPayload, ApprovalLimits, BallotConfidentialityV1, BallotKindV1,
        CandidateDefinition, CandidateId, CandidateSet, ElectionId, ElectionManifestV1,
        ElectionManifestV1Input,
    };
    use tari_cc_private_ballot_crypto::test_only_verifier::TestOnlyProofVerifierV1;
    use tari_cc_private_ballot_protocol::{
        CandidateSetCommitment, PROTOCOL_VERSION_V1, RegistryCommitment, TEST_ONLY_SUITE_ID,
        ValidationCode, test_only::TestOnlyDeterministicHasher,
    };

    fn candidate_id(bytes: &[u8]) -> CandidateId {
        let Ok(id) = CandidateId::new(bytes.to_vec()) else {
            panic!("test candidate ID must be valid");
        };

        id
    }

    fn candidate_set() -> CandidateSet {
        let Ok(candidate) =
            CandidateDefinition::new(candidate_id(b"candidate-a"), "Candidate A".to_owned())
        else {
            panic!("test candidate must be valid");
        };

        let Ok(candidates) = CandidateSet::new(vec![candidate]) else {
            panic!("test candidate set must be valid");
        };

        candidates
    }

    fn approval_limits() -> ApprovalLimits {
        let Ok(limits) = ApprovalLimits::new(1, 1, false) else {
            panic!("test limits must be valid");
        };

        limits
    }

    fn manifest() -> ElectionManifestV1 {
        let Ok(election_id) = ElectionId::new(b"ledger-election".to_vec()) else {
            panic!("test election ID must be valid");
        };

        let Ok(manifest) = ElectionManifestV1::new(ElectionManifestV1Input {
            protocol_version: PROTOCOL_VERSION_V1,
            election_id,
            ballot_kind: BallotKindV1::NonBindingApprovalPilot,
            ballot_confidentiality: BallotConfidentialityV1::Public,
            registry_commitment: RegistryCommitment::new([1_u8; 32]),
            candidate_set_commitment: CandidateSetCommitment::new([2_u8; 32]),
            proof_suite_id: TEST_ONLY_SUITE_ID.to_owned(),
            approval_limits: approval_limits(),
            governance_source_revision: "revision-1".to_owned(),
        }) else {
            panic!("test manifest must be valid");
        };

        manifest
    }

    fn payload() -> ApprovalBallotPayload {
        let candidates = candidate_set();

        let Ok(payload) = ApprovalBallotPayload::new(
            vec![candidate_id(b"candidate-a")],
            &candidates,
            approval_limits(),
        ) else {
            panic!("test payload must be valid");
        };

        payload
    }

    fn verified_ballot(nullifier: &[u8]) -> VerifiedApprovalBallotV1 {
        let provider = TestOnlyDeterministicHasher;
        let manifest = manifest();
        let payload = payload();

        let Ok(statement) = reconstruct_approval_proof_statement(&manifest, &payload, &provider)
        else {
            panic!("statement reconstruction should succeed");
        };

        let Ok(proof) = TestOnlyProofVerifierV1::proof_for(&statement) else {
            panic!("test proof construction should succeed");
        };

        let Ok(verifier) = TestOnlyProofVerifierV1::new(nullifier.to_vec()) else {
            panic!("test verifier must be valid");
        };

        let Ok(ballot) = verify_approval_proof(&manifest, &payload, &proof, &provider, &verifier)
        else {
            panic!("test ballot verification should succeed");
        };

        ballot
    }

    #[test]
    fn first_valid_ballot_is_accepted() {
        let mut ledger = BallotAcceptanceLedger::new();

        let result = ledger.accept_verified(verified_ballot(b"nullifier-a"));

        assert!(result.is_ok());
        assert_eq!(ledger.len(), 1);
        assert_eq!(
            ledger.accepted_ballots()[0].election_scoped_nullifier(),
            b"nullifier-a"
        );
    }

    #[test]
    fn duplicate_nullifier_is_rejected_without_replacing_first_ballot() {
        let mut ledger = BallotAcceptanceLedger::new();

        let first = ledger.accept_verified(verified_ballot(b"nullifier-a"));

        assert!(first.is_ok());

        let duplicate = ledger.accept_verified(verified_ballot(b"nullifier-a"));

        assert!(matches!(
            duplicate,
            Err(error)
                if error.code() == ValidationCode::DuplicateNullifier
        ));

        assert_eq!(ledger.len(), 1);
        assert_eq!(
            ledger.accepted_ballots()[0].election_scoped_nullifier(),
            b"nullifier-a"
        );
    }

    #[test]
    fn distinct_nullifiers_preserve_acceptance_order() {
        let mut ledger = BallotAcceptanceLedger::new();

        assert!(
            ledger
                .accept_verified(verified_ballot(b"nullifier-b"))
                .is_ok()
        );

        assert!(
            ledger
                .accept_verified(verified_ballot(b"nullifier-a"))
                .is_ok()
        );

        assert_eq!(
            ledger.accepted_ballots()[0].election_scoped_nullifier(),
            b"nullifier-b"
        );

        assert_eq!(
            ledger.accepted_ballots()[1].election_scoped_nullifier(),
            b"nullifier-a"
        );
    }

    #[test]
    fn accepted_ballot_preserves_verified_proof_and_payload() {
        let mut ledger = BallotAcceptanceLedger::new();
        let ballot = verified_ballot(b"nullifier-a");
        let expected_statement = ballot.statement().clone();
        let expected_payload = ballot.payload().clone();

        assert!(ledger.accept_verified(ballot).is_ok());

        let accepted = &ledger.accepted_ballots()[0];

        assert_eq!(accepted.verified_proof().statement(), &expected_statement);
        assert_eq!(accepted.payload(), &expected_payload);
    }
}
