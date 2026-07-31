#![forbid(unsafe_code)]

//! Verified-ballot acceptance and duplicate-nullifier handling.

use std::collections::BTreeSet;

use tari_cc_private_ballot_ballot::ApprovalBallotPayload;
use tari_cc_private_ballot_crypto::VerifiedMembership;
use tari_cc_private_ballot_protocol::{ProtocolError, ValidationCode};

/// One accepted, already verified ballot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedBallot {
    election_scoped_nullifier: Vec<u8>,
    payload: ApprovalBallotPayload,
}

impl AcceptedBallot {
    /// Returns the election-scoped nullifier.
    #[must_use]
    pub fn election_scoped_nullifier(&self) -> &[u8] {
        &self.election_scoped_nullifier
    }

    /// Returns the validated approval payload.
    #[must_use]
    pub const fn payload(&self) -> &ApprovalBallotPayload {
        &self.payload
    }
}

/// Acceptance-order ledger implementing first-valid-ballot-counts.
#[derive(Debug, Default)]
pub struct BallotAcceptanceLedger {
    seen_nullifiers: BTreeSet<Vec<u8>>,
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

    /// Accepts an already verified ballot if its nullifier is new.
    pub fn accept_verified(
        &mut self,
        membership: VerifiedMembership,
        payload: ApprovalBallotPayload,
    ) -> Result<(), ProtocolError> {
        let nullifier = membership.election_scoped_nullifier().to_vec();

        if nullifier.is_empty() {
            return Err(ProtocolError::new(
                ValidationCode::EmptyNullifier,
                "election-scoped nullifier must not be empty",
            ));
        }

        if !self.seen_nullifiers.insert(nullifier.clone()) {
            return Err(ProtocolError::new(
                ValidationCode::DuplicateNullifier,
                "the first valid ballot for this nullifier already counts",
            ));
        }

        self.accepted_ballots.push(AcceptedBallot {
            election_scoped_nullifier: nullifier,
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
    use super::BallotAcceptanceLedger;
    use tari_cc_private_ballot_ballot::{
        ApprovalBallotPayload, ApprovalLimits, CandidateDefinition, CandidateId, CandidateSet,
    };
    use tari_cc_private_ballot_crypto::VerifiedMembership;
    use tari_cc_private_ballot_protocol::ValidationCode;

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

    fn payload() -> ApprovalBallotPayload {
        let candidates = candidate_set();

        let Ok(limits) = ApprovalLimits::new(1, 1, false) else {
            panic!("test limits must be valid");
        };

        let Ok(payload) =
            ApprovalBallotPayload::new(vec![candidate_id(b"candidate-a")], &candidates, limits)
        else {
            panic!("test payload must be valid");
        };

        payload
    }

    fn membership(nullifier: &[u8]) -> VerifiedMembership {
        VerifiedMembership::new(nullifier.to_vec())
    }

    #[test]
    fn first_valid_ballot_is_accepted() {
        let mut ledger = BallotAcceptanceLedger::new();

        let result = ledger.accept_verified(membership(b"nullifier-a"), payload());

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

        let first = ledger.accept_verified(membership(b"nullifier-a"), payload());

        assert!(first.is_ok());

        let duplicate = ledger.accept_verified(membership(b"nullifier-a"), payload());

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
                .accept_verified(membership(b"nullifier-b"), payload())
                .is_ok()
        );

        assert!(
            ledger
                .accept_verified(membership(b"nullifier-a"), payload())
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
    fn empty_nullifier_is_rejected() {
        let mut ledger = BallotAcceptanceLedger::new();
        let result = ledger.accept_verified(membership(b""), payload());

        assert!(matches!(
            result,
            Err(error) if error.code() == ValidationCode::EmptyNullifier
        ));

        assert!(ledger.is_empty());
    }
}

mod proof_statement;
pub use proof_statement::reconstruct_approval_proof_statement;

mod proof_verification;
pub use proof_verification::verify_approval_proof;
