#![forbid(unsafe_code)]

//! Deterministic non-binding approval tallying.

use std::collections::BTreeMap;

use tari_cc_private_ballot_ballot::{ApprovalBallotPayload, CandidateId, CandidateSet};
use tari_cc_private_ballot_protocol::{ProtocolError, ValidationCode};

/// One candidate approval count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateCount {
    candidate_id: CandidateId,
    approvals: u64,
}

impl CandidateCount {
    /// Returns the stable candidate identifier.
    #[must_use]
    pub const fn candidate_id(&self) -> &CandidateId {
        &self.candidate_id
    }

    /// Returns the number of approvals.
    #[must_use]
    pub const fn approvals(&self) -> u64 {
        self.approvals
    }
}

/// Explicit result for the highest approval count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeadingResult {
    NoApprovals,
    SingleLeader {
        candidate_id: CandidateId,
        approvals: u64,
    },
    Tie {
        candidate_ids: Vec<CandidateId>,
        approvals: u64,
    },
}

/// Deterministic tally for accepted approval ballots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalTally {
    accepted_ballots: u64,
    abstentions: u64,
    counts: Vec<CandidateCount>,
}

impl ApprovalTally {
    /// Tallies already accepted ballots against one frozen candidate set.
    pub fn from_ballots<'a>(
        candidates: &CandidateSet,
        ballots: impl IntoIterator<Item = &'a ApprovalBallotPayload>,
    ) -> Result<Self, ProtocolError> {
        let mut counts = BTreeMap::<CandidateId, u64>::new();

        for candidate in candidates.candidates() {
            counts.insert(candidate.id().clone(), 0);
        }

        let mut accepted_ballots = 0_u64;
        let mut abstentions = 0_u64;

        for ballot in ballots {
            accepted_ballots = accepted_ballots.checked_add(1).ok_or_else(|| {
                ProtocolError::new(
                    ValidationCode::InvalidData,
                    "accepted ballot count overflow",
                )
            })?;

            if ballot.is_abstention() {
                abstentions = abstentions.checked_add(1).ok_or_else(|| {
                    ProtocolError::new(ValidationCode::InvalidData, "abstention count overflow")
                })?;
            }

            for candidate_id in ballot.selections() {
                let Some(current) = counts.get_mut(candidate_id) else {
                    return Err(ProtocolError::new(
                        ValidationCode::UnknownCandidateId,
                        "accepted ballot references a different candidate set",
                    ));
                };

                *current = current.checked_add(1).ok_or_else(|| {
                    ProtocolError::new(
                        ValidationCode::InvalidData,
                        "candidate approval count overflow",
                    )
                })?;
            }
        }

        let counts = counts
            .into_iter()
            .map(|(candidate_id, approvals)| CandidateCount {
                candidate_id,
                approvals,
            })
            .collect();

        Ok(Self {
            accepted_ballots,
            abstentions,
            counts,
        })
    }

    /// Returns the number of accepted ballots included in the tally.
    #[must_use]
    pub const fn accepted_ballots(&self) -> u64 {
        self.accepted_ballots
    }

    /// Returns the number of accepted abstentions.
    #[must_use]
    pub const fn abstentions(&self) -> u64 {
        self.abstentions
    }

    /// Returns candidate counts in canonical candidate-ID order.
    #[must_use]
    pub fn counts(&self) -> &[CandidateCount] {
        &self.counts
    }

    /// Reports a single leader, an unresolved tie, or no approvals.
    #[must_use]
    pub fn leading_result(&self) -> LeadingResult {
        let maximum = self.counts.iter().map(CandidateCount::approvals).max();

        let Some(maximum) = maximum else {
            return LeadingResult::NoApprovals;
        };

        if maximum == 0 {
            return LeadingResult::NoApprovals;
        }

        let candidate_ids: Vec<CandidateId> = self
            .counts
            .iter()
            .filter(|count| count.approvals == maximum)
            .map(|count| count.candidate_id.clone())
            .collect();

        if candidate_ids.len() == 1 {
            return LeadingResult::SingleLeader {
                candidate_id: candidate_ids[0].clone(),
                approvals: maximum,
            };
        }

        LeadingResult::Tie {
            candidate_ids,
            approvals: maximum,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ApprovalTally, LeadingResult};
    use tari_cc_private_ballot_ballot::{
        ApprovalBallotPayload, ApprovalLimits, CandidateDefinition, CandidateId, CandidateSet,
    };
    use tari_cc_private_ballot_protocol::ValidationCode;

    fn candidate_id(bytes: &[u8]) -> CandidateId {
        let Ok(id) = CandidateId::new(bytes.to_vec()) else {
            panic!("test candidate ID must be valid");
        };

        id
    }

    fn candidate(identifier: &[u8], name: &str) -> CandidateDefinition {
        let Ok(candidate) = CandidateDefinition::new(candidate_id(identifier), name.to_owned())
        else {
            panic!("test candidate must be valid");
        };

        candidate
    }

    fn candidate_set() -> CandidateSet {
        let Ok(candidates) = CandidateSet::new(vec![
            candidate(b"candidate-c", "Candidate C"),
            candidate(b"candidate-a", "Candidate A"),
            candidate(b"candidate-b", "Candidate B"),
        ]) else {
            panic!("test candidate set must be valid");
        };

        candidates
    }

    fn limits(minimum: usize, maximum: usize, allow_abstention: bool) -> ApprovalLimits {
        let Ok(limits) = ApprovalLimits::new(minimum, maximum, allow_abstention) else {
            panic!("test limits must be valid");
        };

        limits
    }

    fn payload(
        candidates: &CandidateSet,
        selections: Vec<CandidateId>,
        ballot_limits: ApprovalLimits,
    ) -> ApprovalBallotPayload {
        let Ok(payload) = ApprovalBallotPayload::new(selections, candidates, ballot_limits) else {
            panic!("test payload must be valid");
        };

        payload
    }

    #[test]
    fn counts_include_zero_approval_candidates_in_canonical_order() {
        let candidates = candidate_set();
        let ballots = vec![payload(
            &candidates,
            vec![candidate_id(b"candidate-b")],
            limits(1, 2, false),
        )];

        let Ok(tally) = ApprovalTally::from_ballots(&candidates, &ballots) else {
            panic!("tally should succeed");
        };

        let results: Vec<(&[u8], u64)> = tally
            .counts()
            .iter()
            .map(|count| (count.candidate_id().as_bytes(), count.approvals()))
            .collect();

        assert_eq!(
            results,
            vec![
                (b"candidate-a".as_slice(), 0),
                (b"candidate-b".as_slice(), 1),
                (b"candidate-c".as_slice(), 0),
            ]
        );
    }

    #[test]
    fn approvals_and_abstentions_are_counted() {
        let candidates = candidate_set();
        let ballots = vec![
            payload(
                &candidates,
                vec![candidate_id(b"candidate-a"), candidate_id(b"candidate-b")],
                limits(1, 2, true),
            ),
            payload(&candidates, Vec::new(), limits(1, 2, true)),
        ];

        let Ok(tally) = ApprovalTally::from_ballots(&candidates, &ballots) else {
            panic!("tally should succeed");
        };

        assert_eq!(tally.accepted_ballots(), 2);
        assert_eq!(tally.abstentions(), 1);
    }

    #[test]
    fn single_leader_is_reported() {
        let candidates = candidate_set();
        let ballots = vec![
            payload(
                &candidates,
                vec![candidate_id(b"candidate-a")],
                limits(1, 2, false),
            ),
            payload(
                &candidates,
                vec![candidate_id(b"candidate-a"), candidate_id(b"candidate-b")],
                limits(1, 2, false),
            ),
        ];

        let Ok(tally) = ApprovalTally::from_ballots(&candidates, &ballots) else {
            panic!("tally should succeed");
        };

        assert!(matches!(
            tally.leading_result(),
            LeadingResult::SingleLeader { candidate_id, approvals: 2 }
                if candidate_id.as_bytes() == b"candidate-a"
        ));
    }

    #[test]
    fn unresolved_top_count_is_reported_as_a_tie() {
        let candidates = candidate_set();
        let ballots = vec![
            payload(
                &candidates,
                vec![candidate_id(b"candidate-a")],
                limits(1, 1, false),
            ),
            payload(
                &candidates,
                vec![candidate_id(b"candidate-b")],
                limits(1, 1, false),
            ),
        ];

        let Ok(tally) = ApprovalTally::from_ballots(&candidates, &ballots) else {
            panic!("tally should succeed");
        };

        let LeadingResult::Tie {
            candidate_ids,
            approvals,
        } = tally.leading_result()
        else {
            panic!("equal leaders must be reported as a tie");
        };

        let ids: Vec<&[u8]> = candidate_ids.iter().map(CandidateId::as_bytes).collect();

        assert_eq!(approvals, 1);
        assert_eq!(ids, vec![b"candidate-a", b"candidate-b"]);
    }

    #[test]
    fn no_approvals_are_reported_without_inventing_a_winner() {
        let candidates = candidate_set();
        let ballots = vec![payload(&candidates, Vec::new(), limits(1, 2, true))];

        let Ok(tally) = ApprovalTally::from_ballots(&candidates, &ballots) else {
            panic!("tally should succeed");
        };

        assert_eq!(tally.leading_result(), LeadingResult::NoApprovals);
    }

    #[test]
    fn ballot_from_a_different_candidate_set_is_rejected() {
        let candidates = candidate_set();

        let Ok(other_candidates) =
            CandidateSet::new(vec![candidate(b"candidate-z", "Candidate Z")])
        else {
            panic!("other candidate set must be valid");
        };

        let ballots = vec![payload(
            &other_candidates,
            vec![candidate_id(b"candidate-z")],
            limits(1, 1, false),
        )];

        let result = ApprovalTally::from_ballots(&candidates, &ballots);

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::UnknownCandidateId
        ));
    }
}
