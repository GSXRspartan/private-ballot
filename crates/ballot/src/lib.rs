#![forbid(unsafe_code)]

//! Candidate and non-binding approval-ballot models.

mod canonical;
mod lifecycle;
mod manifest;
mod manifest_canonical;
mod manifest_scope;
mod package;

pub use lifecycle::{ElectionLifecycleStateV1, ElectionLifecycleV1};
pub use manifest::{
    BallotConfidentialityV1, BallotKindV1, ElectionId, ElectionManifestV1, ElectionManifestV1Input,
};
pub use package::{BallotPackageEnvelopeV1, BallotPackageV1, BallotPackageV1Input};

use tari_cc_private_ballot_protocol::{
    MAX_CANDIDATE_DISPLAY_NAME_BYTES, MAX_CANDIDATE_ID_BYTES, MAX_CANDIDATES, ProtocolError,
    ValidationCode,
};

/// Stable machine candidate identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CandidateId(Vec<u8>);

impl CandidateId {
    /// Creates a non-empty machine identifier.
    pub fn new(bytes: Vec<u8>) -> Result<Self, ProtocolError> {
        if bytes.is_empty() {
            return Err(ProtocolError::new(
                ValidationCode::EmptyCandidateId,
                "candidate identifier must not be empty",
            ));
        }

        if bytes.len() > MAX_CANDIDATE_ID_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "candidate identifier exceeds the protocol size limit",
            ));
        }

        Ok(Self(bytes))
    }

    /// Returns the canonical machine-identifier bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Candidate metadata with a stable ID separate from its display name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateDefinition {
    id: CandidateId,
    display_name: String,
}

impl CandidateDefinition {
    /// Creates a candidate definition.
    pub fn new(id: CandidateId, display_name: String) -> Result<Self, ProtocolError> {
        if display_name.trim().is_empty() {
            return Err(ProtocolError::new(
                ValidationCode::EmptyCandidateDisplayName,
                "candidate display name must not be empty",
            ));
        }

        if display_name.len() > MAX_CANDIDATE_DISPLAY_NAME_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "candidate display name exceeds the protocol size limit",
            ));
        }

        Ok(Self { id, display_name })
    }

    /// Returns the stable machine identifier.
    #[must_use]
    pub const fn id(&self) -> &CandidateId {
        &self.id
    }

    /// Returns the human-facing display name.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
}

/// Canonically ordered set of candidates for one election.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateSet {
    candidates: Vec<CandidateDefinition>,
}

impl CandidateSet {
    /// Sorts candidates by ID and rejects an empty or duplicate set.
    pub fn new(mut candidates: Vec<CandidateDefinition>) -> Result<Self, ProtocolError> {
        if candidates.is_empty() {
            return Err(ProtocolError::new(
                ValidationCode::EmptyCandidateSet,
                "candidate set must not be empty",
            ));
        }

        if candidates.len() > MAX_CANDIDATES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "candidate count exceeds the protocol limit",
            ));
        }

        candidates.sort_by(|left, right| left.id.cmp(&right.id));

        if candidates.windows(2).any(|pair| pair[0].id == pair[1].id) {
            return Err(ProtocolError::new(
                ValidationCode::DuplicateCandidateId,
                "candidate set contains a duplicate candidate identifier",
            ));
        }

        Ok(Self { candidates })
    }

    /// Returns candidates in canonical machine-ID order.
    #[must_use]
    pub fn candidates(&self) -> &[CandidateDefinition] {
        &self.candidates
    }

    /// Returns the number of candidates.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.candidates.len()
    }

    /// Returns whether the candidate set is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    /// Returns whether a candidate ID belongs to this election.
    #[must_use]
    pub fn contains(&self, id: &CandidateId) -> bool {
        self.candidates
            .binary_search_by(|candidate| candidate.id.cmp(id))
            .is_ok()
    }
}

/// Selection-count rules for a non-binding approval poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalLimits {
    minimum: usize,
    maximum: usize,
    allow_abstention: bool,
}

impl ApprovalLimits {
    /// Creates internally consistent selection limits.
    pub fn new(
        minimum: usize,
        maximum: usize,
        allow_abstention: bool,
    ) -> Result<Self, ProtocolError> {
        if minimum > maximum {
            return Err(ProtocolError::new(
                ValidationCode::InvalidSelectionLimits,
                "minimum selections exceed maximum selections",
            ));
        }

        Ok(Self {
            minimum,
            maximum,
            allow_abstention,
        })
    }

    #[must_use]
    pub const fn minimum(self) -> usize {
        self.minimum
    }

    #[must_use]
    pub const fn maximum(self) -> usize {
        self.maximum
    }

    #[must_use]
    pub const fn allow_abstention(self) -> bool {
        self.allow_abstention
    }
}

/// Canonically ordered approval selections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalBallotPayload {
    selections: Vec<CandidateId>,
}

impl ApprovalBallotPayload {
    /// Validates, sorts, and freezes approval selections.
    pub fn new(
        mut selections: Vec<CandidateId>,
        candidates: &CandidateSet,
        limits: ApprovalLimits,
    ) -> Result<Self, ProtocolError> {
        if limits.maximum > candidates.len() {
            return Err(ProtocolError::new(
                ValidationCode::InvalidSelectionLimits,
                "maximum selections exceed the candidate count",
            ));
        }

        if selections.is_empty() {
            if limits.allow_abstention {
                return Ok(Self { selections });
            }

            return Err(ProtocolError::new(
                ValidationCode::SelectionCountOutOfRange,
                "empty approval selection is not permitted",
            ));
        }

        if selections.len() < limits.minimum || selections.len() > limits.maximum {
            return Err(ProtocolError::new(
                ValidationCode::SelectionCountOutOfRange,
                "approval selection count is outside manifest limits",
            ));
        }

        selections.sort();

        if selections.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ProtocolError::new(
                ValidationCode::DuplicateSelection,
                "approval ballot contains a duplicate candidate",
            ));
        }

        if selections.iter().any(|id| !candidates.contains(id)) {
            return Err(ProtocolError::new(
                ValidationCode::UnknownCandidateId,
                "approval ballot contains an unknown candidate identifier",
            ));
        }

        Ok(Self { selections })
    }

    /// Returns selections in canonical candidate-ID order.
    #[must_use]
    pub fn selections(&self) -> &[CandidateId] {
        &self.selections
    }

    /// Returns whether this payload records an abstention.
    #[must_use]
    pub fn is_abstention(&self) -> bool {
        self.selections.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ApprovalBallotPayload, ApprovalLimits, CandidateDefinition, CandidateId, CandidateSet,
    };
    use tari_cc_private_ballot_protocol::ValidationCode;

    fn id(bytes: &[u8]) -> CandidateId {
        let Ok(id) = CandidateId::new(bytes.to_vec()) else {
            panic!("test candidate ID must be valid");
        };

        id
    }

    fn candidate(identifier: &[u8], display_name: &str) -> CandidateDefinition {
        let Ok(candidate) = CandidateDefinition::new(id(identifier), display_name.to_owned())
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

    #[test]
    fn candidates_are_sorted_by_stable_id() {
        let candidates = candidate_set();
        let ids: Vec<&[u8]> = candidates
            .candidates()
            .iter()
            .map(|candidate| candidate.id().as_bytes())
            .collect();

        assert_eq!(ids, vec![b"candidate-a", b"candidate-b", b"candidate-c"]);
    }

    #[test]
    fn duplicate_candidate_id_is_rejected() {
        let result = CandidateSet::new(vec![
            candidate(b"candidate-a", "First name"),
            candidate(b"candidate-a", "Different display name"),
        ]);

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::DuplicateCandidateId
        ));
    }

    #[test]
    fn selections_are_sorted_canonically() {
        let candidates = candidate_set();
        let result = ApprovalBallotPayload::new(
            vec![id(b"candidate-c"), id(b"candidate-a")],
            &candidates,
            limits(1, 2, false),
        );

        let Ok(payload) = result else {
            panic!("approval payload should be valid");
        };

        let ids: Vec<&[u8]> = payload
            .selections()
            .iter()
            .map(CandidateId::as_bytes)
            .collect();

        assert_eq!(ids, vec![b"candidate-a", b"candidate-c"]);
    }

    #[test]
    fn duplicate_selection_is_rejected() {
        let candidates = candidate_set();
        let result = ApprovalBallotPayload::new(
            vec![id(b"candidate-a"), id(b"candidate-a")],
            &candidates,
            limits(1, 2, false),
        );

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::DuplicateSelection
        ));
    }

    #[test]
    fn unknown_candidate_is_rejected() {
        let candidates = candidate_set();
        let result =
            ApprovalBallotPayload::new(vec![id(b"candidate-z")], &candidates, limits(1, 2, false));

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::UnknownCandidateId
        ));
    }

    #[test]
    fn abstention_is_allowed_only_when_configured() {
        let candidates = candidate_set();

        let allowed = ApprovalBallotPayload::new(Vec::new(), &candidates, limits(1, 2, true));

        let rejected = ApprovalBallotPayload::new(Vec::new(), &candidates, limits(1, 2, false));

        assert!(matches!(allowed, Ok(payload) if payload.is_abstention()));
        assert!(matches!(
            rejected,
            Err(error)
                if error.code() == ValidationCode::SelectionCountOutOfRange
        ));
    }

    #[test]
    fn selection_count_outside_limits_is_rejected() {
        let candidates = candidate_set();
        let result = ApprovalBallotPayload::new(
            vec![id(b"candidate-a"), id(b"candidate-b")],
            &candidates,
            limits(1, 1, false),
        );

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::SelectionCountOutOfRange
        ));
    }

    #[test]
    fn impossible_selection_limits_are_rejected() {
        let candidates = candidate_set();
        let result =
            ApprovalBallotPayload::new(vec![id(b"candidate-a")], &candidates, limits(1, 4, false));

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::InvalidSelectionLimits
        ));
    }
}
