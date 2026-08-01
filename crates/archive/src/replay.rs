//! Metadata-minimized submission ordering and verification decisions.

use tari_cc_private_ballot_protocol::{ManifestHash, ProtocolError, ValidationCode};

/// Raw 32-byte digest of one canonical ballot package.
///
/// The archive records this digest rather than voter, wallet, device,
/// transport, authentication, or client metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BallotPackageDigestV1([u8; 32]);

impl BallotPackageDigestV1 {
    /// Wraps an already derived version-one ballot-package digest.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consumes the wrapper and returns the exact digest bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Contiguous zero-based submission order assigned by the archive.
///
/// This is ordering metadata only. It is not a wall-clock timestamp and
/// does not identify a voter, relay connection, device, or source account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IngestSequenceV1(u64);

impl IngestSequenceV1 {
    /// Creates one sequence value for validation or replay.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the zero-based sequence number.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    fn from_index(index: usize) -> Result<Self, ProtocolError> {
        let value = u64::try_from(index).map_err(|_| {
            ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "archive ingest sequence exceeds the protocol integer limit",
            )
        })?;

        Ok(Self(value))
    }
}

/// Minimal record proving where one available package appears in replay order.
///
/// No exact receipt time is stored. The coarse protocol fact retained here
/// is only whether the package was received before election closing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmissionRecordV1 {
    sequence: IngestSequenceV1,
    package_digest: BallotPackageDigestV1,
    received_before_close: bool,
}

impl SubmissionRecordV1 {
    /// Returns the contiguous archive-assigned ingest sequence.
    #[must_use]
    pub const fn sequence(&self) -> IngestSequenceV1 {
        self.sequence
    }

    /// Returns the digest of the archived ballot package.
    #[must_use]
    pub const fn package_digest(&self) -> BallotPackageDigestV1 {
        self.package_digest
    }

    /// Returns the coarse received-before-close assertion.
    #[must_use]
    pub const fn received_before_close(&self) -> bool {
        self.received_before_close
    }
}

/// Deterministic verifier outcome for one archived submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BallotDecisionOutcomeV1 {
    /// The ballot passed all checks and entered the accepted set.
    Accepted,
    /// The ballot was rejected under one stable protocol validation code.
    Rejected(ValidationCode),
}

impl BallotDecisionOutcomeV1 {
    /// Returns whether this decision accepted the ballot.
    #[must_use]
    pub const fn is_accepted(self) -> bool {
        matches!(self, Self::Accepted)
    }

    /// Returns the deterministic rejection code, when rejected.
    #[must_use]
    pub const fn rejection_code(self) -> Option<ValidationCode> {
        match self {
            Self::Accepted => None,
            Self::Rejected(code) => Some(code),
        }
    }
}

/// One accepted or rejected decision tied to an exact submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BallotDecisionV1 {
    sequence: IngestSequenceV1,
    package_digest: BallotPackageDigestV1,
    outcome: BallotDecisionOutcomeV1,
}

impl BallotDecisionV1 {
    /// Returns the submission sequence decided by this record.
    #[must_use]
    pub const fn sequence(&self) -> IngestSequenceV1 {
        self.sequence
    }

    /// Returns the exact package digest decided by this record.
    #[must_use]
    pub const fn package_digest(&self) -> BallotPackageDigestV1 {
        self.package_digest
    }

    /// Returns the accepted or deterministically rejected outcome.
    #[must_use]
    pub const fn outcome(&self) -> BallotDecisionOutcomeV1 {
        self.outcome
    }
}

/// Append-only replay transcript for one frozen election manifest.
///
/// Submissions receive contiguous sequence numbers. Decisions must be added
/// in that same order so first-valid-ballot handling can be reproduced
/// without using wall-clock timing or transport metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationTranscriptV1 {
    manifest_hash: ManifestHash,
    submissions: Vec<SubmissionRecordV1>,
    decisions: Vec<BallotDecisionV1>,
}

impl VerificationTranscriptV1 {
    /// Creates an empty transcript bound to one frozen manifest.
    #[must_use]
    pub const fn new(manifest_hash: ManifestHash) -> Self {
        Self {
            manifest_hash,
            submissions: Vec::new(),
            decisions: Vec::new(),
        }
    }

    /// Returns the frozen manifest hash governing every record.
    #[must_use]
    pub const fn manifest_hash(&self) -> ManifestHash {
        self.manifest_hash
    }

    /// Appends one available ballot package in archive ingest order.
    pub fn record_submission(
        &mut self,
        package_digest: BallotPackageDigestV1,
        received_before_close: bool,
    ) -> Result<IngestSequenceV1, ProtocolError> {
        let sequence = IngestSequenceV1::from_index(self.submissions.len())?;

        self.submissions.push(SubmissionRecordV1 {
            sequence,
            package_digest,
            received_before_close,
        });

        Ok(sequence)
    }

    /// Records the next deterministic verifier decision.
    ///
    /// Decisions cannot skip, replace, reorder, or refer to another package.
    pub fn record_decision(
        &mut self,
        sequence: IngestSequenceV1,
        package_digest: BallotPackageDigestV1,
        outcome: BallotDecisionOutcomeV1,
    ) -> Result<(), ProtocolError> {
        let expected = IngestSequenceV1::from_index(self.decisions.len())?;

        if sequence < expected {
            return Err(ProtocolError::new(
                ValidationCode::DuplicateBallotDecision,
                "a decision already exists for this ingest sequence",
            ));
        }

        if sequence > expected {
            return Err(ProtocolError::new(
                ValidationCode::InvalidIngestSequence,
                "ballot decisions must follow contiguous ingest order",
            ));
        }

        let index = usize::try_from(sequence.value()).map_err(|_| {
            ProtocolError::new(
                ValidationCode::InvalidIngestSequence,
                "ingest sequence cannot be represented by this verifier",
            )
        })?;

        let Some(submission) = self.submissions.get(index) else {
            return Err(ProtocolError::new(
                ValidationCode::InvalidIngestSequence,
                "ballot decision does not reference an archived submission",
            ));
        };

        if submission.package_digest != package_digest {
            return Err(ProtocolError::new(
                ValidationCode::BallotDecisionDigestMismatch,
                "ballot decision digest differs from the archived submission",
            ));
        }

        self.decisions.push(BallotDecisionV1 {
            sequence,
            package_digest,
            outcome,
        });

        Ok(())
    }

    /// Returns submissions in immutable replay order.
    #[must_use]
    pub fn submissions(&self) -> &[SubmissionRecordV1] {
        &self.submissions
    }

    /// Returns decisions in immutable replay order.
    #[must_use]
    pub fn decisions(&self) -> &[BallotDecisionV1] {
        &self.decisions
    }

    /// Returns the next submitted package awaiting a decision.
    #[must_use]
    pub fn next_undecided_submission(&self) -> Option<&SubmissionRecordV1> {
        self.submissions.get(self.decisions.len())
    }

    /// Returns the number of accepted ballot decisions.
    #[must_use]
    pub fn accepted_count(&self) -> usize {
        self.decisions
            .iter()
            .filter(|decision| decision.outcome.is_accepted())
            .count()
    }

    /// Returns the number of rejected ballot decisions.
    #[must_use]
    pub fn rejected_count(&self) -> usize {
        self.decisions.len() - self.accepted_count()
    }

    /// Confirms that every archived submission has exactly one matching decision.
    pub fn validate_complete(&self) -> Result<(), ProtocolError> {
        if self.submissions.len() != self.decisions.len() {
            return Err(ProtocolError::new(
                ValidationCode::IncompleteVerificationTranscript,
                "verification transcript does not decide every submission",
            ));
        }

        for (submission, decision) in self.submissions.iter().zip(&self.decisions) {
            if submission.sequence != decision.sequence {
                return Err(ProtocolError::new(
                    ValidationCode::InvalidIngestSequence,
                    "submission and decision sequence numbers differ",
                ));
            }

            if submission.package_digest != decision.package_digest {
                return Err(ProtocolError::new(
                    ValidationCode::BallotDecisionDigestMismatch,
                    "submission and decision package digests differ",
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(byte: u8) -> ManifestHash {
        ManifestHash::new([byte; 32])
    }

    fn digest(byte: u8) -> BallotPackageDigestV1 {
        BallotPackageDigestV1::new([byte; 32])
    }

    #[test]
    fn package_digest_preserves_exact_bytes() {
        let digest = digest(7);

        assert_eq!(digest.as_bytes(), &[7_u8; 32]);
        assert_eq!(digest.into_bytes(), [7_u8; 32]);
    }

    #[test]
    fn new_transcript_is_empty_manifest_bound_and_complete() {
        let transcript = VerificationTranscriptV1::new(manifest(1));

        assert_eq!(transcript.manifest_hash().as_bytes(), &[1_u8; 32]);
        assert!(transcript.submissions().is_empty());
        assert!(transcript.decisions().is_empty());
        assert!(transcript.validate_complete().is_ok());
    }

    #[test]
    fn submissions_receive_contiguous_monotonic_sequences() {
        let mut transcript = VerificationTranscriptV1::new(manifest(1));

        let Ok(first) = transcript.record_submission(digest(1), true) else {
            panic!("first submission should be recorded");
        };

        let Ok(second) = transcript.record_submission(digest(2), false) else {
            panic!("second submission should be recorded");
        };

        assert_eq!(first.value(), 0);
        assert_eq!(second.value(), 1);
    }

    #[test]
    fn submission_preserves_only_replay_fields() {
        let mut transcript = VerificationTranscriptV1::new(manifest(1));

        assert!(transcript.record_submission(digest(4), true).is_ok());

        let submission = &transcript.submissions()[0];

        assert_eq!(submission.sequence().value(), 0);
        assert_eq!(submission.package_digest(), digest(4));
        assert!(submission.received_before_close());
    }

    #[test]
    fn accepted_and_rejected_decisions_preserve_replay_order() {
        let mut transcript = VerificationTranscriptV1::new(manifest(1));

        let Ok(first) = transcript.record_submission(digest(1), true) else {
            panic!("first submission should be recorded");
        };

        let Ok(second) = transcript.record_submission(digest(2), true) else {
            panic!("second submission should be recorded");
        };

        assert!(
            transcript
                .record_decision(first, digest(1), BallotDecisionOutcomeV1::Accepted,)
                .is_ok()
        );

        assert!(
            transcript
                .record_decision(
                    second,
                    digest(2),
                    BallotDecisionOutcomeV1::Rejected(ValidationCode::DuplicateNullifier,),
                )
                .is_ok()
        );

        assert_eq!(transcript.decisions()[0].sequence().value(), 0);
        assert_eq!(transcript.decisions()[1].sequence().value(), 1);
        assert_eq!(transcript.accepted_count(), 1);
        assert_eq!(transcript.rejected_count(), 1);
    }

    #[test]
    fn rejection_code_is_preserved() {
        let outcome = BallotDecisionOutcomeV1::Rejected(ValidationCode::MalformedProof);

        assert!(!outcome.is_accepted());
        assert_eq!(
            outcome.rejection_code(),
            Some(ValidationCode::MalformedProof)
        );
    }

    #[test]
    fn decision_without_submission_is_rejected() {
        let mut transcript = VerificationTranscriptV1::new(manifest(1));

        let result = transcript.record_decision(
            IngestSequenceV1::new(0),
            digest(1),
            BallotDecisionOutcomeV1::Accepted,
        );

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::InvalidIngestSequence
        ));
        assert!(transcript.decisions().is_empty());
    }

    #[test]
    fn skipped_decision_is_rejected_without_mutation() {
        let mut transcript = VerificationTranscriptV1::new(manifest(1));

        assert!(transcript.record_submission(digest(1), true).is_ok());
        assert!(transcript.record_submission(digest(2), true).is_ok());

        let result = transcript.record_decision(
            IngestSequenceV1::new(1),
            digest(2),
            BallotDecisionOutcomeV1::Accepted,
        );

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::InvalidIngestSequence
        ));
        assert!(transcript.decisions().is_empty());
    }

    #[test]
    fn duplicate_decision_is_rejected_without_mutation() {
        let mut transcript = VerificationTranscriptV1::new(manifest(1));

        let Ok(sequence) = transcript.record_submission(digest(1), true) else {
            panic!("submission should be recorded");
        };

        assert!(
            transcript
                .record_decision(sequence, digest(1), BallotDecisionOutcomeV1::Accepted,)
                .is_ok()
        );

        let duplicate = transcript.record_decision(
            sequence,
            digest(1),
            BallotDecisionOutcomeV1::Rejected(ValidationCode::DuplicateNullifier),
        );

        assert!(matches!(
            duplicate,
            Err(error)
                if error.code() == ValidationCode::DuplicateBallotDecision
        ));
        assert_eq!(transcript.decisions().len(), 1);
        assert!(transcript.decisions()[0].outcome().is_accepted());
    }

    #[test]
    fn mismatched_package_digest_is_rejected_without_mutation() {
        let mut transcript = VerificationTranscriptV1::new(manifest(1));

        let Ok(sequence) = transcript.record_submission(digest(1), true) else {
            panic!("submission should be recorded");
        };

        let result =
            transcript.record_decision(sequence, digest(9), BallotDecisionOutcomeV1::Accepted);

        assert!(matches!(
            result,
            Err(error)
                if error.code()
                    == ValidationCode::BallotDecisionDigestMismatch
        ));
        assert!(transcript.decisions().is_empty());
    }

    #[test]
    fn incomplete_transcript_is_rejected() {
        let mut transcript = VerificationTranscriptV1::new(manifest(1));

        assert!(transcript.record_submission(digest(1), true).is_ok());

        assert!(matches!(
            transcript.validate_complete(),
            Err(error)
                if error.code()
                    == ValidationCode::IncompleteVerificationTranscript
        ));
    }

    #[test]
    fn complete_transcript_validates() {
        let mut transcript = VerificationTranscriptV1::new(manifest(1));

        let Ok(sequence) = transcript.record_submission(digest(1), true) else {
            panic!("submission should be recorded");
        };

        assert!(
            transcript
                .record_decision(sequence, digest(1), BallotDecisionOutcomeV1::Accepted,)
                .is_ok()
        );

        assert!(transcript.validate_complete().is_ok());
    }

    #[test]
    fn next_undecided_submission_tracks_progress() {
        let mut transcript = VerificationTranscriptV1::new(manifest(1));

        let Ok(first) = transcript.record_submission(digest(1), true) else {
            panic!("first submission should be recorded");
        };

        assert!(transcript.record_submission(digest(2), true).is_ok());

        let Some(next) = transcript.next_undecided_submission() else {
            panic!("first submission should await a decision");
        };

        assert_eq!(next.sequence(), first);

        assert!(
            transcript
                .record_decision(first, digest(1), BallotDecisionOutcomeV1::Accepted,)
                .is_ok()
        );

        let Some(next) = transcript.next_undecided_submission() else {
            panic!("second submission should await a decision");
        };

        assert_eq!(next.sequence().value(), 1);
    }
}
