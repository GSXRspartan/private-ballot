//! Organizer election session facade.
//!
//! Composes the existing election lifecycle, ballot-acceptance ledger, and
//! verification transcript around one validated artifact triple, without
//! changing any of their semantics. The session holds no secret material and
//! no mutable election state beyond what [`ElectionLifecycleV1`] permits.
//!
//! Intake policy: ballots are ingested only while the election is open,
//! matching the lifecycle's own acceptance rule. Every ingested package —
//! accepted or rejected — is recorded in the transcript exactly as the
//! existing replay composition does, with `received_before_close = true`.
//! Attempting intake while not open is a facade error and records nothing.

use tari_cc_private_ballot_archive::{
    BallotDecisionOutcomeV1, BallotPackageDigestV1, VerificationTranscriptV1,
};
use tari_cc_private_ballot_ballot::{
    BallotPackageEnvelopeV1, ElectionLifecycleStateV1, ElectionLifecycleV1,
};
use tari_cc_private_ballot_crypto::TariTriptychPrototypeVerifierV1;
use tari_cc_private_ballot_protocol::{
    Blake3HashProviderV1, HashDomain, ValidationCode, hash_domain_separated,
};
use tari_cc_private_ballot_tally::ApprovalTally;
use tari_cc_private_ballot_verifier::{
    BallotAcceptanceLedger, build_tari_triptych_verifier_from_registry_v1,
    ingest_approval_ballot_package_v1, verify_approval_proof,
};

use crate::artifacts::GuiElectionArtifactsV1;
use crate::error::GuiCoreError;
use crate::intake::{GuiBallotIntakeResultV1, GuiIntakeCategory};
use crate::participation::{
    GuiParticipationSummaryV1, ParticipationVisibility, SMALL_ELECTORATE_THRESHOLD,
    participation_basis_points, participation_visibility_for, result_visibility_for,
};
use crate::summary::GuiElectionSummaryV1;
use crate::tally::{GuiTallySummaryV1, summarize_tally};

/// One organizer election workspace.
///
/// Owns the registry-bound Triptych verifier, the append-only lifecycle, the
/// first-valid-nullifier acceptance ledger, the replay transcript, and the
/// exact canonical bytes of every ingested package (public data needed for
/// archive construction).
#[derive(Debug)]
pub struct GuiElectionSessionV1 {
    artifacts: GuiElectionArtifactsV1,
    verifier: TariTriptychPrototypeVerifierV1,
    lifecycle: ElectionLifecycleV1,
    ledger: BallotAcceptanceLedger,
    transcript: VerificationTranscriptV1,
    packages: Vec<Vec<u8>>,
}

impl GuiElectionSessionV1 {
    /// Creates a frozen session over validated artifacts.
    ///
    /// The registry-bound Triptych verifier is constructed immediately, which
    /// validates that every governance key is a canonical Ristretto point.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`GuiCoreError`] if verifier construction or the
    /// lifecycle freeze fails.
    pub fn new(artifacts: GuiElectionArtifactsV1) -> Result<Self, GuiCoreError> {
        let provider = Blake3HashProviderV1;
        let verifier =
            build_tari_triptych_verifier_from_registry_v1(artifacts.registry(), &provider)
                .map_err(|error| GuiCoreError::from_protocol(&error, "registry"))?;

        let mut lifecycle = ElectionLifecycleV1::new();
        lifecycle
            .freeze(artifacts.manifest_hash(), artifacts.registry_commitment())
            .map_err(|error| GuiCoreError::from_protocol(&error, "lifecycle"))?;

        let transcript = VerificationTranscriptV1::new(artifacts.manifest_hash());

        Ok(Self {
            artifacts,
            verifier,
            lifecycle,
            ledger: BallotAcceptanceLedger::new(),
            transcript,
            packages: Vec::new(),
        })
    }

    /// Opens the frozen election for ballot intake.
    ///
    /// # Errors
    ///
    /// Returns the existing lifecycle error if the transition is not permitted.
    pub fn open(&mut self) -> Result<(), GuiCoreError> {
        self.lifecycle
            .open()
            .map_err(|error| GuiCoreError::from_protocol(&error, "lifecycle"))
    }

    /// Closes ballot acceptance permanently.
    ///
    /// # Errors
    ///
    /// Returns the existing lifecycle error if the transition is not permitted.
    pub fn close(&mut self) -> Result<(), GuiCoreError> {
        self.lifecycle
            .close()
            .map_err(|error| GuiCoreError::from_protocol(&error, "lifecycle"))
    }

    /// Records completion of public verification and tally reproduction.
    ///
    /// # Errors
    ///
    /// Returns the existing lifecycle error if the transition is not permitted.
    pub fn mark_verified(&mut self) -> Result<(), GuiCoreError> {
        self.lifecycle
            .mark_verified()
            .map_err(|error| GuiCoreError::from_protocol(&error, "lifecycle"))
    }

    /// Finalizes the verified result and archive commitments.
    ///
    /// # Errors
    ///
    /// Returns the existing lifecycle error if the transition is not permitted.
    pub fn finalize(&mut self) -> Result<(), GuiCoreError> {
        self.lifecycle
            .finalize()
            .map_err(|error| GuiCoreError::from_protocol(&error, "lifecycle"))
    }

    /// Ingests one canonical ballot package through the existing pipeline.
    ///
    /// The package is decoded, bound, proof-verified, and accepted or
    /// rejected by
    /// [`ingest_approval_ballot_package_v1`]; the deterministic decision is
    /// recorded in the transcript in intake order. A rejected ballot never
    /// mutates the acceptance ledger.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`GuiCoreError`] with code `ELECTION_NOT_OPEN` when
    /// the election is not open (nothing is recorded), or if transcript
    /// recording itself fails.
    pub fn intake_ballot(
        &mut self,
        package_bytes: &[u8],
    ) -> Result<GuiBallotIntakeResultV1, GuiCoreError> {
        if !self.lifecycle.is_open() {
            return Err(GuiCoreError::new(
                ValidationCode::ElectionNotOpen.as_str(),
                crate::error::GuiErrorCategory::InvalidLifecycleTransition,
                Some("lifecycle"),
                "ballots are ingested only while the election is open",
            ));
        }

        let provider = Blake3HashProviderV1;
        let digest = BallotPackageDigestV1::new(hash_domain_separated(
            &provider,
            HashDomain::BallotPackageV1,
            package_bytes,
        ));

        let sequence = self
            .transcript
            .record_submission(digest, true)
            .map_err(|error| GuiCoreError::from_protocol(&error, "transcript"))?;

        let outcome = match ingest_approval_ballot_package_v1(
            package_bytes,
            self.artifacts.manifest(),
            self.artifacts.candidates(),
            &self.lifecycle,
            &mut self.ledger,
            &provider,
            &self.verifier,
        ) {
            Ok(()) => BallotDecisionOutcomeV1::Accepted,
            Err(error) => BallotDecisionOutcomeV1::Rejected(error.code()),
        };

        self.transcript
            .record_decision(sequence, digest, outcome)
            .map_err(|error| GuiCoreError::from_protocol(&error, "transcript"))?;

        self.packages.push(package_bytes.to_vec());

        Ok(self.intake_result(sequence, digest, package_bytes, outcome))
    }

    /// Builds the structured intake result, resolving public post-verification
    /// identifiers where the existing APIs expose them safely.
    fn intake_result(
        &self,
        sequence: tari_cc_private_ballot_archive::IngestSequenceV1,
        digest: BallotPackageDigestV1,
        package_bytes: &[u8],
        outcome: BallotDecisionOutcomeV1,
    ) -> GuiBallotIntakeResultV1 {
        let mut result = GuiBallotIntakeResultV1 {
            accepted: outcome.is_accepted(),
            code: "ACCEPTED",
            category: GuiIntakeCategory::Accepted,
            package_digest_hex: crate::hex::to_lower_hex(digest.as_bytes()),
            sequence: sequence.value(),
            nullifier_hex: None,
            duplicate_of_sequence: None,
        };

        if outcome.is_accepted() {
            if let Some(accepted) = self.ledger.accepted_ballots().last() {
                result.nullifier_hex = Some(crate::hex::to_lower_hex(
                    accepted.election_scoped_nullifier(),
                ));
            }
            return result;
        }

        let Some(code) = outcome.rejection_code() else {
            return result;
        };
        result.code = code.as_str();
        result.category = GuiIntakeCategory::from_validation(code);

        if code == ValidationCode::DuplicateNullifier {
            self.resolve_duplicate_reference(package_bytes, &mut result);
        }

        result
    }

    /// Re-verifies a duplicate ballot read-only to expose its (already public)
    /// nullifier and the sequence of the first accepted ballot carrying it.
    ///
    /// This runs only on the duplicate-rejection path, where proof
    /// verification already succeeded inside the ingestion pipeline. It
    /// mutates nothing and ignores any internal failure.
    fn resolve_duplicate_reference(
        &self,
        package_bytes: &[u8],
        result: &mut GuiBallotIntakeResultV1,
    ) {
        let provider = Blake3HashProviderV1;
        let resolved = (|| {
            let envelope = BallotPackageEnvelopeV1::from_canonical_cbor(package_bytes).ok()?;
            let package = envelope
                .into_ballot_package(
                    self.artifacts.candidates(),
                    self.artifacts.manifest().approval_limits(),
                )
                .ok()?;
            let verified = verify_approval_proof(
                self.artifacts.manifest(),
                package.payload(),
                package.proof(),
                &provider,
                &self.verifier,
            )
            .ok()?;
            let nullifier_bytes = verified.nullifier().as_bytes().to_vec();

            let accepted_index = self.ledger.accepted_ballots().iter().position(|ballot| {
                ballot.election_scoped_nullifier() == nullifier_bytes.as_slice()
            })?;
            let first_sequence = self
                .transcript
                .decisions()
                .iter()
                .filter(|decision| decision.outcome().is_accepted())
                .nth(accepted_index)
                .map(|decision| decision.sequence().value());

            Some((nullifier_bytes, first_sequence))
        })();

        if let Some((nullifier_bytes, first_sequence)) = resolved {
            result.nullifier_hex = Some(crate::hex::to_lower_hex(&nullifier_bytes));
            result.duplicate_of_sequence = first_sequence;
        }
    }

    /// Computes the deterministic tally over the currently accepted ballots.
    ///
    /// Results are sealed until voting has closed. This method refuses to
    /// disclose any tally data while the lifecycle is `DRAFT`, `FROZEN`, or
    /// `OPEN`, returning a bounded [`GuiCoreError`] and computing nothing.
    /// After close (`CLOSED`, `VERIFIED`, `FINALIZED`) the deterministic tally
    /// is returned. This gate is authoritative: every caller that goes
    /// through this facade receives the same protection, independent of the
    /// frontend button state.
    ///
    /// # Errors
    ///
    /// Returns [`GuiCoreError::tally_not_available_before_close`] when the
    /// election has not yet closed, or the existing tally error if the
    /// accepted set is inconsistent with the frozen candidate set (not
    /// possible through this facade).
    pub fn tally(&self) -> Result<GuiTallySummaryV1, GuiCoreError> {
        if !matches!(
            self.lifecycle.state(),
            ElectionLifecycleStateV1::Closed
                | ElectionLifecycleStateV1::Verified
                | ElectionLifecycleStateV1::Finalized
        ) {
            return Err(GuiCoreError::tally_not_available_before_close());
        }

        let tally = self.direct_tally()?;
        Ok(summarize_tally(&tally, self.artifacts.candidates()))
    }

    /// Computes the privacy-aware participation summary from authoritative
    /// backend state (registry size and acceptance-ledger length).
    ///
    /// This method performs no tally arithmetic and never discloses per-option
    /// results. Numeric participation fields are `None` while the
    /// application-local visibility policy seals them (by default, while voting
    /// is open), so a modified frontend cannot retrieve sealed counts by
    /// calling this method. `eligible_voters` is always present because it is
    /// public registry information.
    ///
    /// The acceptance ledger enforces one acceptance per registry-scoped
    /// nullifier, so `accepted_ballots` never exceeds `eligible_voters` through
    /// the public API; remaining capacity is computed with saturating
    /// arithmetic as a defensive bound.
    #[must_use]
    pub fn participation_summary(&self) -> GuiParticipationSummaryV1 {
        let state = self.lifecycle.state();
        let visibility = participation_visibility_for(state);
        let result_visibility = result_visibility_for(state);
        // `usize` and `u64` share width on the target platform, but the
        // workspace forbids `expect`/`unwrap`, so fall back to `u64::MAX`
        // (which the saturating arithmetic below bounds back to a safe value).
        let eligible = u64::try_from(self.artifacts.registry().len()).unwrap_or(u64::MAX);
        let accepted = u64::try_from(self.accepted_count()).unwrap_or(u64::MAX);
        let small_electorate = self.artifacts.registry().len() < SMALL_ELECTORATE_THRESHOLD;

        let (accepted_opt, bps_opt, remaining_opt, coarse_opt) = match visibility {
            ParticipationVisibility::Live => {
                let bps = participation_basis_points(accepted, eligible);
                let remaining = eligible.saturating_sub(accepted);
                (Some(accepted), Some(bps), Some(remaining), None)
            }
            ParticipationVisibility::Coarse => {
                let bps = participation_basis_points(accepted, eligible);
                let bucket =
                    crate::participation::CoarseParticipationBucket::from_basis_points(bps);
                (None, None, None, Some(bucket))
            }
            ParticipationVisibility::SealedUntilClose => (None, None, None, None),
        };

        GuiParticipationSummaryV1 {
            lifecycle_state: state.as_str(),
            participation_visibility: visibility,
            result_visibility,
            eligible_voters: eligible,
            accepted_ballots: accepted_opt,
            participation_basis_points: bps_opt,
            remaining_eligible_capacity: remaining_opt,
            coarse_bucket: coarse_opt,
            small_electorate,
        }
    }

    /// Computes the raw backend tally (used by facade/backend equality tests
    /// and the archive replay verifier).
    ///
    /// # Errors
    ///
    /// Returns the existing tally error.
    pub fn direct_tally(&self) -> Result<ApprovalTally, GuiCoreError> {
        ApprovalTally::from_ballots(
            self.artifacts.candidates(),
            self.ledger
                .accepted_ballots()
                .iter()
                .map(|ballot| ballot.payload()),
        )
        .map_err(|error| GuiCoreError::from_protocol(&error, "tally"))
    }

    /// Returns the election summary including the current lifecycle state.
    #[must_use]
    pub fn summary(&self) -> GuiElectionSummaryV1 {
        self.artifacts
            .summary_with_lifecycle(Some(self.lifecycle.state().as_str()))
    }

    /// Returns the validated artifacts this session is bound to.
    #[must_use]
    pub const fn artifacts(&self) -> &GuiElectionArtifactsV1 {
        &self.artifacts
    }

    /// Returns the current lifecycle state code.
    #[must_use]
    pub const fn lifecycle_state(&self) -> &'static str {
        self.lifecycle.state().as_str()
    }

    /// Returns the current lifecycle state enum for Rust-side facades that
    /// must gate behavior without parsing the display code.
    #[must_use]
    pub const fn lifecycle_state_v1(&self) -> ElectionLifecycleStateV1 {
        self.lifecycle.state()
    }

    /// Returns the replay transcript.
    #[must_use]
    pub const fn transcript(&self) -> &VerificationTranscriptV1 {
        &self.transcript
    }

    /// Returns the number of accepted ballots.
    #[must_use]
    pub fn accepted_count(&self) -> usize {
        self.ledger.len()
    }

    /// Returns the canonical bytes of every ingested package in intake order.
    #[must_use]
    pub fn packages(&self) -> &[Vec<u8>] {
        &self.packages
    }
}
