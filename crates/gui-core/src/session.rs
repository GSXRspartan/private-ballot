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

use std::collections::HashMap;
use std::time::SystemTime;

use tari_cc_private_ballot_archive::{
    BallotDecisionOutcomeV1, BallotPackageDigestV1, VerificationTranscriptV1,
};
use tari_cc_private_ballot_ballot::{ElectionLifecycleStateV1, ElectionLifecycleV1};
use tari_cc_private_ballot_crypto::TariTriptychPrototypeVerifierV1;
use tari_cc_private_ballot_protocol::{
    Blake3HashProviderV1, HashDomain, ValidationCode, hash_domain_separated,
};
use tari_cc_private_ballot_tally::ApprovalTally;
use tari_cc_private_ballot_verifier::{
    BallotAcceptanceLedger, VerifiedApprovalBallotV1,
    build_tari_triptych_verifier_from_registry_v1, ingest_approval_ballot_package_v1,
};

use crate::artifacts::GuiElectionArtifactsV1;
use crate::error::GuiCoreError;
use crate::historical_replay::HistoricalReplayConfigV1;
use crate::intake::{GuiBallotIntakeResultV1, GuiIntakeCategory};
use crate::participation::{
    GuiParticipationSummaryV1, ParticipationVisibility, SMALL_ELECTORATE_THRESHOLD,
    participation_basis_points, participation_visibility_for, result_visibility_for,
};
use crate::summary::GuiElectionSummaryV1;
use crate::tally::{GuiTallySummaryV1, summarize_tally};

/// Derived, in-memory pointer to the FIRST transcript decision for one package
/// digest. The transcript remains authoritative; this never participates in
/// durable encoding and every lookup rechecks the pointed-to transcript row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TranscriptDecisionIndexEntryV1 {
    sequence: tari_cc_private_ballot_archive::IngestSequenceV1,
    outcome: BallotDecisionOutcomeV1,
}

/// Process-local evidence that an immutable, content-addressed inbox file was
/// fully read and digest-validated during this session.
///
/// This is deliberately not durable state. It is only a short-lived read/hash
/// avoidance cache for a file that is already represented by the authoritative
/// transcript. Any identity change makes the caller read and hash the file
/// again before using it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PrivateInboxFileValidationV1 {
    byte_len: u64,
    modified: SystemTime,
}

/// One organizer election workspace.
///
/// Owns the registry-bound Triptych verifier, the append-only lifecycle, the
/// first-valid-nullifier acceptance ledger, the replay transcript, and the
/// exact canonical bytes of every ingested package (public data needed for
/// archive construction).
#[derive(Debug, Clone)]
pub struct GuiElectionSessionV1 {
    artifacts: GuiElectionArtifactsV1,
    verifier: TariTriptychPrototypeVerifierV1,
    lifecycle: ElectionLifecycleV1,
    ledger: BallotAcceptanceLedger,
    transcript: VerificationTranscriptV1,
    packages: Vec<Vec<u8>>,
    /// Derived acceleration only: first decision per exact package digest.
    private_intake_digest_index: HashMap<BallotPackageDigestV1, TranscriptDecisionIndexEntryV1>,
    /// Process-local evidence for safely unchanged inbox files. Never encoded.
    private_inbox_validation_cache: HashMap<BallotPackageDigestV1, PrivateInboxFileValidationV1>,
}

/// Narrow durable representation of one organizer session.
///
/// This is intentionally made from canonical public artifacts plus the exact
/// canonical ballot-package bytes that already feed archive replay. It does
/// not serialize the verifier, nullifier set, or accepted-ledger internals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuiElectionSessionSnapshotV1 {
    pub lifecycle_state: ElectionLifecycleStateV1,
    pub manifest_bytes: Vec<u8>,
    pub registry_bytes: Vec<u8>,
    pub candidate_bytes: Vec<u8>,
    pub packages: Vec<Vec<u8>>,
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
            private_intake_digest_index: HashMap::new(),
            private_inbox_validation_cache: HashMap::new(),
        })
    }

    /// Reconstructs a session by replaying persisted canonical packages
    /// through the same verifier and first-valid-nullifier ledger used during
    /// live intake.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`GuiCoreError`] if artifacts fail validation,
    /// lifecycle replay is invalid, or a transcript invariant fails.
    pub fn from_durable_snapshot(
        snapshot: GuiElectionSessionSnapshotV1,
    ) -> Result<Self, GuiCoreError> {
        crate::instrumentation::record_from_durable_snapshot_call();
        let reconstruction_start = std::time::Instant::now();
        let result = Self::from_durable_snapshot_inner(snapshot);
        crate::instrumentation::add_reconstruction_micros(
            u64::try_from(reconstruction_start.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
        result
    }

    fn from_durable_snapshot_inner(
        snapshot: GuiElectionSessionSnapshotV1,
    ) -> Result<Self, GuiCoreError> {
        if matches!(snapshot.lifecycle_state, ElectionLifecycleStateV1::Draft) {
            return Err(GuiCoreError::new(
                "GUI_WORKSPACE_INVALID_STATE",
                crate::error::GuiErrorCategory::ArchiveIntegrity,
                Some("election-workspace"),
                "durable session snapshot cannot use draft lifecycle state",
            ));
        }

        let artifacts = GuiElectionArtifactsV1::from_bytes(
            &snapshot.manifest_bytes,
            &snapshot.registry_bytes,
            &snapshot.candidate_bytes,
        )?;
        let mut session = Self::new(artifacts)?;

        if matches!(snapshot.lifecycle_state, ElectionLifecycleStateV1::Frozen) {
            if !snapshot.packages.is_empty() {
                return Err(GuiCoreError::new(
                    "GUI_WORKSPACE_INVALID_STATE",
                    crate::error::GuiErrorCategory::ArchiveIntegrity,
                    Some("election-workspace"),
                    "frozen durable workspace cannot contain ballot packages",
                ));
            }
            return Ok(session);
        }

        session.open()?;
        for package in &snapshot.packages {
            crate::instrumentation::record_historical_ballot_replayed();
            let _ = session.intake_ballot_package_bytes(package)?;
        }

        match snapshot.lifecycle_state {
            ElectionLifecycleStateV1::Open => {}
            ElectionLifecycleStateV1::Closed => {
                session.close()?;
            }
            ElectionLifecycleStateV1::Verified => {
                session.close()?;
                session.mark_verified()?;
            }
            ElectionLifecycleStateV1::Finalized => {
                session.close()?;
                session.mark_verified()?;
                session.finalize()?;
            }
            ElectionLifecycleStateV1::Draft | ElectionLifecycleStateV1::Frozen => {
                return Err(GuiCoreError::new(
                    "GUI_WORKSPACE_INVALID_STATE",
                    crate::error::GuiErrorCategory::ArchiveIntegrity,
                    Some("election-workspace"),
                    "durable workspace lifecycle state is inconsistent",
                ));
            }
        }

        Ok(session)
    }

    /// Reconstructs a durable session using bounded multicore historical
    /// verification (Slice 4B).
    ///
    /// Cryptographic proof validity is computed for every stored package by the
    /// bounded worker pool ([`crate::historical_replay::parallel_verify_packages`]),
    /// then the authoritative election semantics — nullifier ledger,
    /// first-valid-wins, transcript sequencing, accepted/rejected classification
    /// — are applied SEQUENTIALLY in canonical package order. The resulting
    /// session is therefore identical, ballot-for-ballot, to the serial
    /// [`from_durable_snapshot`](Self::from_durable_snapshot), independent of the
    /// worker count, batch size, or worker completion order.
    ///
    /// Small elections (below the configured threshold) and an explicit single
    /// worker fall back to the serial replay loop, which is byte-for-byte the
    /// legacy path.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`GuiCoreError`] on the same conditions as
    /// [`from_durable_snapshot`](Self::from_durable_snapshot), or if the bounded
    /// executor faults (fail-closed).
    pub fn from_durable_snapshot_parallel(
        snapshot: GuiElectionSessionSnapshotV1,
        config: &HistoricalReplayConfigV1,
    ) -> Result<Self, GuiCoreError> {
        crate::instrumentation::record_from_durable_snapshot_call();
        let reconstruction_start = std::time::Instant::now();
        let result = Self::reconstruct_parallel_inner(snapshot, config);
        crate::instrumentation::add_reconstruction_micros(
            u64::try_from(reconstruction_start.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
        result
    }

    fn reconstruct_parallel_inner(
        snapshot: GuiElectionSessionSnapshotV1,
        config: &HistoricalReplayConfigV1,
    ) -> Result<Self, GuiCoreError> {
        if matches!(snapshot.lifecycle_state, ElectionLifecycleStateV1::Draft) {
            return Err(GuiCoreError::new(
                "GUI_WORKSPACE_INVALID_STATE",
                crate::error::GuiErrorCategory::ArchiveIntegrity,
                Some("election-workspace"),
                "durable session snapshot cannot use draft lifecycle state",
            ));
        }

        let artifacts = GuiElectionArtifactsV1::from_bytes(
            &snapshot.manifest_bytes,
            &snapshot.registry_bytes,
            &snapshot.candidate_bytes,
        )?;
        let mut session = Self::new(artifacts)?;

        if matches!(snapshot.lifecycle_state, ElectionLifecycleStateV1::Frozen) {
            if !snapshot.packages.is_empty() {
                return Err(GuiCoreError::new(
                    "GUI_WORKSPACE_INVALID_STATE",
                    crate::error::GuiErrorCategory::ArchiveIntegrity,
                    Some("election-workspace"),
                    "frozen durable workspace cannot contain ballot packages",
                ));
            }
            return Ok(session);
        }

        session.open()?;

        if config.uses_parallel_path(snapshot.packages.len()) {
            session.replay_packages_parallel(&snapshot.packages, config)?;
        } else {
            // Serial fallback: byte-for-byte the legacy replay loop.
            for package in &snapshot.packages {
                crate::instrumentation::record_historical_ballot_replayed();
                let _ = session.intake_ballot_package_bytes(package)?;
            }
        }

        Self::apply_terminal_lifecycle(&mut session, snapshot.lifecycle_state)?;

        Ok(session)
    }

    /// Verifies every package's proof across the bounded worker pool, then
    /// applies the results to this session in canonical package order.
    fn replay_packages_parallel(
        &mut self,
        packages: &[Vec<u8>],
        config: &HistoricalReplayConfigV1,
    ) -> Result<(), GuiCoreError> {
        crate::instrumentation::record_historical_parallel_reconstruction();

        let crypto_start = std::time::Instant::now();
        let verify_results = crate::historical_replay::parallel_verify_packages(
            packages,
            &self.artifacts,
            &self.verifier,
            config,
        )?;
        crate::instrumentation::add_parallel_crypto_micros(
            u64::try_from(crypto_start.elapsed().as_micros()).unwrap_or(u64::MAX),
        );

        if verify_results.len() != packages.len() {
            // The verifier must return exactly one result per package. Any
            // mismatch fails the whole reconstruction closed.
            return Err(GuiCoreError::new(
                "GUI_HISTORICAL_REPLAY_RESULT_MISMATCH",
                crate::error::GuiErrorCategory::Unavailable,
                Some("historical-replay"),
                "bounded historical verification returned an unexpected result count",
            ));
        }

        let apply_start = std::time::Instant::now();
        self.apply_verified_packages_in_order(packages, verify_results)?;
        crate::instrumentation::add_ordered_apply_micros(
            u64::try_from(apply_start.elapsed().as_micros()).unwrap_or(u64::MAX),
        );

        Ok(())
    }

    /// Applies precomputed per-package cryptographic validity to the
    /// authoritative session, sequentially and in canonical package order.
    ///
    /// This reproduces [`process_intake_package`](Self::process_intake_package)
    /// exactly, package by package: transcript submission, then the combined
    /// (crypto validity → ledger acceptance) decision, then transcript decision
    /// recording and canonical storage. The only difference from serial replay
    /// is that the expensive proof validity was computed earlier and in
    /// parallel; the order-sensitive ledger/transcript/tally mutations remain
    /// strictly sequential here.
    fn apply_verified_packages_in_order(
        &mut self,
        packages: &[Vec<u8>],
        verify_results: Vec<
            Result<VerifiedApprovalBallotV1, tari_cc_private_ballot_protocol::ProtocolError>,
        >,
    ) -> Result<(), GuiCoreError> {
        for (package_bytes, verify_result) in packages.iter().zip(verify_results) {
            crate::instrumentation::record_historical_ballot_replayed();
            // Preserve the gui-core intake-pipeline verification count: one
            // logical proof verification per replayed package.
            crate::instrumentation::record_triptych_verify_call();

            let digest = Self::package_digest(package_bytes);
            let sequence = self
                .transcript
                .record_submission(digest, true)
                .map_err(|error| GuiCoreError::from_protocol(&error, "transcript"))?;

            let outcome = match verify_result {
                Ok(verified) => match self.ledger.accept_verified(&self.lifecycle, verified) {
                    Ok(()) => BallotDecisionOutcomeV1::Accepted,
                    Err(error) => BallotDecisionOutcomeV1::Rejected(error.code()),
                },
                Err(error) => BallotDecisionOutcomeV1::Rejected(error.code()),
            };

            self.transcript
                .record_decision(sequence, digest, outcome)
                .map_err(|error| GuiCoreError::from_protocol(&error, "transcript"))?;
            self.record_private_intake_digest_index_entry(sequence, digest, outcome);

            self.packages.push(package_bytes.clone());
        }

        crate::instrumentation::add_historical_serial_order_applies(packages.len() as u64);

        Ok(())
    }

    /// Applies the terminal lifecycle transitions after all packages are
    /// replayed. Shared by the parallel reconstruction path.
    fn apply_terminal_lifecycle(
        &mut self,
        lifecycle_state: ElectionLifecycleStateV1,
    ) -> Result<(), GuiCoreError> {
        match lifecycle_state {
            ElectionLifecycleStateV1::Open => Ok(()),
            ElectionLifecycleStateV1::Closed => self.close(),
            ElectionLifecycleStateV1::Verified => {
                self.close()?;
                self.mark_verified()
            }
            ElectionLifecycleStateV1::Finalized => {
                self.close()?;
                self.mark_verified()?;
                self.finalize()
            }
            ElectionLifecycleStateV1::Draft | ElectionLifecycleStateV1::Frozen => {
                Err(GuiCoreError::new(
                    "GUI_WORKSPACE_INVALID_STATE",
                    crate::error::GuiErrorCategory::ArchiveIntegrity,
                    Some("election-workspace"),
                    "durable workspace lifecycle state is inconsistent",
                ))
            }
        }
    }

    /// Returns the replayable durable session representation.
    ///
    /// # Errors
    ///
    /// Returns the existing canonical encoder error if any public artifact
    /// cannot be encoded.
    pub fn to_durable_snapshot(&self) -> Result<GuiElectionSessionSnapshotV1, GuiCoreError> {
        let manifest_bytes = self
            .artifacts
            .manifest()
            .to_canonical_cbor()
            .map_err(|error| GuiCoreError::from_protocol(&error, "manifest"))?;
        let registry_bytes = self
            .artifacts
            .registry()
            .to_canonical_cbor()
            .map_err(|error| GuiCoreError::from_protocol(&error, "registry"))?;
        let candidate_bytes = self
            .artifacts
            .candidates()
            .to_canonical_cbor()
            .map_err(|error| GuiCoreError::from_protocol(&error, "candidates"))?;

        Ok(GuiElectionSessionSnapshotV1 {
            lifecycle_state: self.lifecycle.state(),
            manifest_bytes,
            registry_bytes,
            candidate_bytes,
            packages: self.packages.clone(),
        })
    }

    /// Structurally clones this already-validated in-memory session for a
    /// transactional mutation candidate.
    ///
    /// This intentionally does not call [`from_durable_snapshot`](Self::from_durable_snapshot):
    /// disk resume still replays persisted packages through proof verification,
    /// but ordinary same-process mutations preserve the already-validated
    /// verifier, ledger, transcript, lifecycle, and package bytes directly.
    #[must_use]
    pub fn transactional_clone(&self) -> Self {
        self.clone()
    }

    /// Replays this session into a fresh value using its own durable snapshot.
    ///
    /// This remains available for hostile disk-resume validation tests and
    /// diagnostics. Normal shell mutations should use
    /// [`transactional_clone`](Self::transactional_clone) so historical proofs
    /// are not reverified on every ballot intake.
    pub fn replayed_clone(&self) -> Result<Self, GuiCoreError> {
        Self::from_durable_snapshot(self.to_durable_snapshot()?)
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
    /// Ingests one canonical ballot package through the full validation and
    /// acceptance boundary. Permitted only while the election is OPEN.
    ///
    /// Returns a bounded [`GuiCoreError`] with code `ELECTION_NOT_OPEN` when
    /// the election is not open (nothing is recorded), or if transcript
    /// recording itself fails.
    pub fn intake_ballot_package_bytes(
        &mut self,
        package_bytes: &[u8],
    ) -> Result<GuiBallotIntakeResultV1, GuiCoreError> {
        if !matches!(self.lifecycle.state(), ElectionLifecycleStateV1::Open) {
            return Err(GuiCoreError::new(
                ValidationCode::ElectionNotOpen.as_str(),
                crate::error::GuiErrorCategory::InvalidLifecycleTransition,
                Some("lifecycle"),
                "ballots are ingested only while the election is open",
            ));
        }
        self.process_intake_package(package_bytes)
    }

    /// Reconciles one canonical package from the DURABLE accepted-package
    /// inbox into this authoritative session.
    ///
    /// The inbox is content-addressed and is written ONLY by the collector
    /// AFTER full validation and acceptance, and ALWAYS before an ACCEPTED
    /// receipt is issued, so its presence IS durable evidence that this exact
    /// ballot was admitted while the election was authoritatively OPEN. This
    /// entry point therefore completes the documented post-close drain of
    /// already-admitted work: it stays available in `CLOSED` so a crash
    /// between collector acceptance and GUI reconciliation can never orphan a
    /// receipted ballot. It is NOT a generic post-close intake path — plain
    /// file import remains OPEN-gated, and VERIFIED/FINALIZED refuse outright
    /// because results are sealed at that point.
    ///
    /// Validation, nullifier ledger, transcript, and tally semantics are
    /// byte-for-byte identical to live intake.
    pub fn reconcile_accepted_package_bytes_from_inbox(
        &mut self,
        package_bytes: &[u8],
    ) -> Result<GuiBallotIntakeResultV1, GuiCoreError> {
        self.ensure_inbox_reconciliation_lifecycle()?;
        let digest = Self::package_digest(package_bytes);
        if let Some(result) = self.indexed_inbox_reconciliation_result(digest)? {
            return Ok(result);
        }
        self.process_intake_package_with_digest(package_bytes, digest)
    }

    /// Returns the reconciliation result for a previously fully validated,
    /// unchanged content-addressed inbox file. This avoids rereading/re-hashing
    /// a file only after an earlier pass proved both its bytes and its filename
    /// digest. The transcript index is revalidated before it is used.
    pub(crate) fn reconcile_cached_inbox_digest(
        &self,
        digest: BallotPackageDigestV1,
        byte_len: u64,
        modified: SystemTime,
    ) -> Result<Option<GuiBallotIntakeResultV1>, GuiCoreError> {
        self.ensure_inbox_reconciliation_lifecycle()?;
        let Some(cached) = self.private_inbox_validation_cache.get(&digest) else {
            return Ok(None);
        };
        if cached.byte_len != byte_len || cached.modified != modified {
            return Ok(None);
        }
        self.indexed_inbox_reconciliation_result(digest)
    }

    /// Records a successful full inbox file validation for possible reuse in a
    /// later sync pass. This is transient cache state, not durable authority.
    pub(crate) fn remember_validated_inbox_file(
        &mut self,
        digest: BallotPackageDigestV1,
        byte_len: u64,
        modified: SystemTime,
    ) {
        self.private_inbox_validation_cache
            .insert(digest, PrivateInboxFileValidationV1 { byte_len, modified });
    }

    /// Shared intake pipeline: digest → transcript submission → full protocol
    /// validation → decision recording → canonical storage.
    fn process_intake_package(
        &mut self,
        package_bytes: &[u8],
    ) -> Result<GuiBallotIntakeResultV1, GuiCoreError> {
        self.process_intake_package_with_digest(package_bytes, Self::package_digest(package_bytes))
    }

    fn process_intake_package_with_digest(
        &mut self,
        package_bytes: &[u8],
        digest: BallotPackageDigestV1,
    ) -> Result<GuiBallotIntakeResultV1, GuiCoreError> {
        let provider = Blake3HashProviderV1;

        let sequence = self
            .transcript
            .record_submission(digest, true)
            .map_err(|error| GuiCoreError::from_protocol(&error, "transcript"))?;

        // Each intake performs exactly one approval-proof verification, which
        // performs exactly one Triptych `verify`. Counting here is the
        // authoritative Triptych-invocation count for the gui-core pipeline.
        crate::instrumentation::record_triptych_verify_call();
        let verify_start = std::time::Instant::now();
        let ingest = ingest_approval_ballot_package_v1(
            package_bytes,
            self.artifacts.manifest(),
            self.artifacts.candidates(),
            &self.lifecycle,
            &mut self.ledger,
            &provider,
            &self.verifier,
        );
        crate::instrumentation::add_proof_verification_micros(
            u64::try_from(verify_start.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
        let outcome = match ingest {
            Ok(()) => BallotDecisionOutcomeV1::Accepted,
            Err(error) => BallotDecisionOutcomeV1::Rejected(error.code()),
        };

        self.transcript
            .record_decision(sequence, digest, outcome)
            .map_err(|error| GuiCoreError::from_protocol(&error, "transcript"))?;
        self.record_private_intake_digest_index_entry(sequence, digest, outcome);

        self.packages.push(package_bytes.to_vec());

        Ok(self.intake_result(sequence, digest, package_bytes, outcome))
    }

    fn ensure_inbox_reconciliation_lifecycle(&self) -> Result<(), GuiCoreError> {
        if matches!(
            self.lifecycle.state(),
            ElectionLifecycleStateV1::Draft
                | ElectionLifecycleStateV1::Frozen
                | ElectionLifecycleStateV1::Verified
                | ElectionLifecycleStateV1::Finalized
        ) {
            return Err(GuiCoreError::new(
                ValidationCode::ElectionNotOpen.as_str(),
                crate::error::GuiErrorCategory::InvalidLifecycleTransition,
                Some("lifecycle"),
                "inbox reconciliation is permitted only while voting is open or during the post-close drain",
            ));
        }
        Ok(())
    }

    fn indexed_inbox_reconciliation_result(
        &self,
        digest: BallotPackageDigestV1,
    ) -> Result<Option<GuiBallotIntakeResultV1>, GuiCoreError> {
        let Some(entry) = self.private_intake_digest_index.get(&digest).copied() else {
            crate::instrumentation::record_private_intake_digest_index_miss();
            return Ok(None);
        };
        crate::instrumentation::record_private_intake_digest_index_hit();

        let index = usize::try_from(entry.sequence.value()).map_err(|_| {
            private_intake_digest_index_inconsistent(
                "the indexed transcript sequence is not addressable",
            )
        })?;
        let Some(authoritative) = self.transcript.decisions().get(index) else {
            return Err(private_intake_digest_index_inconsistent(
                "the indexed transcript decision is missing",
            ));
        };
        if authoritative.sequence() != entry.sequence
            || authoritative.package_digest() != digest
            || authoritative.outcome() != entry.outcome
        {
            return Err(private_intake_digest_index_inconsistent(
                "the derived digest index disagrees with the authoritative transcript",
            ));
        }

        let outcome = if entry.outcome.is_accepted() {
            BallotDecisionOutcomeV1::Rejected(ValidationCode::DuplicateNullifier)
        } else {
            entry.outcome
        };
        Ok(Some(self.intake_result(
            entry.sequence,
            digest,
            &[],
            outcome,
        )))
    }

    fn record_private_intake_digest_index_entry(
        &mut self,
        sequence: tari_cc_private_ballot_archive::IngestSequenceV1,
        digest: BallotPackageDigestV1,
        outcome: BallotDecisionOutcomeV1,
    ) {
        // `reconcile_accepted_package_bytes_from_inbox` historically used
        // `decisions().iter().find(...)`; retain that exact earliest-decision
        // semantics when a live exact retry records another transcript row.
        self.private_intake_digest_index
            .entry(digest)
            .or_insert(TranscriptDecisionIndexEntryV1 { sequence, outcome });
    }

    fn package_digest(package_bytes: &[u8]) -> BallotPackageDigestV1 {
        BallotPackageDigestV1::new(hash_domain_separated(
            &Blake3HashProviderV1,
            HashDomain::BallotPackageV1,
            package_bytes,
        ))
    }

    /// Backward-compatible name for the canonical byte-intake boundary.
    ///
    /// All transports (local file today, future privacy transport later) must
    /// hand exact canonical package bytes to `intake_ballot_package_bytes`.
    /// The carrier path/name/timestamp is deliberately outside this facade.
    pub fn intake_ballot(
        &mut self,
        package_bytes: &[u8],
    ) -> Result<GuiBallotIntakeResultV1, GuiCoreError> {
        self.intake_ballot_package_bytes(package_bytes)
    }

    /// Builds the structured intake result without exposing replay or
    /// linkability internals over the GUI boundary.
    fn intake_result(
        &self,
        _sequence: tari_cc_private_ballot_archive::IngestSequenceV1,
        digest: BallotPackageDigestV1,
        _package_bytes: &[u8],
        outcome: BallotDecisionOutcomeV1,
    ) -> GuiBallotIntakeResultV1 {
        let mut result = GuiBallotIntakeResultV1 {
            accepted: outcome.is_accepted(),
            code: "ACCEPTED",
            category: GuiIntakeCategory::Accepted,
            package_digest_hex: crate::hex::to_lower_hex(digest.as_bytes()),
        };

        if outcome.is_accepted() {
            return result;
        }

        let Some(code) = outcome.rejection_code() else {
            return result;
        };
        // Keep the protocol validation code internal when it names a replay
        // primitive. The GUI receives a stable, safe outcome code instead.
        result.code = if code == ValidationCode::DuplicateNullifier {
            "DUPLICATE_BALLOT"
        } else {
            code.as_str()
        };
        result.category = GuiIntakeCategory::from_validation(code);

        result
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

fn private_intake_digest_index_inconsistent(message: &'static str) -> GuiCoreError {
    GuiCoreError::new(
        "GUI_PRIVATE_INTAKE_DIGEST_INDEX_INCONSISTENT",
        crate::error::GuiErrorCategory::ArchiveIntegrity,
        Some("private-intake-inbox"),
        message,
    )
}
