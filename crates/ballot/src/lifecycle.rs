//! Append-only election lifecycle and frozen commitment boundary.

use tari_cc_private_ballot_protocol::{
    ManifestHash, ProofStatementV1, ProtocolError, RegistryCommitment, ValidationCode,
};

/// Stable lifecycle states for one version-one election.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ElectionLifecycleStateV1 {
    Draft,
    Frozen,
    Open,
    Closed,
    Verified,
    Finalized,
}

impl ElectionLifecycleStateV1 {
    /// Returns the stable machine-readable lifecycle identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "DRAFT",
            Self::Frozen => "FROZEN",
            Self::Open => "OPEN",
            Self::Closed => "CLOSED",
            Self::Verified => "VERIFIED",
            Self::Finalized => "FINALIZED",
        }
    }
}

/// Append-only lifecycle with immutable frozen election commitments.
///
/// The only permitted path is:
///
/// `DRAFT -> FROZEN -> OPEN -> CLOSED -> VERIFIED -> FINALIZED`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElectionLifecycleV1 {
    state: ElectionLifecycleStateV1,
    frozen_manifest_hash: Option<ManifestHash>,
    frozen_registry_commitment: Option<RegistryCommitment>,
}

impl Default for ElectionLifecycleV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl ElectionLifecycleV1 {
    /// Creates a draft election with no frozen commitments.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: ElectionLifecycleStateV1::Draft,
            frozen_manifest_hash: None,
            frozen_registry_commitment: None,
        }
    }

    /// Returns the current append-only lifecycle state.
    #[must_use]
    pub const fn state(&self) -> ElectionLifecycleStateV1 {
        self.state
    }

    /// Returns whether ballot acceptance is currently permitted.
    #[must_use]
    pub const fn is_open(&self) -> bool {
        matches!(self.state, ElectionLifecycleStateV1::Open)
    }

    /// Returns the manifest hash fixed when the election was frozen.
    #[must_use]
    pub fn frozen_manifest_hash(&self) -> Option<&ManifestHash> {
        self.frozen_manifest_hash.as_ref()
    }

    /// Returns the registry commitment fixed when the election was frozen.
    #[must_use]
    pub fn frozen_registry_commitment(&self) -> Option<&RegistryCommitment> {
        self.frozen_registry_commitment.as_ref()
    }

    /// Freezes the canonical manifest and registry commitments.
    pub fn freeze(
        &mut self,
        manifest_hash: ManifestHash,
        registry_commitment: RegistryCommitment,
    ) -> Result<(), ProtocolError> {
        if self.state != ElectionLifecycleStateV1::Draft {
            return Err(invalid_transition());
        }

        self.frozen_manifest_hash = Some(manifest_hash);
        self.frozen_registry_commitment = Some(registry_commitment);
        self.state = ElectionLifecycleStateV1::Frozen;

        Ok(())
    }

    /// Opens the frozen election for ballot acceptance.
    pub fn open(&mut self) -> Result<(), ProtocolError> {
        self.transition(
            ElectionLifecycleStateV1::Frozen,
            ElectionLifecycleStateV1::Open,
        )
    }

    /// Closes ballot acceptance permanently.
    pub fn close(&mut self) -> Result<(), ProtocolError> {
        self.transition(
            ElectionLifecycleStateV1::Open,
            ElectionLifecycleStateV1::Closed,
        )
    }

    /// Records completion of public verification and tally reproduction.
    pub fn mark_verified(&mut self) -> Result<(), ProtocolError> {
        self.transition(
            ElectionLifecycleStateV1::Closed,
            ElectionLifecycleStateV1::Verified,
        )
    }

    /// Finalizes the verified result and archive commitments.
    pub fn finalize(&mut self) -> Result<(), ProtocolError> {
        self.transition(
            ElectionLifecycleStateV1::Verified,
            ElectionLifecycleStateV1::Finalized,
        )
    }

    /// Checks that one proof statement belongs to the currently admissible
    /// election window.
    ///
    /// Admission semantics (see `docs/transport/TRANSPORT_ADMISSION_AND_CLOSE_V1`):
    ///
    /// * `OPEN` — normal live admission.
    /// * `CLOSED` — the documented post-close DRAIN window: only work that was
    ///   ALREADY admitted while open may complete its durable hand-off. Network
    ///   admission is fenced at the collector (authoritative-lifecycle gate), so
    ///   no NEW ballot can enter through any application path after close; this
    ///   state exists solely so a crash between collector acceptance and
    ///   workspace reconciliation can never orphan a receipted ballot.
    /// * Every other state — refused outright (`DRAFT`, `FROZEN` never
    ///   admitted anything; `VERIFIED`/`FINALIZED` have sealed results).
    pub fn validate_ballot_statement(
        &self,
        statement: &ProofStatementV1,
    ) -> Result<(), ProtocolError> {
        if !matches!(
            self.state,
            ElectionLifecycleStateV1::Open | ElectionLifecycleStateV1::Closed
        ) {
            return Err(ProtocolError::new(
                ValidationCode::ElectionNotOpen,
                "ballots are accepted only while the election is open (or during the documented post-close drain)",
            ));
        }

        let Some(manifest_hash) = self.frozen_manifest_hash.as_ref() else {
            return Err(ProtocolError::new(
                ValidationCode::InvalidLifecycleTransition,
                "open election is missing its frozen manifest hash",
            ));
        };

        let Some(registry_commitment) = self.frozen_registry_commitment.as_ref() else {
            return Err(ProtocolError::new(
                ValidationCode::InvalidLifecycleTransition,
                "open election is missing its frozen registry commitment",
            ));
        };

        if statement.manifest_hash().as_bytes() != manifest_hash.as_bytes() {
            return Err(ProtocolError::new(
                ValidationCode::WrongManifestHash,
                "verified ballot belongs to a different frozen manifest",
            ));
        }

        if statement.registry_commitment().as_bytes() != registry_commitment.as_bytes() {
            return Err(ProtocolError::new(
                ValidationCode::LifecycleCommitmentMismatch,
                "verified ballot uses a different frozen registry commitment",
            ));
        }

        Ok(())
    }

    fn transition(
        &mut self,
        expected: ElectionLifecycleStateV1,
        next: ElectionLifecycleStateV1,
    ) -> Result<(), ProtocolError> {
        if self.state != expected {
            return Err(invalid_transition());
        }

        self.state = next;
        Ok(())
    }
}

fn invalid_transition() -> ProtocolError {
    ProtocolError::new(
        ValidationCode::InvalidLifecycleTransition,
        "election lifecycle transition is not permitted",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tari_cc_private_ballot_protocol::{
        BallotPayloadHash, ElectionScope, PROTOCOL_VERSION_V1, ProofStatementV1Input,
    };

    fn statement(manifest_byte: u8, registry_byte: u8) -> ProofStatementV1 {
        let Ok(statement) = ProofStatementV1::new(ProofStatementV1Input {
            protocol_version: PROTOCOL_VERSION_V1,
            proof_suite_id: "test-suite".to_owned(),
            manifest_hash: ManifestHash::new([manifest_byte; 32]),
            election_scope: ElectionScope::new([2_u8; 32]),
            registry_commitment: RegistryCommitment::new([registry_byte; 32]),
            ballot_payload_hash: BallotPayloadHash::new([4_u8; 32]),
            ballot_kind_id: "NON_BINDING_APPROVAL_PILOT".to_owned(),
            ballot_confidentiality_id: "PUBLIC".to_owned(),
        }) else {
            panic!("test proof statement must be valid");
        };

        statement
    }

    fn frozen_lifecycle() -> ElectionLifecycleV1 {
        let mut lifecycle = ElectionLifecycleV1::new();

        assert!(
            lifecycle
                .freeze(
                    ManifestHash::new([1_u8; 32]),
                    RegistryCommitment::new([3_u8; 32]),
                )
                .is_ok()
        );

        lifecycle
    }

    #[test]
    fn lifecycle_identifiers_are_stable() {
        let states = [
            (ElectionLifecycleStateV1::Draft, "DRAFT"),
            (ElectionLifecycleStateV1::Frozen, "FROZEN"),
            (ElectionLifecycleStateV1::Open, "OPEN"),
            (ElectionLifecycleStateV1::Closed, "CLOSED"),
            (ElectionLifecycleStateV1::Verified, "VERIFIED"),
            (ElectionLifecycleStateV1::Finalized, "FINALIZED"),
        ];

        for (state, identifier) in states {
            assert_eq!(state.as_str(), identifier);
        }
    }

    #[test]
    fn new_lifecycle_starts_in_draft_without_commitments() {
        let lifecycle = ElectionLifecycleV1::new();

        assert_eq!(lifecycle.state(), ElectionLifecycleStateV1::Draft);
        assert!(!lifecycle.is_open());
        assert!(lifecycle.frozen_manifest_hash().is_none());
        assert!(lifecycle.frozen_registry_commitment().is_none());
    }

    #[test]
    fn ordered_lifecycle_reaches_finalized() {
        let mut lifecycle = frozen_lifecycle();

        assert!(lifecycle.open().is_ok());
        assert!(lifecycle.close().is_ok());
        assert!(lifecycle.mark_verified().is_ok());
        assert!(lifecycle.finalize().is_ok());

        assert_eq!(lifecycle.state(), ElectionLifecycleStateV1::Finalized);
    }

    #[test]
    fn skipping_a_state_is_rejected_without_mutation() {
        let mut lifecycle = ElectionLifecycleV1::new();
        let result = lifecycle.open();

        assert!(matches!(
            result,
            Err(error)
                if error.code()
                    == ValidationCode::InvalidLifecycleTransition
        ));
        assert_eq!(lifecycle.state(), ElectionLifecycleStateV1::Draft);
    }

    #[test]
    fn backward_transition_is_rejected() {
        let mut lifecycle = frozen_lifecycle();

        assert!(lifecycle.open().is_ok());

        let result = lifecycle.freeze(
            ManifestHash::new([9_u8; 32]),
            RegistryCommitment::new([9_u8; 32]),
        );

        assert!(matches!(
            result,
            Err(error)
                if error.code()
                    == ValidationCode::InvalidLifecycleTransition
        ));
        assert_eq!(lifecycle.state(), ElectionLifecycleStateV1::Open);
    }

    #[test]
    fn frozen_commitments_survive_all_later_transitions() {
        let mut lifecycle = frozen_lifecycle();

        assert!(lifecycle.open().is_ok());
        assert!(lifecycle.close().is_ok());
        assert!(lifecycle.mark_verified().is_ok());
        assert!(lifecycle.finalize().is_ok());

        let Some(manifest_hash) = lifecycle.frozen_manifest_hash() else {
            panic!("frozen manifest hash must remain present");
        };

        let Some(registry_commitment) = lifecycle.frozen_registry_commitment() else {
            panic!("frozen registry commitment must remain present");
        };

        assert_eq!(manifest_hash.as_bytes(), &[1_u8; 32]);
        assert_eq!(registry_commitment.as_bytes(), &[3_u8; 32]);
    }

    #[test]
    fn only_open_or_closed_states_accept_a_matching_statement() {
        let matching = statement(1, 3);
        let mut lifecycle = frozen_lifecycle();

        assert!(matches!(
            lifecycle.validate_ballot_statement(&matching),
            Err(error) if error.code() == ValidationCode::ElectionNotOpen
        ));

        assert!(lifecycle.open().is_ok());
        assert!(lifecycle.validate_ballot_statement(&matching).is_ok());

        assert!(lifecycle.close().is_ok());
        // CLOSED is the documented drain window for ALREADY-admitted work;
        // network admission itself is fenced at the collector.
        assert!(lifecycle.validate_ballot_statement(&matching).is_ok());
    }

    #[test]
    fn wrong_manifest_is_rejected() {
        let mut lifecycle = frozen_lifecycle();
        assert!(lifecycle.open().is_ok());

        assert!(matches!(
            lifecycle.validate_ballot_statement(&statement(9, 3)),
            Err(error) if error.code() == ValidationCode::WrongManifestHash
        ));
    }

    #[test]
    fn wrong_registry_commitment_is_rejected() {
        let mut lifecycle = frozen_lifecycle();
        assert!(lifecycle.open().is_ok());

        assert!(matches!(
            lifecycle.validate_ballot_statement(&statement(1, 9)),
            Err(error)
                if error.code()
                    == ValidationCode::LifecycleCommitmentMismatch
        ));
    }
}
