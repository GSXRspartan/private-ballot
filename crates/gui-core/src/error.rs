//! Bounded GUI-facing error type with stable machine codes.
//!
//! Every error carries a stable machine code (preserving the existing project
//! `ValidationCode`, config, snapshot, evidence, and lifecycle reconstruction
//! identifiers wherever one exists), a coarse category for frontend styling,
//! an optional static context label naming the artifact or stage, and a
//! bounded static message. No error carries a path, a secret, or raw
//! third-party error text.

use tari_cc_private_ballot_ootle_anchor_app::{ConfigFileError, EvidenceError, SnapshotFileError};
use tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::LifecycleReconstructionError;
use tari_cc_private_ballot_protocol::{ProtocolError, ValidationCode};

/// Coarse error category for frontend treatment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum GuiErrorCategory {
    /// The input artifact or value failed validation.
    InvalidInput,
    /// The format, version, hash algorithm, or proof suite is unsupported.
    UnsupportedFormat,
    /// Two artifacts that must match do not (commitments, manifests, bindings).
    BindingMismatch,
    /// A proof failed verification or is malformed.
    ProofFailure,
    /// A ballot duplicates an already-accepted nullifier.
    DuplicateBallot,
    /// An election lifecycle transition is not permitted in the current state.
    InvalidLifecycleTransition,
    /// An archive failed an integrity, digest, membership, or replay check.
    ArchiveIntegrity,
    /// A filesystem operation failed.
    FileIo,
    /// An anchor config, snapshot, or evidence artifact failed integrity or
    /// semantic validation.
    AnchorArtifactIntegrity,
    /// A private online transport route is unavailable (e.g. Tor not ready, a
    /// delivery failed, or no authenticated receipt was obtained). Offline
    /// export remains a separate, deliberate action.
    Unavailable,
}

impl GuiErrorCategory {
    /// Returns the stable machine-readable category code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "INVALID_INPUT",
            Self::UnsupportedFormat => "UNSUPPORTED_FORMAT",
            Self::BindingMismatch => "BINDING_MISMATCH",
            Self::ProofFailure => "PROOF_FAILURE",
            Self::DuplicateBallot => "DUPLICATE_BALLOT",
            Self::InvalidLifecycleTransition => "INVALID_LIFECYCLE_TRANSITION",
            Self::ArchiveIntegrity => "ARCHIVE_INTEGRITY",
            Self::FileIo => "FILE_IO",
            Self::AnchorArtifactIntegrity => "ANCHOR_ARTIFACT_INTEGRITY",
            Self::Unavailable => "UNAVAILABLE",
        }
    }
}

/// The single bounded gui-core error type.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiCoreError {
    code: &'static str,
    category: GuiErrorCategory,
    context: Option<&'static str>,
    message: &'static str,
}

impl GuiCoreError {
    /// Creates one bounded error.
    #[must_use]
    pub const fn new(
        code: &'static str,
        category: GuiErrorCategory,
        context: Option<&'static str>,
        message: &'static str,
    ) -> Self {
        Self {
            code,
            category,
            context,
            message,
        }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Returns the coarse category.
    #[must_use]
    pub const fn category(&self) -> GuiErrorCategory {
        self.category
    }

    /// Returns the optional static context label (an artifact or stage name).
    #[must_use]
    pub const fn context(&self) -> Option<&'static str> {
        self.context
    }

    /// Returns the bounded, non-sensitive message.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }

    /// Wraps a protocol validation failure, preserving its stable code.
    #[must_use]
    pub fn from_protocol(error: &ProtocolError, context: &'static str) -> Self {
        Self::new(
            error.code().as_str(),
            category_for_validation(error.code()),
            Some(context),
            error.message(),
        )
    }

    /// A required file was not present.
    #[must_use]
    pub const fn file_not_found(context: &'static str) -> Self {
        Self::new(
            "GUI_FILE_NOT_FOUND",
            GuiErrorCategory::FileIo,
            Some(context),
            "a required file was not found",
        )
    }

    /// A filesystem operation failed.
    #[must_use]
    pub const fn io_failure(context: &'static str) -> Self {
        Self::new(
            "GUI_IO_ERROR",
            GuiErrorCategory::FileIo,
            Some(context),
            "a filesystem operation failed",
        )
    }

    /// The recomputed registry commitment differs from the election manifest.
    #[must_use]
    pub const fn registry_commitment_mismatch() -> Self {
        Self::new(
            "GUI_REGISTRY_COMMITMENT_MISMATCH",
            GuiErrorCategory::BindingMismatch,
            Some("registry"),
            "the voter registry commitment does not match the election manifest",
        )
    }

    /// The archive target directory is not usable for a fresh archive.
    #[must_use]
    pub const fn archive_target_not_empty() -> Self {
        Self::new(
            "GUI_ARCHIVE_TARGET_NOT_EMPTY",
            GuiErrorCategory::FileIo,
            Some("archive-directory"),
            "the archive target directory already contains files",
        )
    }

    /// The archive target path exists and is not a directory.
    #[must_use]
    pub const fn archive_target_invalid() -> Self {
        Self::new(
            "GUI_ARCHIVE_TARGET_INVALID",
            GuiErrorCategory::FileIo,
            Some("archive-directory"),
            "the archive target path exists and is not a directory",
        )
    }

    /// A finalized archive was requested before the election reached FINALIZED.
    #[must_use]
    pub const fn archive_not_finalized() -> Self {
        Self::new(
            "GUI_ARCHIVE_NOT_FINALIZED",
            GuiErrorCategory::InvalidLifecycleTransition,
            Some("archive-finality"),
            "a finalized archive can only be written from a FINALIZED election",
        )
    }

    /// A live anchor config was requested from an archive that did not verify.
    #[must_use]
    pub const fn live_anchor_archive_not_verified() -> Self {
        Self::new(
            "GUI_LIVE_ANCHOR_ARCHIVE_NOT_VERIFIED",
            GuiErrorCategory::ArchiveIntegrity,
            Some("live-anchor-config"),
            "live anchor config generation requires a verified archive",
        )
    }

    /// A live anchor config was requested from a non-finalized archive.
    #[must_use]
    pub const fn live_anchor_archive_not_finalized() -> Self {
        Self::new(
            "GUI_LIVE_ANCHOR_ARCHIVE_NOT_FINALIZED",
            GuiErrorCategory::ArchiveIntegrity,
            Some("live-anchor-config"),
            "live anchor config generation requires a finalized archive",
        )
    }

    /// A live anchor config was requested without an explicit accepted-ballot floor.
    #[must_use]
    pub const fn live_anchor_floor_required() -> Self {
        Self::new(
            "GUI_LIVE_ANCHOR_ACCEPTED_FLOOR_REQUIRED",
            GuiErrorCategory::InvalidInput,
            Some("accepted-ballot-floor"),
            "live anchor config generation requires an explicit accepted-ballot floor",
        )
    }

    /// The verified archive did not meet the requested accepted-ballot floor.
    #[must_use]
    pub const fn live_anchor_accepted_floor_not_met() -> Self {
        Self::new(
            "GUI_LIVE_ANCHOR_ACCEPTED_FLOOR_NOT_MET",
            GuiErrorCategory::InvalidInput,
            Some("accepted-ballot-floor"),
            "the verified archive accepted-ballot count is below the requested floor",
        )
    }

    /// A live anchor config requires a verified final transport binding.
    #[must_use]
    pub const fn live_anchor_transport_binding_required() -> Self {
        Self::new(
            "GUI_LIVE_ANCHOR_TRANSPORT_BINDING_REQUIRED",
            GuiErrorCategory::BindingMismatch,
            Some("transport-binding"),
            "live anchor config generation requires a verified final transport binding",
        )
    }

    /// The archive replay accepted count does not match the transport binding.
    #[must_use]
    pub const fn live_anchor_transport_count_mismatch() -> Self {
        Self::new(
            "GUI_LIVE_ANCHOR_TRANSPORT_COUNT_MISMATCH",
            GuiErrorCategory::BindingMismatch,
            Some("transport-binding"),
            "the archive replay accepted count does not match the transport binding",
        )
    }

    /// The verified final transport binding reports reduced anonymity without acknowledgement.
    #[must_use]
    pub const fn live_anchor_reduced_anonymity_ack_required() -> Self {
        Self::new(
            "GUI_LIVE_ANCHOR_REDUCED_ANONYMITY_ACK_REQUIRED",
            GuiErrorCategory::InvalidInput,
            Some("reduced-anonymity"),
            "reduced anonymity must be explicitly acknowledged before live config generation",
        )
    }

    /// The operator did not attest that a dedicated organizer wallet is used.
    #[must_use]
    pub const fn live_anchor_dedicated_wallet_required() -> Self {
        Self::new(
            "GUI_LIVE_ANCHOR_DEDICATED_WALLET_REQUIRED",
            GuiErrorCategory::InvalidInput,
            Some("organizer-wallet"),
            "live anchor config generation requires dedicated organizer wallet attestation",
        )
    }

    /// A public operator config field was invalid.
    #[must_use]
    pub const fn live_anchor_operator_config_invalid() -> Self {
        Self::new(
            "GUI_LIVE_ANCHOR_OPERATOR_CONFIG_INVALID",
            GuiErrorCategory::InvalidInput,
            Some("live-anchor-config"),
            "a public live anchor operator configuration value is invalid",
        )
    }

    /// Builds a bounded error from a specific live-anchor field rejection.
    ///
    /// This preserves the field-specific machine code and message produced by
    /// the shared operator-field validators (see `live_anchor_preflight`),
    /// replacing the generic `GUI_LIVE_ANCHOR_OPERATOR_CONFIG_INVALID` funnel so
    /// the operator sees exactly which field failed. Both arguments are
    /// `&'static` so no secret or path can be embedded.
    #[must_use]
    pub const fn live_anchor_field_invalid(code: &'static str, message: &'static str) -> Self {
        Self::new(
            code,
            GuiErrorCategory::InvalidInput,
            Some("live-anchor-config"),
            message,
        )
    }

    /// No production transport authority public root has been configured, so a
    /// default/release build has nothing to verify production transport against.
    /// This is the fail-closed unconfigured state (never a fake-root fallback).
    #[must_use]
    pub const fn production_transport_authority_not_provisioned() -> Self {
        Self::new(
            "GUI_PRODUCTION_TRANSPORT_AUTHORITY_NOT_PROVISIONED",
            GuiErrorCategory::InvalidInput,
            Some("production-transport-authority"),
            "no production transport authority public root is configured; load the operator-supplied public root before production transport can be verified",
        )
    }

    /// A configured production transport authority public root field is invalid.
    /// The static `code`/`message` name the specific bad field (key id, public
    /// key encoding, reserved id, network, or root mismatch).
    #[must_use]
    pub const fn production_transport_authority_config_invalid(
        code: &'static str,
        message: &'static str,
    ) -> Self {
        Self::new(
            code,
            GuiErrorCategory::InvalidInput,
            Some("production-transport-authority"),
            message,
        )
    }

    /// A production transport authority public root is already configured and
    /// must be explicitly forgotten before a different one can replace it (root
    /// replacement is never silent).
    #[must_use]
    pub const fn production_transport_authority_already_configured() -> Self {
        Self::new(
            "GUI_PRODUCTION_TRANSPORT_AUTHORITY_ALREADY_CONFIGURED",
            GuiErrorCategory::InvalidLifecycleTransition,
            Some("production-transport-authority"),
            "a production transport authority public root is already configured; forget it explicitly before configuring a different one",
        )
    }

    /// The trusted Ootle deployment record is invalid, unsupported, or corrupt.
    #[must_use]
    pub const fn trusted_ootle_deployment_invalid() -> Self {
        Self::new(
            "GUI_TRUSTED_OOTLE_DEPLOYMENT_INVALID",
            GuiErrorCategory::InvalidInput,
            Some("trusted-ootle-deployment"),
            "the trusted Ootle anchor deployment record is invalid",
        )
    }

    /// A trusted Ootle deployment already exists and must be unlocked first.
    #[must_use]
    pub const fn trusted_ootle_deployment_locked() -> Self {
        Self::new(
            "GUI_TRUSTED_OOTLE_DEPLOYMENT_LOCKED",
            GuiErrorCategory::InvalidLifecycleTransition,
            Some("trusted-ootle-deployment"),
            "unlock the current Ootle anchor deployment before replacing it",
        )
    }

    /// A live anchor config was requested before a trusted deployment was locked.
    #[must_use]
    pub const fn trusted_ootle_deployment_required() -> Self {
        Self::new(
            "GUI_TRUSTED_OOTLE_DEPLOYMENT_REQUIRED",
            GuiErrorCategory::InvalidLifecycleTransition,
            Some("trusted-ootle-deployment"),
            "lock a trusted Ootle anchor deployment before preparing live anchor config",
        )
    }

    /// Unlocking the trusted deployment requires an explicit confirmation flag.
    #[must_use]
    pub const fn trusted_ootle_deployment_unlock_not_confirmed() -> Self {
        Self::new(
            "GUI_TRUSTED_OOTLE_DEPLOYMENT_UNLOCK_NOT_CONFIRMED",
            GuiErrorCategory::InvalidInput,
            Some("trusted-ootle-deployment"),
            "unlocking the trusted Ootle anchor deployment requires explicit confirmation",
        )
    }

    /// The live anchor config output path exists and force was not supplied.
    #[must_use]
    pub const fn live_anchor_config_output_exists() -> Self {
        Self::new(
            "GUI_LIVE_ANCHOR_CONFIG_OUTPUT_EXISTS",
            GuiErrorCategory::FileIo,
            Some("live-anchor-config"),
            "the live anchor config output file already exists",
        )
    }

    /// A mutable anchor output/state path is inside the finalized archive
    /// directory (HIGH-2). Writing there would mutate the finalized archive.
    #[must_use]
    pub const fn live_anchor_output_within_archive() -> Self {
        Self::new(
            "GUI_LIVE_ANCHOR_OUTPUT_WITHIN_ARCHIVE",
            GuiErrorCategory::InvalidInput,
            Some("live-anchor-config"),
            "anchor config, snapshot, and evidence paths must be outside the finalized archive directory",
        )
    }

    /// A walletd/indexer endpoint violates the live anchor endpoint policy (HIGH-3).
    #[must_use]
    pub const fn live_anchor_endpoint_not_loopback() -> Self {
        Self::new(
            "GUI_LIVE_ANCHOR_ENDPOINT_NOT_LOOPBACK",
            GuiErrorCategory::InvalidInput,
            Some("live-anchor-config"),
            "the walletd endpoint must be organizer-local loopback, and the indexer endpoint must be loopback or the trusted hosted Esmeralda indexer",
        )
    }

    /// The maximum fee is zero or exceeds the project policy ceiling (MEDIUM-3).
    #[must_use]
    pub const fn live_anchor_max_fee_out_of_policy() -> Self {
        Self::new(
            "GUI_LIVE_ANCHOR_MAX_FEE_OUT_OF_POLICY",
            GuiErrorCategory::InvalidInput,
            Some("live-anchor-config"),
            "the maximum fee must be greater than zero and within the anchor fee policy ceiling",
        )
    }

    /// GUI-driven publish was requested without the minimum privacy floor.
    #[must_use]
    pub const fn anchor_publish_privacy_floor() -> Self {
        Self::new(
            "GUI_ANCHOR_PUBLISH_PRIVACY_FLOOR",
            GuiErrorCategory::InvalidInput,
            Some("anchor-publish"),
            "publishing requires an explicit accepted-ballot floor of at least two",
        )
    }

    /// The verified cohort is smaller than the configured floor.
    #[must_use]
    pub const fn anchor_publish_accepted_below_floor() -> Self {
        Self::new(
            "GUI_ANCHOR_PUBLISH_COHORT_BELOW_FLOOR",
            GuiErrorCategory::InvalidInput,
            Some("anchor-publish"),
            "the verified archive has fewer accepted ballots than the required floor",
        )
    }

    /// The config lacks immutable live approval facts.
    #[must_use]
    pub const fn anchor_publish_live_facts_missing() -> Self {
        Self::new(
            "GUI_ANCHOR_PUBLISH_LIVE_FACTS_MISSING",
            GuiErrorCategory::InvalidInput,
            Some("anchor-publish"),
            "the anchor config lacks live approval facts required for publishing",
        )
    }

    /// The decision string was not one of approve, reject, or none.
    #[must_use]
    pub const fn anchor_publish_decision_invalid() -> Self {
        Self::new(
            "GUI_ANCHOR_PUBLISH_DECISION_INVALID",
            GuiErrorCategory::InvalidInput,
            Some("anchor-publish"),
            "the publish decision must be approve, reject, or none",
        )
    }

    /// The auth environment variable name is malformed or unreadable.
    #[must_use]
    pub const fn anchor_publish_auth_env_name_invalid() -> Self {
        Self::new(
            "GUI_ANCHOR_PUBLISH_AUTH_ENV_NAME_INVALID",
            GuiErrorCategory::InvalidInput,
            Some("anchor-publish"),
            "the walletd auth environment variable name is invalid or unreadable",
        )
    }

    /// The auth token failed validation (empty, whitespace, or too long).
    #[must_use]
    pub const fn anchor_publish_auth_token_invalid() -> Self {
        Self::new(
            "GUI_ANCHOR_PUBLISH_AUTH_TOKEN_INVALID",
            GuiErrorCategory::InvalidInput,
            Some("anchor-publish"),
            "the walletd bearer token failed validation",
        )
    }

    /// The bounded async executor could not be constructed.
    #[must_use]
    pub const fn anchor_publish_executor_failed() -> Self {
        Self::new(
            "GUI_ANCHOR_PUBLISH_EXECUTOR_FAILED",
            GuiErrorCategory::Unavailable,
            Some("anchor-publish"),
            "the bounded network executor could not be constructed",
        )
    }

    /// A real transport could not be constructed from the endpoints.
    #[must_use]
    pub const fn anchor_publish_transport_unavailable() -> Self {
        Self::new(
            "ANCHOR_PUBLISH_TRANSPORT_UNAVAILABLE",
            GuiErrorCategory::Unavailable,
            Some("anchor-publish"),
            "a network transport could not be constructed from the configured endpoints",
        )
    }

    /// A mutable anchor output/state path would write inside the finalized
    /// archive directory (HIGH-2), rejected before any network action.
    #[must_use]
    pub const fn anchor_publish_output_within_archive() -> Self {
        Self::new(
            "ANCHOR_PUBLISH_OUTPUT_WITHIN_ARCHIVE",
            GuiErrorCategory::InvalidInput,
            Some("anchor-publish"),
            "an anchor output path is inside the finalized archive; nothing was published",
        )
    }

    /// A walletd/indexer endpoint violates the live anchor endpoint policy
    /// (HIGH-3), rejected before any network action or secret transmission.
    #[must_use]
    pub const fn anchor_publish_endpoint_not_loopback() -> Self {
        Self::new(
            "ANCHOR_PUBLISH_ENDPOINT_NOT_LOOPBACK",
            GuiErrorCategory::InvalidInput,
            Some("anchor-publish"),
            "publishing requires organizer-local loopback walletd and a loopback or trusted hosted Esmeralda indexer endpoint",
        )
    }

    /// Another live publish step already holds the per-anchor lock (HIGH-1).
    #[must_use]
    pub const fn anchor_publish_lock_busy() -> Self {
        Self::new(
            "ANCHOR_PUBLISH_LOCK_BUSY",
            GuiErrorCategory::InvalidLifecycleTransition,
            Some("anchor-publish"),
            "another publish step for this election is already in progress",
        )
    }

    /// The durable per-anchor publish lock could not be acquired (HIGH-1).
    #[must_use]
    pub const fn anchor_publish_lock_unavailable() -> Self {
        Self::new(
            "ANCHOR_PUBLISH_LOCK_UNAVAILABLE",
            GuiErrorCategory::FileIo,
            Some("anchor-publish"),
            "the publish lock could not be acquired; nothing was published",
        )
    }

    /// An archive content file listed in the catalog is missing on disk.
    #[must_use]
    pub const fn archive_missing_file() -> Self {
        Self::new(
            "GUI_ARCHIVE_MISSING_FILE",
            GuiErrorCategory::ArchiveIntegrity,
            Some("archive-directory"),
            "a file listed in the archive catalog is missing",
        )
    }

    /// A file is present on disk that the archive catalog does not list.
    #[must_use]
    pub const fn archive_unexpected_file() -> Self {
        Self::new(
            "GUI_ARCHIVE_UNEXPECTED_FILE",
            GuiErrorCategory::ArchiveIntegrity,
            Some("archive-directory"),
            "the archive directory contains a file the catalog does not list",
        )
    }

    /// A required well-known election artifact is absent from the catalog.
    #[must_use]
    pub const fn archive_missing_artifact(context: &'static str) -> Self {
        Self::new(
            "GUI_ARCHIVE_MISSING_ARTIFACT",
            GuiErrorCategory::ArchiveIntegrity,
            Some(context),
            "a required election artifact is absent from the archive catalog",
        )
    }

    /// Tally results are sealed until voting has closed.
    ///
    /// Returned by [`crate::session::GuiElectionSessionV1::tally`] when the
    /// election lifecycle is `DRAFT`, `FROZEN`, or `OPEN`. Carries no tally
    /// data and no accepted-option counts.
    #[must_use]
    pub const fn tally_not_available_before_close() -> Self {
        Self::new(
            "GUI_TALLY_NOT_AVAILABLE_BEFORE_CLOSE",
            GuiErrorCategory::InvalidLifecycleTransition,
            Some("tally"),
            "Tally results are not available until voting is closed.",
        )
    }

    /// A frozen draft can no longer be mutated.
    #[must_use]
    pub const fn draft_already_frozen() -> Self {
        Self::new(
            "GUI_DRAFT_ALREADY_FROZEN",
            GuiErrorCategory::InvalidLifecycleTransition,
            Some("draft"),
            "the election draft is frozen and can no longer be edited",
        )
    }

    /// Freeze was attempted before the draft was complete.
    #[must_use]
    pub const fn draft_incomplete() -> Self {
        Self::new(
            "GUI_DRAFT_INCOMPLETE",
            GuiErrorCategory::InvalidInput,
            Some("draft"),
            "the election draft is missing required fields before freeze",
        )
    }

    /// A governance public key was malformed (bad hex, wrong length, or not a
    /// canonical non-identity Ristretto point).
    #[must_use]
    pub const fn malformed_public_key() -> Self {
        Self::new(
            "GUI_MALFORMED_PUBLIC_KEY",
            GuiErrorCategory::InvalidInput,
            Some("voters"),
            "a governance public key is malformed",
        )
    }

    /// A hex string was not valid even-length lowercase/uppercase hex.
    #[must_use]
    pub const fn malformed_hex_input() -> Self {
        Self::new(
            "GUI_MALFORMED_HEX",
            GuiErrorCategory::InvalidInput,
            Some("voters"),
            "a hex value is not valid hexadecimal",
        )
    }

    /// Export was requested before a frozen election exists.
    #[must_use]
    pub const fn no_frozen_election() -> Self {
        Self::new(
            "GUI_NO_FROZEN_ELECTION",
            GuiErrorCategory::InvalidLifecycleTransition,
            Some("draft"),
            "no frozen election is available to export",
        )
    }

    /// The export target directory already contains files.
    #[must_use]
    pub const fn export_target_not_empty() -> Self {
        Self::new(
            "GUI_EXPORT_TARGET_NOT_EMPTY",
            GuiErrorCategory::FileIo,
            Some("export-directory"),
            "the export target directory already contains files",
        )
    }

    /// The export target path exists and is not a directory.
    #[must_use]
    pub const fn export_target_invalid() -> Self {
        Self::new(
            "GUI_EXPORT_TARGET_INVALID",
            GuiErrorCategory::FileIo,
            Some("export-directory"),
            "the export target path exists and is not a directory",
        )
    }

    /// Two ballot options share the same display label after the existing
    /// display-label normalization. The canonical `CandidateSet` deduplicates
    /// by machine ID only; the organizer facade additionally rejects
    /// ambiguous duplicate display labels so voters cannot be presented with
    /// indistinguishable options.
    #[must_use]
    pub const fn duplicate_option_display_label() -> Self {
        Self::new(
            "GUI_DUPLICATE_OPTION_DISPLAY_LABEL",
            GuiErrorCategory::InvalidInput,
            Some("options"),
            "Ballot option display labels must be unique.",
        )
    }

    /// The configured approval limits would permit no castable ballot: maximum
    /// approvals is zero while abstention is disabled. The canonical
    /// `ApprovalLimits` type permits this combination, but no valid ballot
    /// could then be cast (an empty selection requires abstention, and a
    /// non-empty selection would exceed the zero maximum), so the organizer
    /// facade rejects it as an organizer safety rule.
    #[must_use]
    pub const fn uncastable_approval_limits() -> Self {
        Self::new(
            "GUI_UNCASTABLE_APPROVAL_LIMITS",
            GuiErrorCategory::InvalidInput,
            Some("rules"),
            "At least one approval must be allowed when abstention is disabled.",
        )
    }

    /// No governance document has been selected, but an operation requiring one
    /// (e.g. pin-by-document-digest) was requested.
    #[must_use]
    pub const fn no_governance_document() -> Self {
        Self::new(
            "GUI_NO_GOVERNANCE_DOCUMENT",
            GuiErrorCategory::InvalidInput,
            Some("governance-document"),
            "select a governance document first",
        )
    }

    /// The encrypted voter credential container has corrupt framing or
    /// unsupported V1 algorithm parameters.
    #[must_use]
    pub const fn credential_container_framing() -> Self {
        Self::new(
            "GUI_CREDENTIAL_CONTAINER_FRAMING",
            GuiErrorCategory::UnsupportedFormat,
            Some("credential-container"),
            "the voter credential file is not a supported V1 credential container",
        )
    }

    /// The encrypted voter credential container declares an unsupported format
    /// version.
    #[must_use]
    pub const fn credential_container_version() -> Self {
        Self::new(
            "GUI_CREDENTIAL_CONTAINER_VERSION",
            GuiErrorCategory::UnsupportedFormat,
            Some("credential-container"),
            "the voter credential file version is not supported",
        )
    }

    /// The credential could not be decrypted and reconstructed.
    #[must_use]
    pub const fn credential_unlock_failed() -> Self {
        Self::new(
            "GUI_CREDENTIAL_UNLOCK_FAILED",
            GuiErrorCategory::InvalidInput,
            Some("credential-container"),
            "Could not unlock credential. The passphrase may be incorrect or the file may be damaged.",
        )
    }

    /// A credential container could not be produced from valid inputs.
    #[must_use]
    pub const fn credential_encryption_failed() -> Self {
        Self::new(
            "GUI_CREDENTIAL_ENCRYPTION_FAILED",
            GuiErrorCategory::InvalidInput,
            Some("credential-container"),
            "the voter credential could not be encrypted",
        )
    }

    /// The decrypted scalar does not match the public governance key recorded
    /// in the authenticated container header.
    #[must_use]
    pub const fn credential_public_key_mismatch() -> Self {
        Self::new(
            "GUI_CREDENTIAL_PUBLIC_KEY_MISMATCH",
            GuiErrorCategory::BindingMismatch,
            Some("credential-container"),
            "the decrypted credential does not match the credential file public key",
        )
    }

    /// A credential write target already exists.
    #[must_use]
    pub const fn credential_output_collision() -> Self {
        Self::new(
            "GUI_CREDENTIAL_OUTPUT_COLLISION",
            GuiErrorCategory::FileIo,
            Some("credential-container"),
            "the credential output file already exists",
        )
    }

    /// A credential path is a symlink, reparse point, or otherwise unsafe for
    /// this storage helper.
    #[must_use]
    pub const fn credential_unsafe_path() -> Self {
        Self::new(
            "GUI_CREDENTIAL_UNSAFE_PATH",
            GuiErrorCategory::FileIo,
            Some("credential-container"),
            "the credential path is not a regular direct file path",
        )
    }

    /// A credential operation requires an unlocked in-memory credential.
    #[must_use]
    pub const fn credential_not_loaded() -> Self {
        Self::new(
            "GUI_CREDENTIAL_NOT_LOADED",
            GuiErrorCategory::InvalidLifecycleTransition,
            Some("credential"),
            "no voter credential is currently loaded",
        )
    }

    /// A different voter credential is already loaded in memory.
    #[must_use]
    pub const fn credential_already_loaded() -> Self {
        Self::new(
            "GUI_CREDENTIAL_ALREADY_LOADED",
            GuiErrorCategory::InvalidLifecycleTransition,
            Some("credential"),
            "a different voter credential is already loaded; clear it before switching",
        )
    }
}

/// Maps an existing protocol validation code onto a coarse GUI category.
#[must_use]
pub const fn category_for_validation(code: ValidationCode) -> GuiErrorCategory {
    match code {
        ValidationCode::DuplicateNullifier => GuiErrorCategory::DuplicateBallot,
        ValidationCode::MalformedProof => GuiErrorCategory::ProofFailure,
        ValidationCode::WrongManifestHash
        | ValidationCode::CandidateSetCommitmentMismatch
        | ValidationCode::LifecycleCommitmentMismatch
        | ValidationCode::BallotDecisionDigestMismatch => GuiErrorCategory::BindingMismatch,
        ValidationCode::InvalidLifecycleTransition | ValidationCode::ElectionNotOpen => {
            GuiErrorCategory::InvalidLifecycleTransition
        }
        ValidationCode::UnsupportedProtocolVersion
        | ValidationCode::UnsupportedHashAlgorithm
        | ValidationCode::UnsupportedProofSuite => GuiErrorCategory::UnsupportedFormat,
        ValidationCode::ArchiveFileDigestMismatch
        | ValidationCode::ArchiveManifestHashMismatch
        | ValidationCode::InvalidArchiveManifest
        | ValidationCode::EmptyArchiveFileSet
        | ValidationCode::EmptyArchivePath
        | ValidationCode::InvalidArchivePath
        | ValidationCode::DuplicateArchivePath
        | ValidationCode::InvalidIngestSequence
        | ValidationCode::DuplicateBallotDecision
        | ValidationCode::IncompleteVerificationTranscript => GuiErrorCategory::ArchiveIntegrity,
        _ => GuiErrorCategory::InvalidInput,
    }
}

impl From<ConfigFileError> for GuiCoreError {
    fn from(error: ConfigFileError) -> Self {
        let category = match error {
            ConfigFileError::FileNotFound | ConfigFileError::IoFailure => GuiErrorCategory::FileIo,
            ConfigFileError::UnsupportedProtocolVersion
            | ConfigFileError::UnsupportedHashAlgorithm
            | ConfigFileError::UnsupportedNetwork => GuiErrorCategory::UnsupportedFormat,
            ConfigFileError::DigestMismatch | ConfigFileError::NetworkMismatch => {
                GuiErrorCategory::AnchorArtifactIntegrity
            }
            _ => GuiErrorCategory::InvalidInput,
        };
        Self::new(
            error.as_str(),
            category,
            Some("anchor-config"),
            "anchor application config failed validation",
        )
    }
}

impl From<SnapshotFileError> for GuiCoreError {
    fn from(error: SnapshotFileError) -> Self {
        let category = match error {
            SnapshotFileError::FileNotFound | SnapshotFileError::IoFailure => {
                GuiErrorCategory::FileIo
            }
            SnapshotFileError::UnsupportedProtocolVersion
            | SnapshotFileError::UnsupportedHashAlgorithm => GuiErrorCategory::UnsupportedFormat,
            _ => GuiErrorCategory::AnchorArtifactIntegrity,
        };
        Self::new(
            error.as_str(),
            category,
            Some("anchor-snapshot"),
            "anchor lifecycle snapshot failed validation",
        )
    }
}

impl From<EvidenceError> for GuiCoreError {
    fn from(error: EvidenceError) -> Self {
        Self::new(
            error.as_str(),
            GuiErrorCategory::AnchorArtifactIntegrity,
            Some("anchor-evidence"),
            "anchor evidence record failed validation",
        )
    }
}

impl From<LifecycleReconstructionError> for GuiCoreError {
    fn from(error: LifecycleReconstructionError) -> Self {
        Self::new(
            error.as_str(),
            GuiErrorCategory::AnchorArtifactIntegrity,
            Some("anchor-snapshot"),
            "anchor lifecycle snapshot is not semantically consistent",
        )
    }
}

impl core::fmt::Display for GuiCoreError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.context {
            Some(context) => write!(formatter, "{} ({context}): {}", self.code, self.message),
            None => write!(formatter, "{}: {}", self.code, self.message),
        }
    }
}

impl std::error::Error for GuiCoreError {}
