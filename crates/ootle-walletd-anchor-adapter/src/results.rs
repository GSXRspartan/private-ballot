//! Project-owned lifecycle results (Sections C, D, E, F).
//!
//! These DTOs report only confirmed data. None claims a signature, a transaction
//! identifier, submission, acceptance, or finality: on the confirmed walletd API
//! a transaction identifier exists only after `transaction_requests.submit`
//! (Slice 4A6B), and the approval/rejection responses carry no identifier at all.
//! The account reference and walletd request identifier redact their own `Debug`.

use tari_cc_private_ballot_anchor::OOTLE_ANCHOR_PURPOSE_ID_V1;
use tari_cc_private_ballot_anchor_transport::{AnchorLifecycleState, AnchorRequestId};

use crate::binding::WalletdAnchorBindingV1;
use crate::convert::to_lower_hex_32;
use crate::identifiers::WalletdRequestId;

/// A prepared walletd anchor request, in the `Prepared` lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedWalletdAnchorRequestV1 {
    project_request_id: AnchorRequestId,
    walletd_request_id: WalletdRequestId,
    binding: WalletdAnchorBindingV1,
    instruction_count: usize,
    expires_at: i64,
    state: AnchorLifecycleState,
}

impl PreparedWalletdAnchorRequestV1 {
    /// Assembles a prepared result in the `Prepared` state.
    #[must_use]
    pub(crate) fn new(
        project_request_id: AnchorRequestId,
        walletd_request_id: WalletdRequestId,
        binding: WalletdAnchorBindingV1,
        instruction_count: usize,
        expires_at: i64,
    ) -> Self {
        Self {
            project_request_id,
            walletd_request_id,
            binding,
            instruction_count,
            expires_at,
            state: AnchorLifecycleState::Prepared,
        }
    }

    /// Returns the deterministic project request identifier.
    #[must_use]
    pub const fn project_request_id(&self) -> &AnchorRequestId {
        &self.project_request_id
    }

    /// Returns the opaque walletd request identifier.
    #[must_use]
    pub const fn walletd_request_id(&self) -> WalletdRequestId {
        self.walletd_request_id
    }

    /// Returns the frozen project-owned binding.
    #[must_use]
    pub const fn binding(&self) -> &WalletdAnchorBindingV1 {
        &self.binding
    }

    /// Returns the number of normal instructions in the frozen transaction.
    #[must_use]
    pub const fn instruction_count(&self) -> usize {
        self.instruction_count
    }

    /// Returns the walletd-reported approval-window expiry (unix seconds).
    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// Returns the lifecycle state, always `Prepared`.
    #[must_use]
    pub const fn state(&self) -> AnchorLifecycleState {
        self.state
    }

    /// Renders a deterministic, bounded human-review summary (Section D).
    ///
    /// It derives entirely from the inspected transaction binding: the fixed
    /// pilot purpose, network, fee account, maximum fee, exact 64-character
    /// anchor digest, exact tagged `EmitLog` payload, and instruction count. It
    /// states explicitly that no transaction identifier exists yet and that no
    /// voter or ballot data is present. It contains no caller-supplied prose.
    #[must_use]
    pub fn human_review_summary(&self) -> String {
        format!(
            "walletd-anchor-request purpose={} network={} fee_account={} max_fee={} \
anchor_digest={} emit_log_payload={} instruction_count={} transaction_id=NONE_YET \
voter_or_ballot_data=NONE",
            OOTLE_ANCHOR_PURPOSE_ID_V1,
            self.binding.network().as_str(),
            self.binding.account().as_str(),
            self.binding.max_fee().value(),
            to_lower_hex_32(self.binding.anchor_digest().as_bytes()),
            self.binding.payload().to_encoded_string(),
            self.instruction_count,
        )
    }
}

/// An approved walletd anchor request, in the `Approved` lifecycle state.
///
/// Approval is a gate decision only: it claims no signature bytes, no
/// transaction identifier, no submission, and no finality.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedWalletdAnchorRequestV1 {
    project_request_id: AnchorRequestId,
    walletd_request_id: WalletdRequestId,
    binding: WalletdAnchorBindingV1,
    state: AnchorLifecycleState,
}

impl ApprovedWalletdAnchorRequestV1 {
    /// Assembles an approved result in the `Approved` state.
    #[must_use]
    pub(crate) fn new(
        project_request_id: AnchorRequestId,
        walletd_request_id: WalletdRequestId,
        binding: WalletdAnchorBindingV1,
    ) -> Self {
        Self {
            project_request_id,
            walletd_request_id,
            binding,
            state: AnchorLifecycleState::Approved,
        }
    }

    /// Returns the project request identifier this approval binds to.
    #[must_use]
    pub const fn project_request_id(&self) -> &AnchorRequestId {
        &self.project_request_id
    }

    /// Returns the opaque walletd request identifier.
    #[must_use]
    pub const fn walletd_request_id(&self) -> WalletdRequestId {
        self.walletd_request_id
    }

    /// Returns the frozen project-owned binding.
    #[must_use]
    pub const fn binding(&self) -> &WalletdAnchorBindingV1 {
        &self.binding
    }

    /// Returns the lifecycle state, always `Approved`.
    #[must_use]
    pub const fn state(&self) -> AnchorLifecycleState {
        self.state
    }
}

/// A rejected walletd anchor request, in the `RejectedByApprover` state.
///
/// Rejection is terminal for this adapter: a rejected request can never be
/// approved through the coordinator. It produces no transaction identifier and
/// touches no archive or anchor artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedWalletdAnchorRequestV1 {
    project_request_id: AnchorRequestId,
    walletd_request_id: WalletdRequestId,
    binding: WalletdAnchorBindingV1,
    state: AnchorLifecycleState,
}

impl RejectedWalletdAnchorRequestV1 {
    /// Assembles a rejected result in the `RejectedByApprover` state.
    #[must_use]
    pub(crate) fn new(
        project_request_id: AnchorRequestId,
        walletd_request_id: WalletdRequestId,
        binding: WalletdAnchorBindingV1,
    ) -> Self {
        Self {
            project_request_id,
            walletd_request_id,
            binding,
            state: AnchorLifecycleState::RejectedByApprover,
        }
    }

    /// Returns the project request identifier this rejection binds to.
    #[must_use]
    pub const fn project_request_id(&self) -> &AnchorRequestId {
        &self.project_request_id
    }

    /// Returns the opaque walletd request identifier.
    #[must_use]
    pub const fn walletd_request_id(&self) -> WalletdRequestId {
        self.walletd_request_id
    }

    /// Returns the frozen project-owned binding.
    #[must_use]
    pub const fn binding(&self) -> &WalletdAnchorBindingV1 {
        &self.binding
    }

    /// Returns the lifecycle state, always `RejectedByApprover`.
    #[must_use]
    pub const fn state(&self) -> AnchorLifecycleState {
        self.state
    }
}
