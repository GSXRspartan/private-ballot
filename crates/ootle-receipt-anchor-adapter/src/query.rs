//! Project-owned receipt query identifier (Section A).
//!
//! An [`AnchorReceiptQueryV1`] is the fully-bound input to a receipt query. It is
//! constructed only from an already-validated
//! [`SubmittedWalletdAnchorRequestV1`], so it can never carry a caller-invented
//! anchor digest, arbitrary log text, a different transaction id, or any wallet
//! secret, ballot, or archive content: every field is copied from the submitted
//! binding. Before a query is issued the binding is revalidated against the
//! submitted request with [`AnchorReceiptQueryV1::ensure_matches_submitted`].

use tari_cc_private_ballot_anchor::{OotleAnchorRecordHashV1, OotleNetworkIdV1};
use tari_cc_private_ballot_anchor_transport::{
    AnchorAccountReference, AnchorEpochBindingV1, AnchorLogPayloadV1, AnchorRequestId,
    AnchorTemplateBindingV1, AnchorTransactionId,
};
use tari_cc_private_ballot_ootle_anchor_adapter::OotleAnchorInspectionFingerprintV1;
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::{
    SubmittedWalletdAnchorRequestV1, WalletdRequestId,
};

use crate::errors::ReceiptQueryBindingError;

/// A fully-bound, project-owned receipt query derived from a submitted request.
///
/// It fixes the identifiers, network, fee account, expected anchor digest, exact
/// expected anchor log payload, and unsigned-transaction fingerprint that a
/// retrieved receipt must be verified against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorReceiptQueryV1 {
    project_request_id: AnchorRequestId,
    walletd_request_id: WalletdRequestId,
    transaction_id: AnchorTransactionId,
    network: OotleNetworkIdV1,
    account: AnchorAccountReference,
    anchor_digest: OotleAnchorRecordHashV1,
    payload: AnchorLogPayloadV1,
    fingerprint: OotleAnchorInspectionFingerprintV1,
    template_binding: Option<AnchorTemplateBindingV1>,
    epoch_binding: Option<AnchorEpochBindingV1>,
}

impl AnchorReceiptQueryV1 {
    /// Builds a receipt query from a validated submitted walletd request.
    ///
    /// Every field is copied from the submitted request's frozen binding, so the
    /// query is bound to exactly the anchor that was submitted.
    #[must_use]
    pub fn from_submitted(submitted: &SubmittedWalletdAnchorRequestV1) -> Self {
        let binding = submitted.binding();
        Self {
            project_request_id: submitted.project_request_id().clone(),
            walletd_request_id: submitted.walletd_request_id(),
            transaction_id: submitted.transaction_id().clone(),
            network: binding.network().clone(),
            account: binding.account().clone(),
            anchor_digest: binding.anchor_digest(),
            payload: *binding.payload(),
            fingerprint: binding.fingerprint(),
            template_binding: binding.template_binding().cloned(),
            epoch_binding: binding.epoch_binding(),
        }
    }

    /// Revalidates the query against the submitted request it should have come
    /// from (Section A).
    ///
    /// Field order fixes which mismatch a caller sees first. Any divergence is a
    /// distinct, bounded error; nothing here can panic. This is the check a caller
    /// runs immediately before querying, so a query that was tampered with (or
    /// paired with the wrong submitted request) is rejected before any receipt is
    /// fetched.
    ///
    /// # Errors
    ///
    /// Returns the specific [`ReceiptQueryBindingError`] for the first differing
    /// field.
    pub fn ensure_matches_submitted(
        &self,
        submitted: &SubmittedWalletdAnchorRequestV1,
    ) -> Result<(), ReceiptQueryBindingError> {
        let binding = submitted.binding();
        if self.project_request_id != *submitted.project_request_id() {
            return Err(ReceiptQueryBindingError::ProjectRequestIdMismatch);
        }
        if self.walletd_request_id != submitted.walletd_request_id() {
            return Err(ReceiptQueryBindingError::WalletdRequestIdMismatch);
        }
        if self.transaction_id != *submitted.transaction_id() {
            return Err(ReceiptQueryBindingError::TransactionIdMismatch);
        }
        if self.network != *binding.network() {
            return Err(ReceiptQueryBindingError::NetworkMismatch);
        }
        if self.anchor_digest != binding.anchor_digest() {
            return Err(ReceiptQueryBindingError::AnchorDigestMismatch);
        }
        if self.payload != *binding.payload() {
            return Err(ReceiptQueryBindingError::PayloadMismatch);
        }
        if self.fingerprint != binding.fingerprint() {
            return Err(ReceiptQueryBindingError::FingerprintMismatch);
        }
        if self.template_binding.as_ref() != binding.template_binding() {
            return Err(ReceiptQueryBindingError::TemplateMismatch);
        }
        if self.epoch_binding != binding.epoch_binding() {
            return Err(ReceiptQueryBindingError::EpochMismatch);
        }
        // The account is part of the frozen binding; a divergence here is a
        // payload-independent binding tamper. It is checked last because network,
        // digest, payload, and fingerprint are the security-critical fields a
        // receipt is verified against.
        if self.account != *binding.account() {
            return Err(ReceiptQueryBindingError::PayloadMismatch);
        }
        Ok(())
    }

    /// Returns the bound project request identifier.
    #[must_use]
    pub const fn project_request_id(&self) -> &AnchorRequestId {
        &self.project_request_id
    }

    /// Returns the bound opaque walletd request identifier.
    #[must_use]
    pub const fn walletd_request_id(&self) -> WalletdRequestId {
        self.walletd_request_id
    }

    /// Returns the bound sealed transaction identifier.
    #[must_use]
    pub const fn transaction_id(&self) -> &AnchorTransactionId {
        &self.transaction_id
    }

    /// Returns the bound network.
    #[must_use]
    pub const fn network(&self) -> &OotleNetworkIdV1 {
        &self.network
    }

    /// Returns the bound fee account reference.
    #[must_use]
    pub const fn account(&self) -> &AnchorAccountReference {
        &self.account
    }

    /// Returns the bound expected anchor-record digest.
    #[must_use]
    pub const fn anchor_digest(&self) -> OotleAnchorRecordHashV1 {
        self.anchor_digest
    }

    /// Returns the bound exact expected anchor log payload.
    #[must_use]
    pub const fn payload(&self) -> &AnchorLogPayloadV1 {
        &self.payload
    }

    /// Returns the bound unsigned-transaction inspection fingerprint.
    #[must_use]
    pub const fn fingerprint(&self) -> OotleAnchorInspectionFingerprintV1 {
        self.fingerprint
    }

    /// Returns the pinned v0.39.2 template identity, when this is a V2 query.
    #[must_use]
    pub const fn template_binding(&self) -> Option<&AnchorTemplateBindingV1> {
        self.template_binding.as_ref()
    }

    /// Returns the persisted indexer-observed epoch and transaction expiry.
    #[must_use]
    pub const fn epoch_binding(&self) -> Option<AnchorEpochBindingV1> {
        self.epoch_binding
    }
}
