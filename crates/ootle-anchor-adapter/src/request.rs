//! Project-owned adapter input (Section A).
//!
//! [`OotleAnchorTransactionBuildRequestV1`] wraps the existing offline
//! [`AnchorPreparationRequest`] from the anchor-transport crate. It adds no new
//! free-form field: the only anchor content it can carry is a validated
//! [`AnchorLogPayloadV1`], never a raw arbitrary log string. It holds no private
//! key, mnemonic, signer secret, ballot, proof, registry, archive bytes, or
//! tally.

use tari_cc_private_ballot_anchor::{OotleAnchorRecordHashV1, OotleNetworkIdV1};
use tari_cc_private_ballot_anchor_transport::{
    AnchorAccountReference, AnchorClientReferenceV1, AnchorEpochBindingV1, AnchorEventPayloadV2,
    AnchorLogPayloadV1, AnchorMaxFeeV1, AnchorPreparationRequest, AnchorTemplateBindingV1,
};

/// Input describing exactly one anchor transaction to construct.
///
/// The wrapped [`AnchorPreparationRequest`] already binds the intended network,
/// fee account, validated anchor payload, maximum fee, and optional client
/// reference, so this type is a thin, explicit adapter boundary rather than a
/// second source of truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OotleAnchorTransactionBuildRequestV1 {
    preparation: AnchorPreparationRequest,
    template_binding: Option<AnchorTemplateBindingV1>,
    epoch_binding: Option<AnchorEpochBindingV1>,
}

impl OotleAnchorTransactionBuildRequestV1 {
    /// Wraps an offline preparation request as an adapter build request.
    #[must_use]
    pub fn from_preparation_request(preparation: AnchorPreparationRequest) -> Self {
        Self {
            preparation,
            template_binding: None,
            epoch_binding: None,
        }
    }

    /// Binds an existing preparation request to the approved v0.39.2 event
    /// template and a pre-observed bounded epoch window.
    ///
    /// The legacy constructor remains for reading historical V1 state, but it
    /// deliberately cannot construct a new v0.39.2 transaction without this
    /// explicit immutable deployment identity and expiry binding.
    #[must_use]
    pub fn from_preparation_request_with_event_binding(
        preparation: AnchorPreparationRequest,
        template_binding: AnchorTemplateBindingV1,
        epoch_binding: AnchorEpochBindingV1,
    ) -> Self {
        Self {
            preparation,
            template_binding: Some(template_binding),
            epoch_binding: Some(epoch_binding),
        }
    }

    /// Returns the wrapped preparation request.
    #[must_use]
    pub const fn preparation(&self) -> &AnchorPreparationRequest {
        &self.preparation
    }

    /// Returns the intended project network identifier.
    #[must_use]
    pub fn network(&self) -> &OotleNetworkIdV1 {
        self.preparation.binding().network()
    }

    /// Returns the fee-paying account reference.
    #[must_use]
    pub fn account(&self) -> &AnchorAccountReference {
        self.preparation.binding().account()
    }

    /// Returns the validated anchor log payload.
    #[must_use]
    pub fn payload(&self) -> &AnchorLogPayloadV1 {
        self.preparation.binding().payload()
    }

    /// Returns the exact v0.39.2 event payload derived from the unchanged
    /// canonical anchor digest.
    #[must_use]
    pub fn event_payload(&self) -> AnchorEventPayloadV2 {
        AnchorEventPayloadV2::from_digest(self.anchor_digest())
    }

    /// Returns the pinned published-template identity, if this request is a
    /// new v0.39.2 event anchor rather than a legacy V1 record.
    #[must_use]
    pub fn template_binding(&self) -> Option<&AnchorTemplateBindingV1> {
        self.template_binding.as_ref()
    }

    /// Returns the persisted observed/max epoch pair for a new v0.39.2 event
    /// anchor, if present.
    #[must_use]
    pub const fn epoch_binding(&self) -> Option<AnchorEpochBindingV1> {
        self.epoch_binding
    }

    /// Returns the bound anchor-record digest.
    #[must_use]
    pub fn anchor_digest(&self) -> OotleAnchorRecordHashV1 {
        self.preparation.binding().anchor_digest()
    }

    /// Returns the maximum-fee ceiling.
    #[must_use]
    pub fn max_fee(&self) -> AnchorMaxFeeV1 {
        self.preparation.max_fee()
    }

    /// Returns the optional caller idempotency reference.
    #[must_use]
    pub fn client_reference(&self) -> Option<&AnchorClientReferenceV1> {
        self.preparation.client_reference()
    }
}

impl From<AnchorPreparationRequest> for OotleAnchorTransactionBuildRequestV1 {
    fn from(preparation: AnchorPreparationRequest) -> Self {
        Self::from_preparation_request(preparation)
    }
}
