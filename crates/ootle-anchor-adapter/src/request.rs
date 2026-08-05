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
    AnchorAccountReference, AnchorClientReferenceV1, AnchorLogPayloadV1, AnchorMaxFeeV1,
    AnchorPreparationRequest,
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
}

impl OotleAnchorTransactionBuildRequestV1 {
    /// Wraps an offline preparation request as an adapter build request.
    #[must_use]
    pub fn from_preparation_request(preparation: AnchorPreparationRequest) -> Self {
        Self { preparation }
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
