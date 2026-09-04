//! Immutable walletd-anchor binding checked at every decision (Sections B, E).
//!
//! [`WalletdAnchorBindingV1`] fixes every field an approval or rejection must
//! agree with: the network, fee account, anchor digest, exact `EmitLog` payload,
//! maximum fee, and the Slice 4A5 unsigned-transaction inspection fingerprint. A
//! decision whose supplied binding differs in any field is rejected with a
//! specific error, so a request can never be approved for a different payload,
//! account, network, fee, or transaction than the one that was prepared.

use tari_cc_private_ballot_anchor::{OotleAnchorRecordHashV1, OotleNetworkIdV1};
use tari_cc_private_ballot_anchor_transport::{
    AnchorAccountReference, AnchorEpochBindingV1, AnchorLogPayloadV1, AnchorMaxFeeV1,
    AnchorTemplateBindingV1,
};
use tari_cc_private_ballot_ootle_anchor_adapter::OotleAnchorInspectionFingerprintV1;

use crate::errors::WalletdAnchorAdapterError;

/// The frozen anchor binding a prepared walletd request commits to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletdAnchorBindingV1 {
    network: OotleNetworkIdV1,
    account: AnchorAccountReference,
    anchor_digest: OotleAnchorRecordHashV1,
    payload: AnchorLogPayloadV1,
    max_fee: AnchorMaxFeeV1,
    fingerprint: OotleAnchorInspectionFingerprintV1,
    template_binding: Option<AnchorTemplateBindingV1>,
    epoch_binding: Option<AnchorEpochBindingV1>,
}

impl WalletdAnchorBindingV1 {
    /// Assembles a binding from its already-validated parts.
    #[must_use]
    pub fn new(
        network: OotleNetworkIdV1,
        account: AnchorAccountReference,
        anchor_digest: OotleAnchorRecordHashV1,
        payload: AnchorLogPayloadV1,
        max_fee: AnchorMaxFeeV1,
        fingerprint: OotleAnchorInspectionFingerprintV1,
    ) -> Self {
        Self {
            network,
            account,
            anchor_digest,
            payload,
            max_fee,
            fingerprint,
            template_binding: None,
            epoch_binding: None,
        }
    }

    /// Assembles the v0.39.2 event-template binding. The legacy constructor is
    /// retained only so existing V1 snapshots remain decodable.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new_v2(
        network: OotleNetworkIdV1,
        account: AnchorAccountReference,
        anchor_digest: OotleAnchorRecordHashV1,
        payload: AnchorLogPayloadV1,
        max_fee: AnchorMaxFeeV1,
        fingerprint: OotleAnchorInspectionFingerprintV1,
        template_binding: AnchorTemplateBindingV1,
        epoch_binding: AnchorEpochBindingV1,
    ) -> Self {
        Self {
            network,
            account,
            anchor_digest,
            payload,
            max_fee,
            fingerprint,
            template_binding: Some(template_binding),
            epoch_binding: Some(epoch_binding),
        }
    }

    /// Returns the bound network identifier.
    #[must_use]
    pub const fn network(&self) -> &OotleNetworkIdV1 {
        &self.network
    }

    /// Returns the bound fee account reference.
    #[must_use]
    pub const fn account(&self) -> &AnchorAccountReference {
        &self.account
    }

    /// Returns the bound anchor-record digest.
    #[must_use]
    pub const fn anchor_digest(&self) -> OotleAnchorRecordHashV1 {
        self.anchor_digest
    }

    /// Returns the bound exact anchor `EmitLog` payload.
    #[must_use]
    pub const fn payload(&self) -> &AnchorLogPayloadV1 {
        &self.payload
    }

    /// Returns the bound maximum-fee ceiling.
    #[must_use]
    pub const fn max_fee(&self) -> AnchorMaxFeeV1 {
        self.max_fee
    }

    /// Returns the bound unsigned-transaction inspection fingerprint.
    #[must_use]
    pub const fn fingerprint(&self) -> OotleAnchorInspectionFingerprintV1 {
        self.fingerprint
    }

    /// Returns the mandatory v0.39.2 template binding for newly-created
    /// event anchors. `None` identifies a legacy V1 snapshot.
    #[must_use]
    pub fn template_binding(&self) -> Option<&AnchorTemplateBindingV1> {
        self.template_binding.as_ref()
    }

    /// Returns the persisted v0.39.2 observed/max epoch binding.
    #[must_use]
    pub const fn epoch_binding(&self) -> Option<AnchorEpochBindingV1> {
        self.epoch_binding
    }

    /// Checks that `supplied` agrees with `self` field by field.
    ///
    /// Field order fixes which specific error a caller sees first: network,
    /// account, payload, digest, fee, then fingerprint. Every mismatch is a
    /// distinct, bounded error; nothing here can panic.
    ///
    /// # Errors
    ///
    /// Returns the specific [`WalletdAnchorAdapterError`] for the first differing
    /// field.
    pub fn ensure_matches(&self, supplied: &Self) -> Result<(), WalletdAnchorAdapterError> {
        if self.network != supplied.network {
            return Err(WalletdAnchorAdapterError::NetworkMismatch);
        }
        if self.account != supplied.account {
            return Err(WalletdAnchorAdapterError::AccountMismatch);
        }
        if self.payload != supplied.payload {
            return Err(WalletdAnchorAdapterError::PayloadMismatch);
        }
        if self.anchor_digest != supplied.anchor_digest {
            return Err(WalletdAnchorAdapterError::PayloadMismatch);
        }
        if self.max_fee != supplied.max_fee {
            return Err(WalletdAnchorAdapterError::FeeMismatch);
        }
        if self.fingerprint != supplied.fingerprint {
            return Err(WalletdAnchorAdapterError::FingerprintMismatch);
        }
        if self.template_binding != supplied.template_binding
            || self.epoch_binding != supplied.epoch_binding
        {
            return Err(WalletdAnchorAdapterError::PayloadMismatch);
        }
        Ok(())
    }
}
