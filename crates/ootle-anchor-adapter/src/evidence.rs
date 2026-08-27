//! Project-owned v0.39.2 unsigned-transaction inspection evidence.

use tari_cc_private_ballot_anchor::{OotleAnchorRecordHashV1, OotleNetworkIdV1};
use tari_cc_private_ballot_anchor_transport::{
    AnchorAccountReference, AnchorEpochBindingV1, AnchorEventPayloadV2, AnchorTemplateBindingV1,
};

/// Domain-separated BLAKE3 fingerprint of canonical unsigned transaction CBOR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OotleAnchorInspectionFingerprintV1([u8; 32]);

impl OotleAnchorInspectionFingerprintV1 {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self { Self(bytes) }
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

/// Structural proof that a transaction is the exact pinned event anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OotleUnsignedAnchorTransactionEvidenceV1 {
    pub(crate) network: OotleNetworkIdV1,
    pub(crate) ootle_network_byte: u8,
    pub(crate) account: AnchorAccountReference,
    pub(crate) anchor_digest: OotleAnchorRecordHashV1,
    pub(crate) event_payload: AnchorEventPayloadV2,
    pub(crate) template_binding: AnchorTemplateBindingV1,
    pub(crate) epoch_binding: AnchorEpochBindingV1,
    pub(crate) instruction_count: usize,
    pub(crate) anchor_instruction_index: usize,
    pub(crate) fee_instructions_present: bool,
    pub(crate) input_count: usize,
    pub(crate) blob_count: usize,
    pub(crate) unsigned_schema_version: u16,
    pub(crate) fingerprint: OotleAnchorInspectionFingerprintV1,
}

impl OotleUnsignedAnchorTransactionEvidenceV1 {
    #[must_use]
    pub const fn network(&self) -> &OotleNetworkIdV1 { &self.network }
    #[must_use]
    pub const fn ootle_network_byte(&self) -> u8 { self.ootle_network_byte }
    #[must_use]
    pub const fn account(&self) -> &AnchorAccountReference { &self.account }
    #[must_use]
    pub const fn anchor_digest(&self) -> OotleAnchorRecordHashV1 { self.anchor_digest }
    #[must_use]
    pub const fn event_payload(&self) -> AnchorEventPayloadV2 { self.event_payload }
    #[must_use]
    pub const fn template_binding(&self) -> &AnchorTemplateBindingV1 { &self.template_binding }
    #[must_use]
    pub const fn epoch_binding(&self) -> AnchorEpochBindingV1 { self.epoch_binding }
    #[must_use]
    pub const fn instruction_count(&self) -> usize { self.instruction_count }
    #[must_use]
    pub const fn anchor_instruction_index(&self) -> usize { self.anchor_instruction_index }
    #[must_use]
    pub const fn fee_instructions_present(&self) -> bool { self.fee_instructions_present }
    #[must_use]
    pub const fn input_count(&self) -> usize { self.input_count }
    #[must_use]
    pub const fn blob_count(&self) -> usize { self.blob_count }
    #[must_use]
    pub const fn unsigned_schema_version(&self) -> u16 { self.unsigned_schema_version }
    #[must_use]
    pub const fn fingerprint(&self) -> OotleAnchorInspectionFingerprintV1 { self.fingerprint }
}
