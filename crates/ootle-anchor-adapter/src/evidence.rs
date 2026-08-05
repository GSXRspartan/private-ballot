//! Project-owned unsigned-transaction inspection evidence (Section E).
//!
//! [`OotleUnsignedAnchorTransactionEvidenceV1`] is the inspection result the
//! adapter returns. It carries only observed structure plus the bound project
//! context. It contains no private key, no signed transaction, no claimed
//! transaction identifier, and no finality status: an Ootle transaction
//! identifier exists only after sealing, which this slice never performs.

use tari_cc_private_ballot_anchor::{OotleAnchorRecordHashV1, OotleNetworkIdV1};
use tari_cc_private_ballot_anchor_transport::{AnchorAccountReference, AnchorLogPayloadV1};

/// Adapter-owned inspection fingerprint of a constructed unsigned transaction.
///
/// This is a domain-separated BLAKE3 digest of the unsigned transaction's
/// canonical CBOR encoding under a unique adapter frame. It is **not** a
/// transaction identifier and must never be presented as one: it enables
/// deterministic comparison of two constructions, nothing more.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OotleAnchorInspectionFingerprintV1([u8; 32]);

impl OotleAnchorInspectionFingerprintV1 {
    /// Wraps 32 already-derived fingerprint bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw fingerprint bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Structural evidence for one constructed, unsigned anchor transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OotleUnsignedAnchorTransactionEvidenceV1 {
    pub(crate) network: OotleNetworkIdV1,
    pub(crate) ootle_network_byte: u8,
    pub(crate) account: AnchorAccountReference,
    pub(crate) anchor_digest: OotleAnchorRecordHashV1,
    pub(crate) anchor_log_payload: AnchorLogPayloadV1,
    pub(crate) instruction_count: usize,
    pub(crate) anchor_instruction_index: usize,
    pub(crate) fee_instructions_present: bool,
    pub(crate) input_count: usize,
    pub(crate) blob_count: usize,
    pub(crate) unsigned_schema_version: u16,
    pub(crate) fingerprint: OotleAnchorInspectionFingerprintV1,
}

impl OotleUnsignedAnchorTransactionEvidenceV1 {
    /// Returns the bound project network identifier.
    #[must_use]
    pub const fn network(&self) -> &OotleNetworkIdV1 {
        &self.network
    }

    /// Returns the bound Ootle network byte.
    #[must_use]
    pub const fn ootle_network_byte(&self) -> u8 {
        self.ootle_network_byte
    }

    /// Returns the fee-paying account reference.
    #[must_use]
    pub const fn account(&self) -> &AnchorAccountReference {
        &self.account
    }

    /// Returns the anchored record digest.
    #[must_use]
    pub const fn anchor_digest(&self) -> OotleAnchorRecordHashV1 {
        self.anchor_digest
    }

    /// Returns the exact anchor log payload.
    #[must_use]
    pub const fn anchor_log_payload(&self) -> &AnchorLogPayloadV1 {
        &self.anchor_log_payload
    }

    /// Returns the total number of normal instructions (always one).
    #[must_use]
    pub const fn instruction_count(&self) -> usize {
        self.instruction_count
    }

    /// Returns the index of the anchor instruction (always zero).
    #[must_use]
    pub const fn anchor_instruction_index(&self) -> usize {
        self.anchor_instruction_index
    }

    /// Returns whether any fee instruction is present (always false in this
    /// walletd-injected-fee architecture).
    #[must_use]
    pub const fn fee_instructions_present(&self) -> bool {
        self.fee_instructions_present
    }

    /// Returns the number of substate inputs (always zero).
    #[must_use]
    pub const fn input_count(&self) -> usize {
        self.input_count
    }

    /// Returns the number of attached blobs (always zero).
    #[must_use]
    pub const fn blob_count(&self) -> usize {
        self.blob_count
    }

    /// Returns the inspected unsigned transaction schema version.
    #[must_use]
    pub const fn unsigned_schema_version(&self) -> u16 {
        self.unsigned_schema_version
    }

    /// Returns the adapter-owned inspection fingerprint.
    ///
    /// This is not a transaction identifier.
    #[must_use]
    pub const fn fingerprint(&self) -> OotleAnchorInspectionFingerprintV1 {
        self.fingerprint
    }
}
