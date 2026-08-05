//! Unsigned transaction construction and the offline walletd preparation DTO
//! (Section D).
//!
//! # Fee architecture decision
//!
//! Confirmed from the pinned Ootle source, the wallet daemon's
//! `CallInstructionRequest` accepts a bare normal-instruction list together with
//! a separate `fee_account` and `max_fee`; walletd resolves the fee account and
//! injects the fee instructions during preparation. The project account is an
//! opaque reference, not a resolved Ootle `ComponentAddress`, so this adapter
//! cannot and must not build fee instructions itself.
//!
//! Therefore this adapter constructs only the normal instruction list — exactly
//! one `EmitLog` — as a real, pinned, fee-less [`UnsignedTransaction`], and
//! carries the fee account and maximum fee forward in an offline
//! [`OotleWalletdAnchorPreparationV1`] DTO for a later walletd slice to inject
//! fees from. It never invents fee instructions.

use tari_cc_private_ballot_anchor::{OotleAnchorRecordHashV1, OotleNetworkIdV1};
use tari_cc_private_ballot_anchor_transport::{
    AnchorAccountReference, AnchorClientReferenceV1, AnchorLogPayloadV1, AnchorMaxFeeV1,
};
use tari_ootle_transaction::{TransactionBuilder, UnsignedTransaction};

use crate::errors::OotleAnchorAdapterError;
use crate::evidence::OotleUnsignedAnchorTransactionEvidenceV1;
use crate::inspect::{AnchorInspectionExpectationV1, inspect_unsigned_anchor_transaction};
use crate::log_instruction::build_anchor_emit_log;
use crate::network::map_ootle_network;
use crate::request::OotleAnchorTransactionBuildRequestV1;

/// Offline, project-owned walletd preparation DTO.
///
/// This is the project-owned analog of the confirmed walletd
/// `CallInstructionRequest`, minus the normal instructions (which live in the
/// build result's unsigned transaction). It preserves the explicit fee account
/// and maximum fee so a later walletd slice can inject fees; it never resolves
/// the opaque account and never carries a private key, ballot, proof, or tally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OotleWalletdAnchorPreparationV1 {
    network: OotleNetworkIdV1,
    fee_account: AnchorAccountReference,
    max_fee: AnchorMaxFeeV1,
    client_reference: Option<AnchorClientReferenceV1>,
    anchor_digest: OotleAnchorRecordHashV1,
    anchor_payload: AnchorLogPayloadV1,
}

impl OotleWalletdAnchorPreparationV1 {
    /// Builds an offline walletd preparation DTO.
    #[must_use]
    pub fn new(
        network: OotleNetworkIdV1,
        fee_account: AnchorAccountReference,
        max_fee: AnchorMaxFeeV1,
        client_reference: Option<AnchorClientReferenceV1>,
        anchor_digest: OotleAnchorRecordHashV1,
        anchor_payload: AnchorLogPayloadV1,
    ) -> Self {
        Self {
            network,
            fee_account,
            max_fee,
            client_reference,
            anchor_digest,
            anchor_payload,
        }
    }

    /// Returns the intended project network identifier.
    #[must_use]
    pub const fn network(&self) -> &OotleNetworkIdV1 {
        &self.network
    }

    /// Returns the fee-paying account reference walletd will resolve.
    #[must_use]
    pub const fn fee_account(&self) -> &AnchorAccountReference {
        &self.fee_account
    }

    /// Returns the maximum-fee ceiling walletd will enforce.
    #[must_use]
    pub const fn max_fee(&self) -> AnchorMaxFeeV1 {
        self.max_fee
    }

    /// Returns the optional caller idempotency reference.
    #[must_use]
    pub const fn client_reference(&self) -> Option<&AnchorClientReferenceV1> {
        self.client_reference.as_ref()
    }

    /// Returns the anchored record digest.
    #[must_use]
    pub const fn anchor_digest(&self) -> OotleAnchorRecordHashV1 {
        self.anchor_digest
    }

    /// Returns the anchor log payload.
    #[must_use]
    pub const fn anchor_payload(&self) -> &AnchorLogPayloadV1 {
        &self.anchor_payload
    }
}

/// The result of constructing an unsigned anchor transaction.
///
/// It holds the pinned, fee-less [`UnsignedTransaction`] (available only inside
/// this leaf adapter crate), the project-owned inspection evidence, and the
/// offline walletd preparation DTO.
#[derive(Debug, Clone)]
pub struct OotleAnchorBuildResultV1 {
    unsigned_transaction: UnsignedTransaction,
    evidence: OotleUnsignedAnchorTransactionEvidenceV1,
    walletd_preparation: OotleWalletdAnchorPreparationV1,
}

impl OotleAnchorBuildResultV1 {
    /// Returns the pinned, fee-less unsigned transaction.
    #[must_use]
    pub const fn unsigned_transaction(&self) -> &UnsignedTransaction {
        &self.unsigned_transaction
    }

    /// Returns the project-owned inspection evidence.
    #[must_use]
    pub const fn evidence(&self) -> &OotleUnsignedAnchorTransactionEvidenceV1 {
        &self.evidence
    }

    /// Returns the offline walletd preparation DTO.
    #[must_use]
    pub const fn walletd_preparation(&self) -> &OotleWalletdAnchorPreparationV1 {
        &self.walletd_preparation
    }
}

/// Constructs the unsigned anchor transaction and its inspection evidence.
///
/// The transaction contains exactly one normal instruction — the anchor
/// `EmitLog` — bound to the mapped network, with no fee instructions, no inputs,
/// and no blobs. The returned evidence is produced by the same pure inspection
/// used to reject invalid transactions, so a build result is always internally
/// consistent.
///
/// # Errors
///
/// Returns an [`OotleAnchorAdapterError`] if the network is unsupported, the
/// payload cannot be converted, or the constructed transaction fails inspection.
pub fn build_unsigned_anchor_transaction(
    request: &OotleAnchorTransactionBuildRequestV1,
) -> Result<OotleAnchorBuildResultV1, OotleAnchorAdapterError> {
    let network = map_ootle_network(request.network())?;
    let anchor_instruction = build_anchor_emit_log(request.payload())?;

    let unsigned_transaction = TransactionBuilder::new(network)
        .add_instruction(anchor_instruction)
        .build_unsigned();

    let expectation = AnchorInspectionExpectationV1::new(
        request.network().clone(),
        network,
        request.account().clone(),
        request.anchor_digest(),
        *request.payload(),
    );

    let evidence = inspect_unsigned_anchor_transaction(&unsigned_transaction, &expectation)?;

    let walletd_preparation = OotleWalletdAnchorPreparationV1::new(
        request.network().clone(),
        request.account().clone(),
        request.max_fee(),
        request.client_reference().cloned(),
        request.anchor_digest(),
        *request.payload(),
    );

    Ok(OotleAnchorBuildResultV1 {
        unsigned_transaction,
        evidence,
        walletd_preparation,
    })
}
