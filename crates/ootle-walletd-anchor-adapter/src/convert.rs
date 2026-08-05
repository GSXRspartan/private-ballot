//! Preparation-request conversion (Section B).
//!
//! [`build_walletd_create_request`] converts a completed Slice 4A5
//! [`OotleAnchorBuildResultV1`] into the exact confirmed walletd
//! [`TransactionRequestCreateRequest`], which walletd stores verbatim and frozen.
//! Before building the request it re-runs the Slice 4A5 pure inspector over the
//! unsigned transaction and rejects any unsafe build result, so a mutated or
//! inconsistent construction can never reach walletd.
//!
//! # Fee representation
//!
//! The confirmed `transaction_requests.create` request stores a complete
//! [`UnsignedTransaction`] verbatim and carries a `seal_signer` key handle; it has
//! no separate `fee_account`/`max_fee` fields (those belong to the immediate
//! `transactions.submit_instruction` path, which does not create an approvable
//! frozen request). The Slice 4A5 transaction is deliberately fee-less, so the
//! project's fee account and maximum fee are preserved as project-owned binding
//! metadata for human review here; how the fee is actually paid at submit is a
//! Slice 4A6B concern and is deliberately not invented in this slice.
//!
//! [`OotleAnchorBuildResultV1`]: tari_cc_private_ballot_ootle_anchor_adapter::OotleAnchorBuildResultV1
//! [`UnsignedTransaction`]: tari_ootle_transaction::UnsignedTransaction

use tari_cc_private_ballot_anchor_transport::{AnchorClientReferenceV1, AnchorRequestId};
use tari_cc_private_ballot_ootle_anchor_adapter::{
    AnchorInspectionExpectationV1, OotleAnchorBuildResultV1, OotleAnchorInspectionFingerprintV1,
    inspect_unsigned_anchor_transaction, map_ootle_network,
};
use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, HashProvider};
use tari_ootle_walletd_client::types::TransactionRequestCreateRequest;

use crate::binding::WalletdAnchorBindingV1;
use crate::errors::WalletdAnchorAdapterError;
use crate::identifiers::WalletdSealSignerRef;

/// Domain frame for the deterministic project request identifier.
///
/// Distinct from the Slice 4A5 inspection-fingerprint frame and every protocol
/// and anchor-record frame, so the project request identifier can never collide
/// with a fingerprint, protocol digest, or anchor-record digest.
const PROJECT_REQUEST_ID_DOMAIN_V1: &[u8] =
    b"tari-cc-private-ballot/ootle-walletd-anchor-adapter/project-request-id/v1";

/// A project-owned walletd create-transaction-request command.
///
/// It carries the project-owned binding, the deterministic project request
/// identifier, and the exact confirmed walletd wire request the frozen record is
/// created from. The wire request is reachable only through this leaf crate; no
/// core project crate depends on it.
#[derive(Debug, Clone)]
pub struct WalletdCreateAnchorRequestV1 {
    project_request_id: AnchorRequestId,
    binding: WalletdAnchorBindingV1,
    client_reference: Option<AnchorClientReferenceV1>,
    wire: TransactionRequestCreateRequest,
}

impl WalletdCreateAnchorRequestV1 {
    /// Returns the deterministic project request identifier.
    #[must_use]
    pub const fn project_request_id(&self) -> &AnchorRequestId {
        &self.project_request_id
    }

    /// Returns the frozen project-owned binding.
    #[must_use]
    pub const fn binding(&self) -> &WalletdAnchorBindingV1 {
        &self.binding
    }

    /// Returns the optional caller idempotency reference.
    #[must_use]
    pub const fn client_reference(&self) -> Option<&AnchorClientReferenceV1> {
        self.client_reference.as_ref()
    }

    /// Returns the bound unsigned-transaction inspection fingerprint.
    #[must_use]
    pub fn fingerprint(&self) -> OotleAnchorInspectionFingerprintV1 {
        self.binding.fingerprint()
    }

    /// Returns the exact confirmed walletd create-transaction-request.
    ///
    /// This is the single deliberate seam exposing a walletd wire type, mirroring
    /// how Slice 4A5 exposes the unsigned transaction. A future real client
    /// forwards this verbatim to `create_transaction_request`; the offline fake
    /// ignores it. It carries a `seal_signer` key handle, never key material.
    #[must_use]
    pub const fn wire_request(&self) -> &TransactionRequestCreateRequest {
        &self.wire
    }
}

/// Encodes 32 bytes as exactly 64 lowercase hexadecimal characters.
pub(crate) fn to_lower_hex_32(bytes: &[u8; 32]) -> String {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for &byte in bytes {
        encoded.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// Derives the deterministic project request identifier for a binding.
fn derive_project_request_id(binding: &WalletdAnchorBindingV1) -> AnchorRequestId {
    let provider = Blake3HashProviderV1;
    let mut framed = Vec::new();
    framed.extend_from_slice(PROJECT_REQUEST_ID_DOMAIN_V1);
    framed.push(0);
    framed.extend_from_slice(binding.network().as_str().as_bytes());
    framed.push(0);
    framed.extend_from_slice(binding.account().as_str().as_bytes());
    framed.push(0);
    framed.extend_from_slice(binding.anchor_digest().as_bytes());
    framed.push(0);
    framed.extend_from_slice(binding.fingerprint().as_bytes());
    // The hexadecimal encoding of a 32-byte hash is always a valid bounded
    // identifier, so this construction cannot fail.
    match AnchorRequestId::new(to_lower_hex_32(&provider.hash(&framed))) {
        Ok(id) => id,
        Err(_error) => unreachable!("64 lowercase hex characters are always a valid identifier"),
    }
}

/// Converts a Slice 4A5 build result into the confirmed walletd create request.
///
/// Re-runs the Slice 4A5 inspector over the unsigned transaction and rejects any
/// unsafe build result before assembling the wire request. The `seal_signer`
/// names which wallet-held key seals at submit; no private key is accepted here.
///
/// # Errors
///
/// Returns [`WalletdAnchorAdapterError::UnsafeUnsignedTransaction`] if the
/// re-inspection fails, or [`WalletdAnchorAdapterError::UnsupportedWalletdApi`] if
/// the re-inspection disagrees with the build result's own recorded fingerprint.
pub fn build_walletd_create_request(
    build_result: &OotleAnchorBuildResultV1,
    seal_signer: WalletdSealSignerRef,
    ttl_secs: Option<u64>,
) -> Result<WalletdCreateAnchorRequestV1, WalletdAnchorAdapterError> {
    let preparation = build_result.walletd_preparation();

    // Re-run the Slice 4A5 safety inspection over the unsigned transaction.
    let ootle_network = map_ootle_network(preparation.network())
        .map_err(WalletdAnchorAdapterError::UnsafeUnsignedTransaction)?;
    let expectation = AnchorInspectionExpectationV1::new(
        preparation.network().clone(),
        ootle_network,
        preparation.fee_account().clone(),
        preparation.anchor_digest(),
        *preparation.anchor_payload(),
    );
    let evidence =
        inspect_unsigned_anchor_transaction(build_result.unsigned_transaction(), &expectation)
            .map_err(WalletdAnchorAdapterError::UnsafeUnsignedTransaction)?;

    // The fresh inspection recomputes the fingerprint from the same unsigned
    // transaction, so it must equal the build result's recorded fingerprint.
    if evidence.fingerprint() != build_result.evidence().fingerprint() {
        return Err(WalletdAnchorAdapterError::UnsupportedWalletdApi {
            detail: "build-result fingerprint inconsistent with re-inspection",
        });
    }

    let binding = WalletdAnchorBindingV1::new(
        preparation.network().clone(),
        preparation.fee_account().clone(),
        preparation.anchor_digest(),
        *preparation.anchor_payload(),
        preparation.max_fee(),
        evidence.fingerprint(),
    );

    let project_request_id = derive_project_request_id(&binding);

    let wire = TransactionRequestCreateRequest {
        transaction: build_result.unsigned_transaction().clone(),
        seal_signer: seal_signer.to_key_id(),
        other_signers: Vec::new(),
        signatures: Vec::new(),
        lock_ids: Vec::new(),
        ttl_secs,
    };

    Ok(WalletdCreateAnchorRequestV1 {
        project_request_id,
        binding,
        client_reference: preparation.client_reference().cloned(),
        wire,
    })
}
