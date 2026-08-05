//! Deterministic receipt substate-address derivation and its inspection
//! evidence (Section C).
//!
//! The persisted receipt substate address is derived from the sealed transaction
//! identifier by the confirmed pinned mapping
//! [`TransactionId::into_receipt_address`], which places the 32 transaction-id
//! bytes verbatim into the receipt [`TransactionReceiptAddress`]'s object key.
//! The derivation is therefore an exact, deterministic, collision-free function
//! of the transaction id: equal ids give equal addresses and different ids give
//! different addresses, using the typed pinned API rather than any string
//! parsing.
//!
//! [`TransactionId::into_receipt_address`]: tari_ootle_transaction::TransactionId::into_receipt_address
//! [`TransactionReceiptAddress`]: tari_template_lib_types::TransactionReceiptAddress

use tari_cc_private_ballot_anchor::OotleNetworkIdV1;
use tari_cc_private_ballot_anchor_transport::AnchorTransactionId;

use crate::convert::transaction_id_to_ootle;
use crate::errors::ReceiptIdentifierError;

/// Project-owned evidence recording a receipt-address derivation.
///
/// It records the project transaction id, the typed Ootle transaction id (as its
/// canonical 64-character hex), the derived receipt substate address (both the
/// prefixed display form and the bare object-key hex), and the expected network.
/// It deliberately makes **no** finality claim: deriving a receipt address proves
/// only where a receipt *would* live, never that one exists or was accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorReceiptAddressEvidenceV1 {
    project_transaction_id: AnchorTransactionId,
    ootle_transaction_id_hex: String,
    receipt_address_display: String,
    receipt_object_key_hex: String,
    network: OotleNetworkIdV1,
}

impl AnchorReceiptAddressEvidenceV1 {
    /// Returns the project transaction identifier the address was derived from.
    #[must_use]
    pub const fn project_transaction_id(&self) -> &AnchorTransactionId {
        &self.project_transaction_id
    }

    /// Returns the typed Ootle transaction id as canonical lowercase hex.
    #[must_use]
    pub fn ootle_transaction_id_hex(&self) -> &str {
        &self.ootle_transaction_id_hex
    }

    /// Returns the derived receipt address in its prefixed display form
    /// (`txreceipt_<hex>`).
    #[must_use]
    pub fn receipt_address_display(&self) -> &str {
        &self.receipt_address_display
    }

    /// Returns the derived receipt address's bare object-key hexadecimal.
    #[must_use]
    pub fn receipt_object_key_hex(&self) -> &str {
        &self.receipt_object_key_hex
    }

    /// Returns the expected network the receipt is queried on.
    #[must_use]
    pub const fn network(&self) -> &OotleNetworkIdV1 {
        &self.network
    }
}

/// Derives the receipt-address inspection evidence for a project transaction id
/// (Section C).
///
/// # Errors
///
/// Returns a [`ReceiptIdentifierError`] if the project transaction id is not
/// exactly 64 lowercase hexadecimal characters.
pub fn derive_receipt_address_evidence(
    transaction_id: &AnchorTransactionId,
    network: &OotleNetworkIdV1,
) -> Result<AnchorReceiptAddressEvidenceV1, ReceiptIdentifierError> {
    let ootle_id = transaction_id_to_ootle(transaction_id)?;
    let receipt_address = ootle_id.into_receipt_address();

    Ok(AnchorReceiptAddressEvidenceV1 {
        project_transaction_id: transaction_id.clone(),
        ootle_transaction_id_hex: ootle_id.to_string(),
        receipt_address_display: receipt_address.to_string(),
        receipt_object_key_hex: receipt_address.as_object_key().to_string(),
        network: network.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::derive_receipt_address_evidence;
    use tari_cc_private_ballot_anchor::OotleNetworkIdV1;
    use tari_cc_private_ballot_anchor_transport::AnchorTransactionId;

    fn transaction_id(text: &str) -> AnchorTransactionId {
        match AnchorTransactionId::new(text.to_owned()) {
            Ok(id) => id,
            Err(_error) => panic!("test transaction id must be valid"),
        }
    }

    fn network() -> OotleNetworkIdV1 {
        match OotleNetworkIdV1::new("esmeralda".to_owned()) {
            Ok(id) => id,
            Err(_error) => panic!("test network must be valid"),
        }
    }

    #[test]
    fn derivation_is_deterministic_and_object_key_equals_transaction_id() {
        let id = transaction_id(&"ab".repeat(32));
        let Ok(first) = derive_receipt_address_evidence(&id, &network()) else {
            panic!("derivation must succeed");
        };
        let Ok(second) = derive_receipt_address_evidence(&id, &network()) else {
            panic!("derivation must be repeatable");
        };
        assert_eq!(first, second);
        // The receipt object key is exactly the transaction id bytes.
        assert_eq!(first.receipt_object_key_hex(), id.as_str());
        assert_eq!(first.ootle_transaction_id_hex(), id.as_str());
        assert!(first.receipt_address_display().starts_with("txreceipt_"));
    }

    #[test]
    fn different_transaction_ids_derive_different_addresses() {
        let Ok(first) =
            derive_receipt_address_evidence(&transaction_id(&"ab".repeat(32)), &network())
        else {
            panic!("first derivation must succeed");
        };
        let Ok(second) =
            derive_receipt_address_evidence(&transaction_id(&"cd".repeat(32)), &network())
        else {
            panic!("second derivation must succeed");
        };
        assert_ne!(
            first.receipt_object_key_hex(),
            second.receipt_object_key_hex()
        );
        assert_ne!(
            first.receipt_address_display(),
            second.receipt_address_display()
        );
    }

    #[test]
    fn malformed_transaction_id_is_rejected() {
        let bad = transaction_id(&"ZZ".repeat(32));
        assert!(derive_receipt_address_evidence(&bad, &network()).is_err());
    }
}
