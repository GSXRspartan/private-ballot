//! Walletd/indexer cross-observation agreement (Section H).
//!
//! Each case compares a walletd finalize observation against an independently
//! retrieved indexer receipt through [`compare_walletd_and_indexer`], which
//! extends the Slice 4A4 agreement verifier with the source and expected-binding
//! checks. No case contacts a network.

mod common;

use common::{canonical_network, canonical_payload, canonical_submitted, network, payload};
use tari_cc_private_ballot_anchor_transport::AnchorReceiptSourceKindV1;
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::{
    AnchorReceiptAgreementError, compare_walletd_and_indexer, receipt_scenarios,
};

#[test]
fn matching_walletd_and_indexer_full_acceptances_agree() {
    let submitted = canonical_submitted();
    let tx = submitted.transaction_id().clone();
    let walletd = receipt_scenarios::walletd_accepted_receipt(
        &tx,
        &canonical_network(),
        &canonical_payload(),
    );
    let indexer =
        receipt_scenarios::accepted_receipt(&tx, &canonical_network(), &canonical_payload());

    assert_eq!(
        compare_walletd_and_indexer(&tx, &canonical_network(), &walletd, &indexer),
        Ok(())
    );
}

#[test]
fn walletd_accept_versus_indexer_reject_disagree() {
    let submitted = canonical_submitted();
    let tx = submitted.transaction_id().clone();
    let walletd = receipt_scenarios::walletd_accepted_receipt(
        &tx,
        &canonical_network(),
        &canonical_payload(),
    );
    let indexer = receipt_scenarios::rejected_receipt(&tx, &canonical_network());

    assert!(compare_walletd_and_indexer(&tx, &canonical_network(), &walletd, &indexer).is_err());
}

#[test]
fn walletd_fee_only_versus_indexer_full_disagree() {
    let submitted = canonical_submitted();
    let tx = submitted.transaction_id().clone();
    // A fee-only observation recorded as walletd source.
    let walletd = receipt_scenarios::receipt(
        &tx,
        &canonical_network(),
        tari_cc_private_ballot_anchor_transport::AnchorFinalStatusV1::FeeOnlyAccepted,
        Vec::new(),
        Some("fee-only".to_owned()),
        Some(1),
        AnchorReceiptSourceKindV1::Walletd,
    );
    let indexer =
        receipt_scenarios::accepted_receipt(&tx, &canonical_network(), &canonical_payload());

    assert!(compare_walletd_and_indexer(&tx, &canonical_network(), &walletd, &indexer).is_err());
}

#[test]
fn indexer_receipt_for_another_transaction_is_refused() {
    let submitted = canonical_submitted();
    let tx = submitted.transaction_id().clone();
    let other = common::submit("esmeralda", "fee-account", 0x66);
    let other_tx = other.transaction_id().clone();

    let walletd = receipt_scenarios::walletd_accepted_receipt(
        &tx,
        &canonical_network(),
        &canonical_payload(),
    );
    let indexer =
        receipt_scenarios::accepted_receipt(&other_tx, &canonical_network(), &canonical_payload());

    assert_eq!(
        compare_walletd_and_indexer(&tx, &canonical_network(), &walletd, &indexer),
        Err(AnchorReceiptAgreementError::ExpectedTransactionMismatch)
    );
}

#[test]
fn different_networks_are_refused() {
    let submitted = canonical_submitted();
    let tx = submitted.transaction_id().clone();
    let walletd = receipt_scenarios::walletd_accepted_receipt(
        &tx,
        &canonical_network(),
        &canonical_payload(),
    );
    // Indexer observed on a different network.
    let indexer = receipt_scenarios::accepted_receipt(&tx, &network("igor"), &canonical_payload());

    assert!(compare_walletd_and_indexer(&tx, &canonical_network(), &walletd, &indexer).is_err());
}

#[test]
fn different_anchor_digests_are_refused() {
    let submitted = canonical_submitted();
    let tx = submitted.transaction_id().clone();
    let walletd = receipt_scenarios::walletd_accepted_receipt(
        &tx,
        &canonical_network(),
        &canonical_payload(),
    );
    let indexer = receipt_scenarios::accepted_receipt(&tx, &canonical_network(), &payload(0x99));

    assert!(compare_walletd_and_indexer(&tx, &canonical_network(), &walletd, &indexer).is_err());
}

#[test]
fn swapped_sources_are_refused() {
    let submitted = canonical_submitted();
    let tx = submitted.transaction_id().clone();
    // Pass an indexer-source receipt as the walletd argument.
    let indexer_as_walletd =
        receipt_scenarios::accepted_receipt(&tx, &canonical_network(), &canonical_payload());
    let indexer =
        receipt_scenarios::accepted_receipt(&tx, &canonical_network(), &canonical_payload());

    assert_eq!(
        compare_walletd_and_indexer(&tx, &canonical_network(), &indexer_as_walletd, &indexer),
        Err(AnchorReceiptAgreementError::WrongWalletdSource)
    );
}

#[test]
fn missing_anchor_log_in_one_source_is_refused() {
    let submitted = canonical_submitted();
    let tx = submitted.transaction_id().clone();
    let walletd = receipt_scenarios::walletd_accepted_receipt(
        &tx,
        &canonical_network(),
        &canonical_payload(),
    );
    // Indexer full acceptance but with no anchor log.
    let indexer = receipt_scenarios::receipt(
        &tx,
        &canonical_network(),
        tari_cc_private_ballot_anchor_transport::AnchorFinalStatusV1::Accepted,
        vec![
            tari_cc_private_ballot_anchor_transport::AnchorLogEntryV1::new(
                tari_cc_private_ballot_anchor_transport::AnchorLogLevelV1::Info,
                "transaction executed".to_owned(),
            ),
        ],
        None,
        Some(1),
        AnchorReceiptSourceKindV1::IndependentIndexer,
    );

    assert!(compare_walletd_and_indexer(&tx, &canonical_network(), &walletd, &indexer).is_err());
}
