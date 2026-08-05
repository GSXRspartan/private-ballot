//! Section K / Section M(20) — runtime safety-audit invariants.
//!
//! This binary asserts the runtime-observable half of the dependency/feature
//! audit: the adapter constructs an offline, unsigned, fee-less transaction with
//! no signing, no network, and deterministic hashing. The static half — that
//! only the exact pinned Ootle crates were added and that no async runtime,
//! HTTP/TLS, walletd/indexer client, or local-signing feature is present — is
//! captured as scripted offline `cargo tree` evidence in the Slice 4A5 review
//! document, which this test complements rather than replaces.

mod common;

use common::valid_request;
use tari_cc_private_ballot_ootle_anchor_adapter::build_unsigned_anchor_transaction;

#[test]
fn constructed_transaction_is_offline_unsigned_and_fee_less() {
    let Ok(result) = build_unsigned_anchor_transaction(&valid_request()) else {
        panic!("construction must succeed");
    };
    let unsigned = result.unsigned_transaction();
    let evidence = result.evidence();

    // No signing path is exercised: the pinned unsigned type carries no
    // signature and no identifier, and fees are deferred entirely to walletd.
    assert!(unsigned.fee_instructions().is_empty());
    assert!(!evidence.fee_instructions_present());
    assert!(unsigned.inputs().is_empty());
    assert!(unsigned.blobs().is_empty());
    assert_eq!(evidence.unsigned_schema_version(), 1);
}

#[test]
fn fingerprint_is_deterministic_and_thirty_two_bytes() {
    // Hashing is deterministic BLAKE3 with no entropy or network input.
    let Ok(first) = build_unsigned_anchor_transaction(&valid_request()) else {
        panic!("first construction must succeed");
    };
    let Ok(second) = build_unsigned_anchor_transaction(&valid_request()) else {
        panic!("second construction must succeed");
    };

    let first_fingerprint = first.evidence().fingerprint();
    let second_fingerprint = second.evidence().fingerprint();

    assert_eq!(first_fingerprint.as_bytes(), second_fingerprint.as_bytes());
    assert_eq!(first_fingerprint.as_bytes().len(), 32);
}
