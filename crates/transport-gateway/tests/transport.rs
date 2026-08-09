#![allow(clippy::expect_used)]

#[path = "../../gui-core/tests/common/mod.rs"]
mod common;

use ed25519_dalek::SigningKey;
use hpke::{Kem as KemTrait, Serializable, kem::X25519HkdfSha256};
use tari_cc_private_ballot_gui_core::{
    BatchPolicyV1, PaddingPolicyV1, PrivateBallotEnvelopeV1, RetryStatusV1, TransportDescriptorV1,
    TransportRoutePolicyV1, VoterReceiptStateV1,
};
use tari_cc_private_ballot_protocol::Blake3HashProviderV1;
use tari_cc_private_ballot_transport_gateway::{
    GatewayReceiverKeyV1, TransportGatewaySimulatorV1, new_retry_capability_v1,
    open_envelope_bytes_v1,
};

type Kem = X25519HkdfSha256;

fn descriptor_and_receiver() -> (TransportDescriptorV1, GatewayReceiverKeyV1) {
    let (receiver_secret, receiver_public) = Kem::gen_keypair();
    let mut public = [0; 32];
    public.copy_from_slice(receiver_public.to_bytes().as_slice());
    let mut secret = [0; 32];
    secret.copy_from_slice(receiver_secret.to_bytes().as_slice());
    let manifest = common::manifest();
    let manifest_hash = manifest
        .canonical_hash(&Blake3HashProviderV1)
        .expect("manifest hash");
    let signing = SigningKey::from_bytes(&[42; 32]);
    let descriptor = TransportDescriptorV1::sign_for_test_or_ceremony(
        manifest.election_id().as_bytes().to_vec(),
        manifest_hash,
        1,
        TransportRoutePolicyV1::OfflineOnly,
        Vec::new(),
        Vec::new(),
        public,
        "test-gateway".to_owned(),
        Vec::new(),
        PaddingPolicyV1 {
            id: "test-fixed".to_owned(),
            padded_bytes: 65_536,
        },
        BatchPolicyV1 {
            id: "accepted-100".to_owned(),
            accepted_unique_floor: 100,
        },
        None,
        "test-root".to_owned(),
        &signing,
    )
    .expect("descriptor");
    (
        descriptor,
        GatewayReceiverKeyV1::from_secret_bytes(secret).expect("receiver key"),
    )
}

#[test]
fn envelope_carrier_delivers_exact_bytes_to_real_5a11_intake() {
    let (descriptor, receiver_key) = descriptor_and_receiver();
    let package = common::triptych_package_bytes(0, &[b"candidate-a"]);
    let envelope = PrivateBallotEnvelopeV1::seal(&descriptor, &package).expect("seal");
    assert_eq!(
        open_envelope_bytes_v1(&envelope, &descriptor, &receiver_key).expect("open"),
        package
    );
    let encoded = envelope.to_canonical_cbor().expect("encode");
    let mut session = common::open_session();
    let mut gateway = TransportGatewaySimulatorV1::default();
    let first = gateway
        .deliver(
            &encoded,
            &descriptor,
            &receiver_key,
            new_retry_capability_v1(),
            &mut session,
        )
        .expect("deliver");
    assert_eq!(first.state, VoterReceiptStateV1::Accepted);
    assert_eq!(
        format!("{first:?}"),
        "VoterTransportReceiptV1 { state: Accepted, retry_status: NewDelivery }"
    );
    assert_eq!(gateway.accepted_unique_count(), 1);
    assert!(!gateway.threshold_met(100));
}

#[test]
fn hpke_open_rejects_wrong_key_ciphertext_encapsulation_and_aad_mutation() {
    let (descriptor, receiver_key) = descriptor_and_receiver();
    let envelope = PrivateBallotEnvelopeV1::seal(&descriptor, b"exact bytes").expect("seal");
    let (_, wrong_public) = Kem::gen_keypair();
    let mut wrong_secret = [0; 32];
    let (wrong_receiver_secret, _) = Kem::gen_keypair();
    wrong_secret.copy_from_slice(wrong_receiver_secret.to_bytes().as_slice());
    let wrong_key = GatewayReceiverKeyV1::from_secret_bytes(wrong_secret).expect("wrong key shape");
    assert!(open_envelope_bytes_v1(&envelope, &descriptor, &wrong_key).is_err());
    let encoded = envelope.to_canonical_cbor().expect("encode");
    let mut ciphertext_mutation = encoded.clone();
    let final_byte = ciphertext_mutation.len() - 1;
    ciphertext_mutation[final_byte] ^= 1;
    let mutated = PrivateBallotEnvelopeV1::from_canonical_cbor(&ciphertext_mutation)
        .expect("canonical mutation");
    assert!(open_envelope_bytes_v1(&mutated, &descriptor, &receiver_key).is_err());
    let mut encapsulation_mutation = encoded;
    let encapsulation_offset =
        1 + 1 + 34 + 34 + 1 + "test-gateway".len() + 1 + "test-fixed".len() + 2;
    encapsulation_mutation[encapsulation_offset] ^= 1;
    let mutated = PrivateBallotEnvelopeV1::from_canonical_cbor(&encapsulation_mutation)
        .expect("canonical mutation");
    assert!(open_envelope_bytes_v1(&mutated, &descriptor, &receiver_key).is_err());
    let different_descriptor = TransportDescriptorV1::sign_for_test_or_ceremony(
        common::manifest().election_id().as_bytes().to_vec(),
        common::manifest()
            .canonical_hash(&Blake3HashProviderV1)
            .expect("hash"),
        1,
        TransportRoutePolicyV1::OfflineOnly,
        Vec::new(),
        Vec::new(),
        wrong_public
            .to_bytes()
            .as_slice()
            .try_into()
            .expect("public bytes"),
        "other-gateway".to_owned(),
        Vec::new(),
        PaddingPolicyV1 {
            id: "other-fixed".to_owned(),
            padded_bytes: 65_536,
        },
        BatchPolicyV1 {
            id: "accepted-100".to_owned(),
            accepted_unique_floor: 100,
        },
        None,
        "test-root".to_owned(),
        &SigningKey::from_bytes(&[42; 32]),
    )
    .expect("other descriptor");
    assert!(open_envelope_bytes_v1(&envelope, &different_descriptor, &receiver_key).is_err());
}

#[test]
fn retry_cache_preserves_accepted_duplicate_and_rejected_truth() {
    let (descriptor, receiver_key) = descriptor_and_receiver();
    let first_package = common::triptych_package_bytes(0, &[b"candidate-a"]);
    let first_encoded = PrivateBallotEnvelopeV1::seal(&descriptor, &first_package)
        .expect("seal")
        .to_canonical_cbor()
        .expect("encode");
    let mut session = common::open_session();
    let mut gateway = TransportGatewaySimulatorV1::default();
    let accepted_capability = new_retry_capability_v1();
    assert_eq!(
        gateway
            .deliver(
                &first_encoded,
                &descriptor,
                &receiver_key,
                accepted_capability,
                &mut session
            )
            .expect("accepted")
            .state,
        VoterReceiptStateV1::Accepted
    );
    let retry = gateway
        .deliver(
            &first_encoded,
            &descriptor,
            &receiver_key,
            accepted_capability,
            &mut session,
        )
        .expect("accepted retry");
    assert_eq!(retry.state, VoterReceiptStateV1::Accepted);
    assert_eq!(retry.retry_status, RetryStatusV1::PreviousDeliveryAccepted);

    let duplicate_capability = new_retry_capability_v1();
    let duplicate = gateway
        .deliver(
            &first_encoded,
            &descriptor,
            &receiver_key,
            duplicate_capability,
            &mut session,
        )
        .expect("duplicate");
    assert_eq!(duplicate.state, VoterReceiptStateV1::Received);
    assert_eq!(duplicate.retry_status, RetryStatusV1::GenericDuplicate);
    let retry = gateway
        .deliver(
            &first_encoded,
            &descriptor,
            &receiver_key,
            duplicate_capability,
            &mut session,
        )
        .expect("duplicate retry");
    assert_eq!(retry.state, VoterReceiptStateV1::Received);
    assert_eq!(retry.retry_status, RetryStatusV1::PreviousDeliveryRejected);

    let second_package = common::triptych_package_bytes(1, &[b"candidate-b"]);
    let second_encoded = PrivateBallotEnvelopeV1::seal(&descriptor, &second_package)
        .expect("seal")
        .to_canonical_cbor()
        .expect("encode");
    let reused = gateway
        .deliver(
            &second_encoded,
            &descriptor,
            &receiver_key,
            duplicate_capability,
            &mut session,
        )
        .expect("reused capability");
    assert_eq!(reused.state, VoterReceiptStateV1::Rejected);
    assert_eq!(reused.retry_status, RetryStatusV1::GenericDuplicate);

    let rejected_capability = new_retry_capability_v1();
    let rejected_encoded = PrivateBallotEnvelopeV1::seal(&descriptor, &[0x80])
        .expect("seal")
        .to_canonical_cbor()
        .expect("encode");
    let rejected = gateway
        .deliver(
            &rejected_encoded,
            &descriptor,
            &receiver_key,
            rejected_capability,
            &mut session,
        )
        .expect("rejected");
    assert_eq!(rejected.state, VoterReceiptStateV1::Rejected);
    let retry = gateway
        .deliver(
            &rejected_encoded,
            &descriptor,
            &receiver_key,
            rejected_capability,
            &mut session,
        )
        .expect("rejected retry");
    assert_eq!(retry.state, VoterReceiptStateV1::Rejected);
    assert_eq!(retry.retry_status, RetryStatusV1::PreviousDeliveryRejected);
}

#[test]
fn junk_does_not_inflate_accepted_unique_threshold() {
    let mut gateway = TransportGatewaySimulatorV1::default();
    for _ in 0..99 {
        assert!(gateway.collect(&[0x80]).is_err());
    }
    assert_eq!(gateway.received_count(), 99);
    assert_eq!(gateway.accepted_unique_count(), 0);
    assert!(!gateway.threshold_met(100));
}
