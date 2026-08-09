#![allow(clippy::expect_used)]

#[path = "../../gui-core/tests/common/mod.rs"]
mod common;

use ed25519_dalek::SigningKey;
use hpke::{Kem as KemTrait, Serializable, kem::X25519HkdfSha256};
use tari_cc_private_ballot_gui_core::{
    BatchPolicyV1, PaddingPolicyV1, PrivateBallotEnvelopeV1, RetryStatusV1, TransportDescriptorV1,
    TransportAuthorityRootV1, TransportRoutePolicyV1, VoterReceiptStateV1,
};
use tari_cc_private_ballot_protocol::Blake3HashProviderV1;
use tari_cc_private_ballot_transport_gateway::{
    GatewayReceiverKeyV1, PrivateSubmissionCarrierV1, PrivateSubmissionCoordinatorV1,
    TransportGatewaySimulatorV1, new_retry_capability_v1, open_envelope_bytes_v1,
};
use tari_cc_private_ballot_transport_network::VoterPrivateRouteV1;

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
    assert_eq!(duplicate.state, VoterReceiptStateV1::Rejected);
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
    assert_eq!(retry.state, VoterReceiptStateV1::Rejected);
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

struct FakeCarrier {
    managed_tor_calls: u8,
    relay_calls: u8,
    fail_tor: bool,
    opaque_envelopes: Vec<Vec<u8>>,
}

impl PrivateSubmissionCarrierV1 for FakeCarrier {
    fn send_managed_tor(
        &mut self,
        _: &TransportDescriptorV1,
        envelope: &[u8],
    ) -> Result<(), tari_cc_private_ballot_gui_core::TransportError> {
        self.managed_tor_calls = self.managed_tor_calls.saturating_add(1);
        self.opaque_envelopes.push(envelope.to_vec());
        if self.fail_tor {
            Err(tari_cc_private_ballot_gui_core::TransportError::Unavailable)
        } else {
            Ok(())
        }
    }

    fn send_split_trust_relay(
        &mut self,
        _: &TransportDescriptorV1,
        envelope: &[u8],
    ) -> Result<(), tari_cc_private_ballot_gui_core::TransportError> {
        self.relay_calls = self.relay_calls.saturating_add(1);
        self.opaque_envelopes.push(envelope.to_vec());
        Ok(())
    }
}

fn coordinator_configuration(
    route: TransportRoutePolicyV1,
) -> (TransportAuthorityRootV1, TransportDescriptorV1, GatewayReceiverKeyV1) {
    let (receiver_secret, receiver_public) = Kem::gen_keypair();
    let mut public = [0; 32];
    public.copy_from_slice(receiver_public.to_bytes().as_slice());
    let mut secret = [0; 32];
    secret.copy_from_slice(receiver_secret.to_bytes().as_slice());
    let signing = SigningKey::from_bytes(&[73; 32]);
    let manifest = common::manifest();
    let descriptor = TransportDescriptorV1::sign_for_test_or_ceremony(
        manifest.election_id().as_bytes().to_vec(),
        manifest.canonical_hash(&Blake3HashProviderV1).expect("manifest hash"),
        1,
        route,
        vec!["test-onion.invalid".to_owned()],
        vec!["test-relay.invalid".to_owned()],
        public,
        "test-gateway".to_owned(),
        Vec::new(),
        PaddingPolicyV1 { id: "test-fixed".to_owned(), padded_bytes: 65_536 },
        BatchPolicyV1 { id: "accepted-100".to_owned(), accepted_unique_floor: 100 },
        None,
        "TEST_ROOT".to_owned(),
        &signing,
    )
    .expect("test descriptor");
    (
        TransportAuthorityRootV1::Pinned {
            key_id: "TEST_ROOT".to_owned(),
            public_key: signing.verifying_key().to_bytes(),
        },
        descriptor,
        GatewayReceiverKeyV1::from_secret_bytes(secret).expect("receiver key"),
    )
}

#[test]
fn coordinator_delivers_exact_bytes_through_explicit_managed_tor() {
    let (root, descriptor, receiver) = coordinator_configuration(TransportRoutePolicyV1::ManagedTorOrOffline);
    let package = common::triptych_package_bytes(0, &[b"candidate-a"]);
    let mut coordinator = PrivateSubmissionCoordinatorV1::with_test_configuration(
        root, descriptor, receiver, None,
    )
    .expect("test configuration");
    let mut session = common::open_session();
    let mut carrier = FakeCarrier { managed_tor_calls: 0, relay_calls: 0, fail_tor: false, opaque_envelopes: Vec::new() };
    let result = coordinator
        .submit(VoterPrivateRouteV1::ManagedTor, &package, &mut session, &mut carrier)
        .expect("accepted through coordinator");
    assert_eq!(result.receipt.state, VoterReceiptStateV1::Accepted);
    assert_eq!(carrier.managed_tor_calls, 1);
    assert_eq!(carrier.relay_calls, 0);
    assert_ne!(carrier.opaque_envelopes[0], package);
}

#[test]
fn coordinator_tor_failure_never_calls_relay_or_direct() {
    let (root, descriptor, receiver) = coordinator_configuration(TransportRoutePolicyV1::ManagedTorOrOffline);
    let mut coordinator = PrivateSubmissionCoordinatorV1::with_test_configuration(root, descriptor, receiver, None)
        .expect("test configuration");
    let mut session = common::open_session();
    let mut carrier = FakeCarrier { managed_tor_calls: 0, relay_calls: 0, fail_tor: true, opaque_envelopes: Vec::new() };
    assert!(coordinator
        .submit(VoterPrivateRouteV1::ManagedTor, &common::triptych_package_bytes(0, &[b"candidate-a"]), &mut session, &mut carrier)
        .is_err());
    assert_eq!(carrier.managed_tor_calls, 1);
    assert_eq!(carrier.relay_calls, 0);
}

#[test]
fn coordinator_uses_relay_only_after_explicit_selection_and_production_fails_closed() {
    let (root, descriptor, receiver) = coordinator_configuration(TransportRoutePolicyV1::RelayOrOffline);
    let mut coordinator = PrivateSubmissionCoordinatorV1::with_test_configuration(root, descriptor, receiver, None)
        .expect("test configuration");
    let mut session = common::open_session();
    let mut carrier = FakeCarrier { managed_tor_calls: 0, relay_calls: 0, fail_tor: false, opaque_envelopes: Vec::new() };
    assert_eq!(coordinator
        .submit(VoterPrivateRouteV1::SplitTrustRelay, &common::triptych_package_bytes(0, &[b"candidate-a"]), &mut session, &mut carrier)
        .expect("explicit relay")
        .receipt
        .state, VoterReceiptStateV1::Accepted);
    assert_eq!(carrier.managed_tor_calls, 0);
    assert_eq!(carrier.relay_calls, 1);

    let mut production = PrivateSubmissionCoordinatorV1::production_unprovisioned();
    let mut fresh_session = common::open_session();
    let mut no_carrier = FakeCarrier { managed_tor_calls: 0, relay_calls: 0, fail_tor: false, opaque_envelopes: Vec::new() };
    assert!(production
        .submit(VoterPrivateRouteV1::ManagedTor, &common::triptych_package_bytes(0, &[b"candidate-a"]), &mut fresh_session, &mut no_carrier)
        .is_err());
    assert_eq!(no_carrier.managed_tor_calls, 0);
    assert_eq!(no_carrier.relay_calls, 0);
}
