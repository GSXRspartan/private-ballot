//! Manual end-to-end regression fixture for the managed transport final
//! archive path. It exercises real accepted transport history, two sealed
//! transport partitions, finalized archive verification, live anchor config
//! preparation, and repeated inbox reconciliation idempotence.

#![cfg(feature = "managed-tor")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "../../gui-core/tests/common/mod.rs"]
mod common;

use ed25519_dalek::SigningKey;
use hpke::{Kem as KemTrait, Serializable, kem::X25519HkdfSha256};
use tari_cc_private_ballot_ballot::{
    ApprovalBallotPayload, BallotConfidentialityV1, BallotKindV1, BallotPackageV1,
    BallotPackageV1Input, ElectionId, ElectionManifestV1, ElectionManifestV1Input,
};
use tari_cc_private_ballot_crypto::{
    TARI_TRIPTYCH_PROOF_SUITE_ID_V1, TariTriptychSecretKeyV1, prove_tari_triptych_prototype_v1,
};
use tari_cc_private_ballot_gui_core::{
    BatchPolicyV1, GuiElectionArtifactsV1, GuiElectionSessionV1, GuiLiveAnchorConfigRequestV1,
    PaddingPolicyV1, PrivateBallotEnvelopeV1, TransportDescriptorV1, TransportRoutePolicyV1,
    VoterReceiptStateV1, append_accepted_ballot_package_to_inbox_v1,
    ingest_private_intake_inbox_into_session_v1, verify_archive_directory_v1,
    write_finalized_archive_v1_with_transport_binding,
    write_live_anchor_config_from_verified_archive_v1,
};
use tari_cc_private_ballot_protocol::{
    Blake3HashProviderV1, CanonicalCborWriter, HashProvider, PROTOCOL_VERSION_V1,
};
use tari_cc_private_ballot_registry::RegistrySnapshot;
use tari_cc_private_ballot_transport_gateway::{GatewayReceiverKeyV1, TransportGatewaySimulatorV1};
use tari_cc_private_ballot_verifier::{
    build_tari_triptych_verifier_from_registry_v1, reconstruct_approval_proof_statement,
};

type Kem = X25519HkdfSha256;

const VOTERS: usize = 50;
const BATCH_FLOOR: u64 = 25;
const TEST_ONION: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";

struct FiftyVoterFixture {
    registry: RegistrySnapshot,
    registry_bytes: Vec<u8>,
    manifest: ElectionManifestV1,
    manifest_bytes: Vec<u8>,
}

#[test]
#[ignore = "manual 50-voter real-proof managed-transport final archive regression"]
fn fifty_voter_transport_archive_binding_survives_repeated_sync_and_prepares_anchor_config() {
    let fixture = fifty_voter_fixture();
    let dir = common::TestDir::new("transport-final-archive-50");
    let inbox = dir.join("inbox");

    let (receiver_secret, receiver_public) = Kem::gen_keypair();
    let mut receiver_public_bytes = [0u8; 32];
    receiver_public_bytes.copy_from_slice(receiver_public.to_bytes().as_slice());
    let mut receiver_secret_bytes = [0u8; 32];
    receiver_secret_bytes.copy_from_slice(receiver_secret.to_bytes().as_slice());
    let receiver_key =
        GatewayReceiverKeyV1::from_secret_bytes(receiver_secret_bytes).expect("receiver key");
    let descriptor = descriptor_for(&fixture, receiver_public_bytes);

    let mut gateway = TransportGatewaySimulatorV1::default();
    let mut collector_session = open_fifty_voter_session(&fixture);

    for voter_index in 0..VOTERS {
        let selection = if voter_index % 2 == 0 {
            b"candidate-a".as_slice()
        } else {
            b"candidate-b".as_slice()
        };
        let package = package_bytes_for(&fixture, voter_index, selection);
        let envelope = PrivateBallotEnvelopeV1::seal(&descriptor, &package)
            .expect("seal envelope")
            .to_canonical_cbor()
            .expect("encode envelope");
        let (receipt, _digest) = gateway
            .deliver_and_digest(
                &envelope,
                &descriptor,
                &receiver_key,
                retry_capability(voter_index),
                &mut collector_session,
            )
            .expect("gateway delivery");
        assert_eq!(receipt.state, VoterReceiptStateV1::Accepted);
        append_accepted_ballot_package_to_inbox_v1(&inbox, &package).expect("append inbox");

        if voter_index + 1 == 25 {
            assert!(
                gateway.seal_pending_batch(BATCH_FLOOR, false).is_some(),
                "first partition seals at the configured floor",
            );
        }
    }
    assert!(
        gateway.seal_pending_batch(BATCH_FLOOR, true).is_some(),
        "final partition seals remaining accepted history",
    );

    assert_eq!(gateway.accepted_unique_count(), VOTERS as u64);
    let binding = gateway
        .transport_archive_binding(&descriptor)
        .expect("binding derives from gateway state")
        .expect("sealed batches produce a binding");
    assert_eq!(binding.batches().len(), 2);
    assert_eq!(
        binding
            .batches()
            .iter()
            .map(|batch| batch.accepted_unique_count())
            .sum::<u64>(),
        VOTERS as u64,
    );
    assert!(
        binding
            .batches()
            .iter()
            .all(|batch| !batch.reduced_anonymity()),
        "both partitions meet the transport floor",
    );

    let mut authoritative_session = open_fifty_voter_session(&fixture);
    let first_sync =
        ingest_private_intake_inbox_into_session_v1(&inbox, &mut authoritative_session)
            .expect("first reconciliation");
    assert_eq!(first_sync.discovered, VOTERS);
    assert_eq!(first_sync.newly_accepted, VOTERS);
    assert_eq!(first_sync.rejected, 0);
    assert_eq!(authoritative_session.accepted_count(), VOTERS);

    for _ in 0..8 {
        let repeat =
            ingest_private_intake_inbox_into_session_v1(&inbox, &mut authoritative_session)
                .expect("repeat reconciliation");
        assert_eq!(repeat.discovered, VOTERS);
        assert_eq!(repeat.newly_accepted, 0);
        assert_eq!(repeat.duplicates, VOTERS);
        assert_eq!(
            authoritative_session.transcript().rejected_count(),
            0,
            "re-sync must not archive already-consumed packages as rejected ballots",
        );
        assert_eq!(authoritative_session.packages().len(), VOTERS);
    }

    authoritative_session.close().expect("close");
    authoritative_session.mark_verified().expect("verified");
    authoritative_session.finalize().expect("finalize");

    let archive_dir = dir.join("archive");
    write_finalized_archive_v1_with_transport_binding(
        &authoritative_session,
        &archive_dir,
        &binding,
    )
    .expect("finalized archive write");
    let verification = verify_archive_directory_v1(&archive_dir).expect("archive verification");
    assert!(verification.verified);
    assert!(verification.finalized);
    assert!(verification.transport_binding_present);
    assert!(verification.transport_binding_verified);
    assert_eq!(verification.transport_accepted_count, Some(VOTERS as u64));
    assert_eq!(verification.accepted_count, VOTERS);
    assert_eq!(verification.rejected_count, 0);

    let config = write_live_anchor_config_from_verified_archive_v1(&live_anchor_request(
        &dir,
        &archive_dir,
        VOTERS as u64,
    ))
    .expect("anchor config preparation");
    assert_eq!(config.input_provenance, "ArchiveVerified");
    assert_eq!(config.accepted_ballot_count, VOTERS as u64);
    assert_eq!(config.required_accepted_ballot_floor, VOTERS as u64);
}

fn fifty_voter_fixture() -> FiftyVoterFixture {
    let provider = Blake3HashProviderV1;
    let registry_bytes = registry_bytes_for(VOTERS);
    let registry = RegistrySnapshot::from_canonical_cbor(&registry_bytes).expect("registry");
    let candidates = common::candidate_set();
    let registry_commitment = registry
        .canonical_commitment(&provider)
        .expect("registry commitment");
    let candidate_set_commitment = candidates
        .canonical_commitment(&provider)
        .expect("candidate commitment");
    let election_id = ElectionId::new(b"transport-final-archive-50".to_vec()).expect("election id");
    let manifest = ElectionManifestV1::new(ElectionManifestV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        election_id,
        ballot_kind: BallotKindV1::NonBindingApprovalPilot,
        ballot_confidentiality: BallotConfidentialityV1::Public,
        registry_commitment,
        candidate_set_commitment,
        proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
        approval_limits: common::approval_limits(),
        governance_source_revision: "transport-final-archive-50-revision-1".to_owned(),
    })
    .expect("manifest");
    let manifest_bytes = manifest.to_canonical_cbor().expect("manifest bytes");
    FiftyVoterFixture {
        registry,
        registry_bytes,
        manifest,
        manifest_bytes,
    }
}

fn registry_bytes_for(voters: usize) -> Vec<u8> {
    let mut keys: Vec<[u8; 32]> = (0..voters)
        .map(|index| common::voter(voter_scalar(index)).public_bytes)
        .collect();
    keys.sort_unstable();
    let mut writer = CanonicalCborWriter::new();
    writer.write_array_len(keys.len()).expect("registry array");
    for key in keys {
        writer.write_byte_string(&key).expect("registry key");
    }
    writer.into_bytes()
}

fn voter_scalar(voter_index: usize) -> u64 {
    u64::try_from(voter_index + 1).expect("voter index fits in u64")
}

fn open_fifty_voter_session(fixture: &FiftyVoterFixture) -> GuiElectionSessionV1 {
    let artifacts = GuiElectionArtifactsV1::from_bytes(
        &fixture.manifest_bytes,
        &fixture.registry_bytes,
        &common::candidate_bytes(),
    )
    .expect("artifacts");
    let mut session = GuiElectionSessionV1::new(artifacts).expect("session");
    session.open().expect("open");
    session
}

fn package_bytes_for(fixture: &FiftyVoterFixture, voter_index: usize, selection: &[u8]) -> Vec<u8> {
    let provider = Blake3HashProviderV1;
    let candidates = common::candidate_set();
    let payload = ApprovalBallotPayload::new(
        vec![common::candidate_id(selection)],
        &candidates,
        fixture.manifest.approval_limits(),
    )
    .expect("payload");
    let verifier = build_tari_triptych_verifier_from_registry_v1(&fixture.registry, &provider)
        .expect("verifier");
    let statement = reconstruct_approval_proof_statement(&fixture.manifest, &payload, &provider)
        .expect("statement");
    let secret = TariTriptychSecretKeyV1::from_canonical_bytes(
        common::voter(voter_scalar(voter_index)).secret_bytes,
    )
    .expect("secret");
    let proof = prove_tari_triptych_prototype_v1(&statement, &verifier, &secret).expect("proof");
    let manifest_hash = fixture
        .manifest
        .canonical_hash(&provider)
        .expect("manifest hash");
    let package = BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash,
        proof_suite_id: fixture.manifest.proof_suite_id().to_owned(),
        proof,
        payload,
    })
    .expect("package");
    package.to_canonical_cbor().expect("package bytes")
}

fn descriptor_for(fixture: &FiftyVoterFixture, receiver_public: [u8; 32]) -> TransportDescriptorV1 {
    let authority = SigningKey::from_bytes(&[91; 32]);
    let receipt_key = SigningKey::from_bytes(&[92; 32]);
    TransportDescriptorV1::sign_for_test_or_ceremony(
        fixture.manifest.election_id().as_bytes().to_vec(),
        fixture
            .manifest
            .canonical_hash(&Blake3HashProviderV1)
            .expect("manifest hash"),
        1,
        TransportRoutePolicyV1::ManagedTorOrOffline,
        vec![TEST_ONION.to_owned()],
        Vec::new(),
        receiver_public,
        "transport-final-archive-50-gateway".to_owned(),
        vec![receipt_key.verifying_key().to_bytes()],
        PaddingPolicyV1 {
            id: "fixed-50".to_owned(),
            padded_bytes: 65_536,
        },
        BatchPolicyV1 {
            id: "accepted-25".to_owned(),
            accepted_unique_floor: BATCH_FLOOR,
        },
        None,
        "transport-final-archive-50-root".to_owned(),
        &authority,
    )
    .expect("descriptor")
}

fn retry_capability(voter_index: usize) -> [u8; 32] {
    let mut capability = [0u8; 32];
    capability[..8].copy_from_slice(&voter_scalar(voter_index).to_le_bytes());
    capability
}

fn live_anchor_request(
    dir: &common::TestDir,
    archive_directory: &std::path::Path,
    floor: u64,
) -> GuiLiveAnchorConfigRequestV1 {
    GuiLiveAnchorConfigRequestV1 {
        archive_directory: archive_directory.to_string_lossy().into_owned(),
        output_config_path: dir
            .join("live-anchor-config.cbor")
            .to_string_lossy()
            .into_owned(),
        network: "esmeralda".to_owned(),
        walletd_endpoint: "http://127.0.0.1:12009".to_owned(),
        indexer_endpoint: "http://127.0.0.1:12500".to_owned(),
        template_address: format!("template_{}", "22".repeat(32)),
        template_module: "tari_private_ballot_anchor".to_owned(),
        template_event_topic: "tari_private_ballot_anchor.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V1"
            .to_owned(),
        template_artifact_digest_hex: "33".repeat(32),
        max_epoch_delta: 12,
        account_reference: "fee-account".to_owned(),
        fee_component: format!("component_{}", "11".repeat(32)),
        seal_signer_kind: "account".to_owned(),
        seal_signer_id: "0".to_owned(),
        declared_seal_public_key: "seal-public-key-attested".to_owned(),
        dedicated_organizer_wallet_attested: true,
        max_fee: 1_000,
        required_accepted_ballot_floor: floor,
        reduced_anonymity_acknowledged: false,
        snapshot_path: dir
            .join("live-anchor-snapshot.cbor")
            .to_string_lossy()
            .into_owned(),
        evidence_path: dir
            .join("live-anchor-evidence.cbor")
            .to_string_lossy()
            .into_owned(),
        backoff_base_secs: 1,
        backoff_cap_secs: 2,
        receipt_query_attempts: 8,
        request_timeout_secs: Some(30),
        ttl_secs: None,
    }
}
