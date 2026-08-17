//! §32 integration: joins the already-reviewed gui-core release boundary to the
//! real [`TorSocksPrivateReleaseCarrierV1`] through a fake SOCKS5 server.
//!
//! It proves the adapter fit: at the exact moment the fake SOCKS server receives
//! the envelope bytes, a durable `CAST_PENDING` release record already exists on
//! disk. An authenticated receipt then promotes the voter to `CAST`. No Tauri,
//! no real Tor, no network beyond loopback.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ed25519_dalek::SigningKey;

use tari_cc_private_ballot_ballot::{
    BallotConfidentialityV1, BallotKindV1, ElectionId, ElectionManifestV1, ElectionManifestV1Input,
};
use tari_cc_private_ballot_crypto::TARI_TRIPTYCH_PROOF_SUITE_ID_V1;
use tari_cc_private_ballot_gui_core::{
    AuthenticatedTransportReceiptV1, BatchPolicyV1, DescriptorConsistencyStoreV1,
    ElectionLifecycleStateV1, GuiElectionArtifactsV1, GuiVoterCastLockStateV1,
    GuiVoterElectionBindingV1, GuiVoterSessionV1, PaddingPolicyV1, RetryStatusV1,
    TransportAuthorityRootSetV1, TransportAuthorityRootV1, TransportDescriptorV1,
    TransportRoutePolicyV1, VoterReceiptStateV1, VoterTransportReceiptV1, cast_record_exists_v1,
    load_pending_release_retry_handle_v1, public_credential_fingerprint_hex_v1,
};
use tari_cc_private_ballot_protocol::{
    Blake3HashProviderV1, CanonicalCborWriter, PROTOCOL_VERSION_V1,
};
use tari_cc_private_ballot_registry::RegistrySnapshot;
use tari_cc_private_ballot_transport_network::{
    TorCarrierTimeoutsV1, TorSocksPrivateReleaseCarrierV1,
};

use super::common;
use super::fake_socks::{self, FakeSocks5Config, FakeSocks5Server, http_ok};

const TEST_ONION: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";
const PASSPHRASE: &str = "release-boundary-carrier passphrase";
const ROOT_KEY_ID: &str = "release-carrier-root-2026";

pub fn run_release_boundary_to_carrier_test() {
    let dir = common::TestDir::new("release-boundary-real-carrier");
    let cast_dir = dir.join("voter-cast-locks");
    tari_cc_private_ballot_gui_core::ensure_voter_cast_locks_directory_v1(&cast_dir)
        .expect("cast dir");
    let staging_dir = dir.join("voter-release-staging");
    std::fs::create_dir_all(&staging_dir).expect("staging dir");

    let credential = tari_cc_private_ballot_gui_core::VoterGovernanceCredentialV1::generate()
        .expect("credential");
    let credential_public = credential.public_key_bytes().expect("public key");
    let container = tari_cc_private_ballot_gui_core::export_voter_credential_container_v1(
        &credential,
        PASSPHRASE,
    )
    .expect("container");

    let election_id = b"release-boundary-carrier-election".to_vec();
    let artifacts = artifacts_for_public_key(credential_public, &election_id);

    let authority = SigningKey::from_bytes(&[0x31; 32]);
    let receipt_key = SigningKey::from_bytes(&[0x32; 32]);
    let roots = TransportAuthorityRootSetV1::new(TransportAuthorityRootV1::Pinned {
        key_id: ROOT_KEY_ID.to_owned(),
        public_key: authority.verifying_key().to_bytes(),
    });
    let (gateway_public, _gateway_secret) = gateway_keypair();

    // Eligible voter session + a real prepared ballot.
    let mut session = {
        let credential = tari_cc_private_ballot_gui_core::import_voter_credential_container_v1(
            &container, PASSPHRASE,
        )
        .expect("import");
        let mut session = GuiVoterSessionV1::new(&artifacts);
        let status = session
            .install_credential(credential, &artifacts)
            .expect("install");
        assert!(status.can_continue, "voter must be eligible");
        session
    };
    session
        .set_selection(
            &artifacts,
            ElectionLifecycleStateV1::Open,
            vec![lower_hex(common::candidate_id(b"candidate-a").as_bytes())],
            false,
        )
        .expect("selection");
    let prepared = session
        .prepare_ballot(&artifacts, ElectionLifecycleStateV1::Open)
        .expect("prepare");
    assert!(prepared.ready_to_export);
    let package_digest_hex = prepared.summary.expect("summary").package_digest_hex;

    let prepared_len = session
        .prepared_canonical_ballot_bytes(&artifacts, ElectionLifecycleStateV1::Open)
        .expect("prepared bytes")
        .len();
    let descriptor = TransportDescriptorV1::sign_for_test_or_ceremony(
        election_id.clone(),
        artifacts.manifest_hash(),
        1,
        TransportRoutePolicyV1::ManagedTorOrOffline,
        vec![TEST_ONION.to_owned()],
        Vec::new(),
        gateway_public,
        "release-carrier-gateway".to_owned(),
        vec![receipt_key.verifying_key().to_bytes()],
        PaddingPolicyV1 {
            id: "fixed-release-carrier".to_owned(),
            padded_bytes: prepared_len + 4 + 1024,
        },
        BatchPolicyV1 {
            id: "accepted-1".to_owned(),
            accepted_unique_floor: 1,
        },
        None,
        ROOT_KEY_ID.to_owned(),
        &authority,
    )
    .expect("descriptor");

    // The authenticated receipt the collector will return for this exact release.
    let receipt = AuthenticatedTransportReceiptV1::sign_for_test_or_ceremony(
        VoterTransportReceiptV1 {
            state: VoterReceiptStateV1::Accepted,
            retry_status: RetryStatusV1::NewDelivery,
        },
        descriptor.fingerprint().expect("fingerprint"),
        hex32(&package_digest_hex),
        None,
        "release-carrier-receipt".to_owned(),
        &receipt_key,
    );
    let receipt_bytes = receipt.to_canonical_cbor().expect("canonical receipt");

    // The fake SOCKS callback asserts, at the instant envelope bytes arrive, that
    // a durable PENDING release record already exists — then returns the receipt.
    let pending_seen = Arc::new(AtomicBool::new(false));
    let manifest_hex = GuiVoterElectionBindingV1::from_artifacts(&artifacts).manifest_hash_hex;
    let fingerprint = public_credential_fingerprint_hex_v1(&lower_hex(&credential_public))
        .expect("fingerprint hex");
    let callback = {
        let pending_seen = Arc::clone(&pending_seen);
        let cast_dir = cast_dir.clone();
        let manifest_hex = manifest_hex.clone();
        let fingerprint = fingerprint.clone();
        Box::new(move |_request: &[u8]| -> Vec<u8> {
            let record =
                cast_record_exists_v1(&cast_dir, &manifest_hex, &fingerprint).unwrap_or(false);
            let pending =
                load_pending_release_retry_handle_v1(&cast_dir, &manifest_hex, &fingerprint)
                    .is_some();
            pending_seen.store(record && pending, Ordering::SeqCst);
            http_ok(&receipt_bytes)
        }) as fake_socks::HttpResponder
    };

    let socks = FakeSocks5Server::start(FakeSocks5Config::success_with(callback));
    let mut carrier =
        TorSocksPrivateReleaseCarrierV1::new(socks.addr(), TorCarrierTimeoutsV1::default())
            .expect("carrier");

    let mut consistency = DescriptorConsistencyStoreV1::default();
    let result = session
        .release_prepared_ballot_via_private_transport(
            &artifacts,
            ElectionLifecycleStateV1::Open,
            &descriptor,
            &roots,
            &mut consistency,
            &cast_dir,
            &staging_dir,
            &mut carrier,
        )
        .expect("release attempt returns a result");

    let _ = socks.join();

    assert!(
        pending_seen.load(Ordering::SeqCst),
        "a durable PENDING release record must exist when the carrier sends bytes",
    );
    assert!(result.released, "an authenticated receipt promotes to CAST");
    assert_eq!(result.cast_lock_state, "CAST");
    assert_eq!(session.cast_lock_state(), GuiVoterCastLockStateV1::Cast);
    let _ = fake_socks::success_connect_reply(); // keep helper referenced
}

fn gateway_keypair() -> ([u8; 32], [u8; 32]) {
    use hpke::{Kem as KemTrait, Serializable, kem::X25519HkdfSha256};
    let (secret, public) = X25519HkdfSha256::gen_keypair();
    let mut public_bytes = [0u8; 32];
    public_bytes.copy_from_slice(public.to_bytes().as_slice());
    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(secret.to_bytes().as_slice());
    (public_bytes, secret_bytes)
}

fn artifacts_for_public_key(public_key: [u8; 32], election_id: &[u8]) -> GuiElectionArtifactsV1 {
    let provider = Blake3HashProviderV1;
    let registry = RegistrySnapshot::from_canonical_cbor(&registry_bytes_from_key(public_key))
        .expect("registry");
    let candidates = common::candidate_set();
    let manifest = ElectionManifestV1::new(ElectionManifestV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        election_id: ElectionId::new(election_id.to_vec()).expect("election id"),
        ballot_kind: BallotKindV1::NonBindingApprovalPilot,
        ballot_confidentiality: BallotConfidentialityV1::Public,
        registry_commitment: registry
            .canonical_commitment(&provider)
            .expect("registry commitment"),
        candidate_set_commitment: candidates
            .canonical_commitment(&provider)
            .expect("candidate commitment"),
        proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
        approval_limits: common::approval_limits(),
        governance_source_revision: "release-boundary-carrier".to_owned(),
    })
    .expect("manifest");
    let manifest_bytes = manifest.to_canonical_cbor().expect("manifest bytes");
    let candidate_bytes = candidates.to_canonical_cbor().expect("candidate bytes");
    GuiElectionArtifactsV1::from_bytes(
        &manifest_bytes,
        &registry_bytes_from_key(public_key),
        &candidate_bytes,
    )
    .expect("artifacts")
}

fn registry_bytes_from_key(public_key: [u8; 32]) -> Vec<u8> {
    let mut writer = CanonicalCborWriter::new();
    writer.write_array_len(1).expect("array");
    writer.write_byte_string(&public_key).expect("key");
    writer.into_bytes()
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn hex32(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64, "expected a 32-byte hex digest");
    let mut out = [0u8; 32];
    for (index, chunk) in hex.as_bytes().chunks(2).enumerate() {
        out[index] = (from_hex(chunk[0]) << 4) | from_hex(chunk[1]);
    }
    out
}

fn from_hex(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex digit"),
    }
}
