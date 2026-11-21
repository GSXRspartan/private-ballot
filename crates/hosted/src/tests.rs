#![forbid(unsafe_code)]

//! Hosted backend integration tests: synthetic election, real Triptych
//! proofs, idempotent retry, distinct same-nullifier rejection, malformed
//! and wrong-election rejection, finalization, and Desktop archive
//! verifier compatibility.

use std::sync::Arc;

use axum::body::Body;
use curve25519_dalek_v4::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use ed25519_dalek::SigningKey;
use rusqlite::{Connection, params};
use tari_cc_private_ballot_anchor_transport::{
    ANCHOR_EVENT_FUNCTION_V2, ANCHOR_EVENT_TOPIC_SUFFIX_V2, ANCHOR_TEMPLATE_MODULE_V2,
    AnchorTemplateBindingV2,
};
use tari_cc_private_ballot_anchor::{OotleAnchorPublicPayloadV2, OotleNetworkIdV1};
use tari_cc_private_ballot_archive::{ArchiveHashV1, TransportArchiveBatchV1, TransportArchiveBindingV1};
use tari_cc_private_ballot_ballot::{
    ApprovalBallotPayload, ApprovalLimits, BallotConfidentialityV1, BallotKindV1, BallotPackageV1,
    BallotPackageV1Input, CandidateDefinition, CandidateId, CandidateSet, ElectionId,
    ElectionManifest, ElectionManifestV1, ElectionManifestV1Input,
};
use tari_cc_private_ballot_crypto::{
    TARI_TRIPTYCH_PROOF_SUITE_ID_V1, TariTriptychSecretKeyV1, prove_tari_triptych_prototype_v1,
};
use tari_cc_private_ballot_gui_core::{
    BatchPolicyV1, GuiLiveAnchorV2RequestV1, GuiV2AnchorPublishPreparationRequestV1,
    HostedDescriptorRequestV1, HostedDescriptorResponseV1, HostedOrganizerBootstrapV1,
    HostedVoterPublicBundleV2, PaddingPolicyV1, PrivateBallotEnvelopeV1,
    TransportAuthorityRootSetV1, TransportAuthorityRootV1, TransportDescriptorV1,
    TransportRoutePolicyV1, build_v2_public_payload_from_verified_archive_v1,
    prepare_v2_anchor_publish_from_verified_evidence_v1,
    verify_v2_public_payload_against_archive_v1,
};
use tari_cc_private_ballot_transport_gateway::{
    GatewayReceiverKeyV1, finalized_transport_archive_binding_from_accepted_digests_v1,
    open_envelope_bytes_v1,
};
use tari_cc_private_ballot_protocol::{
    Blake3HashProviderV1, CanonicalCborWriter, HashDomain, PROTOCOL_VERSION_V1,
    hash_domain_separated,
};
use tari_cc_private_ballot_registry::RegistrySnapshot;
use tari_cc_private_ballot_verifier::{
    build_tari_triptych_verifier_from_registry_v1, reconstruct_approval_proof_statement,
};
use tower::ServiceExt;

use crate::storage::{EnrollmentFailpoint, HostedStorage};
use crate::{
    AppState, HostedConfig, InMemoryStorage, ORIGIN_TOKEN_HEADER, admin_router_with_state,
    hex_decode, hex_encode, provision_production_transport_authority_root_v1, router_with_state,
    take_test_log_lines, test_config, verify_archive_dir_for_test,
};

fn point_bytes(m: u64) -> [u8; 32] {
    (RISTRETTO_BASEPOINT_POINT * Scalar::from(m))
        .compress()
        .to_bytes()
}
fn secret_scalar(n: u64) -> TariTriptychSecretKeyV1 {
    match TariTriptychSecretKeyV1::from_canonical_bytes(Scalar::from(n).to_bytes()) {
        Ok(s) => s,
        Err(_) => panic!("test scalar must be canonical"),
    }
}
fn candidate_id(b: &[u8]) -> CandidateId {
    match CandidateId::new(b.to_vec()) {
        Ok(v) => v,
        Err(_) => panic!("candidate id"),
    }
}

struct Fixture {
    manifest_cbor: Vec<u8>,
    registry_cbor: Vec<u8>,
    candidate_cbor: Vec<u8>,
    election_id: String,
}

fn fixture_with(election_id_str: &str, revision: &str) -> Fixture {
    let p = Blake3HashProviderV1;
    let mut keys = vec![point_bytes(1), point_bytes(2), point_bytes(3)];
    keys.sort_unstable();
    let mut w = CanonicalCborWriter::new();
    assert!(w.write_array_len(keys.len()).is_ok());
    for k in &keys {
        assert!(w.write_byte_string(k).is_ok());
    }
    let registry = match RegistrySnapshot::from_canonical_cbor(&w.into_bytes()) {
        Ok(v) => v,
        Err(_) => panic!("registry"),
    };
    let registry_cbor = match registry.to_canonical_cbor() {
        Ok(v) => v,
        Err(_) => panic!("registry cbor"),
    };
    let reg_commit = match registry.canonical_commitment(&p) {
        Ok(v) => v,
        Err(_) => panic!("commit"),
    };
    let cand =
        |id: &[u8], name: &str| match CandidateDefinition::new(candidate_id(id), name.to_owned()) {
            Ok(v) => v,
            Err(_) => panic!("cand"),
        };
    let candidates = match CandidateSet::new(vec![
        cand(b"candidate-a", "Candidate A"),
        cand(b"candidate-b", "Candidate B"),
        cand(b"candidate-c", "Candidate C"),
    ]) {
        Ok(v) => v,
        Err(_) => panic!("candset"),
    };
    let candidate_cbor = match candidates.to_canonical_cbor() {
        Ok(v) => v,
        Err(_) => panic!("cand cbor"),
    };
    let cand_commit = match candidates.canonical_commitment(&p) {
        Ok(v) => v,
        Err(_) => panic!("cand commit"),
    };
    let limits = match ApprovalLimits::new(1, 1, false) {
        Ok(v) => v,
        Err(_) => panic!("limits"),
    };
    let manifest = match ElectionManifestV1::new(ElectionManifestV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        election_id: match ElectionId::new(election_id_str.as_bytes().to_vec()) {
            Ok(v) => v,
            Err(_) => panic!("eid"),
        },
        ballot_kind: BallotKindV1::NonBindingApprovalPilot,
        ballot_confidentiality: BallotConfidentialityV1::Public,
        registry_commitment: reg_commit,
        candidate_set_commitment: cand_commit,
        proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
        approval_limits: limits,
        governance_source_revision: revision.to_owned(),
    }) {
        Ok(v) => v,
        Err(_) => panic!("manifest"),
    };
    Fixture {
        manifest_cbor: match manifest.to_canonical_cbor() {
            Ok(v) => v,
            Err(_) => panic!("manifest cbor"),
        },
        registry_cbor,
        candidate_cbor,
        election_id: election_id_str.to_owned(),
    }
}

fn fixture() -> Fixture {
    let p = Blake3HashProviderV1;
    // Registry: scalars 1,2,3 (voters A,B,C)
    let mut keys = vec![point_bytes(1), point_bytes(2), point_bytes(3)];
    keys.sort_unstable();
    let mut w = CanonicalCborWriter::new();
    assert!(w.write_array_len(keys.len()).is_ok());
    for k in &keys {
        assert!(w.write_byte_string(k).is_ok());
    }
    let registry = match RegistrySnapshot::from_canonical_cbor(&w.into_bytes()) {
        Ok(v) => v,
        Err(_) => panic!("registry"),
    };
    let registry_cbor = match registry.to_canonical_cbor() {
        Ok(v) => v,
        Err(_) => panic!("registry cbor"),
    };
    let reg_commit = match registry.canonical_commitment(&p) {
        Ok(v) => v,
        Err(_) => panic!("commit"),
    };

    let cand =
        |id: &[u8], name: &str| match CandidateDefinition::new(candidate_id(id), name.to_owned()) {
            Ok(v) => v,
            Err(_) => panic!("cand"),
        };
    let candidates = match CandidateSet::new(vec![
        cand(b"candidate-a", "Candidate A"),
        cand(b"candidate-b", "Candidate B"),
        cand(b"candidate-c", "Candidate C"),
    ]) {
        Ok(v) => v,
        Err(_) => panic!("candset"),
    };
    let candidate_cbor = match candidates.to_canonical_cbor() {
        Ok(v) => v,
        Err(_) => panic!("cand cbor"),
    };
    let cand_commit = match candidates.canonical_commitment(&p) {
        Ok(v) => v,
        Err(_) => panic!("cand commit"),
    };
    let limits = match ApprovalLimits::new(1, 1, false) {
        Ok(v) => v,
        Err(_) => panic!("limits"),
    };
    let manifest = match ElectionManifestV1::new(ElectionManifestV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        election_id: match ElectionId::new(b"hosted-synthetic-001".to_vec()) {
            Ok(v) => v,
            Err(_) => panic!("eid"),
        },
        ballot_kind: BallotKindV1::NonBindingApprovalPilot,
        ballot_confidentiality: BallotConfidentialityV1::Public,
        registry_commitment: reg_commit,
        candidate_set_commitment: cand_commit,
        proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
        approval_limits: limits,
        governance_source_revision: "hosted-synthetic".to_owned(),
    }) {
        Ok(v) => v,
        Err(_) => panic!("manifest"),
    };
    Fixture {
        manifest_cbor: match manifest.to_canonical_cbor() {
            Ok(v) => v,
            Err(_) => panic!("manifest cbor"),
        },
        registry_cbor,
        candidate_cbor,
        election_id: "hosted-synthetic-001".to_owned(),
    }
}

/// Models the exact canonical public binding emitted by the Desktop organizer
/// after it has verified signed, durable transport history. Hosted only stores
/// this public evidence and never manufactures an alternative binding.
fn desktop_transport_binding(f: &Fixture, accepted_ballot_count: u64) -> Vec<u8> {
    let (manifest, _, _) = load_fixture(f);
    let manifest_hash = manifest
        .canonical_hash(&Blake3HashProviderV1)
        .unwrap_or_else(|_| panic!("manifest hash"));
    TransportArchiveBindingV1::new(
        f.election_id.as_bytes().to_vec(),
        manifest_hash,
        [0x44; 32],
        7,
        vec![TransportArchiveBatchV1::new(
            7,
            [0x55; 32],
            accepted_ballot_count,
            false,
        )],
    )
    .and_then(|binding| binding.to_canonical_cbor())
    .unwrap_or_else(|_| panic!("desktop transport binding"))
}

fn test_transport_root() -> tari_cc_private_ballot_gui_core::TransportAuthorityRootV1 {
    let signing = SigningKey::from_bytes(&[42; 32]);
    provision_production_transport_authority_root_v1(
        "hosted-test-root",
        signing.verifying_key().to_bytes(),
    )
    .unwrap_or_else(|_| panic!("test transport root"))
}

fn desktop_binding_handoff_json(f: &Fixture, binding: &[u8], descriptor: &[u8]) -> String {
    let (manifest, _, _) = load_fixture(f);
    let manifest_hash = manifest
        .canonical_hash(&Blake3HashProviderV1)
        .unwrap_or_else(|_| panic!("manifest hash"));
    serde_json::to_string(
        &tari_cc_private_ballot_gui_core::DesktopBindingHandoffV1::new(
            f.election_id.clone(),
            hex_encode(manifest_hash.as_bytes()),
            hex_encode(binding),
            hex_encode(descriptor),
        ),
    )
    .unwrap_or_else(|_| panic!("desktop binding handoff json"))
}

fn record_desktop_transport_binding(
    storage: &InMemoryStorage,
    f: &Fixture,
    accepted_ballot_count: u64,
) {
    storage
        .put_finalized_transport_binding(crate::storage::FinalizedTransportBindingRecord {
            election_id: f.election_id.clone(),
            binding_cbor: desktop_transport_binding(f, accepted_ballot_count),
        })
        .unwrap_or_else(|_| panic!("record desktop transport binding"));
}

fn load_fixture(
    f: &Fixture,
) -> (
    tari_cc_private_ballot_ballot::ElectionManifest,
    CandidateSet,
    RegistrySnapshot,
) {
    let manifest = match tari_cc_private_ballot_ballot::ElectionManifest::from_canonical_cbor(
        &f.manifest_cbor,
    ) {
        Ok(v) => v,
        Err(_) => panic!("load manifest"),
    };
    let candidates = match CandidateSet::from_canonical_cbor(&f.candidate_cbor) {
        Ok(v) => v,
        Err(_) => panic!("load cand"),
    };
    let registry = match RegistrySnapshot::from_canonical_cbor(&f.registry_cbor) {
        Ok(v) => v,
        Err(_) => panic!("load reg"),
    };
    (manifest, candidates, registry)
}

fn make_package(f: &Fixture, scalar: u64, candidate: &[u8]) -> Vec<u8> {
    let (manifest, candidates, registry) = load_fixture(f);
    let p = Blake3HashProviderV1;
    let payload = match ApprovalBallotPayload::new(
        vec![candidate_id(candidate)],
        &candidates,
        manifest.approval_limits(),
    ) {
        Ok(v) => v,
        Err(_) => panic!("payload"),
    };
    let verifier = match build_tari_triptych_verifier_from_registry_v1(&registry, &p) {
        Ok(v) => v,
        Err(_) => panic!("verifier"),
    };
    let statement = match reconstruct_approval_proof_statement(&manifest, &payload, &p) {
        Ok(v) => v,
        Err(_) => panic!("statement"),
    };
    let secret = secret_scalar(scalar);
    let proof = match prove_tari_triptych_prototype_v1(&statement, &verifier, &secret) {
        Ok(v) => v,
        Err(_) => panic!("prove"),
    };
    let mh = match manifest.canonical_hash(&p) {
        Ok(v) => v,
        Err(_) => panic!("mh"),
    };
    let package = match BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash: mh,
        proof_suite_id: manifest.proof_suite_id().to_owned(),
        proof,
        payload,
    }) {
        Ok(v) => v,
        Err(_) => panic!("package"),
    };
    match package.to_canonical_cbor() {
        Ok(v) => v,
        Err(_) => panic!("package cbor"),
    }
}

struct TestRouters {
    public: axum::Router,
    admin: axum::Router,
}

fn test_routers() -> (TestRouters, Arc<InMemoryStorage>) {
    let storage = Arc::new(InMemoryStorage::new());
    let mut config = test_config();
    config.transport_authority_root = test_transport_root();
    config.authority_signing_key = Some([42; 32]);
    let state = Arc::new(AppState::new(config, storage.clone()));
    let routers = TestRouters {
        public: router_with_state(state.clone()),
        admin: admin_router_with_state(state),
    };
    (routers, storage)
}

fn test_router() -> (axum::Router, Arc<InMemoryStorage>) {
    let (routers, storage) = test_routers();
    (routers.public, storage)
}

async fn req(
    router: axum::Router,
    method: &str,
    uri: &str,
    body: Option<String>,
    headers: &[(&str, &str)],
) -> (axum::http::StatusCode, String) {
    let mut builder = axum::http::Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let body = match body {
        Some(b) => Body::from(b),
        None => Body::empty(),
    };
    let request = match builder.body(body) {
        Ok(r) => r,
        Err(_) => panic!("request"),
    };
    let response = match router.oneshot(request).await {
        Ok(r) => r,
        Err(_) => panic!("oneshot"),
    };
    let status = response.status();
    let bytes = match axum::body::to_bytes(response.into_body(), 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => panic!("body"),
    };
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn req_bytes(
    router: axum::Router,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
) -> (axum::http::StatusCode, Vec<u8>) {
    let mut builder = axum::http::Request::builder().method(method).uri(uri);
    for (key, value) in headers {
        builder = builder.header(*key, *value);
    }
    let response = router
        .oneshot(builder.body(Body::empty()).unwrap_or_else(|_| panic!("request")))
        .await
        .unwrap_or_else(|_| panic!("oneshot"));
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap_or_else(|_| panic!("body"));
    (status, bytes.to_vec())
}

async fn req_cbor(
    router: axum::Router,
    method: &str,
    uri: &str,
    body: Vec<u8>,
    organizer_secret: &str,
) -> (axum::http::StatusCode, Vec<u8>) {
    let request = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/cbor")
        .header("x-private-ballot-organizer", organizer_secret)
        .body(Body::from(body))
        .unwrap_or_else(|_| panic!("request"));
    let response = router
        .oneshot(request)
        .await
        .unwrap_or_else(|_| panic!("oneshot"));
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap_or_else(|_| panic!("body"));
    (status, bytes.to_vec())
}

async fn import(admin: axum::Router, f: &Fixture) -> axum::http::StatusCode {
    let body = serde_json::json!({"election_id": f.election_id, "manifest_cbor_hex": hex_encode(&f.manifest_cbor), "registry_cbor_hex": hex_encode(&f.registry_cbor), "candidate_cbor_hex": hex_encode(&f.candidate_cbor)}).to_string();
    let (status, _) = req(
        admin,
        "POST",
        "/api/v1/admin/elections/import",
        Some(body),
        &[
            ("content-type", "application/json"),
            ("x-admin-token", "test-admin-token"),
        ],
    )
    .await;
    status
}

#[tokio::test]
async fn end_to_end_hosted_flow_and_desktop_archive_verifier() {
    let f = fixture();
    let (routers, storage) = test_routers();
    let router = routers.public.clone();
    assert_eq!(
        import(routers.admin.clone(), &f).await,
        axum::http::StatusCode::CREATED
    );
    // Voter A ballot
    let pkg_a = make_package(&f, 1, b"candidate-a");
    let body_a = serde_json::json!({"receipt_id": "00000000-0000-4000-8000-000000000001", "package_cbor_hex": hex_encode(&pkg_a), "api_version": "v1"}).to_string();
    let (s1, r1) = req(
        router.clone(),
        "POST",
        &format!("/api/v1/elections/{}/ballots", f.election_id),
        Some(body_a.clone()),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(s1, axum::http::StatusCode::CREATED, "receipt: {r1}");
    let receipt: serde_json::Value =
        serde_json::from_str(&r1).unwrap_or_else(|_| panic!("receipt json"));
    assert_eq!(receipt["status"], "accepted");
    // Exact retry -> same stable receipt, replay=true, no double count
    let (s2, r2) = req(
        router.clone(),
        "POST",
        &format!("/api/v1/elections/{}/ballots", f.election_id),
        Some(body_a.clone()),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(s2, axum::http::StatusCode::OK);
    let receipt2: serde_json::Value =
        serde_json::from_str(&r2).unwrap_or_else(|_| panic!("receipt2 json"));
    assert_eq!(receipt["stable_receipt"], receipt2["stable_receipt"]);
    assert_eq!(receipt2["replay"], true);
    assert_eq!(
        storage
            .list_ballots(&f.election_id)
            .map(|v| v.len())
            .unwrap_or(99),
        1
    );
    // GET receipt
    let (s3, r3) = req(
        router.clone(),
        "GET",
        &format!(
            "/api/v1/elections/{}/receipt/00000000-0000-4000-8000-000000000001",
            f.election_id
        ),
        None,
        &[],
    )
    .await;
    assert_eq!(s3, axum::http::StatusCode::OK, "{r3}");
    // Distinct second ballot from SAME voter (same nullifier) -> duplicate_nullifier
    let pkg_a2 = make_package(&f, 1, b"candidate-b");
    let body_a2 = serde_json::json!({"receipt_id": "00000000-0000-4000-8000-000000000002", "package_cbor_hex": hex_encode(&pkg_a2), "api_version": "v1"}).to_string();
    let (s4, r4) = req(
        router.clone(),
        "POST",
        &format!("/api/v1/elections/{}/ballots", f.election_id),
        Some(body_a2),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(s4, axum::http::StatusCode::CONFLICT, "{r4}");
    assert!(r4.contains("duplicate_nullifier"), "{r4}");
    // Voter B valid
    let pkg_b = make_package(&f, 2, b"candidate-b");
    let body_b = serde_json::json!({"receipt_id": "00000000-0000-4000-8000-000000000003", "package_cbor_hex": hex_encode(&pkg_b), "api_version": "v1"}).to_string();
    let (s5, _) = req(
        router.clone(),
        "POST",
        &format!("/api/v1/elections/{}/ballots", f.election_id),
        Some(body_b),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(s5, axum::http::StatusCode::CREATED);
    // Malformed package
    let body_bad = serde_json::json!({"receipt_id": "00000000-0000-4000-8000-000000000004", "package_cbor_hex": "00ff", "api_version": "v1"}).to_string();
    let (s6, _) = req(
        router.clone(),
        "POST",
        &format!("/api/v1/elections/{}/ballots", f.election_id),
        Some(body_bad),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(s6, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    // Wrong-election: valid package for a different election id would need second fixture; tamper manifest hash by using pkg from other election is covered by wrong manifest hash check in verifier tests. Here submit pkg_a to unknown election -> 404
    let (s7, _) = req(
        router.clone(),
        "POST",
        "/api/v1/elections/nope/ballots",
        Some(body_a.clone()),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(s7, axum::http::StatusCode::NOT_FOUND);
    // Close + finalize (admin plane)
    let (s8, _) = req(
        routers.admin.clone(),
        "POST",
        &format!("/api/v1/admin/elections/{}/close", f.election_id),
        None,
        &[("x-admin-token", "test-admin-token")],
    )
    .await;
    assert_eq!(s8, axum::http::StatusCode::OK);
    // Ballot after close -> election_closed
    let pkg_c = make_package(&f, 3, b"candidate-c");
    let body_c = serde_json::json!({"receipt_id": "00000000-0000-4000-8000-000000000005", "package_cbor_hex": hex_encode(&pkg_c), "api_version": "v1"}).to_string();
    let (s9, r9) = req(
        router.clone(),
        "POST",
        &format!("/api/v1/elections/{}/ballots", f.election_id),
        Some(body_c),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(s9, axum::http::StatusCode::CONFLICT, "{r9}");
    record_desktop_transport_binding(storage.as_ref(), &f, 2);
    let (s10, r10) = req(
        routers.admin.clone(),
        "POST",
        &format!("/api/v1/admin/elections/{}/finalize", f.election_id),
        None,
        &[("x-admin-token", "test-admin-token")],
    )
    .await;
    assert_eq!(s10, axum::http::StatusCode::OK, "{r10}");
    // Results: A->a, B->b => counts 1,1,0
    let (s11, r11) = req(
        router.clone(),
        "GET",
        &format!("/api/v1/elections/{}/results", f.election_id),
        None,
        &[],
    )
    .await;
    assert_eq!(s11, axum::http::StatusCode::OK, "{r11}");
    let results: serde_json::Value =
        serde_json::from_str(&r11).unwrap_or_else(|_| panic!("results json"));
    assert_eq!(results["accepted_ballots"], 2);
    // Archive endpoint
    let (s12, r12) = req(
        router.clone(),
        "GET",
        &format!("/api/v1/elections/{}/archive", f.election_id),
        None,
        &[],
    )
    .await;
    assert_eq!(s12, axum::http::StatusCode::OK, "{r12}");
    let archive: serde_json::Value =
        serde_json::from_str(&r12).unwrap_or_else(|_| panic!("archive json"));
    // Write archive to temp dir and verify with EXISTING desktop verifier
    let dir = std::env::temp_dir().join(format!("pb-hosted-archive-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap_or_else(|_| panic!("mkdir"));
    let files = archive["files"]
        .as_array()
        .map(|v| v.clone())
        .unwrap_or_default();
    let manifest_bytes = hex_decode(archive["archive_manifest_cbor_hex"].as_str().unwrap_or(""))
        .unwrap_or_else(|_| panic!("archive endpoint must return canonical manifest bytes"));
    assert_eq!(archive["anchor_eligible"], true);
    write_archive_from_endpoint(&dir, &files, &manifest_bytes);
    assert!(
        verify_archive_dir_for_test(&dir),
        "desktop verifier must pass hosted archive"
    );

    // Exercise the production Desktop V2 payload/preparation boundary against
    // Hosted's finalized files. This is offline and never contacts a wallet.
    let desktop_payload =
        build_v2_public_payload_from_verified_archive_v1(&GuiLiveAnchorV2RequestV1 {
            archive_directory: dir.to_string_lossy().into_owned(),
            network: "mainnet".to_owned(),
            template_address:
                tari_cc_private_ballot_deployment_registry::MAINNET_V2_TEMPLATE_ADDRESS.to_owned(),
            template_module: ANCHOR_TEMPLATE_MODULE_V2.to_owned(),
            template_function: ANCHOR_EVENT_FUNCTION_V2.to_owned(),
            template_event_topic: format!(
                "{ANCHOR_TEMPLATE_MODULE_V2}.{ANCHOR_EVENT_TOPIC_SUFFIX_V2}"
            ),
            template_artifact_digest_hex:
                tari_cc_private_ballot_deployment_registry::MAINNET_V2_ARTIFACT_BLAKE3.to_owned(),
        })
        .expect("Desktop must build V2 payload from Hosted's verified archive");
    let artifact_digest: [u8; 32] =
        hex_decode(tari_cc_private_ballot_deployment_registry::MAINNET_V2_ARTIFACT_BLAKE3)
            .unwrap_or_else(|_| panic!("release digest"))
            .try_into()
            .unwrap_or_else(|_| panic!("release digest length"));
    let deployment = AnchorTemplateBindingV2::new(
        tari_cc_private_ballot_deployment_registry::MAINNET_V2_TEMPLATE_ADDRESS.to_owned(),
        ANCHOR_TEMPLATE_MODULE_V2.to_owned(),
        ANCHOR_EVENT_FUNCTION_V2.to_owned(),
        format!("{ANCHOR_TEMPLATE_MODULE_V2}.{ANCHOR_EVENT_TOPIC_SUFFIX_V2}"),
        artifact_digest,
    )
    .expect("release deployment binding");
    let desktop_preparation = prepare_v2_anchor_publish_from_verified_evidence_v1(
        &GuiV2AnchorPublishPreparationRequestV1 {
            archive_directory: dir.to_string_lossy().into_owned(),
            payload_hex: desktop_payload.payload_hex.clone(),
            expected_digest_hex: desktop_payload.v2_anchor_digest_hex.clone(),
        },
        &deployment,
    )
    .expect("Desktop must prepare exact V2 call");
    let loaded = crate::LoadedElection::load(storage.as_ref(), &f.election_id)
        .unwrap_or_else(|_| panic!("finalized election loads"));
    let hosted_identity = crate::finalized_anchor_identity(&loaded, storage.as_ref())
        .unwrap_or_else(|_| panic!("Hosted identity derives"));
    assert_eq!(
        desktop_payload.archive_hash_hex,
        hosted_identity.archive_hash_hex
    );
    assert_eq!(desktop_payload.election_id, f.election_id);
    assert_eq!(
        desktop_payload.v2_anchor_digest_hex,
        hosted_identity.anchor_digest_hex
    );
    assert_eq!(
        desktop_payload.public_summary_json,
        hosted_identity.public_summary_json
    );
    assert_eq!(
        desktop_preparation.arguments,
        vec![
            hosted_identity.anchor_digest_hex,
            "mainnet".to_owned(),
            f.election_id.clone(),
            hosted_identity.public_summary_json,
        ]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn write_archive_from_endpoint(
    dir: &std::path::Path,
    files: &[serde_json::Value],
    archive_manifest_bytes: &[u8],
) {
    use std::collections::BTreeMap;
    use tari_cc_private_ballot_archive::ARCHIVE_MANIFEST_CANONICAL_PATH;
    let mut map: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for file in files {
        let path = file["path"].as_str().unwrap_or("").to_owned();
        let hex = file["cbor_hex"].as_str().unwrap_or("");
        let mut bytes = Vec::new();
        let hb = hex.as_bytes();
        let mut i = 0;
        while i + 1 < hb.len() {
            let hi = char::from(hb[i])
                .to_digit(16)
                .unwrap_or_else(|| panic!("hex"));
            let lo = char::from(hb[i + 1])
                .to_digit(16)
                .unwrap_or_else(|| panic!("hex"));
            bytes.push(((hi << 4) | lo) as u8);
            i += 2;
        }
        map.insert(path, bytes);
    }
    let submissions = dir.join("submissions");
    if map.keys().any(|k| k.starts_with("submissions")) {
        std::fs::create_dir_all(&submissions).unwrap_or_else(|_| panic!("mkdir sub"));
    }
    for (path, bytes) in &map {
        let fp = dir.join(path);
        if let Some(parent) = fp.parent() {
            std::fs::create_dir_all(parent).unwrap_or_else(|_| panic!("mkdir parent"));
        }
        std::fs::write(&fp, bytes).unwrap_or_else(|_| panic!("write"));
    }
    std::fs::write(
        dir.join(ARCHIVE_MANIFEST_CANONICAL_PATH),
        archive_manifest_bytes,
    )
    .unwrap_or_else(|_| panic!("write manifest"));
}

#[tokio::test]
async fn historical_finalized_archive_without_transport_provenance_remains_readable() {
    let f = fixture();
    let (routers, storage) = test_routers();
    assert_eq!(
        import(routers.admin.clone(), &f).await,
        axum::http::StatusCode::CREATED
    );
    assert!(
        storage
            .set_election_state(&f.election_id, "open", "closed")
            .unwrap()
    );
    // Model the pre-V5 persisted final state.  No V5 binding is inserted and
    // the endpoint must retain read access without claiming anchorability.
    assert!(
        storage
            .set_election_state(&f.election_id, "closed", "finalized")
            .unwrap()
    );
    let (status, body) = req(
        routers.public,
        "GET",
        &format!("/api/v1/elections/{}/archive", f.election_id),
        None,
        &[],
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    let archive: serde_json::Value =
        serde_json::from_str(&body).unwrap_or_else(|_| panic!("archive json"));
    assert_eq!(archive["anchor_eligible"], false);
    assert_eq!(
        archive["archive_manifest_cbor_hex"]
            .as_str()
            .unwrap_or("")
            .len()
            > 0,
        true
    );
    assert!(!archive["files"].as_array().is_some_and(|files| {
        files
            .iter()
            .any(|file| file["path"] == "transport/archive-binding-v1.cbor")
    }));
    assert!(
        storage
            .get_finalized_transport_binding(&f.election_id)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn wrong_election_binding_is_rejected() {
    let f1 = fixture_with("hosted-synthetic-001", "hosted-synthetic");
    let f2 = fixture_with("hosted-synthetic-002", "hosted-synthetic-other");
    let (routers, _storage) = test_routers();
    let router = routers.public.clone();
    assert_eq!(
        import(routers.admin.clone(), &f1).await,
        axum::http::StatusCode::CREATED
    );
    assert_eq!(
        import(routers.admin.clone(), &f2).await,
        axum::http::StatusCode::CREATED
    );
    let pkg1 = make_package(&f1, 1, b"candidate-a");
    let body = serde_json::json!({"receipt_id": "99999999-9999-4999-8999-999999999999", "package_cbor_hex": hex_encode(&pkg1), "api_version": "v1"}).to_string();
    let (status, text) = req(
        router.clone(),
        "POST",
        "/api/v1/elections/hosted-synthetic-002/ballots",
        Some(body),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::UNPROCESSABLE_ENTITY,
        "{text}"
    );
    assert!(text.contains("wrong_election"), "{text}");
    // Same package is valid in its own election
    let body2 = serde_json::json!({"receipt_id": "99999999-9999-4999-8999-999999999998", "package_cbor_hex": hex_encode(&pkg1), "api_version": "v1"}).to_string();
    let (s2, t2) = req(
        router.clone(),
        "POST",
        "/api/v1/elections/hosted-synthetic-001/ballots",
        Some(body2),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(s2, axum::http::StatusCode::CREATED, "{t2}");
}

#[tokio::test]
async fn stored_ballot_does_not_contain_voter_secret() {
    let f = fixture();
    let (routers, storage) = test_routers();
    let router = routers.public.clone();
    assert_eq!(
        import(routers.admin.clone(), &f).await,
        axum::http::StatusCode::CREATED
    );
    let pkg = make_package(&f, 1, b"candidate-a");
    let body = serde_json::json!({"receipt_id": "88888888-8888-4888-8888-888888888888", "package_cbor_hex": hex_encode(&pkg), "api_version": "v1"}).to_string();
    let (s, t) = req(
        router.clone(),
        "POST",
        &format!("/api/v1/elections/{}/ballots", f.election_id),
        Some(body),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(s, axum::http::StatusCode::CREATED, "{t}");
    let ballots = storage
        .list_ballots(&f.election_id)
        .unwrap_or_else(|_| panic!("list"));
    assert_eq!(ballots.len(), 1);
    let secret_bytes = Scalar::from(1_u64).to_bytes();
    // The stored package is the canonical public package; it must not embed the raw secret scalar as a standalone field.
    // (Package contains proof + public payload; secret scalar bytes as a 32-byte window would only appear by coincidence - check exact field absence via re-verification already done.)
    assert!(
        !ballots[0]
            .package_cbor
            .windows(32)
            .any(|w| w == secret_bytes),
        "secret scalar must not be stored verbatim in package"
    );
    assert!(
        !ballots[0]
            .envelope_hash_hex
            .contains(&hex_encode(&secret_bytes)),
        "secret must not be in envelope hash field"
    );
}

#[tokio::test]
async fn concurrent_same_receipt_does_not_double_count() {
    let f = fixture();
    let (routers, storage) = test_routers();
    let router = routers.public.clone();
    assert_eq!(
        import(routers.admin.clone(), &f).await,
        axum::http::StatusCode::CREATED
    );
    let pkg = make_package(&f, 1, b"candidate-a");
    let body = serde_json::json!({"receipt_id": "11111111-1111-4111-8111-111111111111", "package_cbor_hex": hex_encode(&pkg), "api_version": "v1"}).to_string();
    let r1 = router.clone();
    let b1 = body.clone();
    let eid1 = f.election_id.clone();
    let h1 = tokio::spawn(async move {
        req(
            r1,
            "POST",
            &format!("/api/v1/elections/{}/ballots", eid1),
            Some(b1),
            &[("content-type", "application/json")],
        )
        .await
    });
    let r2 = router.clone();
    let eid2 = f.election_id.clone();
    let h2 = tokio::spawn(async move {
        req(
            r2,
            "POST",
            &format!("/api/v1/elections/{}/ballots", eid2),
            Some(body),
            &[("content-type", "application/json")],
        )
        .await
    });
    let (s1, _) = h1.await.unwrap_or_else(|_| panic!("join"));
    let (s2, _) = h2.await.unwrap_or_else(|_| panic!("join"));
    let statuses = [s1, s2];
    assert!(statuses.contains(&axum::http::StatusCode::CREATED));
    assert!(
        statuses
            .iter()
            .all(|s| *s == axum::http::StatusCode::CREATED || *s == axum::http::StatusCode::OK)
    );
    assert_eq!(
        storage
            .list_ballots(&f.election_id)
            .map(|v| v.len())
            .unwrap_or(99),
        1
    );
}

#[test]
fn sqlite_storage_persists_and_enforces_uniqueness() {
    let dir = std::env::temp_dir().join(format!("pb-hosted-sqlite-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap_or_else(|_| panic!("mkdir"));
    let db = dir.join("test.db");
    {
        let s = crate::SqliteStorage::open(&db).unwrap_or_else(|_| panic!("open"));
        s.put_election(crate::storage::ElectionRecord {
            id: "e1".to_owned(),
            manifest_cbor: vec![1],
            registry_cbor: vec![2],
            candidate_cbor: vec![3],
            state: "open".to_owned(),
            manifest_hash_hex: "00".to_owned(),
        })
        .unwrap_or_else(|_| panic!("put"));
        assert!(
            s.put_election(crate::storage::ElectionRecord {
                id: "e1".to_owned(),
                manifest_cbor: vec![1],
                registry_cbor: vec![2],
                candidate_cbor: vec![3],
                state: "open".to_owned(),
                manifest_hash_hex: "00".to_owned()
            })
            .is_err()
        );
        s.insert_ballot(crate::storage::BallotRecord {
            election_id: "e1".to_owned(),
            receipt_id: "r1".to_owned(),
            package_cbor: vec![9],
            envelope_hash_hex: "aa".to_owned(),
            nullifier: vec![1, 2],
            seq: 1,
        })
        .unwrap_or_else(|_| panic!("insert"));
        assert_eq!(
            s.insert_ballot(crate::storage::BallotRecord {
                election_id: "e1".to_owned(),
                receipt_id: "r2".to_owned(),
                package_cbor: vec![8],
                envelope_hash_hex: "bb".to_owned(),
                nullifier: vec![1, 2],
                seq: 2
            }),
            Err(crate::storage::StorageError::DuplicateNullifier)
        );
    }
    {
        let s2 = crate::SqliteStorage::open(&db).unwrap_or_else(|_| panic!("reopen"));
        assert_eq!(s2.list_ballots("e1").map(|v| v.len()).unwrap_or(99), 1);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sqlite_schema_v2_upgrade_preserves_existing_data_and_is_idempotent() {
    let dir = std::env::temp_dir().join(format!("pb-hosted-v2-upgrade-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap_or_else(|_| panic!("mkdir"));
    let db = dir.join("hosted.db");

    // This is the Stage 3 pre-enrollment (schema v2) persistent shape.
    {
        let legacy = Connection::open(&db).unwrap_or_else(|_| panic!("open v2"));
        legacy
            .execute_batch(
                "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE elections (
                id TEXT PRIMARY KEY, manifest_cbor BLOB NOT NULL, registry_cbor BLOB NOT NULL,
                candidate_cbor BLOB NOT NULL, state TEXT NOT NULL, manifest_hash_hex TEXT NOT NULL
             );
             CREATE TABLE ballots (
                election_id TEXT NOT NULL, receipt_id TEXT NOT NULL, package_cbor BLOB NOT NULL,
                envelope_hash_hex TEXT NOT NULL, nullifier BLOB NOT NULL, seq INTEGER NOT NULL,
                PRIMARY KEY (election_id, receipt_id), UNIQUE (election_id, nullifier),
                FOREIGN KEY (election_id) REFERENCES elections(id)
             );",
            )
            .unwrap_or_else(|_| panic!("create v2 schema"));
        legacy
            .execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', '2')",
                [],
            )
            .unwrap_or_else(|_| panic!("v2 version"));
        legacy.execute(
            "INSERT INTO elections (id, manifest_cbor, registry_cbor, candidate_cbor, state, manifest_hash_hex) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params!["legacy-election", vec![1_u8], vec![2_u8], vec![3_u8], "finalized", "legacy-manifest"],
        ).unwrap_or_else(|_| panic!("v2 election"));
        legacy.execute(
            "INSERT INTO ballots (election_id, receipt_id, package_cbor, envelope_hash_hex, nullifier, seq) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params!["legacy-election", "legacy-receipt", vec![4_u8], "legacy-envelope", vec![5_u8], 7_i64],
        ).unwrap_or_else(|_| panic!("v2 ballot"));
    }

    // First open performs the normal migration and must retain v2 records.
    {
        let storage = crate::SqliteStorage::open(&db).unwrap_or_else(|_| panic!("migrate v2"));
        let election = storage
            .get_election("legacy-election")
            .unwrap_or_else(|_| panic!("read election"))
            .unwrap_or_else(|| panic!("legacy election missing"));
        assert_eq!(election.state, "finalized");
        assert_eq!(election.manifest_cbor, vec![1]);
        let ballots = storage
            .list_ballots("legacy-election")
            .unwrap_or_else(|_| panic!("read ballots"));
        assert_eq!(ballots.len(), 1);
        assert_eq!(ballots[0].receipt_id, "legacy-receipt");
        assert_eq!(ballots[0].seq, 7);
    }

    // The v6 tables/version exist after migration, and a second open is idempotent.
    {
        let migrated = Connection::open(&db).unwrap_or_else(|_| panic!("inspect v3"));
        let version: String = migrated
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap_or_else(|_| panic!("schema version"));
        assert_eq!(version, "6");
        for table in [
            "election_drafts",
            "eligibility_slots",
            "enrollment_invitations",
            "enrolled_credentials",
            "frozen_registries",
            "organizer_credentials",
            "finalized_transport_bindings",
        ] {
            let exists: i64 = migrated
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [table],
                    |r| r.get(0),
                )
                .unwrap_or_else(|_| panic!("table lookup"));
            assert_eq!(exists, 1, "missing {table}");
        }
    }
    {
        let storage = crate::SqliteStorage::open(&db).unwrap_or_else(|_| panic!("reopen v3"));
        assert!(
            storage
                .get_election("legacy-election")
                .unwrap_or_else(|_| panic!("read after reopen"))
                .is_some()
        );
        assert_eq!(
            storage
                .list_ballots("legacy-election")
                .unwrap_or_else(|_| panic!("ballots after reopen"))
                .len(),
            1
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn seed_sqlite_enrollment(
    storage: &crate::SqliteStorage,
    election_id: &str,
) -> (String, String, String) {
    storage
        .put_election_draft(crate::storage::ElectionDraftRecord {
            election_id: election_id.to_owned(),
            candidate_cbor: vec![1],
            proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
            min_approvals: 1,
            max_approvals: 1,
            allow_abstention: true,
            governance_revision: "rollback-test".to_owned(),
            proposal_question: String::new(),
            authorized_slot_count: 1,
            external_roster_commitment_hex: None,
            eligibility_state: "ENROLLMENT_OPEN".to_owned(),
            created_at_ms: 1,
        })
        .unwrap_or_else(|_| panic!("draft"));
    let slot_id = storage
        .create_slots(election_id, 1, 1)
        .unwrap_or_else(|_| panic!("slot"))[0]
        .clone();
    let verifier = format!("verifier-{election_id}");
    let invitation_id = format!("invitation-{election_id}");
    storage
        .insert_invitation(crate::storage::InvitationRecord {
            invitation_id: invitation_id.clone(),
            slot_id: slot_id.clone(),
            election_id: election_id.to_owned(),
            verifier_hex: verifier.clone(),
            state: "ACTIVE".to_owned(),
            created_at_ms: 1,
        })
        .unwrap_or_else(|_| panic!("invitation"));
    (slot_id, verifier, invitation_id)
}

fn assert_sqlite_enrollment_rolled_back(
    storage: &crate::SqliteStorage,
    election_id: &str,
    verifier: &str,
    public_key: &str,
) {
    let invitation = storage
        .get_invitation_by_verifier(verifier)
        .unwrap_or_else(|_| panic!("invitation lookup"))
        .unwrap_or_else(|| panic!("invitation exists"));
    assert_eq!(
        invitation.state, "ACTIVE",
        "invitation must roll back to ACTIVE"
    );
    let slots = storage
        .list_slots(election_id)
        .unwrap_or_else(|_| panic!("slots"));
    assert_eq!(slots.len(), 1);
    assert!(!slots[0].consumed, "slot must roll back to unconsumed");
    assert!(
        storage
            .get_enrolled_credential_by_key(election_id, public_key)
            .unwrap_or_else(|_| panic!("credential lookup"))
            .is_none(),
        "credential must be absent after rollback"
    );
}

#[test]
fn sqlite_enrollment_failure_injection_rolls_back_every_mutation() {
    for failpoint in [
        EnrollmentFailpoint::AfterInvitationMutation,
        EnrollmentFailpoint::AfterSlotMutation,
        EnrollmentFailpoint::BeforeCredentialInsertion,
    ] {
        let dir = std::env::temp_dir().join(format!(
            "pb-hosted-enrollment-fail-{}-{:?}",
            std::process::id(),
            failpoint
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let db = dir.join("enrollment.db");
        {
            let storage = crate::SqliteStorage::open(&db).unwrap_or_else(|_| panic!("open"));
            let election_id = "rollback-election";
            let (_slot_id, verifier, _invitation_id) =
                seed_sqlite_enrollment(&storage, election_id);
            let public_key = "test-public-key";
            storage.set_enrollment_failpoint(failpoint);
            assert_eq!(
                storage.complete_enrollment(election_id, &verifier, public_key, 2),
                Err(crate::storage::StorageError::Db)
            );
            assert_sqlite_enrollment_rolled_back(&storage, election_id, &verifier, public_key);
            storage.set_enrollment_failpoint(EnrollmentFailpoint::None);
            assert!(
                matches!(
                    storage.complete_enrollment(election_id, &verifier, public_key, 3),
                    Ok(crate::storage::EnrollmentCompletion::Created(_))
                ),
                "retry must succeed after rollback at {failpoint:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn sqlite_enrollment_rollback_survives_database_reopen() {
    let dir = std::env::temp_dir().join(format!(
        "pb-hosted-enrollment-reopen-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let db = dir.join("enrollment.db");
    let election_id = "restart-rollback-election";
    let verifier;
    let public_key = "restart-public-key";
    {
        let storage = crate::SqliteStorage::open(&db).unwrap_or_else(|_| panic!("open"));
        let (_slot_id, stored_verifier, _invitation_id) =
            seed_sqlite_enrollment(&storage, election_id);
        verifier = stored_verifier;
        storage.set_enrollment_failpoint(EnrollmentFailpoint::AfterSlotMutation);
        assert_eq!(
            storage.complete_enrollment(election_id, &verifier, public_key, 2),
            Err(crate::storage::StorageError::Db)
        );
    }
    {
        let storage = crate::SqliteStorage::open(&db).unwrap_or_else(|_| panic!("reopen"));
        assert_sqlite_enrollment_rolled_back(&storage, election_id, &verifier, public_key);
        assert!(
            matches!(
                storage.complete_enrollment(election_id, &verifier, public_key, 3),
                Ok(crate::storage::EnrollmentCompletion::Created(_))
            ),
            "exact retry must succeed after database reopen"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn storage_and_config_boundaries() {
    let storage = InMemoryStorage::new();
    storage.append_ballot_envelope("e1", vec![1, 2, 3]);
    assert_eq!(storage.ballot_envelope_count("e1"), 1);
    assert_eq!(crate::DEFAULT_BIND, "127.0.0.1:8788");
    assert_eq!(crate::DEFAULT_ADMIN_BIND, "127.0.0.1:8789");
    let cfg = HostedConfig {
        bind: "0.0.0.0:8788".to_owned(),
        admin_bind: "127.0.0.1:8789".to_owned(),
        service_name: "x".to_owned(),
        api_version: "v1".to_owned(),
        db_path: std::path::PathBuf::from("x.db"),
        admin_token: None,
        origin_token: None,
        allow_public_bind: false,
        rate_limit_per_minute: 10,
        organizer_max_slots: 10,
        transport_authority_root: test_transport_root(),
        transport_environment: "test".to_owned(),
        authority_signing_key: None,
    };
    assert!(cfg.validate().is_err());
    let cfg = HostedConfig {
        bind: "127.0.0.1:8788".to_owned(),
        admin_bind: "0.0.0.0:8789".to_owned(),
        service_name: "x".to_owned(),
        api_version: "v1".to_owned(),
        db_path: std::path::PathBuf::from("x.db"),
        admin_token: None,
        origin_token: None,
        allow_public_bind: true,
        rate_limit_per_minute: 10,
        organizer_max_slots: 10,
        transport_authority_root: test_transport_root(),
        transport_environment: "test".to_owned(),
        authority_signing_key: None,
    };
    assert!(
        cfg.validate().is_err(),
        "admin bind must stay loopback even with public bind allowed"
    );
    let cfg = HostedConfig {
        bind: "127.0.0.1:8788".to_owned(),
        admin_bind: "127.0.0.1:8788".to_owned(),
        service_name: "x".to_owned(),
        api_version: "v1".to_owned(),
        db_path: std::path::PathBuf::from("x.db"),
        admin_token: None,
        origin_token: None,
        allow_public_bind: false,
        rate_limit_per_minute: 10,
        organizer_max_slots: 10,
        transport_authority_root: test_transport_root(),
        transport_environment: "test".to_owned(),
        authority_signing_key: None,
    };
    assert!(
        cfg.validate().is_err(),
        "public and admin binds must differ"
    );
}

#[tokio::test]
async fn public_plane_never_serves_admin_mutations() {
    let f = fixture();
    let (routers, _storage) = test_routers();
    // Admin import succeeds only on the admin plane.
    assert_eq!(
        import(routers.admin.clone(), &f).await,
        axum::http::StatusCode::CREATED
    );
    // The public plane has no admin routes at all: import, close, finalize
    // all 404 even with a valid admin token (edge failure fails closed).
    let body = serde_json::json!({"election_id": f.election_id, "manifest_cbor_hex": hex_encode(&f.manifest_cbor), "registry_cbor_hex": hex_encode(&f.registry_cbor), "candidate_cbor_hex": hex_encode(&f.candidate_cbor)}).to_string();
    let (s1, _) = req(
        routers.public.clone(),
        "POST",
        "/api/v1/admin/elections/import",
        Some(body),
        &[
            ("content-type", "application/json"),
            ("x-admin-token", "test-admin-token"),
        ],
    )
    .await;
    assert_eq!(s1, axum::http::StatusCode::NOT_FOUND);
    let (s2, _) = req(
        routers.public.clone(),
        "POST",
        &format!("/api/v1/admin/elections/{}/close", f.election_id),
        None,
        &[("x-admin-token", "test-admin-token")],
    )
    .await;
    assert_eq!(s2, axum::http::StatusCode::NOT_FOUND);
    let (s3, _) = req(
        routers.public.clone(),
        "POST",
        &format!("/api/v1/admin/elections/{}/finalize", f.election_id),
        None,
        &[("x-admin-token", "test-admin-token")],
    )
    .await;
    assert_eq!(s3, axum::http::StatusCode::NOT_FOUND);
    // The admin plane does not serve voter routes.
    let (s4, _) = req(routers.admin.clone(), "GET", "/api/v1/status", None, &[]).await;
    assert_eq!(s4, axum::http::StatusCode::NOT_FOUND);
    let (s5, _) = req(
        routers.admin.clone(),
        "POST",
        &format!("/api/v1/elections/{}/ballots", f.election_id),
        Some(
            serde_json::json!({"receipt_id": "r", "package_cbor_hex": "00", "api_version": "v1"})
                .to_string(),
        ),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(s5, axum::http::StatusCode::NOT_FOUND);
    // Admin plane health is separate from public health.
    let (s6, _) = req(routers.admin.clone(), "GET", "/admin-health", None, &[]).await;
    assert_eq!(s6, axum::http::StatusCode::OK);
    // Public plane health still works.
    let (s7, _) = req(routers.public.clone(), "GET", "/health", None, &[]).await;
    assert_eq!(s7, axum::http::StatusCode::OK);
}

#[tokio::test]
async fn admin_plane_requires_token_when_configured() {
    let f = fixture();
    let (routers, _storage) = test_routers();
    let body = serde_json::json!({"election_id": f.election_id, "manifest_cbor_hex": hex_encode(&f.manifest_cbor), "registry_cbor_hex": hex_encode(&f.registry_cbor), "candidate_cbor_hex": hex_encode(&f.candidate_cbor)}).to_string();
    let (s1, _) = req(
        routers.admin.clone(),
        "POST",
        "/api/v1/admin/elections/import",
        Some(body.clone()),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(s1, axum::http::StatusCode::UNAUTHORIZED);
    let (s2, _) = req(
        routers.admin.clone(),
        "POST",
        "/api/v1/admin/elections/import",
        Some(body.clone()),
        &[
            ("content-type", "application/json"),
            ("x-admin-token", "wrong-token"),
        ],
    )
    .await;
    assert_eq!(s2, axum::http::StatusCode::UNAUTHORIZED);
    let (s3, _) = req(
        routers.admin.clone(),
        "POST",
        "/api/v1/admin/elections/import",
        Some(body),
        &[
            ("content-type", "application/json"),
            ("x-admin-token", "test-admin-token"),
        ],
    )
    .await;
    assert_eq!(s3, axum::http::StatusCode::CREATED);
}

#[tokio::test]
async fn origin_token_enforced_on_public_plane_when_configured() {
    let storage = Arc::new(InMemoryStorage::new());
    let mut cfg = test_config();
    cfg.origin_token = Some("test-origin-secret".to_owned());
    let state = Arc::new(AppState::new(cfg, storage));
    let router = router_with_state(state);
    // /health stays exempt (Tunnel health checks hit the origin directly).
    let (s1, _) = req(router.clone(), "GET", "/health", None, &[]).await;
    assert_eq!(s1, axum::http::StatusCode::OK);
    // API without the Worker-injected header fails closed.
    let (s2, _) = req(router.clone(), "GET", "/api/v1/status", None, &[]).await;
    assert_eq!(s2, axum::http::StatusCode::UNAUTHORIZED);
    let (s3, _) = req(
        router.clone(),
        "GET",
        "/api/v1/status",
        None,
        &[(ORIGIN_TOKEN_HEADER, "wrong")],
    )
    .await;
    assert_eq!(s3, axum::http::StatusCode::UNAUTHORIZED);
    // API with the correct header passes.
    let (s4, _) = req(
        router.clone(),
        "GET",
        "/api/v1/status",
        None,
        &[(ORIGIN_TOKEN_HEADER, "test-origin-secret")],
    )
    .await;
    assert_eq!(s4, axum::http::StatusCode::OK);
}

#[tokio::test]
async fn health_status_and_no_secret_echo() {
    let (router, _) = test_router();
    let (s, b) = req(router.clone(), "GET", "/health", None, &[]).await;
    assert_eq!(s, axum::http::StatusCode::OK, "{b}");
    let (s2, b2) = req(router.clone(), "GET", "/api/v1/status", None, &[]).await;
    assert_eq!(s2, axum::http::StatusCode::OK, "{b2}");
    // Error responses must not echo submitted package bytes / secret-looking fields
    let (s3, b3) = req(router.clone(), "POST", "/api/v1/elections/x/ballots", Some(serde_json::json!({"receipt_id":"r","package_cbor_hex":"deadbeef","api_version":"v1","secret":"supersecretvalue"}).to_string()), &[("content-type", "application/json")]).await;
    assert!(
        !b3.contains("supersecretvalue"),
        "error must not echo secret: {b3}"
    );
    assert!(
        !b3.contains("deadbeef"),
        "error must not echo package: {b3}"
    );
    assert_eq!(s3, axum::http::StatusCode::NOT_FOUND);
}

// ── Enrollment tests ──────────────────────────────────────────────────────────

fn enroll_key(scalar: u64) -> String {
    hex_encode(&point_bytes(scalar))
}

async fn create_draft_and_open_enrollment(
    admin: &axum::Router,
    election_id: &str,
    candidate_cbor: &[u8],
    slot_count: i64,
) {
    let body = serde_json::json!({
        "election_id": election_id,
        "candidate_cbor_hex": hex_encode(candidate_cbor),
        "proof_suite_id": TARI_TRIPTYCH_PROOF_SUITE_ID_V1,
        "min_approvals": 1,
        "max_approvals": 1,
        "allow_abstention": false,
        "governance_revision": "test-rev-001",
        "authorized_slot_count": slot_count,
    })
    .to_string();
    let (s, t) = req(
        admin.clone(),
        "POST",
        "/api/v1/admin/elections/draft",
        Some(body),
        &[
            ("content-type", "application/json"),
            ("x-admin-token", "test-admin-token"),
        ],
    )
    .await;
    assert_eq!(s, axum::http::StatusCode::CREATED, "create_draft: {t}");
    let (s2, t2) = req(
        admin.clone(),
        "POST",
        &format!("/api/v1/admin/elections/{election_id}/open-enrollment"),
        None,
        &[("x-admin-token", "test-admin-token")],
    )
    .await;
    assert_eq!(s2, axum::http::StatusCode::OK, "open_enrollment: {t2}");
}

async fn issue_invitation_for_slot(
    admin: &axum::Router,
    election_id: &str,
    slot_id: &str,
) -> String {
    let body = serde_json::json!({"slot_id": slot_id}).to_string();
    let (s, t) = req(
        admin.clone(),
        "POST",
        &format!("/api/v1/admin/elections/{election_id}/invitations"),
        Some(body),
        &[
            ("content-type", "application/json"),
            ("x-admin-token", "test-admin-token"),
        ],
    )
    .await;
    assert_eq!(s, axum::http::StatusCode::CREATED, "issue_invitation: {t}");
    let v: serde_json::Value = serde_json::from_str(&t).unwrap();
    v["invitation_secret_hex"].as_str().unwrap().to_owned()
}

async fn enroll(
    public: &axum::Router,
    election_id: &str,
    invitation_secret_hex: &str,
    public_key_hex: &str,
) -> (axum::http::StatusCode, serde_json::Value) {
    let body = serde_json::json!({"invitation_secret_hex": invitation_secret_hex, "public_key_hex": public_key_hex}).to_string();
    let (s, t) = req(
        public.clone(),
        "POST",
        &format!("/api/v1/elections/{election_id}/enroll"),
        Some(body),
        &[("content-type", "application/json")],
    )
    .await;
    let v: serde_json::Value =
        serde_json::from_str(&t).unwrap_or_else(|_| serde_json::json!({"raw": t}));
    (s, v)
}

#[tokio::test]
async fn enrollment_happy_path_and_voting() {
    let f = fixture();
    let (routers, storage) = test_routers();
    let admin = routers.admin.clone();
    let public = routers.public.clone();
    let election_id = "enroll-happy-001";

    create_draft_and_open_enrollment(&admin, election_id, &f.candidate_cbor, 3).await;

    // List slots to get slot IDs
    let slots = storage.list_slots(election_id).unwrap();
    assert_eq!(slots.len(), 3);
    let slot_a = &slots[0].slot_id;
    let slot_b = &slots[1].slot_id;

    // Issue invitations
    let secret_a = issue_invitation_for_slot(&admin, election_id, slot_a).await;
    let secret_b = issue_invitation_for_slot(&admin, election_id, slot_b).await;

    // Enroll voter A
    let key_a = enroll_key(1);
    let (s1, v1) = enroll(&public, election_id, &secret_a, &key_a).await;
    assert_eq!(s1, axum::http::StatusCode::CREATED, "{v1}");
    assert_eq!(v1["idempotent"], false);

    // Case A: same invitation + same key = idempotent retry
    let (s2, v2) = enroll(&public, election_id, &secret_a, &key_a).await;
    assert_eq!(s2, axum::http::StatusCode::OK, "Case A: {v2}");
    assert_eq!(v2["idempotent"], true);

    // Enroll voter B
    let key_b = enroll_key(2);
    let (s3, v3) = enroll(&public, election_id, &secret_b, &key_b).await;
    assert_eq!(s3, axum::http::StatusCode::CREATED, "{v3}");

    // Check enrollment status
    let (ss, sb) = req(
        admin.clone(),
        "GET",
        &format!("/api/v1/admin/elections/{election_id}/enrollment"),
        None,
        &[("x-admin-token", "test-admin-token")],
    )
    .await;
    assert_eq!(ss, axum::http::StatusCode::OK, "{sb}");
    let status_v: serde_json::Value = serde_json::from_str(&sb).unwrap();
    assert_eq!(status_v["enrolled_count"], 2);
    assert_eq!(status_v["eligibility_state"], "ENROLLMENT_OPEN");

    // Freeze registry
    let (sf, tf) = req(
        admin.clone(),
        "POST",
        &format!("/api/v1/admin/elections/{election_id}/freeze"),
        None,
        &[("x-admin-token", "test-admin-token")],
    )
    .await;
    assert_eq!(sf, axum::http::StatusCode::OK, "{tf}");
    let freeze_v: serde_json::Value = serde_json::from_str(&tf).unwrap();
    assert_eq!(freeze_v["enrolled_count"], 2);
    assert!(freeze_v["registry_commitment_hex"].as_str().unwrap().len() == 64);

    // Open voting
    let (sv, tv) = req(
        admin.clone(),
        "POST",
        &format!("/api/v1/admin/elections/{election_id}/open-voting"),
        None,
        &[("x-admin-token", "test-admin-token")],
    )
    .await;
    assert_eq!(sv, axum::http::StatusCode::CREATED, "{tv}");
    let voting_v: serde_json::Value = serde_json::from_str(&tv).unwrap();
    assert_eq!(voting_v["state"], "open");

    // Verify enrollment is closed after freeze
    let (se, te) = enroll(&public, election_id, &secret_b, &key_b).await;
    assert_eq!(
        se,
        axum::http::StatusCode::CONFLICT,
        "enrollment after freeze should fail: {te}"
    );

    // Verify linkage scrubbed: slot_id and invitation_id removed from credentials
    let creds = storage.list_enrolled_credentials(election_id).unwrap();
    assert_eq!(creds.len(), 2);
    for c in &creds {
        assert!(
            c.slot_id.is_none(),
            "slot_id should be scrubbed after freeze"
        );
        assert!(
            c.invitation_id.is_none(),
            "invitation_id should be scrubbed after freeze"
        );
    }
}

#[tokio::test]
async fn enrollment_idempotency_case_b_different_key() {
    let f = fixture();
    let (routers, storage) = test_routers();
    let election_id = "enroll-case-b";
    create_draft_and_open_enrollment(&routers.admin, election_id, &f.candidate_cbor, 2).await;
    let slots = storage.list_slots(election_id).unwrap();
    let secret = issue_invitation_for_slot(&routers.admin, election_id, &slots[0].slot_id).await;
    // Enroll key 1
    let (s1, _) = enroll(&routers.public, election_id, &secret, &enroll_key(1)).await;
    assert_eq!(s1, axum::http::StatusCode::CREATED);
    // Case B: same invitation + different key
    let (s2, v2) = enroll(&routers.public, election_id, &secret, &enroll_key(2)).await;
    assert_eq!(s2, axum::http::StatusCode::CONFLICT, "Case B: {v2}");
    assert!(
        v2["code"]
            .as_str()
            .unwrap_or("")
            .contains("credential_conflict"),
        "{v2}"
    );
    // Slot was consumed only once
    let slots2 = storage.list_slots(election_id).unwrap();
    assert_eq!(slots2.iter().filter(|s| s.consumed).count(), 1);
}

#[tokio::test]
async fn enrollment_idempotency_case_c_duplicate_key_different_invitation() {
    let f = fixture();
    let (routers, storage) = test_routers();
    let election_id = "enroll-case-c";
    create_draft_and_open_enrollment(&routers.admin, election_id, &f.candidate_cbor, 2).await;
    let slots = storage.list_slots(election_id).unwrap();
    let secret1 = issue_invitation_for_slot(&routers.admin, election_id, &slots[0].slot_id).await;
    let secret2 = issue_invitation_for_slot(&routers.admin, election_id, &slots[1].slot_id).await;
    // Enroll key 1 with invitation 1
    let key = enroll_key(1);
    let (s1, _) = enroll(&routers.public, election_id, &secret1, &key).await;
    assert_eq!(s1, axum::http::StatusCode::CREATED);
    // Case C: different invitation, same public key → reject WITHOUT consuming second invitation
    let (s2, v2) = enroll(&routers.public, election_id, &secret2, &key).await;
    assert_eq!(s2, axum::http::StatusCode::CONFLICT, "Case C: {v2}");
    // Second invitation must NOT be consumed (slot 2 still ACTIVE)
    let invs = storage.list_slots(election_id).unwrap();
    // slot 0 consumed (from first enrollment), slot 1 NOT consumed
    let consumed_count = invs.iter().filter(|s| s.consumed).count();
    assert_eq!(
        consumed_count, 1,
        "second slot must not be consumed in Case C"
    );
    // Second invitation still ACTIVE - verify by trying to enroll with it successfully for a different key
    let key2 = enroll_key(2);
    let (s3, _) = enroll(&routers.public, election_id, &secret2, &key2).await;
    assert_eq!(
        s3,
        axum::http::StatusCode::CREATED,
        "second slot should still be enrollable after Case C rejection"
    );
}

#[tokio::test]
async fn cross_device_duplicate_vote_rejected() {
    // After enrollment and open-voting, the same credential from two "devices"
    // (same secret key) produces the same nullifier → second ballot is rejected.
    let f = fixture();
    let (routers, storage) = test_routers();
    let election_id = "enroll-dup-vote";
    create_draft_and_open_enrollment(&routers.admin, election_id, &f.candidate_cbor, 1).await;
    let slots = storage.list_slots(election_id).unwrap();
    let secret = issue_invitation_for_slot(&routers.admin, election_id, &slots[0].slot_id).await;
    let pub_key = enroll_key(1);
    let (s1, _) = enroll(&routers.public, election_id, &secret, &pub_key).await;
    assert_eq!(s1, axum::http::StatusCode::CREATED);
    // Freeze and open voting
    let (sf, tf) = req(
        routers.admin.clone(),
        "POST",
        &format!("/api/v1/admin/elections/{election_id}/freeze"),
        None,
        &[("x-admin-token", "test-admin-token")],
    )
    .await;
    assert_eq!(sf, axum::http::StatusCode::OK, "{tf}");
    let (sv, tv) = req(
        routers.admin.clone(),
        "POST",
        &format!("/api/v1/admin/elections/{election_id}/open-voting"),
        None,
        &[("x-admin-token", "test-admin-token")],
    )
    .await;
    assert_eq!(sv, axum::http::StatusCode::CREATED, "{tv}");
    // Now build the manifest from open-voting response to create a ballot
    // The election was opened with key 1 as the only enrolled credential.
    // Build a ballot using the same election id.
    let loaded_election = storage.get_election(election_id).unwrap().unwrap();
    let manifest = ElectionManifest::from_canonical_cbor(&loaded_election.manifest_cbor).unwrap();
    let candidates = CandidateSet::from_canonical_cbor(&loaded_election.candidate_cbor).unwrap();
    let registry = tari_cc_private_ballot_registry::RegistrySnapshot::from_canonical_cbor(
        &loaded_election.registry_cbor,
    )
    .unwrap();
    let p = Blake3HashProviderV1;
    let payload = ApprovalBallotPayload::new(
        vec![candidate_id(b"candidate-a")],
        &candidates,
        manifest.approval_limits(),
    )
    .unwrap();
    let verifier = build_tari_triptych_verifier_from_registry_v1(&registry, &p).unwrap();
    let statement = tari_cc_private_ballot_verifier::reconstruct_approval_proof_statement(
        &manifest, &payload, &p,
    )
    .unwrap();
    let secret_key = secret_scalar(1);
    let proof = prove_tari_triptych_prototype_v1(&statement, &verifier, &secret_key).unwrap();
    let mh = manifest.canonical_hash(&p).unwrap();
    let pkg = BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash: mh,
        proof_suite_id: manifest.proof_suite_id().to_owned(),
        proof,
        payload: payload.clone(),
    })
    .unwrap();
    let pkg_bytes = pkg.to_canonical_cbor().unwrap();
    // "Device 1" submits ballot
    let body1 = serde_json::json!({"receipt_id": "device1-receipt-001", "package_cbor_hex": hex_encode(&pkg_bytes), "api_version": "v1"}).to_string();
    let (sa, _) = req(
        routers.public.clone(),
        "POST",
        &format!("/api/v1/elections/{election_id}/ballots"),
        Some(body1),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(
        sa,
        axum::http::StatusCode::CREATED,
        "first ballot should be accepted"
    );
    // "Device 2" submits the same proof (same nullifier, same credential, same election)
    let proof2 = prove_tari_triptych_prototype_v1(&statement, &verifier, &secret_key).unwrap();
    let pkg2 = BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash: manifest.canonical_hash(&p).unwrap(),
        proof_suite_id: manifest.proof_suite_id().to_owned(),
        proof: proof2,
        payload,
    })
    .unwrap();
    let pkg2_bytes = pkg2.to_canonical_cbor().unwrap();
    let body2 = serde_json::json!({"receipt_id": "device2-receipt-002", "package_cbor_hex": hex_encode(&pkg2_bytes), "api_version": "v1"}).to_string();
    let (sb, rb) = req(
        routers.public.clone(),
        "POST",
        &format!("/api/v1/elections/{election_id}/ballots"),
        Some(body2),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(
        sb,
        axum::http::StatusCode::CONFLICT,
        "cross-device duplicate vote must be rejected: {rb}"
    );
    assert!(
        rb.contains("duplicate_nullifier"),
        "must report duplicate_nullifier: {rb}"
    );
}

#[tokio::test]
async fn freeze_immutability_no_enrollment_after_freeze() {
    let f = fixture();
    let (routers, storage) = test_routers();
    let election_id = "enroll-freeze-immut";
    create_draft_and_open_enrollment(&routers.admin, election_id, &f.candidate_cbor, 2).await;
    let slots = storage.list_slots(election_id).unwrap();
    // Issue invitation for slot[1] BEFORE freeze so we can try to enroll with it after.
    let secret_slot1 =
        issue_invitation_for_slot(&routers.admin, election_id, &slots[0].slot_id).await;
    let secret_slot2_pre =
        issue_invitation_for_slot(&routers.admin, election_id, &slots[1].slot_id).await;
    let (s1, _) = enroll(&routers.public, election_id, &secret_slot1, &enroll_key(1)).await;
    assert_eq!(s1, axum::http::StatusCode::CREATED);
    // Freeze
    let (sf, tf) = req(
        routers.admin.clone(),
        "POST",
        &format!("/api/v1/admin/elections/{election_id}/freeze"),
        None,
        &[("x-admin-token", "test-admin-token")],
    )
    .await;
    assert_eq!(sf, axum::http::StatusCode::OK, "{tf}");
    // Double-freeze must fail
    let (sf2, tf2) = req(
        routers.admin.clone(),
        "POST",
        &format!("/api/v1/admin/elections/{election_id}/freeze"),
        None,
        &[("x-admin-token", "test-admin-token")],
    )
    .await;
    assert_eq!(
        sf2,
        axum::http::StatusCode::CONFLICT,
        "double-freeze: {tf2}"
    );
    // Issuing a NEW invitation after freeze must fail (state is REGISTRY_FROZEN)
    let (si, ti) = req(
        routers.admin.clone(),
        "POST",
        &format!("/api/v1/admin/elections/{election_id}/invitations"),
        Some(serde_json::json!({"slot_id": &slots[1].slot_id}).to_string()),
        &[
            ("content-type", "application/json"),
            ("x-admin-token", "test-admin-token"),
        ],
    )
    .await;
    assert_eq!(
        si,
        axum::http::StatusCode::CONFLICT,
        "post-freeze invitation issue should fail: {ti}"
    );
    // Enrolling with an invitation issued BEFORE freeze must also fail (state is REGISTRY_FROZEN)
    let (se, te) = enroll(
        &routers.public,
        election_id,
        &secret_slot2_pre,
        &enroll_key(2),
    )
    .await;
    assert_eq!(
        se,
        axum::http::StatusCode::CONFLICT,
        "enrollment after freeze with pre-freeze invitation: {te}"
    );
}

#[tokio::test]
async fn invitation_secret_never_stored_server_side() {
    // The server must never store the invitation plaintext in any storage field.
    let f = fixture();
    let (routers, storage) = test_routers();
    let election_id = "enroll-secret-storage";
    create_draft_and_open_enrollment(&routers.admin, election_id, &f.candidate_cbor, 1).await;
    let slots = storage.list_slots(election_id).unwrap();
    let slot_id = &slots[0].slot_id;
    // Issue an invitation and get the plaintext secret
    let body = serde_json::json!({"slot_id": slot_id}).to_string();
    let (_, t) = req(
        routers.admin.clone(),
        "POST",
        &format!("/api/v1/admin/elections/{election_id}/invitations"),
        Some(body),
        &[
            ("content-type", "application/json"),
            ("x-admin-token", "test-admin-token"),
        ],
    )
    .await;
    let v: serde_json::Value = serde_json::from_str(&t).unwrap();
    let secret_hex = v["invitation_secret_hex"].as_str().unwrap().to_owned();
    // Retrieve the stored invitation record
    let invitation = storage
        .get_active_invitation_for_slot(slot_id)
        .unwrap()
        .unwrap();
    // The stored verifier must NOT equal the secret
    assert_ne!(
        invitation.verifier_hex, secret_hex,
        "invitation plaintext must not be stored as verifier"
    );
    // The stored verifier must equal the computed verifier from the secret
    let secret_bytes = crate::hex_decode(&secret_hex).unwrap();
    let computed_verifier = crate::invitation_verifier(&secret_bytes);
    assert_eq!(
        invitation.verifier_hex, computed_verifier,
        "stored verifier must match computed verifier"
    );
    // The raw secret must have 256 bits of entropy (64 hex chars = 32 bytes)
    assert_eq!(
        secret_hex.len(),
        64,
        "invitation secret must be 32 bytes (64 hex chars)"
    );
}

#[tokio::test]
async fn void_and_reissue_invitation() {
    let f = fixture();
    let (routers, storage) = test_routers();
    let election_id = "enroll-void-reissue";
    create_draft_and_open_enrollment(&routers.admin, election_id, &f.candidate_cbor, 1).await;
    let slots = storage.list_slots(election_id).unwrap();
    let slot_id = &slots[0].slot_id;
    let secret1 = issue_invitation_for_slot(&routers.admin, election_id, slot_id).await;
    // Void the invitation
    let inv = storage
        .get_active_invitation_for_slot(slot_id)
        .unwrap()
        .unwrap();
    let (sv, tv) = req(
        routers.admin.clone(),
        "POST",
        &format!(
            "/api/v1/admin/elections/{election_id}/invitations/{}/void",
            inv.invitation_id
        ),
        None,
        &[("x-admin-token", "test-admin-token")],
    )
    .await;
    assert_eq!(sv, axum::http::StatusCode::OK, "{tv}");
    // Voided secret can no longer enroll
    let (se, te) = enroll(&routers.public, election_id, &secret1, &enroll_key(1)).await;
    assert_eq!(
        se,
        axum::http::StatusCode::UNAUTHORIZED,
        "voided invitation: {te}"
    );
    // Reissue: issue a new invitation for the same slot
    let secret2 = issue_invitation_for_slot(&routers.admin, election_id, slot_id).await;
    assert_ne!(secret1, secret2, "reissued secret must differ");
    // New secret can enroll
    let (sn, tn) = enroll(&routers.public, election_id, &secret2, &enroll_key(1)).await;
    assert_eq!(
        sn,
        axum::http::StatusCode::CREATED,
        "reissued enrollment: {tn}"
    );
}

// ── Additional spec-required security invariant tests ─────────────────────────

#[tokio::test]
async fn wrong_election_invitation_rejected() {
    // An invitation for election A used in election B must be rejected.
    let f = fixture();
    let (routers, storage) = test_routers();
    let election_a = "enroll-wrong-election-a";
    let election_b = "enroll-wrong-election-b";
    create_draft_and_open_enrollment(&routers.admin, election_a, &f.candidate_cbor, 1).await;
    create_draft_and_open_enrollment(&routers.admin, election_b, &f.candidate_cbor, 1).await;
    let slots_a = storage.list_slots(election_a).unwrap();
    let secret_a = issue_invitation_for_slot(&routers.admin, election_a, &slots_a[0].slot_id).await;
    // Use invitation from election A in election B → must fail with 401
    let (s, v) = enroll(&routers.public, election_b, &secret_a, &enroll_key(1)).await;
    assert_eq!(
        s,
        axum::http::StatusCode::UNAUTHORIZED,
        "wrong-election invitation must be rejected: {v}"
    );
    // The same secret is valid in its own election A
    let (s2, v2) = enroll(&routers.public, election_a, &secret_a, &enroll_key(1)).await;
    assert_eq!(
        s2,
        axum::http::StatusCode::CREATED,
        "own-election invitation must succeed: {v2}"
    );
}

#[test]
fn deterministic_registry_commitment_and_domain_separation() {
    use tari_cc_private_ballot_protocol::Blake3HashProviderV1;
    use tari_cc_private_ballot_registry::{
        GovernancePublicKey, RegistryEntry, RegistrySnapshot, VoterGovernanceKeyRegistrationV1,
        VoterKeyProvisioningV1,
    };
    let p = Blake3HashProviderV1;
    let key1 = point_bytes(1).to_vec();
    let key2 = point_bytes(2).to_vec();
    let key3 = point_bytes(3).to_vec();
    let make_entry = |k: Vec<u8>| {
        let gk = GovernancePublicKey::new(k).expect("gk");
        let reg =
            VoterGovernanceKeyRegistrationV1::new(gk, VoterKeyProvisioningV1::GeneratedByVoter);
        RegistryEntry::from_voter_registration(reg)
    };
    let entries1 = vec![make_entry(key1.clone()), make_entry(key2.clone())];
    let entries2 = vec![make_entry(key1.clone()), make_entry(key2.clone())];
    let snap1 = RegistrySnapshot::new(entries1).expect("snap1");
    let snap2 = RegistrySnapshot::new(entries2).expect("snap2");
    let commit1a = snap1.canonical_commitment(&p).expect("c1a");
    let commit1b = snap1.canonical_commitment(&p).expect("c1b");
    let commit2 = snap2.canonical_commitment(&p).expect("c2");
    // Same inputs → same commitment (deterministic)
    assert_eq!(
        commit1a.as_bytes(),
        commit1b.as_bytes(),
        "commitment must be deterministic"
    );
    assert_eq!(
        commit1a.as_bytes(),
        commit2.as_bytes(),
        "same entries → same commitment"
    );
    // Different entries → different commitment
    let entries3 = vec![make_entry(key1.clone()), make_entry(key3.clone())];
    let snap3 = RegistrySnapshot::new(entries3).expect("snap3");
    let commit3 = snap3.canonical_commitment(&p).expect("c3");
    assert_ne!(
        commit1a.as_bytes(),
        commit3.as_bytes(),
        "different entries → different commitment"
    );
    // Single entry → different from two-entry
    let entries4 = vec![make_entry(key1.clone())];
    let snap4 = RegistrySnapshot::new(entries4).expect("snap4");
    let commit4 = snap4.canonical_commitment(&p).expect("c4");
    assert_ne!(
        commit1a.as_bytes(),
        commit4.as_bytes(),
        "different count → different commitment"
    );
    // Domain separation: commitment must differ from raw BLAKE3 of the registry CBOR bytes
    let cbor1 = snap1.to_canonical_cbor().expect("cbor");
    let raw_hash = {
        use tari_cc_private_ballot_protocol::HashProvider;
        p.hash(&cbor1)
    };
    assert_ne!(
        commit1a.as_bytes(),
        &raw_hash,
        "commitment must use domain separation, not raw BLAKE3"
    );
}

#[tokio::test]
async fn voting_before_election_opened_is_rejected() {
    // Ballot submission to an election in ENROLLMENT_OPEN or REGISTRY_FROZEN
    // state must fail because the election record doesn't exist yet in the
    // elections table (created only by admin_open_voting).
    let f = fixture();
    let (routers, storage) = test_routers();
    let election_id = "enroll-vote-before-open";
    create_draft_and_open_enrollment(&routers.admin, election_id, &f.candidate_cbor, 1).await;
    let slots = storage.list_slots(election_id).unwrap();
    let secret = issue_invitation_for_slot(&routers.admin, election_id, &slots[0].slot_id).await;
    let (s1, _) = enroll(&routers.public, election_id, &secret, &enroll_key(1)).await;
    assert_eq!(s1, axum::http::StatusCode::CREATED);
    // Before freeze: no election record → 404
    let pkg = serde_json::json!({"receipt_id": "test-r-001", "package_cbor_hex": "0000", "api_version": "v1"}).to_string();
    let (sv1, tv1) = req(
        routers.public.clone(),
        "POST",
        &format!("/api/v1/elections/{election_id}/ballots"),
        Some(pkg.clone()),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(
        sv1,
        axum::http::StatusCode::NOT_FOUND,
        "ballot before freeze must 404: {tv1}"
    );
    // Freeze but don't open voting: still 404
    let (sf, _) = req(
        routers.admin.clone(),
        "POST",
        &format!("/api/v1/admin/elections/{election_id}/freeze"),
        None,
        &[("x-admin-token", "test-admin-token")],
    )
    .await;
    assert_eq!(sf, axum::http::StatusCode::OK);
    let (sv2, tv2) = req(
        routers.public.clone(),
        "POST",
        &format!("/api/v1/elections/{election_id}/ballots"),
        Some(pkg),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(
        sv2,
        axum::http::StatusCode::NOT_FOUND,
        "ballot before open-voting must 404: {tv2}"
    );
}

#[tokio::test]
async fn unenrolled_credential_ballot_rejected() {
    // A ballot produced for a registry that doesn't match the enrolled registry
    // must be rejected (wrong manifest hash / wrong commitment).
    let f = fixture();
    let (routers, storage) = test_routers();
    let election_id = "enroll-unenrolled-reject";
    create_draft_and_open_enrollment(&routers.admin, election_id, &f.candidate_cbor, 1).await;
    let slots = storage.list_slots(election_id).unwrap();
    let secret = issue_invitation_for_slot(&routers.admin, election_id, &slots[0].slot_id).await;
    // Enroll only key 1 (scalar 1)
    let (s1, _) = enroll(&routers.public, election_id, &secret, &enroll_key(1)).await;
    assert_eq!(s1, axum::http::StatusCode::CREATED);
    let (sf, _) = req(
        routers.admin.clone(),
        "POST",
        &format!("/api/v1/admin/elections/{election_id}/freeze"),
        None,
        &[("x-admin-token", "test-admin-token")],
    )
    .await;
    assert_eq!(sf, axum::http::StatusCode::OK);
    let (sv, _) = req(
        routers.admin.clone(),
        "POST",
        &format!("/api/v1/admin/elections/{election_id}/open-voting"),
        None,
        &[("x-admin-token", "test-admin-token")],
    )
    .await;
    assert_eq!(sv, axum::http::StatusCode::CREATED);
    // Build a ballot using the FIXTURE registry (which has keys 1,2,3) for key 2.
    // The enrolled election uses a 1-entry registry for key 1 → different commitment →
    // different manifest hash → wrong_election rejection.
    let pkg_unenrolled = make_package(&f, 2, b"candidate-a"); // key 2 is in fixture but not enrolled
    let body = serde_json::json!({"receipt_id": "unenrolled-r-001", "package_cbor_hex": hex_encode(&pkg_unenrolled), "api_version": "v1"}).to_string();
    let (sr, tr) = req(
        routers.public.clone(),
        "POST",
        &format!("/api/v1/elections/{election_id}/ballots"),
        Some(body),
        &[("content-type", "application/json")],
    )
    .await;
    // The package is bound to a different manifest (different registry commitment) → wrong_election
    assert_eq!(
        sr,
        axum::http::StatusCode::UNPROCESSABLE_ENTITY,
        "unenrolled credential ballot must be rejected: {tr}"
    );
    assert!(
        tr.contains("wrong_election") || tr.contains("ballot_invalid"),
        "wrong rejection code: {tr}"
    );
    // Confirm the enrolled key CAN vote successfully
    let loaded_election = storage.get_election(election_id).unwrap().unwrap();
    let manifest = ElectionManifest::from_canonical_cbor(&loaded_election.manifest_cbor).unwrap();
    let candidates = CandidateSet::from_canonical_cbor(&loaded_election.candidate_cbor).unwrap();
    let registry = tari_cc_private_ballot_registry::RegistrySnapshot::from_canonical_cbor(
        &loaded_election.registry_cbor,
    )
    .unwrap();
    let p = Blake3HashProviderV1;
    let payload = ApprovalBallotPayload::new(
        vec![candidate_id(b"candidate-a")],
        &candidates,
        manifest.approval_limits(),
    )
    .unwrap();
    let verifier = build_tari_triptych_verifier_from_registry_v1(&registry, &p).unwrap();
    let statement = tari_cc_private_ballot_verifier::reconstruct_approval_proof_statement(
        &manifest, &payload, &p,
    )
    .unwrap();
    let proof = prove_tari_triptych_prototype_v1(&statement, &verifier, &secret_scalar(1)).unwrap();
    let mh = manifest.canonical_hash(&p).unwrap();
    let pkg_enrolled = BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash: mh,
        proof_suite_id: manifest.proof_suite_id().to_owned(),
        proof,
        payload,
    })
    .unwrap()
    .to_canonical_cbor()
    .unwrap();
    let body2 = serde_json::json!({"receipt_id": "enrolled-r-001", "package_cbor_hex": hex_encode(&pkg_enrolled), "api_version": "v1"}).to_string();
    let (sa, ta) = req(
        routers.public.clone(),
        "POST",
        &format!("/api/v1/elections/{election_id}/ballots"),
        Some(body2),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(
        sa,
        axum::http::StatusCode::CREATED,
        "enrolled key must vote successfully: {ta}"
    );
}

#[tokio::test]
async fn two_credentials_from_two_slots_can_both_vote() {
    // Two separate credentials from two separate slots may each cast one vote.
    // This is the explicit Sybil-boundary proof: ONE ENROLLED CREDENTIAL, ONE ACCEPTED VOTE.
    let f = fixture();
    let (routers, storage) = test_routers();
    let election_id = "enroll-two-slots-vote";
    create_draft_and_open_enrollment(&routers.admin, election_id, &f.candidate_cbor, 2).await;
    let slots = storage.list_slots(election_id).unwrap();
    let secret_a = issue_invitation_for_slot(&routers.admin, election_id, &slots[0].slot_id).await;
    let secret_b = issue_invitation_for_slot(&routers.admin, election_id, &slots[1].slot_id).await;
    // Enroll two distinct credentials
    let (s1, _) = enroll(&routers.public, election_id, &secret_a, &enroll_key(1)).await;
    assert_eq!(s1, axum::http::StatusCode::CREATED);
    let (s2, _) = enroll(&routers.public, election_id, &secret_b, &enroll_key(2)).await;
    assert_eq!(s2, axum::http::StatusCode::CREATED);
    // Freeze and open voting
    let (sf, _) = req(
        routers.admin.clone(),
        "POST",
        &format!("/api/v1/admin/elections/{election_id}/freeze"),
        None,
        &[("x-admin-token", "test-admin-token")],
    )
    .await;
    assert_eq!(sf, axum::http::StatusCode::OK);
    let (sv, tv) = req(
        routers.admin.clone(),
        "POST",
        &format!("/api/v1/admin/elections/{election_id}/open-voting"),
        None,
        &[("x-admin-token", "test-admin-token")],
    )
    .await;
    assert_eq!(sv, axum::http::StatusCode::CREATED, "{tv}");
    // Both credentials vote using the enrolled registry
    let loaded = storage.get_election(election_id).unwrap().unwrap();
    let manifest = ElectionManifest::from_canonical_cbor(&loaded.manifest_cbor).unwrap();
    let candidates = CandidateSet::from_canonical_cbor(&loaded.candidate_cbor).unwrap();
    let registry = tari_cc_private_ballot_registry::RegistrySnapshot::from_canonical_cbor(
        &loaded.registry_cbor,
    )
    .unwrap();
    let p = Blake3HashProviderV1;
    let verifier = build_tari_triptych_verifier_from_registry_v1(&registry, &p).unwrap();
    let mh = manifest.canonical_hash(&p).unwrap();
    // Credential A votes
    let payload_a = ApprovalBallotPayload::new(
        vec![candidate_id(b"candidate-a")],
        &candidates,
        manifest.approval_limits(),
    )
    .unwrap();
    let stmt_a = tari_cc_private_ballot_verifier::reconstruct_approval_proof_statement(
        &manifest, &payload_a, &p,
    )
    .unwrap();
    let proof_a = prove_tari_triptych_prototype_v1(&stmt_a, &verifier, &secret_scalar(1)).unwrap();
    let pkg_a = BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash: mh.clone(),
        proof_suite_id: manifest.proof_suite_id().to_owned(),
        proof: proof_a,
        payload: payload_a,
    })
    .unwrap()
    .to_canonical_cbor()
    .unwrap();
    let (sa, ta) = req(routers.public.clone(), "POST", &format!("/api/v1/elections/{election_id}/ballots"), Some(serde_json::json!({"receipt_id": "two-slots-r-a", "package_cbor_hex": hex_encode(&pkg_a), "api_version": "v1"}).to_string()), &[("content-type", "application/json")]).await;
    assert_eq!(
        sa,
        axum::http::StatusCode::CREATED,
        "credential A must vote: {ta}"
    );
    // Credential B votes
    let payload_b = ApprovalBallotPayload::new(
        vec![candidate_id(b"candidate-b")],
        &candidates,
        manifest.approval_limits(),
    )
    .unwrap();
    let stmt_b = tari_cc_private_ballot_verifier::reconstruct_approval_proof_statement(
        &manifest, &payload_b, &p,
    )
    .unwrap();
    let proof_b = prove_tari_triptych_prototype_v1(&stmt_b, &verifier, &secret_scalar(2)).unwrap();
    let pkg_b = BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash: mh.clone(),
        proof_suite_id: manifest.proof_suite_id().to_owned(),
        proof: proof_b,
        payload: payload_b,
    })
    .unwrap()
    .to_canonical_cbor()
    .unwrap();
    let (sb, tb) = req(routers.public.clone(), "POST", &format!("/api/v1/elections/{election_id}/ballots"), Some(serde_json::json!({"receipt_id": "two-slots-r-b", "package_cbor_hex": hex_encode(&pkg_b), "api_version": "v1"}).to_string()), &[("content-type", "application/json")]).await;
    assert_eq!(
        sb,
        axum::http::StatusCode::CREATED,
        "credential B must vote: {tb}"
    );
    // Second attempt by A is rejected (duplicate nullifier)
    let payload_a2 = ApprovalBallotPayload::new(
        vec![candidate_id(b"candidate-c")],
        &candidates,
        manifest.approval_limits(),
    )
    .unwrap();
    let stmt_a2 = tari_cc_private_ballot_verifier::reconstruct_approval_proof_statement(
        &manifest,
        &payload_a2,
        &p,
    )
    .unwrap();
    let proof_a2 =
        prove_tari_triptych_prototype_v1(&stmt_a2, &verifier, &secret_scalar(1)).unwrap();
    let pkg_a2 = BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash: mh,
        proof_suite_id: manifest.proof_suite_id().to_owned(),
        proof: proof_a2,
        payload: payload_a2,
    })
    .unwrap()
    .to_canonical_cbor()
    .unwrap();
    let (sc, tc) = req(routers.public.clone(), "POST", &format!("/api/v1/elections/{election_id}/ballots"), Some(serde_json::json!({"receipt_id": "two-slots-r-a2", "package_cbor_hex": hex_encode(&pkg_a2), "api_version": "v1"}).to_string()), &[("content-type", "application/json")]).await;
    assert_eq!(
        sc,
        axum::http::StatusCode::CONFLICT,
        "credential A second vote must be rejected: {tc}"
    );
    assert!(tc.contains("duplicate_nullifier"), "{tc}");
    assert_eq!(
        storage.list_ballots(election_id).unwrap().len(),
        2,
        "exactly 2 ballots accepted"
    );
}

#[tokio::test]
async fn synthetic_full_election_3slots_enroll_2_freeze_vote_finalize() {
    // Full synthetic election: 3 authorized slots, A and B enroll, C does not.
    // Freeze at 2/3. A votes, second A proof rejected, B votes. Finalize.
    // Document: ONE ENROLLED CREDENTIAL, ONE ACCEPTED VOTE PER ELECTION.
    let f = fixture();
    let (routers, storage) = test_routers();
    let election_id = "enroll-synth-3slot";
    create_draft_and_open_enrollment(&routers.admin, election_id, &f.candidate_cbor, 3).await;
    let slots = storage.list_slots(election_id).unwrap();
    assert_eq!(slots.len(), 3, "3 authorized slots must be created");
    let secret_a = issue_invitation_for_slot(&routers.admin, election_id, &slots[0].slot_id).await;
    let secret_b = issue_invitation_for_slot(&routers.admin, election_id, &slots[1].slot_id).await;
    // Slot C: invitation issued but voter never enrolls
    let _secret_c = issue_invitation_for_slot(&routers.admin, election_id, &slots[2].slot_id).await;
    // Enroll A and B; C left unused
    let (sa, _) = enroll(&routers.public, election_id, &secret_a, &enroll_key(1)).await;
    assert_eq!(sa, axum::http::StatusCode::CREATED);
    let (sb, _) = enroll(&routers.public, election_id, &secret_b, &enroll_key(2)).await;
    assert_eq!(sb, axum::http::StatusCode::CREATED);
    // Check enrollment status: 2/3 enrolled
    let (ss, sb_status) = req(
        routers.admin.clone(),
        "GET",
        &format!("/api/v1/admin/elections/{election_id}/enrollment"),
        None,
        &[("x-admin-token", "test-admin-token")],
    )
    .await;
    assert_eq!(ss, axum::http::StatusCode::OK);
    let status_v: serde_json::Value = serde_json::from_str(&sb_status).unwrap();
    assert_eq!(status_v["enrolled_count"], 2);
    assert_eq!(status_v["authorized_slot_count"], 3);
    // Freeze at 2/3
    let (sf, tf) = req(
        routers.admin.clone(),
        "POST",
        &format!("/api/v1/admin/elections/{election_id}/freeze"),
        None,
        &[("x-admin-token", "test-admin-token")],
    )
    .await;
    assert_eq!(sf, axum::http::StatusCode::OK, "{tf}");
    let freeze_v: serde_json::Value = serde_json::from_str(&tf).unwrap();
    assert_eq!(freeze_v["enrolled_count"], 2);
    assert_eq!(freeze_v["authorized_slot_count"], 3);
    // Open voting
    let (sv, _) = req(
        routers.admin.clone(),
        "POST",
        &format!("/api/v1/admin/elections/{election_id}/open-voting"),
        None,
        &[("x-admin-token", "test-admin-token")],
    )
    .await;
    assert_eq!(sv, axum::http::StatusCode::CREATED);
    let loaded = storage.get_election(election_id).unwrap().unwrap();
    let manifest = ElectionManifest::from_canonical_cbor(&loaded.manifest_cbor).unwrap();
    let candidates = CandidateSet::from_canonical_cbor(&loaded.candidate_cbor).unwrap();
    let registry = tari_cc_private_ballot_registry::RegistrySnapshot::from_canonical_cbor(
        &loaded.registry_cbor,
    )
    .unwrap();
    // Registry has exactly 2 members (A and B, C not enrolled)
    assert_eq!(
        registry.entries().len(),
        2,
        "registry must have exactly 2 enrolled members"
    );
    let p = Blake3HashProviderV1;
    let verifier = build_tari_triptych_verifier_from_registry_v1(&registry, &p).unwrap();
    let mh = manifest.canonical_hash(&p).unwrap();
    // A votes (device 1)
    let payload_a = ApprovalBallotPayload::new(
        vec![candidate_id(b"candidate-a")],
        &candidates,
        manifest.approval_limits(),
    )
    .unwrap();
    let stmt_a = tari_cc_private_ballot_verifier::reconstruct_approval_proof_statement(
        &manifest, &payload_a, &p,
    )
    .unwrap();
    let proof_a1 = prove_tari_triptych_prototype_v1(&stmt_a, &verifier, &secret_scalar(1)).unwrap();
    let pkg_a1 = BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash: mh.clone(),
        proof_suite_id: manifest.proof_suite_id().to_owned(),
        proof: proof_a1,
        payload: payload_a.clone(),
    })
    .unwrap()
    .to_canonical_cbor()
    .unwrap();
    let (ra1, ta1) = req(routers.public.clone(), "POST", &format!("/api/v1/elections/{election_id}/ballots"), Some(serde_json::json!({"receipt_id": "synth-a1", "package_cbor_hex": hex_encode(&pkg_a1), "api_version": "v1"}).to_string()), &[("content-type", "application/json")]).await;
    assert_eq!(ra1, axum::http::StatusCode::CREATED, "A first vote: {ta1}");
    // A votes again (device 2, new proof, same credential) → duplicate_nullifier
    let stmt_a2 = tari_cc_private_ballot_verifier::reconstruct_approval_proof_statement(
        &manifest, &payload_a, &p,
    )
    .unwrap();
    let proof_a2 =
        prove_tari_triptych_prototype_v1(&stmt_a2, &verifier, &secret_scalar(1)).unwrap();
    let pkg_a2_bytes = BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash: mh.clone(),
        proof_suite_id: manifest.proof_suite_id().to_owned(),
        proof: proof_a2,
        payload: payload_a,
    })
    .unwrap()
    .to_canonical_cbor()
    .unwrap();
    assert_ne!(
        pkg_a1, pkg_a2_bytes,
        "proof bytes should differ (randomized Triptych); nullifier identical"
    );
    let (ra2, ta2) = req(routers.public.clone(), "POST", &format!("/api/v1/elections/{election_id}/ballots"), Some(serde_json::json!({"receipt_id": "synth-a2", "package_cbor_hex": hex_encode(&pkg_a2_bytes), "api_version": "v1"}).to_string()), &[("content-type", "application/json")]).await;
    assert_eq!(
        ra2,
        axum::http::StatusCode::CONFLICT,
        "A second vote must be rejected: {ta2}"
    );
    assert!(ta2.contains("duplicate_nullifier"), "{ta2}");
    // B votes
    let payload_b = ApprovalBallotPayload::new(
        vec![candidate_id(b"candidate-b")],
        &candidates,
        manifest.approval_limits(),
    )
    .unwrap();
    let stmt_b = tari_cc_private_ballot_verifier::reconstruct_approval_proof_statement(
        &manifest, &payload_b, &p,
    )
    .unwrap();
    let proof_b = prove_tari_triptych_prototype_v1(&stmt_b, &verifier, &secret_scalar(2)).unwrap();
    let pkg_b = BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash: mh,
        proof_suite_id: manifest.proof_suite_id().to_owned(),
        proof: proof_b,
        payload: payload_b,
    })
    .unwrap()
    .to_canonical_cbor()
    .unwrap();
    let (rb, tb) = req(routers.public.clone(), "POST", &format!("/api/v1/elections/{election_id}/ballots"), Some(serde_json::json!({"receipt_id": "synth-b", "package_cbor_hex": hex_encode(&pkg_b), "api_version": "v1"}).to_string()), &[("content-type", "application/json")]).await;
    assert_eq!(rb, axum::http::StatusCode::CREATED, "B vote: {tb}");
    // Close and finalize
    let (rc, _) = req(
        routers.admin.clone(),
        "POST",
        &format!("/api/v1/admin/elections/{election_id}/close"),
        None,
        &[("x-admin-token", "test-admin-token")],
    )
    .await;
    assert_eq!(rc, axum::http::StatusCode::OK);
    let closed_fixture = Fixture {
        manifest_cbor: loaded.manifest_cbor.clone(),
        registry_cbor: loaded.registry_cbor.clone(),
        candidate_cbor: loaded.candidate_cbor.clone(),
        election_id: election_id.to_owned(),
    };
    record_desktop_transport_binding(storage.as_ref(), &closed_fixture, 2);
    let (rfin, tfin) = req(
        routers.admin.clone(),
        "POST",
        &format!("/api/v1/admin/elections/{election_id}/finalize"),
        None,
        &[("x-admin-token", "test-admin-token")],
    )
    .await;
    assert_eq!(rfin, axum::http::StatusCode::OK, "{tfin}");
    // Results: exactly 2 accepted ballots (A and B); C never voted
    let (rres, tres) = req(
        routers.public.clone(),
        "GET",
        &format!("/api/v1/elections/{election_id}/results"),
        None,
        &[],
    )
    .await;
    assert_eq!(rres, axum::http::StatusCode::OK, "{tres}");
    let results: serde_json::Value = serde_json::from_str(&tres).unwrap();
    assert_eq!(
        results["accepted_ballots"], 2,
        "exactly 2 votes accepted (C never enrolled/voted)"
    );
    // Archive endpoint: verify the archive can be generated and contains the frozen registry
    let (rar, tar) = req(
        routers.public.clone(),
        "GET",
        &format!("/api/v1/elections/{election_id}/archive"),
        None,
        &[],
    )
    .await;
    assert_eq!(rar, axum::http::StatusCode::OK, "{tar}");
    let archive: serde_json::Value = serde_json::from_str(&tar).unwrap();
    // Archive must contain voter_registry.cbor
    let files = archive["files"].as_array().expect("files array");
    assert!(
        files
            .iter()
            .any(|f| f["path"].as_str().unwrap_or("").contains("voter-registry")),
        "archive must include voter registry"
    );
    // Write archive to temp dir and verify with EXISTING desktop verifier
    let dir = std::env::temp_dir().join(format!("pb-synth-3slot-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Reconstruct the enrolled election manifest (not the fixture manifest)
    let enrolled_manifest = manifest;
    struct TmpFixture {
        manifest_cbor: Vec<u8>,
        registry_cbor: Vec<u8>,
        candidate_cbor: Vec<u8>,
        election_id: String,
    }
    let enroll_fixture = TmpFixture {
        manifest_cbor: enrolled_manifest.to_canonical_cbor().unwrap(),
        registry_cbor: loaded.registry_cbor.clone(),
        candidate_cbor: loaded.candidate_cbor.clone(),
        election_id: election_id.to_owned(),
    };
    // Write archive files from endpoint response
    {
        use std::collections::BTreeMap;
        use tari_cc_private_ballot_archive::{
            ARCHIVE_MANIFEST_CANONICAL_PATH, ArchiveFileCatalogV1, ArchiveFileEntryV1,
            ArchiveManifestV1, ArchivePathV1,
        };
        let p2 = Blake3HashProviderV1;
        let mut map: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for file in files {
            let path = file["path"].as_str().unwrap_or("").to_owned();
            let hex = file["cbor_hex"].as_str().unwrap_or("");
            let bytes = crate::hex_decode(hex).unwrap();
            map.insert(path, bytes);
        }
        let enroll_manifest_obj =
            tari_cc_private_ballot_ballot::ElectionManifest::from_canonical_cbor(
                &enroll_fixture.manifest_cbor,
            )
            .unwrap();
        let mh2 = enroll_manifest_obj.canonical_hash(&p2).unwrap();
        let entries2: Vec<ArchiveFileEntryV1> = map
            .iter()
            .map(|(path, bytes)| {
                ArchiveFileEntryV1::for_bytes(ArchivePathV1::new(path.clone()).unwrap(), &p2, bytes)
            })
            .collect();
        let catalog2 = ArchiveFileCatalogV1::new(entries2).unwrap();
        let am = ArchiveManifestV1::finalized_for_provider(mh2, catalog2, &p2).unwrap();
        let am_bytes = am.to_canonical_cbor().unwrap();
        let submissions_dir = dir.join("submissions");
        if map.keys().any(|k| k.starts_with("submissions")) {
            std::fs::create_dir_all(&submissions_dir).unwrap();
        }
        for (path, bytes) in &map {
            let fp = dir.join(path);
            if let Some(parent) = fp.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&fp, bytes).unwrap();
        }
        std::fs::write(dir.join(ARCHIVE_MANIFEST_CANONICAL_PATH), &am_bytes).unwrap();
    }
    assert!(
        verify_archive_dir_for_test(&dir),
        "desktop verifier must pass 3-slot synthetic election archive"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ── Concurrent enrollment race tests ──────────────────────────────────────────

#[tokio::test]
async fn concurrent_same_invitation_race_no_double_enrollment() {
    // Two requests racing with the SAME invitation + SAME key.
    // The ingest_lock serializes them. Required outcome:
    //   - exactly one enrolled credential
    //   - exactly one consumed slot
    //   - both callers receive a safe logical outcome (CREATED or OK/idempotent)
    //   - no server error (5xx)
    let f = fixture();
    let (routers, storage) = test_routers();
    let election_id = "concurrent-same-inv";
    create_draft_and_open_enrollment(&routers.admin, election_id, &f.candidate_cbor, 2).await;
    let slots = storage.list_slots(election_id).unwrap();
    let secret = issue_invitation_for_slot(&routers.admin, election_id, &slots[0].slot_id).await;
    let key_x = enroll_key(1);

    let (pub1, pub2) = (routers.public.clone(), routers.public.clone());
    let (sec1, sec2) = (secret.clone(), secret.clone());
    let (k1, k2) = (key_x.clone(), key_x.clone());
    let eid1 = election_id.to_owned();
    let eid2 = election_id.to_owned();

    // Race: both spawn at the same time and compete for ingest_lock
    let h1 = tokio::spawn(async move { enroll(&pub1, &eid1, &sec1, &k1).await });
    let h2 = tokio::spawn(async move { enroll(&pub2, &eid2, &sec2, &k2).await });
    let (r1, r2) = tokio::join!(h1, h2);
    let (s1, v1) = r1.unwrap_or_else(|_| panic!("join h1"));
    let (s2, v2) = r2.unwrap_or_else(|_| panic!("join h2"));

    // Both must be safe outcomes (no 5xx)
    assert!(
        s1.is_success() || s1 == axum::http::StatusCode::CONFLICT,
        "caller 1 must get a safe outcome, got {s1}: {v1}"
    );
    assert!(
        s2.is_success() || s2 == axum::http::StatusCode::CONFLICT,
        "caller 2 must get a safe outcome, got {s2}: {v2}"
    );
    // At least one CREATED
    assert!(
        s1 == axum::http::StatusCode::CREATED || s2 == axum::http::StatusCode::CREATED,
        "at least one caller must get CREATED: {s1} {v1} / {s2} {v2}"
    );
    // No double enrollment: exactly 1 credential
    let creds = storage.list_enrolled_credentials(election_id).unwrap();
    assert_eq!(
        creds.len(),
        1,
        "exactly one credential must be enrolled after same-invitation race"
    );
    // Exactly 1 slot consumed
    let slots2 = storage.list_slots(election_id).unwrap();
    assert_eq!(
        slots2.iter().filter(|s| s.consumed).count(),
        1,
        "exactly one slot must be consumed after same-invitation race"
    );
}

#[tokio::test]
async fn concurrent_different_invitations_same_key_slot_safety() {
    // Two requests racing with DIFFERENT invitations but the SAME public key.
    // Required outcome:
    //   - exactly one credential enrolled
    //   - exactly one slot consumed
    //   - losing slot remains UNCONSUMED and its invitation remains usable
    //   - after the race, the losing invitation can enroll a DIFFERENT key (critical)
    let f = fixture();
    let (routers, storage) = test_routers();
    let election_id = "concurrent-diff-inv";
    create_draft_and_open_enrollment(&routers.admin, election_id, &f.candidate_cbor, 2).await;
    let slots = storage.list_slots(election_id).unwrap();
    assert_eq!(slots.len(), 2);
    let secret_a = issue_invitation_for_slot(&routers.admin, election_id, &slots[0].slot_id).await;
    let secret_b = issue_invitation_for_slot(&routers.admin, election_id, &slots[1].slot_id).await;
    let key_x = enroll_key(5); // same key for both racing requests

    let (pub1, pub2) = (routers.public.clone(), routers.public.clone());
    let (sa_c, sb_c) = (secret_a.clone(), secret_b.clone());
    let (kx1, kx2) = (key_x.clone(), key_x.clone());
    let eid1 = election_id.to_owned();
    let eid2 = election_id.to_owned();

    // Race: inv A + key X vs inv B + key X
    let h1 = tokio::spawn(async move { enroll(&pub1, &eid1, &sa_c, &kx1).await });
    let h2 = tokio::spawn(async move { enroll(&pub2, &eid2, &sb_c, &kx2).await });
    let (r1, r2) = tokio::join!(h1, h2);
    let (s1, v1) = r1.unwrap_or_else(|_| panic!("join h1"));
    let (s2, v2) = r2.unwrap_or_else(|_| panic!("join h2"));

    // Exactly one CREATED, one CONFLICT
    assert!(
        (s1 == axum::http::StatusCode::CREATED && s2 == axum::http::StatusCode::CONFLICT)
            || (s2 == axum::http::StatusCode::CREATED && s1 == axum::http::StatusCode::CONFLICT),
        "exactly one CREATED and one CONFLICT required: {s1}:{v1} / {s2}:{v2}"
    );
    // Exactly 1 credential enrolled
    let creds = storage.list_enrolled_credentials(election_id).unwrap();
    assert_eq!(
        creds.len(),
        1,
        "exactly one credential enrolled after different-invitation race"
    );
    // Exactly 1 slot consumed (the losing slot must be UNCONSUMED)
    let slots2 = storage.list_slots(election_id).unwrap();
    let consumed: Vec<_> = slots2.iter().filter(|s| s.consumed).collect();
    assert_eq!(
        consumed.len(),
        1,
        "exactly one slot consumed after different-invitation race"
    );

    // The winning credential is key X; identify which invitation won and which lost
    // The losing invitation must remain usable for enrolling a DIFFERENT key (key Y)
    let key_y = enroll_key(6);
    // Determine losing secret: whichever invitation's slot was NOT consumed
    let losing_slot_id = slots2
        .iter()
        .find(|s| !s.consumed)
        .map(|s| s.slot_id.clone())
        .unwrap();
    let losing_secret = if slots[0].slot_id == losing_slot_id {
        &secret_a
    } else {
        &secret_b
    };
    let (sy, vy) = enroll(&routers.public, election_id, losing_secret, &key_y).await;
    assert_eq!(
        sy,
        axum::http::StatusCode::CREATED,
        "losing slot must remain enrollable after race: {vy}"
    );
    // Now 2 credentials enrolled total (key X from winner + key Y from losing slot)
    let creds2 = storage.list_enrolled_credentials(election_id).unwrap();
    assert_eq!(
        creds2.len(),
        2,
        "total 2 credentials after using losing slot"
    );
}

// ── Self-service organizer plane tests (schema v4) ─────────────────────────

fn organizer_secret(tag: u8) -> String {
    hex_encode(&[tag; 32])
}

async fn organizer_create(
    public: &axum::Router,
    election_id: &str,
    secret_hex: &str,
    slot_count: i64,
    options: &[&str],
) -> (axum::http::StatusCode, serde_json::Value) {
    let options_json: Vec<serde_json::Value> = options
        .iter()
        .map(|o| serde_json::Value::from(*o))
        .collect();
    let body = serde_json::json!({
        "election_id": election_id,
        "options": options_json,
        "organizer_secret_hex": secret_hex,
        "min_approvals": 1,
        "max_approvals": 1,
        "allow_abstention": false,
        "authorized_slot_count": slot_count,
        "governance_revision": "self-service-test",
        "proposal_question": "Should the self-service test proposal pass?",
    })
    .to_string();
    let (s, t) = req(
        public.clone(),
        "POST",
        "/api/v1/organizer/elections",
        Some(body),
        &[("content-type", "application/json")],
    )
    .await;
    (
        s,
        serde_json::from_str(&t).unwrap_or_else(|_| serde_json::json!({"raw": t})),
    )
}

async fn organizer_call(
    public: &axum::Router,
    method: &str,
    path: &str,
    body: Option<String>,
    secret: Option<&str>,
) -> (axum::http::StatusCode, serde_json::Value) {
    let mut headers: Vec<(&str, &str)> = vec![("content-type", "application/json")];
    let owned_secret = secret.map(str::to_owned).unwrap_or_default();
    if !owned_secret.is_empty() {
        headers.push(("x-private-ballot-organizer", owned_secret.as_str()));
    }
    let (s, t) = req(public.clone(), method, path, body, &headers).await;
    // Keep the owned secret alive for the lifetime of the borrowed header.
    debug_assert_eq!(owned_secret.is_empty(), secret.is_none());
    (
        s,
        serde_json::from_str(&t).unwrap_or_else(|_| serde_json::json!({"raw": t})),
    )
}

async fn organizer_create_ok(
    public: &axum::Router,
    election_id: &str,
    secret_hex: &str,
    slot_count: i64,
) {
    let (s, v) = organizer_create(
        public,
        election_id,
        secret_hex,
        slot_count,
        &["candidate-a", "candidate-b", "candidate-c"],
    )
    .await;
    assert_eq!(
        s,
        axum::http::StatusCode::CREATED,
        "organizer create must succeed: {v}"
    );
    assert_eq!(v["eligibility_state"], "DRAFT");
    assert_eq!(v["authorized_slot_count"], slot_count);
    assert_eq!(
        v["proof_suite_id"], TARI_TRIPTYCH_PROOF_SUITE_ID_V1,
        "proof suite must be pinned server-side"
    );
    assert!(
        v.get("organizer_secret_hex").is_none(),
        "server must never echo the organizer secret"
    );
}

#[tokio::test]
async fn organizer_anyone_can_create_election_via_public_router() {
    let (routers, storage) = test_routers();
    let public = routers.public.clone();
    let secret = organizer_secret(0xA1);
    // No admin token, no SSH, no server access: just the public router.
    organizer_create_ok(&public, "org-create-001", &secret, 5).await;
    // Draft persisted with pinned proof suite and validated candidate set.
    let draft = storage
        .get_election_draft("org-create-001")
        .unwrap()
        .unwrap();
    assert_eq!(draft.authorized_slot_count, 5);
    assert_eq!(draft.proof_suite_id, TARI_TRIPTYCH_PROOF_SUITE_ID_V1);
    assert!(CandidateSet::from_canonical_cbor(&draft.candidate_cbor).is_ok());
    // Duplicate election id rejected.
    let (s2, v2) = organizer_create(
        &public,
        "org-create-001",
        &secret,
        5,
        &["candidate-a", "candidate-b", "candidate-c"],
    )
    .await;
    assert_eq!(s2, axum::http::StatusCode::CONFLICT, "{v2}");
    assert_eq!(v2["code"], "election_exists");
}

#[tokio::test]
async fn organizer_capability_plaintext_is_never_stored() {
    let dir = std::env::temp_dir().join(format!(
        "pb-hosted-organizer-plaintext-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let db = dir.join("org.db");
    let secret = organizer_secret(0xB2);
    {
        let storage =
            Arc::new(crate::SqliteStorage::open(&db).unwrap_or_else(|_| panic!("open sqlite")));
        let state = Arc::new(AppState::new(test_config(), storage));
        let public = router_with_state(state);
        organizer_create_ok(&public, "org-plaintext-001", &secret, 3).await;
    }
    // Inspect the raw database: the organizer credential row must be the
    // verifier, never the plaintext secret.
    {
        let conn = Connection::open(&db).unwrap_or_else(|_| panic!("inspect"));
        let mut stmt = conn
            .prepare("SELECT election_id, organizer_verifier_hex FROM organizer_credentials")
            .unwrap_or_else(|_| panic!("stmt"));
        let rows: Vec<(String, String)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        assert_eq!(rows.len(), 1);
        let (eid, verifier_hex) = rows[0].clone();
        assert_eq!(eid, "org-plaintext-001");
        assert_eq!(
            verifier_hex,
            crate::organizer_verifier("org-plaintext-001", &hex_decode(&secret).unwrap())
        );
        assert_ne!(
            verifier_hex, secret,
            "plaintext organizer secret must never be stored"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn organizer_missing_or_malformed_credential_rejected() {
    let (routers, _storage) = test_routers();
    let public = routers.public.clone();
    let secret = organizer_secret(0xC3);
    organizer_create_ok(&public, "org-auth-001", &secret, 2).await;
    // No header at all
    let (s1, v1) = organizer_call(
        &public,
        "GET",
        "/api/v1/organizer/elections/org-auth-001",
        None,
        None,
    )
    .await;
    assert_eq!(s1, axum::http::StatusCode::UNAUTHORIZED, "{v1}");
    assert_eq!(v1["code"], "organizer_credential_required");
    // Not hex
    let (s2, _) = organizer_call(
        &public,
        "GET",
        "/api/v1/organizer/elections/org-auth-001",
        None,
        Some("zz-not-hex"),
    )
    .await;
    assert_eq!(s2, axum::http::StatusCode::UNAUTHORIZED);
    // Wrong length (16 bytes)
    let (s3, _) = organizer_call(
        &public,
        "GET",
        "/api/v1/organizer/elections/org-auth-001",
        None,
        Some(&hex_encode(&[1u8; 16])),
    )
    .await;
    assert_eq!(s3, axum::http::StatusCode::UNAUTHORIZED);
    // Error responses carry no secret information.
    assert!(v1.to_string().len() < 200 && !v1.to_string().contains(&secret));
}

#[tokio::test]
async fn organizer_wrong_credential_rejected() {
    let (routers, _storage) = test_routers();
    let public = routers.public.clone();
    organizer_create_ok(&public, "org-auth-002", &organizer_secret(0xD4), 2).await;
    let (s, v) = organizer_call(
        &public,
        "GET",
        "/api/v1/organizer/elections/org-auth-002",
        None,
        Some(&organizer_secret(0xD5)),
    )
    .await;
    assert_eq!(s, axum::http::StatusCode::UNAUTHORIZED, "{v}");
    assert_eq!(v["code"], "organizer_credential_required");
}

#[tokio::test]
async fn organizer_credential_is_election_scoped() {
    let (routers, _storage) = test_routers();
    let public = routers.public.clone();
    let secret_a = organizer_secret(0xE6);
    let secret_b = organizer_secret(0xF7);
    organizer_create_ok(&public, "org-scope-a", &secret_a, 2).await;
    organizer_create_ok(&public, "org-scope-b", &secret_b, 2).await;
    // Election A's credential must NOT authorize election B (read or mutate).
    let (s1, v1) = organizer_call(
        &public,
        "GET",
        "/api/v1/organizer/elections/org-scope-b",
        None,
        Some(&secret_a),
    )
    .await;
    assert_eq!(s1, axum::http::StatusCode::UNAUTHORIZED, "{v1}");
    let (s2, v2) = organizer_call(
        &public,
        "POST",
        "/api/v1/organizer/elections/org-scope-b/open-enrollment",
        None,
        Some(&secret_a),
    )
    .await;
    assert_eq!(s2, axum::http::StatusCode::UNAUTHORIZED, "{v2}");
    // And B's credential must not authorize A.
    let (s3, v3) = organizer_call(
        &public,
        "GET",
        "/api/v1/organizer/elections/org-scope-a",
        None,
        Some(&secret_b),
    )
    .await;
    assert_eq!(s3, axum::http::StatusCode::UNAUTHORIZED, "{v3}");
    // Own credential works.
    let (s4, v4) = organizer_call(
        &public,
        "GET",
        "/api/v1/organizer/elections/org-scope-a",
        None,
        Some(&secret_a),
    )
    .await;
    assert_eq!(s4, axum::http::StatusCode::OK, "{v4}");
    assert_eq!(v4["election_id"], "org-scope-a");
}

#[tokio::test]
async fn organizer_lifecycle_enrollment_slots_invitations() {
    let (routers, storage) = test_routers();
    let public = routers.public.clone();
    let secret = organizer_secret(0x11);
    organizer_create_ok(&public, "org-lifecycle-001", &secret, 3).await;

    // Open enrollment with own credential.
    let (s1, v1) = organizer_call(
        &public,
        "POST",
        "/api/v1/organizer/elections/org-lifecycle-001/open-enrollment",
        None,
        Some(&secret),
    )
    .await;
    assert_eq!(s1, axum::http::StatusCode::OK, "{v1}");
    assert_eq!(v1["eligibility_state"], "ENROLLMENT_OPEN");

    // Inspect slot/enrollment state without database access.
    let (s2, v2) = organizer_call(
        &public,
        "GET",
        "/api/v1/organizer/elections/org-lifecycle-001/enrollment",
        None,
        Some(&secret),
    )
    .await;
    assert_eq!(s2, axum::http::StatusCode::OK, "{v2}");
    assert_eq!(v2["total_slots"], 3);
    assert_eq!(v2["available_slots"], 3);
    assert_eq!(v2["consumed_slots"], 0);
    assert_eq!(v2["enrolled_count"], 0);

    let (s3, v3) = organizer_call(
        &public,
        "GET",
        "/api/v1/organizer/elections/org-lifecycle-001/slots",
        None,
        Some(&secret),
    )
    .await;
    assert_eq!(s3, axum::http::StatusCode::OK, "{v3}");
    let slots = v3.as_array().unwrap_or_else(|| panic!("slots array: {v3}"));
    assert_eq!(slots.len(), 3);
    for slot in slots {
        assert!(
            slot["slot_id"].as_str().unwrap_or("").len() >= 8,
            "opaque slot id: {slot}"
        );
        assert_eq!(slot["consumed"], false);
        assert!(slot["invitation_id"].is_null(), "no invitation yet");
    }

    // Issue an invitation WITHOUT knowing slot ids (empty body = auto-pick).
    let (s4, v4) = organizer_call(
        &public,
        "POST",
        "/api/v1/organizer/elections/org-lifecycle-001/invitations",
        None,
        Some(&secret),
    )
    .await;
    assert_eq!(s4, axum::http::StatusCode::CREATED, "{v4}");
    let invitation_secret = v4["invitation_secret_hex"]
        .as_str()
        .unwrap_or_else(|| panic!("plaintext invitation: {v4}"))
        .to_owned();
    assert_eq!(
        invitation_secret.len(),
        64,
        "invitation plaintext is 64 hex chars"
    );
    let invitation_id = v4["invitation_id"].as_str().unwrap().to_owned();

    // The plaintext is returned ONCE: slot listing exposes state only.
    let (s5, v5) = organizer_call(
        &public,
        "GET",
        "/api/v1/organizer/elections/org-lifecycle-001/slots",
        None,
        Some(&secret),
    )
    .await;
    assert_eq!(s5, axum::http::StatusCode::OK, "{v5}");
    assert!(
        !v5.to_string().contains(&invitation_secret),
        "slot listing must never contain the invitation plaintext"
    );

    // Reissue: explicit slot targeting returns a NEW plaintext; the old one
    // is voided and cannot be recovered (only reissued).
    let slot_id = v4["slot_id"].as_str().unwrap().to_owned();
    let body = serde_json::json!({ "slot_id": slot_id }).to_string();
    let (s6, v6) = organizer_call(
        &public,
        "POST",
        "/api/v1/organizer/elections/org-lifecycle-001/invitations",
        Some(body),
        Some(&secret),
    )
    .await;
    assert_eq!(s6, axum::http::StatusCode::CREATED, "{v6}");
    let reissued_secret = v6["invitation_secret_hex"].as_str().unwrap().to_owned();
    assert_ne!(
        reissued_secret, invitation_secret,
        "reissue must mint a new secret"
    );
    let reissued_invitation_id = v6["invitation_id"].as_str().unwrap().to_owned();
    assert_ne!(reissued_invitation_id, invitation_id);

    // Void the reissued invitation, then confirm unknown ids fail closed.
    let (s7, v7) = organizer_call(&public, "POST", &format!("/api/v1/organizer/elections/org-lifecycle-001/invitations/{reissued_invitation_id}/void"), None, Some(&secret)).await;
    assert_eq!(s7, axum::http::StatusCode::OK, "{v7}");
    assert_eq!(v7["state"], "VOIDED");
    let (s8, v8) = organizer_call(
        &public,
        "POST",
        "/api/v1/organizer/elections/org-lifecycle-001/invitations/does-not-exist/void",
        None,
        Some(&secret),
    )
    .await;
    assert_eq!(s8, axum::http::StatusCode::NOT_FOUND, "{v8}");

    // Reissue after void works (slot unconsumed again).
    let body = serde_json::json!({ "slot_id": slot_id }).to_string();
    let (s9, v9) = organizer_call(
        &public,
        "POST",
        "/api/v1/organizer/elections/org-lifecycle-001/invitations",
        Some(body),
        Some(&secret),
    )
    .await;
    assert_eq!(s9, axum::http::StatusCode::CREATED, "{v9}");
    let usable_secret = v9["invitation_secret_hex"].as_str().unwrap().to_owned();

    // A voter can enroll with the current invitation; the organizer never
    // sees the voter's private credential (only the public enrollment key).
    let key_a = enroll_key(1);
    let (s10, v10) = enroll(&public, "org-lifecycle-001", &usable_secret, &key_a).await;
    assert_eq!(s10, axum::http::StatusCode::CREATED, "{v10}");
    assert_eq!(
        v10["public_key_hex"], key_a,
        "enrollment exposes only the public key"
    );

    // Organizer endpoints must not expose voter keys or secrets.
    let (s11, v11) = organizer_call(
        &public,
        "GET",
        "/api/v1/organizer/elections/org-lifecycle-001",
        None,
        Some(&secret),
    )
    .await;
    assert_eq!(s11, axum::http::StatusCode::OK, "{v11}");
    let body_text = v11.to_string();
    assert!(
        !body_text.contains(&key_a),
        "organizer view must not expose voter public keys"
    );
    assert!(
        !body_text.contains("secret_key"),
        "organizer view must not expose voter secrets"
    );
    assert_eq!(v11["enrolled_count"], 1);
    assert_eq!(v11["consumed_slots"], 1);
    let creds = storage
        .list_enrolled_credentials("org-lifecycle-001")
        .unwrap();
    assert_eq!(creds.len(), 1);
    assert!(creds[0].slot_id.is_some(), "linkage kept until freeze");
}

#[tokio::test]
async fn organizer_freeze_rejects_post_freeze_mutations() {
    let (routers, _storage) = test_routers();
    let public = routers.public.clone();
    let secret = organizer_secret(0x21);
    organizer_create_ok(&public, "org-freeze-001", &secret, 2).await;
    organizer_call(
        &public,
        "POST",
        "/api/v1/organizer/elections/org-freeze-001/open-enrollment",
        None,
        Some(&secret),
    )
    .await;
    let (s0, v0) = organizer_call(
        &public,
        "POST",
        "/api/v1/organizer/elections/org-freeze-001/invitations",
        None,
        Some(&secret),
    )
    .await;
    assert_eq!(s0, axum::http::StatusCode::CREATED, "{v0}");
    let invitation_secret = v0["invitation_secret_hex"].as_str().unwrap().to_owned();
    let (se, _) = enroll(
        &public,
        "org-freeze-001",
        &invitation_secret,
        &enroll_key(2),
    )
    .await;
    assert_eq!(se, axum::http::StatusCode::CREATED);

    // Freeze own registry.
    let (s1, v1) = organizer_call(
        &public,
        "POST",
        "/api/v1/organizer/elections/org-freeze-001/freeze",
        None,
        Some(&secret),
    )
    .await;
    assert_eq!(s1, axum::http::StatusCode::OK, "{v1}");
    assert_eq!(v1["eligibility_state"], "REGISTRY_FROZEN");
    assert_eq!(v1["enrolled_count"], 1);
    assert_eq!(
        v1["registry_commitment_hex"].as_str().unwrap_or("").len(),
        64
    );

    // Post-freeze: enrollment closed, new invitations rejected, re-freeze rejected.
    let (s2, v2) = organizer_call(
        &public,
        "POST",
        "/api/v1/organizer/elections/org-freeze-001/invitations",
        None,
        Some(&secret),
    )
    .await;
    assert_eq!(s2, axum::http::StatusCode::CONFLICT, "{v2}");
    assert_eq!(v2["code"], "invalid_state");
    let (s3, v3) = enroll(
        &public,
        "org-freeze-001",
        &invitation_secret,
        &enroll_key(3),
    )
    .await;
    assert_eq!(s3, axum::http::StatusCode::CONFLICT, "{v3}");
    assert_eq!(v3["code"], "enrollment_closed");
    let (s4, _) = organizer_call(
        &public,
        "POST",
        "/api/v1/organizer/elections/org-freeze-001/freeze",
        None,
        Some(&secret),
    )
    .await;
    assert_eq!(s4, axum::http::StatusCode::CONFLICT);
}

#[tokio::test]
async fn organizer_bootstrap_is_v2_bound_signed_and_capability_protected() {
    let (routers, _storage) = test_routers();
    let public = routers.public;
    let election_id = "org-bootstrap-001";
    let organizer = organizer_secret(0x66);
    organizer_create_ok(&public, election_id, &organizer, 1).await;
    assert_eq!(
        organizer_call(
            &public,
            "POST",
            &format!("/api/v1/organizer/elections/{election_id}/open-enrollment"),
            None,
            Some(&organizer),
        )
        .await
        .0,
        axum::http::StatusCode::OK
    );
    let (_, invitation) = organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/invitations"),
        None,
        Some(&organizer),
    )
    .await;
    let invitation_secret = invitation["invitation_secret_hex"]
        .as_str()
        .unwrap_or_else(|| panic!("invitation secret"));
    assert_eq!(
        enroll(&public, election_id, invitation_secret, &enroll_key(1))
            .await
            .0,
        axum::http::StatusCode::CREATED
    );
    for (action, expected) in [
        ("freeze", axum::http::StatusCode::OK),
        ("open-voting", axum::http::StatusCode::CREATED),
    ] {
        assert_eq!(
            organizer_call(
                &public,
                "POST",
                &format!("/api/v1/organizer/elections/{election_id}/{action}"),
                None,
                Some(&organizer),
            )
            .await
            .0,
            expected
        );
    }

    let path = format!("/api/v1/organizer/elections/{election_id}/desktop-bootstrap");
    let foreign_organizer = organizer_secret(0x67);
    assert_eq!(
        req_bytes(
            public.clone(),
            "GET",
            &path,
            &[("x-private-ballot-organizer", &foreign_organizer)],
        )
        .await
        .0,
        axum::http::StatusCode::UNAUTHORIZED
    );
    let (status, bytes) = req_bytes(
        public,
        "GET",
        &path,
        &[("x-private-ballot-organizer", &organizer)],
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let bootstrap = HostedOrganizerBootstrapV1::from_canonical_cbor(&bytes)
        .unwrap_or_else(|error| panic!("canonical bootstrap: {error}"));
    let artifacts = bootstrap
        .verify(&TransportAuthorityRootSetV1::new(test_transport_root()))
        .unwrap_or_else(|error| panic!("signed bootstrap: {error}"));
    assert_eq!(artifacts.manifest().proposal_question(), Some("Should the self-service test proposal pass?"));
    assert_eq!(artifacts.manifest().election_id().as_bytes(), election_id.as_bytes());
}

#[tokio::test]
async fn organizer_descriptor_issuance_is_authenticated_exact_and_replay_safe() {
    let (routers, storage) = test_routers();
    let public = routers.public;
    let election_id = "org-descriptor-001";
    let organizer = organizer_secret(0x68);
    organizer_create_ok(&public, election_id, &organizer, 1).await;
    assert_eq!(
        organizer_call(
            &public,
            "POST",
            &format!("/api/v1/organizer/elections/{election_id}/open-enrollment"),
            None,
            Some(&organizer),
        )
        .await
        .0,
        axum::http::StatusCode::OK
    );
    let (_, invitation) = organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/invitations"),
        None,
        Some(&organizer),
    )
    .await;
    let invitation_secret = invitation["invitation_secret_hex"]
        .as_str()
        .unwrap_or_else(|| panic!("invitation secret"));
    assert_eq!(
        enroll(&public, election_id, invitation_secret, &enroll_key(1)).await.0,
        axum::http::StatusCode::CREATED
    );
    for action in ["freeze", "open-voting"] {
        assert!(matches!(
            organizer_call(
                &public,
                "POST",
                &format!("/api/v1/organizer/elections/{election_id}/{action}"),
                None,
                Some(&organizer),
            )
            .await
            .0,
            axum::http::StatusCode::OK | axum::http::StatusCode::CREATED
        ));
    }
    let record = storage
        .get_election(election_id)
        .unwrap_or_else(|_| panic!("storage"))
        .unwrap_or_else(|| panic!("election"));
    let manifest = ElectionManifest::from_canonical_cbor(&record.manifest_cbor)
        .unwrap_or_else(|_| panic!("manifest"));
    let descriptor = TransportDescriptorV1::unsigned_for_authority(
        election_id.as_bytes().to_vec(),
        manifest
            .canonical_hash(&Blake3HashProviderV1)
            .unwrap_or_else(|_| panic!("hash")),
        1,
        TransportRoutePolicyV1::ManagedTorOrOffline,
        vec!["http://test.invalid".to_owned()],
        Vec::new(),
        [7; 32],
        "desktop-generated-gateway".to_owned(),
        vec![[8; 32]],
        PaddingPolicyV1 {
            id: "test-padding".to_owned(),
            padded_bytes: 2048,
        },
        BatchPolicyV1 {
            id: "test-batch".to_owned(),
            accepted_unique_floor: 1,
        },
        None,
        "hosted-test-root".to_owned(),
    )
    .unwrap_or_else(|_| panic!("draft"));
    let request = HostedDescriptorRequestV1::new([0x23; 32], "test".to_owned(), descriptor)
        .unwrap_or_else(|_| panic!("request"));
    let bytes = request.to_canonical_cbor().unwrap_or_else(|_| panic!("cbor"));
    let path = format!("/api/v1/organizer/elections/{election_id}/descriptor-issuance");
    assert_eq!(
        req_cbor(public.clone(), "POST", &path, bytes.clone(), &organizer_secret(0x69))
            .await
            .0,
        axum::http::StatusCode::UNAUTHORIZED
    );
    let (status, issued) = req_cbor(public.clone(), "POST", &path, bytes.clone(), &organizer).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let response = HostedDescriptorResponseV1::from_canonical_cbor(&issued)
        .unwrap_or_else(|_| panic!("response"));
    assert_eq!(response.request_id(), request.request_id());
    response
        .descriptor()
        .verify(
            &test_transport_root(),
            manifest
                .canonical_hash(&Blake3HashProviderV1)
                .unwrap_or_else(|_| panic!("hash")),
        )
        .unwrap_or_else(|_| panic!("authority descriptor"));

    // Exact retries return the original canonical response, while a changed
    // public parameter under the same request ID is rejected.
    let (replay_status, replay) = req_cbor(public.clone(), "POST", &path, bytes, &organizer).await;
    assert_eq!(replay_status, axum::http::StatusCode::OK);
    assert_eq!(replay, issued);
    let conflicting = HostedDescriptorRequestV1::new(
        request.request_id(),
        "test".to_owned(),
        TransportDescriptorV1::unsigned_for_authority(
            election_id.as_bytes().to_vec(),
            manifest.canonical_hash(&Blake3HashProviderV1).unwrap_or_else(|_| panic!("hash")),
            1,
            TransportRoutePolicyV1::ManagedTorOrOffline,
            vec!["http://test.invalid".to_owned()],
            Vec::new(),
            [9; 32],
            "desktop-generated-gateway".to_owned(),
            vec![[8; 32]],
            PaddingPolicyV1 { id: "test-padding".to_owned(), padded_bytes: 2048 },
            BatchPolicyV1 { id: "test-batch".to_owned(), accepted_unique_floor: 1 },
            None,
            "hosted-test-root".to_owned(),
        )
        .unwrap_or_else(|_| panic!("conflicting draft")),
    )
    .unwrap_or_else(|_| panic!("conflicting request"));
    let (conflict_status, _) = req_cbor(
        public,
        "POST",
        &path,
        conflicting.to_canonical_cbor().unwrap_or_else(|_| panic!("conflicting cbor")),
        &organizer,
    )
    .await;
    assert_eq!(conflict_status, axum::http::StatusCode::CONFLICT);
}

#[tokio::test]
async fn organizer_full_lifecycle_vote_close_finalize_results_archive() {
    let (routers, storage) = test_routers();
    let public = routers.public.clone();
    let secret = organizer_secret(0x31);
    let election_id = "org-full-e2e-001";
    organizer_create_ok(&public, election_id, &secret, 3).await;
    organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/open-enrollment"),
        None,
        Some(&secret),
    )
    .await;

    // Three invitations, three enrolled voters (scalars 1, 2, 3).
    let mut invitation_secrets = Vec::new();
    for _ in 0..3 {
        let (s, v) = organizer_call(
            &public,
            "POST",
            &format!("/api/v1/organizer/elections/{election_id}/invitations"),
            None,
            Some(&secret),
        )
        .await;
        assert_eq!(s, axum::http::StatusCode::CREATED, "{v}");
        invitation_secrets.push(v["invitation_secret_hex"].as_str().unwrap().to_owned());
    }
    for (i, invitation) in invitation_secrets.iter().enumerate() {
        let (s, v) = enroll(
            &public,
            election_id,
            invitation,
            &enroll_key((i + 1) as u64),
        )
        .await;
        assert_eq!(s, axum::http::StatusCode::CREATED, "{v}");
    }

    // Freeze then open voting (organizer plane).
    let (sf, vf) = organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/freeze"),
        None,
        Some(&secret),
    )
    .await;
    assert_eq!(sf, axum::http::StatusCode::OK, "{vf}");
    let (sv, vv) = organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/open-voting"),
        None,
        Some(&secret),
    )
    .await;
    assert_eq!(sv, axum::http::StatusCode::CREATED, "{vv}");
    assert_eq!(vv["state"], "open");

    // Build packages against the manifest the server froze (public package).
    let (sp, vp) = req(
        public.clone(),
        "GET",
        &format!("/api/v1/elections/{election_id}"),
        None,
        &[],
    )
    .await;
    assert_eq!(sp, axum::http::StatusCode::OK, "{vp}");
    let pkg_json: serde_json::Value =
        serde_json::from_str(&vp).unwrap_or_else(|_| panic!("package json"));
    let f2 = Fixture {
        election_id: election_id.to_owned(),
        manifest_cbor: hex_decode(pkg_json["manifest_cbor_hex"].as_str().unwrap()).unwrap(),
        registry_cbor: hex_decode(pkg_json["registry_cbor_hex"].as_str().unwrap()).unwrap(),
        candidate_cbor: hex_decode(pkg_json["candidate_cbor_hex"].as_str().unwrap()).unwrap(),
    };

    // Issue the authoritative Hosted descriptor while the election is open.
    // All subsequent binding computations must use this exact descriptor.
    let issued_descriptor_lifecycle = {
        let manifest = ElectionManifest::from_canonical_cbor(&f2.manifest_cbor)
            .expect("lifecycle manifest");
        let manifest_hash = manifest.canonical_hash(&Blake3HashProviderV1).expect("lifecycle hash");
        let draft = TransportDescriptorV1::unsigned_for_authority(
            election_id.as_bytes().to_vec(),
            manifest_hash,
            1,
            TransportRoutePolicyV1::ManagedTorOrOffline,
            vec!["http://test.invalid".to_owned()],
            Vec::new(),
            [7; 32],
            "hosted-test-gateway".to_owned(),
            vec![[8; 32]],
            PaddingPolicyV1 { id: "test-padding".to_owned(), padded_bytes: 2048 },
            BatchPolicyV1 { id: "test-batch".to_owned(), accepted_unique_floor: 1 },
            None,
            "hosted-test-root".to_owned(),
        ).expect("lifecycle descriptor draft");
        let request = HostedDescriptorRequestV1::new(
            [0x31; 32],
            "test".to_owned(),
            draft,
        ).expect("lifecycle descriptor request");
        let path = format!("/api/v1/organizer/elections/{election_id}/descriptor-issuance");
        let (s_desc, issued_cbor) = req_cbor(
            public.clone(),
            "POST",
            &path,
            request.to_canonical_cbor().expect("lifecycle request cbor"),
            &secret,
        ).await;
        assert_eq!(s_desc, axum::http::StatusCode::OK, "lifecycle descriptor issuance");
        HostedDescriptorResponseV1::from_canonical_cbor(&issued_cbor)
            .expect("lifecycle descriptor response")
            .descriptor()
            .clone()
    };

    // Voter 1 votes; a second ballot from the same credential (same
    // nullifier) is rejected exactly as before.
    let pkg_a = make_package(&f2, 1, b"candidate-a");
    let body_a = serde_json::json!({"receipt_id": "11111111-1111-4111-8111-111111111111", "package_cbor_hex": hex_encode(&pkg_a), "api_version": "v1"}).to_string();
    let (s1, r1) = req(
        public.clone(),
        "POST",
        &format!("/api/v1/elections/{election_id}/ballots"),
        Some(body_a),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(s1, axum::http::StatusCode::CREATED, "{r1}");
    let pkg_a2 = make_package(&f2, 1, b"candidate-b");
    let body_a2 = serde_json::json!({"receipt_id": "11111111-1111-4111-8111-111111111112", "package_cbor_hex": hex_encode(&pkg_a2), "api_version": "v1"}).to_string();
    let (s2, r2) = req(
        public.clone(),
        "POST",
        &format!("/api/v1/elections/{election_id}/ballots"),
        Some(body_a2),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(s2, axum::http::StatusCode::CONFLICT, "{r2}");
    assert!(
        r2.contains("duplicate_nullifier"),
        "duplicate-nullifier behavior unchanged: {r2}"
    );
    // Voter 2 votes.
    let pkg_b = make_package(&f2, 2, b"candidate-b");
    let body_b = serde_json::json!({"receipt_id": "11111111-1111-4111-8111-111111111113", "package_cbor_hex": hex_encode(&pkg_b), "api_version": "v1"}).to_string();
    let (s3, r3) = req(
        public.clone(),
        "POST",
        &format!("/api/v1/elections/{election_id}/ballots"),
        Some(body_b),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(s3, axum::http::StatusCode::CREATED, "{r3}");

    // Close, close-then-submit rejected, finalize.
    let (sc, vc) = organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/close"),
        None,
        Some(&secret),
    )
    .await;
    assert_eq!(sc, axum::http::StatusCode::OK, "{vc}");
    assert_eq!(vc["state"], "closed");
    // The shipped bridge starts with a capability-protected, public request
    // that carries only the exact Hosted election identity.  It is not
    // available to another organizer and it is not available before close.
    let (srequest_unauthorized, _) = organizer_call(
        &public,
        "GET",
        &format!("/api/v1/organizer/elections/{election_id}/binding-handoff"),
        None,
        Some(&organizer_secret(0x32)),
    )
    .await;
    assert_eq!(srequest_unauthorized, axum::http::StatusCode::UNAUTHORIZED);
    let (srequest, vrequest) = organizer_call(
        &public,
        "GET",
        &format!("/api/v1/organizer/elections/{election_id}/binding-handoff"),
        None,
        Some(&secret),
    )
    .await;
    assert_eq!(srequest, axum::http::StatusCode::OK, "{vrequest}");
    assert_eq!(
        vrequest["schema"].as_str(),
        Some(tari_cc_private_ballot_gui_core::HOSTED_BINDING_REQUEST_SCHEMA_V1)
    );
    assert_eq!(vrequest["election_id"].as_str(), Some(election_id));
    assert_eq!(
        vrequest["manifest_hash_hex"].as_str().unwrap_or("").len(),
        64
    );
    let pkg_c = make_package(&f2, 3, b"candidate-c");
    let body_c = serde_json::json!({"receipt_id": "11111111-1111-4111-8111-111111111114", "package_cbor_hex": hex_encode(&pkg_c), "api_version": "v1"}).to_string();
    let (s4, r4) = req(
        public.clone(),
        "POST",
        &format!("/api/v1/elections/{election_id}/ballots"),
        Some(body_c),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(s4, axum::http::StatusCode::CONFLICT, "{r4}");
    let (smissing, vmissing) = organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/finalize"),
        None,
        Some(&secret),
    )
    .await;
    assert_eq!(smissing, axum::http::StatusCode::CONFLICT, "{vmissing}");
    assert_eq!(vmissing["code"], "transport_binding_required");
    let lifecycle_binding_digests: Vec<[u8; 32]> = [&pkg_a, &pkg_b]
        .iter()
        .map(|p| hash_domain_separated(&Blake3HashProviderV1, HashDomain::BallotPackageV1, p))
        .collect();
    let lifecycle_transport_binding =
        finalized_transport_archive_binding_from_accepted_digests_v1(
            &issued_descriptor_lifecycle,
            &lifecycle_binding_digests,
        )
        .expect("lifecycle transport binding")
        .expect("non-empty lifecycle binding");
    let binding = lifecycle_transport_binding.to_canonical_cbor().expect("lifecycle binding cbor");
    let descriptor = issued_descriptor_lifecycle.to_canonical_cbor().expect("lifecycle descriptor cbor");
    let mut wrong_election_handoff: serde_json::Value =
        serde_json::from_str(&desktop_binding_handoff_json(&f2, &binding, &descriptor))
            .unwrap_or_else(|_| panic!("desktop binding handoff json"));
    wrong_election_handoff["election_id"] = serde_json::Value::String("other-election".to_owned());
    let (swrong_election, vwrong_election) = organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/transport-binding"),
        Some(wrong_election_handoff.to_string()),
        Some(&secret),
    )
    .await;
    assert_eq!(
        swrong_election,
        axum::http::StatusCode::CONFLICT,
        "{vwrong_election}"
    );
    assert_eq!(vwrong_election["code"], "transport_binding_required");
    let (smalformed_handoff, vmalformed_handoff) = organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/transport-binding"),
        Some("{\"schema\":\"wrong\"}".to_owned()),
        Some(&secret),
    )
    .await;
    assert_eq!(
        smalformed_handoff,
        axum::http::StatusCode::BAD_REQUEST,
        "{vmalformed_handoff}"
    );
    assert_eq!(vmalformed_handoff["code"], "invalid_request");
    let mut altered_binding = binding.clone();
    let last = altered_binding.len() - 1;
    altered_binding[last] ^= 1;
    let (saltered, valtered) = organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/transport-binding"),
        Some(desktop_binding_handoff_json(
            &f2,
            &altered_binding,
            &descriptor,
        )),
        Some(&secret),
    )
    .await;
    assert_eq!(saltered, axum::http::StatusCode::CONFLICT, "{valtered}");
    assert_eq!(valtered["code"], "transport_binding_required");
    // A different *canonical* binding with the same election and accepted
    // count cannot win a first-write race: its accepted digest set is not the
    // authenticated history held by Hosted.
    let wrong_lifecycle_digests: Vec<[u8; 32]> = [&pkg_a, &pkg_c]
        .iter()
        .map(|p| hash_domain_separated(&Blake3HashProviderV1, HashDomain::BallotPackageV1, p))
        .collect();
    let same_count_different_binding =
        finalized_transport_archive_binding_from_accepted_digests_v1(
            &issued_descriptor_lifecycle,
            &wrong_lifecycle_digests,
        )
        .expect("wrong-content binding")
        .expect("non-empty wrong-content binding")
        .to_canonical_cbor()
        .expect("wrong-content binding cbor");
    let (sdifferent, vdifferent) = organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/transport-binding"),
        Some(desktop_binding_handoff_json(
            &f2,
            &same_count_different_binding,
            &descriptor,
        )),
        Some(&secret),
    )
    .await;
    assert_eq!(sdifferent, axum::http::StatusCode::CONFLICT, "{vdifferent}");
    assert_eq!(vdifferent["code"], "transport_binding_required");
    let mut altered_descriptor = descriptor.clone();
    let descriptor_last = altered_descriptor.len() - 1;
    altered_descriptor[descriptor_last] ^= 1;
    let (sdescriptor, vdescriptor) = organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/transport-binding"),
        Some(desktop_binding_handoff_json(
            &f2,
            &binding,
            &altered_descriptor,
        )),
        Some(&secret),
    )
    .await;
    assert_eq!(
        sdescriptor,
        axum::http::StatusCode::CONFLICT,
        "{vdescriptor}"
    );
    assert_eq!(vdescriptor["code"], "transport_binding_required");
    let (sbinding, vbinding) = organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/transport-binding"),
        Some(desktop_binding_handoff_json(&f2, &binding, &descriptor)),
        Some(&secret),
    )
    .await;
    assert_eq!(sbinding, axum::http::StatusCode::CREATED, "{vbinding}");
    assert!(
        storage
            .get_finalized_transport_binding(election_id)
            .unwrap()
            .is_some()
    );
    let (sreplay, vreplay) = organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/transport-binding"),
        Some(desktop_binding_handoff_json(&f2, &binding, &descriptor)),
        Some(&secret),
    )
    .await;
    assert_eq!(sreplay, axum::http::StatusCode::CONFLICT, "{vreplay}");
    assert_eq!(vreplay["code"], "transport_binding_already_recorded");
    let (sconflict, vconflict) = organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/transport-binding"),
        Some(desktop_binding_handoff_json(
            &f2,
            &same_count_different_binding,
            &descriptor,
        )),
        Some(&secret),
    )
    .await;
    assert_eq!(sconflict, axum::http::StatusCode::CONFLICT, "{vconflict}");
    assert_eq!(vconflict["code"], "transport_binding_required");
    assert_eq!(
        storage
            .get_finalized_transport_binding(election_id)
            .unwrap()
            .expect("first finalized transport binding remains stored")
            .binding_cbor,
        binding,
        "a mismatched replay must not replace the stored binding"
    );
    let (sverified_status, vverified_status) = organizer_call(
        &public,
        "GET",
        &format!("/api/v1/organizer/elections/{election_id}"),
        None,
        Some(&secret),
    )
    .await;
    assert_eq!(
        sverified_status,
        axum::http::StatusCode::OK,
        "{vverified_status}"
    );
    assert_eq!(vverified_status["transport_binding_status"], "verified");

    // A separately authorized, normally closed election cannot accept A's
    // Desktop file merely because it carries otherwise authentic bytes.
    let election_b = "org-full-e2e-002";
    let secret_b = organizer_secret(0x33);
    organizer_create_ok(&public, election_b, &secret_b, 1).await;
    let (sopen_b, vopen_b) = organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_b}/open-enrollment"),
        None,
        Some(&secret_b),
    )
    .await;
    assert_eq!(sopen_b, axum::http::StatusCode::OK, "{vopen_b}");
    let (sinvite_b, vinvite_b) = organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_b}/invitations"),
        None,
        Some(&secret_b),
    )
    .await;
    assert_eq!(sinvite_b, axum::http::StatusCode::CREATED, "{vinvite_b}");
    let (senroll_b, venroll_b) = enroll(
        &public,
        election_b,
        vinvite_b["invitation_secret_hex"].as_str().unwrap_or(""),
        &enroll_key(7),
    )
    .await;
    assert_eq!(senroll_b, axum::http::StatusCode::CREATED, "{venroll_b}");
    let (sfreeze_b, vfreeze_b) = organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_b}/freeze"),
        None,
        Some(&secret_b),
    )
    .await;
    assert_eq!(sfreeze_b, axum::http::StatusCode::OK, "{vfreeze_b}");
    let (svote_b, vvote_b) = organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_b}/open-voting"),
        None,
        Some(&secret_b),
    )
    .await;
    assert_eq!(svote_b, axum::http::StatusCode::CREATED, "{vvote_b}");
    let (sclose_b, vclose_b) = organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_b}/close"),
        None,
        Some(&secret_b),
    )
    .await;
    assert_eq!(sclose_b, axum::http::StatusCode::OK, "{vclose_b}");
    let (scross, vcross) = organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_b}/transport-binding"),
        Some(desktop_binding_handoff_json(&f2, &binding, &descriptor)),
        Some(&secret_b),
    )
    .await;
    assert_eq!(scross, axum::http::StatusCode::CONFLICT, "{vcross}");
    assert_eq!(vcross["code"], "transport_binding_required");
    let (sfin, vfin) = organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/finalize"),
        None,
        Some(&secret),
    )
    .await;
    assert_eq!(sfin, axum::http::StatusCode::OK, "{vfin}");
    assert_eq!(vfin["state"], "finalized");
    assert_eq!(vfin["accepted_ballots"], 2);

    // Public results and archive still work after organizer-driven finalize.
    let (sres, vres) = organizer_call(
        &public,
        "GET",
        &format!("/api/v1/elections/{election_id}/results"),
        None,
        None,
    )
    .await;
    assert_eq!(sres, axum::http::StatusCode::OK, "{vres}");
    assert_eq!(vres["accepted_ballots"], 2);
    let counts = vres["counts"].as_array().unwrap();
    let total: u64 = counts.iter().filter_map(|c| c["approvals"].as_u64()).sum();
    assert_eq!(total, 2);
    let (sarch, varch) = organizer_call(
        &public,
        "GET",
        &format!("/api/v1/elections/{election_id}/archive"),
        None,
        None,
    )
    .await;
    assert_eq!(sarch, axum::http::StatusCode::OK, "{varch}");
    assert_eq!(varch["archive_hash_hex"].as_str().unwrap_or("").len(), 64);
    assert!(
        varch["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["path"].as_str().unwrap_or("").contains("manifest"))
    );

    // Continue through the real offline Desktop V2 preparation boundary using
    // only the archive that the normal organizer endpoint just finalized.
    // This intentionally does not construct an archive or insert a binding
    // through storage helpers.
    let dir = std::env::temp_dir().join(format!(
        "pb-hosted-organizer-handoff-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap_or_else(|_| panic!("mkdir"));
    let archive_manifest = hex_decode(varch["archive_manifest_cbor_hex"].as_str().unwrap_or(""))
        .unwrap_or_else(|_| panic!("archive manifest"));
    let archive_files = varch["files"]
        .as_array()
        .cloned()
        .unwrap_or_else(|| panic!("archive files"));
    write_archive_from_endpoint(&dir, &archive_files, &archive_manifest);
    assert!(verify_archive_dir_for_test(&dir));
    let desktop_payload =
        build_v2_public_payload_from_verified_archive_v1(&GuiLiveAnchorV2RequestV1 {
            archive_directory: dir.to_string_lossy().into_owned(),
            network: "mainnet".to_owned(),
            template_address:
                tari_cc_private_ballot_deployment_registry::MAINNET_V2_TEMPLATE_ADDRESS.to_owned(),
            template_module: ANCHOR_TEMPLATE_MODULE_V2.to_owned(),
            template_function: ANCHOR_EVENT_FUNCTION_V2.to_owned(),
            template_event_topic: format!(
                "{ANCHOR_TEMPLATE_MODULE_V2}.{ANCHOR_EVENT_TOPIC_SUFFIX_V2}"
            ),
            template_artifact_digest_hex:
                tari_cc_private_ballot_deployment_registry::MAINNET_V2_ARTIFACT_BLAKE3.to_owned(),
        })
        .expect("Desktop V2 payload from normal Hosted organizer archive");
    let artifact_digest: [u8; 32] =
        hex_decode(tari_cc_private_ballot_deployment_registry::MAINNET_V2_ARTIFACT_BLAKE3)
            .unwrap_or_else(|_| panic!("release digest"))
            .try_into()
            .unwrap_or_else(|_| panic!("release digest length"));
    let deployment = AnchorTemplateBindingV2::new(
        tari_cc_private_ballot_deployment_registry::MAINNET_V2_TEMPLATE_ADDRESS.to_owned(),
        ANCHOR_TEMPLATE_MODULE_V2.to_owned(),
        ANCHOR_EVENT_FUNCTION_V2.to_owned(),
        format!("{ANCHOR_TEMPLATE_MODULE_V2}.{ANCHOR_EVENT_TOPIC_SUFFIX_V2}"),
        artifact_digest,
    )
    .expect("release deployment binding");
    let prepared = prepare_v2_anchor_publish_from_verified_evidence_v1(
        &GuiV2AnchorPublishPreparationRequestV1 {
            archive_directory: dir.to_string_lossy().into_owned(),
            payload_hex: desktop_payload.payload_hex.clone(),
            expected_digest_hex: desktop_payload.v2_anchor_digest_hex.clone(),
        },
        &deployment,
    )
    .expect("Desktop V2 preparation from normal Hosted organizer archive");
    let loaded = crate::LoadedElection::load(storage.as_ref(), election_id)
        .unwrap_or_else(|_| panic!("finalized election loads"));
    let hosted_identity = crate::finalized_anchor_identity(&loaded, storage.as_ref())
        .unwrap_or_else(|_| panic!("Hosted identity derives"));
    assert_eq!(desktop_payload.election_id, election_id);
    assert_eq!(
        desktop_payload.archive_hash_hex,
        hosted_identity.archive_hash_hex
    );
    assert_eq!(
        desktop_payload.v2_anchor_digest_hex,
        hosted_identity.anchor_digest_hex
    );
    assert_eq!(
        prepared.arguments,
        vec![
            hosted_identity.anchor_digest_hex,
            "mainnet".to_owned(),
            election_id.to_owned(),
            hosted_identity.public_summary_json,
        ]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn organizer_cannot_perform_global_administration() {
    let f = fixture();
    let (routers, _storage) = test_routers();
    let public = routers.public.clone();
    let admin = routers.admin.clone();
    let secret = organizer_secret(0x41);
    organizer_create_ok(&public, "org-no-admin-001", &secret, 2).await;

    // Global admin routes do not exist on the public router at all.
    for path in [
        "/api/v1/admin/elections/draft",
        "/api/v1/admin/elections/import",
        "/api/v1/admin/elections/org-no-admin-001/close",
        "/api/v1/admin/elections/org-no-admin-001/freeze",
        "/api/v1/admin/elections/org-no-admin-001/finalize",
    ] {
        let (s, _) = req(
            public.clone(),
            "POST",
            path,
            Some("{}".to_owned()),
            &[
                ("content-type", "application/json"),
                ("x-admin-token", "test-admin-token"),
            ],
        )
        .await;
        assert_eq!(
            s,
            axum::http::StatusCode::NOT_FOUND,
            "public router must not serve {path}"
        );
    }

    // The organizer credential is NOT an admin token: on the loopback admin
    // plane it authorizes nothing.
    for path in [
        "/api/v1/admin/elections/draft",
        "/api/v1/admin/elections/import",
        "/api/v1/admin/elections/org-no-admin-001/close",
        "/api/v1/admin/elections/org-no-admin-001/finalize",
    ] {
        let (s, _) = req(
            admin.clone(),
            "POST",
            path,
            Some("{}".to_owned()),
            &[
                ("content-type", "application/json"),
                ("x-private-ballot-organizer", secret.as_str()),
            ],
        )
        .await;
        assert_eq!(
            s,
            axum::http::StatusCode::UNAUTHORIZED,
            "organizer credential must not grant admin: {path}"
        );
    }

    // An election the organizer did not create is invisible: even a draft
    // created on the admin plane cannot be read with a foreign credential.
    create_draft_and_open_enrollment(&admin, "org-no-admin-foreign", &f.candidate_cbor, 1).await;
    let (s2, v2) = organizer_call(
        &public,
        "GET",
        "/api/v1/organizer/elections/org-no-admin-foreign",
        None,
        Some(&secret),
    )
    .await;
    assert_eq!(s2, axum::http::StatusCode::UNAUTHORIZED, "{v2}");
}

#[tokio::test]
async fn organizer_request_logging_never_contains_secrets() {
    let (routers, _storage) = test_routers();
    let public = routers.public.clone();
    let secret = organizer_secret(0x51);
    organizer_create_ok(&public, "org-log-001", &secret, 2).await;
    organizer_call(
        &public,
        "POST",
        "/api/v1/organizer/elections/org-log-001/open-enrollment",
        None,
        Some(&secret),
    )
    .await;
    let (s, v) = organizer_call(
        &public,
        "POST",
        "/api/v1/organizer/elections/org-log-001/invitations",
        None,
        Some(&secret),
    )
    .await;
    assert_eq!(s, axum::http::StatusCode::CREATED, "{v}");
    let invitation_secret = v["invitation_secret_hex"].as_str().unwrap().to_owned();
    let lines = take_test_log_lines();
    assert!(!lines.is_empty(), "requests must be logged");
    for line in &lines {
        assert!(
            !line.contains(&secret),
            "log line must not contain organizer secret: {line}"
        );
        assert!(
            !line.contains(&invitation_secret),
            "log line must not contain invitation secret: {line}"
        );
        assert!(
            !line.contains("organizer_secret_hex"),
            "log line must not contain request body keys: {line}"
        );
        assert!(
            !line.contains("x-private-ballot-organizer"),
            "log line must not contain credential header: {line}"
        );
    }
    // The log line format is restricted to method/path/status/duration.
    let create_line = lines
        .iter()
        .find(|l| l.contains("POST") && l.contains("/api/v1/organizer/elections"))
        .unwrap();
    assert!(
        create_line.starts_with("hosted method=POST path="),
        "log format restricted: {create_line}"
    );
}

#[tokio::test]
async fn organizer_creation_and_slot_limits_enforced() {
    // Custom config with a tight self-service slot cap.
    let storage = Arc::new(InMemoryStorage::new());
    let mut cfg = test_config();
    cfg.organizer_max_slots = 5;
    let state = Arc::new(AppState::new(cfg, storage));
    let public = router_with_state(state);
    let secret = organizer_secret(0x61);

    let (s_over, v_over) = organizer_create(
        &public,
        "org-limit-over",
        &secret,
        6,
        &["candidate-a", "candidate-b", "candidate-c"],
    )
    .await;
    assert_eq!(s_over, axum::http::StatusCode::BAD_REQUEST, "{v_over}");
    let (s_ok, v_ok) = organizer_create(
        &public,
        "org-limit-ok",
        &secret,
        5,
        &["candidate-a", "candidate-b", "candidate-c"],
    )
    .await;
    assert_eq!(s_ok, axum::http::StatusCode::CREATED, "{v_ok}");

    // Config validation: organizer slot cap must be within bounds.
    let mut cfg = test_config();
    cfg.organizer_max_slots = 0;
    assert!(cfg.clone().validate().is_err());
    cfg.organizer_max_slots = crate::MAX_ORGANIZER_SLOTS_LIMIT + 1;
    assert!(cfg.clone().validate().is_err());
    cfg.organizer_max_slots = crate::MAX_ORGANIZER_SLOTS_LIMIT;
    assert!(cfg.validate().is_ok());
}

#[tokio::test]
async fn organizer_malformed_and_oversized_requests_rejected() {
    let (routers, _storage) = test_routers();
    let public = routers.public.clone();
    let secret = organizer_secret(0x71);
    let good_options = ["candidate-a", "candidate-b", "candidate-c"];

    // Malformed JSON
    let (s1, _) = req(
        public.clone(),
        "POST",
        "/api/v1/organizer/elections",
        Some("{not json".to_owned()),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(s1, axum::http::StatusCode::BAD_REQUEST);
    // Missing required fields
    let (s2, _) = req(
        public.clone(),
        "POST",
        "/api/v1/organizer/elections",
        Some(serde_json::json!({"election_id": "x"}).to_string()),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(s2, axum::http::StatusCode::BAD_REQUEST);
    // Invalid election_id characters
    let (s3, v3) = organizer_create(&public, "bad id!", &secret, 1, &good_options).await;
    assert_eq!(s3, axum::http::StatusCode::BAD_REQUEST, "{v3}");
    // Oversized election_id
    let long_id: String = "a".repeat(200);
    let (s4, _) = organizer_create(&public, &long_id, &secret, 1, &good_options).await;
    assert_eq!(s4, axum::http::StatusCode::BAD_REQUEST);
    // Invalid secret (not hex / wrong length)
    let (s5, _) = organizer_create(&public, "org-malformed-1", "not-hex", 1, &good_options).await;
    assert_eq!(s5, axum::http::StatusCode::BAD_REQUEST);
    let (s6, _) = organizer_create(
        &public,
        "org-malformed-2",
        &hex_encode(&[9u8; 16]),
        1,
        &good_options,
    )
    .await;
    assert_eq!(s6, axum::http::StatusCode::BAD_REQUEST);
    // Empty options
    let (s7, _) = organizer_create(&public, "org-malformed-3", &secret, 1, &[]).await;
    assert_eq!(s7, axum::http::StatusCode::BAD_REQUEST);
    // Duplicate option names
    let (s8, _) = organizer_create(&public, "org-malformed-4", &secret, 1, &["Yes", "Yes"]).await;
    assert_eq!(s8, axum::http::StatusCode::BAD_REQUEST);
    // Empty option name
    let (s9, _) = organizer_create(&public, "org-malformed-5", &secret, 1, &["Yes", "   "]).await;
    assert_eq!(s9, axum::http::StatusCode::BAD_REQUEST);
    // Approval limits: min > max and max > option count
    let body = serde_json::json!({
        "election_id": "org-malformed-6", "options": good_options, "organizer_secret_hex": secret,
        "min_approvals": 2, "max_approvals": 1, "authorized_slot_count": 1,
    })
    .to_string();
    let (s10, _) = req(
        public.clone(),
        "POST",
        "/api/v1/organizer/elections",
        Some(body),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(s10, axum::http::StatusCode::BAD_REQUEST);
    let body = serde_json::json!({
        "election_id": "org-malformed-7", "options": ["a", "b"], "organizer_secret_hex": secret,
        "min_approvals": 2, "max_approvals": 3, "authorized_slot_count": 1,
    })
    .to_string();
    let (s11, _) = req(
        public.clone(),
        "POST",
        "/api/v1/organizer/elections",
        Some(body),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(s11, axum::http::StatusCode::BAD_REQUEST);
    // Slot count 0 rejected
    let (s12, _) = organizer_create(&public, "org-malformed-8", &secret, 0, &good_options).await;
    assert_eq!(s12, axum::http::StatusCode::BAD_REQUEST);
    // Hosted self-service archives do not carry governance source bytes, so
    // content-digest pins must be rejected rather than exported as unproven.
    let content_pin_body = serde_json::json!({
        "election_id": "org-content-pin-unsupported",
        "options": good_options,
        "organizer_secret_hex": secret,
        "min_approvals": 1,
        "max_approvals": 1,
        "authorized_slot_count": 1,
        "governance_revision": format!("blake3:{}", "0".repeat(64)),
        "proposal_question": "Should the content-pin validation fire?",
    })
    .to_string();
    let (content_pin_status, content_pin_response) = req(
        public.clone(),
        "POST",
        "/api/v1/organizer/elections",
        Some(content_pin_body),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(content_pin_status, axum::http::StatusCode::BAD_REQUEST);
    let content_pin_json: serde_json::Value = serde_json::from_str(&content_pin_response).unwrap();
    assert_eq!(
        content_pin_json["code"],
        "unsupported_governance_content_pin"
    );
    // Oversized body (> 64 KiB) rejected
    let big_options: Vec<String> = (0..2000)
        .map(|i| format!("option-{i}-{}", "x".repeat(64)))
        .collect();
    let big_body = serde_json::json!({
        "election_id": "org-oversized", "options": big_options, "organizer_secret_hex": secret,
        "authorized_slot_count": 1,
    })
    .to_string();
    assert!(big_body.len() > 64 * 1024);
    let (s13, _) = req(
        public.clone(),
        "POST",
        "/api/v1/organizer/elections",
        Some(big_body),
        &[("content-type", "application/json")],
    )
    .await;
    assert!(
        s13 == axum::http::StatusCode::PAYLOAD_TOO_LARGE
            || s13 == axum::http::StatusCode::BAD_REQUEST,
        "oversized body must be rejected, got {s13}"
    );
}

#[test]
fn sqlite_migration_v3_to_v4_preserves_staging_data() {
    let dir = std::env::temp_dir().join(format!("pb-hosted-migration-v3-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap_or_else(|_| panic!("mkdir"));
    let db = dir.join("migration.db");

    // Simulate an existing schema v3 staging database with real-looking rows.
    {
        let legacy = Connection::open(&db).unwrap_or_else(|_| panic!("open v3"));
        legacy.execute_batch(
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE elections (
                id TEXT PRIMARY KEY, manifest_cbor BLOB NOT NULL, registry_cbor BLOB NOT NULL,
                candidate_cbor BLOB NOT NULL, state TEXT NOT NULL, manifest_hash_hex TEXT NOT NULL
             );
             CREATE TABLE ballots (
                election_id TEXT NOT NULL, receipt_id TEXT NOT NULL, package_cbor BLOB NOT NULL,
                envelope_hash_hex TEXT NOT NULL, nullifier BLOB NOT NULL, seq INTEGER NOT NULL,
                PRIMARY KEY (election_id, receipt_id), UNIQUE (election_id, nullifier),
                FOREIGN KEY (election_id) REFERENCES elections(id)
             );
             CREATE TABLE election_drafts (
                election_id TEXT PRIMARY KEY, candidate_cbor BLOB NOT NULL, proof_suite_id TEXT NOT NULL,
                min_approvals INTEGER NOT NULL DEFAULT 1, max_approvals INTEGER NOT NULL DEFAULT 1,
                allow_abstention INTEGER NOT NULL DEFAULT 1, governance_revision TEXT NOT NULL DEFAULT '',
                authorized_slot_count INTEGER NOT NULL, external_roster_commitment_hex TEXT,
                eligibility_state TEXT NOT NULL DEFAULT 'DRAFT', created_at_ms INTEGER NOT NULL
             );
             CREATE TABLE eligibility_slots (
                slot_id TEXT PRIMARY KEY, election_id TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0,
                created_at_ms INTEGER NOT NULL, FOREIGN KEY (election_id) REFERENCES election_drafts(election_id)
             );
             CREATE TABLE enrollment_invitations (
                invitation_id TEXT PRIMARY KEY, slot_id TEXT NOT NULL, election_id TEXT NOT NULL,
                verifier_hex TEXT NOT NULL UNIQUE, state TEXT NOT NULL DEFAULT 'ACTIVE', created_at_ms INTEGER NOT NULL,
                FOREIGN KEY (slot_id) REFERENCES eligibility_slots(slot_id),
                FOREIGN KEY (election_id) REFERENCES election_drafts(election_id)
             );
             CREATE TABLE enrolled_credentials (
                election_id TEXT NOT NULL, public_key_hex TEXT NOT NULL, slot_id TEXT, invitation_id TEXT,
                enrolled_at_ms INTEGER NOT NULL, PRIMARY KEY (election_id, public_key_hex)
             );
             CREATE TABLE frozen_registries (
                election_id TEXT PRIMARY KEY, registry_cbor_hex TEXT NOT NULL, registry_commitment_hex TEXT NOT NULL,
                authorized_slot_count INTEGER NOT NULL, enrolled_count INTEGER NOT NULL, frozen_at_ms INTEGER NOT NULL,
                external_roster_commitment_hex TEXT
             );",
        ).unwrap_or_else(|_| panic!("create v3 schema"));
        legacy
            .execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', '3')",
                [],
            )
            .unwrap_or_else(|_| panic!("v3 version"));
        legacy.execute(
            "INSERT INTO election_drafts (election_id, candidate_cbor, proof_suite_id, min_approvals, max_approvals, allow_abstention, governance_revision, authorized_slot_count, external_roster_commitment_hex, eligibility_state, created_at_ms) VALUES (?1, ?2, ?3, 1, 1, 1, 'legacy-rev', 4, NULL, 'ENROLLMENT_OPEN', 1000)",
            params!["legacy-draft", vec![1_u8], TARI_TRIPTYCH_PROOF_SUITE_ID_V1],
        ).unwrap_or_else(|_| panic!("v3 draft"));
        legacy.execute(
            "INSERT INTO eligibility_slots (slot_id, election_id, consumed, created_at_ms) VALUES (?1, 'legacy-draft', 1, 1001)",
            params!["legacy-slot"],
        ).unwrap_or_else(|_| panic!("v3 slot"));
        legacy.execute(
            "INSERT INTO enrollment_invitations (invitation_id, slot_id, election_id, verifier_hex, state, created_at_ms) VALUES (?1, 'legacy-slot', 'legacy-draft', 'legacy-verifier', 'CONSUMED', 1002)",
            params!["legacy-invitation"],
        ).unwrap_or_else(|_| panic!("v3 invitation"));
        legacy.execute(
            "INSERT INTO enrolled_credentials (election_id, public_key_hex, slot_id, invitation_id, enrolled_at_ms) VALUES ('legacy-draft', 'legacy-key', 'legacy-slot', 'legacy-invitation', 1003)",
            [],
        ).unwrap_or_else(|_| panic!("v3 credential"));
    }

    // First open migrates to v4 and preserves every v3 record.
    {
        let storage = crate::SqliteStorage::open(&db).unwrap_or_else(|_| panic!("migrate v3->v4"));
        let draft = storage.get_election_draft("legacy-draft").unwrap().unwrap();
        assert_eq!(draft.eligibility_state, "ENROLLMENT_OPEN");
        assert_eq!(draft.authorized_slot_count, 4);
        assert_eq!(draft.governance_revision, "legacy-rev");
        let slots = storage.list_slots("legacy-draft").unwrap();
        assert_eq!(slots.len(), 1);
        assert!(slots[0].consumed);
        let invitation = storage
            .get_invitation_by_id("legacy-invitation")
            .unwrap()
            .unwrap();
        assert_eq!(invitation.state, "CONSUMED");
        assert_eq!(invitation.verifier_hex, "legacy-verifier");
        let creds = storage.list_enrolled_credentials("legacy-draft").unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].public_key_hex, "legacy-key");
        assert!(creds[0].slot_id.is_some(), "pre-freeze linkage preserved");
        // New v4 capacity exists: an organizer credential can be added.
        storage
            .put_organizer_credential(crate::storage::OrganizerCredentialRecord {
                election_id: "legacy-draft".to_owned(),
                organizer_verifier_hex: "v4-verifier".to_owned(),
                created_at_ms: 2000,
            })
            .unwrap_or_else(|_| panic!("v4 insert after migration"));
    }

    // Version bumped to 6 and the organizer and finalized-binding tables exist.
    {
        let conn = Connection::open(&db).unwrap_or_else(|_| panic!("inspect v4"));
        let version: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap_or_else(|_| panic!("schema version"));
        assert_eq!(version, "6");
        let exists: i64 = conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'organizer_credentials'", [], |r| r.get(0)).unwrap_or_else(|_| panic!("table lookup"));
        assert_eq!(exists, 1);
    }

    // Reopen advances to 7: data intact.
    {
        let storage = crate::SqliteStorage::open(&db).unwrap_or_else(|_| panic!("reopen v4"));
        assert!(
            storage
                .get_election_draft("legacy-draft")
                .unwrap()
                .is_some()
        );
        assert_eq!(
            storage
                .get_invitation_by_id("legacy-invitation")
                .unwrap()
                .unwrap()
                .state,
            "CONSUMED"
        );
        assert!(
            storage
                .get_organizer_credential("legacy-draft")
                .unwrap()
                .is_some()
        );
        let conn = Connection::open(&db).unwrap_or_else(|_| panic!("inspect after reopen"));
        let version: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap_or_else(|_| panic!("schema version"));
        assert_eq!(version, "7");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn in_memory_organizer_credential_operations() {
    let storage = InMemoryStorage::new();
    assert!(storage.get_organizer_credential("nope").unwrap().is_none());
    storage
        .put_organizer_credential(crate::storage::OrganizerCredentialRecord {
            election_id: "e".to_owned(),
            organizer_verifier_hex: "v".to_owned(),
            created_at_ms: 1,
        })
        .unwrap_or_else(|_| panic!("put"));
    assert_eq!(
        storage
            .get_organizer_credential("e")
            .unwrap()
            .unwrap()
            .organizer_verifier_hex,
        "v"
    );
    assert!(matches!(
        storage.put_organizer_credential(crate::storage::OrganizerCredentialRecord {
            election_id: "e".to_owned(),
            organizer_verifier_hex: "v2".to_owned(),
            created_at_ms: 2,
        }),
        Err(crate::StorageError::ElectionExists)
    ));
    assert!(storage.get_invitation_by_id("missing").unwrap().is_none());
    assert_eq!(storage.list_invitations("e").unwrap().len(), 0);
}

// ---------------------------------------------------------------------------
// Section 9: Organizer-to-voter V2 bundle integration test (17 steps, no
// fixtures). Exercises the complete pipeline:
//   organizer creates V2 election → opens enrollment → freezes → opens voting
//   → issues descriptor → voter fetches bundle → bundle verifies end-to-end.
// ---------------------------------------------------------------------------

/// Builds an unsigned descriptor draft for the given election under the test
/// authority key (key_id = "hosted-test-root").
fn make_descriptor_draft_for(
    election_id_bytes: &[u8],
    manifest_hash: tari_cc_private_ballot_protocol::ManifestHash,
) -> TransportDescriptorV1 {
    TransportDescriptorV1::unsigned_for_authority(
        election_id_bytes.to_vec(),
        manifest_hash,
        1,
        TransportRoutePolicyV1::ManagedTorOrOffline,
        vec!["2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion".to_owned()],
        Vec::new(),
        [0x07_u8; 32],
        "integration-test-gateway".to_owned(),
        vec![[0x08_u8; 32]],
        PaddingPolicyV1 {
            id: "integration-padding".to_owned(),
            padded_bytes: 2048,
        },
        BatchPolicyV1 {
            id: "integration-batch".to_owned(),
            accepted_unique_floor: 1,
        },
        None,
        "hosted-test-root".to_owned(),
    )
    .unwrap_or_else(|_| panic!("descriptor draft"))
}

#[tokio::test]
async fn organizer_to_voter_v2_bundle_pipeline_end_to_end() {
    // Step 1: Set up test state with a Pinned authority root and signing key.
    let (routers, storage) = test_routers();
    let public = routers.public;
    let election_id = "v2-bundle-e2e-001";
    let organizer = organizer_secret(0x91);

    // Step 2: Organizer creates a V2 election (proposal_question is non-empty →
    // the manifest will be ElectionManifestV2 with a proposal_question).
    organizer_create_ok(&public, election_id, &organizer, 3).await;

    // Step 3: Open enrollment.
    assert_eq!(
        organizer_call(
            &public,
            "POST",
            &format!("/api/v1/organizer/elections/{election_id}/open-enrollment"),
            None,
            Some(&organizer),
        )
        .await
        .0,
        axum::http::StatusCode::OK
    );

    // Step 4: Issue an invitation.
    let (_, invitation) = organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/invitations"),
        None,
        Some(&organizer),
    )
    .await;
    let inv_secret = invitation["invitation_secret_hex"]
        .as_str()
        .unwrap_or_else(|| panic!("invitation secret"));

    // Step 5: Enroll a voter.
    assert_eq!(
        enroll(&public, election_id, inv_secret, &enroll_key(1))
            .await
            .0,
        axum::http::StatusCode::CREATED
    );

    // Step 6: Freeze the registry.
    assert_eq!(
        organizer_call(
            &public,
            "POST",
            &format!("/api/v1/organizer/elections/{election_id}/freeze"),
            None,
            Some(&organizer),
        )
        .await
        .0,
        axum::http::StatusCode::OK
    );

    // Step 7: Open voting (election state → "open"). Returns 201 CREATED.
    assert_eq!(
        organizer_call(
            &public,
            "POST",
            &format!("/api/v1/organizer/elections/{election_id}/open-voting"),
            None,
            Some(&organizer),
        )
        .await
        .0,
        axum::http::StatusCode::CREATED
    );

    // Step 8: Confirm voter-bundle is not yet available (no issuance recorded).
    let (pre_status, _) = req_bytes(
        public.clone(),
        "GET",
        &format!("/api/v1/elections/{election_id}/voter-bundle"),
        &[],
    )
    .await;
    assert_eq!(
        pre_status,
        axum::http::StatusCode::CONFLICT,
        "voter-bundle without prior descriptor issuance must return 409"
    );

    // Step 9: Load election record to derive manifest hash and election_id.
    let record = storage
        .get_election(election_id)
        .unwrap_or_else(|_| panic!("storage"))
        .unwrap_or_else(|| panic!("election record"));
    let manifest = ElectionManifest::from_canonical_cbor(&record.manifest_cbor)
        .unwrap_or_else(|_| panic!("manifest parse"));
    let manifest_hash = manifest
        .canonical_hash(&Blake3HashProviderV1)
        .unwrap_or_else(|_| panic!("manifest hash"));

    // Step 10: Confirm this is a V2 manifest (proposal_question must be Some).
    assert!(
        manifest.proposal_question().is_some(),
        "organizer_create_ok must produce a V2 election"
    );
    assert_eq!(
        manifest.proposal_question(),
        Some("Should the self-service test proposal pass?")
    );

    // Step 11: Build and submit a descriptor issuance request.
    let election_id_bytes = manifest.election_id().as_bytes().to_vec();
    let draft = make_descriptor_draft_for(&election_id_bytes, manifest_hash);
    let request = HostedDescriptorRequestV1::new([0x91_u8; 32], "test".to_owned(), draft)
        .unwrap_or_else(|_| panic!("descriptor request"));
    let request_cbor = request.to_canonical_cbor().unwrap_or_else(|_| panic!("request cbor"));
    let (issuance_status, issued_cbor) = req_cbor(
        public.clone(),
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/descriptor-issuance"),
        request_cbor,
        &organizer,
    )
    .await;
    assert_eq!(
        issuance_status,
        axum::http::StatusCode::OK,
        "descriptor issuance must succeed"
    );

    // Step 12: Decode and verify the issued descriptor response.
    let response = HostedDescriptorResponseV1::from_canonical_cbor(&issued_cbor)
        .unwrap_or_else(|_| panic!("descriptor response decode"));
    assert_eq!(response.request_id(), request.request_id());
    response
        .descriptor()
        .verify(&test_transport_root(), manifest_hash)
        .unwrap_or_else(|_| panic!("descriptor verify under test root"));

    // Step 13: GET /api/v1/elections/{id}/voter-bundle — now must succeed.
    let (bundle_status, bundle_cbor) = req_bytes(
        public.clone(),
        "GET",
        &format!("/api/v1/elections/{election_id}/voter-bundle"),
        &[],
    )
    .await;
    assert_eq!(
        bundle_status,
        axum::http::StatusCode::OK,
        "voter-bundle must be available after descriptor issuance"
    );
    assert!(
        !bundle_cbor.is_empty(),
        "voter-bundle body must not be empty"
    );

    // Step 14: Decode the bundle.
    let bundle = HostedVoterPublicBundleV2::from_canonical_cbor(&bundle_cbor)
        .unwrap_or_else(|_| panic!("voter bundle decode"));

    // Step 15: Fully verify the bundle — all 10 security checks.
    let verified = bundle.verify().unwrap_or_else(|_| panic!("voter bundle verify"));

    // Step 16: Assert the verified bundle's election artifacts match the
    // authoritative election record.
    assert_eq!(
        verified.descriptor.election_id(),
        election_id_bytes.as_slice(),
        "verified descriptor election_id must match the election"
    );
    assert_eq!(
        verified.descriptor.manifest_hash(),
        manifest_hash,
        "verified descriptor manifest_hash must match the election"
    );
    assert_eq!(
        verified.artifacts.manifest().election_id().as_bytes(),
        election_id_bytes.as_slice(),
        "verified artifacts election_id must match"
    );
    assert_eq!(
        verified.artifacts.manifest_hash().as_bytes(),
        manifest_hash.as_bytes(),
        "verified artifacts manifest_hash must match"
    );

    // Step 17: Assert the authority root is Pinned (never ProductionNotProvisioned).
    assert!(
        matches!(verified.root, TransportAuthorityRootV1::Pinned { .. }),
        "authority root must be Pinned"
    );

    // Idempotency: a second GET must return the identical canonical CBOR bytes.
    let (bundle_status2, bundle_cbor2) = req_bytes(
        public.clone(),
        "GET",
        &format!("/api/v1/elections/{election_id}/voter-bundle"),
        &[],
    )
    .await;
    assert_eq!(bundle_status2, axum::http::StatusCode::OK);
    assert_eq!(bundle_cbor, bundle_cbor2, "voter-bundle must be idempotent");

    // --- Negative gate: closed election must reject the voter-bundle request ---
    organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/close"),
        None,
        Some(&organizer),
    )
    .await;
    let (closed_status, _) = req_bytes(
        public.clone(),
        "GET",
        &format!("/api/v1/elections/{election_id}/voter-bundle"),
        &[],
    )
    .await;
    assert_eq!(
        closed_status,
        axum::http::StatusCode::CONFLICT,
        "voter-bundle must be unavailable for a closed election"
    );
}

#[tokio::test]
async fn voter_bundle_requires_descriptor_issuance_before_serving() {
    // Separate from the main e2e test to verify the specific 409 path.
    let (routers, _storage) = test_routers();
    let public = routers.public;
    let election_id = "v2-bundle-no-issuance-001";
    let organizer = organizer_secret(0x92);

    organizer_create_ok(&public, election_id, &organizer, 1).await;
    organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/open-enrollment"),
        None,
        Some(&organizer),
    )
    .await;
    let (_, invitation) = organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/invitations"),
        None,
        Some(&organizer),
    )
    .await;
    let inv_secret = invitation["invitation_secret_hex"]
        .as_str()
        .unwrap_or_else(|| panic!("inv secret"));
    enroll(&public, election_id, inv_secret, &enroll_key(2)).await;
    for action in ["freeze", "open-voting"] {
        organizer_call(
            &public,
            "POST",
            &format!("/api/v1/organizer/elections/{election_id}/{action}"),
            None,
            Some(&organizer),
        )
        .await;
    }
    // Open, V2, but NO descriptor issuance → must 409.
    let (status, _) = req_bytes(
        public,
        "GET",
        &format!("/api/v1/elections/{election_id}/voter-bundle"),
        &[],
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::CONFLICT,
        "open election with no descriptor issuance must 409"
    );
}

#[tokio::test]
async fn voter_bundle_unavailable_for_non_open_elections() {
    // A closed election (state="closed" in elections table) must reject voter-bundle with 409.
    // Draft elections are not in the elections table at all and return 404 from LoadedElection::load,
    // so we must advance to "open" and then close to get the state-gate 409.
    let (routers, _storage) = test_routers();
    let public = routers.public;
    let election_id = "v2-bundle-state-gate-001";
    let organizer = organizer_secret(0x93);

    organizer_create_ok(&public, election_id, &organizer, 1).await;
    organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/open-enrollment"),
        None,
        Some(&organizer),
    )
    .await;
    let (_, invitation) = organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/invitations"),
        None,
        Some(&organizer),
    )
    .await;
    let inv_secret = invitation["invitation_secret_hex"]
        .as_str()
        .unwrap_or_else(|| panic!("inv secret"));
    enroll(&public, election_id, inv_secret, &enroll_key(3)).await;
    for action in ["freeze", "open-voting"] {
        organizer_call(
            &public,
            "POST",
            &format!("/api/v1/organizer/elections/{election_id}/{action}"),
            None,
            Some(&organizer),
        )
        .await;
    }
    // Now close the election so state="closed" in the elections table.
    organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/close"),
        None,
        Some(&organizer),
    )
    .await;
    // Closed election must 409 (state gate fires before descriptor check).
    let (closed_status, _) = req_bytes(
        public.clone(),
        "GET",
        &format!("/api/v1/elections/{election_id}/voter-bundle"),
        &[],
    )
    .await;
    assert_eq!(
        closed_status,
        axum::http::StatusCode::CONFLICT,
        "closed election must not serve voter-bundle"
    );
}

// ── Section 10: Organizer archive endpoint – negative security matrix ─────────

#[tokio::test]
async fn organizer_archive_requires_credential() {
    // GET /api/v1/organizer/elections/{id}/archive must reject with 401 when no
    // organizer credential header is present.
    let (routers, _storage) = test_routers();
    let public = routers.public;
    let election_id = "org-archive-auth-001";
    let secret = organizer_secret(0x41);
    organizer_create_ok(&public, election_id, &secret, 1).await;

    // No credential header → 401.
    let (s_no_cred, _) = req(
        public.clone(),
        "GET",
        &format!("/api/v1/organizer/elections/{election_id}/archive"),
        None,
        &[],
    )
    .await;
    assert_eq!(
        s_no_cred,
        axum::http::StatusCode::UNAUTHORIZED,
        "missing credential must be 401"
    );

    // Wrong credential header → 401.
    let wrong_secret = organizer_secret(0x99);
    let (s_wrong, _) = req(
        public.clone(),
        "GET",
        &format!("/api/v1/organizer/elections/{election_id}/archive"),
        None,
        &[("x-private-ballot-organizer", wrong_secret.as_str())],
    )
    .await;
    assert_eq!(
        s_wrong,
        axum::http::StatusCode::UNAUTHORIZED,
        "wrong credential must be 401"
    );
}

#[tokio::test]
async fn organizer_archive_requires_finalized_election() {
    // GET /api/v1/organizer/elections/{id}/archive must return 409 when the
    // election is in the elections table but has not been finalized.
    // We advance to "open" state (which writes the election into the elections
    // table) so that check_organizer passes and LoadedElection::load succeeds,
    // then verify that the state gate returns 409.
    let (routers, _storage) = test_routers();
    let public = routers.public;
    let election_id = "org-archive-state-001";
    let secret = organizer_secret(0x42);
    organizer_create_ok(&public, election_id, &secret, 1).await;
    organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/open-enrollment"),
        None,
        Some(&secret),
    )
    .await;
    // Issue one invitation and enroll one voter so freeze/open can proceed.
    let (_, inv) = organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/invitations"),
        None,
        Some(&secret),
    )
    .await;
    let inv_secret = inv["invitation_secret_hex"].as_str().unwrap_or("").to_owned();
    enroll(&public, election_id, &inv_secret, &enroll_key(7)).await;
    for action in ["freeze", "open-voting"] {
        organizer_call(
            &public,
            "POST",
            &format!("/api/v1/organizer/elections/{election_id}/{action}"),
            None,
            Some(&secret),
        )
        .await;
    }

    // Election is now "open" (in the elections table) but not yet finalized → 409.
    let (s_open, v_open) = organizer_call(
        &public,
        "GET",
        &format!("/api/v1/organizer/elections/{election_id}/archive"),
        None,
        Some(&secret),
    )
    .await;
    assert_eq!(
        s_open,
        axum::http::StatusCode::CONFLICT,
        "non-finalized election must be 409: {v_open}"
    );
    assert_eq!(v_open["code"], "election_not_finalized");
}

#[tokio::test]
async fn organizer_archive_nonexistent_election_is_401() {
    // For a nonexistent election, check_organizer fires first and returns 401
    // (no stored credential → fail-closed, same response as wrong credential).
    // The endpoint never reveals whether the election exists via the organizer plane.
    let (routers, _storage) = test_routers();
    let public = routers.public;
    let secret = organizer_secret(0x43);

    let (s, _) = organizer_call(
        &public,
        "GET",
        "/api/v1/organizer/elections/does-not-exist-000/archive",
        None,
        Some(&secret),
    )
    .await;
    assert_eq!(s, axum::http::StatusCode::UNAUTHORIZED, "nonexistent election has no stored credential → 401 (fail-closed)");
}

// ── Section 12: Full e2e – organizer archive endpoint → verify → V2 anchor ───

#[tokio::test]
async fn organizer_archive_endpoint_full_e2e_v2_anchor() {
    // Verifies the new organizer-authenticated archive endpoint through the
    // complete release boundary:
    //   organizer create → enroll → freeze → open-voting → vote × 2 → close
    //   → transport-binding → finalize
    //   → GET /api/v1/organizer/elections/{id}/archive (organizer-authenticated)
    //   → write_archive_from_endpoint → verify_archive_dir_for_test
    //   → build_v2_public_payload_from_verified_archive_v1
    //   → prepare_v2_anchor_publish_from_verified_evidence_v1
    //   → cross-check: archive_hash and anchor_digest match Hosted identity
    let (routers, storage) = test_routers();
    let public = routers.public.clone();
    let secret = organizer_secret(0x51);
    let election_id = "org-archive-e2e-001";

    organizer_create_ok(&public, election_id, &secret, 3).await;
    organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/open-enrollment"),
        None,
        Some(&secret),
    )
    .await;

    // Enroll two voters.
    let mut invitation_secrets = Vec::new();
    for _ in 0..2 {
        let (s, v) = organizer_call(
            &public,
            "POST",
            &format!("/api/v1/organizer/elections/{election_id}/invitations"),
            None,
            Some(&secret),
        )
        .await;
        assert_eq!(s, axum::http::StatusCode::CREATED, "{v}");
        invitation_secrets.push(v["invitation_secret_hex"].as_str().unwrap().to_owned());
    }
    for (i, invitation) in invitation_secrets.iter().enumerate() {
        let (s, v) = enroll(&public, election_id, invitation, &enroll_key((i + 1) as u64)).await;
        assert_eq!(s, axum::http::StatusCode::CREATED, "{v}");
    }

    // Freeze → open-voting.
    let (sf, vf) = organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/freeze"),
        None,
        Some(&secret),
    )
    .await;
    assert_eq!(sf, axum::http::StatusCode::OK, "{vf}");
    let (sv, vv) = organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/open-voting"),
        None,
        Some(&secret),
    )
    .await;
    assert_eq!(sv, axum::http::StatusCode::CREATED, "{vv}");

    // Fetch frozen manifest so ballot packages use the correct registry hash.
    let (sp, vp) = req(
        public.clone(),
        "GET",
        &format!("/api/v1/elections/{election_id}"),
        None,
        &[],
    )
    .await;
    assert_eq!(sp, axum::http::StatusCode::OK, "{vp}");
    let pkg_json: serde_json::Value =
        serde_json::from_str(&vp).unwrap_or_else(|_| panic!("package json"));
    let f2 = Fixture {
        election_id: election_id.to_owned(),
        manifest_cbor: hex_decode(pkg_json["manifest_cbor_hex"].as_str().unwrap()).unwrap(),
        registry_cbor: hex_decode(pkg_json["registry_cbor_hex"].as_str().unwrap()).unwrap(),
        candidate_cbor: hex_decode(pkg_json["candidate_cbor_hex"].as_str().unwrap()).unwrap(),
    };

    // Two voters cast ballots.
    let pkg_a = make_package(&f2, 1, b"candidate-a");
    let (s1, r1) = req(
        public.clone(),
        "POST",
        &format!("/api/v1/elections/{election_id}/ballots"),
        Some(serde_json::json!({"receipt_id": "22222222-2222-4222-8222-222222222221", "package_cbor_hex": hex_encode(&pkg_a), "api_version": "v1"}).to_string()),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(s1, axum::http::StatusCode::CREATED, "{r1}");
    let pkg_b = make_package(&f2, 2, b"candidate-b");
    let (s2, r2) = req(
        public.clone(),
        "POST",
        &format!("/api/v1/elections/{election_id}/ballots"),
        Some(serde_json::json!({"receipt_id": "22222222-2222-4222-8222-222222222222", "package_cbor_hex": hex_encode(&pkg_b), "api_version": "v1"}).to_string()),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(s2, axum::http::StatusCode::CREATED, "{r2}");

    // Issue the authoritative Hosted descriptor while the election is still open.
    let issued_descriptor_archive = {
        let manifest = ElectionManifest::from_canonical_cbor(&f2.manifest_cbor)
            .expect("archive manifest");
        let manifest_hash = manifest.canonical_hash(&Blake3HashProviderV1).expect("archive hash");
        let draft = TransportDescriptorV1::unsigned_for_authority(
            election_id.as_bytes().to_vec(),
            manifest_hash,
            1,
            TransportRoutePolicyV1::ManagedTorOrOffline,
            vec!["http://test.invalid".to_owned()],
            Vec::new(),
            [7; 32],
            "hosted-test-gateway".to_owned(),
            vec![[8; 32]],
            PaddingPolicyV1 { id: "test-padding".to_owned(), padded_bytes: 2048 },
            BatchPolicyV1 { id: "test-batch".to_owned(), accepted_unique_floor: 1 },
            None,
            "hosted-test-root".to_owned(),
        ).expect("archive descriptor draft");
        let request = HostedDescriptorRequestV1::new(
            [0x51; 32],
            "test".to_owned(),
            draft,
        ).expect("archive descriptor request");
        let path = format!("/api/v1/organizer/elections/{election_id}/descriptor-issuance");
        let (s_desc, issued_cbor) = req_cbor(
            public.clone(),
            "POST",
            &path,
            request.to_canonical_cbor().expect("archive request cbor"),
            &secret,
        ).await;
        assert_eq!(s_desc, axum::http::StatusCode::OK, "archive descriptor issuance");
        HostedDescriptorResponseV1::from_canonical_cbor(&issued_cbor)
            .expect("archive descriptor response")
            .descriptor()
            .clone()
    };

    // Close → submit transport binding → finalize.
    let (sc, vc) = organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/close"),
        None,
        Some(&secret),
    )
    .await;
    assert_eq!(sc, axum::http::StatusCode::OK, "{vc}");
    let archive_binding_digests: Vec<[u8; 32]> = [&pkg_a, &pkg_b]
        .iter()
        .map(|p| hash_domain_separated(&Blake3HashProviderV1, HashDomain::BallotPackageV1, p))
        .collect();
    let archive_transport_binding =
        finalized_transport_archive_binding_from_accepted_digests_v1(
            &issued_descriptor_archive,
            &archive_binding_digests,
        )
        .expect("archive transport binding")
        .expect("non-empty archive binding");
    let binding = archive_transport_binding.to_canonical_cbor().expect("archive binding cbor");
    let descriptor = issued_descriptor_archive.to_canonical_cbor().expect("archive descriptor cbor");
    let (sbind, vbind) = organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/transport-binding"),
        Some(desktop_binding_handoff_json(&f2, &binding, &descriptor)),
        Some(&secret),
    )
    .await;
    assert_eq!(sbind, axum::http::StatusCode::CREATED, "{vbind}");
    let (sfin, vfin) = organizer_call(
        &public,
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/finalize"),
        None,
        Some(&secret),
    )
    .await;
    assert_eq!(sfin, axum::http::StatusCode::OK, "{vfin}");
    assert_eq!(vfin["state"], "finalized");

    // ── Organizer-authenticated archive endpoint ──────────────────────────────
    // This is the new endpoint under test. Same body shape as the public one,
    // but gated on the election-scoped organizer credential.
    let (sarch, varch) = organizer_call(
        &public,
        "GET",
        &format!("/api/v1/organizer/elections/{election_id}/archive"),
        None,
        Some(&secret),
    )
    .await;
    assert_eq!(sarch, axum::http::StatusCode::OK, "{varch}");
    assert_eq!(varch["election_id"].as_str(), Some(election_id));
    assert_eq!(varch["archive_hash_hex"].as_str().unwrap_or("").len(), 64);
    assert!(varch["anchor_eligible"].as_bool().unwrap_or(false), "transport-bound election must be anchor-eligible");
    assert!(
        varch["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["path"].as_str().unwrap_or("").contains("manifest")),
        "archive body must include the archive-manifest file"
    );

    // Cross-check: organizer endpoint body matches public endpoint body.
    let (spub, vpub) = organizer_call(
        &public,
        "GET",
        &format!("/api/v1/elections/{election_id}/archive"),
        None,
        None,
    )
    .await;
    assert_eq!(spub, axum::http::StatusCode::OK, "{vpub}");
    assert_eq!(
        varch["archive_hash_hex"],
        vpub["archive_hash_hex"],
        "organizer and public endpoints must return identical archive hash"
    );

    // ── Write to staging directory → verify → V2 anchor preparation ──────────
    let dir = std::env::temp_dir().join(format!("pb-org-archive-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap_or_else(|_| panic!("mkdir"));
    let archive_manifest =
        hex_decode(varch["archive_manifest_cbor_hex"].as_str().unwrap_or(""))
            .unwrap_or_else(|_| panic!("archive manifest hex"));
    let archive_files = varch["files"]
        .as_array()
        .cloned()
        .unwrap_or_else(|| panic!("archive files"));
    write_archive_from_endpoint(&dir, &archive_files, &archive_manifest);
    assert!(
        verify_archive_dir_for_test(&dir),
        "archive written from organizer endpoint must pass verify_archive_dir_for_test"
    );

    let desktop_payload =
        build_v2_public_payload_from_verified_archive_v1(&GuiLiveAnchorV2RequestV1 {
            archive_directory: dir.to_string_lossy().into_owned(),
            network: "mainnet".to_owned(),
            template_address:
                tari_cc_private_ballot_deployment_registry::MAINNET_V2_TEMPLATE_ADDRESS.to_owned(),
            template_module: tari_cc_private_ballot_anchor_transport::ANCHOR_TEMPLATE_MODULE_V2.to_owned(),
            template_function: tari_cc_private_ballot_anchor_transport::ANCHOR_EVENT_FUNCTION_V2.to_owned(),
            template_event_topic: format!(
                "{}.{}",
                tari_cc_private_ballot_anchor_transport::ANCHOR_TEMPLATE_MODULE_V2,
                tari_cc_private_ballot_anchor_transport::ANCHOR_EVENT_TOPIC_SUFFIX_V2
            ),
            template_artifact_digest_hex:
                tari_cc_private_ballot_deployment_registry::MAINNET_V2_ARTIFACT_BLAKE3.to_owned(),
        })
        .expect("V2 payload must build from organizer-endpoint archive");

    let artifact_digest: [u8; 32] =
        hex_decode(tari_cc_private_ballot_deployment_registry::MAINNET_V2_ARTIFACT_BLAKE3)
            .unwrap_or_else(|_| panic!("release digest"))
            .try_into()
            .unwrap_or_else(|_| panic!("release digest length"));
    let deployment = tari_cc_private_ballot_anchor_transport::AnchorTemplateBindingV2::new(
        tari_cc_private_ballot_deployment_registry::MAINNET_V2_TEMPLATE_ADDRESS.to_owned(),
        tari_cc_private_ballot_anchor_transport::ANCHOR_TEMPLATE_MODULE_V2.to_owned(),
        tari_cc_private_ballot_anchor_transport::ANCHOR_EVENT_FUNCTION_V2.to_owned(),
        format!(
            "{}.{}",
            tari_cc_private_ballot_anchor_transport::ANCHOR_TEMPLATE_MODULE_V2,
            tari_cc_private_ballot_anchor_transport::ANCHOR_EVENT_TOPIC_SUFFIX_V2
        ),
        artifact_digest,
    )
    .expect("release deployment binding");
    let prepared = prepare_v2_anchor_publish_from_verified_evidence_v1(
        &GuiV2AnchorPublishPreparationRequestV1 {
            archive_directory: dir.to_string_lossy().into_owned(),
            payload_hex: desktop_payload.payload_hex.clone(),
            expected_digest_hex: desktop_payload.v2_anchor_digest_hex.clone(),
        },
        &deployment,
    )
    .expect("V2 anchor preparation must succeed from organizer-endpoint archive");

    // Final cross-check: Desktop-derived archive hash matches Hosted identity.
    let loaded = crate::LoadedElection::load(storage.as_ref(), election_id)
        .unwrap_or_else(|_| panic!("finalized election loads"));
    let hosted_identity = crate::finalized_anchor_identity(&loaded, storage.as_ref())
        .unwrap_or_else(|_| panic!("Hosted identity derives"));
    assert_eq!(desktop_payload.election_id, election_id);
    assert_eq!(
        desktop_payload.archive_hash_hex,
        hosted_identity.archive_hash_hex,
        "Desktop archive hash must match Hosted identity"
    );
    assert_eq!(
        desktop_payload.v2_anchor_digest_hex,
        hosted_identity.anchor_digest_hex,
        "Desktop anchor digest must match Hosted identity"
    );
    assert_eq!(
        prepared.arguments,
        vec![
            hosted_identity.anchor_digest_hex.clone(),
            "mainnet".to_owned(),
            election_id.to_owned(),
            hosted_identity.public_summary_json.clone(),
        ],
        "V2 anchor arguments must match Hosted identity"
    );

    // ── Section 3: "Connect enabled" gate ────────────────────────────────────
    // Feed the exact Desktop export artifact (desktop_payload.payload_hex) into
    // verify_v2_public_payload_against_archive_v1. This is the Connect gate: it
    // verifies the exported payload against the archive imported from the
    // production organizer endpoint. Hosted derives its expected identity
    // independently via finalized_anchor_identity — no field is copied from the
    // Desktop export.
    let connect_result = verify_v2_public_payload_against_archive_v1(
        &dir,
        &hex_decode(&desktop_payload.payload_hex).expect("Desktop export must hex-decode"),
        &desktop_payload.v2_anchor_digest_hex,
    )
    .expect("Connect must become enabled: authentic payload must verify against imported archive");
    // 7-field identity cross-check (all must agree for Connect to be enabled).
    assert_eq!(connect_result.election_id, election_id, "Connect: election ID");
    assert_eq!(
        connect_result.archive_hash_hex, hosted_identity.archive_hash_hex,
        "Connect: archive identity"
    );
    assert_eq!(
        connect_result.v2_anchor_digest_hex, hosted_identity.anchor_digest_hex,
        "Connect: anchor digest"
    );
    assert_eq!(connect_result.network, "mainnet", "Connect: network");
    assert_eq!(
        connect_result.public_summary_json, hosted_identity.public_summary_json,
        "Connect: public summary"
    );
    assert_eq!(
        connect_result.template_address,
        tari_cc_private_ballot_deployment_registry::MAINNET_V2_TEMPLATE_ADDRESS,
        "Connect: deployment address"
    );
    assert_eq!(
        connect_result.template_artifact_digest_hex,
        tari_cc_private_ballot_deployment_registry::MAINNET_V2_ARTIFACT_BLAKE3,
        "Connect: artifact digest"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ── Section 13: Legacy V4 regression – no transport binding → anchor_eligible=false ──

#[tokio::test]
async fn organizer_archive_legacy_v4_anchor_not_eligible() {
    // A finalized V4 election (no transport binding) must still be served by
    // the public archive endpoint with anchor_eligible=false, and the
    // organizer-authenticated archive endpoint must return 401 (admin-imported
    // elections have no organizer credential).
    let f = fixture();
    let (routers, storage) = test_routers();
    assert_eq!(
        import(routers.admin.clone(), &f).await,
        axum::http::StatusCode::CREATED
    );
    let election_id = &f.election_id;

    // Advance to finalized state via storage (V4 path: no transport binding).
    assert!(storage.set_election_state(election_id, "open", "closed").unwrap());
    assert!(storage.set_election_state(election_id, "closed", "finalized").unwrap());

    // Public archive endpoint must report anchor_eligible=false.
    let (spub, vpub) = req(
        routers.public.clone(),
        "GET",
        &format!("/api/v1/elections/{election_id}/archive"),
        None,
        &[],
    )
    .await;
    assert_eq!(spub, axum::http::StatusCode::OK, "{vpub}");
    let vpub_json: serde_json::Value = serde_json::from_str(&vpub).unwrap();
    assert_eq!(vpub_json["anchor_eligible"], false, "V4 public archive must not be anchor-eligible");

    // Organizer-authenticated endpoint returns 401 (no organizer credential
    // was registered for an admin-imported V4 election).
    let organizer = organizer_secret(0x61);
    let (sorg, _) = req(
        routers.public.clone(),
        "GET",
        &format!("/api/v1/organizer/elections/{election_id}/archive"),
        None,
        &[("x-private-ballot-organizer", organizer.as_str())],
    )
    .await;
    assert_eq!(
        sorg,
        axum::http::StatusCode::UNAUTHORIZED,
        "V4 admin-imported election has no organizer credential → 401"
    );
}

// ── Section 4: Real-export negative matrix ───────────────────────────────────
// Uses the REAL Desktop export from an organizer-authenticated archive.
// Mutates one field at a time; every mutation must fail
// verify_v2_public_payload_against_archive_v1 before Connect is enabled.
// DO NOT use bundleFixture(). DO NOT use manually supplied digests.

#[tokio::test]
async fn desktop_export_to_hosted_connect_negative_matrix() {
    // Build a real Desktop export through the production organizer endpoint path.
    let (routers, _storage) = test_routers();
    let public = routers.public.clone();
    let secret = organizer_secret(0xA1);
    let election_id = "org-neg-matrix-001";

    organizer_create_ok(&public, election_id, &secret, 2).await;
    organizer_call(&public, "POST",
        &format!("/api/v1/organizer/elections/{election_id}/open-enrollment"),
        None, Some(&secret)).await;
    let mut inv_secrets = Vec::new();
    for _ in 0..2usize {
        let (s, v) = organizer_call(&public, "POST",
            &format!("/api/v1/organizer/elections/{election_id}/invitations"),
            None, Some(&secret)).await;
        assert_eq!(s, axum::http::StatusCode::CREATED, "{v}");
        inv_secrets.push(v["invitation_secret_hex"].as_str().unwrap().to_owned());
    }
    for (i, inv) in inv_secrets.iter().enumerate() {
        let (s, v) = enroll(&public, election_id, inv, &enroll_key((i + 1) as u64)).await;
        assert_eq!(s, axum::http::StatusCode::CREATED, "{v}");
    }
    organizer_call(&public, "POST",
        &format!("/api/v1/organizer/elections/{election_id}/freeze"),
        None, Some(&secret)).await;
    organizer_call(&public, "POST",
        &format!("/api/v1/organizer/elections/{election_id}/open-voting"),
        None, Some(&secret)).await;

    let (sp, vp) = req(public.clone(), "GET",
        &format!("/api/v1/elections/{election_id}"), None, &[]).await;
    assert_eq!(sp, axum::http::StatusCode::OK, "{vp}");
    let pkg_json: serde_json::Value = serde_json::from_str(&vp).unwrap();
    let f_nm = Fixture {
        election_id: election_id.to_owned(),
        manifest_cbor: hex_decode(pkg_json["manifest_cbor_hex"].as_str().unwrap()).unwrap(),
        registry_cbor: hex_decode(pkg_json["registry_cbor_hex"].as_str().unwrap()).unwrap(),
        candidate_cbor: hex_decode(pkg_json["candidate_cbor_hex"].as_str().unwrap()).unwrap(),
    };
    let pkg_a = make_package(&f_nm, 1, b"candidate-a");
    let pkg_b = make_package(&f_nm, 2, b"candidate-b");
    let (s1, r1) = req(public.clone(), "POST",
        &format!("/api/v1/elections/{election_id}/ballots"),
        Some(serde_json::json!({"receipt_id": "aa000000-0000-4000-8000-000000000001", "package_cbor_hex": hex_encode(&pkg_a), "api_version": "v1"}).to_string()),
        &[("content-type", "application/json")]).await;
    assert_eq!(s1, axum::http::StatusCode::CREATED, "{r1}");
    let (s2, r2) = req(public.clone(), "POST",
        &format!("/api/v1/elections/{election_id}/ballots"),
        Some(serde_json::json!({"receipt_id": "aa000000-0000-4000-8000-000000000002", "package_cbor_hex": hex_encode(&pkg_b), "api_version": "v1"}).to_string()),
        &[("content-type", "application/json")]).await;
    assert_eq!(s2, axum::http::StatusCode::CREATED, "{r2}");

    // Issue the authoritative Hosted descriptor while the election is still open.
    let issued_descriptor_neg = {
        let manifest = ElectionManifest::from_canonical_cbor(&f_nm.manifest_cbor)
            .expect("neg-matrix manifest");
        let manifest_hash = manifest.canonical_hash(&Blake3HashProviderV1).expect("neg-matrix hash");
        let draft = TransportDescriptorV1::unsigned_for_authority(
            election_id.as_bytes().to_vec(),
            manifest_hash,
            1,
            TransportRoutePolicyV1::ManagedTorOrOffline,
            vec!["http://test.invalid".to_owned()],
            Vec::new(),
            [7; 32],
            "hosted-test-gateway".to_owned(),
            vec![[8; 32]],
            PaddingPolicyV1 { id: "test-padding".to_owned(), padded_bytes: 2048 },
            BatchPolicyV1 { id: "test-batch".to_owned(), accepted_unique_floor: 1 },
            None,
            "hosted-test-root".to_owned(),
        ).expect("neg-matrix descriptor draft");
        let request = HostedDescriptorRequestV1::new(
            [0xA1; 32],
            "test".to_owned(),
            draft,
        ).expect("neg-matrix descriptor request");
        let path = format!("/api/v1/organizer/elections/{election_id}/descriptor-issuance");
        let (s_desc, issued_cbor) = req_cbor(
            public.clone(),
            "POST",
            &path,
            request.to_canonical_cbor().expect("neg-matrix request cbor"),
            &secret,
        ).await;
        assert_eq!(s_desc, axum::http::StatusCode::OK, "neg-matrix descriptor issuance");
        HostedDescriptorResponseV1::from_canonical_cbor(&issued_cbor)
            .expect("neg-matrix descriptor response")
            .descriptor()
            .clone()
    };

    organizer_call(&public, "POST",
        &format!("/api/v1/organizer/elections/{election_id}/close"),
        None, Some(&secret)).await;
    let neg_binding_digests: Vec<[u8; 32]> = [&pkg_a, &pkg_b]
        .iter()
        .map(|p| hash_domain_separated(&Blake3HashProviderV1, HashDomain::BallotPackageV1, p))
        .collect();
    let neg_transport_binding =
        finalized_transport_archive_binding_from_accepted_digests_v1(
            &issued_descriptor_neg,
            &neg_binding_digests,
        )
        .expect("neg-matrix transport binding")
        .expect("non-empty neg-matrix binding");
    let binding = neg_transport_binding.to_canonical_cbor().expect("neg-matrix binding cbor");
    let descriptor = issued_descriptor_neg.to_canonical_cbor().expect("neg-matrix descriptor cbor");
    organizer_call(&public, "POST",
        &format!("/api/v1/organizer/elections/{election_id}/transport-binding"),
        Some(desktop_binding_handoff_json(&f_nm, &binding, &descriptor)),
        Some(&secret)).await;
    organizer_call(&public, "POST",
        &format!("/api/v1/organizer/elections/{election_id}/finalize"),
        None, Some(&secret)).await;

    let (_, varch) = organizer_call(&public, "GET",
        &format!("/api/v1/organizer/elections/{election_id}/archive"),
        None, Some(&secret)).await;
    let dir = std::env::temp_dir().join(format!("pb-neg-matrix-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let archive_manifest =
        hex_decode(varch["archive_manifest_cbor_hex"].as_str().unwrap_or("")).expect("manifest hex");
    let archive_files = varch["files"].as_array().cloned().unwrap_or_else(|| panic!("archive files"));
    write_archive_from_endpoint(&dir, &archive_files, &archive_manifest);
    assert!(verify_archive_dir_for_test(&dir));

    let desktop_payload = build_v2_public_payload_from_verified_archive_v1(&GuiLiveAnchorV2RequestV1 {
        archive_directory: dir.to_string_lossy().into_owned(),
        network: "mainnet".to_owned(),
        template_address: tari_cc_private_ballot_deployment_registry::MAINNET_V2_TEMPLATE_ADDRESS.to_owned(),
        template_module: tari_cc_private_ballot_anchor_transport::ANCHOR_TEMPLATE_MODULE_V2.to_owned(),
        template_function: tari_cc_private_ballot_anchor_transport::ANCHOR_EVENT_FUNCTION_V2.to_owned(),
        template_event_topic: format!("{}.{}",
            tari_cc_private_ballot_anchor_transport::ANCHOR_TEMPLATE_MODULE_V2,
            tari_cc_private_ballot_anchor_transport::ANCHOR_EVENT_TOPIC_SUFFIX_V2),
        template_artifact_digest_hex:
            tari_cc_private_ballot_deployment_registry::MAINNET_V2_ARTIFACT_BLAKE3.to_owned(),
    }).expect("real Desktop export must build from organizer-endpoint archive");

    let payload_bytes = hex_decode(&desktop_payload.payload_hex).expect("payload hex");
    let digest = desktop_payload.v2_anchor_digest_hex.clone();

    // Decode the real export as a mutable struct for field-level mutations.
    let canonical = OotleAnchorPublicPayloadV2::from_canonical_json_bytes(&payload_bytes)
        .expect("real export must decode as canonical payload");

    // Mutation 1: election ID.
    {
        let mut p = canonical.clone();
        p.election_id = b"wrong-election-00".to_vec();
        let tampered = p.to_canonical_json_bytes().expect("re-encode");
        assert!(
            verify_v2_public_payload_against_archive_v1(&dir, &tampered, &digest).is_err(),
            "mutation [election id] must fail before Connect"
        );
    }

    // Mutation 2: archive identity (archive_hash field).
    {
        let mut p = canonical.clone();
        p.archive_hash = ArchiveHashV1::new([0xABu8; 32]);
        let tampered = p.to_canonical_json_bytes().expect("re-encode");
        assert!(
            verify_v2_public_payload_against_archive_v1(&dir, &tampered, &digest).is_err(),
            "mutation [archive identity] must fail before Connect"
        );
    }

    // Mutation 3: transport binding (registry_commitment is derived from the binding).
    {
        let mut p = canonical.clone();
        p.registry_commitment[0] ^= 0xFF;
        let tampered = p.to_canonical_json_bytes().expect("re-encode");
        assert!(
            verify_v2_public_payload_against_archive_v1(&dir, &tampered, &digest).is_err(),
            "mutation [transport binding (registry_commitment)] must fail before Connect"
        );
    }

    // Mutation 4: anchor digest.
    {
        assert!(
            verify_v2_public_payload_against_archive_v1(&dir, &payload_bytes, &"ab".repeat(32)).is_err(),
            "mutation [anchor digest] must fail before Connect"
        );
    }

    // Mutation 5: network.
    {
        let mut p = canonical.clone();
        p.network = OotleNetworkIdV1::new("stagenet".to_owned()).expect("valid network id");
        let tampered = p.to_canonical_json_bytes().expect("re-encode");
        assert!(
            verify_v2_public_payload_against_archive_v1(&dir, &tampered, &digest).is_err(),
            "mutation [network] must fail before Connect"
        );
    }

    // Mutation 6: public summary (ballot_question is part of the public summary payload).
    {
        let mut p = canonical.clone();
        p.ballot_question = "Tampered question for negative-matrix test".to_owned();
        let tampered = p.to_canonical_json_bytes().expect("re-encode");
        assert!(
            verify_v2_public_payload_against_archive_v1(&dir, &tampered, &digest).is_err(),
            "mutation [public summary (ballot_question)] must fail before Connect"
        );
    }

    // Mutation 7: deployment identity (template_address).
    {
        let mut p = canonical.clone();
        p.template.template_address = "0".repeat(66);
        let tampered = p.to_canonical_json_bytes().expect("re-encode");
        assert!(
            verify_v2_public_payload_against_archive_v1(&dir, &tampered, &digest).is_err(),
            "mutation [deployment identity (template_address)] must fail before Connect"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

// ── Section 5: True release flow through Connect ──────────────────────────────
// Full V2 flow: organizer bootstrap download + Desktop organizer import →
// descriptor request → authenticated Hosted issuance → Desktop signed-response
// import → V2 voter bundle → fresh voter import → ballot cast → close →
// real binding handoff → finalize → organizer-authenticated archive fetch →
// Desktop archive import → archive verification → V2 preparation →
// actual Desktop browser-anchor export → Hosted Manage → independent Hosted
// identity validation → Connect enabled.
// No wallet transaction required.

#[tokio::test]
async fn organizer_full_v2_release_flow_through_connect() {
    let (routers, storage) = test_routers();
    let public = routers.public.clone();
    let secret = organizer_secret(0xA2);
    let election_id = "v2-connect-flow-001";

    // ── 1. Full Hosted V2 creation ────────────────────────────────────────────
    organizer_create_ok(&public, election_id, &secret, 2).await;
    organizer_call(&public, "POST",
        &format!("/api/v1/organizer/elections/{election_id}/open-enrollment"),
        None, Some(&secret)).await;

    // ── 2. Enroll two voters ──────────────────────────────────────────────────
    let mut inv_secrets = Vec::new();
    for _ in 0..2usize {
        let (s, v) = organizer_call(&public, "POST",
            &format!("/api/v1/organizer/elections/{election_id}/invitations"),
            None, Some(&secret)).await;
        assert_eq!(s, axum::http::StatusCode::CREATED, "{v}");
        inv_secrets.push(v["invitation_secret_hex"].as_str().unwrap().to_owned());
    }
    for (i, inv) in inv_secrets.iter().enumerate() {
        let (s, v) = enroll(&public, election_id, inv, &enroll_key((i + 1) as u64)).await;
        assert_eq!(s, axum::http::StatusCode::CREATED, "{v}");
    }

    // ── 3. Freeze → open voting ───────────────────────────────────────────────
    let (sf, vf) = organizer_call(&public, "POST",
        &format!("/api/v1/organizer/elections/{election_id}/freeze"),
        None, Some(&secret)).await;
    assert_eq!(sf, axum::http::StatusCode::OK, "{vf}");
    let (sv, vv) = organizer_call(&public, "POST",
        &format!("/api/v1/organizer/elections/{election_id}/open-voting"),
        None, Some(&secret)).await;
    assert_eq!(sv, axum::http::StatusCode::CREATED, "{vv}");

    // ── 4. Organizer bootstrap + Desktop organizer import ─────────────────────
    // Bootstrap is only available once the election is open (state = "open").
    let (s_boot, boot_bytes) = req_bytes(
        public.clone(),
        "GET",
        &format!("/api/v1/organizer/elections/{election_id}/desktop-bootstrap"),
        &[("x-private-ballot-organizer", &secret)],
    ).await;
    assert_eq!(s_boot, axum::http::StatusCode::OK, "bootstrap endpoint");
    let bootstrap = HostedOrganizerBootstrapV1::from_canonical_cbor(&boot_bytes)
        .expect("bootstrap must decode");
    let boot_artifacts = bootstrap
        .verify(&tari_cc_private_ballot_gui_core::TransportAuthorityRootSetV1::new(
            test_transport_root(),
        ))
        .expect("bootstrap must verify under test root");
    assert_eq!(
        boot_artifacts.manifest().election_id().as_bytes(),
        election_id.as_bytes(),
        "bootstrap election ID must match"
    );

    // ── 5. Descriptor request → authenticated Hosted issuance ─────────────────
    // Build a gateway receiver key from a known test secret so the descriptor's
    // public key is HPKE-derivable, enabling the full V2 transport path in step 8.
    let gateway_receiver = GatewayReceiverKeyV1::from_secret_bytes([0x07_u8; 32])
        .expect("test gateway receiver key must be valid");
    let gateway_pk = gateway_receiver.receiver_public_key();
    let record = storage.get_election(election_id).unwrap().unwrap();
    let manifest = tari_cc_private_ballot_ballot::ElectionManifest::from_canonical_cbor(
        &record.manifest_cbor,
    ).expect("manifest parse");
    let manifest_hash = manifest.canonical_hash(&Blake3HashProviderV1).expect("manifest hash");
    let election_id_bytes = manifest.election_id().as_bytes().to_vec();
    // Use the DERIVED public key so the descriptor can be used for sealing envelopes.
    let draft = TransportDescriptorV1::unsigned_for_authority(
        election_id_bytes.clone(),
        manifest_hash,
        1,
        TransportRoutePolicyV1::ManagedTorOrOffline,
        vec!["2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion".to_owned()],
        Vec::new(),
        gateway_pk,
        "integration-test-gateway".to_owned(),
        vec![[0x08_u8; 32]],
        PaddingPolicyV1 {
            id: "integration-padding".to_owned(),
            padded_bytes: 2048,
        },
        BatchPolicyV1 {
            id: "integration-batch".to_owned(),
            accepted_unique_floor: 1,
        },
        None,
        "hosted-test-root".to_owned(),
    ).expect("descriptor draft");
    let request = HostedDescriptorRequestV1::new(
        [0xA2_u8; 32],
        "test".to_owned(),
        draft,
    ).expect("descriptor request");
    let request_cbor = request.to_canonical_cbor().expect("request cbor");
    let (s_desc, issued_cbor) = req_cbor(
        public.clone(),
        "POST",
        &format!("/api/v1/organizer/elections/{election_id}/descriptor-issuance"),
        request_cbor,
        &secret,
    ).await;
    assert_eq!(s_desc, axum::http::StatusCode::OK, "descriptor issuance");

    // ── 6. Desktop signed-response import ─────────────────────────────────────
    let response = HostedDescriptorResponseV1::from_canonical_cbor(&issued_cbor)
        .expect("descriptor response decode");
    assert_eq!(response.request_id(), request.request_id());
    response
        .descriptor()
        .verify(&test_transport_root(), manifest_hash)
        .expect("descriptor must verify under test root");
    // Keep the issued descriptor: steps 8 and 9 must use it, not a fresh one.
    let issued_descriptor = response.descriptor().clone();

    // ── 7. V2 voter bundle (confirms production intake path is live) ───────────
    let (s_bundle, bundle_cbor) = req_bytes(
        public.clone(),
        "GET",
        &format!("/api/v1/elections/{election_id}/voter-bundle"),
        &[],
    ).await;
    assert_eq!(s_bundle, axum::http::StatusCode::OK, "voter bundle");
    let bundle = HostedVoterPublicBundleV2::from_canonical_cbor(&bundle_cbor)
        .expect("voter bundle decode");
    let verified_bundle = bundle.verify().expect("voter bundle must verify");
    assert_eq!(verified_bundle.descriptor.election_id(), election_id.as_bytes());

    // ── 8. V2 transport path: seal → transport intake simulation → ballot relay ──
    // Voters seal ballot packages using the issued descriptor's gateway public key.
    // The Desktop organizer opens the envelopes via its Tor gateway (simulated here
    // with open_envelope_bytes_v1) and relays the decrypted packages to Hosted.
    let (sp, vp) = req(public.clone(), "GET",
        &format!("/api/v1/elections/{election_id}"), None, &[]).await;
    assert_eq!(sp, axum::http::StatusCode::OK, "{vp}");
    let pkg_json: serde_json::Value = serde_json::from_str(&vp).unwrap();
    let f_v2 = Fixture {
        election_id: election_id.to_owned(),
        manifest_cbor: hex_decode(pkg_json["manifest_cbor_hex"].as_str().unwrap()).unwrap(),
        registry_cbor: hex_decode(pkg_json["registry_cbor_hex"].as_str().unwrap()).unwrap(),
        candidate_cbor: hex_decode(pkg_json["candidate_cbor_hex"].as_str().unwrap()).unwrap(),
    };
    let pkg_a = make_package(&f_v2, 1, b"candidate-a");
    // 8a. Voter seals ballot package for Tor transport.
    let envelope_a = PrivateBallotEnvelopeV1::seal(&issued_descriptor, &pkg_a)
        .expect("envelope seal for voter A");
    let envelope_a_cbor = envelope_a.to_canonical_cbor().expect("envelope A encode");
    // 8b. Desktop Tor gateway opens the envelope (simulates organizer intake).
    let relay_a = open_envelope_bytes_v1(
        &PrivateBallotEnvelopeV1::from_canonical_cbor(&envelope_a_cbor)
            .expect("envelope A decode"),
        &issued_descriptor,
        &gateway_receiver,
    ).expect("envelope A open");
    assert_eq!(relay_a, pkg_a, "transport round-trip must preserve ballot package");
    // 8c. Desktop relays the ballot to Hosted's ledger.
    let (s1, r1) = req(public.clone(), "POST",
        &format!("/api/v1/elections/{election_id}/ballots"),
        Some(serde_json::json!({
            "receipt_id": "bb000000-0000-4000-8000-000000000001",
            "package_cbor_hex": hex_encode(&relay_a),
            "api_version": "v1",
        }).to_string()),
        &[("content-type", "application/json")]).await;
    assert_eq!(s1, axum::http::StatusCode::CREATED, "{r1}");
    let pkg_b = make_package(&f_v2, 2, b"candidate-b");
    // Voter B: same seal → open → relay path.
    let envelope_b = PrivateBallotEnvelopeV1::seal(&issued_descriptor, &pkg_b)
        .expect("envelope seal for voter B");
    let envelope_b_cbor = envelope_b.to_canonical_cbor().expect("envelope B encode");
    let relay_b = open_envelope_bytes_v1(
        &PrivateBallotEnvelopeV1::from_canonical_cbor(&envelope_b_cbor)
            .expect("envelope B decode"),
        &issued_descriptor,
        &gateway_receiver,
    ).expect("envelope B open");
    assert_eq!(relay_b, pkg_b, "transport round-trip must preserve ballot package");
    let (s2, r2) = req(public.clone(), "POST",
        &format!("/api/v1/elections/{election_id}/ballots"),
        Some(serde_json::json!({
            "receipt_id": "bb000000-0000-4000-8000-000000000002",
            "package_cbor_hex": hex_encode(&relay_b),
            "api_version": "v1",
        }).to_string()),
        &[("content-type", "application/json")]).await;
    assert_eq!(s2, axum::http::StatusCode::CREATED, "{r2}");

    // ── 9. Close → real binding handoff (using ISSUED descriptor) → finalize ────
    // After Fix #3 the binding must use the EXACT descriptor issued in step 5-6.
    // Build the transport binding from the issued descriptor and the actual relayed
    // ballot packages; do NOT create a fresh independent descriptor here.
    let (sc, vc) = organizer_call(&public, "POST",
        &format!("/api/v1/organizer/elections/{election_id}/close"),
        None, Some(&secret)).await;
    assert_eq!(sc, axum::http::StatusCode::OK, "{vc}");
    let binding_digests: Vec<[u8; 32]> = [&pkg_a, &pkg_b]
        .iter()
        .map(|p| hash_domain_separated(&Blake3HashProviderV1, HashDomain::BallotPackageV1, p))
        .collect();
    let transport_binding =
        finalized_transport_archive_binding_from_accepted_digests_v1(&issued_descriptor, &binding_digests)
            .expect("transport binding computation")
            .expect("non-empty accepted packages");
    let binding = transport_binding.to_canonical_cbor().expect("binding cbor");
    let descriptor = issued_descriptor.to_canonical_cbor().expect("issued descriptor cbor");
    let (sbind, vbind) = organizer_call(&public, "POST",
        &format!("/api/v1/organizer/elections/{election_id}/transport-binding"),
        Some(desktop_binding_handoff_json(&f_v2, &binding, &descriptor)),
        Some(&secret)).await;
    assert_eq!(sbind, axum::http::StatusCode::CREATED, "{vbind}");
    let (sfin, vfin) = organizer_call(&public, "POST",
        &format!("/api/v1/organizer/elections/{election_id}/finalize"),
        None, Some(&secret)).await;
    assert_eq!(sfin, axum::http::StatusCode::OK, "{vfin}");
    assert_eq!(vfin["state"], "finalized");

    // ── 10. Organizer-authenticated Hosted archive fetch ──────────────────────
    let (sarch, varch) = organizer_call(&public, "GET",
        &format!("/api/v1/organizer/elections/{election_id}/archive"),
        None, Some(&secret)).await;
    assert_eq!(sarch, axum::http::StatusCode::OK, "{varch}");
    assert!(
        varch["anchor_eligible"].as_bool().unwrap_or(false),
        "transport-bound election must be anchor-eligible"
    );

    // ── 11. Desktop archive import ────────────────────────────────────────────
    let dir = std::env::temp_dir().join(format!("pb-v2-connect-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let archive_manifest =
        hex_decode(varch["archive_manifest_cbor_hex"].as_str().unwrap_or("")).expect("manifest hex");
    let archive_files = varch["files"].as_array().cloned().unwrap_or_else(|| panic!("files"));
    write_archive_from_endpoint(&dir, &archive_files, &archive_manifest);

    // ── 12. Archive verification ──────────────────────────────────────────────
    assert!(verify_archive_dir_for_test(&dir), "archive must pass verifier");

    // ── 13. V2 preparation (actual Desktop browser-anchor export) ─────────────
    let desktop_payload = build_v2_public_payload_from_verified_archive_v1(&GuiLiveAnchorV2RequestV1 {
        archive_directory: dir.to_string_lossy().into_owned(),
        network: "mainnet".to_owned(),
        template_address:
            tari_cc_private_ballot_deployment_registry::MAINNET_V2_TEMPLATE_ADDRESS.to_owned(),
        template_module:
            tari_cc_private_ballot_anchor_transport::ANCHOR_TEMPLATE_MODULE_V2.to_owned(),
        template_function:
            tari_cc_private_ballot_anchor_transport::ANCHOR_EVENT_FUNCTION_V2.to_owned(),
        template_event_topic: format!("{}.{}",
            tari_cc_private_ballot_anchor_transport::ANCHOR_TEMPLATE_MODULE_V2,
            tari_cc_private_ballot_anchor_transport::ANCHOR_EVENT_TOPIC_SUFFIX_V2),
        template_artifact_digest_hex:
            tari_cc_private_ballot_deployment_registry::MAINNET_V2_ARTIFACT_BLAKE3.to_owned(),
    }).expect("V2 payload must build from organizer-endpoint archive");
    let artifact_digest: [u8; 32] =
        hex_decode(tari_cc_private_ballot_deployment_registry::MAINNET_V2_ARTIFACT_BLAKE3)
            .unwrap().try_into().unwrap();
    let deployment = tari_cc_private_ballot_anchor_transport::AnchorTemplateBindingV2::new(
        tari_cc_private_ballot_deployment_registry::MAINNET_V2_TEMPLATE_ADDRESS.to_owned(),
        tari_cc_private_ballot_anchor_transport::ANCHOR_TEMPLATE_MODULE_V2.to_owned(),
        tari_cc_private_ballot_anchor_transport::ANCHOR_EVENT_FUNCTION_V2.to_owned(),
        format!("{}.{}",
            tari_cc_private_ballot_anchor_transport::ANCHOR_TEMPLATE_MODULE_V2,
            tari_cc_private_ballot_anchor_transport::ANCHOR_EVENT_TOPIC_SUFFIX_V2),
        artifact_digest,
    ).expect("deployment binding");
    let prepared = prepare_v2_anchor_publish_from_verified_evidence_v1(
        &GuiV2AnchorPublishPreparationRequestV1 {
            archive_directory: dir.to_string_lossy().into_owned(),
            payload_hex: desktop_payload.payload_hex.clone(),
            expected_digest_hex: desktop_payload.v2_anchor_digest_hex.clone(),
        },
        &deployment,
    ).expect("V2 preparation must succeed");

    // ── 14. Exact unchanged export into Hosted Manage → Connect enabled ────────
    // Hosted derives its expected identity independently via finalized_anchor_identity.
    let loaded = crate::LoadedElection::load(storage.as_ref(), election_id)
        .expect("finalized election must load");
    let hosted_identity = crate::finalized_anchor_identity(&loaded, storage.as_ref())
        .expect("Hosted identity must derive");
    let connect_result = verify_v2_public_payload_against_archive_v1(
        &dir,
        &hex_decode(&desktop_payload.payload_hex).expect("payload hex"),
        &desktop_payload.v2_anchor_digest_hex,
    ).expect("Connect must be enabled after full V2 release flow");
    // 7-field identity cross-check (independent Hosted identity validation).
    assert_eq!(connect_result.election_id, election_id,              "Connect: election ID");
    assert_eq!(connect_result.archive_hash_hex, hosted_identity.archive_hash_hex, "Connect: archive identity");
    assert_eq!(connect_result.v2_anchor_digest_hex, hosted_identity.anchor_digest_hex, "Connect: anchor digest");
    assert_eq!(connect_result.network, "mainnet",                    "Connect: network");
    assert_eq!(connect_result.public_summary_json, hosted_identity.public_summary_json, "Connect: public summary");
    assert_eq!(
        connect_result.template_address,
        tari_cc_private_ballot_deployment_registry::MAINNET_V2_TEMPLATE_ADDRESS,
        "Connect: deployment address"
    );
    assert_eq!(
        connect_result.template_artifact_digest_hex,
        tari_cc_private_ballot_deployment_registry::MAINNET_V2_ARTIFACT_BLAKE3,
        "Connect: artifact digest"
    );
    // Prepared arguments must match Hosted identity.
    assert_eq!(
        prepared.arguments,
        vec![
            hosted_identity.anchor_digest_hex,
            "mainnet".to_owned(),
            election_id.to_owned(),
            hosted_identity.public_summary_json,
        ],
        "V2 anchor arguments must match Hosted identity"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
// ---------------------------------------------------------------------------
// Anchor-payload endpoint (browser Mainnet anchoring)
// ---------------------------------------------------------------------------

const ANCHOR_PAYLOAD_PATH: &str = "/anchor-payload";

/// A transport binding whose batch reports reduced anonymity, used to prove the
/// endpoint requires an explicit acknowledgement before issuing a payload.
fn reduced_anonymity_binding(f: &Fixture, accepted_ballot_count: u64) -> Vec<u8> {
    let (manifest, _, _) = load_fixture(f);
    let manifest_hash = manifest
        .canonical_hash(&Blake3HashProviderV1)
        .unwrap_or_else(|_| panic!("manifest hash"));
    TransportArchiveBindingV1::new(
        f.election_id.as_bytes().to_vec(),
        manifest_hash,
        [0x44; 32],
        7,
        vec![TransportArchiveBatchV1::new(
            7,
            [0x55; 32],
            accepted_ballot_count,
            true,
        )],
    )
    .and_then(|binding| binding.to_canonical_cbor())
    .unwrap_or_else(|_| panic!("reduced-anonymity transport binding"))
}

async fn import_open_election(routers: &TestRouters, f: &Fixture) {
    assert_eq!(
        import(routers.admin.clone(), f).await,
        axum::http::StatusCode::CREATED
    );
}

async fn submit_ballot(routers: &TestRouters, f: &Fixture, index: u64, scalar: u64) {
    let pkg = make_package(f, scalar, b"candidate-a");
    let body = serde_json::json!({
        "receipt_id": format!("00000000-0000-4000-8000-{index:012}"),
        "package_cbor_hex": hex_encode(&pkg),
        "api_version": "v1",
    })
    .to_string();
    let (status, response) = req(
        routers.public.clone(),
        "POST",
        &format!("/api/v1/elections/{}/ballots", f.election_id),
        Some(body),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::CREATED, "{response}");
}

async fn close_election(routers: &TestRouters, f: &Fixture) {
    let (status, response) = req(
        routers.admin.clone(),
        "POST",
        &format!("/api/v1/admin/elections/{}/close", f.election_id),
        None,
        &[("x-admin-token", "test-admin-token")],
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{response}");
}

async fn finalize_election(routers: &TestRouters, f: &Fixture) {
    let (status, response) = req(
        routers.admin.clone(),
        "POST",
        &format!("/api/v1/admin/elections/{}/finalize", f.election_id),
        None,
        &[("x-admin-token", "test-admin-token")],
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{response}");
}

/// Imports, votes, closes, records one binding, and finalizes an election.
async fn finalized_election(
    routers: &TestRouters,
    storage: &Arc<InMemoryStorage>,
    f: &Fixture,
    scalars: &[u64],
    binding: Option<Vec<u8>>,
) {
    import_open_election(routers, f).await;
    for (index, scalar) in scalars.iter().enumerate() {
        submit_ballot(routers, f, index as u64 + 1, *scalar).await;
    }
    close_election(routers, f).await;
    if let Some(binding) = binding {
        storage
            .put_finalized_transport_binding(crate::storage::FinalizedTransportBindingRecord {
                election_id: f.election_id.clone(),
                binding_cbor: binding,
            })
            .unwrap_or_else(|_| panic!("record transport binding"));
    }
    finalize_election(routers, f).await;
}

async fn get_anchor_payload(router: &axum::Router, election_id: &str) -> (axum::http::StatusCode, String) {
    req(
        router.clone(),
        "GET",
        &format!("/api/v1/elections/{election_id}{ANCHOR_PAYLOAD_PATH}"),
        None,
        &[],
    )
    .await
}

#[tokio::test]
async fn anchor_payload_rejects_a_non_finalized_election() {
    let f = fixture_with("anchor-open", "anchor-open-rev");
    let (routers, _storage) = test_routers();
    import_open_election(&routers, &f).await;

    let (status, body) = get_anchor_payload(&routers.public, &f.election_id).await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT, "{body}");
    assert_eq!(
        error_code(&body).as_deref(),
        Some("election_not_finalized"),
        "{body}"
    );
}

#[tokio::test]
async fn anchor_payload_rejects_an_election_without_a_transport_binding() {
    let f = fixture_with("anchor-no-binding", "anchor-no-binding-rev");
    let (routers, storage) = test_routers();
    import_open_election(&routers, &f).await;
    submit_ballot(&routers, &f, 1, 1).await;
    submit_ballot(&routers, &f, 2, 2).await;
    close_election(&routers, &f).await;

    // Finalization legitimately refuses without a binding, so model the legacy
    // state directly: a finalized row that predates the binding table.
    storage
        .set_election_state(&f.election_id, "closed", "finalized")
        .unwrap_or_else(|_| panic!("force legacy finalized state"));

    let (status, body) = get_anchor_payload(&routers.public, &f.election_id).await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT, "{body}");
    assert_eq!(error_code(&body).as_deref(), Some("anchor_not_eligible"), "{body}");
}

#[tokio::test]
async fn anchor_payload_rejects_a_malformed_election_id() {
    let f = fixture_with("anchor-malformed-id", "anchor-malformed-id-rev");
    let (routers, _storage) = test_routers();
    import_open_election(&routers, &f).await;

    for candidate in ["..%2F..%2Fetc%2Fpasswd", "nope", "a%20b", "x%2Fy"] {
        let (status, body) = get_anchor_payload(&routers.public, candidate).await;
        assert_eq!(
            status,
            axum::http::StatusCode::NOT_FOUND,
            "candidate {candidate}: {body}"
        );
        // Errors expose exactly one stable code and one fixed message.
        assert_eq!(
            object_keys(&body),
            vec!["code".to_owned(), "message".to_owned()],
            "{body}"
        );
    }
}

#[tokio::test]
async fn anchor_payload_returns_the_canonical_mainnet_v2_payload() {
    let f = fixture_with("anchor-canonical", "anchor-canonical-rev");
    let (routers, storage) = test_routers();
    let accepted = 2_u64;
    finalized_election(
        &routers,
        &storage,
        &f,
        &[1, 2],
        Some(desktop_transport_binding(&f, accepted)),
    )
    .await;

    let (status, body) = get_anchor_payload(&routers.public, &f.election_id).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    let payload: serde_json::Value = serde_json::from_str(&body).unwrap_or_else(|_| panic!("json"));

    // Only the documented fields are returned.
    assert_eq!(
        object_keys(&body),
        vec![
            "anchor_args",
            "archive_hash_hex",
            "election_id",
            "network",
            "payload_hex",
            "public_summary_json",
            "template_address",
            "template_artifact_digest_hex",
            "template_event_topic",
            "template_function",
            "template_module",
            "v2_anchor_digest_hex",
        ]
    );

    // The anchor network comes from the released deployment, never from the
    // transport environment (which is "test" in this configuration).
    assert_eq!(payload["network"], "mainnet");
    assert_eq!(payload["election_id"], f.election_id);
    assert_eq!(
        payload["template_address"],
        tari_cc_private_ballot_deployment_registry::MAINNET_V2_TEMPLATE_ADDRESS
    );
    assert_eq!(
        payload["template_artifact_digest_hex"],
        tari_cc_private_ballot_deployment_registry::MAINNET_V2_ARTIFACT_BLAKE3
    );
    assert_eq!(payload["template_module"], ANCHOR_TEMPLATE_MODULE_V2);
    assert_eq!(payload["template_function"], ANCHOR_EVENT_FUNCTION_V2);
    assert_eq!(
        payload["template_event_topic"],
        format!("{ANCHOR_TEMPLATE_MODULE_V2}.{ANCHOR_EVENT_TOPIC_SUFFIX_V2}")
    );

    // Arguments are exactly [anchorDigest, network, electionId, publicSummary].
    let args = payload["anchor_args"]
        .as_object()
        .unwrap_or_else(|| panic!("anchor_args object"));
    assert_eq!(args["anchor_digest_hex"], payload["v2_anchor_digest_hex"]);
    assert_eq!(args["network"], "mainnet");
    assert_eq!(args["election_id"], f.election_id);
    assert_eq!(args["public_summary"], payload["public_summary_json"]);

    // No internal path or host detail appears anywhere in the response.
    for forbidden in ["pb-anchor", "anchor-payload-", "127.0.0.1", "sqlite"] {
        assert!(
            !body.contains(forbidden),
            "response must not contain {forbidden}: {body}"
        );
    }

    // Re-derive the canonical payload from the archive exactly as the Desktop
    // does, and require byte-identical output.
    let dir = std::env::temp_dir().join(format!("pb-anchor-canonical-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (_archive_status, archive_body) = req(
        routers.public.clone(),
        "GET",
        &format!("/api/v1/elections/{}/archive", f.election_id),
        None,
        &[],
    )
    .await;
    let archive: serde_json::Value =
        serde_json::from_str(&archive_body).unwrap_or_else(|_| panic!("archive json"));
    std::fs::create_dir_all(&dir).unwrap_or_else(|_| panic!("mkdir"));
    write_archive_from_endpoint(
        &dir,
        archive["files"].as_array().map(Vec::as_slice).unwrap_or(&[]),
        &hex_decode(archive["archive_manifest_cbor_hex"].as_str().unwrap_or(""))
            .unwrap_or_else(|_| panic!("manifest hex")),
    );
    assert!(verify_archive_dir_for_test(&dir));

    let desktop = build_v2_public_payload_from_verified_archive_v1(&GuiLiveAnchorV2RequestV1 {
        archive_directory: dir.to_string_lossy().into_owned(),
        network: "mainnet".to_owned(),
        template_address: tari_cc_private_ballot_deployment_registry::MAINNET_V2_TEMPLATE_ADDRESS
            .to_owned(),
        template_module: ANCHOR_TEMPLATE_MODULE_V2.to_owned(),
        template_function: ANCHOR_EVENT_FUNCTION_V2.to_owned(),
        template_event_topic: format!("{ANCHOR_TEMPLATE_MODULE_V2}.{ANCHOR_EVENT_TOPIC_SUFFIX_V2}"),
        template_artifact_digest_hex:
            tari_cc_private_ballot_deployment_registry::MAINNET_V2_ARTIFACT_BLAKE3.to_owned(),
    })
    .unwrap_or_else(|_| panic!("desktop payload"));
    assert_eq!(desktop.payload_hex, payload["payload_hex"], "canonical bytes");
    assert_eq!(
        desktop.v2_anchor_digest_hex, payload["v2_anchor_digest_hex"],
        "canonical digest"
    );
    assert_eq!(desktop.archive_hash_hex, payload["archive_hash_hex"]);
    assert_eq!(desktop.public_summary_json, payload["public_summary_json"]);
    assert_eq!(desktop.election_id, f.election_id);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn anchor_payload_enforces_the_privacy_floor_and_reduced_anonymity_acknowledgement() {
    // A single accepted ballot is below the release floor of 2.
    let small = fixture_with("anchor-floor", "anchor-floor-rev");
    let (routers, storage) = test_routers();
    finalized_election(
        &routers,
        &storage,
        &small,
        &[1],
        Some(desktop_transport_binding(&small, 1)),
    )
    .await;
    let (status, body) = get_anchor_payload(&routers.public, &small.election_id).await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT, "{body}");
    assert_eq!(
        error_code(&body).as_deref(),
        Some("anchor_privacy_floor_not_met"),
        "{body}"
    );

    // Two accepted ballots with a reduced-anonymity binding require an explicit
    // acknowledgement; without it the request fails closed.
    let reduced = fixture_with("anchor-reduced", "anchor-reduced-rev");
    let (routers, storage) = test_routers();
    finalized_election(
        &routers,
        &storage,
        &reduced,
        &[1, 2],
        Some(reduced_anonymity_binding(&reduced, 2)),
    )
    .await;
    let (status, body) = get_anchor_payload(&routers.public, &reduced.election_id).await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT, "{body}");
    assert_eq!(
        error_code(&body).as_deref(),
        Some("anchor_reduced_anonymity_ack_required"),
        "{body}"
    );

    // With the acknowledgement the same election produces a canonical payload.
    let (status, body) = req(
        routers.public.clone(),
        "GET",
        &format!(
            "/api/v1/elections/{}{ANCHOR_PAYLOAD_PATH}?acknowledge_reduced_anonymity=true",
            reduced.election_id
        ),
        None,
        &[],
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    let payload: serde_json::Value = serde_json::from_str(&body).unwrap_or_else(|_| panic!("json"));
    assert_eq!(payload["network"], "mainnet");
    assert_eq!(payload["election_id"], reduced.election_id);
}

#[tokio::test]
async fn anchor_payload_verification_rejects_a_tampered_archive() {
    let f = fixture_with("anchor-tampered", "anchor-tampered-rev");
    let (routers, storage) = test_routers();
    finalized_election(
        &routers,
        &storage,
        &f,
        &[1, 2],
        Some(desktop_transport_binding(&f, 2)),
    )
    .await;
    let (status, body) = get_anchor_payload(&routers.public, &f.election_id).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    let payload: serde_json::Value = serde_json::from_str(&body).unwrap_or_else(|_| panic!("json"));

    let dir = std::env::temp_dir().join(format!("pb-anchor-tampered-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (_status, archive_body) = req(
        routers.public.clone(),
        "GET",
        &format!("/api/v1/elections/{}/archive", f.election_id),
        None,
        &[],
    )
    .await;
    let archive: serde_json::Value =
        serde_json::from_str(&archive_body).unwrap_or_else(|_| panic!("archive json"));
    std::fs::create_dir_all(&dir).unwrap_or_else(|_| panic!("mkdir"));
    write_archive_from_endpoint(
        &dir,
        archive["files"].as_array().map(Vec::as_slice).unwrap_or(&[]),
        &hex_decode(archive["archive_manifest_cbor_hex"].as_str().unwrap_or(""))
            .unwrap_or_else(|_| panic!("manifest hex")),
    );
    assert!(verify_archive_dir_for_test(&dir), "untampered archive verifies");

    // Flip one byte of one submission without updating the catalog.
    let submissions = std::fs::read_dir(dir.join("submissions"))
        .unwrap_or_else(|_| panic!("submissions dir"))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.extension().is_some_and(|ext| ext == "cbor"))
        .unwrap_or_else(|| panic!("a submission file"));
    let mut bytes = std::fs::read(&submissions).unwrap_or_else(|_| panic!("read submission"));
    if let Some(byte) = bytes.first_mut() {
        *byte ^= 0xff;
    }
    std::fs::write(&submissions, &bytes).unwrap_or_else(|_| panic!("write submission"));

    let tampered = build_v2_public_payload_from_verified_archive_v1(&GuiLiveAnchorV2RequestV1 {
        archive_directory: dir.to_string_lossy().into_owned(),
        network: payload["network"].as_str().unwrap_or("").to_owned(),
        template_address: payload["template_address"].as_str().unwrap_or("").to_owned(),
        template_module: payload["template_module"].as_str().unwrap_or("").to_owned(),
        template_function: payload["template_function"].as_str().unwrap_or("").to_owned(),
        template_event_topic: payload["template_event_topic"].as_str().unwrap_or("").to_owned(),
        template_artifact_digest_hex: payload["template_artifact_digest_hex"]
            .as_str()
            .unwrap_or("")
            .to_owned(),
    });
    assert!(
        tampered.is_err(),
        "a tampered archive must never produce a canonical payload"
    );

    // The detached-payload verifier must reject the same tampered archive.
    let payload_hex = payload["payload_hex"].as_str().unwrap_or("");
    let digest_hex = payload["v2_anchor_digest_hex"].as_str().unwrap_or("");
    assert!(
        verify_v2_public_payload_against_archive_v1(
            &dir,
            &hex_decode(payload_hex).unwrap_or_else(|_| panic!("payload hex")),
            digest_hex,
        )
        .is_err(),
        "the independent verifier must reject a tampered archive"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn anchor_payload_never_deletes_a_directory_derived_from_the_client_election_id() {
    let f = fixture_with("anchor-decoy", "anchor-decoy-rev");
    let (routers, storage) = test_routers();
    finalized_election(
        &routers,
        &storage,
        &f,
        &[1, 2],
        Some(desktop_transport_binding(&f, 2)),
    )
    .await;

    // A directory named after the legacy client-derived pattern must survive.
    let decoy = std::env::temp_dir().join(format!("pb-anchor-payload-{}", f.election_id));
    let _ = std::fs::remove_dir_all(&decoy);
    std::fs::create_dir_all(&decoy).unwrap_or_else(|_| panic!("decoy mkdir"));
    let sentinel = decoy.join("sentinel.txt");
    std::fs::write(&sentinel, b"do not delete").unwrap_or_else(|_| panic!("sentinel write"));

    let (status, body) = get_anchor_payload(&routers.public, &f.election_id).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(sentinel.exists(), "the client-named decoy must not be deleted");
    assert_eq!(
        std::fs::read(&sentinel).unwrap_or_else(|_| panic!("sentinel read")),
        b"do not delete"
    );
    let _ = std::fs::remove_dir_all(&decoy);
}

#[tokio::test]
async fn anchor_payload_response_is_bounded_and_carries_only_public_data() {
    let f = fixture_with("anchor-bounded", "anchor-bounded-rev");
    let (routers, storage) = test_routers();
    finalized_election(
        &routers,
        &storage,
        &f,
        &[1, 2],
        Some(desktop_transport_binding(&f, 2)),
    )
    .await;
    let (status, body) = get_anchor_payload(&routers.public, &f.election_id).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    let payload: serde_json::Value = serde_json::from_str(&body).unwrap_or_else(|_| panic!("json"));

    // Bounded: the public summary and its hex transport form stay inside the
    // protocol's 256 KiB ceiling.
    assert!(payload["public_summary_json"].as_str().unwrap_or("").len() <= 256 * 1024);
    assert!(payload["payload_hex"].as_str().unwrap_or("").len() <= 2 * 256 * 1024 + 64);

    // Public only: no ballot, nullifier, credential, or organizer material.
    for forbidden in [
        "package_cbor",
        "nullifier",
        "secret",
        "credential",
        "organizer_verifier",
        "authority_signing_key",
        "invitation",
    ] {
        assert!(
            !body.to_ascii_lowercase().contains(forbidden),
            "response must not contain {forbidden}"
        );
    }
}

fn object_keys(json: &str) -> Vec<String> {
    let value: serde_json::Value = serde_json::from_str(json).unwrap_or_else(|_| panic!("json"));
    let mut keys: Vec<String> = value
        .as_object()
        .unwrap_or_else(|| panic!("object"))
        .keys()
        .cloned()
        .collect();
    keys.sort();
    keys
}

fn error_code(json: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    value.get("code")?.as_str().map(str::to_owned)
}