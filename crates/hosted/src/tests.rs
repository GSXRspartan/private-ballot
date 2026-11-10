#![forbid(unsafe_code)]

//! Hosted backend integration tests: synthetic election, real Triptych
//! proofs, idempotent retry, distinct same-nullifier rejection, malformed
//! and wrong-election rejection, finalization, and Desktop archive
//! verifier compatibility.

use std::sync::Arc;

use axum::body::Body;
use curve25519_dalek_v4::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use tari_cc_private_ballot_ballot::{
    ApprovalBallotPayload, ApprovalLimits, BallotConfidentialityV1, BallotKindV1, BallotPackageV1,
    BallotPackageV1Input, CandidateDefinition, CandidateId, CandidateSet, ElectionId,
    ElectionManifestV1, ElectionManifestV1Input,
};
use tari_cc_private_ballot_crypto::{
    TARI_TRIPTYCH_PROOF_SUITE_ID_V1, TariTriptychSecretKeyV1, prove_tari_triptych_prototype_v1,
};
use tari_cc_private_ballot_protocol::{
    Blake3HashProviderV1, CanonicalCborWriter, PROTOCOL_VERSION_V1,
};
use tari_cc_private_ballot_registry::RegistrySnapshot;
use tari_cc_private_ballot_verifier::{
    build_tari_triptych_verifier_from_registry_v1, reconstruct_approval_proof_statement,
};
use tower::ServiceExt;

use crate::{
    AppState, HostedConfig, InMemoryStorage, ORIGIN_TOKEN_HEADER, admin_router_with_state, hex_encode,
    router_with_state, test_config, verify_archive_dir_for_test,
};
use crate::storage::HostedStorage;

fn point_bytes(m: u64) -> [u8; 32] {
    (RISTRETTO_BASEPOINT_POINT * Scalar::from(m)).compress().to_bytes()
}
fn secret_scalar(n: u64) -> TariTriptychSecretKeyV1 {
    match TariTriptychSecretKeyV1::from_canonical_bytes(Scalar::from(n).to_bytes()) {
        Ok(s) => s,
        Err(_) => panic!("test scalar must be canonical"),
    }
}
fn candidate_id(b: &[u8]) -> CandidateId {
    match CandidateId::new(b.to_vec()) { Ok(v) => v, Err(_) => panic!("candidate id") }
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
    for k in &keys { assert!(w.write_byte_string(k).is_ok()); }
    let registry = match RegistrySnapshot::from_canonical_cbor(&w.into_bytes()) { Ok(v) => v, Err(_) => panic!("registry") };
    let registry_cbor = match registry.to_canonical_cbor() { Ok(v) => v, Err(_) => panic!("registry cbor") };
    let reg_commit = match registry.canonical_commitment(&p) { Ok(v) => v, Err(_) => panic!("commit") };
    let cand = |id: &[u8], name: &str| match CandidateDefinition::new(candidate_id(id), name.to_owned()) { Ok(v) => v, Err(_) => panic!("cand") };
    let candidates = match CandidateSet::new(vec![cand(b"candidate-a", "Candidate A"), cand(b"candidate-b", "Candidate B"), cand(b"candidate-c", "Candidate C")]) { Ok(v) => v, Err(_) => panic!("candset") };
    let candidate_cbor = match candidates.to_canonical_cbor() { Ok(v) => v, Err(_) => panic!("cand cbor") };
    let cand_commit = match candidates.canonical_commitment(&p) { Ok(v) => v, Err(_) => panic!("cand commit") };
    let limits = match ApprovalLimits::new(1, 1, false) { Ok(v) => v, Err(_) => panic!("limits") };
    let manifest = match ElectionManifestV1::new(ElectionManifestV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        election_id: match ElectionId::new(election_id_str.as_bytes().to_vec()) { Ok(v) => v, Err(_) => panic!("eid") },
        ballot_kind: BallotKindV1::NonBindingApprovalPilot,
        ballot_confidentiality: BallotConfidentialityV1::Public,
        registry_commitment: reg_commit,
        candidate_set_commitment: cand_commit,
        proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
        approval_limits: limits,
        governance_source_revision: revision.to_owned(),
    }) { Ok(v) => v, Err(_) => panic!("manifest") };
    Fixture { manifest_cbor: match manifest.to_canonical_cbor() { Ok(v) => v, Err(_) => panic!("manifest cbor") }, registry_cbor, candidate_cbor, election_id: election_id_str.to_owned() }
}

fn fixture() -> Fixture {
    let p = Blake3HashProviderV1;
    // Registry: scalars 1,2,3 (voters A,B,C)
    let mut keys = vec![point_bytes(1), point_bytes(2), point_bytes(3)];
    keys.sort_unstable();
    let mut w = CanonicalCborWriter::new();
    assert!(w.write_array_len(keys.len()).is_ok());
    for k in &keys { assert!(w.write_byte_string(k).is_ok()); }
    let registry = match RegistrySnapshot::from_canonical_cbor(&w.into_bytes()) { Ok(v) => v, Err(_) => panic!("registry") };
    let registry_cbor = match registry.to_canonical_cbor() { Ok(v) => v, Err(_) => panic!("registry cbor") };
    let reg_commit = match registry.canonical_commitment(&p) { Ok(v) => v, Err(_) => panic!("commit") };

    let cand = |id: &[u8], name: &str| match CandidateDefinition::new(candidate_id(id), name.to_owned()) { Ok(v) => v, Err(_) => panic!("cand") };
    let candidates = match CandidateSet::new(vec![cand(b"candidate-a", "Candidate A"), cand(b"candidate-b", "Candidate B"), cand(b"candidate-c", "Candidate C")]) { Ok(v) => v, Err(_) => panic!("candset") };
    let candidate_cbor = match candidates.to_canonical_cbor() { Ok(v) => v, Err(_) => panic!("cand cbor") };
    let cand_commit = match candidates.canonical_commitment(&p) { Ok(v) => v, Err(_) => panic!("cand commit") };
    let limits = match ApprovalLimits::new(1, 1, false) { Ok(v) => v, Err(_) => panic!("limits") };
    let manifest = match ElectionManifestV1::new(ElectionManifestV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        election_id: match ElectionId::new(b"hosted-synthetic-001".to_vec()) { Ok(v) => v, Err(_) => panic!("eid") },
        ballot_kind: BallotKindV1::NonBindingApprovalPilot,
        ballot_confidentiality: BallotConfidentialityV1::Public,
        registry_commitment: reg_commit,
        candidate_set_commitment: cand_commit,
        proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
        approval_limits: limits,
        governance_source_revision: "hosted-synthetic".to_owned(),
    }) { Ok(v) => v, Err(_) => panic!("manifest") };
    Fixture { manifest_cbor: match manifest.to_canonical_cbor() { Ok(v) => v, Err(_) => panic!("manifest cbor") }, registry_cbor, candidate_cbor, election_id: "hosted-synthetic-001".to_owned() }
}

fn load_fixture(f: &Fixture) -> (tari_cc_private_ballot_ballot::ElectionManifest, CandidateSet, RegistrySnapshot) {
    let manifest = match tari_cc_private_ballot_ballot::ElectionManifest::from_canonical_cbor(&f.manifest_cbor) { Ok(v) => v, Err(_) => panic!("load manifest") };
    let candidates = match CandidateSet::from_canonical_cbor(&f.candidate_cbor) { Ok(v) => v, Err(_) => panic!("load cand") };
    let registry = match RegistrySnapshot::from_canonical_cbor(&f.registry_cbor) { Ok(v) => v, Err(_) => panic!("load reg") };
    (manifest, candidates, registry)
}

fn make_package(f: &Fixture, scalar: u64, candidate: &[u8]) -> Vec<u8> {
    let (manifest, candidates, registry) = load_fixture(f);
    let p = Blake3HashProviderV1;
    let payload = match ApprovalBallotPayload::new(vec![candidate_id(candidate)], &candidates, manifest.approval_limits()) { Ok(v) => v, Err(_) => panic!("payload") };
    let verifier = match build_tari_triptych_verifier_from_registry_v1(&registry, &p) { Ok(v) => v, Err(_) => panic!("verifier") };
    let statement = match reconstruct_approval_proof_statement(&manifest, &payload, &p) { Ok(v) => v, Err(_) => panic!("statement") };
    let secret = secret_scalar(scalar);
    let proof = match prove_tari_triptych_prototype_v1(&statement, &verifier, &secret) { Ok(v) => v, Err(_) => panic!("prove") };
    let mh = match manifest.canonical_hash(&p) { Ok(v) => v, Err(_) => panic!("mh") };
    let package = match BallotPackageV1::new(BallotPackageV1Input { protocol_version: PROTOCOL_VERSION_V1, manifest_hash: mh, proof_suite_id: manifest.proof_suite_id().to_owned(), proof, payload }) { Ok(v) => v, Err(_) => panic!("package") };
    match package.to_canonical_cbor() { Ok(v) => v, Err(_) => panic!("package cbor") }
}

struct TestRouters {
    public: axum::Router,
    admin: axum::Router,
}

fn test_routers() -> (TestRouters, Arc<InMemoryStorage>) {
    let storage = Arc::new(InMemoryStorage::new());
    let state = Arc::new(AppState::new(test_config(), storage.clone()));
    let routers = TestRouters { public: router_with_state(state.clone()), admin: admin_router_with_state(state) };
    (routers, storage)
}

fn test_router() -> (axum::Router, Arc<InMemoryStorage>) {
    let (routers, storage) = test_routers();
    (routers.public, storage)
}

async fn req(router: axum::Router, method: &str, uri: &str, body: Option<String>, headers: &[(&str, &str)]) -> (axum::http::StatusCode, String) {
    let mut builder = axum::http::Request::builder().method(method).uri(uri);
    for (k, v) in headers { builder = builder.header(*k, *v); }
    let body = match body { Some(b) => Body::from(b), None => Body::empty() };
    let request = match builder.body(body) { Ok(r) => r, Err(_) => panic!("request") };
    let response = match router.oneshot(request).await { Ok(r) => r, Err(_) => panic!("oneshot") };
    let status = response.status();
    let bytes = match axum::body::to_bytes(response.into_body(), 1024 * 1024).await { Ok(b) => b, Err(_) => panic!("body") };
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn import(admin: axum::Router, f: &Fixture) -> axum::http::StatusCode {
    let body = serde_json::json!({"election_id": f.election_id, "manifest_cbor_hex": hex_encode(&f.manifest_cbor), "registry_cbor_hex": hex_encode(&f.registry_cbor), "candidate_cbor_hex": hex_encode(&f.candidate_cbor)}).to_string();
    let (status, _) = req(admin, "POST", "/api/v1/admin/elections/import", Some(body), &[("content-type", "application/json"), ("x-admin-token", "test-admin-token")]).await;
    status
}

#[tokio::test]
async fn end_to_end_hosted_flow_and_desktop_archive_verifier() {
    let f = fixture();
    let (routers, storage) = test_routers();
    let router = routers.public.clone();
    assert_eq!(import(routers.admin.clone(), &f).await, axum::http::StatusCode::CREATED);
    // Voter A ballot
    let pkg_a = make_package(&f, 1, b"candidate-a");
    let body_a = serde_json::json!({"receipt_id": "00000000-0000-4000-8000-000000000001", "package_cbor_hex": hex_encode(&pkg_a), "api_version": "v1"}).to_string();
    let (s1, r1) = req(router.clone(), "POST", &format!("/api/v1/elections/{}/ballots", f.election_id), Some(body_a.clone()), &[("content-type", "application/json")]).await;
    assert_eq!(s1, axum::http::StatusCode::CREATED, "receipt: {r1}");
    let receipt: serde_json::Value = serde_json::from_str(&r1).unwrap_or_else(|_| panic!("receipt json"));
    assert_eq!(receipt["status"], "accepted");
    // Exact retry -> same stable receipt, replay=true, no double count
    let (s2, r2) = req(router.clone(), "POST", &format!("/api/v1/elections/{}/ballots", f.election_id), Some(body_a.clone()), &[("content-type", "application/json")]).await;
    assert_eq!(s2, axum::http::StatusCode::OK);
    let receipt2: serde_json::Value = serde_json::from_str(&r2).unwrap_or_else(|_| panic!("receipt2 json"));
    assert_eq!(receipt["stable_receipt"], receipt2["stable_receipt"]);
    assert_eq!(receipt2["replay"], true);
    assert_eq!(storage.list_ballots(&f.election_id).map(|v| v.len()).unwrap_or(99), 1);
    // GET receipt
    let (s3, r3) = req(router.clone(), "GET", &format!("/api/v1/elections/{}/receipt/00000000-0000-4000-8000-000000000001", f.election_id), None, &[]).await;
    assert_eq!(s3, axum::http::StatusCode::OK, "{r3}");
    // Distinct second ballot from SAME voter (same nullifier) -> duplicate_nullifier
    let pkg_a2 = make_package(&f, 1, b"candidate-b");
    let body_a2 = serde_json::json!({"receipt_id": "00000000-0000-4000-8000-000000000002", "package_cbor_hex": hex_encode(&pkg_a2), "api_version": "v1"}).to_string();
    let (s4, r4) = req(router.clone(), "POST", &format!("/api/v1/elections/{}/ballots", f.election_id), Some(body_a2), &[("content-type", "application/json")]).await;
    assert_eq!(s4, axum::http::StatusCode::CONFLICT, "{r4}");
    assert!(r4.contains("duplicate_nullifier"), "{r4}");
    // Voter B valid
    let pkg_b = make_package(&f, 2, b"candidate-b");
    let body_b = serde_json::json!({"receipt_id": "00000000-0000-4000-8000-000000000003", "package_cbor_hex": hex_encode(&pkg_b), "api_version": "v1"}).to_string();
    let (s5, _) = req(router.clone(), "POST", &format!("/api/v1/elections/{}/ballots", f.election_id), Some(body_b), &[("content-type", "application/json")]).await;
    assert_eq!(s5, axum::http::StatusCode::CREATED);
    // Malformed package
    let body_bad = serde_json::json!({"receipt_id": "00000000-0000-4000-8000-000000000004", "package_cbor_hex": "00ff", "api_version": "v1"}).to_string();
    let (s6, _) = req(router.clone(), "POST", &format!("/api/v1/elections/{}/ballots", f.election_id), Some(body_bad), &[("content-type", "application/json")]).await;
    assert_eq!(s6, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    // Wrong-election: valid package for a different election id would need second fixture; tamper manifest hash by using pkg from other election is covered by wrong manifest hash check in verifier tests. Here submit pkg_a to unknown election -> 404
    let (s7, _) = req(router.clone(), "POST", "/api/v1/elections/nope/ballots", Some(body_a.clone()), &[("content-type", "application/json")]).await;
    assert_eq!(s7, axum::http::StatusCode::NOT_FOUND);
    // Close + finalize (admin plane)
    let (s8, _) = req(routers.admin.clone(), "POST", &format!("/api/v1/admin/elections/{}/close", f.election_id), None, &[("x-admin-token", "test-admin-token")]).await;
    assert_eq!(s8, axum::http::StatusCode::OK);
    // Ballot after close -> election_closed
    let pkg_c = make_package(&f, 3, b"candidate-c");
    let body_c = serde_json::json!({"receipt_id": "00000000-0000-4000-8000-000000000005", "package_cbor_hex": hex_encode(&pkg_c), "api_version": "v1"}).to_string();
    let (s9, r9) = req(router.clone(), "POST", &format!("/api/v1/elections/{}/ballots", f.election_id), Some(body_c), &[("content-type", "application/json")]).await;
    assert_eq!(s9, axum::http::StatusCode::CONFLICT, "{r9}");
    let (s10, r10) = req(routers.admin.clone(), "POST", &format!("/api/v1/admin/elections/{}/finalize", f.election_id), None, &[("x-admin-token", "test-admin-token")]).await;
    assert_eq!(s10, axum::http::StatusCode::OK, "{r10}");
    // Results: A->a, B->b => counts 1,1,0
    let (s11, r11) = req(router.clone(), "GET", &format!("/api/v1/elections/{}/results", f.election_id), None, &[]).await;
    assert_eq!(s11, axum::http::StatusCode::OK, "{r11}");
    let results: serde_json::Value = serde_json::from_str(&r11).unwrap_or_else(|_| panic!("results json"));
    assert_eq!(results["accepted_ballots"], 2);
    // Archive endpoint
    let (s12, r12) = req(router.clone(), "GET", &format!("/api/v1/elections/{}/archive", f.election_id), None, &[]).await;
    assert_eq!(s12, axum::http::StatusCode::OK, "{r12}");
    let archive: serde_json::Value = serde_json::from_str(&r12).unwrap_or_else(|_| panic!("archive json"));
    // Write archive to temp dir and verify with EXISTING desktop verifier
    let dir = std::env::temp_dir().join(format!("pb-hosted-archive-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap_or_else(|_| panic!("mkdir"));
    // Rebuild archive files via storage + public API types: use archive endpoint files
    let files = archive["files"].as_array().map(|v| v.clone()).unwrap_or_default();
    // Need archive-manifest bytes: reconstruct by asking hosted to write? Instead use files + manifest from endpoint is not included. So fetch via internal: we re-derive using crate functions in lib tests is complex; here we write files and then generate manifest by calling the same logic through a second request is not possible. Workaround: the archive endpoint returns only content files; the test below writes them and also writes archive-manifest by recomputing with archive crate directly.
    write_archive_from_endpoint(&dir, &f, &files);
    assert!(verify_archive_dir_for_test(&dir), "desktop verifier must pass hosted archive");
    let _ = std::fs::remove_dir_all(&dir);
}

fn write_archive_from_endpoint(dir: &std::path::Path, f: &Fixture, files: &[serde_json::Value]) {
    use std::collections::BTreeMap;
    use tari_cc_private_ballot_archive::{ArchiveFileCatalogV1, ArchiveFileEntryV1, ArchiveManifestV1, ArchivePathV1, ARCHIVE_MANIFEST_CANONICAL_PATH};
    use tari_cc_private_ballot_protocol::Blake3HashProviderV1;
    let p = Blake3HashProviderV1;
    let mut map: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for file in files {
        let path = file["path"].as_str().unwrap_or("").to_owned();
        let hex = file["cbor_hex"].as_str().unwrap_or("");
        let mut bytes = Vec::new();
        let hb = hex.as_bytes();
        let mut i = 0;
        while i + 1 < hb.len() { let hi = char::from(hb[i]).to_digit(16).unwrap_or_else(|| panic!("hex")); let lo = char::from(hb[i+1]).to_digit(16).unwrap_or_else(|| panic!("hex")); bytes.push(((hi<<4)|lo) as u8); i+=2; }
        map.insert(path, bytes);
    }
    // manifest hash from fixture manifest
    let (manifest, _, _) = load_fixture(f);
    let mh = manifest.canonical_hash(&p).unwrap_or_else(|_| panic!("mh"));
    let entries: Vec<ArchiveFileEntryV1> = map.iter().map(|(path, bytes)| ArchiveFileEntryV1::for_bytes(ArchivePathV1::new(path.clone()).unwrap_or_else(|_| panic!("path")), &p, bytes)).collect();
    let catalog = ArchiveFileCatalogV1::new(entries).unwrap_or_else(|_| panic!("catalog"));
    let am = ArchiveManifestV1::finalized_for_provider(mh, catalog, &p).unwrap_or_else(|_| panic!("archive manifest"));
    let am_bytes = am.to_canonical_cbor().unwrap_or_else(|_| panic!("am cbor"));
    let submissions = dir.join("submissions");
    if map.keys().any(|k| k.starts_with("submissions")) { std::fs::create_dir_all(&submissions).unwrap_or_else(|_| panic!("mkdir sub")); }
    for (path, bytes) in &map { let fp = dir.join(path); if let Some(parent) = fp.parent() { std::fs::create_dir_all(parent).unwrap_or_else(|_| panic!("mkdir parent")); } std::fs::write(&fp, bytes).unwrap_or_else(|_| panic!("write")); }
    std::fs::write(dir.join(ARCHIVE_MANIFEST_CANONICAL_PATH), &am_bytes).unwrap_or_else(|_| panic!("write manifest"));
}

#[tokio::test]
async fn wrong_election_binding_is_rejected() {
    let f1 = fixture_with("hosted-synthetic-001", "hosted-synthetic");
    let f2 = fixture_with("hosted-synthetic-002", "hosted-synthetic-other");
    let (routers, _storage) = test_routers();
    let router = routers.public.clone();
    assert_eq!(import(routers.admin.clone(), &f1).await, axum::http::StatusCode::CREATED);
    assert_eq!(import(routers.admin.clone(), &f2).await, axum::http::StatusCode::CREATED);
    let pkg1 = make_package(&f1, 1, b"candidate-a");
    let body = serde_json::json!({"receipt_id": "99999999-9999-4999-8999-999999999999", "package_cbor_hex": hex_encode(&pkg1), "api_version": "v1"}).to_string();
    let (status, text) = req(router.clone(), "POST", "/api/v1/elections/hosted-synthetic-002/ballots", Some(body), &[("content-type", "application/json")]).await;
    assert_eq!(status, axum::http::StatusCode::UNPROCESSABLE_ENTITY, "{text}");
    assert!(text.contains("wrong_election"), "{text}");
    // Same package is valid in its own election
    let body2 = serde_json::json!({"receipt_id": "99999999-9999-4999-8999-999999999998", "package_cbor_hex": hex_encode(&pkg1), "api_version": "v1"}).to_string();
    let (s2, t2) = req(router.clone(), "POST", "/api/v1/elections/hosted-synthetic-001/ballots", Some(body2), &[("content-type", "application/json")]).await;
    assert_eq!(s2, axum::http::StatusCode::CREATED, "{t2}");
}

#[tokio::test]
async fn stored_ballot_does_not_contain_voter_secret() {
    let f = fixture();
    let (routers, storage) = test_routers();
    let router = routers.public.clone();
    assert_eq!(import(routers.admin.clone(), &f).await, axum::http::StatusCode::CREATED);
    let pkg = make_package(&f, 1, b"candidate-a");
    let body = serde_json::json!({"receipt_id": "88888888-8888-4888-8888-888888888888", "package_cbor_hex": hex_encode(&pkg), "api_version": "v1"}).to_string();
    let (s, t) = req(router.clone(), "POST", &format!("/api/v1/elections/{}/ballots", f.election_id), Some(body), &[("content-type", "application/json")]).await;
    assert_eq!(s, axum::http::StatusCode::CREATED, "{t}");
    let ballots = storage.list_ballots(&f.election_id).unwrap_or_else(|_| panic!("list"));
    assert_eq!(ballots.len(), 1);
    let secret_bytes = Scalar::from(1_u64).to_bytes();
    // The stored package is the canonical public package; it must not embed the raw secret scalar as a standalone field.
    // (Package contains proof + public payload; secret scalar bytes as a 32-byte window would only appear by coincidence - check exact field absence via re-verification already done.)
    assert!(!ballots[0].package_cbor.windows(32).any(|w| w == secret_bytes), "secret scalar must not be stored verbatim in package");
    assert!(!ballots[0].envelope_hash_hex.contains(&hex_encode(&secret_bytes)), "secret must not be in envelope hash field");
}

#[tokio::test]
async fn concurrent_same_receipt_does_not_double_count() {
    let f = fixture();
    let (routers, storage) = test_routers();
    let router = routers.public.clone();
    assert_eq!(import(routers.admin.clone(), &f).await, axum::http::StatusCode::CREATED);
    let pkg = make_package(&f, 1, b"candidate-a");
    let body = serde_json::json!({"receipt_id": "11111111-1111-4111-8111-111111111111", "package_cbor_hex": hex_encode(&pkg), "api_version": "v1"}).to_string();
    let r1 = router.clone();
    let b1 = body.clone();
    let eid1 = f.election_id.clone();
    let h1 = tokio::spawn(async move { req(r1, "POST", &format!("/api/v1/elections/{}/ballots", eid1), Some(b1), &[("content-type", "application/json")]).await });
    let r2 = router.clone();
    let eid2 = f.election_id.clone();
    let h2 = tokio::spawn(async move { req(r2, "POST", &format!("/api/v1/elections/{}/ballots", eid2), Some(body), &[("content-type", "application/json")]).await });
    let (s1, _) = h1.await.unwrap_or_else(|_| panic!("join"));
    let (s2, _) = h2.await.unwrap_or_else(|_| panic!("join"));
    let statuses = [s1, s2];
    assert!(statuses.contains(&axum::http::StatusCode::CREATED));
    assert!(statuses.iter().all(|s| *s == axum::http::StatusCode::CREATED || *s == axum::http::StatusCode::OK));
    assert_eq!(storage.list_ballots(&f.election_id).map(|v| v.len()).unwrap_or(99), 1);
}

#[test]
fn sqlite_storage_persists_and_enforces_uniqueness() {
    let dir = std::env::temp_dir().join(format!("pb-hosted-sqlite-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap_or_else(|_| panic!("mkdir"));
    let db = dir.join("test.db");
    {
        let s = crate::SqliteStorage::open(&db).unwrap_or_else(|_| panic!("open"));
        s.put_election(crate::storage::ElectionRecord { id: "e1".to_owned(), manifest_cbor: vec![1], registry_cbor: vec![2], candidate_cbor: vec![3], state: "open".to_owned(), manifest_hash_hex: "00".to_owned() }).unwrap_or_else(|_| panic!("put"));
        assert!(s.put_election(crate::storage::ElectionRecord { id: "e1".to_owned(), manifest_cbor: vec![1], registry_cbor: vec![2], candidate_cbor: vec![3], state: "open".to_owned(), manifest_hash_hex: "00".to_owned() }).is_err());
        s.insert_ballot(crate::storage::BallotRecord { election_id: "e1".to_owned(), receipt_id: "r1".to_owned(), package_cbor: vec![9], envelope_hash_hex: "aa".to_owned(), nullifier: vec![1,2], seq: 1 }).unwrap_or_else(|_| panic!("insert"));
        assert_eq!(s.insert_ballot(crate::storage::BallotRecord { election_id: "e1".to_owned(), receipt_id: "r2".to_owned(), package_cbor: vec![8], envelope_hash_hex: "bb".to_owned(), nullifier: vec![1,2], seq: 2 }), Err(crate::storage::StorageError::DuplicateNullifier));
    }
    {
        let s2 = crate::SqliteStorage::open(&db).unwrap_or_else(|_| panic!("reopen"));
        assert_eq!(s2.list_ballots("e1").map(|v| v.len()).unwrap_or(99), 1);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn storage_and_config_boundaries() {
    let storage = InMemoryStorage::new();
    storage.append_ballot_envelope("e1", vec![1,2,3]);
    assert_eq!(storage.ballot_envelope_count("e1"), 1);
    assert_eq!(crate::DEFAULT_BIND, "127.0.0.1:8788");
    assert_eq!(crate::DEFAULT_ADMIN_BIND, "127.0.0.1:8789");
    let cfg = HostedConfig { bind: "0.0.0.0:8788".to_owned(), admin_bind: "127.0.0.1:8789".to_owned(), service_name: "x".to_owned(), api_version: "v1".to_owned(), db_path: std::path::PathBuf::from("x.db"), admin_token: None, origin_token: None, allow_public_bind: false, rate_limit_per_minute: 10 };
    assert!(cfg.validate().is_err());
    let cfg = HostedConfig { bind: "127.0.0.1:8788".to_owned(), admin_bind: "0.0.0.0:8789".to_owned(), service_name: "x".to_owned(), api_version: "v1".to_owned(), db_path: std::path::PathBuf::from("x.db"), admin_token: None, origin_token: None, allow_public_bind: true, rate_limit_per_minute: 10 };
    assert!(cfg.validate().is_err(), "admin bind must stay loopback even with public bind allowed");
    let cfg = HostedConfig { bind: "127.0.0.1:8788".to_owned(), admin_bind: "127.0.0.1:8788".to_owned(), service_name: "x".to_owned(), api_version: "v1".to_owned(), db_path: std::path::PathBuf::from("x.db"), admin_token: None, origin_token: None, allow_public_bind: false, rate_limit_per_minute: 10 };
    assert!(cfg.validate().is_err(), "public and admin binds must differ");
}

#[tokio::test]
async fn public_plane_never_serves_admin_mutations() {
    let f = fixture();
    let (routers, _storage) = test_routers();
    // Admin import succeeds only on the admin plane.
    assert_eq!(import(routers.admin.clone(), &f).await, axum::http::StatusCode::CREATED);
    // The public plane has no admin routes at all: import, close, finalize
    // all 404 even with a valid admin token (edge failure fails closed).
    let body = serde_json::json!({"election_id": f.election_id, "manifest_cbor_hex": hex_encode(&f.manifest_cbor), "registry_cbor_hex": hex_encode(&f.registry_cbor), "candidate_cbor_hex": hex_encode(&f.candidate_cbor)}).to_string();
    let (s1, _) = req(routers.public.clone(), "POST", "/api/v1/admin/elections/import", Some(body), &[("content-type", "application/json"), ("x-admin-token", "test-admin-token")]).await;
    assert_eq!(s1, axum::http::StatusCode::NOT_FOUND);
    let (s2, _) = req(routers.public.clone(), "POST", &format!("/api/v1/admin/elections/{}/close", f.election_id), None, &[("x-admin-token", "test-admin-token")]).await;
    assert_eq!(s2, axum::http::StatusCode::NOT_FOUND);
    let (s3, _) = req(routers.public.clone(), "POST", &format!("/api/v1/admin/elections/{}/finalize", f.election_id), None, &[("x-admin-token", "test-admin-token")]).await;
    assert_eq!(s3, axum::http::StatusCode::NOT_FOUND);
    // The admin plane does not serve voter routes.
    let (s4, _) = req(routers.admin.clone(), "GET", "/api/v1/status", None, &[]).await;
    assert_eq!(s4, axum::http::StatusCode::NOT_FOUND);
    let (s5, _) = req(routers.admin.clone(), "POST", &format!("/api/v1/elections/{}/ballots", f.election_id), Some(serde_json::json!({"receipt_id": "r", "package_cbor_hex": "00", "api_version": "v1"}).to_string()), &[("content-type", "application/json")]).await;
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
    let (s1, _) = req(routers.admin.clone(), "POST", "/api/v1/admin/elections/import", Some(body.clone()), &[("content-type", "application/json")]).await;
    assert_eq!(s1, axum::http::StatusCode::UNAUTHORIZED);
    let (s2, _) = req(routers.admin.clone(), "POST", "/api/v1/admin/elections/import", Some(body.clone()), &[("content-type", "application/json"), ("x-admin-token", "wrong-token")]).await;
    assert_eq!(s2, axum::http::StatusCode::UNAUTHORIZED);
    let (s3, _) = req(routers.admin.clone(), "POST", "/api/v1/admin/elections/import", Some(body), &[("content-type", "application/json"), ("x-admin-token", "test-admin-token")]).await;
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
    let (s3, _) = req(router.clone(), "GET", "/api/v1/status", None, &[(ORIGIN_TOKEN_HEADER, "wrong")]).await;
    assert_eq!(s3, axum::http::StatusCode::UNAUTHORIZED);
    // API with the correct header passes.
    let (s4, _) = req(router.clone(), "GET", "/api/v1/status", None, &[(ORIGIN_TOKEN_HEADER, "test-origin-secret")]).await;
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
    assert!(!b3.contains("supersecretvalue"), "error must not echo secret: {b3}");
    assert!(!b3.contains("deadbeef"), "error must not echo package: {b3}");
    assert_eq!(s3, axum::http::StatusCode::NOT_FOUND);
}

// ── Enrollment tests ──────────────────────────────────────────────────────────

use tari_cc_private_ballot_ballot::ElectionManifest;

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
    }).to_string();
    let (s, t) = req(admin.clone(), "POST", "/api/v1/admin/elections/draft", Some(body), &[("content-type", "application/json"), ("x-admin-token", "test-admin-token")]).await;
    assert_eq!(s, axum::http::StatusCode::CREATED, "create_draft: {t}");
    let (s2, t2) = req(admin.clone(), "POST", &format!("/api/v1/admin/elections/{election_id}/open-enrollment"), None, &[("x-admin-token", "test-admin-token")]).await;
    assert_eq!(s2, axum::http::StatusCode::OK, "open_enrollment: {t2}");
}

async fn issue_invitation_for_slot(admin: &axum::Router, election_id: &str, slot_id: &str) -> String {
    let body = serde_json::json!({"slot_id": slot_id}).to_string();
    let (s, t) = req(admin.clone(), "POST", &format!("/api/v1/admin/elections/{election_id}/invitations"), Some(body), &[("content-type", "application/json"), ("x-admin-token", "test-admin-token")]).await;
    assert_eq!(s, axum::http::StatusCode::CREATED, "issue_invitation: {t}");
    let v: serde_json::Value = serde_json::from_str(&t).unwrap();
    v["invitation_secret_hex"].as_str().unwrap().to_owned()
}

async fn enroll(public: &axum::Router, election_id: &str, invitation_secret_hex: &str, public_key_hex: &str) -> (axum::http::StatusCode, serde_json::Value) {
    let body = serde_json::json!({"invitation_secret_hex": invitation_secret_hex, "public_key_hex": public_key_hex}).to_string();
    let (s, t) = req(public.clone(), "POST", &format!("/api/v1/elections/{election_id}/enroll"), Some(body), &[("content-type", "application/json")]).await;
    let v: serde_json::Value = serde_json::from_str(&t).unwrap_or_else(|_| serde_json::json!({"raw": t}));
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
    let (ss, sb) = req(admin.clone(), "GET", &format!("/api/v1/admin/elections/{election_id}/enrollment"), None, &[("x-admin-token", "test-admin-token")]).await;
    assert_eq!(ss, axum::http::StatusCode::OK, "{sb}");
    let status_v: serde_json::Value = serde_json::from_str(&sb).unwrap();
    assert_eq!(status_v["enrolled_count"], 2);
    assert_eq!(status_v["eligibility_state"], "ENROLLMENT_OPEN");

    // Freeze registry
    let (sf, tf) = req(admin.clone(), "POST", &format!("/api/v1/admin/elections/{election_id}/freeze"), None, &[("x-admin-token", "test-admin-token")]).await;
    assert_eq!(sf, axum::http::StatusCode::OK, "{tf}");
    let freeze_v: serde_json::Value = serde_json::from_str(&tf).unwrap();
    assert_eq!(freeze_v["enrolled_count"], 2);
    assert!(freeze_v["registry_commitment_hex"].as_str().unwrap().len() == 64);

    // Open voting
    let (sv, tv) = req(admin.clone(), "POST", &format!("/api/v1/admin/elections/{election_id}/open-voting"), None, &[("x-admin-token", "test-admin-token")]).await;
    assert_eq!(sv, axum::http::StatusCode::CREATED, "{tv}");
    let voting_v: serde_json::Value = serde_json::from_str(&tv).unwrap();
    assert_eq!(voting_v["state"], "open");

    // Verify enrollment is closed after freeze
    let (se, te) = enroll(&public, election_id, &secret_b, &key_b).await;
    assert_eq!(se, axum::http::StatusCode::CONFLICT, "enrollment after freeze should fail: {te}");

    // Verify linkage scrubbed: slot_id and invitation_id removed from credentials
    let creds = storage.list_enrolled_credentials(election_id).unwrap();
    assert_eq!(creds.len(), 2);
    for c in &creds {
        assert!(c.slot_id.is_none(), "slot_id should be scrubbed after freeze");
        assert!(c.invitation_id.is_none(), "invitation_id should be scrubbed after freeze");
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
    assert!(v2["code"].as_str().unwrap_or("").contains("credential_conflict"), "{v2}");
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
    assert_eq!(consumed_count, 1, "second slot must not be consumed in Case C");
    // Second invitation still ACTIVE - verify by trying to enroll with it successfully for a different key
    let key2 = enroll_key(2);
    let (s3, _) = enroll(&routers.public, election_id, &secret2, &key2).await;
    assert_eq!(s3, axum::http::StatusCode::CREATED, "second slot should still be enrollable after Case C rejection");
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
    let (sf, tf) = req(routers.admin.clone(), "POST", &format!("/api/v1/admin/elections/{election_id}/freeze"), None, &[("x-admin-token", "test-admin-token")]).await;
    assert_eq!(sf, axum::http::StatusCode::OK, "{tf}");
    let (sv, tv) = req(routers.admin.clone(), "POST", &format!("/api/v1/admin/elections/{election_id}/open-voting"), None, &[("x-admin-token", "test-admin-token")]).await;
    assert_eq!(sv, axum::http::StatusCode::CREATED, "{tv}");
    // Now build the manifest from open-voting response to create a ballot
    // The election was opened with key 1 as the only enrolled credential.
    // Build a ballot using the same election id.
    let loaded_election = storage.get_election(election_id).unwrap().unwrap();
    let manifest = ElectionManifest::from_canonical_cbor(&loaded_election.manifest_cbor).unwrap();
    let candidates = CandidateSet::from_canonical_cbor(&loaded_election.candidate_cbor).unwrap();
    let registry = tari_cc_private_ballot_registry::RegistrySnapshot::from_canonical_cbor(&loaded_election.registry_cbor).unwrap();
    let p = Blake3HashProviderV1;
    let payload = ApprovalBallotPayload::new(vec![candidate_id(b"candidate-a")], &candidates, manifest.approval_limits()).unwrap();
    let verifier = build_tari_triptych_verifier_from_registry_v1(&registry, &p).unwrap();
    let statement = tari_cc_private_ballot_verifier::reconstruct_approval_proof_statement(&manifest, &payload, &p).unwrap();
    let secret_key = secret_scalar(1);
    let proof = prove_tari_triptych_prototype_v1(&statement, &verifier, &secret_key).unwrap();
    let mh = manifest.canonical_hash(&p).unwrap();
    let pkg = BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash: mh,
        proof_suite_id: manifest.proof_suite_id().to_owned(),
        proof,
        payload: payload.clone(),
    }).unwrap();
    let pkg_bytes = pkg.to_canonical_cbor().unwrap();
    // "Device 1" submits ballot
    let body1 = serde_json::json!({"receipt_id": "device1-receipt-001", "package_cbor_hex": hex_encode(&pkg_bytes), "api_version": "v1"}).to_string();
    let (sa, _) = req(routers.public.clone(), "POST", &format!("/api/v1/elections/{election_id}/ballots"), Some(body1), &[("content-type", "application/json")]).await;
    assert_eq!(sa, axum::http::StatusCode::CREATED, "first ballot should be accepted");
    // "Device 2" submits the same proof (same nullifier, same credential, same election)
    let proof2 = prove_tari_triptych_prototype_v1(&statement, &verifier, &secret_key).unwrap();
    let pkg2 = BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash: manifest.canonical_hash(&p).unwrap(),
        proof_suite_id: manifest.proof_suite_id().to_owned(),
        proof: proof2,
        payload,
    }).unwrap();
    let pkg2_bytes = pkg2.to_canonical_cbor().unwrap();
    let body2 = serde_json::json!({"receipt_id": "device2-receipt-002", "package_cbor_hex": hex_encode(&pkg2_bytes), "api_version": "v1"}).to_string();
    let (sb, rb) = req(routers.public.clone(), "POST", &format!("/api/v1/elections/{election_id}/ballots"), Some(body2), &[("content-type", "application/json")]).await;
    assert_eq!(sb, axum::http::StatusCode::CONFLICT, "cross-device duplicate vote must be rejected: {rb}");
    assert!(rb.contains("duplicate_nullifier"), "must report duplicate_nullifier: {rb}");
}

#[tokio::test]
async fn freeze_immutability_no_enrollment_after_freeze() {
    let f = fixture();
    let (routers, storage) = test_routers();
    let election_id = "enroll-freeze-immut";
    create_draft_and_open_enrollment(&routers.admin, election_id, &f.candidate_cbor, 2).await;
    let slots = storage.list_slots(election_id).unwrap();
    // Issue invitation for slot[1] BEFORE freeze so we can try to enroll with it after.
    let secret_slot1 = issue_invitation_for_slot(&routers.admin, election_id, &slots[0].slot_id).await;
    let secret_slot2_pre = issue_invitation_for_slot(&routers.admin, election_id, &slots[1].slot_id).await;
    let (s1, _) = enroll(&routers.public, election_id, &secret_slot1, &enroll_key(1)).await;
    assert_eq!(s1, axum::http::StatusCode::CREATED);
    // Freeze
    let (sf, tf) = req(routers.admin.clone(), "POST", &format!("/api/v1/admin/elections/{election_id}/freeze"), None, &[("x-admin-token", "test-admin-token")]).await;
    assert_eq!(sf, axum::http::StatusCode::OK, "{tf}");
    // Double-freeze must fail
    let (sf2, tf2) = req(routers.admin.clone(), "POST", &format!("/api/v1/admin/elections/{election_id}/freeze"), None, &[("x-admin-token", "test-admin-token")]).await;
    assert_eq!(sf2, axum::http::StatusCode::CONFLICT, "double-freeze: {tf2}");
    // Issuing a NEW invitation after freeze must fail (state is REGISTRY_FROZEN)
    let (si, ti) = req(routers.admin.clone(), "POST", &format!("/api/v1/admin/elections/{election_id}/invitations"),
        Some(serde_json::json!({"slot_id": &slots[1].slot_id}).to_string()),
        &[("content-type", "application/json"), ("x-admin-token", "test-admin-token")]).await;
    assert_eq!(si, axum::http::StatusCode::CONFLICT, "post-freeze invitation issue should fail: {ti}");
    // Enrolling with an invitation issued BEFORE freeze must also fail (state is REGISTRY_FROZEN)
    let (se, te) = enroll(&routers.public, election_id, &secret_slot2_pre, &enroll_key(2)).await;
    assert_eq!(se, axum::http::StatusCode::CONFLICT, "enrollment after freeze with pre-freeze invitation: {te}");
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
    let (_, t) = req(routers.admin.clone(), "POST", &format!("/api/v1/admin/elections/{election_id}/invitations"), Some(body), &[("content-type", "application/json"), ("x-admin-token", "test-admin-token")]).await;
    let v: serde_json::Value = serde_json::from_str(&t).unwrap();
    let secret_hex = v["invitation_secret_hex"].as_str().unwrap().to_owned();
    // Retrieve the stored invitation record
    let invitation = storage.get_active_invitation_for_slot(slot_id).unwrap().unwrap();
    // The stored verifier must NOT equal the secret
    assert_ne!(invitation.verifier_hex, secret_hex, "invitation plaintext must not be stored as verifier");
    // The stored verifier must equal the computed verifier from the secret
    let secret_bytes = crate::hex_decode(&secret_hex).unwrap();
    let computed_verifier = crate::invitation_verifier(&secret_bytes);
    assert_eq!(invitation.verifier_hex, computed_verifier, "stored verifier must match computed verifier");
    // The raw secret must have 256 bits of entropy (64 hex chars = 32 bytes)
    assert_eq!(secret_hex.len(), 64, "invitation secret must be 32 bytes (64 hex chars)");
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
    let inv = storage.get_active_invitation_for_slot(slot_id).unwrap().unwrap();
    let (sv, tv) = req(routers.admin.clone(), "POST", &format!("/api/v1/admin/elections/{election_id}/invitations/{}/void", inv.invitation_id), None, &[("x-admin-token", "test-admin-token")]).await;
    assert_eq!(sv, axum::http::StatusCode::OK, "{tv}");
    // Voided secret can no longer enroll
    let (se, te) = enroll(&routers.public, election_id, &secret1, &enroll_key(1)).await;
    assert_eq!(se, axum::http::StatusCode::UNAUTHORIZED, "voided invitation: {te}");
    // Reissue: issue a new invitation for the same slot
    let secret2 = issue_invitation_for_slot(&routers.admin, election_id, slot_id).await;
    assert_ne!(secret1, secret2, "reissued secret must differ");
    // New secret can enroll
    let (sn, tn) = enroll(&routers.public, election_id, &secret2, &enroll_key(1)).await;
    assert_eq!(sn, axum::http::StatusCode::CREATED, "reissued enrollment: {tn}");
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
    assert_eq!(s, axum::http::StatusCode::UNAUTHORIZED, "wrong-election invitation must be rejected: {v}");
    // The same secret is valid in its own election A
    let (s2, v2) = enroll(&routers.public, election_a, &secret_a, &enroll_key(1)).await;
    assert_eq!(s2, axum::http::StatusCode::CREATED, "own-election invitation must succeed: {v2}");
}

#[test]
fn deterministic_registry_commitment_and_domain_separation() {
    use tari_cc_private_ballot_registry::{GovernancePublicKey, RegistryEntry, RegistrySnapshot,
        VoterGovernanceKeyRegistrationV1, VoterKeyProvisioningV1};
    use tari_cc_private_ballot_protocol::Blake3HashProviderV1;
    let p = Blake3HashProviderV1;
    let key1 = point_bytes(1).to_vec();
    let key2 = point_bytes(2).to_vec();
    let key3 = point_bytes(3).to_vec();
    let make_entry = |k: Vec<u8>| {
        let gk = GovernancePublicKey::new(k).expect("gk");
        let reg = VoterGovernanceKeyRegistrationV1::new(gk, VoterKeyProvisioningV1::GeneratedByVoter);
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
    assert_eq!(commit1a.as_bytes(), commit1b.as_bytes(), "commitment must be deterministic");
    assert_eq!(commit1a.as_bytes(), commit2.as_bytes(), "same entries → same commitment");
    // Different entries → different commitment
    let entries3 = vec![make_entry(key1.clone()), make_entry(key3.clone())];
    let snap3 = RegistrySnapshot::new(entries3).expect("snap3");
    let commit3 = snap3.canonical_commitment(&p).expect("c3");
    assert_ne!(commit1a.as_bytes(), commit3.as_bytes(), "different entries → different commitment");
    // Single entry → different from two-entry
    let entries4 = vec![make_entry(key1.clone())];
    let snap4 = RegistrySnapshot::new(entries4).expect("snap4");
    let commit4 = snap4.canonical_commitment(&p).expect("c4");
    assert_ne!(commit1a.as_bytes(), commit4.as_bytes(), "different count → different commitment");
    // Domain separation: commitment must differ from raw BLAKE3 of the registry CBOR bytes
    let cbor1 = snap1.to_canonical_cbor().expect("cbor");
    let raw_hash = {
        use tari_cc_private_ballot_protocol::HashProvider;
        p.hash(&cbor1)
    };
    assert_ne!(commit1a.as_bytes(), &raw_hash, "commitment must use domain separation, not raw BLAKE3");
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
    let (sv1, tv1) = req(routers.public.clone(), "POST", &format!("/api/v1/elections/{election_id}/ballots"), Some(pkg.clone()), &[("content-type", "application/json")]).await;
    assert_eq!(sv1, axum::http::StatusCode::NOT_FOUND, "ballot before freeze must 404: {tv1}");
    // Freeze but don't open voting: still 404
    let (sf, _) = req(routers.admin.clone(), "POST", &format!("/api/v1/admin/elections/{election_id}/freeze"), None, &[("x-admin-token", "test-admin-token")]).await;
    assert_eq!(sf, axum::http::StatusCode::OK);
    let (sv2, tv2) = req(routers.public.clone(), "POST", &format!("/api/v1/elections/{election_id}/ballots"), Some(pkg), &[("content-type", "application/json")]).await;
    assert_eq!(sv2, axum::http::StatusCode::NOT_FOUND, "ballot before open-voting must 404: {tv2}");
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
    let (sf, _) = req(routers.admin.clone(), "POST", &format!("/api/v1/admin/elections/{election_id}/freeze"), None, &[("x-admin-token", "test-admin-token")]).await;
    assert_eq!(sf, axum::http::StatusCode::OK);
    let (sv, _) = req(routers.admin.clone(), "POST", &format!("/api/v1/admin/elections/{election_id}/open-voting"), None, &[("x-admin-token", "test-admin-token")]).await;
    assert_eq!(sv, axum::http::StatusCode::CREATED);
    // Build a ballot using the FIXTURE registry (which has keys 1,2,3) for key 2.
    // The enrolled election uses a 1-entry registry for key 1 → different commitment →
    // different manifest hash → wrong_election rejection.
    let pkg_unenrolled = make_package(&f, 2, b"candidate-a"); // key 2 is in fixture but not enrolled
    let body = serde_json::json!({"receipt_id": "unenrolled-r-001", "package_cbor_hex": hex_encode(&pkg_unenrolled), "api_version": "v1"}).to_string();
    let (sr, tr) = req(routers.public.clone(), "POST", &format!("/api/v1/elections/{election_id}/ballots"), Some(body), &[("content-type", "application/json")]).await;
    // The package is bound to a different manifest (different registry commitment) → wrong_election
    assert_eq!(sr, axum::http::StatusCode::UNPROCESSABLE_ENTITY, "unenrolled credential ballot must be rejected: {tr}");
    assert!(tr.contains("wrong_election") || tr.contains("ballot_invalid"), "wrong rejection code: {tr}");
    // Confirm the enrolled key CAN vote successfully
    let loaded_election = storage.get_election(election_id).unwrap().unwrap();
    let manifest = ElectionManifest::from_canonical_cbor(&loaded_election.manifest_cbor).unwrap();
    let candidates = CandidateSet::from_canonical_cbor(&loaded_election.candidate_cbor).unwrap();
    let registry = tari_cc_private_ballot_registry::RegistrySnapshot::from_canonical_cbor(&loaded_election.registry_cbor).unwrap();
    let p = Blake3HashProviderV1;
    let payload = ApprovalBallotPayload::new(vec![candidate_id(b"candidate-a")], &candidates, manifest.approval_limits()).unwrap();
    let verifier = build_tari_triptych_verifier_from_registry_v1(&registry, &p).unwrap();
    let statement = tari_cc_private_ballot_verifier::reconstruct_approval_proof_statement(&manifest, &payload, &p).unwrap();
    let proof = prove_tari_triptych_prototype_v1(&statement, &verifier, &secret_scalar(1)).unwrap();
    let mh = manifest.canonical_hash(&p).unwrap();
    let pkg_enrolled = BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1, manifest_hash: mh,
        proof_suite_id: manifest.proof_suite_id().to_owned(), proof, payload,
    }).unwrap().to_canonical_cbor().unwrap();
    let body2 = serde_json::json!({"receipt_id": "enrolled-r-001", "package_cbor_hex": hex_encode(&pkg_enrolled), "api_version": "v1"}).to_string();
    let (sa, ta) = req(routers.public.clone(), "POST", &format!("/api/v1/elections/{election_id}/ballots"), Some(body2), &[("content-type", "application/json")]).await;
    assert_eq!(sa, axum::http::StatusCode::CREATED, "enrolled key must vote successfully: {ta}");
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
    let (sf, _) = req(routers.admin.clone(), "POST", &format!("/api/v1/admin/elections/{election_id}/freeze"), None, &[("x-admin-token", "test-admin-token")]).await;
    assert_eq!(sf, axum::http::StatusCode::OK);
    let (sv, tv) = req(routers.admin.clone(), "POST", &format!("/api/v1/admin/elections/{election_id}/open-voting"), None, &[("x-admin-token", "test-admin-token")]).await;
    assert_eq!(sv, axum::http::StatusCode::CREATED, "{tv}");
    // Both credentials vote using the enrolled registry
    let loaded = storage.get_election(election_id).unwrap().unwrap();
    let manifest = ElectionManifest::from_canonical_cbor(&loaded.manifest_cbor).unwrap();
    let candidates = CandidateSet::from_canonical_cbor(&loaded.candidate_cbor).unwrap();
    let registry = tari_cc_private_ballot_registry::RegistrySnapshot::from_canonical_cbor(&loaded.registry_cbor).unwrap();
    let p = Blake3HashProviderV1;
    let verifier = build_tari_triptych_verifier_from_registry_v1(&registry, &p).unwrap();
    let mh = manifest.canonical_hash(&p).unwrap();
    // Credential A votes
    let payload_a = ApprovalBallotPayload::new(vec![candidate_id(b"candidate-a")], &candidates, manifest.approval_limits()).unwrap();
    let stmt_a = tari_cc_private_ballot_verifier::reconstruct_approval_proof_statement(&manifest, &payload_a, &p).unwrap();
    let proof_a = prove_tari_triptych_prototype_v1(&stmt_a, &verifier, &secret_scalar(1)).unwrap();
    let pkg_a = BallotPackageV1::new(BallotPackageV1Input { protocol_version: PROTOCOL_VERSION_V1, manifest_hash: mh.clone(), proof_suite_id: manifest.proof_suite_id().to_owned(), proof: proof_a, payload: payload_a }).unwrap().to_canonical_cbor().unwrap();
    let (sa, ta) = req(routers.public.clone(), "POST", &format!("/api/v1/elections/{election_id}/ballots"), Some(serde_json::json!({"receipt_id": "two-slots-r-a", "package_cbor_hex": hex_encode(&pkg_a), "api_version": "v1"}).to_string()), &[("content-type", "application/json")]).await;
    assert_eq!(sa, axum::http::StatusCode::CREATED, "credential A must vote: {ta}");
    // Credential B votes
    let payload_b = ApprovalBallotPayload::new(vec![candidate_id(b"candidate-b")], &candidates, manifest.approval_limits()).unwrap();
    let stmt_b = tari_cc_private_ballot_verifier::reconstruct_approval_proof_statement(&manifest, &payload_b, &p).unwrap();
    let proof_b = prove_tari_triptych_prototype_v1(&stmt_b, &verifier, &secret_scalar(2)).unwrap();
    let pkg_b = BallotPackageV1::new(BallotPackageV1Input { protocol_version: PROTOCOL_VERSION_V1, manifest_hash: mh.clone(), proof_suite_id: manifest.proof_suite_id().to_owned(), proof: proof_b, payload: payload_b }).unwrap().to_canonical_cbor().unwrap();
    let (sb, tb) = req(routers.public.clone(), "POST", &format!("/api/v1/elections/{election_id}/ballots"), Some(serde_json::json!({"receipt_id": "two-slots-r-b", "package_cbor_hex": hex_encode(&pkg_b), "api_version": "v1"}).to_string()), &[("content-type", "application/json")]).await;
    assert_eq!(sb, axum::http::StatusCode::CREATED, "credential B must vote: {tb}");
    // Second attempt by A is rejected (duplicate nullifier)
    let payload_a2 = ApprovalBallotPayload::new(vec![candidate_id(b"candidate-c")], &candidates, manifest.approval_limits()).unwrap();
    let stmt_a2 = tari_cc_private_ballot_verifier::reconstruct_approval_proof_statement(&manifest, &payload_a2, &p).unwrap();
    let proof_a2 = prove_tari_triptych_prototype_v1(&stmt_a2, &verifier, &secret_scalar(1)).unwrap();
    let pkg_a2 = BallotPackageV1::new(BallotPackageV1Input { protocol_version: PROTOCOL_VERSION_V1, manifest_hash: mh, proof_suite_id: manifest.proof_suite_id().to_owned(), proof: proof_a2, payload: payload_a2 }).unwrap().to_canonical_cbor().unwrap();
    let (sc, tc) = req(routers.public.clone(), "POST", &format!("/api/v1/elections/{election_id}/ballots"), Some(serde_json::json!({"receipt_id": "two-slots-r-a2", "package_cbor_hex": hex_encode(&pkg_a2), "api_version": "v1"}).to_string()), &[("content-type", "application/json")]).await;
    assert_eq!(sc, axum::http::StatusCode::CONFLICT, "credential A second vote must be rejected: {tc}");
    assert!(tc.contains("duplicate_nullifier"), "{tc}");
    assert_eq!(storage.list_ballots(election_id).unwrap().len(), 2, "exactly 2 ballots accepted");
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
    let (ss, sb_status) = req(routers.admin.clone(), "GET", &format!("/api/v1/admin/elections/{election_id}/enrollment"), None, &[("x-admin-token", "test-admin-token")]).await;
    assert_eq!(ss, axum::http::StatusCode::OK);
    let status_v: serde_json::Value = serde_json::from_str(&sb_status).unwrap();
    assert_eq!(status_v["enrolled_count"], 2);
    assert_eq!(status_v["authorized_slot_count"], 3);
    // Freeze at 2/3
    let (sf, tf) = req(routers.admin.clone(), "POST", &format!("/api/v1/admin/elections/{election_id}/freeze"), None, &[("x-admin-token", "test-admin-token")]).await;
    assert_eq!(sf, axum::http::StatusCode::OK, "{tf}");
    let freeze_v: serde_json::Value = serde_json::from_str(&tf).unwrap();
    assert_eq!(freeze_v["enrolled_count"], 2);
    assert_eq!(freeze_v["authorized_slot_count"], 3);
    // Open voting
    let (sv, _) = req(routers.admin.clone(), "POST", &format!("/api/v1/admin/elections/{election_id}/open-voting"), None, &[("x-admin-token", "test-admin-token")]).await;
    assert_eq!(sv, axum::http::StatusCode::CREATED);
    let loaded = storage.get_election(election_id).unwrap().unwrap();
    let manifest = ElectionManifest::from_canonical_cbor(&loaded.manifest_cbor).unwrap();
    let candidates = CandidateSet::from_canonical_cbor(&loaded.candidate_cbor).unwrap();
    let registry = tari_cc_private_ballot_registry::RegistrySnapshot::from_canonical_cbor(&loaded.registry_cbor).unwrap();
    // Registry has exactly 2 members (A and B, C not enrolled)
    assert_eq!(registry.entries().len(), 2, "registry must have exactly 2 enrolled members");
    let p = Blake3HashProviderV1;
    let verifier = build_tari_triptych_verifier_from_registry_v1(&registry, &p).unwrap();
    let mh = manifest.canonical_hash(&p).unwrap();
    // A votes (device 1)
    let payload_a = ApprovalBallotPayload::new(vec![candidate_id(b"candidate-a")], &candidates, manifest.approval_limits()).unwrap();
    let stmt_a = tari_cc_private_ballot_verifier::reconstruct_approval_proof_statement(&manifest, &payload_a, &p).unwrap();
    let proof_a1 = prove_tari_triptych_prototype_v1(&stmt_a, &verifier, &secret_scalar(1)).unwrap();
    let pkg_a1 = BallotPackageV1::new(BallotPackageV1Input { protocol_version: PROTOCOL_VERSION_V1, manifest_hash: mh.clone(), proof_suite_id: manifest.proof_suite_id().to_owned(), proof: proof_a1, payload: payload_a.clone() }).unwrap().to_canonical_cbor().unwrap();
    let (ra1, ta1) = req(routers.public.clone(), "POST", &format!("/api/v1/elections/{election_id}/ballots"), Some(serde_json::json!({"receipt_id": "synth-a1", "package_cbor_hex": hex_encode(&pkg_a1), "api_version": "v1"}).to_string()), &[("content-type", "application/json")]).await;
    assert_eq!(ra1, axum::http::StatusCode::CREATED, "A first vote: {ta1}");
    // A votes again (device 2, new proof, same credential) → duplicate_nullifier
    let stmt_a2 = tari_cc_private_ballot_verifier::reconstruct_approval_proof_statement(&manifest, &payload_a, &p).unwrap();
    let proof_a2 = prove_tari_triptych_prototype_v1(&stmt_a2, &verifier, &secret_scalar(1)).unwrap();
    let pkg_a2_bytes = BallotPackageV1::new(BallotPackageV1Input { protocol_version: PROTOCOL_VERSION_V1, manifest_hash: mh.clone(), proof_suite_id: manifest.proof_suite_id().to_owned(), proof: proof_a2, payload: payload_a }).unwrap().to_canonical_cbor().unwrap();
    assert_ne!(pkg_a1, pkg_a2_bytes, "proof bytes should differ (randomized Triptych); nullifier identical");
    let (ra2, ta2) = req(routers.public.clone(), "POST", &format!("/api/v1/elections/{election_id}/ballots"), Some(serde_json::json!({"receipt_id": "synth-a2", "package_cbor_hex": hex_encode(&pkg_a2_bytes), "api_version": "v1"}).to_string()), &[("content-type", "application/json")]).await;
    assert_eq!(ra2, axum::http::StatusCode::CONFLICT, "A second vote must be rejected: {ta2}");
    assert!(ta2.contains("duplicate_nullifier"), "{ta2}");
    // B votes
    let payload_b = ApprovalBallotPayload::new(vec![candidate_id(b"candidate-b")], &candidates, manifest.approval_limits()).unwrap();
    let stmt_b = tari_cc_private_ballot_verifier::reconstruct_approval_proof_statement(&manifest, &payload_b, &p).unwrap();
    let proof_b = prove_tari_triptych_prototype_v1(&stmt_b, &verifier, &secret_scalar(2)).unwrap();
    let pkg_b = BallotPackageV1::new(BallotPackageV1Input { protocol_version: PROTOCOL_VERSION_V1, manifest_hash: mh, proof_suite_id: manifest.proof_suite_id().to_owned(), proof: proof_b, payload: payload_b }).unwrap().to_canonical_cbor().unwrap();
    let (rb, tb) = req(routers.public.clone(), "POST", &format!("/api/v1/elections/{election_id}/ballots"), Some(serde_json::json!({"receipt_id": "synth-b", "package_cbor_hex": hex_encode(&pkg_b), "api_version": "v1"}).to_string()), &[("content-type", "application/json")]).await;
    assert_eq!(rb, axum::http::StatusCode::CREATED, "B vote: {tb}");
    // Close and finalize
    let (rc, _) = req(routers.admin.clone(), "POST", &format!("/api/v1/admin/elections/{election_id}/close"), None, &[("x-admin-token", "test-admin-token")]).await;
    assert_eq!(rc, axum::http::StatusCode::OK);
    let (rfin, tfin) = req(routers.admin.clone(), "POST", &format!("/api/v1/admin/elections/{election_id}/finalize"), None, &[("x-admin-token", "test-admin-token")]).await;
    assert_eq!(rfin, axum::http::StatusCode::OK, "{tfin}");
    // Results: exactly 2 accepted ballots (A and B); C never voted
    let (rres, tres) = req(routers.public.clone(), "GET", &format!("/api/v1/elections/{election_id}/results"), None, &[]).await;
    assert_eq!(rres, axum::http::StatusCode::OK, "{tres}");
    let results: serde_json::Value = serde_json::from_str(&tres).unwrap();
    assert_eq!(results["accepted_ballots"], 2, "exactly 2 votes accepted (C never enrolled/voted)");
    // Archive endpoint: verify the archive can be generated and contains the frozen registry
    let (rar, tar) = req(routers.public.clone(), "GET", &format!("/api/v1/elections/{election_id}/archive"), None, &[]).await;
    assert_eq!(rar, axum::http::StatusCode::OK, "{tar}");
    let archive: serde_json::Value = serde_json::from_str(&tar).unwrap();
    // Archive must contain voter_registry.cbor
    let files = archive["files"].as_array().expect("files array");
    assert!(files.iter().any(|f| f["path"].as_str().unwrap_or("").contains("voter-registry")), "archive must include voter registry");
    // Write archive to temp dir and verify with EXISTING desktop verifier
    let dir = std::env::temp_dir().join(format!("pb-synth-3slot-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Reconstruct the enrolled election manifest (not the fixture manifest)
    let enrolled_manifest = manifest;
    struct TmpFixture { manifest_cbor: Vec<u8>, registry_cbor: Vec<u8>, candidate_cbor: Vec<u8>, election_id: String }
    let enroll_fixture = TmpFixture {
        manifest_cbor: enrolled_manifest.to_canonical_cbor().unwrap(),
        registry_cbor: loaded.registry_cbor.clone(),
        candidate_cbor: loaded.candidate_cbor.clone(),
        election_id: election_id.to_owned(),
    };
    // Write archive files from endpoint response
    {
        use std::collections::BTreeMap;
        use tari_cc_private_ballot_archive::{ArchiveFileCatalogV1, ArchiveFileEntryV1, ArchiveManifestV1, ArchivePathV1, ARCHIVE_MANIFEST_CANONICAL_PATH};
        let p2 = Blake3HashProviderV1;
        let mut map: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for file in files {
            let path = file["path"].as_str().unwrap_or("").to_owned();
            let hex = file["cbor_hex"].as_str().unwrap_or("");
            let bytes = crate::hex_decode(hex).unwrap();
            map.insert(path, bytes);
        }
        let enroll_manifest_obj = tari_cc_private_ballot_ballot::ElectionManifest::from_canonical_cbor(&enroll_fixture.manifest_cbor).unwrap();
        let mh2 = enroll_manifest_obj.canonical_hash(&p2).unwrap();
        let entries2: Vec<ArchiveFileEntryV1> = map.iter().map(|(path, bytes)| ArchiveFileEntryV1::for_bytes(ArchivePathV1::new(path.clone()).unwrap(), &p2, bytes)).collect();
        let catalog2 = ArchiveFileCatalogV1::new(entries2).unwrap();
        let am = ArchiveManifestV1::finalized_for_provider(mh2, catalog2, &p2).unwrap();
        let am_bytes = am.to_canonical_cbor().unwrap();
        let submissions_dir = dir.join("submissions");
        if map.keys().any(|k| k.starts_with("submissions")) { std::fs::create_dir_all(&submissions_dir).unwrap(); }
        for (path, bytes) in &map { let fp = dir.join(path); if let Some(parent) = fp.parent() { std::fs::create_dir_all(parent).unwrap(); } std::fs::write(&fp, bytes).unwrap(); }
        std::fs::write(dir.join(ARCHIVE_MANIFEST_CANONICAL_PATH), &am_bytes).unwrap();
    }
    assert!(verify_archive_dir_for_test(&dir), "desktop verifier must pass 3-slot synthetic election archive");
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
    assert!(s1.is_success() || s1 == axum::http::StatusCode::CONFLICT,
        "caller 1 must get a safe outcome, got {s1}: {v1}");
    assert!(s2.is_success() || s2 == axum::http::StatusCode::CONFLICT,
        "caller 2 must get a safe outcome, got {s2}: {v2}");
    // At least one CREATED
    assert!(s1 == axum::http::StatusCode::CREATED || s2 == axum::http::StatusCode::CREATED,
        "at least one caller must get CREATED: {s1} {v1} / {s2} {v2}");
    // No double enrollment: exactly 1 credential
    let creds = storage.list_enrolled_credentials(election_id).unwrap();
    assert_eq!(creds.len(), 1, "exactly one credential must be enrolled after same-invitation race");
    // Exactly 1 slot consumed
    let slots2 = storage.list_slots(election_id).unwrap();
    assert_eq!(slots2.iter().filter(|s| s.consumed).count(), 1,
        "exactly one slot must be consumed after same-invitation race");
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
        (s1 == axum::http::StatusCode::CREATED && s2 == axum::http::StatusCode::CONFLICT) ||
        (s2 == axum::http::StatusCode::CREATED && s1 == axum::http::StatusCode::CONFLICT),
        "exactly one CREATED and one CONFLICT required: {s1}:{v1} / {s2}:{v2}"
    );
    // Exactly 1 credential enrolled
    let creds = storage.list_enrolled_credentials(election_id).unwrap();
    assert_eq!(creds.len(), 1, "exactly one credential enrolled after different-invitation race");
    // Exactly 1 slot consumed (the losing slot must be UNCONSUMED)
    let slots2 = storage.list_slots(election_id).unwrap();
    let consumed: Vec<_> = slots2.iter().filter(|s| s.consumed).collect();
    assert_eq!(consumed.len(), 1, "exactly one slot consumed after different-invitation race");

    // The winning credential is key X; identify which invitation won and which lost
    // The losing invitation must remain usable for enrolling a DIFFERENT key (key Y)
    let key_y = enroll_key(6);
    // Determine losing secret: whichever invitation's slot was NOT consumed
    let losing_slot_id = slots2.iter().find(|s| !s.consumed).map(|s| s.slot_id.clone()).unwrap();
    let losing_secret = if slots[0].slot_id == losing_slot_id { &secret_a } else { &secret_b };
    let (sy, vy) = enroll(&routers.public, election_id, losing_secret, &key_y).await;
    assert_eq!(sy, axum::http::StatusCode::CREATED,
        "losing slot must remain enrollable after race: {vy}");
    // Now 2 credentials enrolled total (key X from winner + key Y from losing slot)
    let creds2 = storage.list_enrolled_credentials(election_id).unwrap();
    assert_eq!(creds2.len(), 2, "total 2 credentials after using losing slot");
}
