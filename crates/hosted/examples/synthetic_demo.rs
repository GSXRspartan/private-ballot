#![forbid(unsafe_code)]

//! Prints a synthetic hosted election as JSON (public artifacts + synthetic
//! voter secrets for local demo ONLY). Run:
//! `cargo run -p tari-cc-private-ballot-hosted --example synthetic_demo`
//! Output is written to stdout; redirect to a file outside the repo.
//! Synthetic secrets are deterministic scalars 1,2,3 hex - never use for
//! a real election.

use curve25519_dalek_v4::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use tari_cc_private_ballot_ballot::{
    ApprovalLimits, BallotConfidentialityV1, BallotKindV1, CandidateDefinition, CandidateId,
    CandidateSet, ElectionId, ElectionManifestV1, ElectionManifestV1Input, ElectionManifestModel,
};
use tari_cc_private_ballot_crypto::TARI_TRIPTYCH_PROOF_SUITE_ID_V1;
use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, CanonicalCborWriter, PROTOCOL_VERSION_V1, HashProvider};
use tari_cc_private_ballot_registry::RegistrySnapshot;

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
fn point(m: u64) -> [u8; 32] { (RISTRETTO_BASEPOINT_POINT * Scalar::from(m)).compress().to_bytes() }
fn cid(b: &[u8]) -> CandidateId { match CandidateId::new(b.to_vec()) { Ok(v) => v, Err(_) => panic!("cid") } }

fn main() {
    let p = Blake3HashProviderV1;
    let mut keys = vec![point(1), point(2), point(3)];
    keys.sort_unstable();
    let mut w = CanonicalCborWriter::new();
    assert!(w.write_array_len(keys.len()).is_ok());
    for k in &keys { assert!(w.write_byte_string(k).is_ok()); }
    let registry = match RegistrySnapshot::from_canonical_cbor(&w.into_bytes()) { Ok(v) => v, Err(e) => panic!("registry: {}", e.code().as_str()) };
    let registry_cbor = match registry.to_canonical_cbor() { Ok(v) => v, Err(e) => panic!("reg cbor: {}", e.code().as_str()) };
    let reg_commit = match registry.canonical_commitment(&p) { Ok(v) => v, Err(e) => panic!("commit: {}", e.code().as_str()) };
    let cand = |id: &[u8], name: &str| match CandidateDefinition::new(cid(id), name.to_owned()) { Ok(v) => v, Err(_) => panic!("cand") };
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
    // Ensure ElectionManifestModel trait is in scope for canonical_hash parity check
    let mh = match manifest.canonical_hash(&p) { Ok(v) => v, Err(_) => panic!("mh") };
    let manifest_cbor = match manifest.to_canonical_cbor() { Ok(v) => v, Err(_) => panic!("manifest cbor") };
    let out = serde_json::json!({
        "election_id": "hosted-synthetic-001",
        "manifest_cbor_hex": hex(&manifest_cbor),
        "registry_cbor_hex": hex(&registry_cbor),
        "candidate_cbor_hex": hex(&candidate_cbor),
        "manifest_hash_hex": hex(mh.as_bytes()),
        "voters": [
            {"name": "voter-a-synthetic", "secret_key_hex": hex(&Scalar::from(1_u64).to_bytes())},
            {"name": "voter-b-synthetic", "secret_key_hex": hex(&Scalar::from(2_u64).to_bytes())},
            {"name": "voter-c-synthetic", "secret_key_hex": hex(&Scalar::from(3_u64).to_bytes())}
        ],
        "candidates": [
            {"id_hex": hex(b"candidate-a"), "display_name": "Candidate A"},
            {"id_hex": hex(b"candidate-b"), "display_name": "Candidate B"},
            {"id_hex": hex(b"candidate-c"), "display_name": "Candidate C"}
        ]
    });
    let text = serde_json::to_string_pretty(&out).unwrap_or_else(|_| panic!("json"));
    if let Some(path) = std::env::args().nth(1) {
        std::fs::write(&path, &text).unwrap_or_else(|_| panic!("write demo"));
    } else {
        println!("{text}");
    }
}
