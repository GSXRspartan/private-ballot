#![forbid(unsafe_code)]

//! Browser Private Ballot cryptography (Stage 2).
//!
//! Runs ENTIRELY in the browser. Voter secret scalars are accepted from
//! in-memory JS state, used once to construct a Triptych proof, zeroized on
//! drop inside `TariTriptychSecretKeyV1`, and never returned, logged, or
//! sent to the backend. Only the canonical ballot package (PUBLIC
//! confidentiality by protocol design), its envelope hash, and the public
//! nullifier (linking tag, revealed only after local verification) leave
//! this module.
//!
//! Randomness: `prove_tari_triptych_prototype_v1` uses OS RNG internally;
//! on wasm32-unknown-unknown `getrandom` is built with the `js` feature so
//! the browser WebCrypto CSPRNG supplies randomness. No deterministic test
//! RNG is used.

use tari_cc_private_ballot_ballot::{
    ApprovalBallotPayload, BallotPackageV1, BallotPackageV1Input, CandidateId, CandidateSet,
    ElectionManifest,
};
use tari_cc_private_ballot_crypto::{
    TariTriptychSecretKeyV1, prove_tari_triptych_prototype_v1,
};
use tari_cc_private_ballot_protocol::{
    Blake3HashProviderV1, HashDomain, HashProvider, PROTOCOL_VERSION_V1, hash_domain_separated,
};
use tari_cc_private_ballot_registry::RegistrySnapshot;
use tari_cc_private_ballot_verifier::{
    build_tari_triptych_verifier_from_registry_v1, reconstruct_approval_proof_statement,
    verify_approval_proof,
};
use wasm_bindgen::prelude::*;

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes { out.push_str(&format!("{b:02x}")); }
    out
}
fn hex_decode(input: &str) -> Result<Vec<u8>, String> {
    let input = input.trim();
    if input.len() % 2 != 0 || !input.chars().all(|c| c.is_ascii_hexdigit()) { return Err("invalid hex".to_owned()); }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = char::from(bytes[i]).to_digit(16).ok_or_else(|| "invalid hex".to_owned())?;
        let lo = char::from(bytes[i + 1]).to_digit(16).ok_or_else(|| "invalid hex".to_owned())?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Ok(out)
}
fn err(msg: &str) -> String { serde_json::json!({"ok": false, "error": msg}).to_string() }
fn ok_json(v: serde_json::Value) -> String { let mut m = serde_json::json!({"ok": true}); if let Some(obj) = m.as_object_mut() { if let Some(o) = v.as_object() { for (k, val) in o { obj.insert(k.clone(), val.clone()); } } } m.to_string() }

/// Election information for rendering the ballot UI without CBOR parsing in JS.
#[wasm_bindgen]
pub fn election_info(manifest_hex: &str, registry_hex: &str, candidate_hex: &str) -> String {
    match election_info_inner(manifest_hex, registry_hex, candidate_hex) {
        Ok(v) => ok_json(v),
        Err(e) => err(&e),
    }
}
fn election_info_inner(manifest_hex: &str, registry_hex: &str, candidate_hex: &str) -> Result<serde_json::Value, String> {
    let manifest_cbor = hex_decode(manifest_hex)?;
    let registry_cbor = hex_decode(registry_hex)?;
    let candidate_cbor = hex_decode(candidate_hex)?;
    let manifest = ElectionManifest::from_canonical_cbor(&manifest_cbor).map_err(|e| e.code().as_str().to_owned())?;
    let candidates = CandidateSet::from_canonical_cbor(&candidate_cbor).map_err(|e| e.code().as_str().to_owned())?;
    let registry = RegistrySnapshot::from_canonical_cbor(&registry_cbor).map_err(|e| e.code().as_str().to_owned())?;
    let p = Blake3HashProviderV1;
    let mh = manifest.canonical_hash(&p).map_err(|e| e.code().as_str().to_owned())?;
    let cand_json: Vec<_> = candidates.candidates().iter().map(|c| serde_json::json!({"id_hex": hex_encode(c.id().as_bytes()), "id_text": String::from_utf8_lossy(c.id().as_bytes()), "display_name": c.display_name()})).collect();
    Ok(serde_json::json!({
        "election_id_hex": hex_encode(manifest.election_id().as_bytes()),
        "election_id_text": String::from_utf8_lossy(manifest.election_id().as_bytes()),
        "manifest_hash_hex": hex_encode(mh.as_bytes()),
        "proof_suite_id": manifest.proof_suite_id(),
        "ballot_kind_id": manifest.ballot_kind().as_str(),
        "proposal_question": manifest.proposal_question(),
        "eligible_voter_count": registry.entries().len(),
        "approval_minimum": manifest.approval_limits().minimum(),
        "approval_maximum": manifest.approval_limits().maximum(),
        "allow_abstention": manifest.approval_limits().allow_abstention(),
        "candidates": cand_json,
    }))
}

/// Generates a fresh voter secret scalar (browser CSPRNG via OsRng/getrandom-js).
/// The returned hex IS the secret; the caller must keep it in memory only.
#[wasm_bindgen]
pub fn generate_secret_key() -> String {
    match TariTriptychSecretKeyV1::generate_os_rng() {
        Ok(secret) => {
            let hex = secret.with_credential_container_secret_bytes_v1(|b| hex_encode(b)).unwrap_or_default();
            ok_json(serde_json::json!({"secret_key_hex": hex}))
        }
        Err(e) => err(e.code().as_str()),
    }
}

/// Derives the governance public key for a secret (public, safe to display).
#[wasm_bindgen]
pub fn public_key_for_secret(secret_hex: &str) -> String {
    match public_key_inner(secret_hex) { Ok(v) => ok_json(v), Err(e) => err(&e) }
}
fn public_key_inner(secret_hex: &str) -> Result<serde_json::Value, String> {
    let bytes = hex_decode(secret_hex)?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| "invalid secret length".to_owned())?;
    let secret = TariTriptychSecretKeyV1::from_canonical_bytes(arr).map_err(|e| e.code().as_str().to_owned())?;
    let pk = secret.governance_public_key().map_err(|e| e.code().as_str().to_owned())?;
    Ok(serde_json::json!({"public_key_hex": hex_encode(pk.as_bytes())}))
}

/// Creates a ballot package + Triptych proof in the browser and locally verifies it.
/// `selections_hex_json`: JSON array of candidate-id hex strings, e.g. `["candidate-a" hex]`.
/// Returns package_cbor_hex, envelope_hash_hex, nullifier_hex (public linking tag after verify).
#[wasm_bindgen]
pub fn create_ballot_package(manifest_hex: &str, registry_hex: &str, candidate_hex: &str, secret_hex: &str, selections_hex_json: &str) -> String {
    match create_inner(manifest_hex, registry_hex, candidate_hex, secret_hex, selections_hex_json) {
        Ok(v) => ok_json(v),
        Err(e) => err(&e),
    }
}
fn create_inner(manifest_hex: &str, registry_hex: &str, candidate_hex: &str, secret_hex: &str, selections_hex_json: &str) -> Result<serde_json::Value, String> {
    let manifest_cbor = hex_decode(manifest_hex)?;
    let registry_cbor = hex_decode(registry_hex)?;
    let candidate_cbor = hex_decode(candidate_hex)?;
    let secret_bytes = hex_decode(secret_hex)?;
    let secret_arr: [u8; 32] = secret_bytes.try_into().map_err(|_| "invalid secret length".to_owned())?;
    let selections_json: Vec<String> = serde_json::from_str(selections_hex_json).map_err(|_| "invalid selections".to_owned())?;
    let manifest = ElectionManifest::from_canonical_cbor(&manifest_cbor).map_err(|e| e.code().as_str().to_owned())?;
    let candidates = CandidateSet::from_canonical_cbor(&candidate_cbor).map_err(|e| e.code().as_str().to_owned())?;
    let registry = RegistrySnapshot::from_canonical_cbor(&registry_cbor).map_err(|e| e.code().as_str().to_owned())?;
    let mut selections = Vec::new();
    for s in &selections_json { let b = hex_decode(s)?; selections.push(CandidateId::new(b).map_err(|e| e.code().as_str().to_owned())?); }
    let payload = ApprovalBallotPayload::new(selections, &candidates, manifest.approval_limits()).map_err(|e| e.code().as_str().to_owned())?;
    let p = Blake3HashProviderV1;
    let verifier = build_tari_triptych_verifier_from_registry_v1(&registry, &p).map_err(|e| e.code().as_str().to_owned())?;
    let statement = reconstruct_approval_proof_statement(&manifest, &payload, &p).map_err(|e| e.code().as_str().to_owned())?;
    let secret = TariTriptychSecretKeyV1::from_canonical_bytes(secret_arr).map_err(|e| e.code().as_str().to_owned())?;
    let proof = prove_tari_triptych_prototype_v1(&statement, &verifier, &secret).map_err(|e| e.code().as_str().to_owned())?;
    drop(secret);
    let mh = manifest.canonical_hash(&p).map_err(|e| e.code().as_str().to_owned())?;
    let package = BallotPackageV1::new(BallotPackageV1Input { protocol_version: PROTOCOL_VERSION_V1, manifest_hash: mh, proof_suite_id: manifest.proof_suite_id().to_owned(), proof, payload }).map_err(|e| e.code().as_str().to_owned())?;
    let package_bytes = package.to_canonical_cbor().map_err(|e| e.code().as_str().to_owned())?;
    // Local verification before anything leaves the browser.
    let env_hash = hex_encode(&hash_domain_separated(&p, HashDomain::BallotPackageV1, &package_bytes));
    let verified = verify_approval_proof(&manifest, package.payload(), package.proof(), &p, &verifier).map_err(|e| e.code().as_str().to_owned())?;
    Ok(serde_json::json!({
        "package_cbor_hex": hex_encode(&package_bytes),
        "envelope_hash_hex": env_hash,
        "nullifier_hex": hex_encode(verified.nullifier().as_bytes()),
        "manifest_hash_hex": hex_encode(mh.as_bytes()),
    }))
}

/// Verifies a package locally (used by tests / receipt display).
#[wasm_bindgen]
pub fn verify_package(manifest_hex: &str, registry_hex: &str, candidate_hex: &str, package_hex: &str) -> String {
    match verify_inner(manifest_hex, registry_hex, candidate_hex, package_hex) { Ok(v) => ok_json(v), Err(e) => err(&e) }
}
fn verify_inner(manifest_hex: &str, registry_hex: &str, candidate_hex: &str, package_hex: &str) -> Result<serde_json::Value, String> {
    let manifest_cbor = hex_decode(manifest_hex)?;
    let registry_cbor = hex_decode(registry_hex)?;
    let candidate_cbor = hex_decode(candidate_hex)?;
    let package_cbor = hex_decode(package_hex)?;
    let manifest = ElectionManifest::from_canonical_cbor(&manifest_cbor).map_err(|e| e.code().as_str().to_owned())?;
    let candidates = CandidateSet::from_canonical_cbor(&candidate_cbor).map_err(|e| e.code().as_str().to_owned())?;
    let registry = RegistrySnapshot::from_canonical_cbor(&registry_cbor).map_err(|e| e.code().as_str().to_owned())?;
    let package = BallotPackageV1::from_canonical_cbor(&package_cbor, &candidates, manifest.approval_limits()).map_err(|e| e.code().as_str().to_owned())?;
    let p = Blake3HashProviderV1;
    let verifier = build_tari_triptych_verifier_from_registry_v1(&registry, &p).map_err(|e| e.code().as_str().to_owned())?;
    let verified = verify_approval_proof(&manifest, package.payload(), package.proof(), &p, &verifier).map_err(|e| e.code().as_str().to_owned())?;
    Ok(serde_json::json!({"nullifier_hex": hex_encode(verified.nullifier().as_bytes())}))
}

/// Package binding hash (must match hosted backend `package_hash_hex`).
#[wasm_bindgen]
pub fn package_hash_hex(manifest_hex: &str, registry_hex: &str, candidate_hex: &str) -> String {
    match package_hash_inner(manifest_hex, registry_hex, candidate_hex) { Ok(v) => ok_json(v), Err(e) => err(&e) }
}
fn package_hash_inner(manifest_hex: &str, registry_hex: &str, candidate_hex: &str) -> Result<serde_json::Value, String> {
    let m = hex_decode(manifest_hex)?; let r = hex_decode(registry_hex)?; let c = hex_decode(candidate_hex)?;
    let p = Blake3HashProviderV1;
    let mut input = Vec::with_capacity(m.len() + r.len() + c.len());
    input.extend_from_slice(&m); input.extend_from_slice(&r); input.extend_from_slice(&c);
    Ok(serde_json::json!({"package_hash_hex": hex_encode(&p.hash(&input))}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hex_round_trip() {
        assert_eq!(hex_encode(&[0xde, 0xad]), "dead");
        assert_eq!(hex_decode("dead").is_ok(), true);
        assert!(hex_decode("xyz").is_err());
    }
}
