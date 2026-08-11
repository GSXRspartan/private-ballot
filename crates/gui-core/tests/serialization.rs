//! Serialization boundary tests (required cases 7 and the no-secret
//! invariant for the serialized election summary).
//!
//! These tests exercise the exact path the Tauri `load_election` and
//! `election_summary` commands use: `GuiElectionArtifactsV1::from_paths` (or
//! `from_bytes`) → `GuiElectionSessionV1::new` → `summary()`, then serialize
//! the returned `GuiElectionSummaryV1` through `serde_json` exactly as the
//! Tauri command boundary does. They assert that the structured summary
//! carries every field the frontend needs and that no secret-bearing field
//! name appears in the serialized JSON.

mod common;

use serde_json::Value;
use tari_cc_private_ballot_gui_core::{
    GuiBallotIntakeResultV1, GuiElectionArtifactsV1, GuiElectionSessionV1, GuiIntakeCategory,
    GuiPreparedBallotSummaryV1,
};

use common::{TestDir, candidate_bytes, manifest_bytes, registry_bytes};

fn serialize_loaded_summary() -> Value {
    let artifacts = match GuiElectionArtifactsV1::from_bytes(
        &manifest_bytes(),
        &registry_bytes(),
        &candidate_bytes(),
    ) {
        Ok(artifacts) => artifacts,
        Err(error) => panic!("fixture artifacts must load: {error}"),
    };
    let session = match GuiElectionSessionV1::new(artifacts) {
        Ok(session) => session,
        Err(error) => panic!("fixture session must construct: {error}"),
    };
    let summary = session.summary();
    let json = match serde_json::to_string(&summary) {
        Ok(json) => json,
        Err(error) => panic!("summary must serialize: {error}"),
    };
    match serde_json::from_str(&json) {
        Ok(value) => value,
        Err(error) => panic!("serialized summary must be valid JSON: {error}"),
    }
}

/// Required case 1 (facade level): valid paths return a structured election
/// summary with every field the frontend displays.
#[test]
fn valid_load_returns_structured_summary() {
    let dir = TestDir::new("serialization-valid");
    let manifest_path = dir.join("manifest.cbor");
    let registry_path = dir.join("registry.cbor");
    let candidate_path = dir.join("candidates.cbor");
    assert!(std::fs::write(&manifest_path, manifest_bytes()).is_ok());
    assert!(std::fs::write(&registry_path, registry_bytes()).is_ok());
    assert!(std::fs::write(&candidate_path, candidate_bytes()).is_ok());

    let artifacts =
        match GuiElectionArtifactsV1::from_paths(&manifest_path, &registry_path, &candidate_path) {
            Ok(artifacts) => artifacts,
            Err(error) => panic!("valid artifact paths must load: {error}"),
        };
    let session = match GuiElectionSessionV1::new(artifacts) {
        Ok(session) => session,
        Err(error) => panic!("session must construct: {error}"),
    };
    let summary = session.summary();

    assert_eq!(summary.voter_count, 3);
    assert_eq!(summary.candidates.len(), 3);
    assert_eq!(summary.lifecycle_state, Some("FROZEN"));
    assert!(!summary.manifest_hash_hex.is_empty());
    assert!(!summary.registry_commitment_hex.is_empty());
    assert!(!summary.candidate_set_commitment_hex.is_empty());
    assert!(!summary.proof_suite_id.is_empty());
    assert!(!summary.governance_source_revision.is_empty());
}

/// Required case 7: no secret-bearing field appears anywhere in the serialized
/// election summary. The summary is what crosses the Tauri boundary into
/// TypeScript; it must never carry a secret scalar, walletd auth, seed,
/// mnemonic, or signing material.
#[test]
fn serialized_summary_carries_no_secret_field() {
    let value = serialize_loaded_summary();
    let object = match value.as_object() {
        Some(object) => object,
        None => panic!("summary serializes to a JSON object"),
    };

    // Every expected public field is present.
    for field in [
        "election_id_hex",
        "election_id_text",
        "lifecycle_state",
        "manifest_hash_hex",
        "registry_commitment_hex",
        "candidate_set_commitment_hex",
        "voter_count",
        "proof_suite_id",
        "ballot_kind",
        "ballot_confidentiality",
        "approval_min",
        "approval_max",
        "abstention_allowed",
        "governance_source_revision",
        "candidates",
    ] {
        assert!(object.contains_key(field), "summary must expose {field}");
    }

    // No field name may hint at secret-bearing material.
    let mut all_keys: Vec<String> = object.keys().cloned().collect();
    if let Some(candidates) = object.get("candidates").and_then(Value::as_array) {
        for candidate in candidates {
            if let Some(candidate_obj) = candidate.as_object() {
                all_keys.extend(candidate_obj.keys().cloned());
            }
        }
    }
    for forbidden in [
        "secret",
        "private_key",
        "secret_key",
        "secret_scalar",
        "seed",
        "mnemonic",
        "auth",
        "token",
        "password",
        "wallet",
    ] {
        for key in &all_keys {
            assert!(
                !key.to_lowercase().contains(forbidden),
                "serialized summary must not expose a secret-bearing field named '{key}' (matched '{forbidden}')"
            );
        }
    }

    // The serialized text itself must not contain the fixture secret bytes in
    // hex (defensive: even if no field is named for it, a value must not leak).
    let json = match serde_json::to_string(&value) {
        Ok(json) => json,
        Err(error) => panic!("re-serialize for scan: {error}"),
    };
    let secret_hex = common::voters()[0]
        .secret_bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert!(
        !json.to_lowercase().contains(&secret_hex),
        "serialized summary must not contain the fixture secret scalar in hex"
    );
}

/// The public Tauri-facing ballot DTOs must not serialize replay/linkability
/// internals even though gui-core retains them for verification and archive
/// replay. This protects the Rust-to-JavaScript boundary, not merely rendering.
#[test]
fn public_ballot_dtos_exclude_replay_and_secret_material() {
    let intake = GuiBallotIntakeResultV1 {
        accepted: false,
        code: "DUPLICATE_BALLOT",
        category: GuiIntakeCategory::Duplicate,
        package_digest_hex: "a".repeat(64),
    };
    let prepared = GuiPreparedBallotSummaryV1 {
        election_id_hex: "b".repeat(64),
        manifest_hash_hex: "c".repeat(64),
        selected_option_ids_hex: vec!["d".repeat(64)],
        selected_display_labels: vec!["Option".to_owned()],
        abstaining: false,
        proof_suite_id: "TARI_TRIPTYCH_PROTOTYPE_V1".to_owned(),
        canonical_package_bytes: 123,
        package_digest_hex: "e".repeat(64),
        locally_verified: true,
        ready_to_export: true,
    };
    let json = serde_json::to_string(&(intake, prepared)).unwrap_or_default();
    for forbidden in [
        "nullifier",
        "linkability",
        "member_index",
        "private_scalar",
        "secret_credential",
        "credential_bytes",
        "duplicate_of_sequence",
        "intake_sequence",
    ] {
        assert!(
            !json.to_lowercase().contains(forbidden),
            "public DTO JSON must not contain {forbidden}"
        );
    }
}
