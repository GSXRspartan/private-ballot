//! Voter confirmation boundary tests (Slice 5A8, required cases U1-U12).
//!
//! The voter confirmation view model is built from the validated artifact
//! triple and an optional governance document digest. It carries no voter
//! secret, no credential, and no proof material. These tests assert the
//! cryptographically bound fields, the explicit non-canonical presentation
//! marking, the absence of any unbound proposal question, and the honest
//! governance document status labeling.

mod common;

use serde_json::Value;
use tari_cc_private_ballot_gui_core::{
    GuiGovernanceMatchStatusV1, VOTER_NEXT_STAGE_PLACEHOLDER, build_voter_election_confirmation,
    content_digest_pin_for_bytes,
};
use tari_cc_private_ballot_gui_core::governance::GuiGovernanceDocumentDigestV1;

use common::artifacts;

fn ok<T, E: std::fmt::Display>(result: Result<T, E>, msg: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{msg}: {error}"),
    }
}

#[test]
fn u1_confirmation_includes_election_id() {
    let confirmation = build_voter_election_confirmation(&artifacts(), None);
    assert!(!confirmation.bound.election_id_hex.is_empty());
    assert!(confirmation.bound.election_id_text.is_some());
}

#[test]
fn u2_confirmation_includes_manifest_hash() {
    let confirmation = build_voter_election_confirmation(&artifacts(), None);
    assert!(!confirmation.bound.manifest_hash_hex.is_empty());
    assert_eq!(confirmation.bound.manifest_hash_hex.len(), 64);
}

#[test]
fn u3_confirmation_includes_governance_source_revision() {
    let confirmation = build_voter_election_confirmation(&artifacts(), None);
    assert!(!confirmation.bound.governance_source_revision.is_empty());
}

#[test]
fn u4_confirmation_includes_canonical_option_display_labels() {
    let confirmation = build_voter_election_confirmation(&artifacts(), None);
    assert_eq!(confirmation.bound.option_display_labels.len(), 3);
    assert!(confirmation.bound.option_display_labels.contains(&"Candidate A".to_owned()));
}

#[test]
fn u5_confirmation_includes_approval_rules() {
    let confirmation = build_voter_election_confirmation(&artifacts(), None);
    assert_eq!(confirmation.bound.approval_min, 1);
    assert_eq!(confirmation.bound.approval_max, 2);
    assert!(!confirmation.bound.abstention_allowed);
}

#[test]
fn u6_confirmation_includes_proof_suite() {
    let confirmation = build_voter_election_confirmation(&artifacts(), None);
    assert!(!confirmation.bound.proof_suite_id.is_empty());
}

#[test]
fn u7_advanced_commitments_present() {
    let confirmation = build_voter_election_confirmation(&artifacts(), None);
    assert!(!confirmation.advanced.option_machine_ids_hex.is_empty());
    assert_eq!(confirmation.advanced.registry_commitment_hex.len(), 64);
    assert_eq!(confirmation.advanced.candidate_set_commitment_hex.len(), 64);
    assert!(confirmation.advanced.voter_count > 0);
}

#[test]
fn u8_presentation_type_explicitly_marked_non_canonical() {
    let confirmation = build_voter_election_confirmation(&artifacts(), None);
    assert!(!confirmation.presentation_is_canonical);
    assert!(
        confirmation.presentation_notice.contains("not part of ElectionManifestV1"),
        "presentation notice must mark it non-canonical"
    );
}

#[test]
fn u9_no_unbound_proposal_question() {
    let confirmation = build_voter_election_confirmation(&artifacts(), None);
    assert!(
        confirmation.no_proposal_question_notice.contains("no title, description, or proposal-question"),
        "must state no proposal question exists"
    );
    // No field is named like a proposal question.
    let json = ok(serde_json::to_string(&confirmation), "serialize");
    let lower = json.to_lowercase();
    assert!(!lower.contains("\"question\""));
    assert!(!lower.contains("\"title\""));
    assert!(!lower.contains("\"description\""));
}

#[test]
fn u10_matching_content_digest_status_says_matched() {
    // Build artifacts with a content-digest governance pin and a matching doc.
    let doc_bytes = b"governance-doc-for-voter";
    let pin = content_digest_pin_for_bytes(doc_bytes);
    let artifacts = common::artifacts_with_revision(&pin);
    let digest_hex = pin.strip_prefix("blake3:").unwrap_or("").to_owned();
    let doc = GuiGovernanceDocumentDigestV1 {
        display_filename: "proposal.md".to_owned(),
        bytes: doc_bytes.len() as u64,
        digest_algorithm_id: tari_cc_private_ballot_protocol::BLAKE3_256_HASH_ALGORITHM_ID_V1,
        digest_hex,
    };
    let confirmation = build_voter_election_confirmation(&artifacts, Some(&doc));
    assert_eq!(
        confirmation.governance_document_status.status,
        GuiGovernanceMatchStatusV1::Matched
    );
    assert!(confirmation.governance_document_status.status.is_cryptographically_matched());
}

#[test]
fn u11_git_sha_status_does_not_say_cryptographically_verified() {
    let artifacts = common::artifacts_with_revision("git:0123456789abcdef0123456789abcdef01234567");
    let doc = GuiGovernanceDocumentDigestV1 {
        display_filename: "proposal.md".to_owned(),
        bytes: 4,
        digest_algorithm_id: tari_cc_private_ballot_protocol::BLAKE3_256_HASH_ALGORITHM_ID_V1,
        digest_hex: "ab".repeat(32),
    };
    let confirmation = build_voter_election_confirmation(&artifacts, Some(&doc));
    assert_eq!(
        confirmation.governance_document_status.status,
        GuiGovernanceMatchStatusV1::OperatorAttested
    );
    let label = confirmation.governance_document_status.status_label;
    assert!(
        label.contains("not independently verified"),
        "operator-attested label must state it is not independently verified: {label}"
    );
    assert!(
        !label.contains("cryptographically verified"),
        "operator-attested label must not claim cryptographic verification: {label}"
    );
}

#[test]
fn u12_no_secret_bearing_field() {
    let confirmation = build_voter_election_confirmation(&artifacts(), None);
    let json = ok(serde_json::to_string(&confirmation), "serialize");
    let value = ok(serde_json::from_str::<Value>(&json), "parse");
    let mut keys: Vec<String> = Vec::new();
    if let Some(obj) = value.as_object() {
        keys.extend(obj.keys().cloned());
        for (_, v) in obj {
            if let Some(inner) = v.as_object() {
                keys.extend(inner.keys().cloned());
            }
        }
    }
    for forbidden in ["secret", "seed", "mnemonic", "auth", "token", "password", "wallet", "scalar", "private_key"] {
        for k in &keys {
            assert!(!k.to_lowercase().contains(forbidden), "field {k} forbidden");
        }
    }
}

#[test]
fn next_stage_placeholder_is_deferred() {
    assert!(
        VOTER_NEXT_STAGE_PLACEHOLDER.contains("next reviewed slice"),
        "next stage must remain a deferred placeholder"
    );
    let confirmation = build_voter_election_confirmation(&artifacts(), None);
    assert_eq!(confirmation.next_stage_placeholder, VOTER_NEXT_STAGE_PLACEHOLDER);
}
