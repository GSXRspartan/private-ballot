//! Organizer election-creation tests (Slice 5A6, required cases 1-34).
//!
//! Every test is offline and deterministic. Real Ristretto public keys come
//! from the shared voter fixtures; no voter key material is ever read by the
//! creation facade. The workspace denies `unwrap_used`/`expect_used`, so
//! results are unwrapped through bounded `ok`/`err` helpers.

mod common;

use serde_json::Value;
use tari_cc_private_ballot_ballot::{
    ApprovalLimits, BallotConfidentialityV1, BallotKindV1, CandidateDefinition, CandidateId,
    CandidateSet, ElectionId, ElectionManifestV1, ElectionManifestV1Input,
};
use tari_cc_private_ballot_crypto::TARI_TRIPTYCH_PROOF_SUITE_ID_V1;
use tari_cc_private_ballot_gui_core::{
    GuiBallotPresentationType, GuiCoreError, GuiElectionArtifactsV1, GuiElectionDraftV1,
    GuiElectionSummaryV1, write_election_artifacts_v1,
};
use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, PROTOCOL_VERSION_V1};
use tari_cc_private_ballot_registry::{
    GovernancePublicKey, RegistryEntry, RegistrySnapshot, VoterGovernanceKeyRegistrationV1,
    VoterKeyProvisioningV1,
};

use common::{TestDir, voters};

fn ok<T, E: std::fmt::Display>(result: Result<T, E>, msg: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{msg}: {error}"),
    }
}

fn err<T, E>(result: Result<T, E>, msg: &str) -> E {
    match result {
        Ok(_) => panic!("{msg}"),
        Err(error) => error,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn voter_hexs() -> Vec<String> {
    voters().iter().map(|v| hex(&v.public_bytes)).collect()
}

fn options() -> Vec<(String, String)> {
    vec![
        ("candidate-a".to_owned(), "Candidate A".to_owned()),
        ("candidate-b".to_owned(), "Candidate B".to_owned()),
        ("candidate-c".to_owned(), "Candidate C".to_owned()),
    ]
}

fn complete_draft() -> GuiElectionDraftV1 {
    let mut draft = GuiElectionDraftV1::new();
    ok(
        draft.set_basics("creation-test-election".to_owned(), "creation-rev-1".to_owned()),
        "basics must be valid",
    );
    ok(draft.set_rules(1, 2, true), "rules must be valid");
    ok(draft.set_voters(voter_hexs()), "voters must be valid");
    ok(draft.set_options(options()), "options must be valid");
    ok(
        draft.set_presentation(GuiBallotPresentationType::Candidate),
        "presentation must be valid",
    );
    draft
}

fn freeze_complete() -> (GuiElectionDraftV1, GuiElectionSummaryV1) {
    let mut draft = complete_draft();
    let (result, _session) = ok(draft.freeze(), "freeze must succeed");
    (draft, result.summary)
}

// ------------------------------------------------------------------ Creation

#[test]
fn valid_creation_succeeds_and_freezes() {
    let mut draft = complete_draft();
    let (result, session) = ok(draft.freeze(), "freeze must succeed");
    let summary = result.summary;

    assert_eq!(summary.lifecycle_state, Some("FROZEN"));
    assert_eq!(summary.election_id_text.as_deref(), Some("creation-test-election"));
    assert_eq!(summary.governance_source_revision, "creation-rev-1");
    assert_eq!(summary.voter_count, 3);
    assert_eq!(summary.candidates.len(), 3);
    assert_eq!(summary.approval_min, 1);
    assert_eq!(summary.approval_max, 2);
    assert!(summary.abstention_allowed);
    assert_eq!(summary.ballot_kind, "NON_BINDING_APPROVAL_PILOT");
    assert_eq!(summary.ballot_confidentiality, "PUBLIC");
    assert_eq!(summary.proof_suite_id, TARI_TRIPTYCH_PROOF_SUITE_ID_V1);
    assert!(!summary.manifest_hash_hex.is_empty());
    assert!(!summary.registry_commitment_hex.is_empty());
    assert!(!summary.candidate_set_commitment_hex.is_empty());
    assert_eq!(result.presentation, GuiBallotPresentationType::Candidate);
    assert!(!result.presentation_is_canonical);
    assert!(draft.is_frozen());
    assert_eq!(session.summary().lifecycle_state, Some("FROZEN"));
}

#[test]
fn governance_and_candidate_share_one_approval_ballot_representation() {
    let mut candidate_draft = complete_draft();
    ok(
        candidate_draft.set_presentation(GuiBallotPresentationType::Candidate),
        "candidate presentation",
    );
    let (candidate_result, _) = ok(candidate_draft.freeze(), "candidate freeze");

    let mut governance_draft = complete_draft();
    ok(
        governance_draft.set_presentation(GuiBallotPresentationType::GovernanceProposal),
        "governance presentation",
    );
    let (governance_result, _) = ok(governance_draft.freeze(), "governance freeze");

    assert_eq!(
        candidate_result.summary.manifest_hash_hex,
        governance_result.summary.manifest_hash_hex
    );
    assert_eq!(
        candidate_result.summary.ballot_kind,
        governance_result.summary.ballot_kind
    );
}

#[test]
fn malformed_election_id_is_rejected() {
    let mut draft = GuiElectionDraftV1::new();
    let error = err(
        draft.set_basics(String::new(), "rev-1".to_owned()),
        "empty election id must fail",
    );
    assert_eq!(error.code(), "EMPTY_ELECTION_ID");
}

#[test]
fn unsupported_proof_suite_is_not_exposed() {
    let mut draft = complete_draft();
    let (result, _) = ok(draft.freeze(), "freeze must succeed");
    assert_eq!(result.summary.proof_suite_id, TARI_TRIPTYCH_PROOF_SUITE_ID_V1);
}

#[test]
fn invalid_approval_limits_are_rejected() {
    let mut draft = GuiElectionDraftV1::new();
    let error = err(draft.set_rules(3, 1, false), "min>max must fail");
    assert_eq!(error.code(), "INVALID_SELECTION_LIMITS");
}

// ------------------------------------------------- F3: uncastable approval config

#[test]
fn zero_max_with_abstention_disabled_is_rejected() {
    let mut draft = GuiElectionDraftV1::new();
    let error = err(draft.set_rules(0, 0, false), "min=0/max=0/abstention=false must fail");
    assert_eq!(error.code(), "GUI_UNCASTABLE_APPROVAL_LIMITS");
    assert_eq!(
        error.message(),
        "At least one approval must be allowed when abstention is disabled.",
    );
    // No rules state is installed on rejection.
    let preview = draft.preview();
    assert!(preview.approval_min.is_none());
    assert!(preview.approval_max.is_none());
}

#[test]
fn zero_max_with_abstention_enabled_is_accepted() {
    let mut draft = GuiElectionDraftV1::new();
    ok(draft.set_rules(0, 0, true), "min=0/max=0/abstention=true accepted");
    let preview = draft.preview();
    assert_eq!(preview.approval_min, Some(0));
    assert_eq!(preview.approval_max, Some(0));
    assert!(preview.allow_abstention);
}

#[test]
fn zero_min_one_max_with_abstention_disabled_is_accepted() {
    let mut draft = GuiElectionDraftV1::new();
    ok(
        draft.set_rules(0, 1, false),
        "min=0/max=1/abstention=false accepted",
    );
    let preview = draft.preview();
    assert_eq!(preview.approval_min, Some(0));
    assert_eq!(preview.approval_max, Some(1));
    assert!(!preview.allow_abstention);
}

#[test]
fn existing_min_max_validation_is_unchanged() {
    let mut draft = GuiElectionDraftV1::new();
    let error = err(draft.set_rules(3, 1, true), "min>max must still fail");
    assert_eq!(error.code(), "INVALID_SELECTION_LIMITS");
    // The uncastable rule must not fire for a normal min>max case.
    let error = err(draft.set_rules(2, 1, false), "min>max with abstention off");
    assert_eq!(error.code(), "INVALID_SELECTION_LIMITS");
}

#[test]
fn approval_max_exceeding_option_count_blocks_freeze() {
    let mut draft = complete_draft();
    ok(draft.set_rules(1, 9, true), "rules set");
    let error = err(draft.freeze(), "max>options must block freeze");
    assert_eq!(error.code(), "GUI_DRAFT_INCOMPLETE");
}

#[test]
fn empty_required_fields_block_freeze() {
    let mut draft = GuiElectionDraftV1::new();
    let error = err(draft.freeze(), "empty draft must block freeze");
    assert_eq!(error.code(), "GUI_DRAFT_INCOMPLETE");
}

// ------------------------------------------------------------------ Registry

#[test]
fn valid_public_keys_are_accepted() {
    let mut draft = GuiElectionDraftV1::new();
    ok(draft.set_basics("e".to_owned(), "r".to_owned()), "basics");
    ok(draft.set_voters(voter_hexs()), "voters");
    let preview = draft.preview();
    assert_eq!(preview.voter_count, 3);
    assert!(preview.registry_commitment_hex.is_some());
}

#[test]
fn malformed_public_key_is_rejected() {
    let mut draft = GuiElectionDraftV1::new();
    let bad = vec!["zz".to_owned(); 32];
    let error = err(draft.set_voters(bad), "non-hex must fail");
    assert_eq!(error.code(), "GUI_MALFORMED_HEX");

    let error = err(
        draft.set_voters(vec!["deadbeef".to_owned()]),
        "wrong-length key must fail",
    );
    assert_eq!(error.code(), "GUI_MALFORMED_PUBLIC_KEY");

    let non_point = hex(&[0xff_u8; 32]);
    let error = err(
        draft.set_voters(vec![non_point]),
        "non-point key must fail",
    );
    assert_eq!(error.code(), "GUI_MALFORMED_PUBLIC_KEY");
}

#[test]
fn duplicate_public_key_is_rejected() {
    let mut draft = GuiElectionDraftV1::new();
    let mut keys = voter_hexs();
    keys.push(keys[0].clone());
    let error = err(draft.set_voters(keys), "duplicate must fail");
    assert_eq!(error.code(), "DUPLICATE_GOVERNANCE_KEY");
}

#[test]
fn no_secret_key_api_is_required_to_build_a_registry() {
    let mut draft = GuiElectionDraftV1::new();
    ok(draft.set_voters(voter_hexs()), "public keys alone build the registry");
    assert_eq!(draft.voter_count(), 3);
}

#[test]
fn registry_commitment_equals_direct_backend_construction() {
    let provider = Blake3HashProviderV1;
    let draft = complete_draft();
    let preview = draft.preview();
    let direct = direct_registry_commitment(&provider);
    assert_eq!(preview.registry_commitment_hex, Some(to_hex(direct.as_bytes())));
}

#[test]
fn registry_ordering_is_canonical_regardless_of_input_order() {
    let provider = Blake3HashProviderV1;
    let mut reversed: Vec<String> = voter_hexs();
    reversed.reverse();

    let mut a = GuiElectionDraftV1::new();
    ok(a.set_basics("e".to_owned(), "r".to_owned()), "basics a");
    ok(a.set_voters(voter_hexs()), "voters a");
    let mut b = GuiElectionDraftV1::new();
    ok(b.set_basics("e".to_owned(), "r".to_owned()), "basics b");
    ok(b.set_voters(reversed), "voters b");

    let pa = a.preview();
    let pb = b.preview();
    assert_eq!(pa.registry_commitment_hex, pb.registry_commitment_hex);
    assert_eq!(
        pa.registry_commitment_hex,
        Some(to_hex(direct_registry_commitment(&provider).as_bytes()))
    );
}

// --------------------------------------------- F4: canonical registry import

/// Builds an independent canonical `RegistrySnapshot` from the shared voter
/// fixtures and encodes it through the canonical encoder. The commitment and
/// key bytes derived here come exclusively from the backend registry types,
/// not from the gui-core import helper under test.
fn independent_registry_bytes() -> Vec<u8> {
    ok(direct_registry_snapshot().to_canonical_cbor(), "encode registry")
}

#[test]
fn import_registry_bytes_round_trips_and_matches_independent_commitment() {
    let provider = Blake3HashProviderV1;
    let encoded = independent_registry_bytes();
    let independent = direct_registry_snapshot();
    let independent_commitment =
        ok(independent.canonical_commitment(&provider), "independent commitment");
    let independent_keys: Vec<String> = independent
        .entries()
        .iter()
        .map(|entry| to_hex(entry.governance_key().as_bytes()))
        .collect();

    let mut draft = GuiElectionDraftV1::new();
    ok(draft.set_basics("import-test".to_owned(), "rev-1".to_owned()), "basics");
    ok(draft.import_registry_bytes(&encoded), "import must succeed");
    ok(draft.set_options(options()), "options");
    ok(draft.set_rules(1, 2, true), "rules");
    ok(
        draft.set_presentation(GuiBallotPresentationType::Candidate),
        "presentation",
    );

    let preview = draft.preview();
    // Voter count matches.
    assert_eq!(preview.voter_count, independent.entries().len());
    // Public keys match canonical registry semantics (canonical order).
    let imported_keys: Vec<String> = preview.voters.iter().map(|v| v.public_key_hex.clone()).collect();
    assert_eq!(imported_keys, independent_keys);
    // Imported registry commitment matches the independently constructed one.
    assert_eq!(
        preview.registry_commitment_hex,
        Some(to_hex(independent_commitment.as_bytes())),
    );

    // The draft is complete enough to freeze; the frozen session's registry
    // commitment must also match the independent commitment.
    let (_result, session) = ok(draft.freeze(), "freeze after import");
    assert_eq!(
        to_hex(session.artifacts().registry_commitment().as_bytes()),
        to_hex(independent_commitment.as_bytes()),
    );
}

#[test]
fn import_registry_bytes_rejects_malformed_cbor_without_corrupting_draft() {
    let mut draft = GuiElectionDraftV1::new();
    ok(draft.set_basics("malformed".to_owned(), "rev".to_owned()), "basics");

    // Malformed bytes: not valid canonical CBOR. 0xff has CBOR major type 7,
    // but a registry is encoded as an array (major type 4), so the strict
    // reader rejects with the stable bounded UNEXPECTED_CBOR_TYPE code.
    let malformed: &[u8] = &[0xff, 0xff, 0xff];
    let error = err(
        draft.import_registry_bytes(malformed),
        "malformed cbor must be rejected",
    );
    assert_eq!(error.code(), "UNEXPECTED_CBOR_TYPE");

    // The draft was not partially corrupted and no voter state was installed.
    let preview = draft.preview();
    assert_eq!(preview.voter_count, 0);
    assert!(preview.voters.is_empty());
    assert!(preview.registry_commitment_hex.is_none());
    // Basics set before the failed import remain intact.
    assert_eq!(preview.election_id_text.as_deref(), Some("malformed"));
}

#[test]
fn import_registry_bytes_rejects_non_canonical_registry_format() {
    // The canonical registry format requires keys in strictly ascending byte
    // order. An out-of-order encoded registry is rejected by the existing
    // canonical format check (NON_CANONICAL_CBOR). This exercises a real
    // existing version/type check, not an invented format.
    let non_canonical: Vec<u8> = vec![0x82, 0x41, b'b', 0x41, b'a'];

    let mut draft = GuiElectionDraftV1::new();
    let error = err(
        draft.import_registry_bytes(&non_canonical),
        "non-canonical registry must be rejected",
    );
    assert_eq!(error.code(), "NON_CANONICAL_CBOR");
    // No voter state installed.
    assert_eq!(draft.preview().voter_count, 0);
}

#[test]
fn import_registry_bytes_preserves_prior_voters_on_failure() {
    let mut draft = GuiElectionDraftV1::new();
    ok(draft.set_voters(voter_hexs()), "initial voters");
    assert_eq!(draft.voter_count(), 3);

    let malformed: &[u8] = &[0xff, 0xff];
    let error = err(
        draft.import_registry_bytes(malformed),
        "malformed import must fail",
    );
    assert_eq!(error.code(), "UNEXPECTED_CBOR_TYPE");
    // Prior voter state is preserved (no silent corruption/removal).
    assert_eq!(draft.voter_count(), 3);
}

// -------------------------------------------------------------------- Options

#[test]
fn valid_options_are_accepted() {
    let mut draft = GuiElectionDraftV1::new();
    ok(draft.set_options(options()), "options");
    let preview = draft.preview();
    assert_eq!(preview.options.len(), 3);
    assert!(preview.candidate_set_commitment_hex.is_some());
}

#[test]
fn duplicate_option_id_is_rejected() {
    let mut draft = GuiElectionDraftV1::new();
    let dup = vec![
        ("a".to_owned(), "A".to_owned()),
        ("a".to_owned(), "B".to_owned()),
    ];
    let error = err(draft.set_options(dup), "duplicate option id must fail");
    assert_eq!(error.code(), "DUPLICATE_CANDIDATE_ID");
}

#[test]
fn invalid_option_id_is_rejected() {
    let mut draft = GuiElectionDraftV1::new();
    let error = err(
        draft.set_options(vec![(String::new(), "Empty ID".to_owned())]),
        "empty option id must fail",
    );
    assert_eq!(error.code(), "EMPTY_CANDIDATE_ID");

    let error = err(
        draft.set_options(vec![("a".to_owned(), "   ".to_owned())]),
        "empty label must fail",
    );
    assert_eq!(error.code(), "EMPTY_CANDIDATE_DISPLAY_NAME");
}

#[test]
fn option_set_commitment_is_deterministic() {
    let mut a = GuiElectionDraftV1::new();
    ok(a.set_options(options()), "options a");
    let mut b = GuiElectionDraftV1::new();
    ok(
        b.set_options(vec![
            ("candidate-c".to_owned(), "Candidate C".to_owned()),
            ("candidate-a".to_owned(), "Candidate A".to_owned()),
            ("candidate-b".to_owned(), "Candidate B".to_owned()),
        ]),
        "options b",
    );
    assert_eq!(
        a.preview().candidate_set_commitment_hex,
        b.preview().candidate_set_commitment_hex
    );
}

#[test]
fn option_ordering_matches_canonical_backend_behavior() {
    let provider = Blake3HashProviderV1;
    let mut draft = GuiElectionDraftV1::new();
    ok(draft.set_options(options()), "options");
    let preview = draft.preview();
    let direct = direct_candidate_commitment(&provider);
    assert_eq!(preview.candidate_set_commitment_hex, Some(to_hex(direct.as_bytes())));
}

// --------------------------------------------------- F1: duplicate display labels

#[test]
fn duplicate_option_id_is_still_rejected() {
    let mut draft = GuiElectionDraftV1::new();
    let dup = vec![
        ("a".to_owned(), "A".to_owned()),
        ("a".to_owned(), "B".to_owned()),
    ];
    let error = err(draft.set_options(dup), "duplicate option id must still fail");
    assert_eq!(error.code(), "DUPLICATE_CANDIDATE_ID");
}

#[test]
fn distinct_ids_with_duplicate_display_label_are_rejected() {
    let mut draft = GuiElectionDraftV1::new();
    let dup_label = vec![
        ("approve-a".to_owned(), "Yes".to_owned()),
        ("approve-b".to_owned(), "Yes".to_owned()),
    ];
    let error = err(
        draft.set_options(dup_label),
        "duplicate display label must fail",
    );
    assert_eq!(error.code(), "GUI_DUPLICATE_OPTION_DISPLAY_LABEL");
    assert_eq!(error.message(), "Ballot option display labels must be unique.");
    // No option state is installed on rejection.
    assert!(draft.preview().options.is_empty());
}

#[test]
fn distinct_display_labels_are_accepted() {
    let mut draft = GuiElectionDraftV1::new();
    ok(
        draft.set_options(vec![
            ("approve-a".to_owned(), "Yes".to_owned()),
            ("approve-b".to_owned(), "No".to_owned()),
        ]),
        "distinct labels must be accepted",
    );
    assert_eq!(draft.preview().options.len(), 2);
}

#[test]
fn duplicate_display_label_rejection_happens_before_freeze_output() {
    let mut draft = complete_draft();
    // Replace the option set with one that has a duplicate display label.
    let error = err(
        draft.set_options(vec![
            ("approve-a".to_owned(), "Yes".to_owned()),
            ("approve-b".to_owned(), "Yes".to_owned()),
        ]),
        "duplicate display label must fail before freeze",
    );
    assert_eq!(error.code(), "GUI_DUPLICATE_OPTION_DISPLAY_LABEL");
    // Because set_options rejected the replacement, the draft's prior option
    // set is preserved. Clear it so we can prove no freeze output is produced
    // for a draft that never reached a valid complete state with the duplicate.
    let mut fresh = GuiElectionDraftV1::new();
    ok(fresh.set_basics("e".to_owned(), "r".to_owned()), "basics");
    ok(fresh.set_voters(voter_hexs()), "voters");
    let dup_error = err(
        fresh.set_options(vec![
            ("a".to_owned(), "Same".to_owned()),
            ("b".to_owned(), "Same".to_owned()),
        ]),
        "duplicate label",
    );
    assert_eq!(dup_error.code(), "GUI_DUPLICATE_OPTION_DISPLAY_LABEL");
    // No options were installed, so the draft is incomplete and freeze
    // produces no canonical output.
    let preview = fresh.preview();
    assert!(preview.options.is_empty());
    assert!(!preview.complete);
    assert!(preview.manifest_hash_hex.is_none());
    let freeze_error = err(fresh.freeze(), "freeze must fail without options");
    assert_eq!(freeze_error.code(), "GUI_DRAFT_INCOMPLETE");
}

#[test]
fn duplicate_display_label_is_detected_after_trim_normalization() {
    let mut draft = GuiElectionDraftV1::new();
    let dup_label = vec![
        ("a".to_owned(), "Yes".to_owned()),
        ("b".to_owned(), "   Yes   ".to_owned()),
    ];
    let error = err(
        draft.set_options(dup_label),
        "trim-equivalent labels must collide",
    );
    assert_eq!(error.code(), "GUI_DUPLICATE_OPTION_DISPLAY_LABEL");
}

// --------------------------------------------------------------------- Freeze

#[test]
fn freeze_produces_frozen_lifecycle() {
    let (_draft, summary) = freeze_complete();
    assert_eq!(summary.lifecycle_state, Some("FROZEN"));
}

#[test]
fn post_freeze_registry_mutation_is_rejected() {
    let (mut draft, _) = freeze_complete();
    let error = err(draft.set_voters(voter_hexs()), "post-freeze voters must fail");
    assert_eq!(error.code(), "GUI_DRAFT_ALREADY_FROZEN");
}

#[test]
fn post_freeze_option_mutation_is_rejected() {
    let (mut draft, _) = freeze_complete();
    let error = err(draft.set_options(options()), "post-freeze options must fail");
    assert_eq!(error.code(), "GUI_DRAFT_ALREADY_FROZEN");
}

#[test]
fn post_freeze_rules_mutation_is_rejected() {
    let (mut draft, _) = freeze_complete();
    let error = err(draft.set_rules(1, 1, false), "post-freeze rules must fail");
    assert_eq!(error.code(), "GUI_DRAFT_ALREADY_FROZEN");
}

#[test]
fn manifest_hash_is_stable_after_freeze() {
    let (draft, summary) = freeze_complete();
    let result = match draft.creation_result() {
        Some(result) => result,
        None => panic!("frozen result must be present"),
    };
    assert_eq!(result.summary.manifest_hash_hex, summary.manifest_hash_hex);
    assert_eq!(
        draft.creation_result().unwrap_or(result).summary.manifest_hash_hex,
        summary.manifest_hash_hex
    );
}

// -------------------------------------------------------------------- Export

#[test]
fn export_writes_all_canonical_files() {
    let mut draft = complete_draft();
    let (_result, session) = ok(draft.freeze(), "freeze");
    let dir = TestDir::new("creation-export");
    let target = dir.join("election");

    let exported = ok(write_election_artifacts_v1(session.artifacts(), &target), "export");
    let names: Vec<&str> = exported.files.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(
        names,
        vec!["election-manifest.cbor", "voter-registry.cbor", "candidate-set.cbor"]
    );
    for file in &exported.files {
        assert!(target.join(&file.path).is_file());
        assert!(file.bytes > 0);
        assert_eq!(file.digest_hex.len(), 64);
    }
    assert_eq!(exported.manifest_hash_hex.len(), 64);
}

#[test]
fn export_overwrite_is_rejected() {
    let mut draft = complete_draft();
    let (_result, session) = ok(draft.freeze(), "freeze");
    let dir = TestDir::new("creation-overwrite");
    let target = dir.join("out");
    ok(write_election_artifacts_v1(session.artifacts(), &target), "first export");
    let error = err(
        write_election_artifacts_v1(session.artifacts(), &target),
        "second export must fail",
    );
    assert_eq!(error.code(), "GUI_EXPORT_TARGET_NOT_EMPTY");
}

#[test]
fn export_file_target_is_rejected() {
    let mut draft = complete_draft();
    let (_result, session) = ok(draft.freeze(), "freeze");
    let dir = TestDir::new("creation-file-target");
    let target = dir.join("not-a-dir");
    std::fs::write(&target, b"x").unwrap_or_else(|e| panic!("write: {e}"));
    let error = err(
        write_election_artifacts_v1(session.artifacts(), &target),
        "file target must fail",
    );
    assert_eq!(error.code(), "GUI_EXPORT_TARGET_INVALID");
}

#[test]
fn exported_bytes_equal_canonical_encoder_output() {
    let provider = Blake3HashProviderV1;
    let mut draft = complete_draft();
    let (_result, session) = ok(draft.freeze(), "freeze");
    let dir = TestDir::new("creation-bytes");
    let target = dir.join("out");
    let exported = ok(write_election_artifacts_v1(session.artifacts(), &target), "export");

    let manifest_bytes = std::fs::read(target.join("election-manifest.cbor"))
        .unwrap_or_else(|e| panic!("read manifest: {e}"));
    let registry_bytes = std::fs::read(target.join("voter-registry.cbor"))
        .unwrap_or_else(|e| panic!("read registry: {e}"));
    let candidate_bytes = std::fs::read(target.join("candidate-set.cbor"))
        .unwrap_or_else(|e| panic!("read candidates: {e}"));

    assert_eq!(
        manifest_bytes,
        ok(session.artifacts().manifest().to_canonical_cbor(), "manifest encode")
    );
    assert_eq!(
        registry_bytes,
        ok(session.artifacts().registry().to_canonical_cbor(), "registry encode")
    );
    assert_eq!(
        candidate_bytes,
        ok(session.artifacts().candidates().to_canonical_cbor(), "candidates encode")
    );

    use tari_cc_private_ballot_archive::ArchiveFileDigestV1;
    for file in &exported.files {
        let bytes = std::fs::read(target.join(&file.path))
            .unwrap_or_else(|e| panic!("read {}: {e}", file.path));
        let digest = ArchiveFileDigestV1::for_bytes(&provider, &bytes);
        assert_eq!(file.digest_hex, to_hex(digest.as_bytes()));
    }
}

#[test]
fn export_then_5a4_load_round_trip_is_exact() {
    let mut draft = complete_draft();
    let (result, session) = ok(draft.freeze(), "freeze");
    let dir = TestDir::new("creation-roundtrip");
    let target = dir.join("out");
    ok(write_election_artifacts_v1(session.artifacts(), &target), "export");

    let reloaded = ok(
        GuiElectionArtifactsV1::from_paths(
            &target.join("election-manifest.cbor"),
            &target.join("voter-registry.cbor"),
            &target.join("candidate-set.cbor"),
        ),
        "reload",
    );

    assert_eq!(reloaded.manifest_hash(), session.artifacts().manifest_hash());
    assert_eq!(
        reloaded.registry_commitment(),
        session.artifacts().registry_commitment()
    );
    assert_eq!(
        reloaded.candidate_set_commitment(),
        session.artifacts().candidate_set_commitment()
    );

    let expected = result.summary;
    let actual = reloaded.summary();
    assert_eq!(actual.election_id_hex, expected.election_id_hex);
    assert_eq!(actual.election_id_text, expected.election_id_text);
    assert_eq!(actual.manifest_hash_hex, expected.manifest_hash_hex);
    assert_eq!(actual.registry_commitment_hex, expected.registry_commitment_hex);
    assert_eq!(
        actual.candidate_set_commitment_hex,
        expected.candidate_set_commitment_hex
    );
    assert_eq!(actual.voter_count, expected.voter_count);
    assert_eq!(actual.proof_suite_id, expected.proof_suite_id);
    assert_eq!(actual.approval_min, expected.approval_min);
    assert_eq!(actual.approval_max, expected.approval_max);
    assert_eq!(actual.abstention_allowed, expected.abstention_allowed);
    assert_eq!(actual.governance_source_revision, expected.governance_source_revision);
    assert_eq!(actual.ballot_kind, expected.ballot_kind);
    assert_eq!(actual.candidates, expected.candidates);
}

#[test]
fn same_draft_produces_identical_canonical_bytes_and_hash() {
    let mut first = complete_draft();
    let (first_result, first_session) = ok(first.freeze(), "first freeze");
    let mut second = complete_draft();
    let (second_result, second_session) = ok(second.freeze(), "second freeze");

    assert_eq!(
        first_result.summary.manifest_hash_hex,
        second_result.summary.manifest_hash_hex
    );
    assert_eq!(
        ok(first_session.artifacts().manifest().to_canonical_cbor(), "first manifest"),
        ok(second_session.artifacts().manifest().to_canonical_cbor(), "second manifest")
    );
    assert_eq!(
        ok(first_session.artifacts().registry().to_canonical_cbor(), "first registry"),
        ok(second_session.artifacts().registry().to_canonical_cbor(), "second registry")
    );
    assert_eq!(
        ok(first_session.artifacts().candidates().to_canonical_cbor(), "first candidates"),
        ok(second_session.artifacts().candidates().to_canonical_cbor(), "second candidates")
    );
}

#[test]
fn presentation_metadata_does_not_alter_canonical_bytes() {
    let mut candidate = complete_draft();
    ok(candidate.set_presentation(GuiBallotPresentationType::Candidate), "candidate");
    let (candidate_result, candidate_session) = ok(candidate.freeze(), "candidate freeze");

    let mut measure = complete_draft();
    ok(measure.set_presentation(GuiBallotPresentationType::BallotMeasure), "measure");
    let (measure_result, measure_session) = ok(measure.freeze(), "measure freeze");

    assert_ne!(candidate_result.presentation, measure_result.presentation);
    assert_eq!(
        candidate_result.summary.manifest_hash_hex,
        measure_result.summary.manifest_hash_hex
    );
    assert_eq!(
        ok(candidate_session.artifacts().manifest().to_canonical_cbor(), "candidate manifest"),
        ok(measure_session.artifacts().manifest().to_canonical_cbor(), "measure manifest")
    );
}

// -------------------------------------------------------------------- Secrets

#[test]
fn serialized_creation_result_contains_no_secret_material() {
    let mut draft = complete_draft();
    let (result, _session) = ok(draft.freeze(), "freeze");
    let preview = draft.preview();
    let json = ok(serde_json::to_string(&result), "serialize result");
    let preview_json = ok(serde_json::to_string(&preview), "serialize preview");

    let secret_hex = hex(&voters()[0].secret_bytes);
    for text in [&json, &preview_json] {
        let lower = text.to_lowercase();
        assert!(
            !lower.contains(&secret_hex),
            "creation DTO must not contain voter key material"
        );
        assert!(!lower.contains("seed"));
        assert!(!lower.contains("mnemonic"));
        assert!(!lower.contains("password"));
    }

    for value in [
        ok(serde_json::from_str::<Value>(&json), "parse result json"),
        ok(serde_json::from_str::<Value>(&preview_json), "parse preview json"),
    ] {
        let mut keys: Vec<String> = Vec::new();
        if let Some(obj) = value.as_object() {
            keys.extend(obj.keys().cloned());
        }
        for forbidden in ["secret", "seed", "mnemonic", "auth", "token", "password", "wallet"] {
            for k in &keys {
                assert!(!k.to_lowercase().contains(forbidden), "field {k} forbidden");
            }
        }
    }
}

#[test]
fn error_strings_contain_no_secret_material() {
    let mut draft = GuiElectionDraftV1::new();
    let secret_hex = hex(&voters()[0].secret_bytes);
    let errors: Vec<GuiCoreError> = vec![
        err(draft.set_basics(String::new(), "r".to_owned()), "empty id"),
        err(draft.set_rules(3, 1, false), "min>max"),
        err(draft.set_voters(vec!["zz".to_owned(); 32]), "bad hex"),
        err(draft.freeze(), "incomplete freeze"),
    ];
    for error in errors {
        let rendered = error.to_string();
        assert!(!rendered.to_lowercase().contains(&secret_hex));
        assert!(rendered.is_ascii());
    }
}

#[test]
fn no_wallet_or_seed_field_exists_in_draft_dto() {
    let draft = complete_draft();
    let preview = draft.preview();
    let json = ok(serde_json::to_string(&preview), "serialize");
    for forbidden in ["wallet", "seed", "auth", "token", "password", "mnemonic"] {
        assert!(
            !json.to_lowercase().contains(forbidden),
            "draft DTO must not expose {forbidden}"
        );
    }
}

// ------------------------------------------------------------------ Canonical

#[test]
fn creation_does_not_change_published_canonical_vectors() {
    let provider = Blake3HashProviderV1;
    let mut draft = complete_draft();
    let (_result, session) = ok(draft.freeze(), "freeze");

    let direct_registry = direct_registry_snapshot();
    let direct_candidates = direct_candidate_set();
    let direct_manifest = direct_manifest(
        &provider,
        ok(direct_registry.canonical_commitment(&provider), "registry commit"),
        ok(direct_candidates.canonical_commitment(&provider), "candidates commit"),
    );

    assert_eq!(
        ok(session.artifacts().registry().to_canonical_cbor(), "session registry"),
        ok(direct_registry.to_canonical_cbor(), "direct registry")
    );
    assert_eq!(
        ok(session.artifacts().candidates().to_canonical_cbor(), "session candidates"),
        ok(direct_candidates.to_canonical_cbor(), "direct candidates")
    );
    assert_eq!(
        ok(session.artifacts().manifest().to_canonical_cbor(), "session manifest"),
        ok(direct_manifest.to_canonical_cbor(), "direct manifest")
    );
}

// ----------------------------------------------------------------- helpers

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn direct_registry_snapshot() -> RegistrySnapshot {
    let entries = voters()
        .iter()
        .map(|v| {
            let key = ok(GovernancePublicKey::new(v.public_bytes.to_vec()), "gov key");
            let registration =
                VoterGovernanceKeyRegistrationV1::new(key, VoterKeyProvisioningV1::ImportedByVoter);
            RegistryEntry::from_voter_registration(registration)
        })
        .collect();
    ok(RegistrySnapshot::new(entries), "registry snapshot")
}

fn direct_registry_commitment(
    provider: &Blake3HashProviderV1,
) -> tari_cc_private_ballot_protocol::RegistryCommitment {
    ok(direct_registry_snapshot().canonical_commitment(provider), "registry commitment")
}

fn direct_candidate_set() -> CandidateSet {
    let defs = options()
        .into_iter()
        .map(|(id, name)| {
            let cid = ok(CandidateId::new(id.into_bytes()), "candidate id");
            ok(CandidateDefinition::new(cid, name), "candidate def")
        })
        .collect();
    ok(CandidateSet::new(defs), "candidate set")
}

fn direct_candidate_commitment(
    provider: &Blake3HashProviderV1,
) -> tari_cc_private_ballot_protocol::CandidateSetCommitment {
    ok(direct_candidate_set().canonical_commitment(provider), "candidate commitment")
}

fn direct_manifest(
    _provider: &Blake3HashProviderV1,
    registry_commitment: tari_cc_private_ballot_protocol::RegistryCommitment,
    candidate_set_commitment: tari_cc_private_ballot_protocol::CandidateSetCommitment,
) -> ElectionManifestV1 {
    let limits = ok(ApprovalLimits::new(1, 2, true), "limits");
    ok(
        ElectionManifestV1::new(ElectionManifestV1Input {
            protocol_version: PROTOCOL_VERSION_V1,
            election_id: ok(ElectionId::new(b"creation-test-election".to_vec()), "election id"),
            ballot_kind: BallotKindV1::NonBindingApprovalPilot,
            ballot_confidentiality: BallotConfidentialityV1::Public,
            registry_commitment,
            candidate_set_commitment,
            proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
            approval_limits: limits,
            governance_source_revision: "creation-rev-1".to_owned(),
        }),
        "manifest",
    )
}
