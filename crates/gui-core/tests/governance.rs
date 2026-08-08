//! Governance source pinning, document digesting, reference matching, archive
//! inclusion, and canonical regression tests (Slice 5A8, required cases T1-T26).
//!
//! Every test is offline and deterministic. Real governance document files are
//! written into unique temporary directories. No network, walletd, indexer, or
//! signing is performed. No voter secret material is handled.

#![allow(dead_code)]

mod common;

use tari_cc_private_ballot_archive::{
    ARCHIVE_MANIFEST_CANONICAL_PATH, ArchiveFileCatalogV1, ArchiveFileEntryV1, ArchiveManifestV1,
    ArchivePathV1,
};
use tari_cc_private_ballot_gui_core::archive_writer::{
    write_archive_directory_v1_with_governance_document,
};
use tari_cc_private_ballot_gui_core::{
    GuiElectionDraftV1, GuiGovernanceArchivePinFactV1, GuiGovernanceMatchStatusV1,
    GuiGovernanceSourcePinV1, GuiCoreError, MAX_GOVERNANCE_DOCUMENT_BYTES,
    GOVERNANCE_DOCUMENT_ARCHIVE_PATH, GOVERNANCE_PIN_PREFIX_BLAKE3,
    compute_governance_document_digest, content_digest_pin_for_bytes, match_governance_document,
    validate_governance_source_pin, verify_archive_directory_v1,
};
use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, MAX_GOVERNANCE_REVISION_BYTES};

use common::{TestDir, open_session, open_session_with_revision, voters};

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

fn write_doc(dir: &TestDir, name: &str, contents: &[u8]) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap_or_else(|e| panic!("write doc: {e}"));
    path
}

// ============================================================ Validation T1-T7

const VALID_GIT: &str = "git:0123456789abcdef0123456789abcdef01234567";

#[test]
fn t1_valid_blake3_digest_reference_accepted() {
    let pin = validate_governance_source_pin(&content_digest_pin_for_bytes(b"doc"));
    assert!(pin.format_valid);
    assert_eq!(pin.kind, "BLAKE3_DIGEST");
}

#[test]
fn t2_malformed_digest_length_rejected() {
    let pin = validate_governance_source_pin("blake3:abcd");
    assert!(!pin.format_valid);
}

#[test]
fn t3_non_hex_rejected() {
    let bad = format!("{GOVERNANCE_PIN_PREFIX_BLAKE3}{}", "z".repeat(64));
    let pin = validate_governance_source_pin(&bad);
    assert!(!pin.format_valid);
}

#[test]
fn t4_whitespace_ambiguity_rejected() {
    assert!(!validate_governance_source_pin("   ").format_valid);
    assert!(!validate_governance_source_pin(" blake3:abcd").format_valid);
    assert!(!validate_governance_source_pin("blake3:abcd ").format_valid);
}

#[test]
fn t5_mutable_reference_junk_rejected() {
    for bad in ["latest", "main", "forum post", "current proposal", "HEAD", "tip"] {
        let pin = validate_governance_source_pin(bad);
        assert_eq!(pin.kind, "UNRECOGNIZED");
        assert!(!pin.format_valid, "{bad} should be unrecognized");
    }
}

#[test]
fn t6_valid_git_sha_accepted() {
    let pin = validate_governance_source_pin(VALID_GIT);
    assert!(pin.format_valid);
    assert_eq!(pin.kind, "GIT_COMMIT");
}

#[test]
fn t7_malformed_git_sha_rejected() {
    assert!(!validate_governance_source_pin("git:abcd").format_valid);
    assert!(!validate_governance_source_pin("git:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").format_valid);
}

// ===================================================== Document digest T8-T13

#[test]
fn t8_known_bytes_produce_expected_digest() {
    let dir = TestDir::new("gov-doc-digest");
    let path = write_doc(&dir, "proposal.md", b"governance-pilot-document");
    let digest = ok(compute_governance_document_digest(&path), "digest");
    let expected = content_digest_pin_for_bytes(b"governance-pilot-document");
    let expected_hex = expected
        .strip_prefix(GOVERNANCE_PIN_PREFIX_BLAKE3)
        .unwrap_or("");
    assert_eq!(digest.digest_hex, expected_hex);
    assert_eq!(digest.bytes, 25);
    assert_eq!(digest.display_filename, "proposal.md");
}

#[test]
fn t9_one_byte_change_gives_different_digest() {
    let dir = TestDir::new("gov-doc-onebyte");
    let p1 = write_doc(&dir, "a.md", b"governance-pilot");
    let p2 = write_doc(&dir, "b.md", b"governance-pilox");
    let d1 = ok(compute_governance_document_digest(&p1), "d1");
    let d2 = ok(compute_governance_document_digest(&p2), "d2");
    assert_ne!(d1.digest_hex, d2.digest_hex);
}

#[test]
fn t10_zero_byte_document_behavior_explicit() {
    let dir = TestDir::new("gov-doc-zero");
    let path = write_doc(&dir, "empty.bin", b"");
    let digest = ok(compute_governance_document_digest(&path), "zero digest");
    assert_eq!(digest.bytes, 0);
    // Zero-byte document is a valid (if unusual) immutable document.
    let pin = content_digest_pin_for_bytes(b"");
    let status = match_governance_document(&pin, Some(&digest));
    assert_eq!(status.status, GuiGovernanceMatchStatusV1::Matched);
}

#[test]
fn t11_oversized_document_rejected() {
    let dir = TestDir::new("gov-doc-oversize");
    let oversized = vec![0_u8; MAX_GOVERNANCE_DOCUMENT_BYTES + 1];
    let path = write_doc(&dir, "big.bin", &oversized);
    let error = err(
        compute_governance_document_digest(&path),
        "oversized must fail",
    );
    assert_eq!(error.code(), "GUI_GOVERNANCE_DOCUMENT_TOO_LARGE");
}

#[test]
fn t12_directory_rejected() {
    let dir = TestDir::new("gov-doc-dir");
    let subdir = dir.join("subdir");
    std::fs::create_dir(&subdir).unwrap_or_else(|e| panic!("mkdir: {e}"));
    let error = err(
        compute_governance_document_digest(&subdir),
        "directory must fail",
    );
    assert_eq!(error.code(), "GUI_GOVERNANCE_DOCUMENT_IS_DIRECTORY");
}

#[test]
fn t13_symlink_rejected_according_to_policy() {
    let dir = TestDir::new("gov-doc-symlink");
    let target = write_doc(&dir, "real.md", b"real-content");
    let link = dir.join("link.md");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&target, &link).unwrap_or_else(|e| panic!("symlink: {e}"));
    }
    #[cfg(windows)]
    {
        // Windows symlinks require elevated privileges in many CI sandboxes;
        // fall back to proving the policy is enforced for a directory-named
        // target that is not a regular file. The unit tests in `governance.rs`
        // exercise the symlink branch directly.
        if std::os::windows::fs::symlink_file(&target, &link).is_err() {
            // Symlink creation unavailable; assert the directory rejection
            // path covers the non-regular-file policy instead.
            let error = err(
                compute_governance_document_digest(dir.path()),
                "dir must fail",
            );
            assert_eq!(error.code(), "GUI_GOVERNANCE_DOCUMENT_IS_DIRECTORY");
            return;
        }
    }
    let error = err(
        compute_governance_document_digest(&link),
        "symlink must fail",
    );
    assert_eq!(error.code(), "GUI_GOVERNANCE_DOCUMENT_SYMLINK");
}

// ================================================ Reference matching T14-T16

#[test]
fn t14_matching_content_digest_succeeds() {
    let pin = content_digest_pin_for_bytes(b"matching-doc");
    let dir = TestDir::new("gov-match-ok");
    let path = write_doc(&dir, "p.md", b"matching-doc");
    let doc = ok(compute_governance_document_digest(&path), "doc");
    let status = match_governance_document(&pin, Some(&doc));
    assert_eq!(status.status, GuiGovernanceMatchStatusV1::Matched);
    assert!(status.status.is_cryptographically_matched());
}

#[test]
fn t15_mismatching_content_digest_fails() {
    let pin = content_digest_pin_for_bytes(b"doc-a");
    let dir = TestDir::new("gov-match-mismatch");
    let path = write_doc(&dir, "p.md", b"doc-b");
    let doc = ok(compute_governance_document_digest(&path), "doc");
    let status = match_governance_document(&pin, Some(&doc));
    assert_eq!(status.status, GuiGovernanceMatchStatusV1::Mismatch);
    assert!(!status.status.is_cryptographically_matched());
}

#[test]
fn t16_git_sha_reports_operator_attested_not_verified() {
    let dir = TestDir::new("gov-git-attest");
    let path = write_doc(&dir, "p.md", b"git-doc");
    let doc = ok(compute_governance_document_digest(&path), "doc");
    let status = match_governance_document(VALID_GIT, Some(&doc));
    assert_eq!(status.status, GuiGovernanceMatchStatusV1::OperatorAttested);
    assert!(!status.status.is_cryptographically_matched());
    // The label must not claim cryptographic verification; it states
    // correspondence is "not independently verified".
    assert!(status.status_label.contains("not independently verified"));
    assert!(
        !status.status_label.contains("cryptographically verified"),
        "operator-attested label must not claim cryptographic verification: {}",
        status.status_label
    );
}

// ====================================================== Creation T17-T19

fn complete_draft_with_revision(revision: &str) -> GuiElectionDraftV1 {
    let mut draft = GuiElectionDraftV1::new();
    ok(
        draft.set_basics("gov-test-election".to_owned(), revision.to_owned()),
        "basics",
    );
    ok(draft.set_rules(1, 2, true), "rules");
    ok(draft.set_voters(voter_hexs()), "voters");
    ok(draft.set_options(options()), "options");
    draft
}

#[test]
fn t17_content_digest_pin_can_populate_governance_source_revision() {
    let dir = TestDir::new("gov-populate");
    let path = write_doc(&dir, "proposal.md", b"populate-doc");
    let mut draft = complete_draft_with_revision("placeholder-rev");
    ok(draft.set_governance_document(&path), "select doc");
    ok(draft.use_governance_document_digest_as_revision(), "use digest");
    let preview = draft.preview();
    let pin = &preview.governance_source_pin;
    assert!(pin.format_valid);
    assert_eq!(pin.kind, "BLAKE3_DIGEST");
    assert_eq!(
        preview.governance_document_status.status,
        GuiGovernanceMatchStatusV1::Matched
    );
    assert!(preview.complete);
}

#[test]
fn t18_freeze_fails_when_digest_mode_document_does_not_match() {
    let dir = TestDir::new("gov-freeze-mismatch");
    // Select a document, then pin a *different* digest.
    let real_path = write_doc(&dir, "real.md", b"real-content");
    let real_pin = content_digest_pin_for_bytes(b"real-content");
    let other_pin = content_digest_pin_for_bytes(b"different-content");
    let mut draft = complete_draft_with_revision(&other_pin);
    ok(draft.set_governance_document(&real_path), "select real doc");
    // The bound revision (other_pin) does not match the selected doc (real_pin).
    let error = err(draft.freeze(), "freeze must fail on mismatch");
    assert_eq!(error.code(), "GUI_GOVERNANCE_DIGEST_MISMATCH");
    // Sanity: pinning the real digest would freeze fine.
    let mut good = complete_draft_with_revision(&real_pin);
    ok(good.set_governance_document(&real_path), "select real doc again");
    let (_result, _session) = ok(good.freeze(), "freeze with matching pin");
}

#[test]
fn t19_manifest_bytes_byte_identical_whether_or_not_document_support_enabled() {
    let pin = content_digest_pin_for_bytes(b"some-doc");
    let mut with_doc = complete_draft_with_revision(&pin);
    let dir = TestDir::new("gov-canonical-invariance");
    let path = write_doc(&dir, "d.md", b"some-doc");
    ok(with_doc.set_governance_document(&path), "set doc");

    let mut without_doc = complete_draft_with_revision(&pin);

    let (with_result, with_session) = ok(with_doc.freeze(), "freeze with doc");
    let (without_result, without_session) = ok(without_doc.freeze(), "freeze without doc");

    assert_eq!(
        with_result.summary.manifest_hash_hex,
        without_result.summary.manifest_hash_hex
    );
    assert_eq!(
        ok(with_session.artifacts().manifest().to_canonical_cbor(), "with manifest"),
        ok(without_session.artifacts().manifest().to_canonical_cbor(), "without manifest")
    );
}

// ========================================================= Archive T20-T24

fn session_with_governance_doc() -> (tari_cc_private_ballot_gui_core::GuiElectionSessionV1, Vec<u8>) {
    let mut session = open_session();
    if let Err(error) = session.close() {
        panic!("session must close: {error}");
    }
    (session, b"governance-archive-document".to_vec())
}

#[test]
fn t20_governance_document_included_in_archive_content() {
    let (session, doc) = session_with_governance_doc();
    let dir = TestDir::new("gov-archive-include");
    let target = dir.join("archive");
    let result = ok(
        write_archive_directory_v1_with_governance_document(&session, &target, Some(&doc)),
        "write archive",
    );
    let paths: Vec<&str> = result.files.iter().map(|f| f.path.as_str()).collect();
    assert!(paths.contains(&GOVERNANCE_DOCUMENT_ARCHIVE_PATH));
    assert!(target.join(GOVERNANCE_DOCUMENT_ARCHIVE_PATH).is_file());
}

#[test]
fn t21_archive_with_governance_document_verifies() {
    let (session, doc) = session_with_governance_doc();
    let dir = TestDir::new("gov-archive-verify");
    let target = dir.join("archive");
    ok(
        write_archive_directory_v1_with_governance_document(&session, &target, Some(&doc)),
        "write archive",
    );
    let verification = ok(verify_archive_directory_v1(&target), "verify");
    assert!(verification.verified, "failure: {:?}", verification.failure_code);
    assert!(verification.files.iter().any(|f| f.path == GOVERNANCE_DOCUMENT_ARCHIVE_PATH));
}

#[test]
fn t22_one_byte_document_mutation_breaks_archive_verification() {
    let (session, doc) = session_with_governance_doc();
    let dir = TestDir::new("gov-archive-tamper");
    let target = dir.join("archive");
    ok(
        write_archive_directory_v1_with_governance_document(&session, &target, Some(&doc)),
        "write archive",
    );
    let gov_path = target.join(GOVERNANCE_DOCUMENT_ARCHIVE_PATH);
    let bytes = std::fs::read(&gov_path).unwrap_or_else(|e| panic!("read gov: {e}"));
    let mut tampered = bytes.clone();
    tampered[0] ^= 0x01;
    std::fs::write(&gov_path, tampered).unwrap_or_else(|e| panic!("write tampered: {e}"));
    let verification = ok(verify_archive_directory_v1(&target), "verify");
    assert!(!verification.verified);
    assert_eq!(verification.failure_stage, Some("CATALOG_FILES"));
    assert_eq!(
        verification.failure_code.as_deref(),
        Some("ARCHIVE_FILE_DIGEST_MISMATCH")
    );
}

#[test]
fn t23_document_archive_path_cannot_be_path_traversed() {
    // The archive path is a project-controlled constant, independent of the
    // organizer filename. Confirm it satisfies the portable ArchivePathV1
    // profile (no traversal, no absolute/drive/backslash segments).
    use tari_cc_private_ballot_archive::ArchivePathV1;
    ok(
        ArchivePathV1::new(GOVERNANCE_DOCUMENT_ARCHIVE_PATH.to_owned()),
        "governance archive path must be portable",
    );
    // A hostile organizer filename must not be accepted as an archive path.
    for hostile in [
        "../evil.bin",
        "..\\evil.bin",
        "/etc/passwd",
        "C:evil.bin",
        "governance/../escape.bin",
    ] {
        let result = ArchivePathV1::new(hostile.to_owned());
        assert!(result.is_err(), "hostile path must be rejected: {hostile}");
    }
}

#[test]
fn t24_hostile_filename_cannot_control_archive_path() {
    // The selected document filename is sanitized for display only and is
    // never used as the archive path. Compute the digest from a hostile-named
    // file and confirm the archive path remains the fixed constant.
    let dir = TestDir::new("gov-hostile-name");
    let hostile_name = "..\\..\\evil.md";
    let path = write_doc(&dir, hostile_name, b"hostile-content");
    let digest = ok(compute_governance_document_digest(&path), "digest hostile");
    // The display filename is sanitized (no backslashes).
    assert!(
        !digest.display_filename.contains('\\') && !digest.display_filename.contains('/'),
        "display filename must be sanitized: {}",
        digest.display_filename
    );
    // The archive path is always the constant regardless of the source name.
    assert_eq!(GOVERNANCE_DOCUMENT_ARCHIVE_PATH, "governance/source.bin");
}

// =============================================== No canonical change T25-T26

#[test]
fn t25_existing_v1_canonical_vectors_unchanged() {
    // A non-pin revision (as the existing test fixtures use) must still freeze
    // and produce identical canonical bytes. Pin format validity is advisory
    // and does not gate freeze.
    let mut draft = complete_draft_with_revision("creation-rev-1");
    let (_result, session) = ok(draft.freeze(), "freeze legacy revision");
    // The manifest still encodes the exact opaque string.
    assert_eq!(
        session.artifacts().manifest().governance_source_revision(),
        "creation-rev-1"
    );
}

#[test]
fn t26_archive_without_governance_document_still_verifies() {
    // The existing archive path (no governance document) remains compatible.
    let mut session = open_session();
    if let Err(error) = session.close() {
        panic!("session must close: {error}");
    }
    let dir = TestDir::new("gov-archive-no-doc");
    let target = dir.join("archive");
    let result = ok(
        write_archive_directory_v1_with_governance_document(&session, &target, None),
        "write archive without doc",
    );
    let paths: Vec<&str> = result.files.iter().map(|f| f.path.as_str()).collect();
    assert!(!paths.contains(&GOVERNANCE_DOCUMENT_ARCHIVE_PATH));
    let verification = ok(verify_archive_directory_v1(&target), "verify");
    assert!(verification.verified, "failure: {:?}", verification.failure_code);
}

// =============================================== Bonus: pin DTO carries no secret

#[test]
fn governance_pin_dto_carries_no_secret_field() {
    let pin: GuiGovernanceSourcePinV1 = validate_governance_source_pin(VALID_GIT);
    let json = ok(serde_json::to_string(&pin), "serialize pin");
    let lower = json.to_lowercase();
    for forbidden in ["secret", "seed", "mnemonic", "auth", "token", "password", "wallet"] {
        assert!(!lower.contains(forbidden), "pin DTO exposes {forbidden}");
    }
}

#[test]
fn governance_pin_normalization_preserves_protocol_byte_limit() {
    // A normalized pin must still satisfy the protocol byte limit.
    let pin = content_digest_pin_for_bytes(b"x");
    assert!(pin.len() <= MAX_GOVERNANCE_REVISION_BYTES);
    let validated = validate_governance_source_pin(&pin);
    assert!(validated.format_valid);
}

#[test]
fn governance_document_too_large_error_is_bounded() {
    let error = GuiCoreError::governance_document_too_large();
    assert!(error.message().is_ascii());
    assert_eq!(error.code(), "GUI_GOVERNANCE_DOCUMENT_TOO_LARGE");
}

// ============================================================
// Slice 5A8 final hardening (M1): archive governance pin gate.
//
// These tests lock the "single digest identity" property (pin ↔ document ↔
// archive catalog) and the verify-time cross-check that catches an internally
// catalog-consistent archive containing the WRONG governance document for the
// bound `blake3:` pin. They also cover the missing-document and Git SHA
// operator-attested paths. No voter secret, no network.
// ============================================================

/// Frozen known-answer vector for the project domain-separated ArchiveFileV1
/// BLAKE3-256 digest of a governance document.
///
/// This is **not** plain `b3sum`. The digest is
/// `blake3(HASH_FRAME_PREFIX || 0x00 || "tari-cc-private-ballot/archive-file/v1"
///        || 0x00 || document_bytes)` — the same project-owned domain-separated
/// ArchiveFileV1 digest the archive content catalog records. The expected
/// 32-byte hex constant below is hard-coded and is NOT recomputed at runtime
/// with the production function (that would make the test tautological). The
/// test fails if the ArchiveFileV1 hash domain, domain framing, algorithm, or
/// byte interpretation changes.
#[test]
fn kat_governance_document_digest_is_frozen() {
    const KAT_BYTES: &[u8] = b"tari-governance-document-kat-v1";
    const KAT_DIGEST_HEX: &str =
        "9d1ba26f69b6e1af1f6c3a687139eb3110cc9289a97aa22806f65a652fc60053";
    let pin = content_digest_pin_for_bytes(KAT_BYTES);
    assert_eq!(
        pin,
        format!("{GOVERNANCE_PIN_PREFIX_BLAKE3}{KAT_DIGEST_HEX}"),
        "frozen KAT digest changed: ArchiveFileV1 hash domain/framing/algorithm altered"
    );
    // Negative: a one-byte change in the document must NOT produce the KAT.
    let mut mutated = KAT_BYTES.to_vec();
    mutated[0] ^= 0x01;
    let mutated_pin = content_digest_pin_for_bytes(&mutated);
    assert_ne!(
        mutated_pin,
        format!("{GOVERNANCE_PIN_PREFIX_BLAKE3}{KAT_DIGEST_HEX}"),
        "one-byte mutation must not match the frozen KAT"
    );
}

/// Locks the "single digest identity" property: the content-digest pin derived
/// by the production pin helper equals the archive catalog digest recorded for
/// the exact same bytes.
#[test]
fn content_pin_digest_equals_archive_catalog_digest() {
    let doc = b"pin-equality-document";
    let pin = content_digest_pin_for_bytes(doc);
    let pin_hex = pin
        .strip_prefix(GOVERNANCE_PIN_PREFIX_BLAKE3)
        .unwrap_or_else(|| panic!("content pin starts with blake3:"))
        .to_owned();

    let mut session = open_session_with_revision(&pin);
    ok(session.close(), "close session");

    let dir = TestDir::new("gov-pin-equality");
    let target = dir.join("archive");
    let result = ok(
        write_archive_directory_v1_with_governance_document(&session, &target, Some(doc)),
        "write archive with matching pin",
    );
    let gov_entry = result
        .files
        .iter()
        .find(|f| f.path == GOVERNANCE_DOCUMENT_ARCHIVE_PATH)
        .unwrap_or_else(|| panic!("governance document archived"));
    assert_eq!(
        gov_entry.digest_hex, pin_hex,
        "catalog digest must equal the content-pin digest for the same bytes"
    );

    let verification = ok(verify_archive_directory_v1(&target), "verify");
    assert!(verification.verified, "failure: {:?}", verification.failure_code);
    assert_eq!(
        verification.governance_source_matches_pin,
        GuiGovernanceArchivePinFactV1::Matched,
        "blake3-pin archive with the correct document must report Matched"
    );
}

/// Negative: writing an archive whose governance document bytes do not match
/// the bound `blake3:` pin is rejected at write time with the stable
/// `GUI_GOVERNANCE_DIGEST_MISMATCH` code. No internally-consistent-but-wrong
/// archive is ever produced.
#[test]
fn write_rejects_governance_document_mismatching_blake3_pin() {
    let real_doc = b"real-governance-document";
    let real_pin = content_digest_pin_for_bytes(real_doc);
    let other_doc = b"different-governance-document";

    let mut session = open_session_with_revision(&real_pin);
    ok(session.close(), "close session");

    let dir = TestDir::new("gov-write-mismatch");
    let target = dir.join("archive");
    let error = err(
        write_archive_directory_v1_with_governance_document(&session, &target, Some(other_doc)),
        "mismatched write must fail",
    );
    assert_eq!(error.code(), "GUI_GOVERNANCE_DIGEST_MISMATCH");
    // No archive directory should have been left behind as a valid archive.
    assert!(
        !target.join(ARCHIVE_MANIFEST_CANONICAL_PATH).is_file(),
        "rejected write must not leave an archive-manifest"
    );
}

/// Writes one raw file (creating parent directories as needed) for the
/// manually-constructed archive fixtures below.
fn write_raw_file(path: &std::path::Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap_or_else(|e| panic!("create parent: {e}"));
    }
    std::fs::write(path, bytes).unwrap_or_else(|e| panic!("write raw file: {e}"));
}

/// Builds an internally catalog-consistent archive directory from scratch
/// (bypassing the production writer's write-time gate) so the verify-time
/// governance-pin cross-check itself is what catches a wrong document. The
/// resulting archive has every catalog digest matching its on-disk bytes and a
/// rebuilt archive-manifest; it is "valid" by ordinary archive integrity
/// except for the governance-source correspondence.
fn build_internally_consistent_archive(
    target: &std::path::Path,
    artifacts: &tari_cc_private_ballot_gui_core::GuiElectionArtifactsV1,
    governance_doc: Option<&[u8]>,
) {
    let provider = Blake3HashProviderV1;
    let manifest_bytes = ok(artifacts.manifest().to_canonical_cbor(), "manifest cbor");
    let registry_bytes = ok(artifacts.registry().to_canonical_cbor(), "registry cbor");
    let candidate_bytes = ok(artifacts.candidates().to_canonical_cbor(), "candidates cbor");

    let mut file_set: Vec<(String, Vec<u8>)> = vec![
        ("election-manifest.cbor".to_owned(), manifest_bytes),
        ("voter-registry.cbor".to_owned(), registry_bytes),
        ("candidate-set.cbor".to_owned(), candidate_bytes),
    ];
    if let Some(doc) = governance_doc {
        file_set.push((GOVERNANCE_DOCUMENT_ARCHIVE_PATH.to_owned(), doc.to_vec()));
    }

    let mut cat_entries = Vec::with_capacity(file_set.len());
    for (path, bytes) in &file_set {
        let archive_path = ok(ArchivePathV1::new(path.clone()), "archive path");
        let entry = ArchiveFileEntryV1::for_bytes(archive_path, &provider, bytes);
        cat_entries.push(entry);
        write_raw_file(&target.join(path), bytes);
    }
    let catalog = ok(ArchiveFileCatalogV1::new(cat_entries), "archive catalog");
    let archive_manifest = ok(
        ArchiveManifestV1::for_provider(artifacts.manifest_hash(), catalog, &provider),
        "archive manifest",
    );
    let archive_manifest_bytes = ok(archive_manifest.to_canonical_cbor(), "archive manifest cbor");
    write_raw_file(
        &target.join(ARCHIVE_MANIFEST_CANONICAL_PATH),
        &archive_manifest_bytes,
    );
}

/// The key regression: an archive that is internally catalog-consistent (every
/// catalog digest matches its on-disk bytes, archive hash rebuilds) but
/// contains the WRONG governance document for the bound `blake3:` pin is
/// caught by the verify-time governance-pin cross-check, not by ordinary
/// archive digest verification.
#[test]
fn verify_rejects_internally_consistent_archive_with_wrong_governance_document() {
    let doc_a = b"governance-document-A";
    let pin_a = content_digest_pin_for_bytes(doc_a);
    let doc_b = b"governance-document-B-different-bytes";

    let artifacts = common::artifacts_with_revision(&pin_a);
    let dir = TestDir::new("gov-verify-wrong-doc");
    let target = dir.join("archive");
    // Build an archive whose catalog is consistent with doc_b on disk, but the
    // manifest pins digest_a. Ordinary archive integrity passes; the
    // governance-pin cross-check must catch it.
    build_internally_consistent_archive(&target, &artifacts, Some(doc_b));

    let verification = ok(verify_archive_directory_v1(&target), "verify");
    assert!(
        !verification.verified,
        "internally-consistent wrong-doc archive must fail: {:?}",
        verification.failure_code
    );
    assert_eq!(
        verification.failure_stage,
        Some("GOVERNANCE_PIN"),
        "the governance-pin cross-check itself must catch the wrong document"
    );
    assert_eq!(
        verification.failure_code.as_deref(),
        Some("GUI_GOVERNANCE_ARCHIVE_PIN_MISMATCH")
    );
    assert_eq!(
        verification.governance_source_matches_pin,
        GuiGovernanceArchivePinFactV1::Mismatch
    );
}

/// A `blake3:` pin with no archived `governance/source.bin` fails verify
/// explicitly (not as a generic optional-content omission).
#[test]
fn verify_rejects_missing_governance_document_for_blake3_pin() {
    let doc = b"missing-governance-document";
    let pin = content_digest_pin_for_bytes(doc);

    let artifacts = common::artifacts_with_revision(&pin);
    let dir = TestDir::new("gov-verify-missing");
    let target = dir.join("archive");
    // No governance document archived, but the manifest pins its digest.
    build_internally_consistent_archive(&target, &artifacts, None);

    let verification = ok(verify_archive_directory_v1(&target), "verify");
    assert!(!verification.verified, "must fail: {:?}", verification.failure_code);
    assert_eq!(verification.failure_stage, Some("GOVERNANCE_PIN"));
    assert_eq!(
        verification.failure_code.as_deref(),
        Some("GUI_GOVERNANCE_ARCHIVE_DOCUMENT_MISSING")
    );
    assert_eq!(
        verification.governance_source_matches_pin,
        GuiGovernanceArchivePinFactV1::Missing
    );
}

/// A Git SHA pin archive remains operator-attested: the document is not
/// cryptographically matched to the Git reference, and the UI must not display
/// "Matched"/"Verified" for the correspondence.
#[test]
fn verify_git_sha_archive_reports_operator_attested_not_matched() {
    let doc = b"git-attested-governance-document";
    let artifacts = common::artifacts_with_revision(
        "git:0123456789abcdef0123456789abcdef01234567",
    );
    let dir = TestDir::new("gov-verify-git");
    let target = dir.join("archive");
    build_internally_consistent_archive(&target, &artifacts, Some(doc));

    let verification = ok(verify_archive_directory_v1(&target), "verify");
    assert!(verification.verified, "failure: {:?}", verification.failure_code);
    assert_eq!(
        verification.governance_source_matches_pin,
        GuiGovernanceArchivePinFactV1::OperatorAttested,
        "Git SHA pin must report operator-attested, not Matched"
    );
    assert!(
        !verification.governance_source_matches_pin.is_matched(),
        "operator-attested must not collapse into Matched"
    );
}

/// No-pin / unrecognized-revision archives remain valid and report
/// NotApplicable for the governance-source-pin fact.
#[test]
fn verify_unrecognized_revision_archive_reports_not_applicable() {
    let artifacts = common::artifacts_with_revision("unrecognized-revision-text");
    let dir = TestDir::new("gov-verify-nopin");
    let target = dir.join("archive");
    build_internally_consistent_archive(&target, &artifacts, None);

    let verification = ok(verify_archive_directory_v1(&target), "verify");
    assert!(verification.verified, "failure: {:?}", verification.failure_code);
    assert_eq!(
        verification.governance_source_matches_pin,
        GuiGovernanceArchivePinFactV1::NotApplicable
    );
}

/// `governance_source_matches_pin` reports `Matched` only for actual equality.
/// A correct blake3-pin archive reports Matched; the wrong-doc and missing
/// cases (above) report Mismatch and Missing respectively; Git reports
/// OperatorAttested; unrecognized reports NotApplicable. This test pins the
/// matched boundary explicitly.
#[test]
fn governance_source_matches_pin_true_only_for_actual_equality() {
    // Matched (covered in content_pin_digest_equals_archive_catalog_digest).
    // Here we assert the production pin helper, the catalog digest, and the
    // verifier fact all agree for the matching case.
    let doc = b"equality-boundary-doc";
    let pin = content_digest_pin_for_bytes(doc);
    let mut session = open_session_with_revision(&pin);
    ok(session.close(), "close session");
    let dir = TestDir::new("gov-equality-boundary");
    let target = dir.join("archive");
    ok(
        write_archive_directory_v1_with_governance_document(&session, &target, Some(doc)),
        "write matching archive",
    );
    let verification = ok(verify_archive_directory_v1(&target), "verify");
    assert!(verification.verified);
    assert!(verification.governance_source_matches_pin.is_matched());
    assert_eq!(
        verification.governance_source_matches_pin.as_str(),
        "MATCHED"
    );
    assert_eq!(
        verification.governance_source_matches_pin.label(),
        "Matched"
    );
}

/// The new governance-pin failure codes are bounded, ASCII, and carry no
/// secret/path material.
#[test]
fn governance_archive_pin_error_codes_are_bounded_and_safe() {
    for error in [
        GuiCoreError::governance_archive_pin_mismatch(),
        GuiCoreError::governance_archive_document_missing(),
    ] {
        assert!(error.message().is_ascii(), "message must be ASCII: {}", error.code());
        let lower = error.message().to_lowercase();
        for forbidden in ["secret", "seed", "mnemonic", "path", "token", "password", "wallet"] {
            assert!(
                !lower.contains(forbidden),
                "error {} message leaks {forbidden}: {}",
                error.code(),
                error.message()
            );
        }
    }
}
