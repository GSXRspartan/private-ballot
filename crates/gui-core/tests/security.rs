//! Security boundary and error-model tests (required cases 45-50).

mod common;

use tari_cc_private_ballot_gui_core::archive_writer::write_archive_directory_v1;
use tari_cc_private_ballot_gui_core::{
    GuiCoreError, GuiElectionArtifactsV1, verify_archive_directory_v1,
};
use tari_cc_private_ballot_protocol::MAX_CANONICAL_OBJECT_BYTES;

use common::{TestDir, candidate_bytes, manifest_bytes, open_session, registry_bytes};

fn collect_source() -> String {
    let src_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
    let mut sources = String::new();
    let entries = match std::fs::read_dir(src_dir) {
        Ok(entries) => entries,
        Err(_) => panic!("gui-core src directory must be readable"),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        match std::fs::read_to_string(&path) {
            Ok(text) => sources.push_str(&text),
            Err(_) => panic!("gui-core source file must be readable"),
        }
    }
    sources
}

#[test]
fn gui_core_sources_contain_no_secret_bearing_api() {
    let sources = collect_source();
    // Code-level identifiers of secret-bearing APIs. Prose words such as
    // "mnemonic" legitimately appear in documentation comments that state
    // the boundary, so only API identifiers are scanned.
    for forbidden in [
        "TariTriptychSecretKeyV1",
        "WalletdAuthSecret",
        "with_walletd_auth",
        "seed_phrase",
        "private_key",
        "secret_scalar",
        "RistrettoSecretKey",
    ] {
        assert!(
            !sources.contains(forbidden),
            "gui-core source must not reference {forbidden}"
        );
    }
}

#[test]
fn gui_core_sources_contain_no_network_or_async_usage() {
    let sources = collect_source();
    for forbidden in [
        "std::net",
        "TcpStream",
        "UdpSocket",
        "reqwest",
        "tokio",
        "async fn",
        "hyper",
        "ureq",
    ] {
        assert!(
            !sources.contains(forbidden),
            "gui-core source must not reference {forbidden}"
        );
    }
}

#[test]
fn error_strings_are_bounded_and_ascii() {
    let errors: Vec<GuiCoreError> = vec![
        GuiCoreError::file_not_found("manifest"),
        GuiCoreError::io_failure("archive-file"),
        GuiCoreError::registry_commitment_mismatch(),
        GuiCoreError::archive_target_not_empty(),
        GuiCoreError::archive_target_invalid(),
        GuiCoreError::archive_missing_file(),
        GuiCoreError::archive_unexpected_file(),
        GuiCoreError::archive_missing_artifact("manifest"),
    ];

    // Also collect real protocol-derived errors through the public facades.
    let bad_load =
        GuiElectionArtifactsV1::from_bytes(&[0xff], &registry_bytes(), &candidate_bytes());
    match bad_load {
        Ok(_) => panic!("invalid manifest bytes must fail"),
        Err(error) => {
            assert!(error.code().len() <= 64);
            assert!(error.message().len() <= 128);
        }
    }

    for error in errors {
        assert!(error.code().len() <= 64, "code too long: {}", error.code());
        assert!(error.message().len() <= 128, "message too long");
        assert!(error.code().is_ascii());
        assert!(error.message().is_ascii());
        let rendered = error.to_string();
        assert!(rendered.len() <= 256, "rendered error too long: {rendered}");
        assert!(rendered.is_ascii());
    }
}

#[test]
fn errors_carry_no_credential_material_or_paths() {
    // Build errors after using a secret-bearing fixture: the error text must
    // never contain the secret bytes in any encoding.
    let secret_hex = common::voters()[0]
        .secret_bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    let mut session = open_session();
    let package = common::triptych_package_bytes(0, &[b"candidate-a"]);
    if let Err(error) = session.intake_ballot(&package) {
        panic!("valid ballot must intake: {error}");
    }
    // Force a duplicate rejection (an intake "error path" result).
    let duplicate = common::triptych_package_bytes(0, &[b"candidate-b"]);
    let duplicate_result = match session.intake_ballot(&duplicate) {
        Ok(result) => result,
        Err(_) => panic!("duplicate must return a decision"),
    };
    assert!(!duplicate_result.accepted);
    assert!(!duplicate_result.code.contains(&secret_hex));

    // Load failures must not leak paths or secrets.
    let dir = TestDir::new("security-noleak");
    let missing = dir.join("absent.cbor");
    let error = match GuiElectionArtifactsV1::from_paths(&missing, &missing, &missing) {
        Ok(_) => panic!("missing files must fail"),
        Err(error) => error,
    };
    let rendered = error.to_string();
    assert!(!rendered.contains(&secret_hex));
    assert!(
        !rendered.contains("absent.cbor"),
        "error text must not embed file names: {rendered}"
    );
    assert!(!rendered.contains(&dir.path().to_string_lossy().to_string()));
}

#[test]
fn paths_with_spaces_are_supported() {
    let dir = TestDir::new("paths with spaces");
    let sub = dir.join("election files");
    assert!(std::fs::create_dir_all(&sub).is_ok());

    let manifest_path = sub.join("election manifest.cbor");
    let registry_path = sub.join("voter registry.cbor");
    let candidate_path = sub.join("candidate set.cbor");
    assert!(std::fs::write(&manifest_path, manifest_bytes()).is_ok());
    assert!(std::fs::write(&registry_path, registry_bytes()).is_ok());
    assert!(std::fs::write(&candidate_path, candidate_bytes()).is_ok());

    let artifacts =
        GuiElectionArtifactsV1::from_paths(&manifest_path, &registry_path, &candidate_path);
    assert!(artifacts.is_ok());

    let mut session = open_session();
    let package = common::triptych_package_bytes(0, &[b"candidate-a"]);
    assert!(session.intake_ballot(&package).is_ok());
    assert!(session.close().is_ok());

    let archive_dir = sub.join("archive output");
    let written = write_archive_directory_v1(&session, &archive_dir);
    assert!(written.is_ok());
    let verified = verify_archive_directory_v1(&archive_dir);
    match verified {
        Ok(result) => assert!(result.verified, "failure: {:?}", result.failure_code),
        Err(error) => panic!("spaced-path archive must verify: {error}"),
    }
}

#[test]
fn oversized_artifact_is_rejected_within_limits() {
    let dir = TestDir::new("oversized");
    let oversized = dir.join("big.cbor");
    assert!(std::fs::write(&oversized, vec![0u8; MAX_CANONICAL_OBJECT_BYTES + 1]).is_ok());

    let error = match GuiElectionArtifactsV1::from_paths(&oversized, &oversized, &oversized) {
        Ok(_) => panic!("oversized artifact must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "PROTOCOL_LIMIT_EXCEEDED");
}

#[test]
fn facade_crates_do_not_depend_on_gui_or_network_libraries() {
    // The dependency audit is enforced structurally by Cargo (path-only
    // backend dependencies); this test asserts the manifest declares no
    // forbidden dependency names. `serde` is deliberately permitted from
    // Slice 5A3 onward: ADR-0007 defers DTO serialization to the shell slice
    // that needs it, and 5A3 is that slice. Serialization is not a GUI,
    // network, async-runtime, secret-store, or database capability.
    let manifest = match std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
    {
        Ok(text) => text,
        Err(_) => panic!("gui-core Cargo.toml must be readable"),
    };
    for forbidden in [
        "tauri", "tokio", "reqwest", "hyper", "ureq", "actix", "axum", "keyring", "rusqlite",
        "sqlx",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "gui-core must not depend on {forbidden}"
        );
    }
}
