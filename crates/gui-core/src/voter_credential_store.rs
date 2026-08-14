//! Default encrypted voter credential store helpers.
//!
//! The Tauri shell resolves the platform app-data directory and passes that
//! path into this module. gui-core composes only deterministic child paths,
//! validates public governance keys, and reads/writes the reviewed encrypted
//! [`VoterCredentialContainerV1`](crate::voter_credential_container::VoterCredentialContainerV1)
//! bytes. It never stores plaintext credentials and never chooses a fallback
//! directory.

use std::path::{Path, PathBuf};

use serde::Serialize;
use tari_cc_private_ballot_crypto::{RISTRETTO_COMPRESSED_POINT_BYTES, RistrettoPublicKeyV1};

use crate::error::GuiCoreError;
use crate::hex::{abbreviate_hex, from_hex, to_lower_hex};
use crate::voter_credential::VoterGovernanceCredentialV1;
use crate::voter_credential_container::{
    VOTER_CREDENTIAL_CONTAINER_V1_BYTES, VOTER_CREDENTIAL_CONTAINER_V1_FORMAT_VERSION,
    VoterCredentialContainerV1, default_voter_credential_filename_v1,
    export_voter_credential_container_v1, read_voter_credential_container_v1,
    write_voter_credential_container_v1,
};

/// Backend-controlled child directory for local encrypted credentials.
pub const VOTER_CREDENTIALS_DIRECTORY_NAME: &str = "credentials";
const VOTER_CREDENTIAL_FILE_PREFIX: &str = "credential-";
const VOTER_CREDENTIAL_FILE_SUFFIX: &str = ".tcbcred";
const PUBLIC_KEY_HEX_LEN: usize = RISTRETTO_COMPRESSED_POINT_BYTES * 2;

/// Safe public summary of one encrypted local credential file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuiVoterCredentialFileSummaryV1 {
    /// Full public governance key from the authenticated container header.
    pub public_governance_key_hex: String,
    /// Abbreviated public governance key for display.
    pub public_governance_key_abbrev: String,
    /// Fixed credential container format version.
    pub format_version: u16,
    /// True when this summary came from the backend-controlled default store.
    pub saved_locally: bool,
    /// True when the filename is the canonical default filename for the key.
    pub is_default: bool,
}

/// Bounded public result for saved-credential discovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuiSavedVoterCredentialsV1 {
    /// Number of valid saved credentials returned.
    pub saved_credential_count: usize,
    /// Number of expected-pattern entries skipped because they were malformed,
    /// wrong-sized, not ordinary files, or unsafe indirections.
    pub skipped_invalid_count: usize,
    /// Valid saved credentials sorted by public governance key.
    pub credentials: Vec<GuiVoterCredentialFileSummaryV1>,
}

/// Safe public result for a portable credential backup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuiVoterCredentialBackupResultV1 {
    /// Full public governance key for the backed-up credential.
    pub public_governance_key_hex: String,
    /// Abbreviated public governance key for display.
    pub public_governance_key_abbrev: String,
    /// Fixed credential container format version.
    pub format_version: u16,
}

/// Safe public result for local saved-credential deletion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuiSavedVoterCredentialDeleteResultV1 {
    /// Full public governance key whose backend-derived file was targeted.
    pub public_governance_key_hex: String,
    /// Abbreviated public governance key for display.
    pub public_governance_key_abbrev: String,
    /// Whether the exact backend-derived file existed and was removed.
    pub deleted: bool,
}

/// Returns the backend-controlled credentials directory under an injected
/// platform app-data root.
#[must_use]
pub fn voter_credentials_directory_v1(app_data_root: &Path) -> PathBuf {
    app_data_root.join(VOTER_CREDENTIALS_DIRECTORY_NAME)
}

/// Returns the backend-derived default credential path for a validated public
/// governance key.
#[must_use]
pub fn default_voter_credential_path_v1(
    credentials_dir: &Path,
    public_key: &[u8; RISTRETTO_COMPRESSED_POINT_BYTES],
) -> PathBuf {
    credentials_dir.join(default_voter_credential_filename_v1(public_key))
}

/// Strictly parses a public governance key hex identifier supplied over IPC.
///
/// The key must be exactly 32 bytes of hex and must decompress as a canonical
/// Ristretto public key.
pub fn parse_public_governance_key_hex_v1(
    public_key_hex: &str,
) -> Result<[u8; RISTRETTO_COMPRESSED_POINT_BYTES], GuiCoreError> {
    if public_key_hex.len() != PUBLIC_KEY_HEX_LEN {
        return Err(GuiCoreError::malformed_hex_input());
    }
    let bytes = from_hex(public_key_hex).ok_or_else(GuiCoreError::malformed_hex_input)?;
    let public_key: [u8; RISTRETTO_COMPRESSED_POINT_BYTES] = bytes
        .try_into()
        .map_err(|_| GuiCoreError::malformed_hex_input())?;
    RistrettoPublicKeyV1::from_bytes(&public_key)
        .map_err(|_| GuiCoreError::malformed_hex_input())?;
    Ok(public_key)
}

/// Creates or validates the backend credentials directory.
///
/// The directory itself must not be a symlink or Windows reparse point. On
/// Unix, permissions are narrowed to owner-only access where supported.
pub fn ensure_voter_credentials_directory_v1(credentials_dir: &Path) -> Result<(), GuiCoreError> {
    match std::fs::symlink_metadata(credentials_dir) {
        Ok(metadata) => {
            reject_path_indirection(&metadata)?;
            if !metadata.is_dir() {
                return Err(GuiCoreError::credential_unsafe_path());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(credentials_dir)
                .map_err(|_| GuiCoreError::io_failure("credential-directory"))?;
            let metadata = std::fs::symlink_metadata(credentials_dir)
                .map_err(|_| GuiCoreError::io_failure("credential-directory"))?;
            reject_path_indirection(&metadata)?;
            if !metadata.is_dir() {
                return Err(GuiCoreError::credential_unsafe_path());
            }
        }
        Err(_) => return Err(GuiCoreError::io_failure("credential-directory")),
    }

    restrict_directory_permissions(credentials_dir)
}

/// Lists valid local saved credentials from the backend-controlled directory.
///
/// Non-matching files are ignored. Matching-pattern entries are counted as
/// skipped when they are malformed, wrong-sized, unsafe, or not ordinary files.
pub fn list_saved_voter_credentials_v1(
    credentials_dir: &Path,
) -> Result<GuiSavedVoterCredentialsV1, GuiCoreError> {
    match std::fs::symlink_metadata(credentials_dir) {
        Ok(metadata) => {
            reject_path_indirection(&metadata)?;
            if !metadata.is_dir() {
                return Err(GuiCoreError::credential_unsafe_path());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(GuiSavedVoterCredentialsV1 {
                saved_credential_count: 0,
                skipped_invalid_count: 0,
                credentials: Vec::new(),
            });
        }
        Err(_) => return Err(GuiCoreError::io_failure("credential-directory")),
    }

    let entries = std::fs::read_dir(credentials_dir)
        .map_err(|_| GuiCoreError::io_failure("credential-directory"))?;
    let mut credentials = Vec::new();
    let mut skipped_invalid_count = 0_usize;

    for entry in entries {
        let Ok(entry) = entry else {
            skipped_invalid_count = skipped_invalid_count.saturating_add(1);
            continue;
        };
        let Some(file_name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !credential_file_name_has_expected_shape(&file_name) {
            continue;
        }
        if public_key_from_default_file_name(&file_name).is_err() {
            skipped_invalid_count = skipped_invalid_count.saturating_add(1);
            continue;
        }

        let path = entry.path();
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            skipped_invalid_count = skipped_invalid_count.saturating_add(1);
            continue;
        };
        if reject_path_indirection(&metadata).is_err() || !metadata.is_file() {
            skipped_invalid_count = skipped_invalid_count.saturating_add(1);
            continue;
        }
        if metadata.len() != VOTER_CREDENTIAL_CONTAINER_V1_BYTES as u64 {
            skipped_invalid_count = skipped_invalid_count.saturating_add(1);
            continue;
        }

        let Ok(container) = read_voter_credential_container_v1(&path) else {
            skipped_invalid_count = skipped_invalid_count.saturating_add(1);
            continue;
        };
        let public_key = container.public_key_bytes();
        if default_voter_credential_filename_v1(&public_key) != file_name {
            skipped_invalid_count = skipped_invalid_count.saturating_add(1);
            continue;
        }
        credentials.push(file_summary_for_public_key(&public_key, true, true));
    }

    credentials.sort_by(|left, right| {
        left.public_governance_key_hex
            .cmp(&right.public_governance_key_hex)
    });
    Ok(GuiSavedVoterCredentialsV1 {
        saved_credential_count: credentials.len(),
        skipped_invalid_count,
        credentials,
    })
}

/// Encrypts and writes a new local durable credential after its caller has
/// decided that no conflicting identity is loaded.
pub fn write_new_durable_voter_credential_v1(
    credentials_dir: &Path,
    credential: &VoterGovernanceCredentialV1,
    passphrase: &str,
) -> Result<GuiVoterCredentialFileSummaryV1, GuiCoreError> {
    let public_key = credential.public_key_bytes()?;
    let container = export_voter_credential_container_v1(credential, passphrase)?;
    write_voter_credential_container_v1(
        &default_voter_credential_path_v1(credentials_dir, &public_key),
        &container,
    )?;
    Ok(file_summary_for_public_key(&public_key, true, true))
}

/// Reads and decrypts the backend-derived local credential for the requested
/// public governance key.
pub fn unlock_saved_voter_credential_v1(
    credentials_dir: &Path,
    public_key: &[u8; RISTRETTO_COMPRESSED_POINT_BYTES],
    passphrase: &str,
) -> Result<VoterGovernanceCredentialV1, GuiCoreError> {
    let path = default_voter_credential_path_v1(credentials_dir, public_key);
    let container = read_voter_credential_container_v1(&path)?;
    let credential = container.decrypt(passphrase)?;
    if credential.public_key_bytes()? != *public_key {
        return Err(GuiCoreError::credential_public_key_mismatch());
    }
    Ok(credential)
}

/// Reads and decrypts one portable credential file chosen by the user.
pub fn import_voter_credential_from_path_v1(
    path: &Path,
    passphrase: &str,
) -> Result<(VoterGovernanceCredentialV1, VoterCredentialContainerV1), GuiCoreError> {
    let container = read_voter_credential_container_v1(path)?;
    let credential = container.decrypt(passphrase)?;
    if credential.public_key_bytes()? != container.public_key_bytes() {
        return Err(GuiCoreError::credential_public_key_mismatch());
    }
    Ok((credential, container))
}

/// Copies an already validated imported encrypted container into the default
/// local store.
///
/// This deliberately copies the encrypted bytes after successful decrypt and
/// public-key validation. Re-encrypting would add cost without adding a new
/// security property for import: the V1 header is authenticated and the same
/// passphrase is the only passphrase supplied for the imported file.
pub fn copy_validated_voter_credential_to_default_v1(
    credentials_dir: &Path,
    container: &VoterCredentialContainerV1,
) -> Result<GuiVoterCredentialFileSummaryV1, GuiCoreError> {
    let public_key = container.public_key_bytes();
    let path = default_voter_credential_path_v1(credentials_dir, &public_key);
    write_voter_credential_container_v1(&path, container)?;
    Ok(file_summary_for_public_key(&public_key, true, true))
}

/// Writes a fresh encrypted portable backup for an unlocked credential.
pub fn backup_voter_credential_to_path_v1(
    credential: &VoterGovernanceCredentialV1,
    path: &Path,
    passphrase: &str,
) -> Result<GuiVoterCredentialBackupResultV1, GuiCoreError> {
    let public_key = credential.public_key_bytes()?;
    let container = export_voter_credential_container_v1(credential, passphrase)?;
    write_voter_credential_container_v1(path, &container)?;
    Ok(backup_result_for_public_key(&public_key))
}

/// Deletes only the backend-derived local credential file for a validated
/// public governance key.
pub fn delete_saved_voter_credential_v1(
    credentials_dir: &Path,
    public_key: &[u8; RISTRETTO_COMPRESSED_POINT_BYTES],
) -> Result<GuiSavedVoterCredentialDeleteResultV1, GuiCoreError> {
    let path = default_voter_credential_path_v1(credentials_dir, public_key);
    let deleted = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => {
            reject_path_indirection(&metadata)?;
            if !metadata.is_file() {
                return Err(GuiCoreError::credential_unsafe_path());
            }
            std::fs::remove_file(&path)
                .map_err(|_| GuiCoreError::io_failure("credential-container"))?;
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => return Err(GuiCoreError::io_failure("credential-container")),
    };
    Ok(GuiSavedVoterCredentialDeleteResultV1 {
        deleted,
        ..delete_result_for_public_key(public_key)
    })
}

/// Returns a public local-file summary for a validated public key.
#[must_use]
pub fn file_summary_for_public_key(
    public_key: &[u8; RISTRETTO_COMPRESSED_POINT_BYTES],
    saved_locally: bool,
    is_default: bool,
) -> GuiVoterCredentialFileSummaryV1 {
    let public_hex = to_lower_hex(public_key);
    GuiVoterCredentialFileSummaryV1 {
        public_governance_key_abbrev: abbreviate_hex(&public_hex, 8, 6),
        public_governance_key_hex: public_hex,
        format_version: VOTER_CREDENTIAL_CONTAINER_V1_FORMAT_VERSION,
        saved_locally,
        is_default,
    }
}

fn backup_result_for_public_key(
    public_key: &[u8; RISTRETTO_COMPRESSED_POINT_BYTES],
) -> GuiVoterCredentialBackupResultV1 {
    let public_hex = to_lower_hex(public_key);
    GuiVoterCredentialBackupResultV1 {
        public_governance_key_abbrev: abbreviate_hex(&public_hex, 8, 6),
        public_governance_key_hex: public_hex,
        format_version: VOTER_CREDENTIAL_CONTAINER_V1_FORMAT_VERSION,
    }
}

fn delete_result_for_public_key(
    public_key: &[u8; RISTRETTO_COMPRESSED_POINT_BYTES],
) -> GuiSavedVoterCredentialDeleteResultV1 {
    let public_hex = to_lower_hex(public_key);
    GuiSavedVoterCredentialDeleteResultV1 {
        public_governance_key_abbrev: abbreviate_hex(&public_hex, 8, 6),
        public_governance_key_hex: public_hex,
        deleted: false,
    }
}

fn credential_file_name_has_expected_shape(file_name: &str) -> bool {
    file_name.starts_with(VOTER_CREDENTIAL_FILE_PREFIX)
        && file_name.ends_with(VOTER_CREDENTIAL_FILE_SUFFIX)
        && file_name.len()
            == VOTER_CREDENTIAL_FILE_PREFIX.len()
                + PUBLIC_KEY_HEX_LEN
                + VOTER_CREDENTIAL_FILE_SUFFIX.len()
}

fn public_key_from_default_file_name(
    file_name: &str,
) -> Result<[u8; RISTRETTO_COMPRESSED_POINT_BYTES], GuiCoreError> {
    if !credential_file_name_has_expected_shape(file_name) {
        return Err(GuiCoreError::malformed_hex_input());
    }
    let start = VOTER_CREDENTIAL_FILE_PREFIX.len();
    let end = start + PUBLIC_KEY_HEX_LEN;
    parse_public_governance_key_hex_v1(&file_name[start..end])
}

fn reject_path_indirection(metadata: &std::fs::Metadata) -> Result<(), GuiCoreError> {
    if metadata.file_type().is_symlink() || is_windows_reparse_point(metadata) {
        return Err(GuiCoreError::credential_unsafe_path());
    }
    Ok(())
}

#[cfg(windows)]
fn is_windows_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_windows_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn restrict_directory_permissions(path: &Path) -> Result<(), GuiCoreError> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(path)
        .map_err(|_| GuiCoreError::io_failure("credential-directory"))?
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions)
        .map_err(|_| GuiCoreError::io_failure("credential-directory"))
}

#[cfg(not(unix))]
fn restrict_directory_permissions(_path: &Path) -> Result<(), GuiCoreError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek_v4::scalar::Scalar;
    use zeroize::Zeroizing;

    const PASSPHRASE: &str = "store passphrase";

    #[test]
    fn directory_and_filename_are_derived_from_app_data_and_public_key() {
        let app_data = TestDir::new("app-data");
        let credential = credential(7);
        let public_key = ok(credential.public_key_bytes());
        let credentials_dir = voter_credentials_directory_v1(app_data.path());
        let path = default_voter_credential_path_v1(&credentials_dir, &public_key);

        assert_eq!(credentials_dir, app_data.path().join("credentials"));
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some(default_voter_credential_filename_v1(&public_key).as_str())
        );
        assert!(!path.to_string_lossy().contains("election"));
        assert!(!path.to_string_lossy().contains("passphrase"));
    }

    #[test]
    fn list_finds_valid_container_and_skips_malformed_entries() {
        let app_data = TestDir::new("list");
        let credentials_dir = voter_credentials_directory_v1(app_data.path());
        ok(ensure_voter_credentials_directory_v1(&credentials_dir));
        let credential = credential(7);
        let public_key = ok(credential.public_key_bytes());
        ok(write_new_durable_voter_credential_v1(
            &credentials_dir,
            &credential,
            PASSPHRASE,
        ));

        ok(std::fs::write(
            credentials_dir.join(format!("credential-{}.tcbcred", "00".repeat(32))),
            [0_u8; 143],
        ));
        ok(std::fs::write(
            credentials_dir.join("notes.txt"),
            b"ignored",
        ));

        let listed = ok(list_saved_voter_credentials_v1(&credentials_dir));

        assert_eq!(listed.saved_credential_count, 1);
        assert_eq!(listed.skipped_invalid_count, 1);
        assert_eq!(
            listed.credentials[0].public_governance_key_hex,
            to_lower_hex(&public_key)
        );
        let json = ok(serde_json::to_value(&listed));
        assert!(json.pointer("/credentials/0/path").is_none());
        assert!(json.to_string().contains(&to_lower_hex(&public_key)));
        for forbidden in ["salt", "nonce", "ciphertext", "passphrase", "secret"] {
            assert!(!json.to_string().to_lowercase().contains(forbidden));
        }
    }

    #[test]
    fn import_persistence_copies_validated_encrypted_bytes_and_backup_reencrypts() {
        let app_data = TestDir::new("import");
        let credentials_dir = voter_credentials_directory_v1(app_data.path());
        ok(ensure_voter_credentials_directory_v1(&credentials_dir));
        let credential = credential(11);
        let portable = app_data.join("portable.tcbcred");
        let backup = app_data.join("backup.tcbcred");
        ok(backup_voter_credential_to_path_v1(
            &credential,
            &portable,
            PASSPHRASE,
        ));

        let (imported, container) = ok(import_voter_credential_from_path_v1(&portable, PASSPHRASE));
        assert_eq!(
            ok(imported.public_key_bytes()),
            ok(credential.public_key_bytes())
        );
        let summary = ok(copy_validated_voter_credential_to_default_v1(
            &credentials_dir,
            &container,
        ));
        let default_path = default_voter_credential_path_v1(
            &credentials_dir,
            &parse_public_governance_key_hex_v1(&summary.public_governance_key_hex)
                .expect("summary public key"),
        );
        assert_eq!(
            ok(std::fs::read(&default_path)),
            ok(std::fs::read(&portable))
        );

        ok(backup_voter_credential_to_path_v1(
            &imported,
            &backup,
            "backup passphrase",
        ));
        assert_eq!(
            ok(read_voter_credential_container_v1(&backup)).public_key_bytes(),
            ok(credential.public_key_bytes())
        );
        assert_ne!(ok(std::fs::read(&default_path)), ok(std::fs::read(&backup)));
        assert!(default_path.exists());
    }

    #[test]
    fn delete_saved_targets_only_the_default_file_for_the_public_key() {
        let app_data = TestDir::new("delete");
        let credentials_dir = voter_credentials_directory_v1(app_data.path());
        ok(ensure_voter_credentials_directory_v1(&credentials_dir));
        let credential = credential(13);
        let public_key = ok(credential.public_key_bytes());
        ok(write_new_durable_voter_credential_v1(
            &credentials_dir,
            &credential,
            PASSPHRASE,
        ));
        let unrelated = credentials_dir.join("credential-unrelated.tcbcred");
        ok(std::fs::write(&unrelated, b"not matching"));

        let deleted = ok(delete_saved_voter_credential_v1(
            &credentials_dir,
            &public_key,
        ));

        assert!(deleted.deleted);
        assert!(!default_voter_credential_path_v1(&credentials_dir, &public_key).exists());
        assert!(unrelated.exists());
        let deleted_again = ok(delete_saved_voter_credential_v1(
            &credentials_dir,
            &public_key,
        ));
        assert!(!deleted_again.deleted);
    }

    #[test]
    fn symlink_entries_are_not_listed_where_platform_testable() {
        let app_data = TestDir::new("symlink");
        let credentials_dir = voter_credentials_directory_v1(app_data.path());
        ok(ensure_voter_credentials_directory_v1(&credentials_dir));
        let credential = credential(17);
        let public_key = ok(credential.public_key_bytes());
        let target = app_data.join("target.tcbcred");
        ok(backup_voter_credential_to_path_v1(
            &credential,
            &target,
            PASSPHRASE,
        ));
        let link = default_voter_credential_path_v1(&credentials_dir, &public_key);

        if create_file_symlink(&target, &link).is_ok() {
            let listed = ok(list_saved_voter_credentials_v1(&credentials_dir));
            assert_eq!(listed.saved_credential_count, 0);
            assert_eq!(listed.skipped_invalid_count, 1);
        }
    }

    fn credential(scalar: u64) -> VoterGovernanceCredentialV1 {
        ok(VoterGovernanceCredentialV1::from_canonical_scalar_v1(
            Zeroizing::new(Scalar::from(scalar).to_bytes()),
        ))
    }

    fn ok<T, E: core::fmt::Debug>(result: Result<T, E>) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error:?}"),
        }
    }

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "gui-core-credential-store-{}-{label}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            if let Err(error) = std::fs::create_dir_all(&path) {
                panic!("test temp dir must be creatable: {error}");
            }
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn join(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[cfg(unix)]
    fn create_file_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn create_file_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::windows::fs::symlink_file(target, link)
    }
}
