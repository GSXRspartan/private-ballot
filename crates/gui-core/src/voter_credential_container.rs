//! Durable encrypted voter governance credential containers.
//!
//! This module stores one reusable voter governance credential, not a Tari
//! wallet seed. The credential is election-independent: election binding and
//! duplicate-vote prevention remain Triptych verifier/nullifier concerns.
//!
//! Passphrases are accepted as arbitrary Unicode and normalized to NFC before
//! Argon2id input. This normalization applies only to the passphrase. It never
//! changes credential scalar bytes, public governance keys, election data, or
//! proposal-question rules.

use core::fmt;
use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::rand_core::{OsRng, RngCore};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use tari_cc_private_ballot_crypto::{RISTRETTO_COMPRESSED_POINT_BYTES, RistrettoPublicKeyV1};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::error::GuiCoreError;
use crate::hex::to_lower_hex;
use crate::voter_credential::VoterGovernanceCredentialV1;

#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};

/// Stable application magic for V1 voter credential containers.
pub const VOTER_CREDENTIAL_CONTAINER_V1_MAGIC: [u8; 8] = *b"TCB-CRED";
/// Fixed V1 binary container version.
pub const VOTER_CREDENTIAL_CONTAINER_V1_FORMAT_VERSION: u16 = 1;
/// Fixed V1 KDF identifier: Argon2id.
pub const VOTER_CREDENTIAL_CONTAINER_V1_KDF_ID_ARGON2ID: u8 = 1;
/// Fixed V1 AEAD identifier: XChaCha20-Poly1305.
pub const VOTER_CREDENTIAL_CONTAINER_V1_AEAD_ID_XCHACHA20_POLY1305: u8 = 1;
/// Fixed V1 Argon2id memory cost, in MiB.
pub const VOTER_CREDENTIAL_CONTAINER_V1_KDF_MEMORY_MIB: u32 = 64;
/// Fixed V1 Argon2id time cost.
pub const VOTER_CREDENTIAL_CONTAINER_V1_KDF_TIME_COST: u32 = 3;
/// Fixed V1 Argon2id parallelism.
pub const VOTER_CREDENTIAL_CONTAINER_V1_KDF_PARALLELISM: u32 = 4;
/// Fixed V1 salt length.
pub const VOTER_CREDENTIAL_CONTAINER_V1_SALT_BYTES: usize = 16;
/// Fixed V1 XChaCha20-Poly1305 nonce length.
pub const VOTER_CREDENTIAL_CONTAINER_V1_NONCE_BYTES: usize = 24;
/// Fixed V1 plaintext length: one canonical Triptych scalar.
pub const VOTER_CREDENTIAL_CONTAINER_V1_PLAINTEXT_BYTES: usize = RISTRETTO_COMPRESSED_POINT_BYTES;
/// Fixed V1 ciphertext length: 32-byte ciphertext + 16-byte Poly1305 tag.
pub const VOTER_CREDENTIAL_CONTAINER_V1_CIPHERTEXT_AND_TAG_BYTES: usize =
    VOTER_CREDENTIAL_CONTAINER_V1_PLAINTEXT_BYTES + 16;
/// Fixed V1 authenticated header length.
pub const VOTER_CREDENTIAL_CONTAINER_V1_HEADER_BYTES: usize = PUBLIC_KEY_OFFSET + 32;
/// Exact V1 container byte length.
pub const VOTER_CREDENTIAL_CONTAINER_V1_BYTES: usize = VOTER_CREDENTIAL_CONTAINER_V1_HEADER_BYTES
    + VOTER_CREDENTIAL_CONTAINER_V1_CIPHERTEXT_AND_TAG_BYTES;

const VERSION_OFFSET: usize = 8;
const KDF_ID_OFFSET: usize = VERSION_OFFSET + 2;
const AEAD_ID_OFFSET: usize = KDF_ID_OFFSET + 1;
const KDF_MEM_OFFSET: usize = AEAD_ID_OFFSET + 1;
const KDF_TIME_OFFSET: usize = KDF_MEM_OFFSET + 4;
const KDF_PARALLELISM_OFFSET: usize = KDF_TIME_OFFSET + 4;
const SALT_OFFSET: usize = KDF_PARALLELISM_OFFSET + 4;
const NONCE_OFFSET: usize = SALT_OFFSET + VOTER_CREDENTIAL_CONTAINER_V1_SALT_BYTES;
const PUBLIC_KEY_OFFSET: usize = NONCE_OFFSET + VOTER_CREDENTIAL_CONTAINER_V1_NONCE_BYTES;
const CIPHERTEXT_OFFSET: usize = VOTER_CREDENTIAL_CONTAINER_V1_HEADER_BYTES;
const ARGON2_MEMORY_KIB: u32 = VOTER_CREDENTIAL_CONTAINER_V1_KDF_MEMORY_MIB * 1024;
const DERIVED_KEY_BYTES: usize = 32;

#[cfg(test)]
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// One strict fixed-layout encrypted voter governance credential container.
///
/// The serialized form is exactly [`VOTER_CREDENTIAL_CONTAINER_V1_BYTES`]
/// bytes. It contains public format metadata, a public governance key, a random
/// salt and nonce, and authenticated ciphertext. It does not contain an
/// election ID, manifest hash, voter name, registry index, wallet seed, or
/// plaintext credential scalar.
pub struct VoterCredentialContainerV1 {
    bytes: [u8; VOTER_CREDENTIAL_CONTAINER_V1_BYTES],
}

impl VoterCredentialContainerV1 {
    /// Encrypts one voter governance credential into a V1 container.
    pub fn encrypt(
        credential: &VoterGovernanceCredentialV1,
        passphrase: &str,
    ) -> Result<Self, GuiCoreError> {
        let public_key = credential.public_key_bytes()?;
        credential
            .secret_key()
            .with_credential_container_secret_bytes_v1(|secret_bytes| {
                encrypt_secret_bytes_v1(secret_bytes, public_key, passphrase)
            })
            .map_err(|_| GuiCoreError::credential_unlock_failed())?
    }

    /// Strictly parses a V1 container from bytes without running Argon2.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GuiCoreError> {
        parse_header(bytes)?;
        let container_bytes: [u8; VOTER_CREDENTIAL_CONTAINER_V1_BYTES] = bytes
            .try_into()
            .map_err(|_| GuiCoreError::credential_container_framing())?;
        Ok(Self {
            bytes: container_bytes,
        })
    }

    /// Decrypts and reconstructs the voter governance credential.
    pub fn decrypt(&self, passphrase: &str) -> Result<VoterGovernanceCredentialV1, GuiCoreError> {
        let header = parse_header(&self.bytes)?;
        let key = derive_key(passphrase, &header.salt)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key[..]));
        let mut plaintext = Zeroizing::new(self.bytes[CIPHERTEXT_OFFSET..].to_vec());

        cipher
            .decrypt_in_place(
                XNonce::from_slice(&header.nonce),
                &self.bytes[..VOTER_CREDENTIAL_CONTAINER_V1_HEADER_BYTES],
                &mut *plaintext,
            )
            .map_err(|_| GuiCoreError::credential_unlock_failed())?;

        if plaintext.len() != VOTER_CREDENTIAL_CONTAINER_V1_PLAINTEXT_BYTES {
            return Err(GuiCoreError::credential_unlock_failed());
        }

        let mut secret_bytes = Zeroizing::new([0_u8; RISTRETTO_COMPRESSED_POINT_BYTES]);
        secret_bytes.copy_from_slice(&plaintext);
        let credential = VoterGovernanceCredentialV1::from_canonical_scalar_v1(secret_bytes)?;
        let derived_public_key = credential.public_key_bytes()?;

        if derived_public_key != header.public_key {
            return Err(GuiCoreError::credential_public_key_mismatch());
        }

        Ok(credential)
    }

    /// Returns the exact serialized encrypted container bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the public governance key recorded in the authenticated header.
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; RISTRETTO_COMPRESSED_POINT_BYTES] {
        read_array::<32>(&self.bytes, PUBLIC_KEY_OFFSET)
    }

    /// Returns the exact serialized encrypted container bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; VOTER_CREDENTIAL_CONTAINER_V1_BYTES] {
        self.bytes
    }
}

impl fmt::Debug for VoterCredentialContainerV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VoterCredentialContainerV1([REDACTED])")
    }
}

/// Encrypts one credential for portable backup or durable local storage.
pub fn export_voter_credential_container_v1(
    credential: &VoterGovernanceCredentialV1,
    passphrase: &str,
) -> Result<VoterCredentialContainerV1, GuiCoreError> {
    VoterCredentialContainerV1::encrypt(credential, passphrase)
}

/// Imports one credential from an already parsed encrypted container.
pub fn import_voter_credential_container_v1(
    container: &VoterCredentialContainerV1,
    passphrase: &str,
) -> Result<VoterGovernanceCredentialV1, GuiCoreError> {
    container.decrypt(passphrase)
}

/// Parses and imports one credential from encrypted container bytes.
pub fn import_voter_credential_container_bytes_v1(
    bytes: &[u8],
    passphrase: &str,
) -> Result<VoterGovernanceCredentialV1, GuiCoreError> {
    VoterCredentialContainerV1::from_bytes(bytes)?.decrypt(passphrase)
}

/// Derives a default public filename from the full public governance key.
#[must_use]
pub fn default_voter_credential_filename_v1(
    public_key: &[u8; RISTRETTO_COMPRESSED_POINT_BYTES],
) -> String {
    format!("credential-{}.tcbcred", to_lower_hex(public_key))
}

/// Writes an encrypted credential container to a fresh path.
///
/// The helper receives an explicit path from its caller. It does not choose an
/// app-data directory. Bytes are written to a temporary sibling file opened
/// with create-new semantics, flushed, `sync_all`-ed, closed, and atomically
/// persisted with no-clobber finalization. Existing destinations are rejected
/// by default.
pub fn write_voter_credential_container_v1(
    path: &Path,
    container: &VoterCredentialContainerV1,
) -> Result<(), GuiCoreError> {
    write_container_bytes_inner(path, container.as_bytes(), false)
}

/// Reads and strictly parses an encrypted credential container from a file.
pub fn read_voter_credential_container_v1(
    path: &Path,
) -> Result<VoterCredentialContainerV1, GuiCoreError> {
    let metadata = reject_existing_path_for_read(path)?;
    if metadata.len() != VOTER_CREDENTIAL_CONTAINER_V1_BYTES as u64 {
        return Err(GuiCoreError::credential_container_framing());
    }
    let bytes =
        std::fs::read(path).map_err(|_| GuiCoreError::io_failure("credential-container"))?;
    VoterCredentialContainerV1::from_bytes(&bytes)
}

fn encrypt_secret_bytes_v1(
    secret_bytes: &[u8; RISTRETTO_COMPRESSED_POINT_BYTES],
    public_key: [u8; RISTRETTO_COMPRESSED_POINT_BYTES],
    passphrase: &str,
) -> Result<VoterCredentialContainerV1, GuiCoreError> {
    let mut salt = [0_u8; VOTER_CREDENTIAL_CONTAINER_V1_SALT_BYTES];
    let mut nonce = [0_u8; VOTER_CREDENTIAL_CONTAINER_V1_NONCE_BYTES];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    encrypt_secret_bytes_with_salt_nonce_v1(secret_bytes, public_key, passphrase, salt, nonce)
}

fn encrypt_secret_bytes_with_salt_nonce_v1(
    secret_bytes: &[u8; RISTRETTO_COMPRESSED_POINT_BYTES],
    public_key: [u8; RISTRETTO_COMPRESSED_POINT_BYTES],
    passphrase: &str,
    salt: [u8; VOTER_CREDENTIAL_CONTAINER_V1_SALT_BYTES],
    nonce: [u8; VOTER_CREDENTIAL_CONTAINER_V1_NONCE_BYTES],
) -> Result<VoterCredentialContainerV1, GuiCoreError> {
    RistrettoPublicKeyV1::from_bytes(&public_key)
        .map_err(|_| GuiCoreError::credential_container_framing())?;

    let mut bytes = [0_u8; VOTER_CREDENTIAL_CONTAINER_V1_BYTES];
    write_header(&mut bytes, salt, nonce, public_key);

    let key = derive_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key[..]));
    let mut plaintext = Zeroizing::new(Vec::with_capacity(
        VOTER_CREDENTIAL_CONTAINER_V1_CIPHERTEXT_AND_TAG_BYTES,
    ));
    plaintext.extend_from_slice(secret_bytes);

    cipher
        .encrypt_in_place(
            XNonce::from_slice(&nonce),
            &bytes[..VOTER_CREDENTIAL_CONTAINER_V1_HEADER_BYTES],
            &mut *plaintext,
        )
        .map_err(|_| GuiCoreError::credential_encryption_failed())?;

    if plaintext.len() != VOTER_CREDENTIAL_CONTAINER_V1_CIPHERTEXT_AND_TAG_BYTES {
        return Err(GuiCoreError::credential_encryption_failed());
    }

    bytes[CIPHERTEXT_OFFSET..].copy_from_slice(&plaintext);

    Ok(VoterCredentialContainerV1 { bytes })
}

fn write_header(
    bytes: &mut [u8; VOTER_CREDENTIAL_CONTAINER_V1_BYTES],
    salt: [u8; VOTER_CREDENTIAL_CONTAINER_V1_SALT_BYTES],
    nonce: [u8; VOTER_CREDENTIAL_CONTAINER_V1_NONCE_BYTES],
    public_key: [u8; RISTRETTO_COMPRESSED_POINT_BYTES],
) {
    bytes[..8].copy_from_slice(&VOTER_CREDENTIAL_CONTAINER_V1_MAGIC);
    bytes[VERSION_OFFSET..KDF_ID_OFFSET]
        .copy_from_slice(&VOTER_CREDENTIAL_CONTAINER_V1_FORMAT_VERSION.to_le_bytes());
    bytes[KDF_ID_OFFSET] = VOTER_CREDENTIAL_CONTAINER_V1_KDF_ID_ARGON2ID;
    bytes[AEAD_ID_OFFSET] = VOTER_CREDENTIAL_CONTAINER_V1_AEAD_ID_XCHACHA20_POLY1305;
    bytes[KDF_MEM_OFFSET..KDF_TIME_OFFSET]
        .copy_from_slice(&VOTER_CREDENTIAL_CONTAINER_V1_KDF_MEMORY_MIB.to_le_bytes());
    bytes[KDF_TIME_OFFSET..KDF_PARALLELISM_OFFSET]
        .copy_from_slice(&VOTER_CREDENTIAL_CONTAINER_V1_KDF_TIME_COST.to_le_bytes());
    bytes[KDF_PARALLELISM_OFFSET..SALT_OFFSET]
        .copy_from_slice(&VOTER_CREDENTIAL_CONTAINER_V1_KDF_PARALLELISM.to_le_bytes());
    bytes[SALT_OFFSET..NONCE_OFFSET].copy_from_slice(&salt);
    bytes[NONCE_OFFSET..PUBLIC_KEY_OFFSET].copy_from_slice(&nonce);
    bytes[PUBLIC_KEY_OFFSET..CIPHERTEXT_OFFSET].copy_from_slice(&public_key);
}

fn derive_key(
    passphrase: &str,
    salt: &[u8; VOTER_CREDENTIAL_CONTAINER_V1_SALT_BYTES],
) -> Result<Zeroizing<[u8; DERIVED_KEY_BYTES]>, GuiCoreError> {
    let normalized = normalize_passphrase_nfc(passphrase);
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        VOTER_CREDENTIAL_CONTAINER_V1_KDF_TIME_COST,
        VOTER_CREDENTIAL_CONTAINER_V1_KDF_PARALLELISM,
        Some(DERIVED_KEY_BYTES),
    )
    .map_err(|_| GuiCoreError::credential_unlock_failed())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0_u8; DERIVED_KEY_BYTES]);

    argon2
        .hash_password_into(normalized.as_bytes(), salt, &mut key[..])
        .map_err(|_| GuiCoreError::credential_unlock_failed())?;

    Ok(key)
}

fn normalize_passphrase_nfc(passphrase: &str) -> Zeroizing<String> {
    Zeroizing::new(passphrase.nfc().collect())
}

struct ParsedHeader {
    salt: [u8; VOTER_CREDENTIAL_CONTAINER_V1_SALT_BYTES],
    nonce: [u8; VOTER_CREDENTIAL_CONTAINER_V1_NONCE_BYTES],
    public_key: [u8; RISTRETTO_COMPRESSED_POINT_BYTES],
}

fn parse_header(bytes: &[u8]) -> Result<ParsedHeader, GuiCoreError> {
    if bytes.len() != VOTER_CREDENTIAL_CONTAINER_V1_BYTES {
        return Err(GuiCoreError::credential_container_framing());
    }
    if bytes[..8] != VOTER_CREDENTIAL_CONTAINER_V1_MAGIC {
        return Err(GuiCoreError::credential_container_framing());
    }

    let version = u16::from_le_bytes(read_array::<2>(bytes, VERSION_OFFSET));
    if version != VOTER_CREDENTIAL_CONTAINER_V1_FORMAT_VERSION {
        return Err(GuiCoreError::credential_container_version());
    }
    if bytes[KDF_ID_OFFSET] != VOTER_CREDENTIAL_CONTAINER_V1_KDF_ID_ARGON2ID {
        return Err(GuiCoreError::credential_container_framing());
    }
    if bytes[AEAD_ID_OFFSET] != VOTER_CREDENTIAL_CONTAINER_V1_AEAD_ID_XCHACHA20_POLY1305 {
        return Err(GuiCoreError::credential_container_framing());
    }

    let memory_mib = u32::from_le_bytes(read_array::<4>(bytes, KDF_MEM_OFFSET));
    let time_cost = u32::from_le_bytes(read_array::<4>(bytes, KDF_TIME_OFFSET));
    let parallelism = u32::from_le_bytes(read_array::<4>(bytes, KDF_PARALLELISM_OFFSET));
    if memory_mib != VOTER_CREDENTIAL_CONTAINER_V1_KDF_MEMORY_MIB
        || time_cost != VOTER_CREDENTIAL_CONTAINER_V1_KDF_TIME_COST
        || parallelism != VOTER_CREDENTIAL_CONTAINER_V1_KDF_PARALLELISM
    {
        return Err(GuiCoreError::credential_container_framing());
    }

    let salt = read_array::<16>(bytes, SALT_OFFSET);
    let nonce = read_array::<24>(bytes, NONCE_OFFSET);
    let public_key = read_array::<32>(bytes, PUBLIC_KEY_OFFSET);
    RistrettoPublicKeyV1::from_bytes(&public_key)
        .map_err(|_| GuiCoreError::credential_container_framing())?;

    Ok(ParsedHeader {
        salt,
        nonce,
        public_key,
    })
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut out = [0_u8; N];
    out.copy_from_slice(&bytes[offset..offset + N]);
    out
}

fn write_container_bytes_inner(
    path: &Path,
    bytes: &[u8],
    fail_after_sync_for_test: bool,
) -> Result<(), GuiCoreError> {
    VoterCredentialContainerV1::from_bytes(bytes)?;
    reject_parent_indirection(path)?;
    reject_existing_destination(path)?;

    let mut tmp = new_temporary_sibling(path)?;
    let result = (|| -> Result<(), GuiCoreError> {
        {
            let file = tmp.as_file_mut();
            use std::io::Write;
            file.write_all(bytes)
                .map_err(|_| GuiCoreError::io_failure("credential-container"))?;
            file.flush()
                .map_err(|_| GuiCoreError::io_failure("credential-container"))?;
            file.sync_all()
                .map_err(|_| GuiCoreError::io_failure("credential-container"))?;
        }

        if fail_after_sync_for_test {
            return Err(GuiCoreError::io_failure("credential-container"));
        }

        // The pre-check rejects existing unsafe paths early; this persist call
        // is the OS-level no-clobber transition that closes the TOCTOU race.
        reject_existing_destination(path)?;
        tmp.persist_noclobber(path)
            .map(drop)
            .map_err(|error| persist_error_to_gui_error(error.error, path))
    })();

    result
}

fn new_temporary_sibling(path: &Path) -> Result<tempfile::NamedTempFile, GuiCoreError> {
    let Some(file_name) = path.file_name() else {
        return Err(GuiCoreError::credential_unsafe_path());
    };
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let mut prefix = std::ffi::OsString::from(".");
    prefix.push(file_name);
    prefix.push(".");

    tempfile::Builder::new()
        .prefix(&prefix)
        .suffix(".tmp")
        .tempfile_in(parent.unwrap_or_else(|| Path::new(".")))
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                GuiCoreError::credential_output_collision()
            } else {
                GuiCoreError::io_failure("credential-container")
            }
        })
}

fn persist_error_to_gui_error(error: std::io::Error, path: &Path) -> GuiCoreError {
    if error.kind() == std::io::ErrorKind::AlreadyExists || std::fs::symlink_metadata(path).is_ok()
    {
        GuiCoreError::credential_output_collision()
    } else {
        GuiCoreError::io_failure("credential-container")
    }
}

fn reject_parent_indirection(path: &Path) -> Result<(), GuiCoreError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }

    let metadata = std::fs::symlink_metadata(parent)
        .map_err(|_| GuiCoreError::io_failure("credential-container"))?;
    reject_path_indirection(&metadata)?;
    if !metadata.is_dir() {
        return Err(GuiCoreError::credential_unsafe_path());
    }
    Ok(())
}

fn reject_existing_destination(path: &Path) -> Result<(), GuiCoreError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            reject_path_indirection(&metadata)?;
            Err(GuiCoreError::credential_output_collision())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(GuiCoreError::io_failure("credential-container")),
    }
}

fn reject_existing_path_for_read(path: &Path) -> Result<std::fs::Metadata, GuiCoreError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            GuiCoreError::file_not_found("credential-container")
        } else {
            GuiCoreError::io_failure("credential-container")
        }
    })?;
    reject_path_indirection(&metadata)?;
    if !metadata.is_file() {
        return Err(GuiCoreError::credential_unsafe_path());
    }
    Ok(metadata)
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

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek_v4::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::thread;

    const PASSPHRASE: &str = "correct horse battery staple";

    #[test]
    fn create_container_and_parse_header() {
        let credential = credential(7);
        let container = ok(VoterCredentialContainerV1::encrypt(&credential, PASSPHRASE));
        let bytes = container.as_bytes();

        assert_eq!(bytes.len(), VOTER_CREDENTIAL_CONTAINER_V1_BYTES);
        assert_eq!(&bytes[..8], &VOTER_CREDENTIAL_CONTAINER_V1_MAGIC);
        assert_eq!(
            u16::from_le_bytes(read_array::<2>(bytes, VERSION_OFFSET)),
            VOTER_CREDENTIAL_CONTAINER_V1_FORMAT_VERSION
        );
        assert_eq!(
            bytes[KDF_ID_OFFSET],
            VOTER_CREDENTIAL_CONTAINER_V1_KDF_ID_ARGON2ID
        );
        assert_eq!(
            bytes[AEAD_ID_OFFSET],
            VOTER_CREDENTIAL_CONTAINER_V1_AEAD_ID_XCHACHA20_POLY1305
        );
        assert_eq!(
            u32::from_le_bytes(read_array::<4>(bytes, KDF_MEM_OFFSET)),
            VOTER_CREDENTIAL_CONTAINER_V1_KDF_MEMORY_MIB
        );
        assert_eq!(
            u32::from_le_bytes(read_array::<4>(bytes, KDF_TIME_OFFSET)),
            VOTER_CREDENTIAL_CONTAINER_V1_KDF_TIME_COST
        );
        assert_eq!(
            u32::from_le_bytes(read_array::<4>(bytes, KDF_PARALLELISM_OFFSET)),
            VOTER_CREDENTIAL_CONTAINER_V1_KDF_PARALLELISM
        );
        assert_eq!(container.public_key_bytes(), public_key(7));
    }

    #[test]
    fn decrypt_correct_passphrase_and_reload_public_key() {
        let credential = credential(7);
        let original_public_key = ok(credential.public_key_bytes());
        let container = ok(VoterCredentialContainerV1::encrypt(&credential, PASSPHRASE));

        let imported = ok(container.decrypt(PASSPHRASE));

        assert_eq!(ok(imported.public_key_bytes()), original_public_key);
    }

    #[test]
    fn same_secret_same_passphrase_uses_fresh_salt_and_nonce() {
        let first = ok(VoterCredentialContainerV1::encrypt(
            &credential(7),
            PASSPHRASE,
        ));
        let second = ok(VoterCredentialContainerV1::encrypt(
            &credential(7),
            PASSPHRASE,
        ));

        assert_ne!(first.as_bytes(), second.as_bytes());
        assert_ne!(
            &first.as_bytes()[SALT_OFFSET..NONCE_OFFSET],
            &second.as_bytes()[SALT_OFFSET..NONCE_OFFSET]
        );
        assert_ne!(
            &first.as_bytes()[NONCE_OFFSET..PUBLIC_KEY_OFFSET],
            &second.as_bytes()[NONCE_OFFSET..PUBLIC_KEY_OFFSET]
        );
    }

    #[test]
    fn wrong_passphrase_and_mutations_fail() {
        let container = ok(VoterCredentialContainerV1::encrypt(
            &credential(7),
            PASSPHRASE,
        ));
        assert_code(
            container.decrypt("wrong passphrase"),
            "GUI_CREDENTIAL_UNLOCK_FAILED",
        );

        let mut ciphertext_mutation = container.as_bytes().to_vec();
        ciphertext_mutation[CIPHERTEXT_OFFSET] ^= 0x01;
        let parsed = ok(VoterCredentialContainerV1::from_bytes(&ciphertext_mutation));
        assert_code(parsed.decrypt(PASSPHRASE), "GUI_CREDENTIAL_UNLOCK_FAILED");

        let mut header_mutation = container.as_bytes().to_vec();
        header_mutation[SALT_OFFSET] ^= 0x01;
        let parsed = ok(VoterCredentialContainerV1::from_bytes(&header_mutation));
        assert_code(parsed.decrypt(PASSPHRASE), "GUI_CREDENTIAL_UNLOCK_FAILED");
    }

    #[test]
    fn strict_framing_rejects_malformed_inputs_before_unlock() {
        let container = ok(VoterCredentialContainerV1::encrypt(
            &credential(7),
            PASSPHRASE,
        ));
        let bytes = container.as_bytes();

        let mut bad_magic = bytes.to_vec();
        bad_magic[0] ^= 0x01;
        assert_code(
            VoterCredentialContainerV1::from_bytes(&bad_magic),
            "GUI_CREDENTIAL_CONTAINER_FRAMING",
        );

        let mut bad_version = bytes.to_vec();
        bad_version[VERSION_OFFSET..KDF_ID_OFFSET].copy_from_slice(&2_u16.to_le_bytes());
        assert_code(
            VoterCredentialContainerV1::from_bytes(&bad_version),
            "GUI_CREDENTIAL_CONTAINER_VERSION",
        );

        let mut bad_kdf = bytes.to_vec();
        bad_kdf[KDF_ID_OFFSET] = 99;
        assert_code(
            VoterCredentialContainerV1::from_bytes(&bad_kdf),
            "GUI_CREDENTIAL_CONTAINER_FRAMING",
        );

        let mut bad_aead = bytes.to_vec();
        bad_aead[AEAD_ID_OFFSET] = 99;
        assert_code(
            VoterCredentialContainerV1::from_bytes(&bad_aead),
            "GUI_CREDENTIAL_CONTAINER_FRAMING",
        );
    }

    #[test]
    fn malicious_kdf_parameters_are_rejected_before_argon2() {
        let container = ok(VoterCredentialContainerV1::encrypt(
            &credential(7),
            PASSPHRASE,
        ));

        for (start, end, value) in [
            (KDF_MEM_OFFSET, KDF_TIME_OFFSET, u32::MAX),
            (KDF_TIME_OFFSET, KDF_PARALLELISM_OFFSET, u32::MAX),
            (KDF_PARALLELISM_OFFSET, SALT_OFFSET, u32::MAX),
            (KDF_MEM_OFFSET, KDF_TIME_OFFSET, 0),
            (KDF_TIME_OFFSET, KDF_PARALLELISM_OFFSET, 0),
            (KDF_PARALLELISM_OFFSET, SALT_OFFSET, 0),
            (KDF_MEM_OFFSET, KDF_TIME_OFFSET, 65),
            (KDF_TIME_OFFSET, KDF_PARALLELISM_OFFSET, 4),
            (KDF_PARALLELISM_OFFSET, SALT_OFFSET, 5),
        ] {
            let mut mutated = container.as_bytes().to_vec();
            mutated[start..end].copy_from_slice(&value.to_le_bytes());
            assert_code(
                VoterCredentialContainerV1::from_bytes(&mutated),
                "GUI_CREDENTIAL_CONTAINER_FRAMING",
            );
        }
    }

    #[test]
    fn truncation_trailing_and_random_bytes_are_rejected() {
        let container = ok(VoterCredentialContainerV1::encrypt(
            &credential(7),
            PASSPHRASE,
        ));
        let mut trailing = container.as_bytes().to_vec();
        trailing.push(0);
        let random = vec![0x55; VOTER_CREDENTIAL_CONTAINER_V1_BYTES];

        assert_code(
            VoterCredentialContainerV1::from_bytes(
                &container.as_bytes()[..VOTER_CREDENTIAL_CONTAINER_V1_BYTES - 1],
            ),
            "GUI_CREDENTIAL_CONTAINER_FRAMING",
        );
        assert_code(
            VoterCredentialContainerV1::from_bytes(&trailing),
            "GUI_CREDENTIAL_CONTAINER_FRAMING",
        );
        assert_code(
            VoterCredentialContainerV1::from_bytes(&random),
            "GUI_CREDENTIAL_CONTAINER_FRAMING",
        );
    }

    #[test]
    fn authenticated_plaintext_validation_rejects_bad_secret_and_public_key_mismatch() {
        let zero_plaintext = [0_u8; 32];
        let zero_container = ok(encrypt_secret_bytes_with_salt_nonce_v1(
            &zero_plaintext,
            public_key(7),
            PASSPHRASE,
            [1_u8; 16],
            [2_u8; 24],
        ));
        assert_code(
            zero_container.decrypt(PASSPHRASE),
            "GUI_CREDENTIAL_UNLOCK_FAILED",
        );

        let noncanonical_plaintext = [0xff_u8; 32];
        let noncanonical_container = ok(encrypt_secret_bytes_with_salt_nonce_v1(
            &noncanonical_plaintext,
            public_key(7),
            PASSPHRASE,
            [3_u8; 16],
            [4_u8; 24],
        ));
        assert_code(
            noncanonical_container.decrypt(PASSPHRASE),
            "GUI_CREDENTIAL_UNLOCK_FAILED",
        );

        let scalar = Scalar::from(7_u64).to_bytes();
        let mismatch = ok(encrypt_secret_bytes_with_salt_nonce_v1(
            &scalar,
            public_key(11),
            PASSPHRASE,
            [5_u8; 16],
            [6_u8; 24],
        ));
        assert_code(
            mismatch.decrypt(PASSPHRASE),
            "GUI_CREDENTIAL_PUBLIC_KEY_MISMATCH",
        );
    }

    #[test]
    fn nfc_and_equivalent_nfd_passphrases_unlock_identically() {
        let nfc = "Caf\u{e9} vote";
        let nfd = "Cafe\u{301} vote";
        let credential = credential(7);
        let public_key = ok(credential.public_key_bytes());
        let container = ok(VoterCredentialContainerV1::encrypt(&credential, nfc));

        assert_eq!(
            ok(container.decrypt(nfd).and_then(|c| c.public_key_bytes())),
            public_key
        );
    }

    #[test]
    fn plaintext_secret_and_sensitive_words_do_not_appear_in_container_or_errors() {
        let secret = Scalar::from(7_u64).to_bytes();
        let passphrase = "do not print this passphrase";
        let container = ok(VoterCredentialContainerV1::encrypt(
            &credential(7),
            passphrase,
        ));

        assert!(
            !container
                .as_bytes()
                .windows(secret.len())
                .any(|w| w == secret)
        );
        let rendered = format!("{container:?}");
        assert_eq!(rendered, "VoterCredentialContainerV1([REDACTED])");
        assert!(!rendered.contains(passphrase));

        let error = match container.decrypt("incorrect") {
            Ok(_) => panic!("wrong passphrase must fail"),
            Err(error) => error,
        };
        let error_debug = format!("{error:?}");
        let error_display = format!("{error}");
        let secret_hex = to_lower_hex(&secret);
        for rendered_error in [error_debug, error_display] {
            assert!(!rendered_error.contains(passphrase));
            assert!(!rendered_error.to_lowercase().contains(&secret_hex));
            assert!(!rendered_error.to_lowercase().contains("derived"));
            assert!(!rendered_error.to_lowercase().contains("scalar"));
        }
    }

    #[test]
    fn default_filename_uses_full_public_key_hex() {
        let public = public_key(7);
        let filename = default_voter_credential_filename_v1(&public);

        assert_eq!(
            filename,
            format!("credential-{}.tcbcred", to_lower_hex(&public))
        );
    }

    #[test]
    fn file_store_writes_reads_and_refuses_overwrite() {
        let dir = TestDir::new("credential-store-basic");
        let path = dir.join("credential.tcbcred");
        let container = ok(VoterCredentialContainerV1::encrypt(
            &credential(7),
            PASSPHRASE,
        ));

        ok(write_voter_credential_container_v1(&path, &container));
        let stored = ok(std::fs::read(&path));
        assert_eq!(stored, container.as_bytes());
        let read_back = ok(read_voter_credential_container_v1(&path));
        assert_eq!(read_back.as_bytes(), container.as_bytes());
        assert_code(
            write_voter_credential_container_v1(&path, &container),
            "GUI_CREDENTIAL_OUTPUT_COLLISION",
        );
    }

    #[test]
    fn read_rejects_non_exact_file_lengths_before_parse() {
        let dir = TestDir::new("credential-store-lengths");
        for (name, len) in [
            ("empty.tcbcred", 0_u64),
            ("short.tcbcred", 143),
            ("long.tcbcred", 145),
            ("oversized.tcbcred", 1024 * 1024),
        ] {
            let path = dir.join(name);
            let file = ok(std::fs::File::create(&path));
            ok(file.set_len(len));
            assert_code(
                read_voter_credential_container_v1(&path),
                "GUI_CREDENTIAL_CONTAINER_FRAMING",
            );
        }

        let valid_path = dir.join("valid.tcbcred");
        let container = ok(VoterCredentialContainerV1::encrypt(
            &credential(7),
            PASSPHRASE,
        ));
        ok(write_voter_credential_container_v1(&valid_path, &container));
        let read_back = ok(read_voter_credential_container_v1(&valid_path));
        assert_eq!(read_back.as_bytes(), container.as_bytes());
    }

    #[test]
    fn partial_write_failure_leaves_no_destination_and_cleans_temp() {
        let dir = TestDir::new("credential-store-failure");
        let path = dir.join("credential.tcbcred");
        let container = ok(VoterCredentialContainerV1::encrypt(
            &credential(7),
            PASSPHRASE,
        ));

        assert_code(
            write_container_bytes_inner(&path, container.as_bytes(), true),
            "GUI_IO_ERROR",
        );
        assert!(!path.exists());
        let entries = ok(std::fs::read_dir(dir.path()));
        assert_eq!(entries.count(), 0);
    }

    #[test]
    fn concurrent_double_creation_does_not_overwrite() {
        let dir = TestDir::new("credential-store-concurrent");
        let first = Arc::new(ok(VoterCredentialContainerV1::encrypt(
            &credential(7),
            PASSPHRASE,
        )));
        let second = Arc::new(ok(VoterCredentialContainerV1::encrypt(
            &credential(11),
            PASSPHRASE,
        )));
        assert_ne!(first.as_bytes(), second.as_bytes());

        let mut decrypted_winner_sample = None;
        for attempt in 0..8 {
            let path = Arc::new(dir.join(&format!("credential-{attempt}.tcbcred")));
            let first_result = spawn_writer(Arc::clone(&path), Arc::clone(&first));
            let second_result = spawn_writer(Arc::clone(&path), Arc::clone(&second));
            let results = [join_writer(first_result), join_writer(second_result)];
            let successes = results.iter().filter(|result| result.is_ok()).count();
            let collisions = results
                .iter()
                .filter(|result| {
                    matches!(result, Err(error) if error.code() == "GUI_CREDENTIAL_OUTPUT_COLLISION")
                })
                .count();

            assert_eq!(successes, 1);
            assert_eq!(collisions, 1);

            let stored = ok(std::fs::read(&*path));
            assert_eq!(stored.len(), VOTER_CREDENTIAL_CONTAINER_V1_BYTES);
            assert!(stored == first.as_bytes() || stored == second.as_bytes());
            ok(VoterCredentialContainerV1::from_bytes(&stored));
            decrypted_winner_sample.get_or_insert(stored);
        }

        let decrypted_winner_sample =
            decrypted_winner_sample.expect("at least one race attempt must store a credential");
        let winning_container = ok(VoterCredentialContainerV1::from_bytes(
            &decrypted_winner_sample,
        ));
        let winning_credential = ok(winning_container.decrypt(PASSPHRASE));
        let winning_public_key = ok(winning_credential.public_key_bytes());
        assert!(
            winning_public_key == first.public_key_bytes()
                || winning_public_key == second.public_key_bytes()
        );
    }

    #[test]
    fn unsafe_symlink_destination_is_rejected_where_platform_testable() {
        let dir = TestDir::new("credential-store-symlink");
        let target = dir.join("target.tcbcred");
        let link = dir.join("link.tcbcred");
        ok(std::fs::write(&target, b"not a credential"));

        if create_file_symlink(&target, &link).is_ok() {
            let container = ok(VoterCredentialContainerV1::encrypt(
                &credential(7),
                PASSPHRASE,
            ));
            assert_code(
                write_voter_credential_container_v1(&link, &container),
                "GUI_CREDENTIAL_UNSAFE_PATH",
            );
            assert_code(
                read_voter_credential_container_v1(&link),
                "GUI_CREDENTIAL_UNSAFE_PATH",
            );
        }
    }

    fn credential(scalar: u64) -> VoterGovernanceCredentialV1 {
        ok(VoterGovernanceCredentialV1::from_canonical_scalar_v1(
            Zeroizing::new(Scalar::from(scalar).to_bytes()),
        ))
    }

    fn public_key(scalar: u64) -> [u8; 32] {
        (RISTRETTO_BASEPOINT_POINT * Scalar::from(scalar))
            .compress()
            .to_bytes()
    }

    fn assert_code<T>(result: Result<T, GuiCoreError>, expected: &'static str) {
        match result {
            Ok(_) => panic!("expected error {expected}"),
            Err(error) => assert_eq!(error.code(), expected),
        }
    }

    fn ok<T, E: core::fmt::Debug>(result: Result<T, E>) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error:?}"),
        }
    }

    fn spawn_writer(
        path: Arc<PathBuf>,
        container: Arc<VoterCredentialContainerV1>,
    ) -> thread::JoinHandle<Result<(), GuiCoreError>> {
        thread::spawn(move || write_voter_credential_container_v1(&path, &container))
    }

    fn join_writer(
        handle: thread::JoinHandle<Result<(), GuiCoreError>>,
    ) -> Result<(), GuiCoreError> {
        match handle.join() {
            Ok(result) => result,
            Err(_) => panic!("writer thread must not panic"),
        }
    }

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(label: &str) -> Self {
            let id = TEMP_COUNTER.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!(
                "gui-core-credential-container-{}-{label}-{id}",
                std::process::id()
            ));
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
