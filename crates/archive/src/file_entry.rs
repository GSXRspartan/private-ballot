//! Canonical archive paths and domain-separated content-file digests.

use std::collections::BTreeSet;

use tari_cc_private_ballot_protocol::{
    HashDomain, HashProvider, MAX_ARCHIVE_FILES, MAX_ARCHIVE_PATH_BYTES, ProtocolError,
    ValidationCode, hash_domain_separated,
};

/// Portable canonical path relative to the root of one election archive.
///
/// Version one paths:
///
/// - use printable ASCII protocol characters only;
/// - use `/` as the only separator;
/// - are relative and contain no drive prefix;
/// - contain no empty, `.` or `..` segments;
/// - reject Windows reserved device-name segments;
/// - are compared by exact bytes for canonical ordering;
/// - are compared case-insensitively for portable collision rejection.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArchivePathV1(String);

impl ArchivePathV1 {
    /// Validates one portable archive-relative path.
    pub fn new(path: String) -> Result<Self, ProtocolError> {
        if path.is_empty() {
            return Err(ProtocolError::new(
                ValidationCode::EmptyArchivePath,
                "archive path must not be empty",
            ));
        }

        if path.len() > MAX_ARCHIVE_PATH_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "archive path exceeds the protocol size limit",
            ));
        }

        if !path.is_ascii() {
            return Err(invalid_path(
                "archive path must use the version-one portable ASCII profile",
            ));
        }

        if path.starts_with('/') || path.ends_with('/') {
            return Err(invalid_path(
                "archive path must be relative and must name a file",
            ));
        }

        if path.contains('\\') || path.contains(':') {
            return Err(invalid_path(
                "archive path must not contain a backslash or drive prefix",
            ));
        }

        if !path.bytes().all(is_allowed_path_byte) {
            return Err(invalid_path(
                "archive path contains a character outside the portable profile",
            ));
        }

        for segment in path.split('/') {
            validate_segment(segment)?;
        }

        Ok(Self(path))
    }

    /// Returns the exact canonical path text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn portable_collision_key(&self) -> String {
        self.0.to_ascii_lowercase()
    }
}

fn is_allowed_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/')
}

fn validate_segment(segment: &str) -> Result<(), ProtocolError> {
    if segment.is_empty() {
        return Err(invalid_path(
            "archive path must not contain an empty segment",
        ));
    }

    if matches!(segment, "." | "..") {
        return Err(invalid_path(
            "archive path must not contain traversal segments",
        ));
    }

    if segment.ends_with('.') {
        return Err(invalid_path("archive path segment must not end with a dot"));
    }

    let stem = match segment.find('.') {
        Some(index) => &segment[..index],
        None => segment,
    };

    let reserved_name = stem.to_ascii_uppercase();

    if is_windows_reserved_name(&reserved_name) {
        return Err(invalid_path(
            "archive path contains a reserved portable device name",
        ));
    }

    Ok(())
}

fn is_windows_reserved_name(value: &str) -> bool {
    matches!(
        value,
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

fn invalid_path(message: &'static str) -> ProtocolError {
    ProtocolError::new(ValidationCode::InvalidArchivePath, message)
}

/// Domain-separated digest of one archive content file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArchiveFileDigestV1([u8; 32]);

impl ArchiveFileDigestV1 {
    /// Wraps an already derived version-one archive-file digest.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Derives the file digest from the exact stored bytes.
    #[must_use]
    pub fn for_bytes<H: HashProvider>(provider: &H, bytes: &[u8]) -> Self {
        Self(hash_domain_separated(
            provider,
            HashDomain::ArchiveFileV1,
            bytes,
        ))
    }

    /// Returns the exact raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Verifies exact content bytes against this digest.
    pub fn verify_bytes<H: HashProvider>(
        &self,
        provider: &H,
        bytes: &[u8],
    ) -> Result<(), ProtocolError> {
        if Self::for_bytes(provider, bytes) != *self {
            return Err(ProtocolError::new(
                ValidationCode::ArchiveFileDigestMismatch,
                "archive file bytes do not match the recorded digest",
            ));
        }

        Ok(())
    }
}

/// One canonical archive path and its content-file digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveFileEntryV1 {
    path: ArchivePathV1,
    digest: ArchiveFileDigestV1,
}

impl ArchiveFileEntryV1 {
    /// Creates one entry from an already validated path and digest.
    #[must_use]
    pub const fn new(path: ArchivePathV1, digest: ArchiveFileDigestV1) -> Self {
        Self { path, digest }
    }

    /// Creates one entry by digesting the exact stored file bytes.
    #[must_use]
    pub fn for_bytes<H: HashProvider>(path: ArchivePathV1, provider: &H, bytes: &[u8]) -> Self {
        Self {
            path,
            digest: ArchiveFileDigestV1::for_bytes(provider, bytes),
        }
    }

    /// Returns the canonical archive-relative path.
    #[must_use]
    pub const fn path(&self) -> &ArchivePathV1 {
        &self.path
    }

    /// Returns the recorded domain-separated file digest.
    #[must_use]
    pub const fn digest(&self) -> ArchiveFileDigestV1 {
        self.digest
    }

    /// Verifies exact content bytes against this file entry.
    pub fn verify_bytes<H: HashProvider>(
        &self,
        provider: &H,
        bytes: &[u8],
    ) -> Result<(), ProtocolError> {
        self.digest.verify_bytes(provider, bytes)
    }
}

/// Canonically ordered, collision-free archive content-file entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveFileCatalogV1 {
    entries: Vec<ArchiveFileEntryV1>,
}

impl ArchiveFileCatalogV1 {
    /// Sorts by exact canonical path and rejects portable path collisions.
    pub fn new(mut entries: Vec<ArchiveFileEntryV1>) -> Result<Self, ProtocolError> {
        if entries.is_empty() {
            return Err(ProtocolError::new(
                ValidationCode::EmptyArchiveFileSet,
                "archive file catalog must not be empty",
            ));
        }

        if entries.len() > MAX_ARCHIVE_FILES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "archive file count exceeds the protocol limit",
            ));
        }

        entries.sort_by(|left, right| left.path.cmp(&right.path));

        let mut portable_paths = BTreeSet::new();

        for entry in &entries {
            if !portable_paths.insert(entry.path.portable_collision_key()) {
                return Err(ProtocolError::new(
                    ValidationCode::DuplicateArchivePath,
                    "archive contains duplicate or case-colliding paths",
                ));
            }
        }

        Ok(Self { entries })
    }

    /// Returns entries in canonical path-byte order.
    #[must_use]
    pub fn entries(&self) -> &[ArchiveFileEntryV1] {
        &self.entries
    }

    /// Returns the number of content files represented by the catalog.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the catalog contains no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tari_cc_private_ballot_protocol::{
        MAX_ARCHIVE_PATH_BYTES, test_only::TestOnlyDeterministicHasher,
    };

    fn path(value: &str) -> ArchivePathV1 {
        let Ok(path) = ArchivePathV1::new(value.to_owned()) else {
            panic!("test archive path must be valid");
        };

        path
    }

    fn entry(value: &str, digest_byte: u8) -> ArchiveFileEntryV1 {
        ArchiveFileEntryV1::new(path(value), ArchiveFileDigestV1::new([digest_byte; 32]))
    }

    #[test]
    fn specified_archive_paths_are_valid() {
        let valid_paths = [
            "README.md",
            "manifest.cbor",
            "candidate-manifest.json",
            "submissions/00000000.cbor",
            "relay-receipts/relay-a/00000001.cbor",
            "archive-signatures/verifier-01.sig",
            "SHA256SUMS",
        ];

        for value in valid_paths {
            assert!(ArchivePathV1::new(value.to_owned()).is_ok());
        }
    }

    #[test]
    fn empty_archive_path_is_rejected() {
        let result = ArchivePathV1::new(String::new());

        assert!(matches!(
            result,
            Err(error) if error.code() == ValidationCode::EmptyArchivePath
        ));
    }

    #[test]
    fn unsafe_or_nonportable_paths_are_rejected() {
        let invalid_paths = [
            "/manifest.cbor",
            "submissions/",
            "submissions//ballot.cbor",
            "submissions/./ballot.cbor",
            "submissions/../manifest.cbor",
            r"submissions\ballot.cbor",
            "C:manifest.cbor",
            "manifest cbor",
            "manifest?.cbor",
            "manifest.",
            "føø.cbor",
        ];

        for value in invalid_paths {
            assert!(matches!(
                ArchivePathV1::new(value.to_owned()),
                Err(error) if error.code() == ValidationCode::InvalidArchivePath
            ));
        }
    }

    #[test]
    fn portable_device_names_are_rejected_in_any_case() {
        let invalid_paths = [
            "CON",
            "con.txt",
            "submissions/AUX.cbor",
            "batches/com1.json",
            "archive-signatures/Lpt9.sig",
        ];

        for value in invalid_paths {
            assert!(matches!(
                ArchivePathV1::new(value.to_owned()),
                Err(error) if error.code() == ValidationCode::InvalidArchivePath
            ));
        }
    }

    #[test]
    fn oversized_archive_path_is_rejected() {
        let result = ArchivePathV1::new("a".repeat(MAX_ARCHIVE_PATH_BYTES + 1));

        assert!(matches!(
            result,
            Err(error) if error.code() == ValidationCode::ProtocolLimitExceeded
        ));
    }

    #[test]
    fn file_digest_is_deterministic() {
        let provider = TestOnlyDeterministicHasher;

        let first = ArchiveFileDigestV1::for_bytes(&provider, b"archive bytes");
        let second = ArchiveFileDigestV1::for_bytes(&provider, b"archive bytes");

        assert_eq!(first, second);
    }

    #[test]
    fn changed_file_bytes_change_the_digest() {
        let provider = TestOnlyDeterministicHasher;

        let first = ArchiveFileDigestV1::for_bytes(&provider, b"first");
        let second = ArchiveFileDigestV1::for_bytes(&provider, b"second");

        assert_ne!(first, second);
    }

    #[test]
    fn entry_verifies_exact_file_bytes() {
        let provider = TestOnlyDeterministicHasher;

        let entry =
            ArchiveFileEntryV1::for_bytes(path("manifest.cbor"), &provider, b"manifest bytes");

        assert!(entry.verify_bytes(&provider, b"manifest bytes").is_ok());
    }

    #[test]
    fn mismatched_file_digest_is_rejected() {
        let provider = TestOnlyDeterministicHasher;

        let entry =
            ArchiveFileEntryV1::for_bytes(path("manifest.cbor"), &provider, b"original bytes");

        assert!(matches!(
            entry.verify_bytes(&provider, b"changed bytes"),
            Err(error)
                if error.code() == ValidationCode::ArchiveFileDigestMismatch
        ));
    }

    #[test]
    fn catalog_sorts_entries_by_canonical_path() {
        let Ok(catalog) = ArchiveFileCatalogV1::new(vec![
            entry("submissions/00000000.cbor", 3),
            entry("README.md", 1),
            entry("manifest.cbor", 2),
        ]) else {
            panic!("test archive catalog must be valid");
        };

        let paths: Vec<&str> = catalog
            .entries()
            .iter()
            .map(|item| item.path().as_str())
            .collect();

        assert_eq!(
            paths,
            vec!["README.md", "manifest.cbor", "submissions/00000000.cbor",]
        );
    }

    #[test]
    fn exact_duplicate_archive_paths_are_rejected() {
        let result =
            ArchiveFileCatalogV1::new(vec![entry("manifest.cbor", 1), entry("manifest.cbor", 2)]);

        assert!(matches!(
            result,
            Err(error) if error.code() == ValidationCode::DuplicateArchivePath
        ));
    }

    #[test]
    fn case_colliding_archive_paths_are_rejected() {
        let result = ArchiveFileCatalogV1::new(vec![entry("README.md", 1), entry("readme.md", 2)]);

        assert!(matches!(
            result,
            Err(error) if error.code() == ValidationCode::DuplicateArchivePath
        ));
    }

    #[test]
    fn empty_archive_file_catalog_is_rejected() {
        let result = ArchiveFileCatalogV1::new(Vec::new());

        assert!(matches!(
            result,
            Err(error) if error.code() == ValidationCode::EmptyArchiveFileSet
        ));
    }
}
