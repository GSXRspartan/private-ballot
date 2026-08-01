//! Canonical top-level archive manifest and final archive hash.

use tari_cc_private_ballot_protocol::{
    CanonicalCborReader, CanonicalCborWriter, HashDomain, HashProvider, MAX_ARCHIVE_FILES,
    MAX_CANONICAL_OBJECT_BYTES, MAX_HASH_ALGORITHM_ID_BYTES, ManifestHash, ProtocolError,
    ValidationCode, hash_domain_separated,
};

use crate::{ArchiveFileCatalogV1, ArchiveFileDigestV1, ArchiveFileEntryV1, ArchivePathV1};

/// First top-level archive-manifest schema version.
pub const ARCHIVE_MANIFEST_VERSION_V1: u16 = 1;

/// Canonical path reserved for the archive manifest itself.
///
/// The manifest cannot list its own bytes because that would require a digest
/// that changes when inserted into the manifest.
pub const ARCHIVE_MANIFEST_CANONICAL_PATH: &str = "archive-manifest.cbor";

/// Detached signatures bind the final archive hash and therefore remain
/// outside the hash-covered content-file catalog.
pub const ARCHIVE_SIGNATURE_PATH_PREFIX: &str = "archive-signatures/";

const ARCHIVE_MANIFEST_FIELD_COUNT_V1: usize = 4;
const ARCHIVE_FILE_ENTRY_FIELD_COUNT_V1: usize = 2;

/// Final domain-separated hash of one canonical archive manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArchiveHashV1([u8; 32]);

impl ArchiveHashV1 {
    /// Wraps an already derived archive hash.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact raw archive-hash bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consumes the wrapper and returns the exact raw bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Canonical top-level manifest for the hash-covered archive content set.
///
/// This object binds:
///
/// - its own schema version;
/// - the frozen election-manifest hash;
/// - the exact hash-algorithm identifier;
/// - every content-file path and digest in canonical path order.
///
/// The manifest file itself and detached signatures are not content entries.
/// Signatures are expected to authenticate the resulting `ArchiveHashV1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveManifestV1 {
    archive_manifest_version: u16,
    election_manifest_hash: ManifestHash,
    hash_algorithm_id: String,
    files: ArchiveFileCatalogV1,
}

impl ArchiveManifestV1 {
    /// Validates and freezes one version-one archive manifest.
    pub fn new(
        archive_manifest_version: u16,
        election_manifest_hash: ManifestHash,
        hash_algorithm_id: String,
        files: ArchiveFileCatalogV1,
    ) -> Result<Self, ProtocolError> {
        if archive_manifest_version != ARCHIVE_MANIFEST_VERSION_V1 {
            return Err(ProtocolError::new(
                ValidationCode::UnsupportedProtocolVersion,
                "archive manifest does not use version one",
            ));
        }

        if hash_algorithm_id.trim().is_empty() {
            return Err(ProtocolError::new(
                ValidationCode::EmptyHashAlgorithmId,
                "archive hash-algorithm identifier must not be empty",
            ));
        }

        if hash_algorithm_id.len() > MAX_HASH_ALGORITHM_ID_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "archive hash-algorithm identifier exceeds the protocol limit",
            ));
        }

        validate_catalog_scope(&files)?;

        Ok(Self {
            archive_manifest_version,
            election_manifest_hash,
            hash_algorithm_id,
            files,
        })
    }

    /// Creates a manifest using the selected hash provider's exact identifier.
    pub fn for_provider<H: HashProvider>(
        election_manifest_hash: ManifestHash,
        files: ArchiveFileCatalogV1,
        provider: &H,
    ) -> Result<Self, ProtocolError> {
        Self::new(
            ARCHIVE_MANIFEST_VERSION_V1,
            election_manifest_hash,
            provider.algorithm_id().to_owned(),
            files,
        )
    }

    /// Returns the archive-manifest schema version.
    #[must_use]
    pub const fn archive_manifest_version(&self) -> u16 {
        self.archive_manifest_version
    }

    /// Returns the frozen election-manifest hash.
    #[must_use]
    pub const fn election_manifest_hash(&self) -> ManifestHash {
        self.election_manifest_hash
    }

    /// Returns the exact hash-algorithm identifier committed by the manifest.
    #[must_use]
    pub fn hash_algorithm_id(&self) -> &str {
        &self.hash_algorithm_id
    }

    /// Returns hash-covered content files in canonical archive-path order.
    #[must_use]
    pub const fn files(&self) -> &ArchiveFileCatalogV1 {
        &self.files
    }

    /// Encodes the complete manifest using canonical CBOR.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut writer = CanonicalCborWriter::new();

        writer.write_array_len(ARCHIVE_MANIFEST_FIELD_COUNT_V1)?;
        writer.write_unsigned(u64::from(self.archive_manifest_version));
        writer.write_byte_string(self.election_manifest_hash.as_bytes())?;
        writer.write_text_string(&self.hash_algorithm_id)?;
        writer.write_array_len(self.files.len())?;

        for entry in self.files.entries() {
            writer.write_array_len(ARCHIVE_FILE_ENTRY_FIELD_COUNT_V1)?;
            writer.write_text_string(entry.path().as_str())?;
            writer.write_byte_string(entry.digest().as_bytes())?;
        }

        let encoded = writer.into_bytes();

        if encoded.len() > MAX_CANONICAL_OBJECT_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "canonical archive manifest exceeds the protocol object limit",
            ));
        }

        Ok(encoded)
    }

    /// Strictly decodes one canonically ordered archive manifest.
    pub fn from_canonical_cbor(encoded: &[u8]) -> Result<Self, ProtocolError> {
        if encoded.len() > MAX_CANONICAL_OBJECT_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "encoded archive manifest exceeds the protocol object limit",
            ));
        }

        let mut reader = CanonicalCborReader::new(encoded);

        if reader.read_array_len()? != ARCHIVE_MANIFEST_FIELD_COUNT_V1 {
            return Err(invalid_cbor(
                "archive manifest must contain exactly four fields",
            ));
        }

        let archive_manifest_version = u16::try_from(reader.read_unsigned()?)
            .map_err(|_| invalid_cbor("archive-manifest version exceeds the integer limit"))?;

        if archive_manifest_version != ARCHIVE_MANIFEST_VERSION_V1 {
            return Err(ProtocolError::new(
                ValidationCode::UnsupportedProtocolVersion,
                "archive manifest does not use version one",
            ));
        }

        let election_manifest_hash = ManifestHash::new(read_digest(
            &mut reader,
            "election-manifest hash must contain exactly 32 bytes",
        )?);

        let hash_algorithm_id = reader.read_text_string()?.to_owned();

        if hash_algorithm_id.trim().is_empty() {
            return Err(ProtocolError::new(
                ValidationCode::EmptyHashAlgorithmId,
                "archive hash-algorithm identifier must not be empty",
            ));
        }

        if hash_algorithm_id.len() > MAX_HASH_ALGORITHM_ID_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "archive hash-algorithm identifier exceeds the protocol limit",
            ));
        }

        let file_count = reader.read_array_len()?;

        if file_count == 0 {
            return Err(ProtocolError::new(
                ValidationCode::EmptyArchiveFileSet,
                "archive manifest must contain at least one content file",
            ));
        }

        if file_count > MAX_ARCHIVE_FILES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "archive manifest file count exceeds the protocol limit",
            ));
        }

        let mut entries = Vec::with_capacity(file_count);

        for _ in 0..file_count {
            if reader.read_array_len()? != ARCHIVE_FILE_ENTRY_FIELD_COUNT_V1 {
                return Err(invalid_cbor(
                    "archive file entry must contain exactly two fields",
                ));
            }

            let path = ArchivePathV1::new(reader.read_text_string()?.to_owned())?;

            let digest = ArchiveFileDigestV1::new(read_digest(
                &mut reader,
                "archive file digest must contain exactly 32 bytes",
            )?);

            entries.push(ArchiveFileEntryV1::new(path, digest));
        }

        reader.finish()?;

        for pair in entries.windows(2) {
            if pair[0].path() > pair[1].path() {
                return Err(ProtocolError::new(
                    ValidationCode::NonCanonicalCbor,
                    "archive file entries are not in canonical path order",
                ));
            }
        }

        let files = ArchiveFileCatalogV1::new(entries)?;

        Self::new(
            archive_manifest_version,
            election_manifest_hash,
            hash_algorithm_id,
            files,
        )
    }

    /// Derives the final domain-separated archive hash.
    pub fn canonical_hash<H: HashProvider>(
        &self,
        provider: &H,
    ) -> Result<ArchiveHashV1, ProtocolError> {
        self.validate_hash_provider(provider)?;

        let encoded = self.to_canonical_cbor()?;

        Ok(ArchiveHashV1::new(hash_domain_separated(
            provider,
            HashDomain::ArchiveManifestV1,
            &encoded,
        )))
    }

    /// Verifies one expected final archive hash.
    pub fn verify_hash<H: HashProvider>(
        &self,
        provider: &H,
        expected: ArchiveHashV1,
    ) -> Result<(), ProtocolError> {
        let actual = self.canonical_hash(provider)?;

        if actual != expected {
            return Err(ProtocolError::new(
                ValidationCode::ArchiveManifestHashMismatch,
                "canonical archive manifest does not match the expected archive hash",
            ));
        }

        Ok(())
    }

    /// Verifies that a provider matches the manifest's committed algorithm ID.
    pub fn validate_hash_provider<H: HashProvider>(
        &self,
        provider: &H,
    ) -> Result<(), ProtocolError> {
        if provider.algorithm_id() != self.hash_algorithm_id {
            return Err(ProtocolError::new(
                ValidationCode::UnsupportedHashAlgorithm,
                "selected hash provider differs from the archive manifest",
            ));
        }

        Ok(())
    }
}

fn read_digest(
    reader: &mut CanonicalCborReader<'_>,
    message: &'static str,
) -> Result<[u8; 32], ProtocolError> {
    <[u8; 32]>::try_from(reader.read_byte_string()?).map_err(|_| invalid_cbor(message))
}

fn invalid_cbor(message: &'static str) -> ProtocolError {
    ProtocolError::new(ValidationCode::InvalidCbor, message)
}

fn validate_catalog_scope(files: &ArchiveFileCatalogV1) -> Result<(), ProtocolError> {
    for entry in files.entries() {
        let path = entry.path().as_str();

        if path == ARCHIVE_MANIFEST_CANONICAL_PATH {
            return Err(ProtocolError::new(
                ValidationCode::InvalidArchiveManifest,
                "archive manifest cannot include its own canonical file",
            ));
        }

        if path.starts_with(ARCHIVE_SIGNATURE_PATH_PREFIX) {
            return Err(ProtocolError::new(
                ValidationCode::InvalidArchiveManifest,
                "detached archive signatures are outside the hash-covered content catalog",
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tari_cc_private_ballot_protocol::{
        MAX_HASH_ALGORITHM_ID_BYTES, test_only::TestOnlyDeterministicHasher,
    };

    #[derive(Debug, Clone, Copy)]
    struct OtherHasher;

    impl HashProvider for OtherHasher {
        fn algorithm_id(&self) -> &'static str {
            "OTHER_TEST_HASH"
        }

        fn hash(&self, _framed_input: &[u8]) -> [u8; 32] {
            [99_u8; 32]
        }
    }

    fn path(value: &str) -> ArchivePathV1 {
        let Ok(path) = ArchivePathV1::new(value.to_owned()) else {
            panic!("test archive path must be valid");
        };

        path
    }

    fn entry(value: &str, digest_byte: u8) -> ArchiveFileEntryV1 {
        ArchiveFileEntryV1::new(path(value), ArchiveFileDigestV1::new([digest_byte; 32]))
    }

    fn catalog(values: &[(&str, u8)]) -> ArchiveFileCatalogV1 {
        let entries = values
            .iter()
            .map(|(value, digest_byte)| entry(value, *digest_byte))
            .collect();

        let Ok(catalog) = ArchiveFileCatalogV1::new(entries) else {
            panic!("test archive catalog must be valid");
        };

        catalog
    }

    fn provider_manifest(election_hash_byte: u8, values: &[(&str, u8)]) -> ArchiveManifestV1 {
        let provider = TestOnlyDeterministicHasher;

        let Ok(manifest) = ArchiveManifestV1::for_provider(
            ManifestHash::new([election_hash_byte; 32]),
            catalog(values),
            &provider,
        ) else {
            panic!("test archive manifest must be valid");
        };

        manifest
    }

    fn encoded_manifest(
        version: u64,
        election_hash: &[u8],
        hash_algorithm_id: &str,
        values: &[(&str, Vec<u8>)],
    ) -> Vec<u8> {
        let mut writer = CanonicalCborWriter::new();

        assert!(
            writer
                .write_array_len(ARCHIVE_MANIFEST_FIELD_COUNT_V1)
                .is_ok()
        );

        writer.write_unsigned(version);

        assert!(writer.write_byte_string(election_hash).is_ok());
        assert!(writer.write_text_string(hash_algorithm_id).is_ok());
        assert!(writer.write_array_len(values.len()).is_ok());

        for (path, digest) in values {
            assert!(
                writer
                    .write_array_len(ARCHIVE_FILE_ENTRY_FIELD_COUNT_V1)
                    .is_ok()
            );

            assert!(writer.write_text_string(path).is_ok());
            assert!(writer.write_byte_string(digest).is_ok());
        }

        writer.into_bytes()
    }

    #[test]
    fn archive_manifest_vector_is_exact() {
        let Ok(manifest) = ArchiveManifestV1::new(
            ARCHIVE_MANIFEST_VERSION_V1,
            ManifestHash::new([1_u8; 32]),
            "h".to_owned(),
            catalog(&[("a", 2)]),
        ) else {
            panic!("test archive manifest must be valid");
        };

        let Ok(encoded) = manifest.to_canonical_cbor() else {
            panic!("archive-manifest encoding should succeed");
        };

        let mut expected = vec![0x84, 0x01, 0x58, 0x20];
        expected.extend_from_slice(&[1_u8; 32]);
        expected.extend_from_slice(&[0x61, b'h', 0x81, 0x82, 0x61, b'a', 0x58, 0x20]);
        expected.extend_from_slice(&[2_u8; 32]);

        assert_eq!(encoded, expected);
    }

    #[test]
    fn archive_manifest_round_trip_preserves_exact_bytes() {
        let original = provider_manifest(
            1,
            &[
                ("submissions/00000000.cbor", 3),
                ("manifest.cbor", 1),
                ("registry.cbor", 2),
            ],
        );

        let Ok(encoded) = original.to_canonical_cbor() else {
            panic!("archive-manifest encoding should succeed");
        };

        let Ok(decoded) = ArchiveManifestV1::from_canonical_cbor(&encoded) else {
            panic!("archive-manifest decoding should succeed");
        };

        let Ok(reencoded) = decoded.to_canonical_cbor() else {
            panic!("archive-manifest re-encoding should succeed");
        };

        assert_eq!(decoded, original);
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn input_order_does_not_change_archive_hash() {
        let provider = TestOnlyDeterministicHasher;

        let first = provider_manifest(1, &[("registry.cbor", 2), ("manifest.cbor", 1)]);

        let second = provider_manifest(1, &[("manifest.cbor", 1), ("registry.cbor", 2)]);

        let Ok(first_hash) = first.canonical_hash(&provider) else {
            panic!("first archive hash should succeed");
        };

        let Ok(second_hash) = second.canonical_hash(&provider) else {
            panic!("second archive hash should succeed");
        };

        assert_eq!(first_hash, second_hash);
    }

    #[test]
    fn changed_file_digest_changes_archive_hash() {
        let provider = TestOnlyDeterministicHasher;
        let first = provider_manifest(1, &[("manifest.cbor", 1)]);
        let second = provider_manifest(1, &[("manifest.cbor", 2)]);

        let Ok(first_hash) = first.canonical_hash(&provider) else {
            panic!("first archive hash should succeed");
        };

        let Ok(second_hash) = second.canonical_hash(&provider) else {
            panic!("second archive hash should succeed");
        };

        assert_ne!(first_hash, second_hash);
    }

    #[test]
    fn changed_election_manifest_hash_changes_archive_hash() {
        let provider = TestOnlyDeterministicHasher;
        let first = provider_manifest(1, &[("manifest.cbor", 1)]);
        let second = provider_manifest(2, &[("manifest.cbor", 1)]);

        let Ok(first_hash) = first.canonical_hash(&provider) else {
            panic!("first archive hash should succeed");
        };

        let Ok(second_hash) = second.canonical_hash(&provider) else {
            panic!("second archive hash should succeed");
        };

        assert_ne!(first_hash, second_hash);
    }

    #[test]
    fn mismatched_hash_provider_is_rejected() {
        let manifest = provider_manifest(1, &[("manifest.cbor", 1)]);

        assert!(matches!(
            manifest.canonical_hash(&OtherHasher),
            Err(error)
                if error.code() == ValidationCode::UnsupportedHashAlgorithm
        ));
    }

    #[test]
    fn mismatched_archive_hash_is_rejected() {
        let provider = TestOnlyDeterministicHasher;
        let manifest = provider_manifest(1, &[("manifest.cbor", 1)]);

        assert!(matches!(
            manifest.verify_hash(&provider, ArchiveHashV1::new([9_u8; 32])),
            Err(error)
                if error.code()
                    == ValidationCode::ArchiveManifestHashMismatch
        ));
    }

    #[test]
    fn wrong_manifest_field_count_is_rejected() {
        let mut writer = CanonicalCborWriter::new();

        assert!(writer.write_array_len(3).is_ok());

        assert!(matches!(
            ArchiveManifestV1::from_canonical_cbor(&writer.into_bytes()),
            Err(error) if error.code() == ValidationCode::InvalidCbor
        ));
    }

    #[test]
    fn unsupported_archive_manifest_version_is_rejected() {
        let encoded = encoded_manifest(2, &[1_u8; 32], "h", &[("manifest.cbor", vec![2_u8; 32])]);

        assert!(matches!(
            ArchiveManifestV1::from_canonical_cbor(&encoded),
            Err(error)
                if error.code()
                    == ValidationCode::UnsupportedProtocolVersion
        ));
    }

    #[test]
    fn malformed_election_manifest_hash_is_rejected() {
        let encoded = encoded_manifest(1, &[1_u8; 31], "h", &[("manifest.cbor", vec![2_u8; 32])]);

        assert!(matches!(
            ArchiveManifestV1::from_canonical_cbor(&encoded),
            Err(error) if error.code() == ValidationCode::InvalidCbor
        ));
    }

    #[test]
    fn malformed_file_digest_is_rejected() {
        let encoded = encoded_manifest(1, &[1_u8; 32], "h", &[("manifest.cbor", vec![2_u8; 31])]);

        assert!(matches!(
            ArchiveManifestV1::from_canonical_cbor(&encoded),
            Err(error) if error.code() == ValidationCode::InvalidCbor
        ));
    }

    #[test]
    fn unsorted_encoded_entries_are_rejected() {
        let encoded = encoded_manifest(
            1,
            &[1_u8; 32],
            "h",
            &[
                ("registry.cbor", vec![2_u8; 32]),
                ("manifest.cbor", vec![1_u8; 32]),
            ],
        );

        assert!(matches!(
            ArchiveManifestV1::from_canonical_cbor(&encoded),
            Err(error) if error.code() == ValidationCode::NonCanonicalCbor
        ));
    }

    #[test]
    fn empty_hash_algorithm_id_is_rejected() {
        let result = ArchiveManifestV1::new(
            ARCHIVE_MANIFEST_VERSION_V1,
            ManifestHash::new([1_u8; 32]),
            String::new(),
            catalog(&[("manifest.cbor", 1)]),
        );

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::EmptyHashAlgorithmId
        ));
    }

    #[test]
    fn oversized_hash_algorithm_id_is_rejected() {
        let result = ArchiveManifestV1::new(
            ARCHIVE_MANIFEST_VERSION_V1,
            ManifestHash::new([1_u8; 32]),
            "h".repeat(MAX_HASH_ALGORITHM_ID_BYTES + 1),
            catalog(&[("manifest.cbor", 1)]),
        );

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::ProtocolLimitExceeded
        ));
    }

    #[test]
    fn self_referential_archive_manifest_path_is_rejected() {
        let result = ArchiveManifestV1::new(
            ARCHIVE_MANIFEST_VERSION_V1,
            ManifestHash::new([1_u8; 32]),
            "h".to_owned(),
            catalog(&[(ARCHIVE_MANIFEST_CANONICAL_PATH, 1)]),
        );

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::InvalidArchiveManifest
        ));
    }

    #[test]
    fn detached_signature_paths_are_rejected() {
        let result = ArchiveManifestV1::new(
            ARCHIVE_MANIFEST_VERSION_V1,
            ManifestHash::new([1_u8; 32]),
            "h".to_owned(),
            catalog(&[("archive-signatures/verifier-01.sig", 1)]),
        );

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::InvalidArchiveManifest
        ));
    }
}
