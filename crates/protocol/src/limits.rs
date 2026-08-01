//! Conservative protocol resource limits.

/// Maximum size of one canonical protocol object.
pub const MAX_CANONICAL_OBJECT_BYTES: usize = 1_048_576;

/// Maximum UTF-8 byte length of one canonical archive-relative path.
pub const MAX_ARCHIVE_PATH_BYTES: usize = 1_024;

/// Maximum number of content-file entries in one archive manifest.
pub const MAX_ARCHIVE_FILES: usize = 65_536;

/// Maximum UTF-8 byte length of one hash-algorithm identifier.
pub const MAX_HASH_ALGORITHM_ID_BYTES: usize = 128;
/// Maximum number of members in the first registry format.
pub const MAX_REGISTRY_MEMBERS: usize = 4_096;

/// Maximum encoded size of one governance public key.
///
/// The selected production suite may impose a smaller exact size.
pub const MAX_GOVERNANCE_KEY_BYTES: usize = 128;

/// Maximum number of candidates in a version-one election.
pub const MAX_CANDIDATES: usize = 256;

/// Maximum encoded size of one stable candidate identifier.
pub const MAX_CANDIDATE_ID_BYTES: usize = 128;

/// Maximum UTF-8 byte length of one candidate display name.
pub const MAX_CANDIDATE_DISPLAY_NAME_BYTES: usize = 512;

/// Maximum encoded size of one election identifier.
pub const MAX_ELECTION_ID_BYTES: usize = 128;

/// Maximum UTF-8 byte length of a proof-suite identifier.
pub const MAX_PROOF_SUITE_ID_BYTES: usize = 128;

/// Maximum UTF-8 byte length of a governance source revision.
pub const MAX_GOVERNANCE_REVISION_BYTES: usize = 256;

/// Maximum canonical size of a version-one proof statement.
pub const MAX_PROOF_STATEMENT_BYTES: usize = 4_096;

/// Maximum UTF-8 byte length of a ballot-kind identifier.
pub const MAX_BALLOT_KIND_ID_BYTES: usize = 64;

/// Maximum UTF-8 byte length of a ballot-confidentiality identifier.
pub const MAX_BALLOT_CONFIDENTIALITY_ID_BYTES: usize = 64;

/// Maximum encoded proof size accepted by the verifier boundary.
pub const MAX_PROOF_BYTES: usize = 65_536;

/// Maximum authenticated nullifier or key-image size.
///
/// A selected production proof suite may impose a smaller exact size.
pub const MAX_NULLIFIER_BYTES: usize = 128;
