//! Conservative protocol resource limits.

/// Maximum size of one canonical protocol object.
pub const MAX_CANONICAL_OBJECT_BYTES: usize = 1_048_576;

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
