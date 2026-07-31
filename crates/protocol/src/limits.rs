//! Conservative protocol resource limits.

/// Maximum size of one canonical protocol object.
pub const MAX_CANONICAL_OBJECT_BYTES: usize = 1_048_576;

/// Maximum number of members in the first registry format.
pub const MAX_REGISTRY_MEMBERS: usize = 4_096;

/// Maximum encoded size of one governance public key.
///
/// The selected production suite may impose a smaller exact size.
pub const MAX_GOVERNANCE_KEY_BYTES: usize = 128;
