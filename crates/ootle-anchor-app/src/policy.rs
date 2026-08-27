//! Canonical, single-source live-publication policy constants.
//!
//! These values are enforced in the SHARED trusted publish layer
//! ([`crate::driver::AnchorAppDriver`]) so that every live entry point — the
//! GUI/Tauri shell, the standalone CLI binary, and any direct driver
//! invocation — is bound by the same rules. gui-core re-exports the floor so
//! there is exactly one definition and no divergent duplicate.

/// Minimum accepted-ballot floor for LIVE aggregate-anchor publication.
///
/// A public aggregate anchor over a single accepted ballot would reduce the
/// smallest possible anonymity set to one person, so live publication is
/// blocked whenever the config's explicit floor is below this value, or the
/// verified accepted cohort is below it. This mirrors the project's
/// transport-batch anonymity convention (`accepted_unique_floor = 2`).
///
/// Local commitment computation and offline archive verification are pure and
/// remain available for one-voter/synthetic fixtures; only LIVE publication is
/// gated.
pub const OOTLE_ANCHOR_PUBLISH_MIN_ACCEPTED_BALLOT_FLOOR_V1: u64 = 2;

/// The single, backend-owned environment variable name that may hold the
/// optional walletd bearer token.
///
/// The frontend/API can never choose an arbitrary environment variable name to
/// read as a bearer secret (a confused-deputy exfiltration risk): the only
/// name the shell will ever read is this one. The value is resolved by the
/// shell, never crosses the gui-core boundary, and is never persisted, logged,
/// or placed into config/snapshot/evidence/error strings.
pub const WALLETD_AUTH_TOKEN_ENV_VAR_V1: &str = "WALLETD_AUTH_TOKEN";
