//! Authentication and secret boundary (Section I).
//!
//! The confirmed walletd JSON-RPC client accepts an optional bearer JWT
//! (`EncodedJwtString`, a `Zeroizing<String>`) for authentication. The indexer
//! REST client has no authentication support.
//!
//! [`WalletdAuthSecret`] is a bounded secret-reference type: its `Debug` output
//! is redacted, it is not persisted in lifecycle snapshots, it is not included
//! in evidence logs, and it does not derive `PartialEq` or `Hash` over the raw
//! credential. The raw token is reachable only through a `pub(crate)` accessor
//! used to construct the pinned `WalletDaemonClient`.

use core::fmt;

use tari_ootle_walletd_client::types::EncodedJwtString;

/// Rejection categories for a walletd auth secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletdAuthSecretError {
    /// The token was empty.
    Empty,
    /// The token contained a control character or whitespace.
    ForbiddenCharacter,
    /// The token exceeded the bounded maximum length.
    TooLong,
}

impl WalletdAuthSecretError {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "AUTH_SECRET_EMPTY",
            Self::ForbiddenCharacter => "AUTH_SECRET_FORBIDDEN_CHARACTER",
            Self::TooLong => "AUTH_SECRET_TOO_LONG",
        }
    }
}

impl fmt::Display for WalletdAuthSecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for WalletdAuthSecretError {}

/// Maximum byte length of a bearer token.
const MAX_AUTH_SECRET_BYTES: usize = 4096;

/// Bounded bearer-token reference for walletd authentication.
///
/// The token is a JWT or API key supplied by a human operator. It is never a
/// private key, mnemonic, or signing secret. Its `Debug` output is fully
/// redacted so it cannot leak into logs. It does not derive `PartialEq` or
/// `Hash` over the raw credential, and it is never persisted in a lifecycle
/// snapshot or evidence report.
pub struct WalletdAuthSecret {
    token: String,
}

impl WalletdAuthSecret {
    /// Validates and freezes a bearer token.
    ///
    /// # Errors
    ///
    /// Returns [`WalletdAuthSecretError::Empty`] if the token is empty,
    /// [`WalletdAuthSecretError::ForbiddenCharacter`] if it contains a control
    /// or whitespace character, or [`WalletdAuthSecretError::TooLong`] if it
    /// exceeds 4096 bytes.
    pub fn new(token: String) -> Result<Self, WalletdAuthSecretError> {
        if token.is_empty() {
            return Err(WalletdAuthSecretError::Empty);
        }
        if token.len() > MAX_AUTH_SECRET_BYTES {
            return Err(WalletdAuthSecretError::TooLong);
        }
        if token.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(WalletdAuthSecretError::ForbiddenCharacter);
        }
        Ok(Self { token })
    }

    /// Returns the raw token for constructing the pinned `WalletDaemonClient`.
    ///
    /// This is `pub(crate)` so the raw credential never crosses the public API
    /// boundary. The returned `EncodedJwtString` is zeroized on drop.
    pub(crate) fn as_jwt_string(&self) -> EncodedJwtString {
        self.token.clone().into()
    }
}

impl Clone for WalletdAuthSecret {
    fn clone(&self) -> Self {
        Self {
            token: self.token.clone(),
        }
    }
}

impl fmt::Debug for WalletdAuthSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WalletdAuthSecret(<redacted>)")
    }
}
