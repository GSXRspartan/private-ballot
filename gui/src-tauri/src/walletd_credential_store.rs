//! OS-backed secure credential storage for the walletd API key.
//!
//! # Boundary contract
//!
//! * The raw walletd API key never crosses the frontend/backend boundary as
//!   a return value from any command. Frontend actions are `connect` (send
//!   once), `reconnect` (send once), `forget`, and a `status` query that
//!   returns only presence / metadata — never the secret.
//! * On Windows the backing store is the user's Credential Manager (DPAPI).
//!   On macOS it is the Keychain. On Linux it is the Secret Service.
//! * The key is scoped by a fixed service name so it is trivially discoverable
//!   in the OS UI and revocable there.
//! * `WALLETD_AUTH_TOKEN` remains as a development / CI fallback only; the
//!   normal product path is the OS-backed store.
//! * Every buffer holding raw key material is `Zeroizing` so its heap
//!   allocation is wiped on drop. Errors never include the secret.

use std::fmt;

use keyring::Entry;
use tari_cc_private_ballot_ootle_anchor_app::WALLETD_AUTH_TOKEN_ENV_VAR_V1;
use zeroize::Zeroizing;

/// OS credential-store service name for the walletd API key. Stable so the
/// user can see and revoke it in Credential Manager / Keychain / Secret
/// Service by name.
const SERVICE_NAME: &str = "tari-private-ballot";

/// OS credential-store account/username label. Encodes the endpoint the
/// key belongs to so multiple credentials can coexist in future without
/// churn.
const ACCOUNT_LABEL: &str = "walletd@127.0.0.1:5100";

/// Minimum acceptable length for the walletd API key (`tw_` + 43 base64
/// chars = 46). The store rejects anything shorter as almost certainly a
/// paste error rather than a real key. It does NOT enforce the `tw_`
/// prefix because a future walletd may change the prefix.
const MIN_KEY_LENGTH: usize = 46;

/// Maximum acceptable length. A real walletd API key is exactly 46 chars;
/// this cap is a generous safety valve against paste-bombs.
const MAX_KEY_LENGTH: usize = 512;

/// Bounded error kinds returned by the credential store. Errors never
/// contain the raw key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletdCredentialStoreError {
    /// The store is not usable on this host (no OS credential service).
    Unavailable,
    /// The submitted key is empty, too short, or too long — clearly wrong.
    InvalidKey,
    /// The store returned an unexpected failure.
    StoreFailure,
}

impl fmt::Display for WalletdCredentialStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("os credential store unavailable"),
            Self::InvalidKey => f.write_str("walletd api key is not a valid tari walletd key"),
            Self::StoreFailure => f.write_str("os credential store rejected the request"),
        }
    }
}

impl std::error::Error for WalletdCredentialStoreError {}

/// Public presence/metadata for one walletd credential. The raw key is
/// never included.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WalletdCredentialStatusV1 {
    /// True when a credential is present in OS-backed storage.
    pub stored: bool,
    /// True when the development-only `WALLETD_AUTH_TOKEN` env var is set.
    /// Frontend uses this only to show a diagnostic hint. The env var is
    /// NOT the normal product path.
    pub env_fallback_present: bool,
    /// Human-readable label of where the credential lives, for advanced
    /// diagnostics. Never the credential itself.
    pub store_label: &'static str,
    /// The env var name the shell reads as a dev/CI fallback, for
    /// diagnostics.
    pub env_var_name: &'static str,
}

fn entry() -> Result<Entry, WalletdCredentialStoreError> {
    Entry::new(SERVICE_NAME, ACCOUNT_LABEL)
        .map_err(|_| WalletdCredentialStoreError::Unavailable)
}

/// Validates one candidate walletd API key. Returns the trimmed key on
/// success. The raw key never appears in the returned error.
fn validate_candidate(raw: &str) -> Result<Zeroizing<String>, WalletdCredentialStoreError> {
    let trimmed = raw.trim();
    let len = trimmed.len();
    if !(MIN_KEY_LENGTH..=MAX_KEY_LENGTH).contains(&len) {
        return Err(WalletdCredentialStoreError::InvalidKey);
    }
    if trimmed
        .bytes()
        .any(|b| !(b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
    {
        return Err(WalletdCredentialStoreError::InvalidKey);
    }
    Ok(Zeroizing::new(trimmed.to_owned()))
}

/// Stores or replaces the walletd API key. Called from the `connect` and
/// `reconnect` Tauri commands after a successful walletd validation.
pub fn store(raw_key: &str) -> Result<(), WalletdCredentialStoreError> {
    let key = validate_candidate(raw_key)?;
    let entry = entry()?;
    entry
        .set_password(key.as_str())
        .map_err(|_| WalletdCredentialStoreError::StoreFailure)
}

/// Loads the walletd API key from OS-backed storage, falling back to the
/// development env var if the store has none. Returns `Ok(None)` when
/// neither source has a credential.
pub fn load() -> Result<Option<Zeroizing<String>>, WalletdCredentialStoreError> {
    match entry() {
        Ok(entry) => match entry.get_password() {
            Ok(secret) => Ok(Some(Zeroizing::new(secret))),
            Err(keyring::Error::NoEntry) => Ok(load_env_fallback()),
            Err(_) => Err(WalletdCredentialStoreError::StoreFailure),
        },
        Err(WalletdCredentialStoreError::Unavailable) => Ok(load_env_fallback()),
        Err(other) => Err(other),
    }
}

/// Removes the walletd API key from OS-backed storage. Removing a
/// credential that does not exist is a success (idempotent).
pub fn forget() -> Result<(), WalletdCredentialStoreError> {
    let entry = entry()?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Err(WalletdCredentialStoreError::StoreFailure),
    }
}

/// Returns bounded presence/metadata about the walletd credential. Never
/// returns the raw key.
pub fn status() -> WalletdCredentialStatusV1 {
    let stored = match entry() {
        Ok(entry) => matches!(entry.get_password(), Ok(_)),
        Err(_) => false,
    };
    WalletdCredentialStatusV1 {
        stored,
        env_fallback_present: std::env::var_os(WALLETD_AUTH_TOKEN_ENV_VAR_V1).is_some(),
        store_label: if cfg!(windows) {
            "Windows Credential Manager"
        } else if cfg!(target_os = "macos") {
            "macOS Keychain"
        } else {
            "Secret Service"
        },
        env_var_name: WALLETD_AUTH_TOKEN_ENV_VAR_V1,
    }
}

fn load_env_fallback() -> Option<Zeroizing<String>> {
    std::env::var(WALLETD_AUTH_TOKEN_ENV_VAR_V1)
        .ok()
        .map(Zeroizing::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_and_short_keys() {
        assert_eq!(store(""), Err(WalletdCredentialStoreError::InvalidKey));
        assert_eq!(
            store("tw_short"),
            Err(WalletdCredentialStoreError::InvalidKey)
        );
    }

    #[test]
    fn rejects_non_urlsafe_bytes() {
        let bad = format!("tw_{}", "!".repeat(44));
        assert_eq!(store(&bad), Err(WalletdCredentialStoreError::InvalidKey));
    }
}
