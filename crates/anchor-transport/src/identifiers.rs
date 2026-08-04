//! Bounded, opaque, project-owned identifiers for external anchor artifacts.
//!
//! Slice 4A3 confirmed that walletd exposes only opaque handles at this
//! boundary (a request identifier, and a transaction identifier that exists
//! only after sealing). This slice deliberately treats those as bounded opaque
//! UTF-8 tokens rather than pinning them to a specific Ootle binary encoding:
//! the real adapter (a later slice) owns any stronger validation.
//!
//! None of these identifiers can hold private-key material or a mnemonic: they
//! are short, whitespace-free, control-character-free bounded strings, and the
//! account reference additionally redacts its `Debug` output so it cannot leak
//! into logs.

use core::fmt;

use crate::errors::AnchorIdentifierError;

/// Maximum UTF-8 byte length of any bounded opaque identifier.
pub const MAX_ANCHOR_IDENTIFIER_BYTES: usize = 128;

/// Validates one bounded opaque identifier token.
///
/// The token must be non-empty, at most [`MAX_ANCHOR_IDENTIFIER_BYTES`] bytes,
/// and free of any control or whitespace character (which also rejects NUL,
/// newline, tab, and surrounding spaces).
fn validate_identifier(value: &str) -> Result<(), AnchorIdentifierError> {
    if value.is_empty() {
        return Err(AnchorIdentifierError::Empty);
    }

    if value.len() > MAX_ANCHOR_IDENTIFIER_BYTES {
        return Err(AnchorIdentifierError::TooLong);
    }

    if value
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(AnchorIdentifierError::ForbiddenCharacter);
    }

    Ok(())
}

/// Opaque walletd request identifier.
///
/// A request identifier is a public handle, not a secret, so its `Debug` is not
/// redacted.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AnchorRequestId(String);

impl AnchorRequestId {
    /// Validates and freezes one bounded request identifier.
    pub fn new(value: String) -> Result<Self, AnchorIdentifierError> {
        validate_identifier(&value)?;
        Ok(Self(value))
    }

    /// Returns the opaque identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Builds an identifier from an internally generated 32-byte hash.
    ///
    /// The hexadecimal encoding of a hash is always a valid identifier, so this
    /// bypasses re-validation for values the crate itself produced.
    #[must_use]
    pub(crate) fn from_trusted_hash(hash: &[u8; 32]) -> Self {
        Self(crate::payload::to_lower_hex_32(hash))
    }
}

/// Opaque sealed-transaction identifier.
///
/// Slice 4A3 confirmed the transaction identifier exists only after sealing.
/// The exact byte length is deliberately not pinned here; a later adapter slice
/// may tighten it. A transaction identifier is a public ledger handle, so its
/// `Debug` is not redacted.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AnchorTransactionId(String);

impl AnchorTransactionId {
    /// Validates and freezes one bounded transaction identifier.
    pub fn new(value: String) -> Result<Self, AnchorIdentifierError> {
        validate_identifier(&value)?;
        Ok(Self(value))
    }

    /// Returns the opaque identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Builds an identifier from an internally generated 32-byte hash.
    #[must_use]
    pub(crate) fn from_trusted_hash(hash: &[u8; 32]) -> Self {
        Self(crate::payload::to_lower_hex_32(hash))
    }
}

/// Bounded reference to the fee-paying account.
///
/// This is the account walletd would seal from. It is not a secret, but it
/// identifies a wallet account, so its `Debug` is redacted to prevent accidental
/// disclosure in logs. Human review reads the value explicitly through
/// [`Self::as_str`].
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AnchorAccountReference(String);

impl AnchorAccountReference {
    /// Validates and freezes one bounded account reference.
    pub fn new(value: String) -> Result<Self, AnchorIdentifierError> {
        validate_identifier(&value)?;
        Ok(Self(value))
    }

    /// Returns the account reference text for explicit human review.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AnchorAccountReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "AnchorAccountReference(<redacted; {} bytes>)",
            self.0.len()
        )
    }
}

/// Bounded caller idempotency reference.
///
/// An optional token a caller may supply so a repeated preparation returns the
/// same request instead of creating a duplicate. It is not sensitive.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AnchorClientReferenceV1(String);

impl AnchorClientReferenceV1 {
    /// Validates and freezes one bounded client reference.
    pub fn new(value: String) -> Result<Self, AnchorIdentifierError> {
        validate_identifier(&value)?;
        Ok(Self(value))
    }

    /// Returns the client reference text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AnchorAccountReference, AnchorClientReferenceV1, AnchorRequestId, AnchorTransactionId,
        MAX_ANCHOR_IDENTIFIER_BYTES,
    };
    use crate::errors::AnchorIdentifierError;

    #[test]
    fn valid_identifiers_are_accepted() {
        let Ok(request) = AnchorRequestId::new("req-0001".to_owned()) else {
            panic!("request identifier should be valid");
        };
        let Ok(transaction) = AnchorTransactionId::new("aa01ffbc".to_owned()) else {
            panic!("transaction identifier should be valid");
        };

        assert_eq!(request.as_str(), "req-0001");
        assert_eq!(transaction.as_str(), "aa01ffbc");
    }

    #[test]
    fn empty_identifier_is_rejected() {
        assert_eq!(
            AnchorRequestId::new(String::new()),
            Err(AnchorIdentifierError::Empty)
        );
    }

    #[test]
    fn oversized_identifier_is_rejected() {
        let value = "z".repeat(MAX_ANCHOR_IDENTIFIER_BYTES + 1);

        assert_eq!(
            AnchorTransactionId::new(value),
            Err(AnchorIdentifierError::TooLong)
        );
    }

    #[test]
    fn whitespace_and_control_characters_are_rejected() {
        for value in ["req 1", "req\t1", "req\n1", "req\0"] {
            assert_eq!(
                AnchorRequestId::new(value.to_owned()),
                Err(AnchorIdentifierError::ForbiddenCharacter)
            );
            assert_eq!(
                AnchorClientReferenceV1::new(value.to_owned()),
                Err(AnchorIdentifierError::ForbiddenCharacter)
            );
        }
    }

    #[test]
    fn account_reference_debug_is_redacted() {
        let Ok(account) = AnchorAccountReference::new("treasury-fee-account".to_owned()) else {
            panic!("account reference should be valid");
        };

        let rendered = format!("{account:?}");

        assert!(!rendered.contains("treasury"));
        assert!(rendered.contains("redacted"));
        assert_eq!(account.as_str(), "treasury-fee-account");
    }

    #[test]
    fn trusted_hash_identifiers_are_lowercase_hex() {
        let hash = [0xab_u8; 32];

        assert_eq!(AnchorRequestId::from_trusted_hash(&hash).as_str().len(), 64);
        assert!(
            AnchorTransactionId::from_trusted_hash(&hash)
                .as_str()
                .chars()
                .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
        );
    }
}
