//! Narrow server-side authority-signing boundary for release artifacts.
//!
//! The signer deliberately accepts only already-domain-separated canonical
//! payload bytes. Implementations never expose their private material; a future
//! HSM or remote signer can implement the same trait without changing artifact
//! schemas or Desktop verification rules.

use ed25519_dalek::{Signer, SigningKey};

/// Stable failure class for authority signing configuration or operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthoritySignerError {
    InvalidKeyId,
    KeyDoesNotMatchConfiguredRoot,
    SigningUnavailable,
}

/// Minimal authority capability used by Hosted artifact issuance.
pub trait AuthoritySigner: Send + Sync {
    /// Configured, rotation-capable public authority identifier.
    fn key_id(&self) -> &str;
    /// Public key corresponding to the configured verification root.
    fn public_key(&self) -> [u8; 32];
    /// Signs canonical bytes that the caller has already domain-separated.
    fn sign_canonical(&self, canonical_payload: &[u8]) -> Result<[u8; 64], AuthoritySignerError>;
}

/// Release implementation backed by an operator-supplied server-side Ed25519
/// key. The key is intentionally private to this module and has no accessor.
pub struct LocalEd25519AuthoritySigner {
    key_id: String,
    signing_key: SigningKey,
}

impl LocalEd25519AuthoritySigner {
    /// Constructs a signer only when its public half matches the configured
    /// authority root. This is the fail-closed configuration join point.
    pub fn new(
        key_id: String,
        signing_key_bytes: [u8; 32],
        configured_public_key: [u8; 32],
    ) -> Result<Self, AuthoritySignerError> {
        if key_id.is_empty() || key_id.len() > 256 {
            return Err(AuthoritySignerError::InvalidKeyId);
        }
        let signing_key = SigningKey::from_bytes(&signing_key_bytes);
        if signing_key.verifying_key().to_bytes() != configured_public_key {
            return Err(AuthoritySignerError::KeyDoesNotMatchConfiguredRoot);
        }
        Ok(Self {
            key_id,
            signing_key,
        })
    }
}

impl AuthoritySigner for LocalEd25519AuthoritySigner {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    fn sign_canonical(&self, canonical_payload: &[u8]) -> Result<[u8; 64], AuthoritySignerError> {
        Ok(self.signing_key.sign(canonical_payload).to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthoritySigner, AuthoritySignerError, LocalEd25519AuthoritySigner};
    use ed25519_dalek::{SigningKey, VerifyingKey};

    #[test]
    fn local_signer_refuses_a_key_that_does_not_match_the_pinned_root() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let result = LocalEd25519AuthoritySigner::new(
            "release-root-2026".to_owned(),
            key.to_bytes(),
            [8; 32],
        );
        assert_eq!(result.err(), Some(AuthoritySignerError::KeyDoesNotMatchConfiguredRoot));
    }

    #[test]
    fn local_signer_exposes_only_public_identity_and_a_signature() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let signer = LocalEd25519AuthoritySigner::new(
            "release-root-2026".to_owned(),
            key.to_bytes(),
            key.verifying_key().to_bytes(),
        )
        .expect("matching root");
        let payload = b"private-ballot/authority-artifact/v1\0canonical";
        let signature = signer.sign_canonical(payload).expect("signature");
        let verifier = VerifyingKey::from_bytes(&signer.public_key()).expect("public key");
        verifier.verify_strict(payload, &ed25519_dalek::Signature::from_bytes(&signature))
            .expect("signature verifies");
    }
}
