//! Versioned byte envelope for the Tari Triptych prototype.
//!
//! Triptych proof serialization does not contain the statement linking tag
//! `J`. The project verifier needs both `J` and the canonical Triptych proof
//! bytes to reconstruct a statement and, after successful verification, to
//! authenticate election-scoped duplicate-detection material.
//!
//! This module defines only that byte transport boundary. It does not add the
//! Triptych dependency, implement proof verification, generate proofs, or
//! authorize production or binding-election use.

use tari_cc_private_ballot_protocol::{MAX_PROOF_BYTES, ProtocolError, ValidationCode};

use crate::{RISTRETTO_COMPRESSED_POINT_BYTES, ristretto::decode_non_identity};

/// Version of the prototype Tari Triptych proof envelope.
pub const TARI_TRIPTYCH_PROOF_ENVELOPE_VERSION_V1: u16 = 1;

/// Number of bytes before the canonical Triptych proof payload.
///
/// Layout:
///
/// - two-byte little-endian envelope version;
/// - 32-byte canonical, nonidentity compressed Ristretto linking tag;
/// - nonempty canonical Triptych proof bytes.
pub const TARI_TRIPTYCH_PROOF_ENVELOPE_HEADER_BYTES: usize = 2 + RISTRETTO_COMPRESSED_POINT_BYTES;

/// Project-owned byte envelope for one Tari Triptych prototype proof.
///
/// The type deliberately exposes no `triptych` or `curve25519-dalek` types.
/// Canonical Triptych proof parsing remains a later private-adapter step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TariTriptychProofEnvelopeV1 {
    linking_tag: [u8; RISTRETTO_COMPRESSED_POINT_BYTES],
    triptych_proof: Vec<u8>,
}

impl TariTriptychProofEnvelopeV1 {
    /// Validates and freezes one prototype proof envelope.
    pub fn new(
        linking_tag: [u8; RISTRETTO_COMPRESSED_POINT_BYTES],
        triptych_proof: Vec<u8>,
    ) -> Result<Self, ProtocolError> {
        validate_linking_tag(linking_tag)?;

        if triptych_proof.is_empty() {
            return Err(ProtocolError::new(
                ValidationCode::MalformedProof,
                "Triptych proof bytes must not be empty",
            ));
        }

        let Some(total_length) =
            TARI_TRIPTYCH_PROOF_ENVELOPE_HEADER_BYTES.checked_add(triptych_proof.len())
        else {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "Triptych proof envelope length overflowed",
            ));
        };

        if total_length > MAX_PROOF_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "Triptych proof envelope exceeds the protocol proof limit",
            ));
        }

        Ok(Self {
            linking_tag,
            triptych_proof,
        })
    }

    /// Strictly decodes one version-one proof envelope.
    pub fn from_bytes(encoded: &[u8]) -> Result<Self, ProtocolError> {
        if encoded.len() > MAX_PROOF_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "Triptych proof envelope exceeds the protocol proof limit",
            ));
        }

        if encoded.len() <= TARI_TRIPTYCH_PROOF_ENVELOPE_HEADER_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::MalformedProof,
                "Triptych proof envelope is truncated",
            ));
        }

        let version = u16::from_le_bytes([encoded[0], encoded[1]]);

        if version != TARI_TRIPTYCH_PROOF_ENVELOPE_VERSION_V1 {
            return Err(ProtocolError::new(
                ValidationCode::MalformedProof,
                "Triptych proof envelope version is unsupported",
            ));
        }

        let mut linking_tag = [0_u8; RISTRETTO_COMPRESSED_POINT_BYTES];
        linking_tag.copy_from_slice(&encoded[2..TARI_TRIPTYCH_PROOF_ENVELOPE_HEADER_BYTES]);

        Self::new(
            linking_tag,
            encoded[TARI_TRIPTYCH_PROOF_ENVELOPE_HEADER_BYTES..].to_vec(),
        )
    }

    /// Returns the canonical compressed linking-tag bytes.
    #[must_use]
    pub const fn linking_tag_bytes(&self) -> &[u8; RISTRETTO_COMPRESSED_POINT_BYTES] {
        &self.linking_tag
    }

    /// Returns the opaque canonical Triptych proof bytes.
    ///
    /// A later private adapter must parse these bytes with
    /// `TriptychProof::from_bytes`, verify the proof, and confirm canonical
    /// reserialization before creating a `VerifiedNullifier`.
    #[must_use]
    pub fn triptych_proof_bytes(&self) -> &[u8] {
        &self.triptych_proof
    }

    /// Encodes this envelope using the fixed version-one layout.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoded = Vec::new();

        encoded.extend_from_slice(&TARI_TRIPTYCH_PROOF_ENVELOPE_VERSION_V1.to_le_bytes());
        encoded.extend_from_slice(&self.linking_tag);
        encoded.extend_from_slice(&self.triptych_proof);

        encoded
    }
}

fn validate_linking_tag(
    encoded: [u8; RISTRETTO_COMPRESSED_POINT_BYTES],
) -> Result<(), ProtocolError> {
    let point = decode_non_identity(encoded).map_err(|_| {
        ProtocolError::new(
            ValidationCode::MalformedProof,
            "Triptych linking tag is not a valid nonidentity Ristretto point",
        )
    })?;

    if point.compress().to_bytes() != encoded {
        return Err(ProtocolError::new(
            ValidationCode::MalformedProof,
            "Triptych linking tag is not canonically encoded",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

    use super::*;

    fn valid_linking_tag() -> [u8; RISTRETTO_COMPRESSED_POINT_BYTES] {
        RISTRETTO_BASEPOINT_POINT.compress().to_bytes()
    }

    fn envelope() -> TariTriptychProofEnvelopeV1 {
        let Ok(envelope) = TariTriptychProofEnvelopeV1::new(valid_linking_tag(), vec![1, 2, 3, 4])
        else {
            panic!("test proof envelope must be valid");
        };

        envelope
    }

    #[test]
    fn round_trip_preserves_exact_bytes() {
        let envelope = envelope();
        let encoded = envelope.to_bytes();

        let Ok(decoded) = TariTriptychProofEnvelopeV1::from_bytes(&encoded) else {
            panic!("encoded proof envelope must decode");
        };

        assert_eq!(decoded, envelope);
        assert_eq!(decoded.to_bytes(), encoded);
    }

    #[test]
    fn exact_version_tag_and_proof_layout_is_stable() {
        let tag = valid_linking_tag();

        let Ok(envelope) = TariTriptychProofEnvelopeV1::new(tag, vec![0xaa, 0xbb, 0xcc]) else {
            panic!("test proof envelope must be valid");
        };

        let encoded = envelope.to_bytes();

        assert_eq!(
            &encoded[..2],
            &TARI_TRIPTYCH_PROOF_ENVELOPE_VERSION_V1.to_le_bytes(),
        );
        assert_eq!(
            &encoded[2..TARI_TRIPTYCH_PROOF_ENVELOPE_HEADER_BYTES],
            tag.as_slice(),
        );
        assert_eq!(
            &encoded[TARI_TRIPTYCH_PROOF_ENVELOPE_HEADER_BYTES..],
            &[0xaa, 0xbb, 0xcc],
        );
    }

    #[test]
    fn getters_preserve_exact_parts() {
        let tag = valid_linking_tag();
        let proof = vec![9, 8, 7];

        let Ok(envelope) = TariTriptychProofEnvelopeV1::new(tag, proof.clone()) else {
            panic!("test proof envelope must be valid");
        };

        assert_eq!(envelope.linking_tag_bytes(), &tag);
        assert_eq!(envelope.triptych_proof_bytes(), proof.as_slice());
    }

    #[test]
    fn too_short_envelope_is_rejected() {
        let encoded = vec![0_u8; TARI_TRIPTYCH_PROOF_ENVELOPE_HEADER_BYTES];

        assert!(matches!(
            TariTriptychProofEnvelopeV1::from_bytes(&encoded),
            Err(error) if error.code() == ValidationCode::MalformedProof
        ));
    }

    #[test]
    fn unsupported_envelope_version_is_rejected() {
        let mut encoded = envelope().to_bytes();
        encoded[..2].copy_from_slice(&2_u16.to_le_bytes());

        assert!(matches!(
            TariTriptychProofEnvelopeV1::from_bytes(&encoded),
            Err(error) if error.code() == ValidationCode::MalformedProof
        ));
    }

    #[test]
    fn empty_triptych_proof_is_rejected() {
        assert!(matches!(
            TariTriptychProofEnvelopeV1::new(valid_linking_tag(), Vec::new()),
            Err(error) if error.code() == ValidationCode::MalformedProof
        ));
    }

    #[test]
    fn identity_linking_tag_is_rejected() {
        let identity = [0_u8; RISTRETTO_COMPRESSED_POINT_BYTES];

        assert!(matches!(
            TariTriptychProofEnvelopeV1::new(identity, vec![1]),
            Err(error) if error.code() == ValidationCode::MalformedProof
        ));
    }

    #[test]
    fn malformed_linking_tag_is_rejected() {
        assert!(matches!(
            TariTriptychProofEnvelopeV1::new(
                [0xff_u8; RISTRETTO_COMPRESSED_POINT_BYTES],
                vec![1],
            ),
            Err(error) if error.code() == ValidationCode::MalformedProof
        ));
    }

    #[test]
    fn oversized_constructed_envelope_is_rejected() {
        let Some(maximum_inner) =
            MAX_PROOF_BYTES.checked_sub(TARI_TRIPTYCH_PROOF_ENVELOPE_HEADER_BYTES)
        else {
            panic!("protocol proof limit must exceed the envelope header");
        };

        let proof = vec![0_u8; maximum_inner.saturating_add(1)];

        assert!(matches!(
            TariTriptychProofEnvelopeV1::new(valid_linking_tag(), proof),
            Err(error)
                if error.code() == ValidationCode::ProtocolLimitExceeded
        ));
    }

    #[test]
    fn oversized_encoded_envelope_is_rejected_before_parsing() {
        let encoded = vec![0_u8; MAX_PROOF_BYTES.saturating_add(1)];

        assert!(matches!(
            TariTriptychProofEnvelopeV1::from_bytes(&encoded),
            Err(error)
                if error.code() == ValidationCode::ProtocolLimitExceeded
        ));
    }
}
