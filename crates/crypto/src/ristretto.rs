//! Canonical Ristretto255 public-key parsing for research proof suites.
//!
//! This module establishes only the group-element encoding boundary. It does
//! not select or implement a ring-signature construction.

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    traits::IsIdentity,
};
use tari_cc_private_ballot_protocol::{ProtocolError, ValidationCode};

/// Canonical byte length of one compressed Ristretto255 point.
pub const RISTRETTO_COMPRESSED_POINT_BYTES: usize = 32;

/// Canonically encoded, non-identity Ristretto255 public key.
///
/// The stored bytes have passed `CompressedRistretto::decompress`, an explicit
/// recompression check, and identity rejection. This type does not contain
/// private key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RistrettoPublicKeyV1([u8; RISTRETTO_COMPRESSED_POINT_BYTES]);

impl RistrettoPublicKeyV1 {
    /// Parses one canonical, non-identity compressed Ristretto255 public key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let encoded: [u8; RISTRETTO_COMPRESSED_POINT_BYTES] = bytes.try_into().map_err(|_| {
            ProtocolError::new(
                ValidationCode::InvalidData,
                "Ristretto public key must be exactly 32 bytes",
            )
        })?;

        let point = decode_non_identity(encoded)?;

        if point.compress().to_bytes() != encoded {
            return Err(ProtocolError::new(
                ValidationCode::InvalidData,
                "Ristretto public key is not canonically encoded",
            ));
        }

        Ok(Self(encoded))
    }

    /// Returns the canonical compressed public-key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the fixed-size canonical compressed public-key bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; RISTRETTO_COMPRESSED_POINT_BYTES] {
        self.0
    }

    /// Reconstructs the validated Ristretto point for internal tests.
    #[cfg(test)]
    fn to_point(self) -> Result<RistrettoPoint, ProtocolError> {
        decode_non_identity(self.0)
    }
}

fn decode_non_identity(
    encoded: [u8; RISTRETTO_COMPRESSED_POINT_BYTES],
) -> Result<RistrettoPoint, ProtocolError> {
    let Some(point) = CompressedRistretto(encoded).decompress() else {
        return Err(ProtocolError::new(
            ValidationCode::InvalidData,
            "Ristretto public key is not a canonical compressed point",
        ));
    };

    if point.is_identity() {
        return Err(ProtocolError::new(
            ValidationCode::InvalidData,
            "Ristretto public key must not be the identity point",
        ));
    }

    Ok(point)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::{
        constants::RISTRETTO_BASEPOINT_COMPRESSED, ristretto::RistrettoPoint, traits::Identity,
    };

    #[test]
    fn basepoint_encoding_is_accepted_and_round_trips() {
        let encoded = RISTRETTO_BASEPOINT_COMPRESSED.to_bytes();

        let Ok(public_key) = RistrettoPublicKeyV1::from_bytes(&encoded) else {
            panic!("Ristretto basepoint encoding must be accepted");
        };

        let Ok(point) = public_key.to_point() else {
            panic!("validated Ristretto public key must decode");
        };

        assert_eq!(public_key.as_bytes(), &encoded);
        assert_eq!(public_key.into_bytes(), encoded);
        assert_eq!(point.compress().to_bytes(), encoded);
    }

    #[test]
    fn wrong_length_encodings_are_rejected() {
        for encoded in [
            vec![0_u8; RISTRETTO_COMPRESSED_POINT_BYTES - 1],
            vec![0_u8; RISTRETTO_COMPRESSED_POINT_BYTES + 1],
        ] {
            assert!(matches!(
                RistrettoPublicKeyV1::from_bytes(&encoded),
                Err(error) if error.code() == ValidationCode::InvalidData
            ));
        }
    }

    #[test]
    fn noncanonical_field_encoding_is_rejected() {
        let encoded = [0xff_u8; RISTRETTO_COMPRESSED_POINT_BYTES];

        assert!(matches!(
            RistrettoPublicKeyV1::from_bytes(&encoded),
            Err(error) if error.code() == ValidationCode::InvalidData
        ));
    }

    #[test]
    fn identity_point_is_rejected() {
        let encoded = RistrettoPoint::identity().compress().to_bytes();

        assert!(matches!(
            RistrettoPublicKeyV1::from_bytes(&encoded),
            Err(error) if error.code() == ValidationCode::InvalidData
        ));
    }

    #[test]
    fn distinct_valid_public_keys_remain_distinct() {
        let first = RISTRETTO_BASEPOINT_COMPRESSED.to_bytes();

        let Some(basepoint) = RISTRETTO_BASEPOINT_COMPRESSED.decompress() else {
            panic!("Ristretto basepoint encoding must decode");
        };

        let second = (basepoint + basepoint).compress().to_bytes();

        let Ok(first_key) = RistrettoPublicKeyV1::from_bytes(&first) else {
            panic!("first public key must be valid");
        };

        let Ok(second_key) = RistrettoPublicKeyV1::from_bytes(&second) else {
            panic!("second public key must be valid");
        };

        assert_ne!(first_key, second_key);
    }
}
