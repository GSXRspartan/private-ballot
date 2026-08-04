//! Canonical `EmitLog` payload for a version-one anchor record digest.
//!
//! The payload is the exact bounded UTF-8 text a later slice would place in a
//! Tari Ootle `Instruction::EmitLog`. Slice 4A3 confirmed that `EmitLog`
//! accepts bounded UTF-8 text rather than arbitrary bytes, so the 32-byte
//! production anchor-record digest is encoded as exactly 64 lowercase
//! hexadecimal characters behind a fixed ASCII prefix:
//!
//! ```text
//! TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V1:<64 lowercase hex characters>
//! ```
//!
//! The type carries only an [`OotleAnchorRecordHashV1`]. It has no field able to
//! hold a memo, election metadata, transaction metadata, or voter/ballot data.

use core::fmt;
use core::str::FromStr;

use tari_cc_private_ballot_anchor::{OOTLE_ANCHOR_RECORD_TYPE_ID_V1, OotleAnchorRecordHashV1};

use crate::errors::AnchorLogPayloadError;

/// Fixed ASCII prefix marking a version-one anchor log payload.
///
/// This is exactly the anchor record's type-and-version identifier, so a ledger
/// log line is self-identifying and cannot be confused with an unrelated log.
pub const ANCHOR_LOG_PAYLOAD_PREFIX_V1: &str = OOTLE_ANCHOR_RECORD_TYPE_ID_V1;

/// Single ASCII separator between the fixed prefix and the hex digest.
pub const ANCHOR_LOG_PAYLOAD_SEPARATOR: char = ':';

/// Exact number of lowercase hexadecimal characters encoding the digest.
pub const ANCHOR_LOG_PAYLOAD_DIGEST_HEX_LEN: usize = 64;

/// Prefix plus the single colon separator, the exact candidate marker.
///
/// A receipt log line is treated as a project anchor log only when its whole
/// string begins with this marker; a string that merely contains the prefix as
/// an interior substring is not a project anchor log.
pub const ANCHOR_LOG_PAYLOAD_CANDIDATE_PREFIX_V1: &str =
    concat!("TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V1", ":");

/// Canonical version-one anchor log payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AnchorLogPayloadV1 {
    digest: OotleAnchorRecordHashV1,
}

impl AnchorLogPayloadV1 {
    /// Exact encoded byte length of every well-formed payload.
    ///
    /// The prefix is fixed and the digest is always 64 hex characters, so the
    /// encoded length is constant; the exact and maximum lengths coincide.
    #[must_use]
    pub const fn exact_encoded_len() -> usize {
        ANCHOR_LOG_PAYLOAD_PREFIX_V1.len() + 1 + ANCHOR_LOG_PAYLOAD_DIGEST_HEX_LEN
    }

    /// Maximum encoded byte length of any well-formed payload.
    ///
    /// Equal to [`Self::exact_encoded_len`] because the encoding is fixed-length.
    #[must_use]
    pub const fn max_encoded_len() -> usize {
        Self::exact_encoded_len()
    }

    /// Builds a payload from an anchor-record digest.
    #[must_use]
    pub const fn from_digest(digest: OotleAnchorRecordHashV1) -> Self {
        Self { digest }
    }

    /// Recovers the wrapped anchor-record digest.
    #[must_use]
    pub const fn digest(&self) -> OotleAnchorRecordHashV1 {
        self.digest
    }

    /// Serializes the payload to its exact canonical string form.
    #[must_use]
    pub fn to_encoded_string(&self) -> String {
        let mut encoded = String::with_capacity(Self::exact_encoded_len());
        encoded.push_str(ANCHOR_LOG_PAYLOAD_PREFIX_V1);
        encoded.push(ANCHOR_LOG_PAYLOAD_SEPARATOR);
        encoded.push_str(&to_lower_hex_32(self.digest.as_bytes()));
        encoded
    }

    /// Strictly parses a payload from its canonical string form.
    ///
    /// The parser accepts only the exact fixed prefix, exactly one colon, and
    /// exactly 64 lowercase hexadecimal characters with nothing before or after.
    /// It rejects empty input, wrong or alternate prefixes, a missing or extra
    /// colon, uppercase hex, odd or wrong-length digests, non-hex characters,
    /// leading or trailing whitespace, embedded newlines, NUL bytes, and any
    /// appended text.
    pub fn parse(input: &str) -> Result<Self, AnchorLogPayloadError> {
        if input.is_empty() {
            return Err(AnchorLogPayloadError::Empty);
        }

        let after_prefix = input
            .strip_prefix(ANCHOR_LOG_PAYLOAD_PREFIX_V1)
            .ok_or(AnchorLogPayloadError::WrongPrefix)?;

        let hex = after_prefix
            .strip_prefix(ANCHOR_LOG_PAYLOAD_SEPARATOR)
            .ok_or(AnchorLogPayloadError::MissingSeparator)?;

        let hex_bytes = hex.as_bytes();
        if hex_bytes.len() != ANCHOR_LOG_PAYLOAD_DIGEST_HEX_LEN {
            return Err(AnchorLogPayloadError::DigestLength);
        }

        let mut digest = [0_u8; 32];
        for (byte, pair) in digest.iter_mut().zip(hex_bytes.chunks_exact(2)) {
            let high =
                lower_hex_value(pair[0]).ok_or(AnchorLogPayloadError::NonLowercaseHexDigit)?;
            let low =
                lower_hex_value(pair[1]).ok_or(AnchorLogPayloadError::NonLowercaseHexDigit)?;
            *byte = (high << 4) | low;
        }

        Ok(Self::from_digest(OotleAnchorRecordHashV1::new(digest)))
    }
}

impl fmt::Display for AnchorLogPayloadV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_encoded_string())
    }
}

impl FromStr for AnchorLogPayloadV1 {
    type Err = AnchorLogPayloadError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl From<OotleAnchorRecordHashV1> for AnchorLogPayloadV1 {
    fn from(digest: OotleAnchorRecordHashV1) -> Self {
        Self::from_digest(digest)
    }
}

/// Encodes 32 bytes as exactly 64 lowercase hexadecimal characters.
#[must_use]
pub(crate) fn to_lower_hex_32(bytes: &[u8; 32]) -> String {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(64);
    for &byte in bytes {
        encoded.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// Maps one lowercase hexadecimal byte to its value, rejecting anything else.
const fn lower_hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ANCHOR_LOG_PAYLOAD_CANDIDATE_PREFIX_V1, ANCHOR_LOG_PAYLOAD_PREFIX_V1, AnchorLogPayloadV1,
        to_lower_hex_32,
    };
    use tari_cc_private_ballot_anchor::OotleAnchorRecordHashV1;

    fn digest(byte: u8) -> OotleAnchorRecordHashV1 {
        OotleAnchorRecordHashV1::new([byte; 32])
    }

    #[test]
    fn exact_and_max_encoded_length_is_one_hundred_three() {
        assert_eq!(AnchorLogPayloadV1::exact_encoded_len(), 103);
        assert_eq!(AnchorLogPayloadV1::max_encoded_len(), 103);
        assert_eq!(ANCHOR_LOG_PAYLOAD_PREFIX_V1.len(), 38);
    }

    #[test]
    fn candidate_prefix_is_prefix_plus_colon() {
        assert_eq!(
            ANCHOR_LOG_PAYLOAD_CANDIDATE_PREFIX_V1,
            format!("{ANCHOR_LOG_PAYLOAD_PREFIX_V1}:")
        );
    }

    #[test]
    fn round_trip_encodes_and_parses() {
        let payload = AnchorLogPayloadV1::from_digest(digest(0x22));
        let encoded = payload.to_encoded_string();

        assert_eq!(encoded.len(), AnchorLogPayloadV1::exact_encoded_len());

        let Ok(parsed) = AnchorLogPayloadV1::parse(&encoded) else {
            panic!("canonical payload must parse");
        };

        assert_eq!(parsed, payload);
        assert_eq!(parsed.digest(), digest(0x22));
    }

    #[test]
    fn lower_hex_matches_known_answer() {
        let mut bytes = [0_u8; 32];
        bytes[0] = 0x0a;
        bytes[31] = 0xff;

        let hex = to_lower_hex_32(&bytes);

        assert!(hex.starts_with("0a"));
        assert!(hex.ends_with("ff"));
        assert_eq!(hex.len(), 64);
    }
}
