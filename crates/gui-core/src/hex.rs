//! Bounded lowercase-hex rendering for public digests and identifiers.
//!
//! Used only for non-secret values (commitments, digests, nullifiers of
//! accepted ballots, transaction fingerprints). Inputs are bounded by the
//! protocol size limits, so outputs are bounded.

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Renders bytes as lowercase hex.
#[must_use]
pub fn to_lower_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}
