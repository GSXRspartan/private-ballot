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

/// Decodes a lowercase/uppercase hex string into bytes.
///
/// Returns `None` when the input is not an even-length sequence of valid hex
/// digits. The caller is responsible for imposing any length bound; this helper
/// only performs a bounded, allocation-free parse of the given slice.
pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let high = hex_nibble(bytes[index])?;
        let low = hex_nibble(bytes[index + 1])?;
        out.push((high << 4) | low);
        index += 2;
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Abbreviates a hex digest/key for compact table display, preserving the
/// first and last few characters with an ellipsis. The full value is never
/// derived from the abbreviation; callers display the full value separately.
#[must_use]
pub fn abbreviate_hex(hex: &str, head: usize, tail: usize) -> String {
    if hex.len() <= head + tail + 1 {
        return hex.to_owned();
    }
    let (h, _) = hex.split_at(head);
    let tail_start = hex.len() - tail;
    let t2 = &hex[tail_start..];
    format!("{h}\u{2026}{t2}")
}
