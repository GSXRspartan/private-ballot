//! Single anchor `EmitLog` instruction construction (Section C).
//!
//! Exactly one function builds exactly one `Instruction::EmitLog`. Its message is
//! the exact canonical [`AnchorLogPayloadV1`] string, byte for byte: no case
//! change, no prefix change, no extra whitespace, no newline, no JSON wrapper, no
//! CBOR-to-hex conversion, no election hashing, and no secondary metadata log.

use tari_cc_private_ballot_anchor_transport::AnchorLogPayloadV1;
use tari_ootle_transaction::Instruction;
use tari_template_lib_types::{LogLevel, MaxString};

use crate::errors::OotleAnchorAdapterError;

/// Fixed log level for the anchor `EmitLog`.
///
/// `Info` is reliably persisted in receipts and does not falsely imply an error
/// or warning, matching the confirmed Ootle log-level semantics.
pub const ANCHOR_EMIT_LOG_LEVEL: LogLevel = LogLevel::Info;

/// Builds the single anchor `EmitLog` instruction for a validated payload.
///
/// The message is the payload's exact canonical string. The Ootle bounded-string
/// bound (32 KiB) is far larger than the fixed 103-byte payload, so the
/// conversion cannot truncate; a conversion error would indicate a corrupted
/// payload and is surfaced rather than silently coerced.
///
/// # Errors
///
/// Returns [`OotleAnchorAdapterError::BoundedStringConversion`] if the canonical
/// payload string cannot be placed in the Ootle bounded string.
pub fn build_anchor_emit_log(
    payload: &AnchorLogPayloadV1,
) -> Result<Instruction, OotleAnchorAdapterError> {
    let message_text = payload.to_encoded_string();

    // The `message` field type of `Instruction::EmitLog` fixes the `MaxString`
    // bound, so no explicit const generic is named here.
    Ok(Instruction::EmitLog {
        level: ANCHOR_EMIT_LOG_LEVEL,
        message: MaxString::try_from(message_text)
            .map_err(|_error| OotleAnchorAdapterError::BoundedStringConversion)?,
    })
}
