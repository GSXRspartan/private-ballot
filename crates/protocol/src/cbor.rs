//! Minimal deterministic CBOR encoding and strict decoding.
//!
//! This module implements only the protocol subset needed by this
//! workspace. It accepts definite-length values and requires the
//! shortest permitted integer and length encodings.

use crate::{ProtocolError, ValidationCode};

const MAJOR_UNSIGNED: u8 = 0;
const MAJOR_BYTE_STRING: u8 = 2;
const MAJOR_TEXT_STRING: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;

fn invalid_cbor(message: &'static str) -> ProtocolError {
    ProtocolError::new(ValidationCode::InvalidCbor, message)
}

fn noncanonical_cbor(message: &'static str) -> ProtocolError {
    ProtocolError::new(ValidationCode::NonCanonicalCbor, message)
}

fn unexpected_type(message: &'static str) -> ProtocolError {
    ProtocolError::new(ValidationCode::UnexpectedCborType, message)
}

fn encode_argument(major: u8, value: u64, output: &mut Vec<u8>) {
    if value <= 23 {
        output.push((major << 5) | value as u8);
    } else if value <= u64::from(u8::MAX) {
        output.push((major << 5) | 24);
        output.push(value as u8);
    } else if value <= u64::from(u16::MAX) {
        output.push((major << 5) | 25);
        output.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= u64::from(u32::MAX) {
        output.push((major << 5) | 26);
        output.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        output.push((major << 5) | 27);
        output.extend_from_slice(&value.to_be_bytes());
    }
}

/// Writer for the supported deterministic CBOR subset.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CanonicalCborWriter {
    output: Vec<u8>,
}

impl CanonicalCborWriter {
    /// Creates an empty writer.
    #[must_use]
    pub const fn new() -> Self {
        Self { output: Vec::new() }
    }

    /// Returns encoded bytes written so far.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.output
    }

    /// Consumes the writer and returns the encoded bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.output
    }

    /// Writes a non-negative integer using its shortest encoding.
    pub fn write_unsigned(&mut self, value: u64) {
        encode_argument(MAJOR_UNSIGNED, value, &mut self.output);
    }

    /// Writes a definite-length byte string.
    pub fn write_byte_string(&mut self, value: &[u8]) -> Result<(), ProtocolError> {
        let length = u64::try_from(value.len())
            .map_err(|_| invalid_cbor("byte-string length exceeds protocol limits"))?;

        encode_argument(MAJOR_BYTE_STRING, length, &mut self.output);
        self.output.extend_from_slice(value);

        Ok(())
    }

    /// Writes a definite-length UTF-8 text string.
    pub fn write_text_string(&mut self, value: &str) -> Result<(), ProtocolError> {
        let length = u64::try_from(value.len())
            .map_err(|_| invalid_cbor("text-string length exceeds protocol limits"))?;

        encode_argument(MAJOR_TEXT_STRING, length, &mut self.output);
        self.output.extend_from_slice(value.as_bytes());

        Ok(())
    }

    /// Writes a definite array length.
    pub fn write_array_len(&mut self, length: usize) -> Result<(), ProtocolError> {
        let length = u64::try_from(length)
            .map_err(|_| invalid_cbor("array length exceeds protocol limits"))?;

        encode_argument(MAJOR_ARRAY, length, &mut self.output);
        Ok(())
    }

    /// Writes a definite map length.
    ///
    /// Callers remain responsible for writing keys in deterministic
    /// encoded-key order.
    pub fn write_map_len(&mut self, length: usize) -> Result<(), ProtocolError> {
        let length = u64::try_from(length)
            .map_err(|_| invalid_cbor("map length exceeds protocol limits"))?;

        encode_argument(MAJOR_MAP, length, &mut self.output);
        Ok(())
    }

    /// Writes a CBOR boolean.
    pub fn write_bool(&mut self, value: bool) {
        self.output.push(if value { 0xf5 } else { 0xf4 });
    }
}

/// Strict reader for the supported deterministic CBOR subset.
#[derive(Debug, Clone)]
pub struct CanonicalCborReader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> CanonicalCborReader<'a> {
    /// Creates a reader over one encoded value sequence.
    #[must_use]
    pub const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    /// Returns the number of bytes consumed.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Requires all input bytes to have been consumed.
    pub fn finish(self) -> Result<(), ProtocolError> {
        if self.offset != self.input.len() {
            return Err(ProtocolError::new(
                ValidationCode::TrailingCborData,
                "trailing bytes remain after the decoded CBOR value",
            ));
        }

        Ok(())
    }

    /// Reads a canonical non-negative integer.
    pub fn read_unsigned(&mut self) -> Result<u64, ProtocolError> {
        self.read_argument(MAJOR_UNSIGNED)
    }

    /// Reads a canonical definite-length byte string.
    pub fn read_byte_string(&mut self) -> Result<&'a [u8], ProtocolError> {
        let length = self.read_argument(MAJOR_BYTE_STRING)?;
        self.take(length)
    }

    /// Reads a canonical definite-length UTF-8 string.
    pub fn read_text_string(&mut self) -> Result<&'a str, ProtocolError> {
        let length = self.read_argument(MAJOR_TEXT_STRING)?;
        let bytes = self.take(length)?;

        core::str::from_utf8(bytes).map_err(|_| invalid_cbor("CBOR text string is not valid UTF-8"))
    }

    /// Reads a canonical definite array length.
    pub fn read_array_len(&mut self) -> Result<usize, ProtocolError> {
        let length = self.read_argument(MAJOR_ARRAY)?;

        usize::try_from(length).map_err(|_| invalid_cbor("array length exceeds platform limits"))
    }

    /// Reads a canonical definite map length.
    pub fn read_map_len(&mut self) -> Result<usize, ProtocolError> {
        let length = self.read_argument(MAJOR_MAP)?;

        usize::try_from(length).map_err(|_| invalid_cbor("map length exceeds platform limits"))
    }

    /// Reads a CBOR boolean.
    pub fn read_bool(&mut self) -> Result<bool, ProtocolError> {
        let initial = self.read_byte()?;

        match initial {
            0xf4 => Ok(false),
            0xf5 => Ok(true),
            _ => Err(unexpected_type("expected a CBOR boolean")),
        }
    }

    fn read_argument(&mut self, expected_major: u8) -> Result<u64, ProtocolError> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;

        if major != expected_major {
            return Err(unexpected_type("unexpected CBOR major type"));
        }

        match additional {
            value @ 0..=23 => Ok(u64::from(value)),
            24 => {
                let value = u64::from(self.read_byte()?);

                if value < 24 {
                    return Err(noncanonical_cbor(
                        "CBOR argument does not use its shortest encoding",
                    ));
                }

                Ok(value)
            }
            25 => {
                let value = u64::from(u16::from_be_bytes(self.read_exact()?));

                if value <= u64::from(u8::MAX) {
                    return Err(noncanonical_cbor(
                        "CBOR argument does not use its shortest encoding",
                    ));
                }

                Ok(value)
            }
            26 => {
                let value = u64::from(u32::from_be_bytes(self.read_exact()?));

                if value <= u64::from(u16::MAX) {
                    return Err(noncanonical_cbor(
                        "CBOR argument does not use its shortest encoding",
                    ));
                }

                Ok(value)
            }
            27 => {
                let value = u64::from_be_bytes(self.read_exact()?);

                if value <= u64::from(u32::MAX) {
                    return Err(noncanonical_cbor(
                        "CBOR argument does not use its shortest encoding",
                    ));
                }

                Ok(value)
            }
            31 => Err(noncanonical_cbor(
                "indefinite-length CBOR items are not permitted",
            )),
            _ => Err(invalid_cbor("reserved CBOR additional information")),
        }
    }

    fn read_byte(&mut self) -> Result<u8, ProtocolError> {
        let Some(value) = self.input.get(self.offset).copied() else {
            return Err(invalid_cbor("truncated CBOR input"));
        };

        self.offset += 1;
        Ok(value)
    }

    fn read_exact<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], ProtocolError> {
        let end = self
            .offset
            .checked_add(LENGTH)
            .ok_or_else(|| invalid_cbor("CBOR offset overflow"))?;

        let Some(slice) = self.input.get(self.offset..end) else {
            return Err(invalid_cbor("truncated CBOR input"));
        };

        let mut output = [0_u8; LENGTH];
        output.copy_from_slice(slice);
        self.offset = end;

        Ok(output)
    }

    fn take(&mut self, length: u64) -> Result<&'a [u8], ProtocolError> {
        let length = usize::try_from(length)
            .map_err(|_| invalid_cbor("CBOR item length exceeds platform limits"))?;

        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| invalid_cbor("CBOR offset overflow"))?;

        let Some(slice) = self.input.get(self.offset..end) else {
            return Err(invalid_cbor("truncated CBOR input"));
        };

        self.offset = end;
        Ok(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::{CanonicalCborReader, CanonicalCborWriter};
    use crate::ValidationCode;

    #[test]
    fn unsigned_integer_vectors_are_exact() {
        let cases = [
            (0_u64, vec![0x00]),
            (23_u64, vec![0x17]),
            (24_u64, vec![0x18, 0x18]),
            (255_u64, vec![0x18, 0xff]),
            (256_u64, vec![0x19, 0x01, 0x00]),
            (65_535_u64, vec![0x19, 0xff, 0xff]),
            (65_536_u64, vec![0x1a, 0x00, 0x01, 0x00, 0x00]),
            (
                u64::from(u32::MAX) + 1,
                vec![0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
            ),
        ];

        for (value, expected) in cases {
            let mut writer = CanonicalCborWriter::new();
            writer.write_unsigned(value);

            assert_eq!(writer.into_bytes(), expected);
        }
    }

    #[test]
    fn compound_vector_is_exact() {
        let mut writer = CanonicalCborWriter::new();

        assert!(writer.write_map_len(2).is_ok());
        assert!(writer.write_text_string("a").is_ok());
        writer.write_unsigned(1);
        assert!(writer.write_text_string("b").is_ok());
        assert!(writer.write_array_len(3).is_ok());
        writer.write_bool(true);
        writer.write_bool(false);
        assert!(writer.write_byte_string(&[0xaa, 0xbb]).is_ok());

        assert_eq!(
            writer.into_bytes(),
            vec![
                0xa2, 0x61, b'a', 0x01, 0x61, b'b', 0x83, 0xf5, 0xf4, 0x42, 0xaa, 0xbb,
            ]
        );
    }

    #[test]
    fn primitive_values_round_trip_and_consume_all_input() {
        let mut writer = CanonicalCborWriter::new();

        writer.write_unsigned(42);
        assert!(writer.write_byte_string(b"bytes").is_ok());
        assert!(writer.write_text_string("text").is_ok());
        writer.write_bool(true);

        let encoded = writer.into_bytes();
        let mut reader = CanonicalCborReader::new(&encoded);

        assert_eq!(reader.read_unsigned(), Ok(42));
        assert_eq!(reader.read_byte_string(), Ok(b"bytes".as_slice()));
        assert_eq!(reader.read_text_string(), Ok("text"));
        assert_eq!(reader.read_bool(), Ok(true));
        assert!(reader.finish().is_ok());
    }

    #[test]
    fn noncanonical_unsigned_integer_is_rejected() {
        let mut reader = CanonicalCborReader::new(&[0x18, 0x17]);
        let result = reader.read_unsigned();

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::NonCanonicalCbor
        ));
    }

    #[test]
    fn noncanonical_byte_string_length_is_rejected() {
        let mut reader = CanonicalCborReader::new(&[0x58, 0x00]);
        let result = reader.read_byte_string();

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::NonCanonicalCbor
        ));
    }

    #[test]
    fn indefinite_length_item_is_rejected() {
        let mut reader = CanonicalCborReader::new(&[0x9f]);
        let result = reader.read_array_len();

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::NonCanonicalCbor
        ));
    }

    #[test]
    fn unexpected_major_type_is_rejected() {
        let mut reader = CanonicalCborReader::new(&[0x61, b'a']);
        let result = reader.read_unsigned();

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::UnexpectedCborType
        ));
    }

    #[test]
    fn trailing_data_is_rejected() {
        let mut reader = CanonicalCborReader::new(&[0x01, 0x02]);

        assert_eq!(reader.read_unsigned(), Ok(1));

        let result = reader.finish();

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::TrailingCborData
        ));
    }

    #[test]
    fn truncated_input_is_rejected() {
        let mut reader = CanonicalCborReader::new(&[0x19, 0x01]);
        let result = reader.read_unsigned();

        assert!(matches!(
            result,
            Err(error) if error.code() == ValidationCode::InvalidCbor
        ));
    }

    #[test]
    fn invalid_utf8_text_is_rejected() {
        let mut reader = CanonicalCborReader::new(&[0x61, 0xff]);
        let result = reader.read_text_string();

        assert!(matches!(
            result,
            Err(error) if error.code() == ValidationCode::InvalidCbor
        ));
    }
}
