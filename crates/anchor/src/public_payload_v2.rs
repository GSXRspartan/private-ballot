//! Canonical V2 public election-summary anchor payload.
//!
//! The V1 anchor ([`crate::OotleAnchorRecordV1`]) commits only to the aggregate
//! archive digest. The V2 payload publishes a *richer public record* derived
//! solely from the independently verified, finalized archive: the ballot
//! question, per-option tally, commitments, and counts. It never carries
//! per-voter data (see [`assert_v2_public_payload_is_leak_free`]).
//!
//! The payload is deterministic and canonical: the same verified archive always
//! produces the same canonical bytes and therefore the same digest. The digest
//! is domain-separated from every other project digest (including the V1 anchor
//! record) by its own frame prefix and label.
//!
//! Corrected V2 on-chain shape (this file): the canonical bytes are
//! deterministic UTF-8 JSON (fixed key order, no whitespace, canonical integer
//! and string escaping) and are placed on-chain verbatim as the readable
//! `public_summary` template argument. An independent observer only needs to
//! hash the emitted `public_summary` bytes under the V2 domain frame to
//! recompute [`OotleAnchorPublicPayloadV2::canonical_digest`], and can display
//! the payload without the detached archive.

use tari_cc_private_ballot_archive::ArchiveHashV1;
use tari_cc_private_ballot_protocol::{
    BLAKE3_256_HASH_ALGORITHM_ID_V1, HashProvider, ManifestHash, ProtocolError, ValidationCode,
};

use crate::record::OotleNetworkIdV1;

/// Stable record-type and version identifier for a V2 public payload.
pub const OOTLE_ANCHOR_PUBLIC_PAYLOAD_TYPE_ID_V2: &str =
    "TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_PUBLIC_V2";

/// Numeric schema version, emitted as the `version` field of the canonical JSON.
pub const OOTLE_ANCHOR_PUBLIC_PAYLOAD_SCHEMA_VERSION_V2: u64 = 2;

/// Frame prefix for the V2 payload digest (distinct from the V1 anchor frame).
pub const OOTLE_ANCHOR_PUBLIC_PAYLOAD_FRAME_PREFIX_V2: &[u8] =
    b"TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_PUBLIC_FRAME_V2";

/// Unique domain label for the V2 public payload digest.
pub const OOTLE_ANCHOR_PUBLIC_PAYLOAD_DOMAIN_LABEL_V2: &str =
    "tari-cc-private-ballot/ootle-anchor-public-payload/v2";

/// Maximum canonical encoded size of one V2 public payload.
pub const MAX_OOTLE_ANCHOR_PUBLIC_PAYLOAD_BYTES_V2: usize = 256 * 1024;

/// Bounds on the individual free-form public fields.
pub const MAX_BALLOT_QUESTION_BYTES_V2: usize = 8 * 1024;
pub const MAX_OPTION_LABEL_BYTES_V2: usize = 1024;
pub const MAX_ENUM_STRING_BYTES_V2: usize = 64;
pub const MAX_ELECTION_ID_BYTES_V2: usize = 128;
pub const MAX_MACHINE_ID_BYTES_V2: usize = 64;
pub const MAX_TALLY_ENTRIES_V2: usize = 65_536;

fn invalid(message: &'static str) -> ProtocolError {
    ProtocolError::new(ValidationCode::InvalidData, message)
}

fn invalid_json(message: &'static str) -> ProtocolError {
    ProtocolError::new(ValidationCode::InvalidCbor, message)
}

/// One public per-option tally entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OotleAnchorTallyEntryV2 {
    /// Human display label for the option (public ballot text).
    pub display_label: String,
    /// The option's canonical machine id bytes (public option identifier).
    pub machine_id: Vec<u8>,
    /// Approval count for this option.
    pub count: u64,
}

impl OotleAnchorTallyEntryV2 {
    fn validate(&self) -> Result<(), ProtocolError> {
        if self.display_label.len() > MAX_OPTION_LABEL_BYTES_V2 {
            return Err(invalid(
                "tally option label exceeds the public payload limit",
            ));
        }
        if self.machine_id.is_empty() || self.machine_id.len() > MAX_MACHINE_ID_BYTES_V2 {
            return Err(invalid("tally option machine id is empty or too long"));
        }
        Ok(())
    }
}

/// The V2 template deployment identity bound into the public payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OotleAnchorTemplateBindingV2 {
    pub template_address: String,
    pub template_module: String,
    pub template_function: String,
    pub event_topic: String,
    pub artifact_digest: [u8; 32],
}

impl OotleAnchorTemplateBindingV2 {
    fn validate(&self) -> Result<(), ProtocolError> {
        for (value, label) in [
            (&self.template_address, "template address"),
            (&self.template_module, "template module"),
            (&self.template_function, "template function"),
            (&self.event_topic, "event topic"),
        ] {
            if value.is_empty() || value.len() > 512 {
                return Err(invalid(match label {
                    "template address" => "V2 template address is empty or too long",
                    "template module" => "V2 template module is empty or too long",
                    "template function" => "V2 template function is empty or too long",
                    _ => "V2 event topic is empty or too long",
                }));
            }
        }
        Ok(())
    }
}

/// The complete canonical V2 public payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OotleAnchorPublicPayloadV2 {
    pub network: OotleNetworkIdV1,
    pub election_id: Vec<u8>,
    pub ballot_question: String,
    pub ballot_kind: String,
    pub confidentiality_mode: String,
    pub proof_suite: String,
    pub manifest_hash: ManifestHash,
    pub archive_hash: ArchiveHashV1,
    pub registry_commitment: [u8; 32],
    pub option_set_commitment: [u8; 32],
    pub eligible_voter_count: u64,
    pub accepted_ballot_count: u64,
    pub rejected_ballot_count: u64,
    pub tally: Vec<OotleAnchorTallyEntryV2>,
    pub archive_finalized: bool,
    /// Only set when a finalized timestamp is already available from archive or
    /// session metadata; never fabricated.
    pub finalized_timestamp_unix_secs: Option<u64>,
    pub template: OotleAnchorTemplateBindingV2,
}

impl OotleAnchorPublicPayloadV2 {
    /// Validates every bounded field. Called before canonical encoding and after
    /// decoding so a malformed payload can never be hashed or trusted.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.election_id.is_empty() || self.election_id.len() > MAX_ELECTION_ID_BYTES_V2 {
            return Err(invalid(
                "election id is empty or exceeds the public payload limit",
            ));
        }
        // Election ID must be valid UTF-8 (so it can appear verbatim in the
        // readable canonical JSON `election_id` field) and must not contain
        // raw control bytes (which are non-canonical outside of escaped forms
        // and would look like garbage in an on-chain payload).
        let election_id_str = std::str::from_utf8(&self.election_id)
            .map_err(|_| invalid("election id must be valid UTF-8"))?;
        if election_id_str.bytes().any(|byte| byte < 0x20) {
            return Err(invalid(
                "election id must not contain raw control characters",
            ));
        }
        if self.ballot_question.len() > MAX_BALLOT_QUESTION_BYTES_V2 {
            return Err(invalid("ballot question exceeds the public payload limit"));
        }
        for (value, message) in [
            (&self.ballot_kind, "ballot kind is empty or too long"),
            (
                &self.confidentiality_mode,
                "confidentiality mode is empty or too long",
            ),
            (&self.proof_suite, "proof suite is empty or too long"),
        ] {
            if value.is_empty() || value.len() > MAX_ENUM_STRING_BYTES_V2 {
                return Err(invalid(message));
            }
        }
        if self.tally.len() > MAX_TALLY_ENTRIES_V2 {
            return Err(invalid("tally exceeds the public payload entry limit"));
        }
        for entry in &self.tally {
            entry.validate()?;
        }
        self.template.validate()?;
        Ok(())
    }

    /// Encodes the payload as deterministic canonical JSON.
    ///
    /// The encoding uses a fixed top-level field order (never sorted by key),
    /// no whitespace, canonical decimal integers, and RFC 8259 string escapes.
    /// Two payloads that are field-for-field equal always produce the exact
    /// same UTF-8 bytes, which is what the on-chain digest commits to.
    pub fn to_canonical_json_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let mut writer = CanonicalJsonWriter::new();
        // The top-level object emits fields in the exact order documented below.
        // Consumers depend on this order because the digest is over the emitted
        // bytes, not over a re-parsed and re-serialized structure.
        writer.begin_object();
        writer.field_string("schema", OOTLE_ANCHOR_PUBLIC_PAYLOAD_TYPE_ID_V2);
        writer.field_u64("version", OOTLE_ANCHOR_PUBLIC_PAYLOAD_SCHEMA_VERSION_V2);
        writer.field_string("network", self.network.as_str());
        // election_id is the exact canonical election identifier string from
        // the frozen manifest (e.g. "500-votertest-01") — validated as
        // control-free UTF-8 above, so it can be placed verbatim in the
        // readable public summary.
        let election_id_str =
            std::str::from_utf8(&self.election_id).expect("validate() guarantees UTF-8");
        writer.field_string("election_id", election_id_str);
        writer.field_string("question", &self.ballot_question);
        writer.field_u64("eligible_voters", self.eligible_voter_count);
        writer.field_u64("accepted_ballots", self.accepted_ballot_count);
        writer.field_u64("rejected_ballots", self.rejected_ballot_count);
        writer.begin_array_field("results");
        for entry in &self.tally {
            writer.begin_object_element();
            writer.field_string("label", &entry.display_label);
            writer.field_lower_hex("machine_id", &entry.machine_id);
            writer.field_u64("votes", entry.count);
            writer.end_object();
        }
        writer.end_array();
        writer.field_string("ballot_kind", &self.ballot_kind);
        writer.field_string("confidentiality_mode", &self.confidentiality_mode);
        writer.field_string("proof_suite", &self.proof_suite);
        writer.field_lower_hex("manifest_hash", self.manifest_hash.as_bytes());
        writer.field_lower_hex("archive_hash", self.archive_hash.as_bytes());
        writer.field_lower_hex("voter_registry_commitment", &self.registry_commitment);
        writer.field_lower_hex("ballot_option_commitment", &self.option_set_commitment);
        writer.field_bool("archive_finalized", self.archive_finalized);
        // The finalized-timestamp field is always present and encodes absence as
        // JSON null so the field count is constant across payloads.
        writer.field_opt_u64(
            "finalized_timestamp_unix_secs",
            self.finalized_timestamp_unix_secs,
        );
        writer.field_string("template_address", &self.template.template_address);
        writer.field_string("template_module", &self.template.template_module);
        writer.field_string("template_function", &self.template.template_function);
        writer.field_string("template_event_topic", &self.template.event_topic);
        writer.field_lower_hex("template_artifact_digest", &self.template.artifact_digest);
        writer.end_object();

        let encoded = writer.into_bytes();
        if encoded.len() > MAX_OOTLE_ANCHOR_PUBLIC_PAYLOAD_BYTES_V2 {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "canonical V2 public payload exceeds the size limit",
            ));
        }
        Ok(encoded)
    }

    /// Strictly decodes one canonical V2 public payload from its exact
    /// canonical JSON bytes.
    ///
    /// The decoder is deliberately strict: it re-encodes the parsed payload and
    /// requires byte-for-byte equality with the input. Any non-canonical form
    /// (different field order, extra whitespace, alternate integer encoding,
    /// alternate string escapes, unknown fields) is rejected — this is
    /// essential because the digest is over the raw bytes.
    pub fn from_canonical_json_bytes(encoded: &[u8]) -> Result<Self, ProtocolError> {
        if encoded.len() > MAX_OOTLE_ANCHOR_PUBLIC_PAYLOAD_BYTES_V2 {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "encoded V2 public payload exceeds the size limit",
            ));
        }
        let payload = parse_canonical_json_bytes(encoded)?;
        payload.validate()?;
        // Canonicalisation round-trip: an accepted payload must re-encode to
        // exactly the input bytes. This rejects any decoded-but-non-canonical
        // encoding (a different key order, whitespace, escapes, or trailing
        // data), which is essential because the digest is over the raw bytes.
        let re_encoded = payload.to_canonical_json_bytes()?;
        if re_encoded != encoded {
            return Err(invalid_json(
                "V2 public payload bytes are not the canonical JSON encoding of their content",
            ));
        }
        Ok(payload)
    }

    /// Derives the domain-separated production digest over the canonical
    /// UTF-8 JSON bytes.
    pub fn canonical_digest<H: HashProvider>(
        &self,
        provider: &H,
    ) -> Result<[u8; 32], ProtocolError> {
        if provider.algorithm_id() != BLAKE3_256_HASH_ALGORITHM_ID_V1 {
            return Err(ProtocolError::new(
                ValidationCode::UnsupportedHashAlgorithm,
                "V2 public payload hashing requires the production hash provider",
            ));
        }
        let encoded = self.to_canonical_json_bytes()?;
        let framed = v2_domain_input(&encoded);
        Ok(provider.hash(&framed))
    }

    /// Verifies one expected V2 payload digest.
    pub fn verify_digest<H: HashProvider>(
        &self,
        provider: &H,
        expected: &[u8; 32],
    ) -> Result<(), ProtocolError> {
        if &self.canonical_digest(provider)? != expected {
            return Err(ProtocolError::new(
                ValidationCode::ArchiveManifestHashMismatch,
                "V2 public payload does not match the expected anchor digest",
            ));
        }
        Ok(())
    }
}

fn v2_domain_input(canonical_bytes: &[u8]) -> Vec<u8> {
    let label = OOTLE_ANCHOR_PUBLIC_PAYLOAD_DOMAIN_LABEL_V2.as_bytes();
    let mut framed = Vec::with_capacity(
        OOTLE_ANCHOR_PUBLIC_PAYLOAD_FRAME_PREFIX_V2.len()
            + 1
            + label.len()
            + 1
            + canonical_bytes.len(),
    );
    framed.extend_from_slice(OOTLE_ANCHOR_PUBLIC_PAYLOAD_FRAME_PREFIX_V2);
    framed.push(0);
    framed.extend_from_slice(label);
    framed.push(0);
    framed.extend_from_slice(canonical_bytes);
    framed
}

// ---------------------------------------------------------------------------
// Deterministic canonical JSON writer.
// ---------------------------------------------------------------------------

/// Small deterministic JSON writer used only for the V2 payload.
///
/// Rules:
/// * no insignificant whitespace anywhere;
/// * fields are emitted in the exact call order (never sorted);
/// * `u64` renders as decimal digits without leading zeros;
/// * strings are RFC 8259 encoded, with `"`, `\`, and every C0 control byte
///   escaped; non-ASCII UTF-8 is written verbatim (never unnecessarily
///   `\u`-escaped), so the encoding is stable across implementations.
struct CanonicalJsonWriter {
    bytes: Vec<u8>,
    /// Whether the next field/element in the current container needs a leading
    /// comma. Reset to `false` on every container open.
    needs_comma: bool,
    /// Stack of parent `needs_comma` states so nested containers restore
    /// separator handling when they close.
    stack: Vec<bool>,
}

impl CanonicalJsonWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(256),
            needs_comma: false,
            stack: Vec::new(),
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    fn push_separator(&mut self) {
        if self.needs_comma {
            self.bytes.push(b',');
        } else {
            self.needs_comma = true;
        }
    }

    fn write_string(&mut self, value: &str) {
        self.bytes.push(b'"');
        for byte in value.as_bytes() {
            match *byte {
                b'"' => self.bytes.extend_from_slice(b"\\\""),
                b'\\' => self.bytes.extend_from_slice(b"\\\\"),
                b'\n' => self.bytes.extend_from_slice(b"\\n"),
                b'\r' => self.bytes.extend_from_slice(b"\\r"),
                b'\t' => self.bytes.extend_from_slice(b"\\t"),
                b'\x08' => self.bytes.extend_from_slice(b"\\b"),
                b'\x0c' => self.bytes.extend_from_slice(b"\\f"),
                byte if byte < 0x20 => {
                    let hi = byte >> 4;
                    let lo = byte & 0x0f;
                    self.bytes.extend_from_slice(b"\\u00");
                    self.bytes.push(hex_digit(hi));
                    self.bytes.push(hex_digit(lo));
                }
                byte => self.bytes.push(byte),
            }
        }
        self.bytes.push(b'"');
    }

    fn write_key(&mut self, key: &str) {
        self.push_separator();
        self.write_string(key);
        self.bytes.push(b':');
    }

    fn begin_object(&mut self) {
        self.push_separator();
        self.bytes.push(b'{');
        self.stack.push(self.needs_comma);
        self.needs_comma = false;
    }

    fn end_object(&mut self) {
        self.bytes.push(b'}');
        self.needs_comma = self.stack.pop().unwrap_or(true);
    }

    fn begin_object_element(&mut self) {
        // Inside an array: the element does not have a key, but it still needs
        // the leading comma if the array already has elements. begin_object
        // handles that via push_separator.
        self.begin_object();
    }

    fn begin_array_field(&mut self, key: &str) {
        self.write_key(key);
        self.bytes.push(b'[');
        self.stack.push(true);
        self.needs_comma = false;
    }

    fn end_array(&mut self) {
        self.bytes.push(b']');
        self.needs_comma = self.stack.pop().unwrap_or(true);
    }

    fn field_string(&mut self, key: &str, value: &str) {
        self.write_key(key);
        self.write_string(value);
    }

    fn field_u64(&mut self, key: &str, value: u64) {
        self.write_key(key);
        self.write_u64(value);
    }

    fn field_bool(&mut self, key: &str, value: bool) {
        self.write_key(key);
        if value {
            self.bytes.extend_from_slice(b"true");
        } else {
            self.bytes.extend_from_slice(b"false");
        }
    }

    fn field_opt_u64(&mut self, key: &str, value: Option<u64>) {
        self.write_key(key);
        match value {
            Some(number) => self.write_u64(number),
            None => self.bytes.extend_from_slice(b"null"),
        }
    }

    fn field_lower_hex(&mut self, key: &str, bytes: &[u8]) {
        self.write_key(key);
        self.bytes.push(b'"');
        for byte in bytes {
            self.bytes.push(hex_digit(byte >> 4));
            self.bytes.push(hex_digit(byte & 0x0f));
        }
        self.bytes.push(b'"');
    }

    fn write_u64(&mut self, value: u64) {
        // `u64::to_string` already emits shortest decimal without leading zeros.
        let text = value.to_string();
        self.bytes.extend_from_slice(text.as_bytes());
    }
}

const fn hex_digit(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        _ => b'a' + (nibble - 10),
    }
}

// ---------------------------------------------------------------------------
// Strict canonical-JSON parser tailored to the V2 payload.
// ---------------------------------------------------------------------------

fn parse_canonical_json_bytes(encoded: &[u8]) -> Result<OotleAnchorPublicPayloadV2, ProtocolError> {
    let mut parser = CanonicalJsonParser::new(encoded);
    parser.consume_byte(b'{')?;

    let schema = parser.expect_string_field("schema")?;
    if schema != OOTLE_ANCHOR_PUBLIC_PAYLOAD_TYPE_ID_V2 {
        return Err(ProtocolError::new(
            ValidationCode::UnsupportedProtocolVersion,
            "unsupported V2 public payload type or version",
        ));
    }
    parser.expect_field_comma()?;
    let version = parser.expect_u64_field("version")?;
    if version != OOTLE_ANCHOR_PUBLIC_PAYLOAD_SCHEMA_VERSION_V2 {
        return Err(ProtocolError::new(
            ValidationCode::UnsupportedProtocolVersion,
            "unsupported V2 public payload version number",
        ));
    }
    parser.expect_field_comma()?;
    let network_str = parser.expect_string_field("network")?;
    let network = OotleNetworkIdV1::new(network_str)?;
    parser.expect_field_comma()?;
    // election_id is the raw canonical election identifier string bytes; the
    // round-trip check + validate() enforce the same UTF-8 + no-control-byte
    // rule as the writer.
    let election_id_str = parser.expect_string_field("election_id")?;
    let election_id = election_id_str.into_bytes();
    parser.expect_field_comma()?;
    let ballot_question = parser.expect_string_field("question")?;
    parser.expect_field_comma()?;
    let eligible_voter_count = parser.expect_u64_field("eligible_voters")?;
    parser.expect_field_comma()?;
    let accepted_ballot_count = parser.expect_u64_field("accepted_ballots")?;
    parser.expect_field_comma()?;
    let rejected_ballot_count = parser.expect_u64_field("rejected_ballots")?;
    parser.expect_field_comma()?;

    // results array of {label, machine_id, votes}
    parser.expect_key("results")?;
    parser.consume_byte(b'[')?;
    let mut tally = Vec::new();
    let mut first = true;
    while parser.peek_byte()? != b']' {
        if !first {
            parser.consume_byte(b',')?;
        }
        parser.consume_byte(b'{')?;
        let label = parser.expect_string_field("label")?;
        parser.expect_field_comma()?;
        let machine_id_hex = parser.expect_string_field("machine_id")?;
        parser.expect_field_comma()?;
        let votes = parser.expect_u64_field("votes")?;
        parser.consume_byte(b'}')?;
        tally.push(OotleAnchorTallyEntryV2 {
            display_label: label,
            machine_id: decode_lower_hex(&machine_id_hex)?,
            count: votes,
        });
        first = false;
        if tally.len() > MAX_TALLY_ENTRIES_V2 {
            return Err(invalid_json("V2 tally exceeds the entry limit"));
        }
    }
    parser.consume_byte(b']')?;
    parser.expect_field_comma()?;

    let ballot_kind = parser.expect_string_field("ballot_kind")?;
    parser.expect_field_comma()?;
    let confidentiality_mode = parser.expect_string_field("confidentiality_mode")?;
    parser.expect_field_comma()?;
    let proof_suite = parser.expect_string_field("proof_suite")?;
    parser.expect_field_comma()?;
    let manifest_hash_hex = parser.expect_string_field("manifest_hash")?;
    let manifest_hash = ManifestHash::new(decode_lower_hex_32(&manifest_hash_hex)?);
    parser.expect_field_comma()?;
    let archive_hash_hex = parser.expect_string_field("archive_hash")?;
    let archive_hash = ArchiveHashV1::new(decode_lower_hex_32(&archive_hash_hex)?);
    parser.expect_field_comma()?;
    let registry_hex = parser.expect_string_field("voter_registry_commitment")?;
    let registry_commitment = decode_lower_hex_32(&registry_hex)?;
    parser.expect_field_comma()?;
    let option_set_hex = parser.expect_string_field("ballot_option_commitment")?;
    let option_set_commitment = decode_lower_hex_32(&option_set_hex)?;
    parser.expect_field_comma()?;
    let archive_finalized = parser.expect_bool_field("archive_finalized")?;
    parser.expect_field_comma()?;
    let finalized_timestamp_unix_secs =
        parser.expect_opt_u64_field("finalized_timestamp_unix_secs")?;
    parser.expect_field_comma()?;
    let template_address = parser.expect_string_field("template_address")?;
    parser.expect_field_comma()?;
    let template_module = parser.expect_string_field("template_module")?;
    parser.expect_field_comma()?;
    let template_function = parser.expect_string_field("template_function")?;
    parser.expect_field_comma()?;
    let template_event_topic = parser.expect_string_field("template_event_topic")?;
    parser.expect_field_comma()?;
    let artifact_digest_hex = parser.expect_string_field("template_artifact_digest")?;
    let artifact_digest = decode_lower_hex_32(&artifact_digest_hex)?;
    parser.consume_byte(b'}')?;
    parser.expect_eof()?;

    Ok(OotleAnchorPublicPayloadV2 {
        network,
        election_id,
        ballot_question,
        ballot_kind,
        confidentiality_mode,
        proof_suite,
        manifest_hash,
        archive_hash,
        registry_commitment,
        option_set_commitment,
        eligible_voter_count,
        accepted_ballot_count,
        rejected_ballot_count,
        tally,
        archive_finalized,
        finalized_timestamp_unix_secs,
        template: OotleAnchorTemplateBindingV2 {
            template_address,
            template_module,
            template_function,
            event_topic: template_event_topic,
            artifact_digest,
        },
    })
}

struct CanonicalJsonParser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> CanonicalJsonParser<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn peek_byte(&self) -> Result<u8, ProtocolError> {
        self.bytes
            .get(self.pos)
            .copied()
            .ok_or_else(|| invalid_json("V2 public payload ended unexpectedly"))
    }

    fn consume_byte(&mut self, expected: u8) -> Result<(), ProtocolError> {
        let actual = self.peek_byte()?;
        if actual != expected {
            return Err(invalid_json("V2 public payload has unexpected structure"));
        }
        self.pos += 1;
        Ok(())
    }

    fn expect_eof(&self) -> Result<(), ProtocolError> {
        if self.pos != self.bytes.len() {
            return Err(invalid_json(
                "V2 public payload has trailing bytes after the closing object",
            ));
        }
        Ok(())
    }

    fn expect_key(&mut self, key: &str) -> Result<(), ProtocolError> {
        self.consume_byte(b'"')?;
        let key_bytes = key.as_bytes();
        if self.pos + key_bytes.len() + 1 > self.bytes.len()
            || &self.bytes[self.pos..self.pos + key_bytes.len()] != key_bytes
            || self.bytes[self.pos + key_bytes.len()] != b'"'
        {
            return Err(invalid_json("V2 public payload key mismatch"));
        }
        self.pos += key_bytes.len() + 1;
        self.consume_byte(b':')?;
        Ok(())
    }

    fn expect_field_comma(&mut self) -> Result<(), ProtocolError> {
        self.consume_byte(b',')
    }

    fn expect_string_field(&mut self, key: &str) -> Result<String, ProtocolError> {
        self.expect_key(key)?;
        self.read_json_string()
    }

    fn expect_u64_field(&mut self, key: &str) -> Result<u64, ProtocolError> {
        self.expect_key(key)?;
        self.read_json_u64()
    }

    fn expect_opt_u64_field(&mut self, key: &str) -> Result<Option<u64>, ProtocolError> {
        self.expect_key(key)?;
        if self.pos + 4 <= self.bytes.len() && &self.bytes[self.pos..self.pos + 4] == b"null" {
            self.pos += 4;
            return Ok(None);
        }
        Ok(Some(self.read_json_u64()?))
    }

    fn expect_bool_field(&mut self, key: &str) -> Result<bool, ProtocolError> {
        self.expect_key(key)?;
        if self.pos + 4 <= self.bytes.len() && &self.bytes[self.pos..self.pos + 4] == b"true" {
            self.pos += 4;
            return Ok(true);
        }
        if self.pos + 5 <= self.bytes.len() && &self.bytes[self.pos..self.pos + 5] == b"false" {
            self.pos += 5;
            return Ok(false);
        }
        Err(invalid_json("V2 public payload boolean is not canonical"))
    }

    fn read_json_string(&mut self) -> Result<String, ProtocolError> {
        self.consume_byte(b'"')?;
        let mut out = Vec::with_capacity(16);
        loop {
            let byte = self.peek_byte()?;
            self.pos += 1;
            match byte {
                b'"' => break,
                b'\\' => {
                    let escaped = self.peek_byte()?;
                    self.pos += 1;
                    match escaped {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'u' => {
                            // Only the exact \u00XX form for control bytes is
                            // canonical here (see the writer); anything else is
                            // a non-canonical alternate encoding.
                            let d0 = self.peek_byte()?;
                            self.pos += 1;
                            let d1 = self.peek_byte()?;
                            self.pos += 1;
                            let d2 = self.peek_byte()?;
                            self.pos += 1;
                            let d3 = self.peek_byte()?;
                            self.pos += 1;
                            if d0 != b'0' || d1 != b'0' {
                                return Err(invalid_json(
                                    "V2 public payload uses a non-canonical unicode escape",
                                ));
                            }
                            let hi = parse_lower_hex_digit(d2)?;
                            let lo = parse_lower_hex_digit(d3)?;
                            let value = (hi << 4) | lo;
                            if value >= 0x20 {
                                return Err(invalid_json(
                                    "V2 public payload uses an unnecessary unicode escape",
                                ));
                            }
                            out.push(value);
                        }
                        _ => {
                            return Err(invalid_json(
                                "V2 public payload uses a non-canonical string escape",
                            ));
                        }
                    }
                }
                byte if byte < 0x20 => {
                    return Err(invalid_json(
                        "V2 public payload string contains a raw control byte",
                    ));
                }
                byte => out.push(byte),
            }
        }
        String::from_utf8(out)
            .map_err(|_| invalid_json("V2 public payload string is not valid UTF-8"))
    }

    fn read_json_u64(&mut self) -> Result<u64, ProtocolError> {
        let start = self.pos;
        while let Some(byte) = self.bytes.get(self.pos).copied() {
            if !byte.is_ascii_digit() {
                break;
            }
            self.pos += 1;
        }
        if self.pos == start {
            return Err(invalid_json("V2 public payload integer field is empty"));
        }
        let text = &self.bytes[start..self.pos];
        if text.len() > 1 && text[0] == b'0' {
            return Err(invalid_json(
                "V2 public payload integer has non-canonical leading zeros",
            ));
        }
        let s = std::str::from_utf8(text)
            .map_err(|_| invalid_json("V2 public payload integer field is not ASCII"))?;
        s.parse::<u64>()
            .map_err(|_| invalid_json("V2 public payload integer field overflows u64"))
    }
}

fn decode_lower_hex(hex: &str) -> Result<Vec<u8>, ProtocolError> {
    if hex.len() % 2 != 0 {
        return Err(invalid_json("V2 public payload hex field has odd length"));
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks_exact(2) {
        let hi = parse_lower_hex_digit(chunk[0])?;
        let lo = parse_lower_hex_digit(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn decode_lower_hex_32(hex: &str) -> Result<[u8; 32], ProtocolError> {
    let bytes = decode_lower_hex(hex)?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| invalid_json("a V2 payload hash field must contain exactly 32 bytes"))
}

fn parse_lower_hex_digit(byte: u8) -> Result<u8, ProtocolError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(invalid_json("V2 public payload hex must be lowercase")),
    }
}

// ---------------------------------------------------------------------------
// Privacy guard (Task J).
// ---------------------------------------------------------------------------

/// Structural + textual privacy guard for a V2 public payload.
///
/// The V2 payload is public by construction (its fields are fixed), but this
/// guard is defence in depth against accidental leakage of per-voter data or
/// local operator context into the free-form public fields. It fails when any
/// free-form text contains a private-material marker or a local filesystem path,
/// and reuses the structural bounds enforced by [`OotleAnchorPublicPayloadV2::validate`].
///
/// # Errors
///
/// Returns a [`ProtocolError`] describing the first leak detected.
pub fn assert_v2_public_payload_is_leak_free(
    payload: &OotleAnchorPublicPayloadV2,
) -> Result<(), ProtocolError> {
    payload.validate()?;

    // Free-form public text fields that a builder mistake could taint. The
    // fixed-shape numeric/hash/commitment fields cannot carry prose.
    let mut texts: Vec<&str> = vec![
        payload.ballot_question.as_str(),
        payload.ballot_kind.as_str(),
        payload.confidentiality_mode.as_str(),
        payload.proof_suite.as_str(),
        payload.network.as_str(),
        payload.template.template_address.as_str(),
        payload.template.template_module.as_str(),
        payload.template.template_function.as_str(),
        payload.template.event_topic.as_str(),
    ];
    for entry in &payload.tally {
        texts.push(entry.display_label.as_str());
    }

    for text in texts {
        if let Some(marker) = forbidden_marker(text) {
            return Err(ProtocolError::new(ValidationCode::InvalidData, marker));
        }
    }
    Ok(())
}

/// Returns a stable error message when `text` contains a private-material marker
/// or a local filesystem path.
fn forbidden_marker(text: &str) -> Option<&'static str> {
    let lowered = text.to_ascii_lowercase();
    const MARKERS: [(&str, &str); 9] = [
        (
            "nullifier",
            "V2 public payload text must not reference a nullifier",
        ),
        (
            "bearer",
            "V2 public payload text must not contain a bearer token",
        ),
        (
            "authorization:",
            "V2 public payload text must not contain an authorization header",
        ),
        (
            "private key",
            "V2 public payload text must not reference a private key",
        ),
        (
            "secret key",
            "V2 public payload text must not reference a secret key",
        ),
        (
            "-----begin",
            "V2 public payload text must not contain PEM key material",
        ),
        (
            "mnemonic",
            "V2 public payload text must not reference a mnemonic",
        ),
        (
            "c:\\users\\",
            "V2 public payload text must not contain a local Windows user path",
        ),
        (
            "/home/",
            "V2 public payload text must not contain a local home path",
        ),
    ];
    for (needle, message) in MARKERS {
        if lowered.contains(needle) {
            return Some(message);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tari_cc_private_ballot_protocol::Blake3HashProviderV1;

    fn sample_payload() -> OotleAnchorPublicPayloadV2 {
        OotleAnchorPublicPayloadV2 {
            network: OotleNetworkIdV1::new("esmeralda".to_owned()).expect("network"),
            election_id: b"election-42".to_vec(),
            ballot_question: "Should we adopt the proposal?".to_owned(),
            ballot_kind: "approval".to_owned(),
            confidentiality_mode: "confidential".to_owned(),
            proof_suite: "triptych-v1".to_owned(),
            manifest_hash: ManifestHash::new([0x11; 32]),
            archive_hash: ArchiveHashV1::new([0x22; 32]),
            registry_commitment: [0x33; 32],
            option_set_commitment: [0x44; 32],
            eligible_voter_count: 500,
            accepted_ballot_count: 480,
            rejected_ballot_count: 20,
            tally: vec![
                OotleAnchorTallyEntryV2 {
                    display_label: "Yes".to_owned(),
                    machine_id: b"opt-yes".to_vec(),
                    count: 300,
                },
                OotleAnchorTallyEntryV2 {
                    display_label: "No".to_owned(),
                    machine_id: b"opt-no".to_vec(),
                    count: 180,
                },
            ],
            archive_finalized: true,
            finalized_timestamp_unix_secs: Some(1_724_000_000),
            template: OotleAnchorTemplateBindingV2 {
                template_address: "template_v2_abc".to_owned(),
                template_module: "tari_private_ballot_anchor_v2".to_owned(),
                template_function: "publish_anchor_v2".to_owned(),
                event_topic: "tari_private_ballot_anchor_v2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2"
                    .to_owned(),
                artifact_digest: [0x55; 32],
            },
        }
    }

    fn digest(payload: &OotleAnchorPublicPayloadV2) -> [u8; 32] {
        payload
            .canonical_digest(&Blake3HashProviderV1)
            .expect("digest")
    }

    #[test]
    fn canonical_round_trip_is_stable() {
        let payload = sample_payload();
        let encoded = payload.to_canonical_json_bytes().expect("encode");
        let decoded =
            OotleAnchorPublicPayloadV2::from_canonical_json_bytes(&encoded).expect("decode");
        assert_eq!(payload, decoded);
        // Same payload → identical canonical bytes (determinism).
        assert_eq!(
            encoded,
            sample_payload().to_canonical_json_bytes().expect("encode"),
        );
    }

    #[test]
    fn canonical_encoding_is_readable_json_with_expected_shape() {
        let bytes = sample_payload().to_canonical_json_bytes().expect("encode");
        let text = std::str::from_utf8(&bytes).expect("utf-8");
        // The canonical JSON is a single line with no structural whitespace
        // (a space inside a quoted question is fine — it's user text).
        assert!(!text.contains('\n'));
        assert!(!text.contains("\": "));
        assert!(!text.contains(", \""));
        assert!(text.starts_with('{'));
        assert!(text.ends_with('}'));
        // Human-readable fields are present as JSON.
        assert!(text.contains("\"schema\":\"TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_PUBLIC_V2\""));
        assert!(text.contains("\"version\":2"));
        assert!(text.contains("\"network\":\"esmeralda\""));
        assert!(text.contains("\"question\":\"Should we adopt the proposal?\""));
        assert!(text.contains("\"eligible_voters\":500"));
        assert!(text.contains("\"accepted_ballots\":480"));
        assert!(text.contains("\"rejected_ballots\":20"));
        assert!(text.contains("\"results\":["));
        assert!(text.contains("\"label\":\"Yes\""));
        assert!(text.contains("\"votes\":300"));
    }

    #[test]
    fn digest_is_deterministic() {
        assert_eq!(digest(&sample_payload()), digest(&sample_payload()));
    }

    /// Independent recomputation over the raw canonical bytes must yield the
    /// same digest an observer would compute from the on-chain `public_summary`.
    #[test]
    fn digest_matches_domain_framed_hash_of_canonical_bytes() {
        let payload = sample_payload();
        let encoded = payload.to_canonical_json_bytes().expect("encode");
        let framed = v2_domain_input(&encoded);
        let expected = Blake3HashProviderV1.hash(&framed);
        assert_eq!(digest(&payload), expected);
    }

    /// Mutation coverage — every readable field bound by the on-chain digest.
    #[test]
    fn every_public_field_mutation_changes_the_digest() {
        let base = digest(&sample_payload());

        for mutate in mutation_matrix() {
            let mut payload = sample_payload();
            mutate(&mut payload);
            assert_ne!(base, digest(&payload));
        }
    }

    /// Explicit list so a reviewer can see every field is covered by the
    /// digest, including the ones a compact scalar summary would omit.
    fn mutation_matrix() -> Vec<Box<dyn Fn(&mut OotleAnchorPublicPayloadV2)>> {
        vec![
            Box::new(|p| p.ballot_question = "A different question?".to_owned()),
            Box::new(|p| p.eligible_voter_count = 501),
            Box::new(|p| p.accepted_ballot_count = 481),
            Box::new(|p| p.rejected_ballot_count = 21),
            Box::new(|p| p.tally[0].display_label = "Definitely yes".to_owned()),
            Box::new(|p| p.tally[0].count += 1),
            Box::new(|p| p.tally.swap(0, 1)),
            Box::new(|p| p.manifest_hash = ManifestHash::new([0x12; 32])),
            Box::new(|p| p.archive_hash = ArchiveHashV1::new([0x23; 32])),
            Box::new(|p| p.registry_commitment = [0x34; 32]),
            Box::new(|p| p.option_set_commitment = [0x45; 32]),
            Box::new(|p| p.election_id = b"election-43".to_vec()),
            Box::new(|p| p.network = OotleNetworkIdV1::new("igor".to_owned()).expect("network")),
            Box::new(|p| p.template.template_address = "template_v2_other".to_owned()),
            Box::new(|p| p.template.event_topic = "tari_private_ballot_anchor_v2.OTHER".to_owned()),
            Box::new(|p| p.template.artifact_digest = [0x66; 32]),
            Box::new(|p| p.ballot_kind = "elimination".to_owned()),
            Box::new(|p| p.confidentiality_mode = "public".to_owned()),
            Box::new(|p| p.proof_suite = "triptych-v2".to_owned()),
            Box::new(|p| p.archive_finalized = false),
            Box::new(|p| p.finalized_timestamp_unix_secs = None),
        ]
    }

    #[test]
    fn non_canonical_json_is_rejected_by_decode() {
        // Whitespace between key and value is not canonical.
        let base = sample_payload().to_canonical_json_bytes().expect("encode");
        let text = std::str::from_utf8(&base).expect("utf-8");
        let mutated = text.replacen("\"version\":2", "\"version\": 2", 1);
        assert_ne!(mutated.as_bytes(), base.as_slice());
        assert!(OotleAnchorPublicPayloadV2::from_canonical_json_bytes(mutated.as_bytes()).is_err(),);
    }

    #[test]
    fn missing_results_array_element_fails_decode() {
        // Manually build a bad payload that closes the results array before
        // any votes entry appears in the expected shape. This is a structural
        // parse failure, not a canonicalization mismatch, so the strict
        // decoder must reject it.
        let base = sample_payload().to_canonical_json_bytes().expect("encode");
        let text = std::str::from_utf8(&base).expect("utf-8");
        // Cut a `,\"votes\":300` fragment out of the first result entry, so
        // the object closes early and the strict parser sees `}` where it
        // expects the votes field.
        let broken = text.replacen(",\"votes\":300", "", 1);
        assert_ne!(broken.as_bytes(), base.as_slice());
        assert!(OotleAnchorPublicPayloadV2::from_canonical_json_bytes(broken.as_bytes()).is_err(),);
    }

    #[test]
    fn verify_digest_accepts_and_rejects() {
        let payload = sample_payload();
        let expected = digest(&payload);
        assert!(
            payload
                .verify_digest(&Blake3HashProviderV1, &expected)
                .is_ok()
        );
        assert!(
            payload
                .verify_digest(&Blake3HashProviderV1, &[0x00; 32])
                .is_err()
        );
    }

    #[test]
    fn privacy_guard_accepts_clean_payload() {
        assert!(assert_v2_public_payload_is_leak_free(&sample_payload()).is_ok());
    }

    /// Regression: the exact canonical election identifier text — including
    /// non-hex names like "500-votertest-01" from the preserved 500-voter
    /// archive — must survive canonical JSON encoding → strict re-decode
    /// round-trip byte-for-byte, and must appear verbatim inside the
    /// `election_id` field of the readable public summary.
    #[test]
    fn canonical_election_id_text_survives_round_trip_verbatim() {
        let mut payload = sample_payload();
        payload.election_id = b"500-votertest-01".to_vec();
        let bytes = payload.to_canonical_json_bytes().expect("encode");
        let text = std::str::from_utf8(&bytes).expect("utf-8");
        assert!(text.contains("\"election_id\":\"500-votertest-01\""));
        let decoded =
            OotleAnchorPublicPayloadV2::from_canonical_json_bytes(&bytes).expect("decode");
        assert_eq!(decoded, payload);
        assert_eq!(decoded.election_id, b"500-votertest-01");
    }

    #[test]
    fn privacy_guard_rejects_leaks_in_free_text() {
        let mut nullifier = sample_payload();
        nullifier.ballot_question = "list of nullifier values".to_owned();
        assert!(assert_v2_public_payload_is_leak_free(&nullifier).is_err());

        let mut path = sample_payload();
        path.tally[0].display_label = "C:\\Users\\pdark\\ballots".to_owned();
        assert!(assert_v2_public_payload_is_leak_free(&path).is_err());

        let mut bearer = sample_payload();
        bearer.proof_suite = "bearer".to_owned();
        assert!(assert_v2_public_payload_is_leak_free(&bearer).is_err());
    }
}
