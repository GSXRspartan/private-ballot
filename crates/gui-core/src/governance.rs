//! Governance source pinning, document digesting, and reference matching
//! (Slice 5A8).
//!
//! Implements the ADR-0008 process-hardening requirements that must hold before
//! voter credential/proof generation begins. This module still treats the
//! manifest's `governance_source_revision` as opaque bound text; schema-specific
//! canonical manifest changes live in the ballot crate.
//!
//! ## `governance_source_revision` protocol semantics (unchanged)
//!
//! The manifest field remains an opaque, non-empty, bounded UTF-8 string that
//! is canonical and manifest-hash bound but **not** cryptographically
//! interpreted by the protocol. This module adds an **application-level**
//! policy that accepts only clearly immutable, locally verifiable reference
//! formats for the Governance Pilot. It never reinterprets arbitrary user text
//! and never contacts a network.
//!
//! ## Accepted immutable pin formats
//!
//! 1. **Content digest (recommended)** — `blake3:<64 lowercase hex>`. The hex
//!    is the project's domain-separated `ArchiveFileV1` BLAKE3-256 digest of
//!    the governance document's exact raw bytes — the **same** digest the
//!    archive content catalog records for the archived governance document.
//!    Reusing the existing `ArchiveFileV1` domain keeps a single digest
//!    identity across the pin, the document evidence, and the archive: when the
//!    pin matches the document, the archive's own per-file digest verification
//!    covers it automatically. No new hash algorithm or domain is introduced.
//! 2. **Git commit SHA (advanced)** — `git:<40 lowercase hex>`. The application
//!    validates the format only. It cannot cryptographically prove a selected
//!    local file corresponds to that Git commit without repository history
//!    access, so correspondence is reported as **operator-attested**, never
//!    "verified".
//!
//! Hex digits are normalized to lowercase in the **advisory** parsed pin
//! representation only; the exact user-supplied `governance_source_revision`
//! string remains the canonical manifest field and is not rewritten. Mutable
//! phrases such as `latest`, `main`, or `forum post` are reported as
//! `UNRECOGNIZED`.
//!
//! ## No secrets
//!
//! Document bytes are non-secret governance content. No voter secret, wallet
//! seed, mnemonic, or signing material is ever read or returned.

use std::path::Path;

use tari_cc_private_ballot_protocol::{
    Blake3HashProviderV1, HashDomain, MAX_GOVERNANCE_REVISION_BYTES, hash_domain_separated,
};

use crate::error::{GuiCoreError, GuiErrorCategory};
use crate::hex::to_lower_hex;

/// Prefix for the recommended content-digest pin form.
pub const GOVERNANCE_PIN_PREFIX_BLAKE3: &str = "blake3:";
/// Prefix for the advanced Git commit SHA pin form.
pub const GOVERNANCE_PIN_PREFIX_GIT: &str = "git:";
/// Hex length of a 32-byte BLAKE3-256 digest.
pub const BLAKE3_DIGEST_HEX_LEN: usize = 64;
/// Hex length of a 20-byte Git commit SHA-1.
pub const GIT_SHA_HEX_LEN: usize = 40;

/// Conservative pilot maximum for one governance document (50 MiB). Ordinary
/// PDFs and Markdown exports are well under this bound; the metadata length is
/// checked before any byte is read, so an oversized or hostile file is rejected
/// without allocation.
pub const MAX_GOVERNANCE_DOCUMENT_BYTES: usize = 50 * 1024 * 1024;

/// Project-controlled, path-traversal-safe archive path for the governance
/// document. The original organizer filename is never used as the archive path;
/// it is carried separately in DTO metadata only. The path satisfies the
/// existing `ArchivePathV1` portable profile (relative, `/`-only, no
/// traversal/reserved segments).
pub const GOVERNANCE_DOCUMENT_ARCHIVE_PATH: &str = "governance/source.bin";

/// Stable machine-readable kind code for a governance source pin.
pub const PIN_KIND_BLAKE3_DIGEST: &str = "BLAKE3_DIGEST";
/// Stable machine-readable kind code for a Git commit SHA pin.
pub const PIN_KIND_GIT_COMMIT: &str = "GIT_COMMIT";
/// Stable machine-readable kind code for an unrecognized (mutable/ambiguous)
/// reference. The protocol still accepts the string; this is an
/// application-level advisory status only.
pub const PIN_KIND_UNRECOGNIZED: &str = "UNRECOGNIZED";

/// Structured validation result for one `governance_source_revision` string.
///
/// `format_valid` is true only when the string matches an accepted immutable
/// pin syntax. **Format validity is not cryptographic verification** — it only
/// means the reference has an immutable shape. A green "Matched" status is
/// reported separately by [`match_governance_document`] once the document
/// digest has actually been compared.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiGovernanceSourcePinV1 {
    /// The exact user-supplied `governance_source_revision` string after
    /// accepted hex-case normalization (lowercased hex digits). This is an
    /// advisory/parsed normalized representation for display and matching only;
    /// it is **not** the canonical manifest field. The canonical manifest
    /// carries the exact user-supplied `governance_source_revision` string
    /// verbatim — this slice does not rewrite canonical bytes (for example,
    /// uppercase hex input remains uppercase in the manifest). Persisting the
    /// normalized form in place of the raw string is out of scope.
    pub normalized: String,
    /// Stable machine-readable kind code (`BLAKE3_DIGEST`, `GIT_COMMIT`, or
    /// `UNRECOGNIZED`).
    pub kind: &'static str,
    /// True when the string matches an accepted immutable pin syntax.
    pub format_valid: bool,
    /// The decoded lowercase-hex digest for a `blake3:` pin, when present.
    pub digest_hex: Option<String>,
    /// The decoded lowercase-hex Git SHA for a `git:` pin, when present.
    pub git_sha_hex: Option<String>,
    /// Calm, professional user-facing status message.
    pub message: &'static str,
}

impl GuiGovernanceSourcePinV1 {
    /// Returns whether this pin is the locally-verifiable content-digest form.
    #[must_use]
    pub fn is_content_digest(&self) -> bool {
        self.kind == PIN_KIND_BLAKE3_DIGEST && self.format_valid
    }

    /// Returns whether this pin is the Git commit SHA form (format valid).
    #[must_use]
    pub fn is_git_commit(&self) -> bool {
        self.kind == PIN_KIND_GIT_COMMIT && self.format_valid
    }
}

/// Computes the project domain-separated `ArchiveFileV1` BLAKE3-256 digest of
/// the exact raw document bytes. This is the same digest the archive content
/// catalog records for the governance document, so pin ↔ document ↔ archive
/// share one digest identity.
#[must_use]
pub fn governance_document_digest_for_bytes(bytes: &[u8]) -> [u8; 32] {
    hash_domain_separated(
        &Blake3HashProviderV1,
        HashDomain::ArchiveFileV1,
        bytes,
    )
}

/// Metadata for one selected governance document (non-secret).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiGovernanceDocumentDigestV1 {
    /// Safe display filename (the leaf name of the selected path, sanitized for
    /// display only; never used as an archive path).
    pub display_filename: String,
    /// Exact byte size of the document.
    pub bytes: u64,
    /// Hash-algorithm identifier (the production BLAKE3-256 provider id).
    pub digest_algorithm_id: &'static str,
    /// Domain-separated `ArchiveFileV1` BLAKE3-256 digest of the raw bytes,
    /// lowercase hex.
    pub digest_hex: String,
}

/// Status of matching a governance document digest against the bound
/// `governance_source_revision` pin.
///
/// `Matched` is reported **only** when the content-digest pin and the document
/// digest are byte-equal. A Git commit SHA pin can never be `Matched` locally;
/// it is `OperatorAttested` when a document has been selected, or
/// `UnverifiedReference` when no document is available. `NotApplicable` is
/// used when the bound revision is not a recognized immutable pin format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum GuiGovernanceMatchStatusV1 {
    Matched,
    Mismatch,
    OperatorAttested,
    UnverifiedReference,
    NotApplicable,
}

impl GuiGovernanceMatchStatusV1 {
    /// Stable machine-readable status code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Matched => "MATCHED",
            Self::Mismatch => "MISMATCH",
            Self::OperatorAttested => "OPERATOR_ATTESTED",
            Self::UnverifiedReference => "UNVERIFIED_REFERENCE",
            Self::NotApplicable => "NOT_APPLICABLE",
        }
    }

    /// Calm, professional user-facing label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Matched => "Digest matches bound governance source",
            Self::Mismatch => "Document digest does not match the bound reference",
            Self::OperatorAttested => {
                "Reference is immutable-format; document correspondence is not independently verified by this application."
            }
            Self::UnverifiedReference => {
                "Reference is immutable-format; no governance document has been selected."
            }
            Self::NotApplicable => {
                "Bound reference is not a recognized immutable pin format; document matching does not apply."
            }
        }
    }

    /// Returns true only when the document digest has been cryptographically
    /// matched to the bound content-digest pin.
    #[must_use]
    pub const fn is_cryptographically_matched(self) -> bool {
        matches!(self, Self::Matched)
    }
}

/// Distinct application-level fact reported by archive verification about the
/// relationship between the bound `governance_source_revision` pin and the
/// archived `governance/source.bin` document (Slice 5A8 hardening).
///
/// This fact is **separate from** archive internal integrity
/// ([`crate::archive_verify::GuiArchiveVerificationV1::verified`]). Archive
/// integrity proves the catalog digests match the on-disk bytes and the archive
/// hash rebuilds; it does **not** prove the archived governance document
/// matches the manifest's bound pin. This fact closes that gap for
/// content-digest (`blake3:`) pins and reports Git SHA pins honestly as
/// operator-attested.
///
/// The UI must not collapse archive integrity and governance-source
/// correspondence into one ambiguous "Verified" badge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum GuiGovernanceArchivePinFactV1 {
    /// The manifest binds a `blake3:` content-digest pin, the archived
    /// `governance/source.bin` is present, its archive catalog digest
    /// verifies, and that digest equals the digest encoded in the pin. The
    /// archived governance document cryptographically matches the bound pin.
    Matched,
    /// The manifest binds a `blake3:` content-digest pin and the archived
    /// `governance/source.bin` is present and catalog-verified, but its digest
    /// does not equal the pin digest. The archive is internally consistent but
    /// contains the wrong governance document for the bound pin.
    Mismatch,
    /// The manifest binds a `blake3:` content-digest pin but the archived
    /// `governance/source.bin` is absent. The pin cannot be checked.
    Missing,
    /// The manifest binds a `git:` commit SHA pin. The archive may contain a
    /// governance document, but its correspondence to the Git commit is not
    /// cryptographically verified by this application; it is
    /// operator-attested only. The UI must not display "Verified" for this
    /// case.
    OperatorAttested,
    /// The bound `governance_source_revision` is not a recognized immutable
    /// pin format (or no governance source pin applies), so no archive
    /// governance-pin cross-check is performed. The archive remains valid on
    /// its own integrity.
    NotApplicable,
}

impl GuiGovernanceArchivePinFactV1 {
    /// Stable machine-readable status code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Matched => "MATCHED",
            Self::Mismatch => "MISMATCH",
            Self::Missing => "MISSING",
            Self::OperatorAttested => "OPERATOR_ATTESTED",
            Self::NotApplicable => "NOT_APPLICABLE",
        }
    }

    /// Calm, professional user-facing label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Matched => "Matched",
            Self::Mismatch => "Mismatch",
            Self::Missing => "Missing",
            Self::OperatorAttested => "Operator-attested",
            Self::NotApplicable => "Not applicable",
        }
    }

    /// Returns true only for the cryptographically matched case.
    #[must_use]
    pub const fn is_matched(self) -> bool {
        matches!(self, Self::Matched)
    }
}

/// Structured result of matching a governance document against a bound pin.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiGovernanceDocumentStatusV1 {
    /// The bound `governance_source_revision` string.
    pub governance_source_revision: String,
    /// Validation of the bound pin format.
    pub pin: GuiGovernanceSourcePinV1,
    /// The selected document digest, when one is available.
    pub document: Option<GuiGovernanceDocumentDigestV1>,
    /// The match status.
    pub status: GuiGovernanceMatchStatusV1,
    /// User-facing status label.
    pub status_label: &'static str,
}

/// Validates one `governance_source_revision` string as an immutable source
/// pin. Performs no network resolution and reads no files.
///
/// The input is parsed into an advisory normalized representation (hex digits
/// lowercased) used for display and matching only. The canonical manifest
/// continues to carry the exact user-supplied `governance_source_revision`
/// string verbatim; this function does not rewrite canonical bytes.
/// `UNRECOGNIZED` strings are reported with `format_valid = false` but are
/// **not** rejected by the protocol; the caller (organizer facade) decides
/// whether to gate freeze on format validity. For the pilot, format validity
/// is advisory in the preview; only a content-digest mismatch against a
/// selected document hard-blocks freeze.
#[must_use]
pub fn validate_governance_source_pin(revision: &str) -> GuiGovernanceSourcePinV1 {
    if revision.len() > MAX_GOVERNANCE_REVISION_BYTES {
        return GuiGovernanceSourcePinV1 {
            normalized: revision.to_owned(),
            kind: PIN_KIND_UNRECOGNIZED,
            format_valid: false,
            digest_hex: None,
            git_sha_hex: None,
            message: "Use an immutable Git commit or content digest.",
        };
    }

    if let Some(hex_part) = revision.strip_prefix(GOVERNANCE_PIN_PREFIX_BLAKE3) {
        return classify_blake3(hex_part);
    }
    if let Some(hex_part) = revision.strip_prefix(GOVERNANCE_PIN_PREFIX_GIT) {
        return classify_git(hex_part);
    }
    unrecognized(revision)
}

fn classify_blake3(hex_part: &str) -> GuiGovernanceSourcePinV1 {
    let normalized_hex = hex_part.to_ascii_lowercase();
    let normalized = format!("{GOVERNANCE_PIN_PREFIX_BLAKE3}{normalized_hex}");
    if hex_part.len() == BLAKE3_DIGEST_HEX_LEN && is_lowercase_hex(&normalized_hex) {
        return GuiGovernanceSourcePinV1 {
            normalized,
            kind: PIN_KIND_BLAKE3_DIGEST,
            format_valid: true,
            digest_hex: Some(normalized_hex),
            git_sha_hex: None,
            message: "Valid immutable reference format.",
        };
    }
    GuiGovernanceSourcePinV1 {
        normalized,
        kind: PIN_KIND_UNRECOGNIZED,
        format_valid: false,
        digest_hex: None,
        git_sha_hex: None,
        message: "Malformed content digest; use blake3:<64 hex>.",
    }
}

fn classify_git(hex_part: &str) -> GuiGovernanceSourcePinV1 {
    let normalized_hex = hex_part.to_ascii_lowercase();
    let normalized = format!("{GOVERNANCE_PIN_PREFIX_GIT}{normalized_hex}");
    if hex_part.len() == GIT_SHA_HEX_LEN && is_lowercase_hex(&normalized_hex) {
        return GuiGovernanceSourcePinV1 {
            normalized,
            kind: PIN_KIND_GIT_COMMIT,
            format_valid: true,
            digest_hex: None,
            git_sha_hex: Some(normalized_hex),
            message: "Valid immutable reference format.",
        };
    }
    GuiGovernanceSourcePinV1 {
        normalized,
        kind: PIN_KIND_UNRECOGNIZED,
        format_valid: false,
        digest_hex: None,
        git_sha_hex: None,
        message: "Malformed Git commit SHA; use git:<40 hex>.",
    }
}

fn unrecognized(revision: &str) -> GuiGovernanceSourcePinV1 {
    // Reject leading/trailing whitespace ambiguity and whitespace-only inputs.
    let trimmed = revision.trim();
    if trimmed.is_empty() || trimmed.len() != revision.len() {
        return GuiGovernanceSourcePinV1 {
            normalized: revision.to_owned(),
            kind: PIN_KIND_UNRECOGNIZED,
            format_valid: false,
            digest_hex: None,
            git_sha_hex: None,
            message: "Use an immutable Git commit or content digest.",
        };
    }
    GuiGovernanceSourcePinV1 {
        normalized: revision.to_owned(),
        kind: PIN_KIND_UNRECOGNIZED,
        format_valid: false,
        digest_hex: None,
        git_sha_hex: None,
        message: "Use an immutable Git commit or content digest.",
    }
}

fn is_lowercase_hex(text: &str) -> bool {
    text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Reads and digests one local governance document. Rejects directories,
/// symlinks, special devices, and oversized files **before** allocating. The
/// document is treated as immutable raw bytes; no PDF/Markdown semantic
/// parsing is performed. Performs no network access.
///
/// # Errors
///
/// Returns a bounded [`GuiCoreError`] for missing, non-regular, symlink,
/// oversized, or unreadable files.
pub fn compute_governance_document_digest(
    path: &Path,
) -> Result<GuiGovernanceDocumentDigestV1, GuiCoreError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            GuiCoreError::file_not_found("governance-document")
        } else {
            GuiCoreError::io_failure("governance-document")
        }
    })?;

    // Reject symlinks: never follow. The pilot policy treats a symlinked
    // governance document as an unsafe source because its target can change.
    if metadata.is_symlink() {
        return Err(GuiCoreError::governance_document_symlink());
    }
    if metadata.is_dir() {
        return Err(GuiCoreError::governance_document_is_directory());
    }
    if !metadata.is_file() {
        return Err(GuiCoreError::io_failure("governance-document"));
    }
    let size = metadata.len();
    if size > MAX_GOVERNANCE_DOCUMENT_BYTES as u64 {
        return Err(GuiCoreError::governance_document_too_large());
    }

    let bytes = std::fs::read(path).map_err(|_| GuiCoreError::io_failure("governance-document"))?;
    // Defensive: re-check the actual read length.
    if bytes.len() > MAX_GOVERNANCE_DOCUMENT_BYTES {
        return Err(GuiCoreError::governance_document_too_large());
    }

    let display_filename = safe_display_filename(path);
    let digest = governance_document_digest_for_bytes(&bytes);

    Ok(GuiGovernanceDocumentDigestV1 {
        display_filename,
        bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        digest_algorithm_id: tari_cc_private_ballot_protocol::BLAKE3_256_HASH_ALGORITHM_ID_V1,
        digest_hex: to_lower_hex(&digest),
    })
}

/// Matches a governance document digest against a bound
/// `governance_source_revision` pin. Pure: no I/O, no network.
#[must_use]
pub fn match_governance_document(
    revision: &str,
    document: Option<&GuiGovernanceDocumentDigestV1>,
) -> GuiGovernanceDocumentStatusV1 {
    let pin = validate_governance_source_pin(revision);
    let status = match (pin.kind, &pin.digest_hex, document) {
        (PIN_KIND_BLAKE3_DIGEST, Some(digest_hex), Some(doc)) => {
            if *digest_hex == doc.digest_hex {
                GuiGovernanceMatchStatusV1::Matched
            } else {
                GuiGovernanceMatchStatusV1::Mismatch
            }
        }
        (PIN_KIND_BLAKE3_DIGEST, Some(_), None) => GuiGovernanceMatchStatusV1::UnverifiedReference,
        (PIN_KIND_GIT_COMMIT, _, Some(_)) => GuiGovernanceMatchStatusV1::OperatorAttested,
        (PIN_KIND_GIT_COMMIT, _, None) => GuiGovernanceMatchStatusV1::UnverifiedReference,
        _ => GuiGovernanceMatchStatusV1::NotApplicable,
    };
    GuiGovernanceDocumentStatusV1 {
        governance_source_revision: revision.to_owned(),
        pin,
        document: document.cloned(),
        status,
        status_label: status.label(),
    }
}

/// Derives the leaf filename for display only. The result is sanitized to a
/// display string and is **never** used as an archive path (the archive path is
/// the fixed [`GOVERNANCE_DOCUMENT_ARCHIVE_PATH`]). Path separators, drive
/// prefixes, and traversal segments in the original path are replaced.
fn safe_display_filename(path: &Path) -> String {
    let leaf = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "governance-document".to_owned());
    // Strip any path separators or nulls that could appear on hostile inputs,
    // and bound the length for safe display.
    let sanitized: String = leaf
        .chars()
        .filter(|c| !matches!(c, '\\' | '/' | '\0') && !c.is_control())
        .take(255)
        .collect();
    if sanitized.is_empty() {
        "governance-document".to_owned()
    } else {
        sanitized
    }
}

/// Builds the canonical `blake3:<digest>` pin string from raw document bytes.
/// Convenience for the organizer "use this document digest" action.
#[must_use]
pub fn content_digest_pin_for_bytes(bytes: &[u8]) -> String {
    let digest = governance_document_digest_for_bytes(bytes);
    format!("{GOVERNANCE_PIN_PREFIX_BLAKE3}{}", to_lower_hex(&digest))
}

/// Reads governance document bytes bounded by the pilot limit, returning both
/// the bytes and the digest metadata derived from the **same single read**.
/// Used by the organizer draft to retain the document for archive inclusion.
///
/// Performs safety metadata checks first (symlink rejection, regular-file
/// check, 50 MiB cap), then reads the bounded file once, then computes the
/// digest metadata from those exact in-memory bytes. This avoids a double
/// allocation/read and removes the pathological local race where returned
/// bytes and a displayed digest could correspond to different file versions.
///
/// # Errors
///
/// Returns a bounded [`GuiCoreError`] on any validation or I/O failure.
pub fn read_governance_document(
    path: &Path,
) -> Result<(Vec<u8>, GuiGovernanceDocumentDigestV1), GuiCoreError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            GuiCoreError::file_not_found("governance-document")
        } else {
            GuiCoreError::io_failure("governance-document")
        }
    })?;
    if metadata.is_symlink() {
        return Err(GuiCoreError::governance_document_symlink());
    }
    if metadata.is_dir() {
        return Err(GuiCoreError::governance_document_is_directory());
    }
    if !metadata.is_file() {
        return Err(GuiCoreError::io_failure("governance-document"));
    }
    if metadata.len() > MAX_GOVERNANCE_DOCUMENT_BYTES as u64 {
        return Err(GuiCoreError::governance_document_too_large());
    }
    let bytes = std::fs::read(path).map_err(|_| GuiCoreError::io_failure("governance-document"))?;
    // Defensive post-read size sanity check: the metadata length is a hint, not
    // a guarantee (the file could be mutated between stat and read). Enforce
    // the bound on the actual bytes we will archive and digest.
    if bytes.len() > MAX_GOVERNANCE_DOCUMENT_BYTES {
        return Err(GuiCoreError::governance_document_too_large());
    }

    let display_filename = safe_display_filename(path);
    let digest = governance_document_digest_for_bytes(&bytes);
    let digest_meta = GuiGovernanceDocumentDigestV1 {
        display_filename,
        bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        digest_algorithm_id: tari_cc_private_ballot_protocol::BLAKE3_256_HASH_ALGORITHM_ID_V1,
        digest_hex: to_lower_hex(&digest),
    };
    Ok((bytes, digest_meta))
}

impl GuiCoreError {
    /// The selected governance document path is a symlink; pilot policy rejects
    /// symlinks because their target can change after freezing.
    #[must_use]
    pub const fn governance_document_symlink() -> Self {
        Self::new(
            "GUI_GOVERNANCE_DOCUMENT_SYMLINK",
            GuiErrorCategory::InvalidInput,
            Some("governance-document"),
            "governance document must not be a symlink",
        )
    }

    /// The selected governance document path is a directory.
    #[must_use]
    pub const fn governance_document_is_directory() -> Self {
        Self::new(
            "GUI_GOVERNANCE_DOCUMENT_IS_DIRECTORY",
            GuiErrorCategory::InvalidInput,
            Some("governance-document"),
            "governance document must be a regular file, not a directory",
        )
    }

    /// The selected governance document exceeds the pilot size limit.
    #[must_use]
    pub const fn governance_document_too_large() -> Self {
        Self::new(
            "GUI_GOVERNANCE_DOCUMENT_TOO_LARGE",
            GuiErrorCategory::InvalidInput,
            Some("governance-document"),
            "governance document exceeds the pilot size limit",
        )
    }

    /// A content-digest governance pin does not match the selected document
    /// digest. Freeze is blocked because the organizer is claiming a
    /// cryptographic match that does not hold. Also used at archive write time
    /// when the bytes being archived do not match the bound content-digest pin.
    #[must_use]
    pub const fn governance_digest_mismatch() -> Self {
        Self::new(
            "GUI_GOVERNANCE_DIGEST_MISMATCH",
            GuiErrorCategory::BindingMismatch,
            Some("governance-document"),
            "the governance source revision digest does not match the selected document",
        )
    }

    /// At archive verification, the manifest binds a content-digest
    /// (`blake3:`) governance source pin, the archived `governance/source.bin`
    /// is present and its catalog digest verifies, but that catalog digest does
    /// not equal the digest encoded in the bound pin. The archive is internally
    /// catalog-consistent but contains the wrong governance document for the
    /// bound pin. This is the verify-time counterpart of the write-time
    /// [`GuiCoreError::governance_digest_mismatch`] gate, expressed against the
    /// already-verified archive catalog rather than the organizer's selected
    /// document.
    #[must_use]
    pub const fn governance_archive_pin_mismatch() -> Self {
        Self::new(
            "GUI_GOVERNANCE_ARCHIVE_PIN_MISMATCH",
            GuiErrorCategory::ArchiveIntegrity,
            Some("governance-document"),
            "the archived governance document digest does not match the manifest governance source pin",
        )
    }

    /// At archive verification, the manifest binds a content-digest
    /// (`blake3:`) governance source pin, but the archived
    /// `governance/source.bin` content file is absent. A content-digest pin
    /// cryptographically commits to a specific document, so the document must
    /// be present for the pin to be checkable; its absence is an explicit
    /// governance-pin failure, not a generic optional-content omission.
    #[must_use]
    pub const fn governance_archive_document_missing() -> Self {
        Self::new(
            "GUI_GOVERNANCE_ARCHIVE_DOCUMENT_MISSING",
            GuiErrorCategory::ArchiveIntegrity,
            Some("governance-document"),
            "the manifest pins a governance content digest but the governance document is absent from the archive",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_BLAKE3_HEX: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const VALID_BLAKE3: &str = "blake3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const VALID_GIT: &str = "git:0123456789abcdef0123456789abcdef01234567";

    fn strip_blake3(pin: &str) -> &str {
        match pin.strip_prefix(GOVERNANCE_PIN_PREFIX_BLAKE3) {
            Some(rest) => rest,
            None => panic!("test pin must start with blake3: prefix"),
        }
    }

    #[test]
    fn lowercase_hex_predicate_is_strict() {
        assert!(is_lowercase_hex("0123456789abcdef"));
        assert!(!is_lowercase_hex("0123ABCDEF"));
        assert!(!is_lowercase_hex("zz"));
        assert!(is_lowercase_hex(""));
    }

    #[test]
    fn valid_blake3_pin_is_accepted_and_normalizes_case() {
        let upper = format!(
            "{GOVERNANCE_PIN_PREFIX_BLAKE3}{}",
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
        );
        let pin = validate_governance_source_pin(&upper);
        assert!(pin.format_valid);
        assert_eq!(pin.kind, PIN_KIND_BLAKE3_DIGEST);
        assert_eq!(pin.digest_hex.as_deref(), Some(VALID_BLAKE3_HEX));
        assert_eq!(pin.normalized, VALID_BLAKE3);
        assert!(pin.is_content_digest());
    }

    #[test]
    fn malformed_blake3_length_is_rejected() {
        let pin = validate_governance_source_pin("blake3:abcd");
        assert!(!pin.format_valid);
        assert_eq!(pin.kind, PIN_KIND_UNRECOGNIZED);
    }

    #[test]
    fn non_hex_blake3_is_rejected() {
        let bad = format!("{GOVERNANCE_PIN_PREFIX_BLAKE3}{}", "z".repeat(BLAKE3_DIGEST_HEX_LEN));
        let pin = validate_governance_source_pin(&bad);
        assert!(!pin.format_valid);
    }

    #[test]
    fn uppercase_blake3_hex_is_accepted_after_normalization() {
        let mixed = format!(
            "{GOVERNANCE_PIN_PREFIX_BLAKE3}{}",
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
        );
        let pin = validate_governance_source_pin(&mixed);
        assert!(pin.format_valid);
        assert_eq!(pin.normalized, VALID_BLAKE3);
    }

    #[test]
    fn valid_git_sha_is_accepted() {
        let pin = validate_governance_source_pin(VALID_GIT);
        assert!(pin.format_valid);
        assert_eq!(pin.kind, PIN_KIND_GIT_COMMIT);
        assert!(pin.is_git_commit());
    }

    #[test]
    fn malformed_git_sha_is_rejected() {
        let pin = validate_governance_source_pin("git:abcd");
        assert!(!pin.format_valid);
    }

    #[test]
    fn mutable_phrases_are_unrecognized() {
        for bad in ["latest", "main", "forum post", "current proposal", "HEAD"] {
            let pin = validate_governance_source_pin(bad);
            assert_eq!(pin.kind, PIN_KIND_UNRECOGNIZED);
            assert!(!pin.format_valid);
        }
    }

    #[test]
    fn whitespace_ambiguity_is_rejected() {
        for bad in ["  ", " blake3:abc", "blake3:abc "] {
            let pin = validate_governance_source_pin(bad);
            assert!(!pin.format_valid, "{bad} should be invalid");
        }
    }

    #[test]
    fn known_bytes_produce_deterministic_digest() {
        let digest_a = governance_document_digest_for_bytes(b"governance-pilot");
        let digest_b = governance_document_digest_for_bytes(b"governance-pilot");
        assert_eq!(digest_a, digest_b);
        let pin = content_digest_pin_for_bytes(b"governance-pilot");
        assert!(pin.starts_with(GOVERNANCE_PIN_PREFIX_BLAKE3));
    }

    #[test]
    fn one_byte_change_changes_the_digest() {
        let a = governance_document_digest_for_bytes(b"governance-pilot");
        let b = governance_document_digest_for_bytes(b"governance-pilox");
        assert_ne!(a, b);
    }

    #[test]
    fn zero_byte_document_has_explicit_digest() {
        let pin = content_digest_pin_for_bytes(b"");
        assert_eq!(pin.len(), GOVERNANCE_PIN_PREFIX_BLAKE3.len() + BLAKE3_DIGEST_HEX_LEN);
        // A zero-byte document is a valid (if unusual) immutable document; its
        // digest is well-defined and pinning it is not blocked.
        let status = match_governance_document(&pin, Some(&compute_status_doc(&pin)));
        assert_eq!(status.status, GuiGovernanceMatchStatusV1::Matched);
    }

    fn compute_status_doc(pin: &str) -> GuiGovernanceDocumentDigestV1 {
        let digest_hex = strip_blake3(pin).to_owned();
        GuiGovernanceDocumentDigestV1 {
            display_filename: "empty.bin".to_owned(),
            bytes: 0,
            digest_algorithm_id: tari_cc_private_ballot_protocol::BLAKE3_256_HASH_ALGORITHM_ID_V1,
            digest_hex,
        }
    }

    #[test]
    fn matching_content_digest_succeeds() {
        let pin = content_digest_pin_for_bytes(b"doc-bytes");
        let doc = GuiGovernanceDocumentDigestV1 {
            display_filename: "proposal.md".to_owned(),
            bytes: 9,
            digest_algorithm_id: tari_cc_private_ballot_protocol::BLAKE3_256_HASH_ALGORITHM_ID_V1,
            digest_hex: strip_blake3(&pin).to_owned(),
        };
        let status = match_governance_document(&pin, Some(&doc));
        assert_eq!(status.status, GuiGovernanceMatchStatusV1::Matched);
        assert!(status.status.is_cryptographically_matched());
    }

    #[test]
    fn mismatching_content_digest_fails() {
        let pin = content_digest_pin_for_bytes(b"doc-bytes");
        let other = content_digest_pin_for_bytes(b"different-bytes");
        let doc = GuiGovernanceDocumentDigestV1 {
            display_filename: "proposal.md".to_owned(),
            bytes: 14,
            digest_algorithm_id: tari_cc_private_ballot_protocol::BLAKE3_256_HASH_ALGORITHM_ID_V1,
            digest_hex: strip_blake3(&other).to_owned(),
        };
        let status = match_governance_document(&pin, Some(&doc));
        assert_eq!(status.status, GuiGovernanceMatchStatusV1::Mismatch);
        assert!(!status.status.is_cryptographically_matched());
    }

    #[test]
    fn git_sha_with_document_is_operator_attested_not_verified() {
        let doc = GuiGovernanceDocumentDigestV1 {
            display_filename: "proposal.md".to_owned(),
            bytes: 4,
            digest_algorithm_id: tari_cc_private_ballot_protocol::BLAKE3_256_HASH_ALGORITHM_ID_V1,
            digest_hex: to_lower_hex(&governance_document_digest_for_bytes(b"doc!")),
        };
        let status = match_governance_document(VALID_GIT, Some(&doc));
        assert_eq!(status.status, GuiGovernanceMatchStatusV1::OperatorAttested);
        assert!(!status.status.is_cryptographically_matched());
    }

    #[test]
    fn git_sha_without_document_is_unverified_reference() {
        let status = match_governance_document(VALID_GIT, None);
        assert_eq!(status.status, GuiGovernanceMatchStatusV1::UnverifiedReference);
    }

    #[test]
    fn unrecognized_revision_with_document_is_not_applicable() {
        let doc = GuiGovernanceDocumentDigestV1 {
            display_filename: "x.md".to_owned(),
            bytes: 1,
            digest_algorithm_id: tari_cc_private_ballot_protocol::BLAKE3_256_HASH_ALGORITHM_ID_V1,
            digest_hex: to_lower_hex(&governance_document_digest_for_bytes(b"x")),
        };
        let status = match_governance_document("latest", Some(&doc));
        assert_eq!(status.status, GuiGovernanceMatchStatusV1::NotApplicable);
    }

    #[test]
    fn archive_path_constant_is_safe_relative() {
        let path = tari_cc_private_ballot_archive::ArchivePathV1::new(
            GOVERNANCE_DOCUMENT_ARCHIVE_PATH.to_owned(),
        );
        assert!(path.is_ok(), "governance archive path must satisfy the portable profile");
    }
}
