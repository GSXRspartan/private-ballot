//! Canonical, reusable archive-containment guard (HIGH-2).
//!
//! A finalized archive directory is an immutable, independently verifiable
//! artifact. If any MUTABLE anchor output/state file (the live config, the
//! lifecycle snapshot, the anchor evidence, the poll gate, or any future state
//! file) were written *inside* that directory, publishing would silently mutate
//! the "finalized" archive and make later independent verification fail.
//!
//! [`path_is_within_archive`] rejects any candidate path that EQUALS the
//! archive directory or is a DESCENDANT of it. It is deliberately not a naive
//! string-prefix check: a sibling such as `archive-anchor-evidence.cbor` next to
//! `archive/` must be ACCEPTED, while `archive/anchor.cbor` and
//! `archive/sub/anchor.cbor` must be REJECTED.
//!
//! Windows path semantics are handled explicitly:
//!
//! * canonicalization of the deepest existing ancestor (resolving symlinks,
//!   reparse points, `8.3` short names, and drive-letter case) for both the
//!   base and the candidate, with the non-existing tail normalized lexically;
//! * `\\?\` verbatim-prefix normalization (applied consistently to both sides);
//! * separator differences (`\` vs `/`);
//! * case-insensitive comparison on Windows;
//! * `.` and `..` components resolved lexically before comparison.

use std::path::{Component, Path, PathBuf};

/// Returns `true` when `candidate` equals `archive_dir` or is nested inside it.
///
/// Both paths are resolved as far as they exist on disk (canonicalizing the
/// deepest existing ancestor) and the remainder is normalized lexically, so the
/// comparison is robust against separator, case, `..`, short-name, and symlink
/// differences on Windows. When neither path can be resolved to a comparable
/// form the guard fails CLOSED (returns `true`), because an unresolvable output
/// path must never be treated as safely outside the finalized archive.
#[must_use]
pub fn path_is_within_archive(candidate: &Path, archive_dir: &Path) -> bool {
    let base = resolve_for_containment(archive_dir);
    let cand = resolve_for_containment(candidate);
    match (base, cand) {
        (Some(base), Some(cand)) => components_contains_or_equals(&base, &cand),
        // If either side cannot be resolved to comparable components, refuse to
        // certify the candidate as outside the archive (fail closed).
        _ => true,
    }
}

/// Resolves a path to a comparable component vector: canonicalize the deepest
/// existing ancestor, then append the lexically-normalized non-existing tail.
fn resolve_for_containment(path: &Path) -> Option<Vec<String>> {
    let (existing, tail) = split_at_deepest_existing(path);
    let mut base_components = match existing {
        Some(existing) => {
            let canonical = std::fs::canonicalize(&existing).ok()?;
            normalize_components(&canonical)
        }
        None => Vec::new(),
    };
    // Apply the non-existing tail lexically (resolving `.`/`..`).
    for component in tail {
        apply_lexical_component(&mut base_components, &component);
    }
    Some(base_components)
}

/// Splits `path` into (deepest existing ancestor, remaining components). The
/// remaining components are the raw tail below the existing prefix.
fn split_at_deepest_existing(path: &Path) -> (Option<PathBuf>, Vec<String>) {
    // Walk from the full path upward until an existing ancestor is found.
    let mut current = path.to_path_buf();
    let mut tail: Vec<String> = Vec::new();
    loop {
        if current.exists() {
            tail.reverse();
            return (Some(current), tail);
        }
        let Some(file_name) = current
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
        else {
            // No more components to strip and nothing existed.
            tail.reverse();
            return (None, tail);
        };
        tail.push(file_name);
        if !current.pop() {
            tail.reverse();
            return (None, tail);
        }
    }
}

/// Normalizes an already-existing (canonicalized) path into comparable string
/// components, stripping a Windows `\\?\` verbatim prefix and folding case on
/// Windows.
fn normalize_components(path: &Path) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => {
                out.push(fold_case(&strip_verbatim(
                    &prefix.as_os_str().to_string_lossy(),
                )));
            }
            Component::RootDir => {
                // Represent the root as a stable sentinel so a rooted path never
                // shares a prefix with a relative one.
                out.push("\u{0}root".to_owned());
            }
            Component::Normal(part) => out.push(fold_case(&part.to_string_lossy())),
            Component::CurDir => {}
            Component::ParentDir => {
                // A `..` in a canonicalized path should not occur, but resolve
                // defensively.
                if out.last().map(|last| last != "\u{0}root").unwrap_or(false) {
                    out.pop();
                }
            }
        }
    }
    out
}

/// Applies one raw tail component (a file/dir name, possibly `.`/`..`) to the
/// resolved component vector, folding case on Windows.
fn apply_lexical_component(components: &mut Vec<String>, raw: &str) {
    match raw {
        "" | "." => {}
        ".." => {
            if components
                .last()
                .map(|last| last != "\u{0}root")
                .unwrap_or(false)
            {
                components.pop();
            }
        }
        other => components.push(fold_case(other)),
    }
}

/// Returns whether `cand` is equal to or nested within `base`, comparing whole
/// components (never substrings).
fn components_contains_or_equals(base: &[String], cand: &[String]) -> bool {
    if base.is_empty() || cand.len() < base.len() {
        return false;
    }
    base.iter().zip(cand.iter()).all(|(b, c)| b == c)
}

/// Strips a Windows `\\?\` (or `\\?\UNC\`) verbatim prefix marker from a
/// prefix-component string so canonicalized and non-canonicalized forms compare
/// equal.
fn strip_verbatim(text: &str) -> String {
    let trimmed = text
        .strip_prefix(r"\\?\UNC\")
        .map(|rest| format!(r"\\{rest}"))
        .or_else(|| text.strip_prefix(r"\\?\").map(str::to_owned))
        .unwrap_or_else(|| text.to_owned());
    trimmed
}

#[cfg(windows)]
fn fold_case(text: &str) -> String {
    text.to_ascii_lowercase()
}

#[cfg(not(windows))]
fn fold_case(text: &str) -> String {
    text.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(tag: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "tari-anchor-pathguard-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&base).expect("temp root must create");
        base
    }

    #[test]
    fn archive_directory_itself_is_within() {
        let root = temp_root("self");
        let archive = root.join("archive");
        std::fs::create_dir_all(&archive).expect("archive dir");
        assert!(path_is_within_archive(&archive, &archive));
    }

    #[test]
    fn direct_child_is_within() {
        let root = temp_root("child");
        let archive = root.join("archive");
        std::fs::create_dir_all(&archive).expect("archive dir");
        assert!(path_is_within_archive(
            &archive.join("anchor-config.cbor"),
            &archive
        ));
    }

    #[test]
    fn nested_descendant_is_within() {
        let root = temp_root("nested");
        let archive = root.join("archive");
        std::fs::create_dir_all(archive.join("subdir")).expect("subdir");
        assert!(path_is_within_archive(
            &archive.join("subdir").join("anchor.cbor"),
            &archive
        ));
    }

    #[test]
    fn sibling_with_shared_name_prefix_is_accepted() {
        let root = temp_root("sibling");
        let archive = root.join("archive");
        std::fs::create_dir_all(&archive).expect("archive dir");
        // The default detached sidecar layout: sibling files next to `archive/`.
        assert!(!path_is_within_archive(
            &root.join("archive-anchor-evidence.cbor"),
            &archive
        ));
        assert!(!path_is_within_archive(
            &root.join("archive-anchor-config.cbor"),
            &archive
        ));
        assert!(!path_is_within_archive(
            &root.join("archive-anchor-snapshot.cbor"),
            &archive
        ));
    }

    #[test]
    fn different_directory_is_accepted() {
        let root = temp_root("different");
        let archive = root.join("archive");
        std::fs::create_dir_all(&archive).expect("archive dir");
        let elsewhere = root.join("elsewhere").join("anchor.cbor");
        assert!(!path_is_within_archive(&elsewhere, &archive));
    }

    #[test]
    fn parent_traversal_back_into_archive_is_within() {
        let root = temp_root("traversal");
        let archive = root.join("archive");
        std::fs::create_dir_all(&archive).expect("archive dir");
        // `<root>/elsewhere/../archive/anchor.cbor` normalizes back inside.
        let sneaky = root
            .join("elsewhere")
            .join("..")
            .join("archive")
            .join("anchor.cbor");
        assert!(path_is_within_archive(&sneaky, &archive));
    }

    #[test]
    fn parent_traversal_out_of_archive_is_accepted() {
        let root = temp_root("traversal-out");
        let archive = root.join("archive");
        std::fs::create_dir_all(&archive).expect("archive dir");
        // `<archive>/../sibling.cbor` normalizes to a sibling, outside.
        let out = archive.join("..").join("sibling.cbor");
        assert!(!path_is_within_archive(&out, &archive));
    }

    #[cfg(windows)]
    #[test]
    fn windows_case_and_separator_insensitive() {
        let root = temp_root("winsep");
        let archive = root.join("Archive");
        std::fs::create_dir_all(&archive).expect("archive dir");
        // Same directory expressed with different case must still be within.
        let mixed = root.join("ARCHIVE").join("anchor.cbor");
        assert!(path_is_within_archive(&mixed, &archive));
    }
}
