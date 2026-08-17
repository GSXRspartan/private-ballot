/**
 * Native file selection for the Load Election workflow (ADR-0007).
 *
 * Uses the Tauri `dialog` plugin's native open-file dialog only. The dialog
 * returns a selected path string; no file is read, copied, or modified here.
 * Reading and validation happen in the Rust shell through gui-core. When the
 * frontend runs outside the desktop shell (plain browser preview), selection
 * resolves to `null` and screens render their neutral states.
 *
 * Each picker takes an optional directory-memory `category`. When present, the
 * last-used directory for that category seeds the dialog's starting location,
 * and a successful selection updates it. Only the directory is remembered — no
 * artifact is auto-loaded, and the remembered path is a UX hint only; Rust
 * still validates whatever file is actually selected. See {@link
 * ./directoryMemory}.
 */

import { open, save } from "@tauri-apps/plugin-dialog";

import { isDesktopShell } from "./client";
import {
  type DirectoryCategory,
  recallDirectory,
  rememberDirectory,
  rememberDirectoryFromFile,
} from "./directoryMemory";

/** Joins a remembered directory with a default filename for save dialogs,
 *  preserving the directory's own path separator. */
function joinDefaultPath(directory: string, filename: string): string {
  const separator = directory.includes("\\") && !directory.includes("/") ? "\\" : "/";
  const trimmed = directory.replace(/[\\/]+$/, "");
  return `${trimmed}${separator}${filename}`;
}

/** First element of an open-dialog result (or the value itself), else null. */
function firstSelected(selected: string | string[] | null): string | null {
  if (Array.isArray(selected)) return selected[0] ?? null;
  return selected ?? null;
}

/**
 * Opens a native single-file open dialog and remembers the chosen file's
 * directory for `category` (when provided).
 */
async function openFile(
  title: string,
  filters: { name: string; extensions: string[] }[],
  category?: DirectoryCategory,
): Promise<string | null> {
  if (!isDesktopShell()) return null;
  const selected = await open({
    title,
    multiple: false,
    directory: false,
    filters,
    defaultPath: category ? recallDirectory(category) : undefined,
  });
  const picked = firstSelected(selected);
  if (picked !== null && category) rememberDirectoryFromFile(category, picked);
  return picked;
}

/**
 * Opens a native single-file picker for one canonical election artifact.
 *
 * @returns the selected path, or `null` when cancelled or unavailable.
 */
export async function pickElectionArtifact(
  title: string,
  category: DirectoryCategory = "electionArtifact",
): Promise<string | null> {
  return openFile(
    title,
    [
      { name: "Canonical CBOR", extensions: ["cbor"] },
      { name: "All files", extensions: ["*"] },
    ],
    category,
  );
}

/**
 * Opens a native directory picker (e.g. for exporting election artifacts).
 * Returns the selected path, or `null` when cancelled or unavailable outside
 * the desktop shell. When `category` is provided, the chosen directory is
 * remembered as the last-used location for that category.
 */
export async function pickDirectory(
  title: string,
  category?: DirectoryCategory,
): Promise<string | null> {
  if (!isDesktopShell()) return null;
  const selected = await open({
    title,
    multiple: false,
    directory: true,
    defaultPath: category ? recallDirectory(category) : undefined,
  });
  const picked = firstSelected(selected);
  if (picked !== null && category) rememberDirectory(category, picked);
  return picked;
}

/** Opens the native save dialog for a new canonical ballot package. Rust,
 * not JavaScript, writes and verifies the selected file. */
export async function pickBallotPackagePath(
  category: DirectoryCategory = "ballotPackage",
): Promise<string | null> {
  if (!isDesktopShell()) return null;
  const rememberedDir = recallDirectory(category);
  const picked = await save({
    title: "Export canonical ballot package",
    defaultPath: rememberedDir
      ? joinDefaultPath(rememberedDir, "ballot-package.cbor")
      : "ballot-package.cbor",
    filters: [{ name: "Canonical ballot package", extensions: ["cbor"] }],
  });
  if (picked !== null) rememberDirectoryFromFile(category, picked);
  return picked;
}

/** Opens a native single-file picker for a portable encrypted voter
 * credential. The frontend receives only the selected path; Rust reads and
 * decrypts the reviewed container. */
export async function pickVoterCredentialFile(): Promise<string | null> {
  return openFile(
    "Import voter credential",
    [
      { name: "Tari Private Ballot credential", extensions: ["tcbcred"] },
      { name: "All files", extensions: ["*"] },
    ],
    "credential",
  );
}

/** Opens the native save dialog for another encrypted credential copy. Rust,
 * not JavaScript, writes the selected file. */
export async function pickVoterCredentialBackupPath(
  defaultPath = "voter-credential.tcbcred",
): Promise<string | null> {
  if (!isDesktopShell()) return null;
  const rememberedDir = recallDirectory("credential");
  const picked = await save({
    title: "Back up voter credential",
    defaultPath: rememberedDir ? joinDefaultPath(rememberedDir, defaultPath) : defaultPath,
    filters: [{ name: "Tari Private Ballot credential", extensions: ["tcbcred"] }],
  });
  if (picked !== null) rememberDirectoryFromFile("credential", picked);
  return picked;
}

/**
 * Opens a native single-file picker for a canonical ballot package import.
 * The selected path is transient operator UX only; Rust reads the bytes and
 * gui-core validates them without persisting the filename or path.
 */
export async function pickBallotPackageFile(
  title = "Import ballot package",
): Promise<string | null> {
  return openFile(
    title,
    [
      { name: "Canonical ballot package", extensions: ["cbor"] },
      { name: "All files", extensions: ["*"] },
    ],
    "ballotPackage",
  );
}

/**
 * Opens a native single-file picker for a canonical registry CBOR file (the
 * canonical organizer import format). Reading and validation happen in Rust;
 * this only returns a path. Distinct from `pickTextFile`, which is the
 * non-canonical public-key text-list convenience input.
 */
export async function pickRegistryCborFile(title: string): Promise<string | null> {
  return openFile(
    title,
    [
      { name: "Canonical CBOR", extensions: ["cbor"] },
      { name: "All files", extensions: ["*"] },
    ],
    "electionArtifact",
  );
}

/**
 * Opens a native single-file picker for a canonical CBOR artifact (archive
 * manifest, anchor config, snapshot, or evidence record). Reading and
 * validation happen in the Rust shell; this only returns a path.
 */
export async function pickCborFile(
  title: string,
  category: DirectoryCategory = "anchorEvidence",
): Promise<string | null> {
  return openFile(
    title,
    [
      { name: "Canonical CBOR", extensions: ["cbor"] },
      { name: "All files", extensions: ["*"] },
    ],
    category,
  );
}

/**
 * Opens a native single-file picker for a governance document (Slice 5A8). The
 * document is treated as immutable raw bytes; no semantic parsing happens in
 * the frontend. Reading, size-checking, and digesting happen in Rust; this
 * only returns a path.
 */
export async function pickGovernanceDocument(title: string): Promise<string | null> {
  return openFile(
    title,
    [
      {
        name: "Governance document",
        extensions: ["md", "txt", "pdf", "json", "html", "rtf", "odt", "docx", "bin"],
      },
      { name: "All files", extensions: ["*"] },
    ],
    "governance",
  );
}

/**
 * Opens a native single-file picker for an already-installed `tor.exe`
 * executable (controlled managed-Tor test only). The frontend receives only the
 * selected path; the Rust shell re-validates that it is an absolute regular file
 * (no symlink/reparse point) before it is ever launched. No directory memory
 * category is used; the selected path is remembered separately as non-secret
 * controlled-test configuration.
 */
export async function pickTorExecutable(
  title = "Select tor.exe",
): Promise<string | null> {
  return openFile(title, [
    { name: "Tor executable", extensions: ["exe"] },
    { name: "All files", extensions: ["*"] },
  ]);
}

/**
 * Opens a native single-file picker for the organizer-produced voter-public
 * transport bundle (controlled managed-Tor test only). Reading, verification,
 * and election binding happen in Rust; this only returns a path.
 */
export async function pickVoterTransportBundle(
  title = "Select voter transport bundle",
): Promise<string | null> {
  return openFile(title, [
    { name: "Voter transport bundle", extensions: ["cbor"] },
    { name: "All files", extensions: ["*"] },
  ]);
}

/**
 * Opens a native single-file picker for a plain-text public-key list (the
 * non-canonical organizer convenience import format). Reading and validation
 * happen in the frontend/Rust; this only returns a path.
 */
export async function pickTextFile(title: string): Promise<string | null> {
  return openFile(
    title,
    [
      { name: "Public-key list", extensions: ["txt", "csv"] },
      { name: "All files", extensions: ["*"] },
    ],
    "electionArtifact",
  );
}
