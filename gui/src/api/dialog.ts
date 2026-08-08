/**
 * Native file selection for the Load Election workflow (ADR-0007).
 *
 * Uses the Tauri `dialog` plugin's native open-file dialog only. The dialog
 * returns a selected path string; no file is read, copied, or modified here.
 * Reading and validation happen in the Rust shell through gui-core. When the
 * frontend runs outside the desktop shell (plain browser preview), selection
 * resolves to `null` and screens render their neutral states.
 */

import { open, save } from "@tauri-apps/plugin-dialog";

import { isDesktopShell } from "./client";

/**
 * Opens a native single-file picker for one canonical election artifact.
 *
 * @returns the selected path, or `null` when cancelled or unavailable.
 */
export async function pickElectionArtifact(title: string): Promise<string | null> {
  if (!isDesktopShell()) return null;
  const selected = await open({
    title,
    multiple: false,
    directory: false,
    filters: [
      { name: "Canonical CBOR", extensions: ["cbor"] },
      { name: "All files", extensions: ["*"] },
    ],
  });
  if (Array.isArray(selected)) return selected[0] ?? null;
  return selected ?? null;
}

/**
 * Opens a native directory picker for exporting election artifacts (or any
 * other directory). Returns the selected path, or `null` when cancelled or
 * unavailable outside the desktop shell.
 */
export async function pickDirectory(title: string): Promise<string | null> {
  if (!isDesktopShell()) return null;
  const selected = await open({
    title,
    multiple: false,
    directory: true,
  });
  if (Array.isArray(selected)) return selected[0] ?? null;
  return selected ?? null;
}

/** Opens the native save dialog for a new canonical ballot package. Rust,
 * not JavaScript, writes and verifies the selected file. */
export async function pickBallotPackagePath(): Promise<string | null> {
  if (!isDesktopShell()) return null;
  return await save({
    title: "Export canonical ballot package",
    defaultPath: "ballot-package.cbor",
    filters: [{ name: "Canonical ballot package", extensions: ["cbor"] }],
  });
}

/**
 * Opens a native single-file picker for a canonical ballot package import.
 * The selected path is transient operator UX only; Rust reads the bytes and
 * gui-core validates them without persisting the filename or path.
 */
export async function pickBallotPackageFile(title = "Import ballot package"): Promise<string | null> {
  if (!isDesktopShell()) return null;
  const selected = await open({
    title,
    multiple: false,
    directory: false,
    filters: [
      { name: "Canonical ballot package", extensions: ["cbor"] },
      { name: "All files", extensions: ["*"] },
    ],
  });
  if (Array.isArray(selected)) return selected[0] ?? null;
  return selected ?? null;
}

/**
 * Opens a native single-file picker for a canonical registry CBOR file (the
 * canonical organizer import format). Reading and validation happen in Rust;
 * this only returns a path. Distinct from `pickTextFile`, which is the
 * non-canonical public-key text-list convenience input.
 */
export async function pickRegistryCborFile(title: string): Promise<string | null> {
  if (!isDesktopShell()) return null;
  const selected = await open({
    title,
    multiple: false,
    directory: false,
    filters: [
      { name: "Canonical CBOR", extensions: ["cbor"] },
      { name: "All files", extensions: ["*"] },
    ],
  });
  if (Array.isArray(selected)) return selected[0] ?? null;
  return selected ?? null;
}

/**
 * Opens a native single-file picker for a governance document (Slice 5A8). The
 * document is treated as immutable raw bytes; no semantic parsing happens in
 * the frontend. Reading, size-checking, and digesting happen in Rust; this
 * only returns a path.
 */
export async function pickGovernanceDocument(title: string): Promise<string | null> {
  if (!isDesktopShell()) return null;
  const selected = await open({
    title,
    multiple: false,
    directory: false,
    filters: [
      {
        name: "Governance document",
        extensions: ["md", "txt", "pdf", "json", "html", "rtf", "odt", "docx", "bin"],
      },
      { name: "All files", extensions: ["*"] },
    ],
  });
  if (Array.isArray(selected)) return selected[0] ?? null;
  return selected ?? null;
}

/**
 * Opens a native single-file picker for a plain-text public-key list (the
 * non-canonical organizer convenience import format). Reading and validation
 * happen in the frontend/Rust; this only returns a path.
 */
export async function pickTextFile(title: string): Promise<string | null> {
  if (!isDesktopShell()) return null;
  const selected = await open({
    title,
    multiple: false,
    directory: false,
    filters: [
      { name: "Public-key list", extensions: ["txt", "csv"] },
      { name: "All files", extensions: ["*"] },
    ],
  });
  if (Array.isArray(selected)) return selected[0] ?? null;
  return selected ?? null;
}
