/**
 * Native file selection for the Load Election workflow (ADR-0007).
 *
 * Uses the Tauri `dialog` plugin's native open-file dialog only. The dialog
 * returns a selected path string; no file is read, copied, or modified here.
 * Reading and validation happen in the Rust shell through gui-core. When the
 * frontend runs outside the desktop shell (plain browser preview), selection
 * resolves to `null` and screens render their neutral states.
 */

import { open } from "@tauri-apps/plugin-dialog";

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