/**
 * Last-used directory memory for the native file pickers.
 *
 * This remembers ONLY the directory a user last browsed to for each kind of
 * operation, so a native dialog reopens where they expect instead of at a
 * default root after restart. It is a convenience preference, never trusted
 * input:
 *
 *   - Only directory strings are stored — never a full artifact path is
 *     auto-loaded, never a filename, never file contents.
 *   - Nothing secret is stored: no passphrase, credential bytes, scalar,
 *     witness, nullifier, ballot selection, prepared-ballot state, wallet
 *     secret, or seed. The category keys below are deliberately limited to
 *     directory-location hints.
 *   - A remembered directory is passed to the native dialog only as its
 *     starting location. The Rust backend still reads and validates whatever
 *     file the user actually selects; a stale or deleted remembered directory
 *     simply falls back to the platform default (the dialog ignores a
 *     non-existent `defaultPath`).
 *
 * Persistence uses the same browser-local storage the rest of the app settings
 * use, under a dedicated key so directory hints are never entangled with (and
 * cannot clobber) the reactive application settings object.
 */

/** Distinct picker locations. Keeping these separate means, e.g., choosing an
 *  archive directory does not move the default credential location. */
export const DIRECTORY_CATEGORIES = [
  "credential",
  "electionArtifact",
  "electionExport",
  "ballotPackage",
  "archive",
  "governance",
  "anchorEvidence",
] as const;

export type DirectoryCategory = (typeof DIRECTORY_CATEGORIES)[number];

export type DirectoryMemory = Partial<Record<DirectoryCategory, string>>;

const STORAGE_KEY = "tari-private-ballot.directory-memory";

function isDirectoryCategory(value: string): value is DirectoryCategory {
  return (DIRECTORY_CATEGORIES as readonly string[]).includes(value);
}

/**
 * Returns the parent directory of a file path, or `null` when none can be
 * derived. Handles both POSIX and Windows separators without touching the
 * filesystem. A path that is already a bare name (no separator) yields `null`.
 */
export function parentDirectory(path: string): string | null {
  if (typeof path !== "string" || path.length === 0) return null;
  // Strip a single trailing separator (but never the root separator itself).
  const trimmed = path.replace(/[\\/]+$/, (match, offset) => (offset === 0 ? match : ""));
  const lastSep = Math.max(trimmed.lastIndexOf("/"), trimmed.lastIndexOf("\\"));
  if (lastSep < 0) return null;
  // Preserve a root separator, e.g. "/file" -> "/", "C:\\x" -> "C:\\".
  if (lastSep === 0) return trimmed.slice(0, 1);
  return trimmed.slice(0, lastSep);
}

/** Sanitizes an untrusted parsed object into a directory memory map. Only known
 *  category keys with non-empty string values survive. */
export function sanitizeDirectoryMemory(raw: unknown): DirectoryMemory {
  const result: DirectoryMemory = {};
  if (raw === null || typeof raw !== "object") return result;
  for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
    if (isDirectoryCategory(key) && typeof value === "string" && value.length > 0) {
      result[key] = value;
    }
  }
  return result;
}

/** Returns the remembered directory for `category` from an in-memory map. */
export function recallFrom(
  memory: DirectoryMemory,
  category: DirectoryCategory,
): string | undefined {
  const value = memory[category];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

/** Returns a new map with `category` set to a directory (used as-is). Empty
 *  directories are ignored so nothing meaningless is stored. */
export function withRememberedDirectory(
  memory: DirectoryMemory,
  category: DirectoryCategory,
  directory: string,
): DirectoryMemory {
  if (typeof directory !== "string" || directory.length === 0) return memory;
  return { ...memory, [category]: directory };
}

/** Returns a new map with `category` set to the parent directory of a selected
 *  file path. Falls back to leaving the map unchanged when no directory can be
 *  derived (e.g. a bare filename). */
export function withRememberedDirectoryFromFile(
  memory: DirectoryMemory,
  category: DirectoryCategory,
  filePath: string,
): DirectoryMemory {
  const directory = parentDirectory(filePath);
  return directory ? withRememberedDirectory(memory, category, directory) : memory;
}

// ---------------------------------------------------------------------------
// Browser-local persistence (thin wrappers over the pure helpers above).
// ---------------------------------------------------------------------------

function storage(): Storage | null {
  try {
    return typeof localStorage !== "undefined" ? localStorage : null;
  } catch {
    return null;
  }
}

function readMemory(): DirectoryMemory {
  const store = storage();
  if (!store) return {};
  try {
    const raw = store.getItem(STORAGE_KEY);
    if (!raw) return {};
    return sanitizeDirectoryMemory(JSON.parse(raw));
  } catch {
    return {};
  }
}

function writeMemory(memory: DirectoryMemory): void {
  const store = storage();
  if (!store) return;
  try {
    store.setItem(STORAGE_KEY, JSON.stringify(memory));
  } catch {
    /* directory hints persist only when storage is available */
  }
}

/** Returns the remembered directory for `category`, or `undefined`. */
export function recallDirectory(category: DirectoryCategory): string | undefined {
  return recallFrom(readMemory(), category);
}

/** Remembers a directory (used as-is) for `category`. */
export function rememberDirectory(category: DirectoryCategory, directory: string): void {
  writeMemory(withRememberedDirectory(readMemory(), category, directory));
}

/** Remembers the parent directory of a selected file path for `category`. */
export function rememberDirectoryFromFile(
  category: DirectoryCategory,
  filePath: string,
): void {
  writeMemory(withRememberedDirectoryFromFile(readMemory(), category, filePath));
}
