/**
 * Local memory for the controlled managed-Tor test transport configuration.
 *
 * This remembers ONLY the three NON-SECRET local file-system locations the
 * controlled one-computer Tor test needs, so a tester does not have to retype
 * three Windows paths after navigating away or restarting the app:
 *
 *   - the absolute path to an already-installed `tor.exe`,
 *   - the voter Tor data directory (outside the repository), and
 *   - the organizer-produced voter-public transport bundle path.
 *
 * It is a convenience preference, never trusted input and never secret:
 *
 *   - Nothing secret is stored: no passphrase, credential bytes, scalar,
 *     witness, nullifier, ballot selection, prepared-ballot state, staged
 *     envelope, receipt, wallet secret, or seed. Only these three location
 *     strings are stored.
 *   - A remembered path is only ever pre-filled into an input the tester can
 *     edit; the Rust shell still re-validates whatever path is actually used
 *     (absolute, regular file / directory, no symlink/reparse point) before any
 *     Tor process is launched or any bundle is read.
 *   - Remembering configuration NEVER starts Tor, transmits anything, or crosses
 *     the release boundary. After a restart the app may pre-fill the fields, but
 *     Tor still requires an explicit fresh start and readiness check before a
 *     submission or retry.
 *
 * Persistence uses the same browser-local storage the rest of the app settings
 * use (see {@link ./directoryMemory}), under a dedicated key so the controlled
 * test configuration is never entangled with reactive application settings.
 */

/** The non-secret controlled-test transport configuration.
 *
 * `torExePath` is a GLOBAL convenience (the same installed tor.exe is reused
 * across elections). `torDataDir` and `voterBundlePath` are ELECTION-SPECIFIC:
 * the voter transport bundle is cryptographically bound to one election, and the
 * data directory is scoped to it. `electionManifestHashHex` records which
 * election those two belong to so they are never silently carried forward as
 * trusted configuration for a DIFFERENT election. */
export interface ManagedTorConfigMemory {
  torExePath: string;
  torDataDir: string;
  voterBundlePath: string;
  /** The election (manifest hash) the two election-specific paths belong to.
   *  Empty when unknown. */
  electionManifestHashHex: string;
}

const EMPTY: ManagedTorConfigMemory = {
  torExePath: "",
  torDataDir: "",
  voterBundlePath: "",
  electionManifestHashHex: "",
};

const STORAGE_KEY = "tari-private-ballot.managed-tor-config";

/** Coerces one stored field into a bounded non-secret string. */
function field(raw: Record<string, unknown>, key: string): string {
  const value = raw[key];
  // Bound the length defensively; these are file-system paths, never blobs.
  return typeof value === "string" && value.length > 0 && value.length <= 4096 ? value : "";
}

/** Sanitizes an untrusted parsed object into a config memory record. Only the
 *  three known string fields survive. */
export function sanitizeManagedTorConfig(raw: unknown): ManagedTorConfigMemory {
  if (raw === null || typeof raw !== "object") return { ...EMPTY };
  const record = raw as Record<string, unknown>;
  return {
    torExePath: field(record, "torExePath"),
    torDataDir: field(record, "torDataDir"),
    voterBundlePath: field(record, "voterBundlePath"),
    electionManifestHashHex: field(record, "electionManifestHashHex"),
  };
}

function storage(): Storage | null {
  try {
    return typeof localStorage !== "undefined" ? localStorage : null;
  } catch {
    return null;
  }
}

/** Returns the remembered controlled-test configuration (all fields default to
 *  empty strings when nothing is stored or storage is unavailable).
 *
 * `torExePath` is always returned (it is global). The election-specific
 * `torDataDir` and `voterBundlePath` are returned ONLY when the caller supplies
 * the current election's manifest hash AND it matches the election those paths
 * were remembered for; otherwise they are blanked, so a different election never
 * silently inherits the previous election's transport bundle or data directory.
 * Call with no argument (or an empty hash) to intentionally read the raw stored
 * values without an election match (e.g. to pre-fill only the global tor.exe). */
export function recallManagedTorConfig(
  currentManifestHashHex?: string,
): ManagedTorConfigMemory {
  const store = storage();
  if (!store) return { ...EMPTY };
  try {
    const raw = store.getItem(STORAGE_KEY);
    if (!raw) return { ...EMPTY };
    const stored = sanitizeManagedTorConfig(JSON.parse(raw));
    if (currentManifestHashHex === undefined) return stored;
    const sameElection =
      currentManifestHashHex.length > 0 &&
      stored.electionManifestHashHex === currentManifestHashHex;
    if (sameElection) {
      return { ...stored, electionManifestHashHex: currentManifestHashHex };
    }
    // Different (or unknown) election: keep the global tor.exe, drop the
    // election-specific paths so they are never reused across elections.
    return {
      torExePath: stored.torExePath,
      torDataDir: "",
      voterBundlePath: "",
      electionManifestHashHex: currentManifestHashHex,
    };
  } catch {
    return { ...EMPTY };
  }
}

/** Remembers the three non-secret controlled-test configuration paths. Empty
 *  fields are stored as empty strings (they clear a previously remembered
 *  value). */
export function rememberManagedTorConfig(config: ManagedTorConfigMemory): void {
  const store = storage();
  if (!store) return;
  try {
    store.setItem(STORAGE_KEY, JSON.stringify(sanitizeManagedTorConfig(config)));
  } catch {
    /* configuration hints persist only when storage is available */
  }
}
