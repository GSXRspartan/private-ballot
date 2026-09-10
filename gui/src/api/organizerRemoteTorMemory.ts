// Organizer external-remote Tor hosting preferences (LOCAL DEVELOPMENT ONLY
// advanced mode). Convenience memory of NON-SECRET, GLOBAL configuration: the
// hosting-mode token, the remote SOCKS endpoint, the externally provisioned
// onion hostname, and the fixed loopback collector port. A SOCKS endpoint and
// an onion hostname are not credentials; no secret material is ever stored.
//
// The Rust shell re-validates EVERY persisted value before anything connects,
// so this store is convenience-only: unknown/malformed values are normalized
// fail-safe here (unknown mode → managed-local; malformed port → cleared) and
// again fail-closed in the backend.

export interface OrganizerRemoteTorMemory {
  /** "managed-local" (default/recommended) or "external-remote" (advanced).
   *  Any unknown value is normalized to "managed-local". */
  torMode: string;
  /** Remote SOCKS host (non-secret). Empty when unset. */
  socksHost: string;
  /** Remote SOCKS port as a digit string (1–65535). Empty when unset or
   *  malformed so it fails closed on reload. */
  socksPort: string;
  /** Externally provisioned organizer onion hostname (non-secret). */
  onionHostname: string;
  /** Fixed loopback collector port as a digit string (1–65535). Empty when
   *  unset or malformed. */
  collectorPort: string;
}

const EMPTY: OrganizerRemoteTorMemory = {
  torMode: "managed-local",
  socksHost: "",
  socksPort: "",
  onionHostname: "",
  collectorPort: "",
};

const STORAGE_KEY = "tari-private-ballot.organizer-remote-tor";

function field(raw: Record<string, unknown>, key: string): string {
  const value = raw[key];
  return typeof value === "string" ? value : "";
}

/** Digit-only port in 1..=65535, else "" (cleared → fails closed on use). */
function portField(raw: Record<string, unknown>, key: string): string {
  const value = field(raw, key);
  return /^\d{1,5}$/.test(value) && Number(value) >= 1 && Number(value) <= 65535
    ? value
    : "";
}

export function sanitizeOrganizerRemoteTorConfig(raw: unknown): OrganizerRemoteTorMemory {
  if (raw === null || typeof raw !== "object") return { ...EMPTY };
  const record = raw as Record<string, unknown>;
  // Normalize the mode to the two known tokens; anything else (or absent) is
  // the recommended managed-local default — never silently remote.
  const rawMode = field(record, "torMode");
  return {
    torMode: rawMode === "external-remote" ? "external-remote" : "managed-local",
    socksHost: field(record, "socksHost"),
    socksPort: portField(record, "socksPort"),
    onionHostname: field(record, "onionHostname"),
    collectorPort: portField(record, "collectorPort"),
  };
}

export function recallOrganizerRemoteTorConfig(): OrganizerRemoteTorMemory {
  const store = storage();
  if (!store) return { ...EMPTY };
  try {
    const raw = store.getItem(STORAGE_KEY);
    if (!raw) return { ...EMPTY };
    return sanitizeOrganizerRemoteTorConfig(JSON.parse(raw));
  } catch {
    return { ...EMPTY };
  }
}

export function rememberOrganizerRemoteTorConfig(
  config: OrganizerRemoteTorMemory,
): void {
  const store = storage();
  if (!store) return;
  try {
    store.setItem(STORAGE_KEY, JSON.stringify(sanitizeOrganizerRemoteTorConfig(config)));
  } catch {
    // Storage unavailable (or full): convenience memory is best-effort only.
  }
}

function storage(): Storage | null {
  try {
    return typeof localStorage !== "undefined" ? localStorage : null;
  } catch {
    return null;
  }
}
