/** Durable, conservative browser recovery for one anchor request. */
export type AnchorRecoveryPhase =
  | "creating_request"
  | "submitted_awaiting_approval"
  | "submit_in_flight"
  | "approved_submitted"
  | "verifying"
  | "verified";

export interface AnchorRecoveryRecord {
  phase: AnchorRecoveryPhase;
  requestId: string | null;
  transactionId: string | null;
  /** Opaque tab-operation token; it carries no wallet or election secret. */
  ownerToken: string;
  /** A short durable lease serializes create/submit across browser tabs. */
  leaseExpiresAtMs: number;
  updatedAtMs: number;
}

export type RecoveryLoadState =
  | { kind: "absent" }
  | { kind: "corrupt"; message: string }
  | { kind: "record"; record: AnchorRecoveryRecord };

export type RecoveryClaim =
  | { kind: "claimed"; record: AnchorRecoveryRecord }
  | { kind: "busy"; record: AnchorRecoveryRecord }
  | { kind: "absent" }
  | { kind: "corrupt"; message: string };

export interface RecoveryStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

const LEASE_MS = 5 * 60 * 1000;

function isPhase(value: unknown): value is AnchorRecoveryPhase {
  return value === "creating_request" ||
    value === "submitted_awaiting_approval" ||
    value === "submit_in_flight" ||
    value === "approved_submitted" ||
    value === "verifying" ||
    value === "verified";
}

function validStringOrNull(value: unknown): value is string | null {
  return value === null || (typeof value === "string" && value.length > 0 && value.length <= 512);
}

function validRecord(value: unknown): value is AnchorRecoveryRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const record = value as Partial<AnchorRecoveryRecord>;
  return isPhase(record.phase) &&
    validStringOrNull(record.requestId) &&
    validStringOrNull(record.transactionId) &&
    typeof record.ownerToken === "string" && record.ownerToken.length >= 16 && record.ownerToken.length <= 256 &&
    Number.isSafeInteger(record.leaseExpiresAtMs) && (record.leaseExpiresAtMs ?? 0) >= 0 &&
    Number.isSafeInteger(record.updatedAtMs) && (record.updatedAtMs ?? 0) >= 0;
}

export class AnchorRecoveryStore {
  private readonly storage: RecoveryStorage;

  constructor(storage: RecoveryStorage) {
    this.storage = storage;
  }

  loadState(bundleKey: string): RecoveryLoadState {
    let raw: string | null;
    try {
      raw = this.storage.getItem(bundleKey);
    } catch {
      return { kind: "corrupt", message: "the saved anchor recovery state could not be read" };
    }
    if (raw === null) return { kind: "absent" };
    try {
      const parsed: unknown = JSON.parse(raw);
      if (!validRecord(parsed)) {
        return { kind: "corrupt", message: "the saved anchor recovery state has an invalid shape" };
      }
      return { kind: "record", record: parsed };
    } catch {
      return { kind: "corrupt", message: "the saved anchor recovery state is not valid JSON" };
    }
  }

  /** Compatibility accessor for display code. Mutating callers must claim first. */
  load(bundleKey: string): AnchorRecoveryRecord | null {
    const state = this.loadState(bundleKey);
    return state.kind === "record" ? state.record : null;
  }

  /**
   * localStorage operations are synchronous. The immediate readback means two
   * tabs cannot both conclude that they won an interleaved reservation race.
   */
  reserve(bundleKey: string, ownerToken: string, nowMs: number = Date.now()): RecoveryClaim {
    const existing = this.loadState(bundleKey);
    if (existing.kind !== "absent") {
      return existing.kind === "record" ? { kind: "busy", record: existing.record } : existing;
    }
    const record: AnchorRecoveryRecord = {
      phase: "creating_request",
      requestId: null,
      transactionId: null,
      ownerToken,
      leaseExpiresAtMs: nowMs + LEASE_MS,
      updatedAtMs: nowMs,
    };
    try {
      this.storage.setItem(bundleKey, JSON.stringify(record));
    } catch {
      return { kind: "corrupt", message: "the anchor request could not be reserved in durable storage" };
    }
    const confirmed = this.loadState(bundleKey);
    if (confirmed.kind !== "record") return confirmed.kind === "absent"
      ? { kind: "corrupt", message: "the anchor reservation disappeared after it was written" }
      : confirmed;
    return confirmed.record.ownerToken === ownerToken && confirmed.record.phase === "creating_request"
      ? { kind: "claimed", record: confirmed.record }
      : { kind: "busy", record: confirmed.record };
  }

  /** Claims an existing operation only after its previous short lease expires. */
  claim(bundleKey: string, ownerToken: string, nowMs: number = Date.now()): RecoveryClaim {
    const state = this.loadState(bundleKey);
    if (state.kind !== "record") return state;
    if (state.record.ownerToken !== ownerToken && state.record.leaseExpiresAtMs > nowMs) {
      return { kind: "busy", record: state.record };
    }
    const record: AnchorRecoveryRecord = {
      ...state.record,
      ownerToken,
      leaseExpiresAtMs: nowMs + LEASE_MS,
      updatedAtMs: nowMs,
    };
    try {
      this.storage.setItem(bundleKey, JSON.stringify(record));
    } catch {
      return { kind: "corrupt", message: "the anchor operation could not be claimed in durable storage" };
    }
    const confirmed = this.loadState(bundleKey);
    if (confirmed.kind !== "record") return confirmed.kind === "absent"
      ? { kind: "corrupt", message: "the claimed anchor state disappeared" }
      : confirmed;
    return confirmed.record.ownerToken === ownerToken
      ? { kind: "claimed", record: confirmed.record }
      : { kind: "busy", record: confirmed.record };
  }

  saveOwned(
    bundleKey: string,
    ownerToken: string,
    record: Omit<AnchorRecoveryRecord, "ownerToken" | "leaseExpiresAtMs" | "updatedAtMs">,
    nowMs: number = Date.now(),
  ): AnchorRecoveryRecord {
    const current = this.loadState(bundleKey);
    if (current.kind !== "record" || current.record.ownerToken !== ownerToken) {
      throw new Error("the saved anchor operation is no longer owned by this tab");
    }
    const next: AnchorRecoveryRecord = {
      ...record,
      ownerToken,
      leaseExpiresAtMs: nowMs + LEASE_MS,
      updatedAtMs: nowMs,
    };
    this.storage.setItem(bundleKey, JSON.stringify(next));
    const confirmed = this.loadState(bundleKey);
    if (confirmed.kind !== "record" || confirmed.record.ownerToken !== ownerToken || confirmed.record.phase !== next.phase) {
      throw new Error("the anchor state could not be durably confirmed");
    }
    return confirmed.record;
  }

  /** Legacy presentation helper. New request paths must reserve/claim first. */
  save(bundleKey: string, record: AnchorRecoveryRecord): void {
    if (!validRecord(record)) throw new Error("invalid anchor recovery record");
    this.storage.setItem(bundleKey, JSON.stringify(record));
  }

  clear(bundleKey: string): void {
    this.storage.removeItem(bundleKey);
  }
}

export function newRecoveryOwnerToken(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function browserRecoveryStore(): AnchorRecoveryStore {
  return new AnchorRecoveryStore(localStorage);
}
