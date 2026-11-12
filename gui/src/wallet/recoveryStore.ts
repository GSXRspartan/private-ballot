export interface AnchorRecoveryRecord {
  phase: "submitted_awaiting_approval" | "approved_submitted" | "verifying" | "verified";
  requestId: string | null;
  transactionId: string | null;
  updatedAtMs: number;
}

export interface RecoveryStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export class AnchorRecoveryStore {
  private readonly storage: RecoveryStorage;

  constructor(storage: RecoveryStorage) {
    this.storage = storage;
  }

  load(bundleKey: string): AnchorRecoveryRecord | null {
    const raw = this.storage.getItem(bundleKey);
    if (raw === null) {
      return null;
    }
    try {
      const parsed = JSON.parse(raw) as Partial<AnchorRecoveryRecord>;
      if (
        (parsed.phase !== "submitted_awaiting_approval" &&
          parsed.phase !== "approved_submitted" &&
          parsed.phase !== "verifying" &&
          parsed.phase !== "verified") ||
        typeof parsed.updatedAtMs !== "number" ||
        (parsed.requestId !== null && typeof parsed.requestId !== "string") ||
        (parsed.transactionId !== null && typeof parsed.transactionId !== "string")
      ) {
        return null;
      }
      return {
        phase: parsed.phase,
        requestId: parsed.requestId ?? null,
        transactionId: parsed.transactionId ?? null,
        updatedAtMs: parsed.updatedAtMs,
      };
    } catch {
      return null;
    }
  }

  save(bundleKey: string, record: AnchorRecoveryRecord): void {
    this.storage.setItem(bundleKey, JSON.stringify(record));
  }

  clear(bundleKey: string): void {
    this.storage.removeItem(bundleKey);
  }
}

export function browserRecoveryStore(): AnchorRecoveryStore {
  return new AnchorRecoveryStore(localStorage);
}
