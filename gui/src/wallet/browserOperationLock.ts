/**
 * Cross-tab serialization for an operation that may ask a wallet to create or
 * submit a transaction. localStorage is durable but has no compare-and-swap,
 * so it cannot by itself make an absent-record reservation atomic.
 */
export interface BrowserOperationLocks {
  request<T>(
    name: string,
    options: { mode: "exclusive"; ifAvailable: true },
    callback: (lock: object | null) => Promise<T> | T,
  ): Promise<T>;
}

function browserLocks(): BrowserOperationLocks | null {
  if (typeof navigator === "undefined" || !navigator.locks) return null;
  return navigator.locks as unknown as BrowserOperationLocks;
}

function lockName(bundleKey: string): string {
  return `tari-private-ballot:anchor-publish:${bundleKey}`;
}

/**
 * The Web Locks API is the browser-wide mutex. Absence is a hard stop: without
 * it two renderer processes could interleave localStorage writes and both
 * believe that they reserved the same anchor operation.
 */
export async function withExclusiveAnchorOperation<T>(
  bundleKey: string,
  action: () => Promise<T> | T,
  locks: BrowserOperationLocks | null = browserLocks(),
): Promise<T> {
  if (locks === null) {
    throw new Error("This browser cannot safely serialize anchor publishing across tabs.");
  }
  return locks.request(lockName(bundleKey), { mode: "exclusive", ifAvailable: true }, async (lock) => {
    if (lock === null) {
      throw new Error("Another tab is already handling this anchor operation.");
    }
    return action();
  });
}
