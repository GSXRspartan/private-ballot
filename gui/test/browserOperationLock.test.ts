import assert from "node:assert/strict";
import test from "node:test";

import {
  type BrowserOperationLocks,
  withExclusiveAnchorOperation,
} from "../src/wallet/browserOperationLock.ts";

class ExclusiveTestLocks implements BrowserOperationLocks {
  private readonly held = new Set<string>();

  async request<T>(
    name: string,
    _options: { mode: "exclusive"; ifAvailable: true },
    callback: (lock: object | null) => Promise<T> | T,
  ): Promise<T> {
    if (this.held.has(name)) return callback(null);
    this.held.add(name);
    try {
      return await callback({});
    } finally {
      this.held.delete(name);
    }
  }
}

test("cross-tab browser lock permits only one anchor operation for one bundle", async () => {
  const locks = new ExclusiveTestLocks();
  let release: (() => void) | null = null;
  let entered: (() => void) | null = null;
  const firstEntered = new Promise<void>((resolve) => { entered = resolve; });
  const firstRelease = new Promise<void>((resolve) => { release = resolve; });

  const first = withExclusiveAnchorOperation("mainnet:bundle", async () => {
    entered?.();
    await firstRelease;
    return "first";
  }, locks);
  await firstEntered;

  await assert.rejects(
    withExclusiveAnchorOperation("mainnet:bundle", () => "second", locks),
    /Another tab is already handling this anchor operation/,
  );
  release?.();
  assert.equal(await first, "first");
  assert.equal(await withExclusiveAnchorOperation("mainnet:bundle", () => "next", locks), "next");
});

test("missing browser lock support fails closed", async () => {
  await assert.rejects(
    withExclusiveAnchorOperation("mainnet:bundle", () => undefined, null),
    /cannot safely serialize anchor publishing across tabs/,
  );
});
