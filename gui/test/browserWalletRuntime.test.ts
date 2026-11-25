import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { createBrowserWalletRuntime } from "../src/wallet/browserWalletRuntime.ts";
import { walletEntryStatus } from "../src/wallet/settingsState.ts";
import type { WalletEntry } from "../src/wallet/settingsState.ts";
import type { TariProviderLike } from "../src/wallet/types.ts";

interface ProviderInit {
  accounts?: () => string[];
  network?: () => string;
  capabilities?: () => unknown;
  on?: (event: string, listener: (payload: unknown) => void) => unknown;
}

function embeddedProvider(init: ProviderInit = {}): TariProviderLike {
  return {
    isTariWallet: true,
    isEmbedded: true,
    info: { name: "Tari Universe", rdns: "mw.tari.universe", embedded: true },
    request(args: { method: string; params?: unknown }) {
      switch (args.method) {
        case "tari_requestAccounts":
          return (init.accounts ?? (() => ["component_a"]))();
        case "tari_getAccounts":
          return (init.accounts ?? (() => ["component_a"]))();
        case "tari_getNetwork":
          return (init.network ?? (() => "mainnet"))();
        case "tari_getCapabilities":
          return (
            init.capabilities ??
            (() => ({ transactionRequests: true, transactionResultLookup: true, dryRunIsLocal: true }))
          )();
        default:
          throw new Error(`unexpected method ${args.method}`);
      }
    },
    on: init.on,
  };
}

function scopeOf(provider: TariProviderLike) {
  return { tariUniverse: provider, tariProviders: [provider], addEventListener: () => () => {} };
}

function rejected(code: number, message: string): never {
  const error = new Error(message) as Error & { code: number };
  error.code = code;
  throw error;
}

describe("browser wallet runtime failure paths", () => {
  it("maps a declined connect to connect_failed with no auto-retry and no retained connection", async () => {
    let requestAccountsCalls = 0;
    const provider = embeddedProvider({
      accounts: () => {
        requestAccountsCalls += 1;
        return rejected(4001, "user rejected");
      },
    });
    const runtime = createBrowserWalletRuntime(scopeOf(provider), 0);
    const entries: WalletEntry[] = [];
    const onEntry = (_kind: "sapient" | "universe", entry: WalletEntry) => entries.push(entry);

    await runtime.connect("universe", onEntry);

    assert.equal(entries.length, 2);
    assert.equal(entries[0].phase.kind, "connecting");
    assert.equal(entries[1].phase.kind, "connect_failed");
    assert.match(walletEntryStatus(entries[1]), /declined in the wallet/);
    assert.equal(requestAccountsCalls, 1);
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(entries.length, 2, "no automatic reconnect after a rejection");
    assert.equal(requestAccountsCalls, 1, "no automatic request resubmission");
  });

  it("clears a connected entry on an empty accountsChanged and stays cleared", async () => {
    let accountsChangedListener: ((payload: unknown) => void) | null = null;
    let requestAccountsCalls = 0;
    const provider = embeddedProvider({
      accounts: () => {
        requestAccountsCalls += 1;
        return ["component_a"];
      },
      on: (event, listener) => {
        if (event === "accountsChanged") accountsChangedListener = listener;
        return () => {};
      },
    });
    const runtime = createBrowserWalletRuntime(scopeOf(provider), 0);
    const entries: WalletEntry[] = [];
    await runtime.connect("universe", (_kind, entry) => entries.push(entry));

    const connected = entries.at(-1);
    assert.equal(connected?.phase.kind, "connected");
    assert.equal(typeof accountsChangedListener, "function");

    accountsChangedListener!([]);
    assert.equal(entries.at(-1)?.phase.kind, "needs_connect");
    accountsChangedListener!(["component_a"]);
    assert.equal(entries.at(-1)?.phase.kind, "needs_connect", "no implicit reconnect on a later event");
    assert.equal(requestAccountsCalls, 1, "disconnect never triggers another connect request");
  });

  it("reports a rejected capabilities probe as unavailable without hiding the wallet entirely", async () => {
    const provider = embeddedProvider({
      capabilities: () => rejected(4001, "user rejected"),
    });
    const runtime = createBrowserWalletRuntime(scopeOf(provider), 0);
    const entries: WalletEntry[] = [];
    await runtime.probeAll((_kind, entry) => entries.push(entry));

    const universe = entries.find((entry) => entry.kind === "universe" && entry.phase.kind !== "checking");
    assert.equal(universe?.phase.kind, "unavailable");
    assert.match(walletEntryStatus(universe!), /declined in the wallet/);
  });
});
