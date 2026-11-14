import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  hasCapability,
  sapientDiscovery,
  universeDiscovery,
  waitForTariInit,
  windowTariProvider,
} from "../src/wallet/provider.ts";
import type { TariProviderLike } from "../src/wallet/types.ts";

type Handler = (params: unknown) => unknown;

interface FakeProviderInit {
  handlers: Record<string, Handler>;
  on?: (event: string, listener: (payload: unknown) => void) => unknown;
  isEmbedded?: boolean;
  info?: TariProviderLike["info"];
}

function fakeProvider(init: FakeProviderInit): TariProviderLike {
  return {
    isTariWallet: true,
    isEmbedded: init.isEmbedded,
    info: init.info,
    request(args: { method: string; params?: unknown }) {
      const handler = init.handlers[args.method];
      if (!handler) {
        const error = new Error(`unsupported method ${args.method}`);
        (error as { code: number }).code = -32601;
        throw error;
      }
      return handler(args.params);
    },
    on: init.on,
  };
}

function scopeWith(provider: unknown): { tari?: unknown } {
  return { tari: provider };
}

const noopSleep = async () => {};

describe("sapient discovery", () => {
  it("finds an extension provider that is not embedded", () => {
    const provider = fakeProvider({ handlers: {} });
    const found = sapientDiscovery(scopeWith(provider));
    assert.equal(found.provider, provider);
    assert.equal(found.reason, null);
  });

  it("refuses an embedded provider (that is Universe's iframe)", () => {
    const provider = fakeProvider({ handlers: {}, isEmbedded: true });
    const found = sapientDiscovery(scopeWith(provider));
    assert.equal(found.provider, null);
    assert.match(found.reason ?? "", /Sapient|universe\.tari\.mw/);
  });

  it("does not mistake the non-embedded Universe bridge for Sapient", () => {
    const provider = fakeProvider({
      handlers: {},
      info: { name: "Tari Universe", rdns: "mw.tari.universe", embedded: true },
    });
    const found = sapientDiscovery(scopeWith(provider));
    assert.equal(found.provider, null);
  });

  it("reports absent wallets honestly", () => {
    const found = sapientDiscovery(scopeWith(undefined));
    assert.equal(found.provider, null);
    assert.match(found.reason ?? "", /No Tari wallet answered/);
  });

  it("refuses objects that are not marked isTariWallet", () => {
    const found = sapientDiscovery(scopeWith({ request: async () => ({}) }));
    assert.equal(found.provider, null);
  });
});

describe("universe discovery", () => {
  it("finds an embedded provider", () => {
    const provider = fakeProvider({ handlers: {}, isEmbedded: true });
    const found = universeDiscovery(scopeWith(provider));
    assert.equal(found.provider, provider);
  });

  it("uses the named connector fallback when an extension already owns window.tari", () => {
    const extension = fakeProvider({ handlers: {} });
    const universe = fakeProvider({
      handlers: {},
      isEmbedded: true,
      info: { name: "Tari Universe", rdns: "mw.tari.universe", embedded: true },
    });
    const found = universeDiscovery({ tari: extension, tariUniverse: universe });
    assert.equal(found.provider, universe);
  });

  it("uses the connector registry fallback when the named global is unavailable", () => {
    const extension = fakeProvider({ handlers: {} });
    const universe = fakeProvider({
      handlers: {},
      isEmbedded: true,
      info: { name: "Tari Universe", rdns: "mw.tari.universe", embedded: true },
    });
    const found = universeDiscovery({ tari: extension, tariProviders: [universe] });
    assert.equal(found.provider, universe);
  });

  it("refuses a provider when the page is not embedded", () => {
    const provider = fakeProvider({ handlers: {} });
    const found = universeDiscovery(scopeWith(provider));
    assert.equal(found.provider, null);
    assert.match(found.reason ?? "", /not running inside it/);
  });

  it("reports absent wallets honestly", () => {
    const found = universeDiscovery(scopeWith(undefined));
    assert.equal(found.provider, null);
    assert.match(found.reason ?? "", /universe\.tari\.mw/);
  });
});

describe("probe", () => {
  it("reports unavailable with the discovery reason when no wallet is present", async () => {
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(undefined)),
    );
    const probe = await adapter.probe();
    assert.equal(probe.available, false);
    assert.equal(probe.state, "unavailable");
    assert.match(probe.unavailableReason ?? "", /No Tari wallet answered/);
    assert.equal(probe.capabilities, null);
  });

  it("reports available with capabilities when the wallet answers", async () => {
    const provider = fakeProvider({
      handlers: {
        tari_getCapabilities: () => ({
          transactionRequests: true,
          transactionResultLookup: true,
        }),
      },
    });
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(provider)),
    );
    const probe = await adapter.probe();
    assert.equal(probe.available, true);
    assert.equal(probe.state, "available");
    assert.deepEqual(probe.capabilities, {
      transactionRequests: true,
      transactionResultLookup: true,
    });
  });

  it("treats 4100 as available but needing connect, never as absent", async () => {
    const provider = fakeProvider({
      handlers: {
        tari_getCapabilities: () => {
          const error = new Error("not connected");
          (error as { code: number }).code = 4100;
          throw error;
        },
      },
    });
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(provider)),
    );
    const probe = await adapter.probe();
    assert.equal(probe.available, true);
    assert.equal(probe.state, "needs_connect");
    assert.match(probe.unusableReason ?? "", /not connected to this site yet/);
  });

  it("maps 4200 to unsupported", async () => {
    const provider = fakeProvider({
      handlers: {
        tari_getCapabilities: () => {
          const error = new Error("unsupported");
          (error as { code: number }).code = 4200;
          throw error;
        },
      },
    });
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(provider)),
    );
    const probe = await adapter.probe();
    assert.equal(probe.available, false);
    assert.equal(probe.state, "unsupported");
  });

  it("surfaces a malformed capabilities answer as unavailable, never a throw", async () => {
    for (const bad of [{}, null, [], { capabilities: ["transactionRequests"] }, { transactionRequests: true }, { transactionRequests: "true", transactionResultLookup: true }]) {
      const provider = fakeProvider({
        handlers: { tari_getCapabilities: () => bad },
      });
      const adapter = windowTariProvider("sapient", "Sapient", () =>
        sapientDiscovery(scopeWith(provider)),
      );
      const probe = await adapter.probe();
      assert.equal(probe.available, false);
      assert.equal(probe.state, "unavailable");
      assert.match(probe.unavailableReason ?? "", /malformed capabilities/);
    }
  });
});

describe("connect", () => {
  it("pins one discovered provider for the operation", async () => {
    const first = fakeProvider({
      handlers: { tari_requestAccounts: () => ["component_first"] },
    });
    const second = fakeProvider({
      handlers: { tari_requestAccounts: () => ["component_second"] },
    });
    let current: TariProviderLike = first;
    const adapter = windowTariProvider("sapient", "Sapient", () => ({ provider: current, reason: null })).pin();
    current = second;
    assert.deepEqual(await adapter.connect(), ["component_first"]);
  });

  it("reads already-authorized accounts without a second connection prompt", async () => {
    const provider = fakeProvider({
      handlers: { tari_getAccounts: () => ["component_abc"] },
    });
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(provider)),
    ).pin();
    assert.deepEqual(await adapter.getAccounts(), ["component_abc"]);
  });

  it("requests accounts and returns them", async () => {
    let requestCount = 0;
    const provider = fakeProvider({
      handlers: {
        tari_requestAccounts: () => {
          requestCount += 1;
          return ["component_abc", "component_def"];
        },
      },
    });
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(provider)),
    );
    assert.deepEqual(await adapter.connect(), ["component_abc", "component_def"]);
    assert.equal(requestCount, 1);
  });

  it("maps 4001 to the declined label", async () => {
    const provider = fakeProvider({
      handlers: {
        tari_requestAccounts: () => {
          const error = new Error("declined");
          (error as { code: number }).code = 4001;
          throw error;
        },
      },
    });
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(provider)),
    );
    await assert.rejects(
      () => adapter.connect(),
      (e: { code: unknown }) => e.code === 4001,
    );
  });

  it("rejects malformed accounts answers", async () => {
    const provider = fakeProvider({
      handlers: { tari_requestAccounts: () => ({}) },
    });
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(provider)),
    );
    await assert.rejects(adapter.connect(), /malformed accounts answer/);
  });

  it("rejects empty account strings", async () => {
    const provider = fakeProvider({
      handlers: { tari_requestAccounts: () => ["component_abc", ""] },
    });
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(provider)),
    );
    await assert.rejects(adapter.connect(), /malformed accounts answer/);
  });
});

describe("getNetwork and getCapabilities", () => {
  it("returns the published string wallet network answer", async () => {
    const provider = fakeProvider({
      handlers: { tari_getNetwork: () => "mainnet" },
    });
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(provider)),
    );
    assert.deepEqual(await adapter.getNetwork(), { network: "mainnet" });
  });

  it("throws on a malformed network answer", async () => {
    const provider = fakeProvider({
      handlers: { tari_getNetwork: () => ({}) },
    });
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(provider)),
    );
    await assert.rejects(adapter.getNetwork(), /malformed network answer/);
  });

  it("hasCapability checks the published boolean fields", async () => {
    const provider = fakeProvider({
      handlers: {
        tari_getCapabilities: () => ({
          transactionRequests: true,
          transactionResultLookup: false,
        }),
      },
    });
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(provider)),
    );
    const caps = await adapter.getCapabilities();
    assert.equal(hasCapability(caps, "transactionRequests"), true);
    assert.equal(hasCapability(caps, "transactionResultLookup"), false);
    assert.equal(hasCapability(null, "transactionRequests"), false);
  });
});

describe("transaction requests", () => {
  it("creates an instructions request and returns its id", async () => {
    let captured: unknown = undefined;
    const provider = fakeProvider({
      handlers: {
        tari_createTransactionRequest: (params) => {
          captured = params;
          return { requestId: "req_1" };
        },
      },
    });
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(provider)),
    );
    const instructions = [{ CallFunction: { address: "template_00", function: "f", args: [] } }];
    const created = await adapter.createTransactionRequest(instructions, "100000");
    assert.equal(created.requestId, "req_1");
    assert.deepEqual(captured, {
      kind: "instructions",
      instructions,
      maxFee: "100000",
    });
  });

  it("omits maxFee when not supplied", async () => {
    let captured: unknown = undefined;
    const provider = fakeProvider({
      handlers: {
        tari_createTransactionRequest: (params) => {
          captured = params;
          return { requestId: "req_1" };
        },
      },
    });
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(provider)),
    );
    await adapter.createTransactionRequest([]);
    assert.deepEqual(captured, { kind: "instructions", instructions: [] });
  });

  it("throws on a malformed create answer", async () => {
    const provider = fakeProvider({
      handlers: { tari_createTransactionRequest: () => ({}) },
    });
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(provider)),
    );
    await assert.rejects(
      () => adapter.createTransactionRequest([]),
      /malformed transaction request answer/,
    );
  });

  it("returns terminal summaries: approved", async () => {
    const provider = fakeProvider({
      handlers: {
        tari_getTransactionRequest: () => ({ status: "approved" }),
      },
    });
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(provider)),
    );
    const summary = await adapter.pollTransactionRequest("req_1", {
      sleep: noopSleep,
    });
    assert.equal(summary.status, "approved");
  });

  it("returns rejected summaries with the wallet error attached", async () => {
    const provider = fakeProvider({
      handlers: {
        tari_getTransactionRequest: () => ({
          status: "rejected",
          error: "user declined",
        }),
      },
    });
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(provider)),
    );
    const summary = await adapter.pollTransactionRequest("req_1", {
      sleep: noopSleep,
    });
    assert.equal(summary.status, "rejected");
    assert.equal(summary.error, "user declined");
  });

  it("keeps polling pending until a terminal status arrives", async () => {
    let calls = 0;
    const provider = fakeProvider({
      handlers: {
        tari_getTransactionRequest: () => {
          calls += 1;
          if (calls < 3) {
            return { status: calls === 1 ? "pending" : "submitting" };
          }
          return { status: "approved" };
        },
      },
    });
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(provider)),
    );
    const summary = await adapter.pollTransactionRequest("req_1", {
      sleep: noopSleep,
    });
    assert.equal(summary.status, "approved");
    assert.equal(calls, 3);
  });

  it("stops at the deadline instead of polling forever", async () => {
    const provider = fakeProvider({
      handlers: {
        tari_getTransactionRequest: () => ({ status: "pending" }),
      },
    });
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(provider)),
    );
    await assert.rejects(
      () =>
        adapter.pollTransactionRequest("req_1", {
          sleep: noopSleep,
          timeoutMs: 0,
        }),
      (e: Error) => /req_1/.test(e.message) && /did not settle/.test(e.message),
    );
  });

  it("throws on a malformed status answer", async () => {
    const provider = fakeProvider({
      handlers: {
        tari_getTransactionRequest: () => ({ status: "mystery" }),
      },
    });
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(provider)),
    );
    await assert.rejects(
      () => adapter.pollTransactionRequest("req_1", { sleep: noopSleep }),
      /malformed transaction request status/,
    );
  });

  it("submits an approved request and validates the transaction id", async () => {
    let captured: unknown = undefined;
    const provider = fakeProvider({
      handlers: {
        tari_submitTransactionRequest: (params) => {
          captured = params;
          return { transactionId: "txn_1" };
        },
      },
    });
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(provider)),
    );
    const submitted = await adapter.submitTransactionRequest("req_1");
    assert.equal(submitted.transactionId, "txn_1");
    assert.deepEqual(captured, { requestId: "req_1" });
  });

  it("throws on a malformed submit answer", async () => {
    const provider = fakeProvider({
      handlers: { tari_submitTransactionRequest: () => ({ nope: true }) },
    });
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(provider)),
    );
    await assert.rejects(adapter.submitTransactionRequest("req_1"), /malformed submit answer/);
  });
});

describe("result lookup and accountsChanged", () => {
  it("passes the transaction id through for result lookup", async () => {
    let captured: { method: unknown; params: unknown } | undefined = undefined;
    const provider = fakeProvider({
      handlers: {
        tari_getTransactionResult: () => ({ result: { Pending: {} } }),
      },
      on: () => undefined,
    });
    provider.request = async (args) => {
      captured = args;
      return { result: { Pending: {} } };
    };
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(provider)),
    );
    const result = await adapter.getTransactionResult("txn_1");
    assert.deepEqual(result, { result: { Pending: {} } });
    assert.deepEqual(captured, {
      method: "tari_getTransactionResult",
      params: { transactionId: "txn_1" },
    });
  });

  it("maps provider errors during result lookup", async () => {
    const provider = fakeProvider({
      handlers: {
        tari_getTransactionResult: () => {
          const error = new Error("not connected");
          (error as { code: number }).code = 4100;
          throw error;
        },
      },
    });
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(provider)),
    );
    await assert.rejects(
      () => adapter.getTransactionResult("txn_1"),
      (e: { code: unknown }) => e.code === 4100,
    );
  });

  it("wires accountsChanged without acting on it", () => {
    const listeners: Array<(payload: unknown) => void> = [];
    const provider = fakeProvider({
      handlers: {},
      on: (event, listener) => {
        assert.equal(event, "accountsChanged");
        listeners.push(listener);
      },
    });
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(provider)),
    );
    let fired: unknown = null;
    adapter.onAccountsChanged((payload) => {
      fired = payload;
    });
    assert.equal(listeners.length, 1);
    listeners[0](["component_abc"]);
    assert.deepEqual(fired, ["component_abc"]);
  });

  it("tolerates providers without an on() method", () => {
    const provider = fakeProvider({ handlers: {} }) as TariProviderLike;
    delete (provider as { on?: unknown }).on;
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(provider)),
    );
    assert.doesNotThrow(() => adapter.onAccountsChanged(() => undefined));
  });
});

describe("delayed provider injection", () => {
  it("resolves true when tari#initialized fires before the deadline", async () => {
    const listeners: Array<() => void> = [];
    const scope = {
      addEventListener: (type: string, listener: () => void) => {
        assert.equal(type, "tari#initialized");
        listeners.push(listener);
      },
    };
    const promise = waitForTariInit(scope, 1000);
    listeners[0]();
    assert.equal(await promise, true);
  });

  it("resolves false after the deadline passes without the event", async () => {
    const scope = {
      addEventListener: () => undefined,
    };
    assert.equal(await waitForTariInit(scope, 20), false);
  });

  it("resolves false when no listener registration is possible", async () => {
    assert.equal(await waitForTariInit({}, 20), false);
  });
});
