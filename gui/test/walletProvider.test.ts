import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  extractDryRunFeeEstimate,
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
      dryRunIsLocal: null,
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

  it("maps a 4001 rejection from capabilities to unavailable without claiming an absent wallet", async () => {
    const provider = fakeProvider({
      handlers: {
        tari_getCapabilities: () => {
          const error = new Error("user rejected");
          (error as { code: number }).code = 4001;
          throw error;
        },
      },
      isEmbedded: true,
    });
    const adapter = windowTariProvider("universe", "Tari Universe", () =>
      universeDiscovery({ tariUniverse: provider }),
    );
    const probe = await adapter.probe();
    assert.equal(probe.available, false);
    assert.equal(probe.state, "unavailable");
    assert.match(probe.unavailableReason ?? "", /declined in the wallet/);
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

describe("provider identity guard before money-moving calls", () => {
  it("refuses to create a request after the page's wallet object was swapped", async () => {
    // Built directly so the counters stay inspectable.
    let createCalls = 0;
    const pinned = fakeProvider({
      handlers: {
        tari_createTransactionRequest: () => {
          createCalls += 1;
          return { requestId: "req_pinned" };
        },
      },
    });
    const impostor = fakeProvider({
      handlers: {
        tari_createTransactionRequest: () => {
          createCalls += 1;
          return { requestId: "req_impostor" };
        },
      },
    });
    const holder: { tari?: unknown } = { tari: pinned };
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(holder),
    );
    adapter.pin();
    holder.tari = impostor;

await assert.rejects(
      () => adapter.createTransactionRequest([]),
      /no longer the same provider/,
    );
    // Neither the pinned (stale) object nor the impostor is trusted.
    assert.equal(createCalls, 0);
  });

  it("refuses to submit after the page's wallet object was swapped", async () => {
    let submitCalls = 0;
    const pinned = fakeProvider({
      handlers: {
        tari_submitTransactionRequest: () => {
          submitCalls += 1;
          return { transactionId: "tx_pinned" };
        },
      },
    });
    const impostor = fakeProvider({
      handlers: {
        tari_submitTransactionRequest: () => {
          submitCalls += 1;
          return { transactionId: "tx_impostor" };
        },
      },
    });
    const holder: { tari?: unknown } = { tari: pinned };
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(holder),
    );
    adapter.pin();
    holder.tari = impostor;

await assert.rejects(
      () => adapter.submitTransactionRequest("req_1"),
      /no longer the same provider/,
    );
    assert.equal(submitCalls, 0);
  });

  it("proceeds when discovery still resolves the pinned provider", async () => {
    const provider = fakeProvider({
      handlers: {
        tari_createTransactionRequest: () => ({ requestId: "req_1" }),
      },
    });
    const holder: { tari?: unknown } = { tari: provider };
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(holder),
    );
    adapter.pin();
    holder.tari = provider;
    const created = await adapter.createTransactionRequest([]);
    assert.equal(created.requestId, "req_1");
  });

it("fails closed when provider disappears before create", async () => {
    const provider = fakeProvider({
      handlers: {
        tari_createTransactionRequest: () => ({ requestId: "req_1" }),
      },
    });
    const holder: { tari?: unknown } = { tari: provider };
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(holder),
    );
    adapter.pin();
    holder.tari = undefined;

    await assert.rejects(
      () => adapter.createTransactionRequest([]),
      /no longer the same provider/,
    );
  });

  it("fails closed when provider disappears after approval before submit", async () => {
    const provider = fakeProvider({
      handlers: {
        tari_submitTransactionRequest: () => ({ transactionId: "txn_1" }),
      },
    });
    const holder: { tari?: unknown } = { tari: provider };
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(holder),
    );
    adapter.pin();
    holder.tari = undefined;

    await assert.rejects(
      () => adapter.submitTransactionRequest("req_1"),
      /no longer the same provider/,
    );
  });

  it("fails closed when replacement provider appears before create", async () => {
    let createCalls = 0;
    const pinned = fakeProvider({
      handlers: {
        tari_createTransactionRequest: () => {
          createCalls += 1;
          return { requestId: "req_pinned" };
        },
      },
    });
    const impostor = fakeProvider({
      handlers: {
        tari_createTransactionRequest: () => {
          createCalls += 1;
          return { requestId: "req_impostor" };
        },
      },
    });
    const holder: { tari?: unknown } = { tari: pinned };
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(holder),
    );
    adapter.pin();
    holder.tari = impostor;

    await assert.rejects(
      () => adapter.createTransactionRequest([]),
      /no longer the same provider/,
    );
    assert.equal(createCalls, 0);
  });

  it("fails closed when replacement provider appears after approval before submit", async () => {
    let submitCalls = 0;
    const pinned = fakeProvider({
      handlers: {
        tari_submitTransactionRequest: () => {
          submitCalls += 1;
          return { transactionId: "tx_pinned" };
        },
      },
    });
    const impostor = fakeProvider({
      handlers: {
        tari_submitTransactionRequest: () => {
          submitCalls += 1;
          return { transactionId: "tx_impostor" };
        },
      },
    });
    const holder: { tari?: unknown } = { tari: pinned };
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(holder),
    );
    adapter.pin();
    holder.tari = impostor;

    await assert.rejects(
      () => adapter.submitTransactionRequest("req_1"),
      /no longer the same provider/,
    );
    assert.equal(submitCalls, 0);
  });

  it("proceeds normally when provider/account/network/capabilities unchanged", async () => {
    const provider = fakeProvider({
      handlers: {
        tari_createTransactionRequest: () => ({ requestId: "req_1" }),
        tari_submitTransactionRequest: () => ({ transactionId: "txn_1" }),
      },
    });
    const holder: { tari?: unknown } = { tari: provider };
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(holder),
    );
    adapter.pin();
    const created = await adapter.createTransactionRequest([]);
    assert.equal(created.requestId, "req_1");
    const submitted = await adapter.submitTransactionRequest(created.requestId);
    assert.equal(submitted.transactionId, "txn_1");
  });
});

describe("non-spending dry-run fee preflight (adapter boundary)", () => {
  function dryRunAdapter(handlers: Record<string, Handler>) {
    return windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(fakeProvider({ handlers }))),
    );
  }

  it("sends dryRun:true and forwards the maxFee verbatim (decimal-string is the driver's job)", async () => {
    let capturedParams: unknown = undefined;
    const adapter = dryRunAdapter({
      tari_signAndSubmitTransaction: (params) => {
        capturedParams = params;
        return { result: { required_fees: "5000" } };
      },
    });
    const instructions = [{ CallFunction: { address: "template_00", function: "f", args: [] } }];
    // The driver passes maxFee as a decimal string; the adapter forwards verbatim.
    await adapter.signAndSubmitTransactionDryRun(instructions, "1000");
    assert.deepEqual(capturedParams, {
      instructions,
      dryRun: true,
      maxFee: "1000",
    });
  });

  it("omits maxFee entirely when no cap is supplied", async () => {
    let capturedParams: unknown = undefined;
    const adapter = dryRunAdapter({
      tari_signAndSubmitTransaction: (params) => {
        capturedParams = params;
        return { transaction_id: "deadbeef", result: { finalize: { total_fees_required: "5000", result: { Accept: {} } } } };
      },
    });
    await adapter.signAndSubmitTransactionDryRun([]);
    assert.deepEqual(capturedParams, { instructions: [], dryRun: true });
  });

  it("extracts total_fees_required from the real Sapient dry-run result with an Accept outcome", async () => {
    const adapter = dryRunAdapter({
      tari_signAndSubmitTransaction: () => ({
        transaction_id: "abc123",
        result: { finalize: { total_fees_required: "1234", result: { Accept: {} } } },
      }),
    });
    const estimate = await adapter.signAndSubmitTransactionDryRun([]);
    assert.deepEqual(estimate, { kind: "estimated", requiredFeesMicrotari: "1234" });
  });

  it("does NOT fall back to fee_receipt.total_fees_paid (not a required-fee estimate)", async () => {
    const adapter = dryRunAdapter({
      tari_signAndSubmitTransaction: () => ({
        transaction_id: "abc123",
        result: { finalize: { fee_receipt: { total_fees_paid: "777" }, result: { Accept: {} } } },
      }),
    });
    const estimate = await adapter.signAndSubmitTransactionDryRun([]);
    assert.equal(estimate.kind, "unsupported");
    if (estimate.kind === "unsupported") {
      assert.match(estimate.reason, /did not expose a verifiable fee field/);
    }
  });

  it("requires an explicit Accept outcome (resolved promise alone is insufficient)", async () => {
    // total_fees_required is present but there is no Accept arm.
    const adapter = dryRunAdapter({
      tari_signAndSubmitTransaction: () => ({
        transaction_id: "abc123",
        result: { finalize: { total_fees_required: "1234" } },
      }),
    });
    const estimate = await adapter.signAndSubmitTransactionDryRun([]);
    assert.equal(estimate.kind, "unsupported");
    if (estimate.kind === "unsupported") {
      assert.match(estimate.reason, /explicit Accept outcome/);
    }
  });

  it("refuses to report a fee for a rejected simulation (Reject / AcceptFeeRejectRest)", async () => {
    for (const rejected of [
      { Reject: { ExecutionFailure: "boom" } },
      { AcceptFeeRejectRest: [{}, { ExecutionFailure: "nope" }] },
    ]) {
      const adapter = dryRunAdapter({
        tari_signAndSubmitTransaction: () => ({
          transaction_id: "abc123",
          result: { finalize: { total_fees_required: "1234", result: rejected } },
        }),
      });
      const estimate = await adapter.signAndSubmitTransactionDryRun([]);
      assert.equal(estimate.kind, "unsupported", `rejected ${JSON.stringify(rejected)}`);
    }
  });

  it("returns unsupported (never invents a figure) when the fee field is absent but Accept is present", async () => {
    const adapter = dryRunAdapter({
      tari_signAndSubmitTransaction: () => ({
        transaction_id: "abc123",
        result: { finalize: { result: { Accept: {} } } },
      }),
    });
    const estimate = await adapter.signAndSubmitTransactionDryRun([]);
    assert.equal(estimate.kind, "unsupported");
    if (estimate.kind === "unsupported") {
      assert.match(estimate.reason, /did not expose a verifiable fee field/);
    }
  });

  it("returns unsupported for a non-object dry-run result", async () => {
    const adapter = dryRunAdapter({
      tari_signAndSubmitTransaction: () => ({ result: null }),
    });
    const estimate = await adapter.signAndSubmitTransactionDryRun([]);
    assert.equal(estimate.kind, "unsupported");
  });

  it("fails closed (throws) on a provider rejection — never falls back to submission", async () => {
    let createCalls = 0;
    let submitCalls = 0;
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(fakeProvider({
        handlers: {
          tari_signAndSubmitTransaction: () => {
            const error = new Error("user rejected");
            (error as { code: number }).code = 4001;
            throw error;
          },
          tari_createTransactionRequest: () => { createCalls += 1; return { requestId: "x" }; },
          tari_submitTransactionRequest: () => { submitCalls += 1; return { transactionId: "t" }; },
        },
      }))),
    );
    await assert.rejects(() => adapter.signAndSubmitTransactionDryRun([]), /user rejected/);
    assert.equal(createCalls, 0, "dry run must never call createTransactionRequest");
    assert.equal(submitCalls, 0, "dry run must never call submitTransactionRequest");
  });

  it("fails closed on a malformed (non-object) dry-run response", async () => {
    const adapter = dryRunAdapter({
      tari_signAndSubmitTransaction: () => "not-an-object" as unknown,
    });
    await assert.rejects(() => adapter.signAndSubmitTransactionDryRun([]), /malformed/);
  });

  it("does not call any approval/submission method on a successful dry run", async () => {
    let createCalls = 0;
    let submitCalls = 0;
    let pollCalls = 0;
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(fakeProvider({
        handlers: {
          tari_signAndSubmitTransaction: () => ({
            transaction_id: "abc123",
            result: { finalize: { total_fees_required: "999", result: { Accept: {} } } },
          }),
          tari_createTransactionRequest: () => { createCalls += 1; return { requestId: "x" }; },
          tari_submitTransactionRequest: () => { submitCalls += 1; return { transactionId: "t" }; },
          tari_getTransactionRequest: () => { pollCalls += 1; return { status: "approved" }; },
        },
      }))),
    );
    const estimate = await adapter.signAndSubmitTransactionDryRun([], 1000);
    assert.equal(estimate.kind, "estimated");
    assert.equal(createCalls, 0);
    assert.equal(submitCalls, 0);
    assert.equal(pollCalls, 0);
  });

  it("reports dryRunIsLocal capability and hasCapability('dryRunIsLocal')", async () => {
    const capsProvider = fakeProvider({
      handlers: {
        tari_getCapabilities: () => ({
          transactionRequests: true,
          transactionResultLookup: true,
          dryRunIsLocal: true,
        }),
      },
    });
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(capsProvider)),
    );
    const caps = await adapter.getCapabilities();
    assert.equal(caps.dryRunIsLocal, true);
    assert.equal(hasCapability(caps, "dryRunIsLocal"), true);
  });

  it("treats an absent dryRunIsLocal capability as not advertised", async () => {
    const capsProvider = fakeProvider({
      handlers: {
        tari_getCapabilities: () => ({ transactionRequests: true, transactionResultLookup: true }),
      },
    });
    const adapter = windowTariProvider("sapient", "Sapient", () =>
      sapientDiscovery(scopeWith(capsProvider)),
    );
    const caps = await adapter.getCapabilities();
    assert.equal(caps.dryRunIsLocal, null);
    assert.equal(hasCapability(caps, "dryRunIsLocal"), false);
  });

  it("refuses a dry run when the pinned provider is swapped mid-operation", async () => {
    const provider = fakeProvider({
      handlers: { tari_signAndSubmitTransaction: () => ({ transaction_id: "t", result: { finalize: { total_fees_required: "1", result: { Accept: {} } } } }) },
    });
    const holder: { tari?: unknown } = { tari: provider };
    const adapter = windowTariProvider("sapient", "Sapient", () => sapientDiscovery(holder));
    adapter.pin();
    const impostor = fakeProvider({ handlers: {} });
    holder.tari = impostor;
    await assert.rejects(
      () => adapter.signAndSubmitTransactionDryRun([]),
      /no longer the same provider/,
    );
  });
});

describe("extractDryRunFeeEstimate (pure)", () => {
  // Evidence-backed shape: { finalize: { total_fees_required: "<µT string>", result: { Accept: … } } }
  it("reads finalize.total_fees_required (decimal string µT) with an Accept outcome", () => {
    assert.deepEqual(
      extractDryRunFeeEstimate({ finalize: { total_fees_required: "4200", result: { Accept: {} } } }),
      { kind: "estimated", requiredFeesMicrotari: "4200" },
    );
  });
  it("accepts bigint and safe-integer number forms for total_fees_required", () => {
    assert.deepEqual(
      extractDryRunFeeEstimate({ finalize: { total_fees_required: 42n, result: { Accept: {} } } }),
      { kind: "estimated", requiredFeesMicrotari: "42" },
    );
    assert.deepEqual(
      extractDryRunFeeEstimate({ finalize: { total_fees_required: 42, result: { Accept: {} } } }),
      { kind: "estimated", requiredFeesMicrotari: "42" },
    );
  });
  it("requires an explicit Accept outcome (no fee without it)", () => {
    assert.equal(
      extractDryRunFeeEstimate({ finalize: { total_fees_required: "900" } }).kind,
      "unsupported",
    );
    assert.equal(
      extractDryRunFeeEstimate({ finalize: { total_fees_required: "900", result: {} } }).kind,
      "unsupported",
    );
  });
  it("does NOT fall back to fee_receipt.total_fees_paid", () => {
    assert.equal(
      extractDryRunFeeEstimate({ finalize: { fee_receipt: { total_fees_paid: "900" }, result: { Accept: {} } } }).kind,
      "unsupported",
    );
  });
  it("refuses a rejected simulation", () => {
    assert.equal(
      extractDryRunFeeEstimate({ finalize: { total_fees_required: "1", result: { Reject: {} } } }).kind,
      "unsupported",
    );
    assert.equal(
      extractDryRunFeeEstimate({ finalize: { total_fees_required: "1", result: { AcceptFeeRejectRest: [{}, {}] } } }).kind,
      "unsupported",
    );
  });
  it("rejects negative, float, non-numeric, and leading-zero figures", () => {
    for (const bad of ["-1", "12.5", "abc", "0123", "", " 5", "1e3"]) {
      assert.equal(
        extractDryRunFeeEstimate({ finalize: { total_fees_required: bad, result: { Accept: {} } } }).kind,
        "unsupported",
        `value ${JSON.stringify(bad)}`,
      );
    }
  });
  it("rejects a missing finalize section", () => {
    assert.equal(extractDryRunFeeEstimate({ result: {} }).kind, "unsupported");
  });
  it("returns unsupported for non-object inputs", () => {
    assert.equal(extractDryRunFeeEstimate(null).kind, "unsupported");
    assert.equal(extractDryRunFeeEstimate([]).kind, "unsupported");
    assert.equal(extractDryRunFeeEstimate("x").kind, "unsupported");
  });
  it("does not read unrelated fields (no invented fee)", () => {
    assert.equal(
      extractDryRunFeeEstimate({ finalize: { events: [], logs: [], result: { Accept: {} } } }).kind,
      "unsupported",
    );
  });
});
