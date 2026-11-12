// Tests for the read-only indexer proxy worker (node --test).
//
// The worker's routing and URL-building logic is exported as pure functions
// and tested without a Workers runtime; the fetch handler is exercised with a
// stubbed global fetch.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  buildUpstreamUrl,
  handleRequest,
  matchAllowedPath,
} from "./worker.js";

function fakeResponse(status, body, headers = {}) {
  return {
    status,
    headers: new Map(Object.entries({ "Content-Type": "application/json", ...headers })),
    arrayBuffer: async () => body,
  };
}

describe("allowed paths", () => {
  it("accepts exactly the four read-only route shapes", () => {
    assert.deepEqual(matchAllowedPath("/network"), { kind: "network" });
    assert.deepEqual(matchAllowedPath(`/transactions/${"ab".repeat(32)}/result`), {
      kind: "result",
      transactionId: "ab".repeat(32),
    });
    assert.deepEqual(matchAllowedPath("/transaction-receipts/rcpt_001"), {
      kind: "receipt",
      objectKey: "rcpt_001",
    });
  });

  it("rejects every other path, including writes and traversal", () => {
    for (const path of [
      "/transactions",
      "/transactions/short/result",
      `/transactions/${"AB".repeat(32)}/result`,
      "/substates/state_1_2",
      "/resources/resource_1",
      "/transactions/dry-run",
      "/wallet/status",
      "/",
      "/../etc/passwd",
      `/transaction-receipts/${"x".repeat(257)}`,
    ]) {
      assert.equal(matchAllowedPath(new URL(`https://p.test${path}`).pathname), null, path);
    }
  });

  it("never forwards a query string even when the path itself is allowed", () => {
    const upstream = buildUpstreamUrl(
      "https://upstream.test",
      matchAllowedPath(
        new URL(`https://p.test/transactions/${"ab".repeat(32)}/result`).pathname,
      ),
    );
    assert.equal(upstream.search, "");
    assert.equal(
      upstream.toString(),
      `https://upstream.test/transactions/${"ab".repeat(32)}/result`,
    );
  });
});

describe("upstream URL building", () => {
  it("appends the allowed path to the configured upstream and strips queries", () => {
    const upstream = buildUpstreamUrl(
      "https://ootle-indexer-a.tari.com/",
      { kind: "result", transactionId: "ab".repeat(32) },
    );
    assert.equal(
      upstream.toString(),
      `https://ootle-indexer-a.tari.com/transactions/${"ab".repeat(32)}/result`,
    );
    assert.equal(upstream.search, "");
  });

  it("rejects a malformed upstream base fail-closed", () => {
    assert.equal(buildUpstreamUrl("not a url", { kind: "network" }), null);
    assert.equal(
      buildUpstreamUrl("ftp://example.com", { kind: "network" }),
      null,
    );
  });
});

describe("request handler", () => {
  it("fails closed with 503 when no upstream is configured", async () => {
    const response = await handleRequest(
      new Request("https://proxy.test/network"),
      {},
    );
    assert.equal(response.status, 503);
  });

  it("rejects disallowed paths with 404 without touching the upstream", async () => {
    let upstreamCalls = 0;
    globalThis.fetch = async () => {
      upstreamCalls += 1;
      return fakeResponse(200, new TextEncoder().encode("{}").buffer);
    };
    const response = await handleRequest(
      new Request("https://proxy.test/substates/state_1_2"),
      { INDEXER_UPSTREAM: "https://upstream.test" },
    );
    assert.equal(response.status, 404);
    assert.equal(upstreamCalls, 0);
  });

  it("rejects write methods with 405 without touching the upstream", async () => {
    let upstreamCalls = 0;
    globalThis.fetch = async () => {
      upstreamCalls += 1;
      return fakeResponse(200, new TextEncoder().encode("{}").buffer);
    };
    const response = await handleRequest(
      new Request("https://proxy.test/network", { method: "POST" }),
      { INDEXER_UPSTREAM: "https://upstream.test" },
    );
    assert.equal(response.status, 405);
    assert.equal(upstreamCalls, 0);
  });

  it("forwards an allowed GET to the configured upstream and caps size", async () => {
    let capturedUrl = "";
    globalThis.fetch = async (url) => {
      capturedUrl = url;
      return fakeResponse(200, new TextEncoder().encode('{"result":"Pending"}').buffer);
    };
    const response = await handleRequest(
      new Request(`https://proxy.test/transactions/${"ab".repeat(32)}/result`),
      { INDEXER_UPSTREAM: "https://upstream.test" },
    );
    assert.equal(response.status, 200);
    assert.equal(
      capturedUrl,
      `https://upstream.test/transactions/${"ab".repeat(32)}/result`,
    );
    assert.equal(response.headers.get("Cache-Control"), "no-store");
  });

  it("answers an oversized upstream response with 502", async () => {
    globalThis.fetch = async () =>
      fakeResponse(200, new ArrayBuffer(512 * 1024 + 1));
    const response = await handleRequest(
      new Request("https://proxy.test/network"),
      { INDEXER_UPSTREAM: "https://upstream.test" },
    );
    assert.equal(response.status, 502);
  });

  it("serves CORS only for the exact configured origin", async () => {
    globalThis.fetch = async () =>
      fakeResponse(200, new TextEncoder().encode("{}").buffer);
    const withOrigin = await handleRequest(
      new Request("https://proxy.test/network"),
      {
        INDEXER_UPSTREAM: "https://upstream.test",
        ALLOWED_ORIGIN: "https://app.example",
      },
    );
    assert.equal(
      withOrigin.headers.get("Access-Control-Allow-Origin"),
      "https://app.example",
    );
    const withoutOrigin = await handleRequest(
      new Request("https://proxy.test/network"),
      { INDEXER_UPSTREAM: "https://upstream.test" },
    );
    assert.equal(withoutOrigin.headers.get("Access-Control-Allow-Origin"), null);
  });
});
