import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

import worker from "../src-edge/worker.ts";
import { buildUpstreamHeaders, isAdminPath } from "../src-edge/headers.mjs";

const DAPP_PATHS = [
  "/", "/index.html", "/manage", "/manage.html", "/create", "/create.html",
  "/enroll", "/enroll.html", "/vote", "/vote.html", "/archive", "/archive.html",
  "/evidence", "/evidence.html", "/guide", "/guide.html", "/about", "/about.html",
  "/settings", "/settings.html", "/anchor", "/anchor.html",
];

const EXPECTED_CSP =
  "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self' https://universe.tari.mw";

const connectorSource = fs.readFileSync(new URL("../public/tari-connector.js", import.meta.url), "utf8");

function assets() {
  return {
    async fetch() {
      return new Response("<!doctype html>", {
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    },
  };
}

const env = { ASSETS: assets(), STAGING_ORIGIN: "https://origin.example", ORIGIN_TOKEN: "edge-secret" };

function csp(response) {
  return response.headers.get("content-security-policy") ?? "";
}

function assertNoXFrameOptions(response, path) {
  assert.equal(response.headers.get("x-frame-options"), null, path);
}

function assertBaseCspIntact(value, path) {
  for (const directive of [
    "default-src 'self'",
    "script-src 'self' 'wasm-unsafe-eval'",
    "style-src 'self'",
    "connect-src 'self'",
    "font-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
  ]) {
    assert.ok(value.includes(directive), `${path}: missing ${directive}`);
  }
  assert.ok(!value.includes("unsafe-inline"), `${path}: unsafe-inline introduced`);
}

test("every canonical and explicit dApp document permits Universe framing with COEP/CORP opt-in", async () => {
  for (const path of DAPP_PATHS) {
    const response = await worker.fetch(new Request(`https://app.example${path}`), env);
    assert.equal(response.status, 200, path);
    assert.equal(csp(response), EXPECTED_CSP, path);
    assert.equal(response.headers.get("cross-origin-embedder-policy"), "require-corp", path);
    assert.equal(response.headers.get("cross-origin-resource-policy"), "cross-origin", path);
    assertNoXFrameOptions(response, path);
    assertBaseCspIntact(csp(response), path);
  }
});

test("frame-ancestors allows only self and the pinned Universe origin", async () => {
  const response = await worker.fetch(new Request("https://app.example/"), env);
  const directive = csp(response).split(";").map((part) => part.trim()).find((part) => part.startsWith("frame-ancestors "));
  assert.ok(directive, "frame-ancestors directive present");
  const sources = directive.slice("frame-ancestors ".length).split(/\s+/);
  assert.deepEqual(sources, ["'self'", "https://universe.tari.mw"]);
  assert.ok(!sources.includes("*"), "no wildcard frame ancestor");
  assert.ok(!sources.some((source) => source.includes("http://")), "no insecure frame ancestor");
  assert.ok(!sources.some((source) => source.includes("universe.tari.mw.evil")), "no lookalike origin");
});

test("no response layer emits a contradictory X-Frame-Options header", async () => {
  const savedFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => new Response("{}", { headers: { "content-type": "application/json" } });
    const paths = ["/", "/anchor", "/assets/app.js", "/api/v1/status", "/api/v1/admin", "/chain/health"];
    for (const path of paths) {
      const response = await worker.fetch(new Request(`https://app.example${path}`), env);
      assertNoXFrameOptions(response, path);
    }
  } finally {
    globalThis.fetch = savedFetch;
  }
});

test("API and admin responses keep the no-frame CSP and do not gain embedding opt-ins", async () => {
  const savedFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => new Response("{}", { headers: { "content-type": "application/json" } });
    for (const path of ["/api/v1/status", "/api/v1/admin"]) {
      const response = await worker.fetch(new Request(`https://app.example${path}`), env);
      assert.ok(csp(response).endsWith("frame-ancestors 'none'"), path);
      assert.equal(response.headers.get("cross-origin-embedder-policy"), null, path);
      assert.equal(response.headers.get("cross-origin-resource-policy"), null, path);
      assertBaseCspIntact(csp(response), path);
    }
    const admin = await worker.fetch(new Request("https://app.example/api/v1/admin"), env);
    assert.equal(admin.status, 404);
  } finally {
    globalThis.fetch = savedFetch;
  }
});

test("unrecognized assets retain the no-frame CSP", async () => {
  const response = await worker.fetch(new Request("https://app.example/assets/app.js"), env);
  assert.ok(csp(response).endsWith("frame-ancestors 'none'"));
  assertBaseCspIntact(csp(response), "/assets/app.js");
});

test("malformed, encoded, and multi-slash admin routes remain blocked at the edge", async () => {
  const savedFetch = globalThis.fetch;
  let upstreamCalls = 0;
  try {
    globalThis.fetch = async () => { upstreamCalls += 1; return new Response("{}", { headers: { "content-type": "application/json" } }); };
    const attempts = [
      "/api/v1/admin",
      "/api/v1/admin/",
      "/api/v1/%61dmin",
      "/api/v1/admin%2Fanything",
      "/api/v1/admin//nested",
      "/api/v1/admin/%ZZ",
    ];
    for (const path of attempts) {
      const response = await worker.fetch(new Request(`https://app.example${path}`), env);
      if (isAdminPath(new URL(`https://app.example${path}`).pathname) || path.includes("%ZZ")) {
        assert.equal(response.status, 404, path);
        assert.ok(csp(response).endsWith("frame-ancestors 'none'"), path);
      }
    }
    assert.equal(upstreamCalls, 0, "admin path variants never reach the backend");
  } finally {
    globalThis.fetch = savedFetch;
  }
});

test("wallet connector still pins reply origin and parent source", () => {
  assert.ok(connectorSource.includes('WALLET_ORIGIN_ALLOWLIST = { "https://universe.tari.mw": true }'));
  assert.ok(connectorSource.includes("if (event.source !== window.parent) return;"));
  assert.ok(connectorSource.includes("if (!WALLET_ORIGIN_ALLOWLIST[event.origin]) return;"));
  assert.ok(connectorSource.includes("if (!embedded)"));
  assert.ok(!connectorSource.includes("event.origin === \"*\""));
  assert.equal((connectorSource.match(/WALLET_ORIGIN_ALLOWLIST\s*=/g) ?? []).length, 1);
});

test("API proxy response body, no-store cache policy, and origin-token injection are unchanged", async () => {
  const savedFetch = globalThis.fetch;
  let seenHeaders;
  try {
    globalThis.fetch = async (_url, init) => {
      seenHeaders = new Headers(init.headers);
      return new Response('{"ok":true}', { status: 200, headers: { "content-type": "application/json" } });
    };
    const response = await worker.fetch(
      new Request("https://app.example/api/v1/status", {
        headers: { "x-private-ballot-origin": "forged", "x-admin-token": "forged" },
      }),
      env,
    );
    assert.equal(response.status, 200);
    assert.equal(await response.text(), '{"ok":true}');
    assert.equal(response.headers.get("cache-control"), "private, no-store");
    assert.equal(seenHeaders.get("x-private-ballot-origin"), "edge-secret");
    assert.equal(seenHeaders.get("x-admin-token"), null);
    assert.equal(buildUpstreamHeaders(new Headers({ "x-admin-token": "x" }), undefined).get("x-admin-token"), null);
  } finally {
    globalThis.fetch = savedFetch;
  }
});
