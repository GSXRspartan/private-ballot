import assert from "node:assert/strict";
import test from "node:test";

import worker from "../src-edge/worker.ts";

const DAPP_PATHS = [
  "/", "/index.html", "/manage", "/manage.html", "/create", "/create.html",
  "/enroll", "/enroll.html", "/vote", "/vote.html", "/archive", "/archive.html",
  "/evidence", "/evidence.html", "/guide", "/guide.html", "/about", "/about.html",
  "/settings", "/settings.html",
];

function assets() {
  return {
    async fetch() {
      return new Response("<!doctype html>", {
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    },
  };
}

const env = { ASSETS: assets(), STAGING_ORIGIN: "https://origin.example" };

test("every canonical and explicit dApp document receives the Universe CSP", async () => {
  for (const path of DAPP_PATHS) {
    const response = await worker.fetch(new Request(`https://app.example${path}`), env);
    assert.equal(response.status, 200, path);
    assert.match(
      response.headers.get("content-security-policy") ?? "",
      /frame-ancestors https:\/\/universe\.tari\.mw$/,
      path,
    );
  }
});

test("API and admin responses receive the no-frame CSP", async () => {
  const savedFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => new Response("{}", { headers: { "content-type": "application/json" } });
    const api = await worker.fetch(new Request("https://app.example/api/v1/status"), env);
    assert.match(api.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'$/);

    const admin = await worker.fetch(new Request("https://app.example/api/v1/admin"), env);
    assert.equal(admin.status, 404);
    assert.match(admin.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'$/);
  } finally {
    globalThis.fetch = savedFetch;
  }
});

test("unrecognized assets retain the no-frame CSP", async () => {
  const response = await worker.fetch(new Request("https://app.example/assets/app.js"), env);
  assert.match(response.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'$/);
});
