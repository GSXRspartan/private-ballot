import test from "node:test";
import assert from "node:assert/strict";

test("headers.mjs strips client origin/admin credentials and injects the Worker origin token", async () => {
  const { ORIGIN_TOKEN_HEADER, ADMIN_TOKEN_HEADER, ORGANIZER_TOKEN_HEADER, buildUpstreamHeaders } = await import("../src-edge/headers.mjs");

  assert.equal(ORIGIN_TOKEN_HEADER, "x-private-ballot-origin");
  assert.equal(ADMIN_TOKEN_HEADER, "x-admin-token");
  assert.equal(ORGANIZER_TOKEN_HEADER, "x-private-ballot-organizer");

  const incoming = new Headers({
    [ORIGIN_TOKEN_HEADER]: "client-forge",
    [ADMIN_TOKEN_HEADER]: "client-forge-admin",
    [ORGANIZER_TOKEN_HEADER]: "a".repeat(64),
    accept: "application/json",
  });
  const out = buildUpstreamHeaders(incoming, "worker-secret");
  assert.equal(out.get(ORIGIN_TOKEN_HEADER), "worker-secret", "Worker token replaces any client value");
  assert.equal(out.get(ADMIN_TOKEN_HEADER), null, "admin token header must never reach the backend");
  assert.equal(out.get(ORGANIZER_TOKEN_HEADER), "a".repeat(64), "organizer capability is forwarded untouched");
  assert.equal(out.get("accept"), "application/json", "ordinary headers are forwarded");
});

test("buildUpstreamHeaders without configured token leaves no origin header", async () => {
  const { ORIGIN_TOKEN_HEADER, buildUpstreamHeaders } = await import("../src-edge/headers.mjs");
  const out = buildUpstreamHeaders(new Headers({ [ORIGIN_TOKEN_HEADER]: "client-forge" }), undefined);
  assert.equal(out.get(ORIGIN_TOKEN_HEADER), null, "no injection when unconfigured; client value still stripped");
});

test("buildUpstreamHeaders works from a plain request-like header list", async () => {
  const { buildUpstreamHeaders } = await import("../src-edge/headers.mjs");
  const req = new Request("https://example.test/api/v1/status", { headers: { "x-admin-token": "nope" } });
  const out = buildUpstreamHeaders(req.headers, "t");
  assert.equal(out.get("x-admin-token"), null);
});

test("isAdminPath blocks the global admin plane, exact and nested", async () => {
  const { isAdminPath } = await import("../src-edge/headers.mjs");
  assert.equal(isAdminPath("/api/v1/admin"), true);
  assert.equal(isAdminPath("/api/v1/admin/"), true);
  assert.equal(isAdminPath("/api/v1/admin/elections/draft"), true);
  assert.equal(isAdminPath("/api/v1/admin/elections/x/finalize"), true);
  assert.equal(isAdminPath("/api/v1/organizer/elections"), false, "organizer plane is not the admin plane");
  assert.equal(isAdminPath("/api/v1/elections/x/ballots"), false);
  assert.equal(isAdminPath("/api/v1/adminx"), false, "prefix must not over-match");
  assert.equal(isAdminPath("/"), false);
});

test("worker.ts delegates header policy to headers.mjs (no inline duplicates)", async () => {
  const fs = await import("node:fs");
  const worker = fs.readFileSync(new URL("../src-edge/worker.ts", import.meta.url), "utf8");
  assert.match(worker, /from "\.\/headers\.mjs"/);
  assert.doesNotMatch(worker, /headers\.delete\("x-admin-token"\)/, "strip logic lives only in headers.mjs");
  assert.doesNotMatch(worker, /headers\.delete\(ORIGIN_TOKEN_HEADER\)/, "strip logic lives only in headers.mjs");
});

test("the same-origin chain route uses only the dedicated indexer Worker binding", async () => {
  const { proxyIndexer } = await import("../src-edge/worker.ts");
  let requested = null;
  const response = await proxyIndexer(
    new Request("https://app.test/chain/transactions/" + "ab".repeat(32) + "/result"),
    { INDEXER_PROXY: { fetch: async (request) => {
      requested = request;
      return new Response("{}", { headers: { "content-type": "application/json" } });
    } } },
    new URL("https://app.test/chain/transactions/" + "ab".repeat(32) + "/result"),
  );
  assert.equal(response.status, 200);
  assert.equal(requested.url, "https://app.test/transactions/" + "ab".repeat(32) + "/result");
  assert.equal(requested.headers.get("x-private-ballot-organizer"), null);
  assert.equal(response.headers.get("content-security-policy").includes("frame-ancestors 'none'"), true);
});
