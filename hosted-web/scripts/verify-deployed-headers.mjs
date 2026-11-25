import assert from "node:assert/strict";

const base = (process.argv[2] ?? process.env.PB_BASE_URL ?? "https://private-ballot-staging.ghostgate.boo").replace(/\/$/, "");

const EXPECTED_CSP =
  "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self' https://universe.tari.mw";

async function get(path) {
  const response = await fetch(`${base}${path}`, { method: "GET", redirect: "follow" });
  return { path, status: response.status, headers: response.headers, url: response.url };
}

function checkDocument(result) {
  assert.equal(result.status, 200, `${result.path}: status`);
  assert.equal(result.headers.get("content-security-policy"), EXPECTED_CSP, `${result.path}: CSP`);
  assert.equal(result.headers.get("cross-origin-embedder-policy"), "require-corp", `${result.path}: COEP`);
  assert.equal(result.headers.get("cross-origin-resource-policy"), "cross-origin", `${result.path}: CORP`);
  assert.equal(result.headers.get("x-frame-options"), null, `${result.path}: X-Frame-Options`);
  assert.equal(
    (result.headers.get("content-security-policy").match(/frame-ancestors/g) ?? []).length,
    1,
    `${result.path}: exactly one frame-ancestors directive`,
  );
}

function checkNoFrame(result, expectedStatus) {
  assert.equal(result.status, expectedStatus, `${result.path}: status`);
  assert.ok(
    (result.headers.get("content-security-policy") ?? "").endsWith("frame-ancestors 'none'"),
    `${result.path}: no-frame CSP`,
  );
  assert.equal(result.headers.get("x-frame-options"), null, `${result.path}: X-Frame-Options`);
  assert.equal(result.headers.get("cross-origin-embedder-policy"), null, `${result.path}: no COEP`);
  assert.equal(result.headers.get("cross-origin-resource-policy"), null, `${result.path}: no CORP`);
}

const documentPaths = ["/", "/index.html", "/anchor", "/manage", "/settings"];
for (const path of documentPaths) {
  const result = await get(path);
  checkDocument(result);
  console.log(`PASS document ${path} -> ${result.url}`);
}

for (const path of ["/api/v1/status", "/tari-connector.js"]) {
  const result = await get(path);
  checkNoFrame(result, 200);
  console.log(`PASS no-frame ${path}`);
}

for (const path of ["/api/v1/admin", "/api/v1/%61dmin"]) {
  const result = await get(path);
  checkNoFrame(result, 404);
  console.log(`PASS blocked ${path}`);
}

const health = await get("/health");
assert.equal(health.status, 200, "/health: status");
console.log("PASS /health");

console.log("ALL DEPLOYED HEADER CHECKS PASSED");
