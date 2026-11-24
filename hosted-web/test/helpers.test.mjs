import test from "node:test";
import assert from "node:assert/strict";

test("privacy notice copy is present in main.ts source", async () => {
  const fs = await import("node:fs");
  const src = fs.readFileSync(new URL("../src/main.ts", import.meta.url), "utf8");
  assert.match(src, /reduced network-metadata privacy/);
  assert.match(src, /not anonymous/);
  assert.match(src, /never sent to the server/);
  // No localStorage of secrets, no secret in URL
  assert.doesNotMatch(src, /localStorage\.setItem\(.*secret/i);
  assert.doesNotMatch(src, /location\.hash.*secret/i);
});

test("no third-party runtime dependencies", async () => {
  const pkg = JSON.parse((await import("node:fs")).readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(pkg.dependencies, undefined);
  assert.ok(pkg.devDependencies);
});
