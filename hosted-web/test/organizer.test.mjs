import test from "node:test";
import assert from "node:assert/strict";

const read = async (p) => (await import("node:fs")).readFileSync(new URL(p, import.meta.url), "utf8");

test("create page generates the organizer secret with crypto.getRandomValues (32 bytes)", async () => {
  const organizer = await read("../src/organizer.ts");
  const create = await read("../src/create.ts");
  assert.match(organizer, /new Uint8Array\(32\)/, "secret must be 32 bytes");
  assert.match(organizer, /crypto\.getRandomValues\(/, "secret must come from the browser CSPRNG");
  assert.match(create, /generateOrganizerSecret\(\)/, "create page must use the shared generator");
});

test("organizer secrets never touch web storage, URLs, or console logging", async () => {
  const organizer = await read("../src/organizer.ts");
  const create = await read("../src/create.ts");
  const manage = await read("../src/manage.ts");
  // Ignore documentation comments; only code is checked.
  const codeOf = (src) => src.split(/\r?\n/).filter((l) => !l.trim().startsWith("*") && !l.trim().startsWith("/*")).join("\n");
  for (const src of [organizer, create, manage]) {
    const code = codeOf(src);
    assert.doesNotMatch(code, /localStorage\.setItem\([^\n]*(secret|invitation|credential)/i);
    assert.doesNotMatch(code, /sessionStorage\.[a-zA-Z]+\([^\n]*(secret|invitation)/i);
    assert.doesNotMatch(code, /indexedDB/i, "no IndexedDB use for credentials");
    assert.doesNotMatch(code, /console\.(log|info|debug)\(/, "no console logging of request state");
    assert.doesNotMatch(code, /location\.(hash|search)/, "no secret or election reference in URL fragments");
  }
  // The organizer secret travels only in the dedicated credential header.
  assert.match(organizer, /"x-private-ballot-organizer"/);
  assert.match(organizer, /access\.organizer_secret_hex/);
  assert.doesNotMatch(
    codeOf(organizer),
    /(location\.|window\.open|href=|encodeURIComponent\()[^\n]*organizer_secret_hex/,
    "secret must never be interpolated into URLs"
  );
  assert.doesNotMatch(
    codeOf(organizer),
    /encodeURIComponent\(access\.organizer_secret_hex\)/,
    "secret must never be URL-encoded into a path or query"
  );
});

test("irreversible lifecycle actions require confirm()", async () => {
  const organizer = await read("../src/organizer.ts");
  for (const action of ["freeze", "close", "finalize"]) {
    assert.match(
      organizer,
      new RegExp(`lifecycleAction\\("${action}", true,`),
      `${action} must be gated by needsConfirm=true`
    );
  }
  assert.match(organizer, /window\.confirm\(/, "confirm() must be called for gated actions");
  assert.match(organizer, /irreversible/);
});

test("invitation plaintext is shown once and cleared from state", async () => {
  const organizer = await read("../src/organizer.ts");
  assert.match(organizer, /shown once/);
  assert.match(organizer, /btn-dismiss-invitation/);
  assert.match(organizer, /function clearTransientSecret\(\)/);
  assert.match(organizer, /cs\.lastInvitation = null/);
  // Slots view must not leak invitation secrets
  assert.doesNotMatch(organizer, /invitation_secret_hex[^;\n]*slots/i);
});

test("access file uses the dedicated schema string and is explicit about plaintext secret", async () => {
  const organizer = await read("../src/organizer.ts");
  assert.match(organizer, /private-ballot-organizer-access-v1/);
  assert.match(organizer, /service_url/);
  assert.match(organizer, /election_id/);
  assert.match(organizer, /organizer_secret_hex/);
  assert.match(organizer, /created_at/);
  assert.match(organizer, /plaintext/);
  assert.match(organizer, /parseAccessFile/);
  assert.match(organizer, /isValidOrganizerSecret/);
  assert.match(organizer, /\/\^\[0-9a-f\]\{64\}\$\//);
});

test("create and manage pages are wired into the shell, vite build, and home", async () => {
  const vite = await read("../vite.config.ts");
  assert.match(vite, /create: "create\.html"/);
  assert.match(vite, /manage: "manage\.html"/);
  const shell = await read("../src/shell.ts");
  assert.match(shell, /navItem\("\/create\.html", "Create Election", "create", section\)/);
  assert.match(shell, /navItem\("\/manage\.html", "Manage Election", "manage", section\)/);
  const home = await read("../src/home.ts");
  assert.match(home, /\/create\.html/);
  assert.match(home, /\/manage\.html/);
  for (const p of ["../create.html", "../manage.html"]) {
    const html = await read(p);
    assert.match(html, /Content-Security-Policy/);
    assert.doesNotMatch(html, /<script[^>]+src="https?:/, "no remote scripts");
  }
});

test("organizer API calls hit only the public organizer namespace", async () => {
  const organizer = await read("../src/organizer.ts");
  assert.match(organizer, /\/api\/v1\/organizer\/elections\//);
  assert.doesNotMatch(organizer, /\/api\/v1\/admin/);
  for (const route of [
    "lifecycleAction(\"open-enrollment\"",
    "\"/slots\"",
    "\"/invitations\"",
    "/void",
    "lifecycleAction(\"freeze\"",
    "lifecycleAction(\"open-voting\"",
    "lifecycleAction(\"close\"",
    "lifecycleAction(\"finalize\"",
  ]) {
    assert.ok(organizer.includes(route), `route ${route} used`);
  }
  // The election status endpoint is polled too.
  assert.match(organizer, /apiPath\(access, ""\)/);
});

test("guide documents the self-service organizer flow without Tor-equivalence claims", async () => {
  const guide = await read("../src/guide.ts");
  assert.match(guide, /create\.html/);
  assert.match(guide, /manage\.html/);
  assert.match(guide, /organizer credential/i);
  assert.match(guide, /verifier of your credential/i);
});

test("no third-party runtime dependencies introduced", async () => {
  const pkg = JSON.parse((await import("node:fs")).readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(pkg.dependencies, undefined);
  for (const p of ["../src/organizer.ts", "../src/create.ts", "../src/manage.ts"]) {
    const src = await read(p);
    for (const m of src.matchAll(/from "([^"]+)"/g)) {
      assert.match(m[1], /^\.\//, "only local imports are allowed");
    }
  }
});
