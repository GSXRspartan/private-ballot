// Release UX checks for the Hosted voter-bundle download (Surface C).
// The public voter-bundle endpoint requires no auth; it serves V2 CBOR once
// voting is open. Voters download it from the enrollment page and import it
// in Private Ballot Desktop.

import test from "node:test";
import assert from "node:assert/strict";

const read = async (p) => (await import("node:fs")).readFileSync(new URL(p, import.meta.url), "utf8");

test("downloadV2VoterBundle fetches the public voter-bundle endpoint", async () => {
  const enroll = await read("../src/enroll.ts");
  assert.match(enroll, /downloadV2VoterBundle/);
  assert.match(enroll, /\/api\/v1\/elections\/.*\/voter-bundle/);
});

test("voter bundle download uses the public endpoint (no organizer header)", async () => {
  const enroll = await read("../src/enroll.ts");
  const fn = enroll.slice(enroll.indexOf("async function downloadV2VoterBundle"));
  // Public endpoint: no auth header
  assert.doesNotMatch(fn, /x-private-ballot-organizer/);
  assert.doesNotMatch(fn, /organizer_secret_hex/);
  // Does not require invitation secret
  assert.doesNotMatch(fn, /invitationSecret/);
});

test("voter bundle download saves as voter-bundle-v2.cbor", async () => {
  const enroll = await read("../src/enroll.ts");
  const fn = enroll.slice(enroll.indexOf("async function downloadV2VoterBundle"));
  assert.match(fn, /voter-bundle-v2\.cbor/);
});

test("voter bundle download handles 404/409 gracefully with not-open message", async () => {
  const enroll = await read("../src/enroll.ts");
  const fn = enroll.slice(enroll.indexOf("async function downloadV2VoterBundle"));
  assert.match(fn, /404/);
  assert.match(fn, /409/);
  assert.match(fn, /not available yet/);
  assert.match(fn, /organizer must open voting/);
});

test("download button appears in the frozen state card", async () => {
  const enroll = await read("../src/enroll.ts");
  // Button text lives in buildHtml's frozen render block
  assert.match(enroll, /btn-download-voter-bundle/);
  assert.match(enroll, /Download Desktop voter bundle/);
  // Confirm it is guarded by the frozen-state check in buildHtml
  const buildHtml = enroll.slice(enroll.indexOf("function buildHtml"));
  assert.match(buildHtml, /case "frozen"/);
  const frozenRender = buildHtml.slice(buildHtml.indexOf('case "frozen"'));
  assert.match(frozenRender, /btn-download-voter-bundle/);
});

test("bind() wires the download button in the frozen case", async () => {
  const enroll = await read("../src/enroll.ts");
  const bindFn = enroll.slice(enroll.indexOf("function bind()"));
  assert.match(bindFn, /case "frozen"/);
  assert.match(bindFn, /btn-download-voter-bundle/);
  assert.match(bindFn, /downloadV2VoterBundle/);
});

test("voter bundle download does not leak election ID into URL path unsafely", async () => {
  const enroll = await read("../src/enroll.ts");
  const fn = enroll.slice(enroll.indexOf("async function downloadV2VoterBundle"));
  // Election ID must be URI-encoded before interpolation
  assert.match(fn, /encodeURIComponent\(electionId\)/);
});
