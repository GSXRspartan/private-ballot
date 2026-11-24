// Release UX checks for the Hosted organizer archive download (Surface A).
// The finalized archive is served by the authenticated organizer endpoint.
// The browser downloads it using the in-memory credential; no secret is
// persisted or sent anywhere other than the x-private-ballot-organizer header.

import test from "node:test";
import assert from "node:assert/strict";

const read = async (p) => (await import("node:fs")).readFileSync(new URL(p, import.meta.url), "utf8");

test("download finalized archive button appears only for finalized elections", async () => {
  const organizer = await read("../src/organizer.ts");
  // Button must be guarded by the finalized state check
  const finalizedBlock = organizer.slice(organizer.indexOf('election_state === "finalized"'));
  assert.match(finalizedBlock, /btn-download-archive/);
});

test("downloadFinalizedArchive uses organizer auth header to the archive endpoint", async () => {
  const organizer = await read("../src/organizer.ts");
  assert.match(organizer, /downloadFinalizedArchive/);
  assert.match(organizer, /apiPath\(access, "\/archive"\)/);
  assert.match(organizer, /"x-private-ballot-organizer": access\.organizer_secret_hex/);
  assert.match(organizer, /\.archive\.json/);
});

test("archive download never puts the organizer secret in a URL or query string", async () => {
  const organizer = await read("../src/organizer.ts");
  const fn = organizer.slice(organizer.indexOf("async function downloadFinalizedArchive"));
  // Secret must only appear in the header, never in the URL path/query
  assert.doesNotMatch(fn, /\?.*organizer_secret/);
  assert.doesNotMatch(fn, /encodeURIComponent\(access\.organizer_secret_hex\)/);
});

test("archive download errors are shown via setError and re-render", async () => {
  const organizer = await read("../src/organizer.ts");
  const fn = organizer.slice(organizer.indexOf("async function downloadFinalizedArchive"));
  assert.match(fn, /setError\(/);
  assert.match(fn, /renderConsole\(\)/);
  assert.match(fn, /401/);
  assert.match(fn, /404/);
});

test("archive download result triggers an info message", async () => {
  const organizer = await read("../src/organizer.ts");
  const fn = organizer.slice(organizer.indexOf("async function downloadFinalizedArchive"));
  assert.match(fn, /cs\.infoMsg/);
  assert.match(fn, /Finalized archive downloaded/);
});

test("bindConsole wires the archive download button", async () => {
  const organizer = await read("../src/organizer.ts");
  assert.match(organizer, /archiveDownloadBtn.*addEventListener\("click"/s);
  assert.match(organizer, /downloadFinalizedArchive/);
});
