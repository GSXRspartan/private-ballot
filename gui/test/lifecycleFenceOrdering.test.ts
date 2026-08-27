// CLOSE/OPEN intake-fence publication ordering contract.
//
// The organizer's CLOSE command must publish the authoritative CLOSED fence
// to the running private-intake collector BEFORE durably committing the close,
// so a submission whose admission begins after the close can never pass an
// OPEN fence and receive ACCEPTED after the authoritative cutoff (fail-closed
// direction). Conversely, OPEN must publish only AFTER its commit succeeds:
// an early OPEN publication would admit ballots before the election truly
// opened (fail-open direction). This file pins both orderings, plus the
// guard that keeps the pre-commit close fence truthful when the click cannot
// legally close anything.
//
// Runs under Node's built-in test runner with TypeScript type stripping;
// follows the repo's semantic source-assertion convention.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const shellLib = readFileSync(
  new URL("../../gui/src-tauri/src/lib.rs", import.meta.url),
  "utf8",
);

/** Extracts the body of one top-level Rust function (closing brace at col 0). */
function sliceFn(source: string, name: string): string {
  const start = source.indexOf(`fn ${name}(`);
  assert.ok(start >= 0, `missing fn ${name}`);
  const rest = source.slice(start);
  // Line-ending agnostic end-of-function marker.
  const closeMatch = rest.match(/\r?\n\}(?:\r?\n|$)/);
  return closeMatch?.index !== undefined ? rest.slice(0, closeMatch.index) : rest;
}

describe("intake-fence publication ordering", () => {
  it("close_voting fences BEFORE the durable commit (fail closed)", () => {
    const body = sliceFn(shellLib, "close_voting");
    const fenceAt = body.indexOf("fence_close_before_commit(&app, &state)?");
    const commitAt = body.indexOf("mutate_session_transactionally(&app, &state");
    assert.ok(fenceAt >= 0, "close_voting must call the pre-commit fence helper");
    assert.ok(commitAt >= 0, "close_voting must still commit through the transaction boundary");
    assert.ok(
      commitAt > fenceAt,
      "CLOSED must fence the collector before the authoritative close commits",
    );
  });

  it("open_voting publishes OPEN only AFTER its durable commit (never fail open)", () => {
    const body = sliceFn(shellLib, "open_voting");
    const commitAt = body.indexOf("mutate_session_transactionally(&app, &state");
    const publishAt = body.indexOf("publish_lifecycle_to_intake(");
    assert.ok(commitAt >= 0, "open_voting commits through the transaction boundary");
    assert.ok(publishAt >= 0, "open_voting publishes OPEN to the intake fence");
    assert.ok(
      publishAt > commitAt,
      "OPEN must never be published before the election truly opens",
    );
    assert.doesNotMatch(body, /fence_close_before_commit/);
  });

  it("the pre-commit close fence mirrors close(): fires only while OPEN", () => {
    const body = sliceFn(shellLib, "fence_close_before_commit");
    assert.match(body, /ElectionLifecycleStateV1::Open/);
    // A non-OPEN session must not make signed status answers lie: no publish.
    assert.match(body, /return Ok\(\(\)\);/);
    assert.match(body, /publish_lifecycle_to_intake\(/);
    assert.match(body, /ElectionLifecycleStateV1::Closed/);
  });

  it("post-close transitions can never re-arm admission", () => {
    // VERIFIED/FINALIZED publications are post-CLOSED; regardless of their
    // ordering they must never publish an OPEN fence state.
    for (const name of ["mark_verified", "finalize_election"]) {
      const body = sliceFn(shellLib, name);
      assert.doesNotMatch(
        body,
        /publish_lifecycle_to_intake\([^)]*ElectionLifecycleStateV1::Open/,
        `${name} must not publish OPEN`,
      );
    }
  });
});
