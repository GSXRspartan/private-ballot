// Archive verification input-binding regression tests.
//
// Proves the pure state logic that keeps a cryptographic verification result
// bound to the exact inputs it was computed from: a result renders only while
// its bound inputs still match the current inputs, changing an input
// invalidates the dependent result, and an async response that resolves after
// the inputs changed is recognized as stale and discarded.
//
// The frontend has no React mount harness (ADR-0007), so the component logic is
// extracted into pure helpers and exercised directly here.
//
// Run with: npm test

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  archiveResultIsStale,
  boundArchiveResult,
  boundTransportAnchorResult,
  transportAnchorResultIsStale,
  type ArchiveVerificationBindingV1,
  type TransportAnchorBindingV1,
} from "../src/archive/archiveBinding.ts";

// Minimal stand-ins: only identity matters to the binding logic.
const archiveOk = { verified: true } as unknown as ArchiveVerificationBindingV1["result"];
const anchorOk = { state: "ANCHORED" } as unknown as TransportAnchorBindingV1["result"];

describe("archive verification is bound to the verified directory", () => {
  it("renders the result only for the directory that produced it", () => {
    const binding: ArchiveVerificationBindingV1 = {
      result: archiveOk,
      verifiedDirectory: "/data/archive-A",
    };
    // Verified A, still on A -> renderable.
    assert.equal(boundArchiveResult(binding, "/data/archive-A"), archiveOk);
    // Changed to B -> the A result is no longer renderable as B.
    assert.equal(boundArchiveResult(binding, "/data/archive-B"), null);
    // No binding -> nothing to render.
    assert.equal(boundArchiveResult(null, "/data/archive-A"), null);
  });
});

describe("transport-anchor verification is bound to BOTH inputs", () => {
  const binding: TransportAnchorBindingV1 = {
    result: anchorOk,
    checkedArchiveDirectory: "/data/archive-A",
    checkedEvidencePath: "/data/evidence-X.cbor",
  };

  it("renders only when both the directory and the evidence path still match", () => {
    assert.equal(
      boundTransportAnchorResult(binding, "/data/archive-A", "/data/evidence-X.cbor"),
      anchorOk,
    );
  });

  it("stops rendering when the evidence path changes", () => {
    assert.equal(
      boundTransportAnchorResult(binding, "/data/archive-A", "/data/evidence-Y.cbor"),
      null,
    );
  });

  it("stops rendering when the archive directory changes", () => {
    assert.equal(
      boundTransportAnchorResult(binding, "/data/archive-B", "/data/evidence-X.cbor"),
      null,
    );
  });
});

describe("async stale-response guarding", () => {
  it("treats an archive response as stale when the directory changed mid-flight", () => {
    // Submitted A; user switched to B before it returned.
    assert.equal(archiveResultIsStale("/data/archive-A", "/data/archive-B"), true);
    // Still on A -> not stale, safe to install.
    assert.equal(archiveResultIsStale("/data/archive-A", "/data/archive-A"), false);
  });

  it("treats a transport-anchor response as stale when either input changed", () => {
    const submitted = { archiveDirectory: "/data/archive-A", evidencePath: "/e/X.cbor" };
    assert.equal(
      transportAnchorResultIsStale(submitted, {
        archiveDirectory: "/data/archive-B",
        evidencePath: "/e/X.cbor",
      }),
      true,
    );
    assert.equal(
      transportAnchorResultIsStale(submitted, {
        archiveDirectory: "/data/archive-A",
        evidencePath: "/e/Y.cbor",
      }),
      true,
    );
    assert.equal(
      transportAnchorResultIsStale(submitted, {
        archiveDirectory: "/data/archive-A",
        evidencePath: "/e/X.cbor",
      }),
      false,
    );
  });

  it("end-to-end: a result installed for A never renders after the user moves to B", () => {
    // Simulate: verify(A) resolves; because the current input is still A at
    // install time (not stale), the binding is stored with verifiedDirectory A.
    const submittedDirectory = "/data/archive-A";
    const currentAtResolve = "/data/archive-A";
    assert.equal(archiveResultIsStale(submittedDirectory, currentAtResolve), false);
    const binding: ArchiveVerificationBindingV1 = {
      result: archiveOk,
      verifiedDirectory: submittedDirectory,
    };
    // Later the user navigates the directory to B: the stored A binding must
    // not render under B.
    assert.equal(boundArchiveResult(binding, "/data/archive-B"), null);
  });
});
