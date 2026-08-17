// Pre-two-computer cleanup-pass regression tests.
//
// Covers the frontend half of the post-smoke cleanup: last-used directory
// memory (directories only, never secrets or artifacts), the Archive
// verification state lifted into session memory (retained across navigation,
// never trusted across restart), truthful result-disclosure and final-archive
// wording, the resumed-durable-session recognition on Manage Election, and the
// responsive layout invariants.
//
// Runs under Node's built-in test runner with TypeScript type stripping.
// Where no React harness exists, GUI behaviors are pinned by semantic source
// assertions, never fragile pixel analysis.
//
// Run with: npm test

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  DIRECTORY_CATEGORIES,
  parentDirectory,
  recallFrom,
  sanitizeDirectoryMemory,
  withRememberedDirectory,
  withRememberedDirectoryFromFile,
} from "../src/api/directoryMemory.ts";
import {
  canWriteFinalArchive,
  resultVisibilityLabel,
  resultsAreSealed,
} from "../src/lifecycle.ts";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const home = readProjectFile("src/screens/Home.tsx");
const manage = readProjectFile("src/screens/ManageElection.tsx");
const archive = readProjectFile("src/screens/Archive.tsx");
const appState = readProjectFile("src/state/AppState.tsx");
const dialog = readProjectFile("src/api/dialog.ts");
const directoryMemory = readProjectFile("src/api/directoryMemory.ts");
const css = readProjectFile("src/styles/global.css");

// -------------------------------------------------------------------------
// Directory memory: directories only, safe fallback, never secrets
// -------------------------------------------------------------------------

describe("directory memory helper", () => {
  it("derives the parent directory across POSIX and Windows separators", () => {
    assert.equal(parentDirectory("/home/user/archive/file.cbor"), "/home/user/archive");
    assert.equal(parentDirectory("C:\\Users\\me\\out\\ballot.cbor"), "C:\\Users\\me\\out");
    assert.equal(parentDirectory("/file"), "/");
    // A bare filename has no directory to remember.
    assert.equal(parentDirectory("ballot.cbor"), null);
    assert.equal(parentDirectory(""), null);
  });

  it("remembers a directory as-is and recalls it per category", () => {
    let memory = withRememberedDirectory({}, "archive", "/data/archives");
    assert.equal(recallFrom(memory, "archive"), "/data/archives");
    // A different category is untouched — choosing an archive directory does
    // not move the credential default.
    assert.equal(recallFrom(memory, "credential"), undefined);
    memory = withRememberedDirectory(memory, "credential", "/keys");
    assert.equal(recallFrom(memory, "archive"), "/data/archives");
    assert.equal(recallFrom(memory, "credential"), "/keys");
  });

  it("remembers the parent directory of a selected file", () => {
    const memory = withRememberedDirectoryFromFile({}, "ballotPackage", "/out/box/b.cbor");
    assert.equal(recallFrom(memory, "ballotPackage"), "/out/box");
  });

  it("ignores empty directories and bare filenames (safe fallback)", () => {
    assert.deepEqual(withRememberedDirectory({}, "archive", ""), {});
    // No derivable directory -> unchanged map -> recall falls back to undefined
    // so the picker opens at its platform default.
    const memory = withRememberedDirectoryFromFile({}, "archive", "bare.cbor");
    assert.equal(recallFrom(memory, "archive"), undefined);
  });

  it("sanitizes untrusted stored data to known categories with string values", () => {
    const cleaned = sanitizeDirectoryMemory({
      archive: "/a",
      credential: 42,
      unknownCategory: "/evil",
      ballotPackage: "",
    });
    assert.deepEqual(cleaned, { archive: "/a" });
    assert.deepEqual(sanitizeDirectoryMemory(null), {});
    assert.deepEqual(sanitizeDirectoryMemory("not-an-object"), {});
  });

  it("keeps categories limited to location hints, never secret-bearing", () => {
    for (const category of DIRECTORY_CATEGORIES) {
      assert.doesNotMatch(
        category,
        /pass|secret|scalar|witness|nullifier|seed|mnemonic|credentialBytes|choice|ballotContent/i,
      );
    }
    // The module persists only sanitized directory strings under one dedicated
    // key; it never reads or writes secret-bearing fields.
    assert.match(directoryMemory, /const STORAGE_KEY = "tari-private-ballot\.directory-memory"/);
    assert.match(directoryMemory, /sanitizeDirectoryMemory\(JSON\.parse\(raw\)\)/);
    assert.doesNotMatch(directoryMemory, /getItem\([^)]*passphrase|setItem\([^)]*passphrase/i);
  });
});

// -------------------------------------------------------------------------
// Result disclosure presentation: OPEN sealed, CLOSED/VERIFIED/FINALIZED not
// -------------------------------------------------------------------------

describe("result disclosure presentation", () => {
  it("labels the disclosed/sealed states with the fixed wire identifiers", () => {
    // These identifiers are exactly what the Rust DTO now serializes; the bug
    // was the frontend receiving PascalCase and matching neither branch.
    assert.equal(resultVisibilityLabel("DISCLOSED"), "Disclosed");
    assert.equal(resultVisibilityLabel("SEALED"), "Sealed");
  });

  it("seals results for DRAFT/FROZEN/OPEN and discloses for CLOSED/VERIFIED/FINALIZED", () => {
    for (const state of ["DRAFT", "FROZEN", "OPEN"]) {
      assert.equal(resultsAreSealed(state), true, `${state} must seal results`);
    }
    for (const state of ["CLOSED", "VERIFIED", "FINALIZED"]) {
      assert.equal(resultsAreSealed(state), false, `${state} must not seal results`);
    }
  });

  it("Home derives sealed state from the authoritative backend visibility, not a guess", () => {
    assert.match(home, /participation\.result_visibility === "SEALED"/);
    assert.match(home, /resultVisibilityLabel\(participation\.result_visibility\)/);
    // The disclosed results card no longer implies the election was never
    // tallied; it states results are available/reproducible.
    assert.match(home, /Results are available\./);
    assert.doesNotMatch(home, /compute the tally and view final\s+result bars/);
  });
});

// -------------------------------------------------------------------------
// Final-archive wording requires FINALIZED (not merely VERIFIED)
// -------------------------------------------------------------------------

describe("final archive wording", () => {
  it("gates the final archive on FINALIZED in the lifecycle helper", () => {
    assert.equal(canWriteFinalArchive("FINALIZED"), true);
    for (const state of ["DRAFT", "FROZEN", "OPEN", "CLOSED", "VERIFIED"]) {
      assert.equal(canWriteFinalArchive(state), false, `${state} is not final`);
    }
  });

  it("Home says the final archive is written after FINALIZED, not after VERIFIED", () => {
    assert.match(home, /after the election is\s+finalized/);
    assert.doesNotMatch(home, /archive from Manage Election after the election is verified/);
  });
});

// -------------------------------------------------------------------------
// Resumed durable session: Manage Election must not ask for source files
// -------------------------------------------------------------------------

describe("resumed durable session recognition", () => {
  it("only asks to choose required files when no election is loaded", () => {
    assert.match(manage, /shellAvailable && !election && !canLoad/);
  });

  it("recognizes an authoritative resumed session without selected paths", () => {
    assert.match(manage, /shellAvailable && election && !selectedArtifactPaths/);
    assert.match(manage, /already loaded from durable recovery state/);
    assert.match(manage, /original source files are not needed to continue/);
  });
});

// -------------------------------------------------------------------------
// Archive verification state: session memory, never trusted across restart
// -------------------------------------------------------------------------

describe("archive verification state handling", () => {
  it("retains archive view state in AppState so navigation does not forget it", () => {
    assert.match(appState, /archiveView:\s*ArchiveViewState/);
    assert.match(appState, /updateArchiveView/);
    assert.match(archive, /archiveView, updateArchiveView/);
    // The rendered result is derived through the input-binding gate, not read
    // raw, so it can only appear for the inputs it was computed from.
    assert.match(archive, /boundArchiveResult\(archiveView\.verification, directory\)/);
    assert.match(archive, /boundTransportAnchorResult\(/);
  });

  it("never persists archive verification or artifact bytes, only the directory hint", () => {
    // AppState archive view is plain React state (session memory), not written
    // to web storage; only the archive *directory* participates in memory.
    assert.doesNotMatch(appState, /localStorage[^\n]*archiveView/);
    assert.doesNotMatch(appState, /localStorage[^\n]*verification/);
    // Only the verified directory (not the result) is remembered.
    assert.match(archive, /rememberDirectory\("archive", submittedDirectory\)/);
    // The remembered directory requires fresh verification each session.
    assert.match(archive, /remembered from an earlier selection/);
    assert.match(archive, /never treated as proof that the archive still verifies/);
  });

  it("initializes the archive directory from the remembered location only", () => {
    assert.match(appState, /directory:\s*recallDirectory\("archive"\)\s*\?\?\s*""/);
    assert.match(appState, /verification:\s*null/);
  });
});

// -------------------------------------------------------------------------
// Picker directory memory wiring
// -------------------------------------------------------------------------

describe("picker directory memory wiring", () => {
  it("threads a category into the native dialogs and seeds defaultPath", () => {
    assert.match(dialog, /recallDirectory\(category\)/);
    assert.match(dialog, /rememberDirectoryFromFile\(category, picked\)/);
    assert.match(dialog, /rememberDirectory\(category, picked\)/);
  });

  it("uses distinct categories for archive vs credential vs export", () => {
    assert.match(manage, /pickDirectory\("Choose archive output directory", "archive"\)/);
    assert.match(archive, /pickDirectory\("Choose archive directory", "archive"\)/);
    const create = readProjectFile("src/screens/CreateElection.tsx");
    assert.match(create, /pickDirectory\("Choose export directory", "electionExport"\)/);
  });
});

// -------------------------------------------------------------------------
// Responsive layout invariants
// -------------------------------------------------------------------------

describe("responsive layout invariants", () => {
  it("prefers roomy multi-column cards and stacks them to one column when narrow", () => {
    assert.match(css, /\.card-grid\s*\{[^}]*minmax\(22rem/);
    assert.match(css, /@media \(max-width: 52rem\)[\s\S]*?\.card-grid\s*\{\s*grid-template-columns:\s*1fr/);
  });

  it("stacks analytics metrics and label/value rows on small windows", () => {
    assert.match(css, /@media \(max-width: 34rem\)[\s\S]*?\.analytics-grid\s*\{\s*grid-template-columns:\s*1fr/);
    assert.match(css, /@media \(max-width: 34rem\)[\s\S]*?\.field-list\s*\{[\s\S]*?grid-template-columns:\s*1fr/);
  });

  it("truncates the header election name intentionally without pushing controls out", () => {
    const rule = css.match(/\.toolbar-election\s*\{[^}]*\}/);
    assert.ok(rule, "missing .toolbar-election rule");
    assert.match(rule[0], /min-width:\s*0/);
    assert.match(rule[0], /text-overflow:\s*ellipsis/);
  });
});
