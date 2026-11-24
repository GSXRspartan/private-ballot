// Release UX boundary checks for the Hosted → Desktop archive import flow.
// Desktop imports a pre-downloaded archive JSON file from disk; it never
// receives the organizer credential. The browser downloads and saves the file
// using its own in-memory credential; Rust reads the file from an absolute path.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const read = (path: string) => readFileSync(new URL(path, import.meta.url), "utf8");
const manage = read("../src/screens/ManageElection.tsx");
const client = read("../src/api/client.ts");
const dialog = read("../src/api/dialog.ts");
const types = read("../src/api/types.ts");
const shell = read("../src-tauri/src/lib.rs");

describe("Hosted archive import", () => {
  it("wires file-picker, client, and UI button into ManageElection", () => {
    assert.match(manage, /pickHostedArchiveJson\(\)/);
    assert.match(manage, /pickDirectory\(.*archive/);
    assert.match(manage, /api\.importHostedArchive\(/);
    assert.match(manage, /onImportHostedArchive/);
    assert.match(manage, /Import Hosted archive/);
    assert.match(manage, /hostedArchiveImportResult/);
  });

  it("dialog provides a JSON file picker for the downloaded archive", () => {
    assert.match(dialog, /pickHostedArchiveJson/);
    assert.match(dialog, /Import Hosted finalized archive/);
  });

  it("client wraps import_hosted_archive with file path, not inline JSON", () => {
    assert.match(client, /"import_hosted_archive"/);
    assert.match(client, /archive_json_path/);
    assert.match(client, /importHostedArchive/);
    assert.doesNotMatch(client, /archive_body_json/);
  });

  it("GuiArchiveImportResultV1 type is declared in types.ts", () => {
    assert.match(types, /GuiArchiveImportResultV1/);
    assert.match(types, /archive_hash_hex: string/);
    assert.match(types, /file_count: number/);
    assert.match(types, /verified: boolean/);
    assert.match(types, /finalized: boolean/);
  });

  it("Rust handler reads from absolute file path, not inline string", () => {
    assert.match(shell, /archive_json_path/);
    assert.match(shell, /is_absolute\(\)/);
    assert.match(shell, /GUI_ARCHIVE_IMPORT_PATH_NOT_ABSOLUTE/);
    assert.match(shell, /read_to_string\(archive_json_path\)/);
    assert.doesNotMatch(shell, /archive_body_json: String/);
  });

  it("Rust handler still path-validates all archive member paths", () => {
    assert.match(shell, /ArchivePathV1/);
    assert.match(shell, /GUI_ARCHIVE_IMPORT_PATH_ESCAPE/);
    assert.match(shell, /starts_with\(&staging_path\)/);
  });

  it("organizer credential never reaches Rust", () => {
    assert.doesNotMatch(shell, /x-private-ballot-organizer/);
    assert.doesNotMatch(shell, /organizer_secret_hex/);
  });
});
