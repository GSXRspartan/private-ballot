// Production transport authority PUBLIC-root operator UX regression tests.
//
// Pins the operator setup/review surface for the configured production
// transport authority public pin. The panel handles ONLY public material: a
// public-key hex in, and a key id / network / public-key fingerprint out. It
// must never present a private-key input, never persist the root as trusted
// state in localStorage (the backend config file is the trusted source), and
// must state plainly that fake/test roots are rejected in release builds.
//
// Runs under Node's built-in test runner with TypeScript type stripping.
// Backend behavior is enforced in Rust; here we pin the frontend plumbing with
// semantic source assertions (the repo's established pattern).

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const manage = readProjectFile("src/screens/ManageElection.tsx");
const client = readProjectFile("src/api/client.ts");
const types = readProjectFile("src/api/types.ts");

describe("production transport authority api surface", () => {
  it("exposes exactly the three public-root commands", () => {
    assert.match(client, /productionTransportAuthorityStatus: \(\) =>/);
    assert.match(
      client,
      /configureProductionTransportAuthorityRoot: \(\s*request: ProductionTransportAuthorityConfigureRequestV1,?\s*\) =>/,
    );
    assert.match(
      client,
      /forgetProductionTransportAuthorityRoot: \(confirm: boolean\) =>/,
    );
    // The status/configure/forget commands map to the shell commands.
    assert.match(client, /"production_transport_authority_status"/);
    assert.match(client, /"configure_production_transport_authority_root"/);
    assert.match(client, /"forget_production_transport_authority_root"/);
  });

  it("carries ONLY public material across the boundary (no private key field)", () => {
    // The configure request has a PUBLIC key hex; no FIELD declares private
    // material (a field is a `name: type;` line, distinct from doc comments).
    const request = types.slice(
      types.indexOf("interface ProductionTransportAuthorityConfigureRequestV1"),
      types.indexOf("interface ProductionTransportAuthorityConfigureRequestV1") + 400,
    );
    assert.match(request, /root_public_key_hex: string;/);
    const requestFields = request.match(/^\s*[a-z_]+: [^;]+;/gim) ?? [];
    for (const field of requestFields) {
      assert.doesNotMatch(field, /private|secret|signing|mnemonic/i);
    }

    // The readiness view exposes a fingerprint, not the raw private material.
    const readiness = types.slice(
      types.indexOf("interface ProductionTransportAuthorityReadinessV1"),
      types.indexOf("interface ProductionTransportAuthorityReadinessV1") + 500,
    );
    assert.match(readiness, /public_key_fingerprint_hex: string \| null;/);
    assert.match(readiness, /managed_tor_build: boolean;/);
    const readinessFields = readiness.match(/^\s*[a-z_]+: [^;]+;/gim) ?? [];
    for (const field of readinessFields) {
      assert.doesNotMatch(field, /private|secret|signing|mnemonic/i);
    }
  });
});

describe("production transport authority operator panel", () => {
  it("renders the three readiness states (unprovisioned, configured, malformed)", () => {
    assert.match(manage, /data-testid="production-authority-unprovisioned"/);
    assert.match(manage, /data-testid="production-authority-configured"/);
    assert.match(manage, /Production authority not provisioned/);
    assert.match(manage, /prodAuthority\.kind === "ready"/);
    assert.match(manage, /prodAuthority\.kind === "malformed"/);
  });

  it("offers a load control and a public-key input, and NO private-key input", () => {
    assert.match(manage, /Load production public root/);
    assert.match(manage, /htmlFor="prod-authority-public-key"/);
    assert.match(manage, /Root public key \(64 hex chars — PUBLIC key only\)/);
    // Scope to the panel: no field within it asks for a private/secret key.
    const panelStart = manage.indexOf('className="production-authority-panel"');
    // Panel ends at its closing </div> before the </DetailsSection>.
    const panelEnd = manage.indexOf('</DetailsSection>', panelStart);
    assert.ok(panelStart >= 0 && panelEnd > panelStart, "panel is delimited");
    const panel = manage.slice(panelStart, panelEnd);
    assert.doesNotMatch(panel, /private key|secret key|signing key|seed phrase|mnemonic/i);
    // No <input> inside the panel is a password field (which would imply secret
    // entry); every input is a plain text field for public values.
    assert.doesNotMatch(panel, /type="password"/);
  });

  it("states the private authority is not stored and fake roots are rejected", () => {
    assert.match(manage, /private signing authority is never entered or\s+stored in the app/);
    assert.match(manage, /Fake\/test roots are rejected in release builds/);
    assert.match(
      manage,
      /The private signing authority is NOT stored in this app/,
    );
  });

  it("surfaces the field-specific backend error code on a bad config", () => {
    assert.match(manage, /error instanceof BackendError \? error\.payload\.code/);
    assert.match(manage, /Could not configure production root: \{prodAuthorityError\}/);
  });

  it("lives inside the Advanced anchor disclosure (not the primary view)", () => {
    const advancedStart = manage.indexOf(
      '<DetailsSection summary="Advanced: technical release verification">',
    );
    const panelStart = manage.indexOf('className="production-authority-panel"');
    assert.ok(advancedStart >= 0, "advanced anchor disclosure exists");
    assert.ok(panelStart > advancedStart, "production authority panel is advanced-only");
  });

  it("never persists the production root as trusted state in localStorage", () => {
    // The panel state is session-only; the trusted source is the backend config
    // file. No production-authority value is written to localStorage.
    for (const marker of [
      "prodAuthority",
      "prodAuthorityKeyId",
      "prodAuthorityPublicKeyHex",
      "production-transport-authority",
    ]) {
      const localStorageWrites = manage.match(
        new RegExp(`localStorage[^\\n]*${marker}`, "g"),
      );
      assert.equal(
        localStorageWrites,
        null,
        `production authority value ${marker} must not be written to localStorage`,
      );
    }
  });
});
