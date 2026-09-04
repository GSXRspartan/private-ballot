// Evidence + Settings + About release-readiness pass (pre-repository audit).
//
// Runs under Node's built-in test runner with TypeScript type stripping.
// Pins semantic invariants against source text — no browser harness is used
// here; the runtime UX is verified separately from the human runtime
// checklist. Assertions cover the failure the operator hit at pre-release:
// the Evidence screen must no longer treat legacy CBOR as the normal
// current format, and normal V2 anchoring must be the primary workflow.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

/** Extracts the body of a named arrow-function handler defined inside a
 *  component (`const <name> = async () => { … };`). Returns the body plus
 *  a small margin of the wrapping declaration so imports/calls are
 *  observable. Enough for source-text semantic assertions; not a parser. */
function extractHandler(source: string, name: string): string {
  const marker = `const ${name} = `;
  const idx = source.indexOf(marker);
  if (idx < 0) return "";
  // Find the matching closing brace by simple balancing from the first `{`.
  const openIdx = source.indexOf("{", idx);
  if (openIdx < 0) return source.slice(idx);
  let depth = 0;
  for (let i = openIdx; i < source.length; i += 1) {
    const ch = source[i];
    if (ch === "{") depth += 1;
    else if (ch === "}") {
      depth -= 1;
      if (depth === 0) return source.slice(idx, i + 1);
    }
  }
  return source.slice(idx);
}

const evidence = readProjectFile("src/screens/Evidence.tsx");
const settings = readProjectFile("src/screens/Settings.tsx");
const about = readProjectFile("src/screens/About.tsx");
const dialog = readProjectFile("src/api/dialog.ts");
const apiClient = readProjectFile("src/api/client.ts");
const apiTypes = readProjectFile("src/api/types.ts");
const identity = readProjectFile("src/branding/identity.ts");
const app = readProjectFile("src/App.tsx");
const shellSource = readProjectFile("src-tauri/src/lib.rs");
const guiCoreLifecycle = readProjectFile(
  "../crates/gui-core/src/live_anchor_v2_lifecycle.rs",
);
const guiCoreLib = readProjectFile("../crates/gui-core/src/lib.rs");

// -------------------------------------------------------------------------
// Evidence: current V2 JSON is the normal evidence format
// -------------------------------------------------------------------------

describe("Evidence — current V2 JSON is the normal format", () => {
  it("uses the V2 JSON picker as the primary evidence path and confines the legacy CBOR picker to a dedicated handler", () => {
    // The manual V2 evidence loader must use the JSON picker …
    assert.match(evidence, /pickV2AnchorEvidenceJson/);
    // … its callback must invoke the schema-validated V2 reader and the
    // V2 cryptographic verifier, never the legacy CBOR decoder.
    const manualHandler = extractHandler(evidence, "onInspectManualJson");
    assert.match(manualHandler, /readV2PublicAnchorEvidenceFile/);
    assert.match(manualHandler, /verifyV2PublicAnchorEvidence/);
    assert.ok(
      !manualHandler.includes("inspectAnchorEvidence"),
      "manual V2 handler must not call the legacy CBOR verifier",
    );
    assert.ok(
      !manualHandler.includes("pickCborFile"),
      "manual V2 handler must not open the legacy CBOR picker",
    );
    // The legacy CBOR picker exists ONLY inside the legacy handler.
    const legacyPickHandler = extractHandler(evidence, "onPickLegacyEvidence");
    assert.match(legacyPickHandler, /pickCborFile\(/);
  });

  it("exposes a V2-specific JSON dialog with the .v2-anchor-evidence.json filter", () => {
    assert.match(dialog, /export async function pickV2AnchorEvidenceJson/);
    assert.match(dialog, /"v2-anchor-evidence\.json"/);
    // The V2 dialog also lists plain JSON as a fallback, but never CBOR.
    const fn = dialog.split("export async function pickV2AnchorEvidenceJson")[1];
    assert.ok(fn, "pickV2AnchorEvidenceJson body missing");
    const body = fn.split("export ")[0];
    assert.doesNotMatch(body, /Canonical CBOR/);
    assert.doesNotMatch(body, /extensions: \["cbor"\]/);
  });

  it("does not tell normal V2 users to select anchor-evidence.cbor in the primary JSX flow", () => {
    // Split the JSX at the first Advanced disclosure — everything before that
    // is the normal path the operator is expected to use.
    const [primaryFlow] = evidence.split(
      "<DetailsSection summary=\"Advanced: load V2 evidence from another location\">",
    );
    assert.ok(primaryFlow, "primary Evidence JSX flow could not be extracted");
    assert.doesNotMatch(primaryFlow, /anchor-evidence\.cbor/);
  });
});

// -------------------------------------------------------------------------
// Evidence: auto-discovery, verification, receipt boundary
// -------------------------------------------------------------------------

describe("Evidence — auto-discovery and archive binding", () => {
  it("hydrates V2 evidence from the currently verified archive", () => {
    assert.match(evidence, /inspectV2LiveAnchorState/);
    assert.match(evidence, /boundArchiveResult/);
    assert.match(evidence, /Verify a final archive first/);
    // Prerequisite guidance must remain (pinned by branding tests too).
    assert.match(evidence, /Choose an evidence file to continue\./);
  });

  it("re-verifies the canonical payload/digest against the archive via the Rust verifier", () => {
    assert.match(evidence, /verifyV2PublicAnchorEvidence\(/);
  });

  it("distinguishes evidence-file verification from on-chain receipt re-verification", () => {
    // Receipt state is displayed as "Previously verified", never as "on-chain
    // reverified" — the Evidence screen does not fetch the indexer.
    assert.match(evidence, /Previously verified/);
    assert.doesNotMatch(evidence, /On-chain receipt reverified/i);
    assert.doesNotMatch(evidence, /re-fetched from the indexer.*Verified/);
  });

  it("never invokes the legacy CBOR decoder from the primary V2 handlers", () => {
    // The legacy CBOR verifier must appear only inside the legacy handler.
    const legacyHandler = extractHandler(evidence, "onInspectLegacy");
    assert.match(legacyHandler, /api\.inspectAnchorEvidence\(/);
    for (const primary of ["onInspectManualJson", "verifyHydrated"]) {
      const handler = extractHandler(evidence, primary);
      assert.ok(
        !handler.includes("inspectAnchorEvidence"),
        `${primary} must not call the legacy CBOR verifier`,
      );
    }
  });

  it("never falsely claims a fresh cryptographic archive binding for unmatched manual V2 evidence", () => {
    // When no verified archive is loaded, or the JSON's archive_directory
    // does not match the loaded one, the UI must state that the binding was
    // NOT cross-checked. It must not silently pass evidence as verified.
    assert.match(evidence, /Not cross-checked \(file's archive_directory ≠ loaded archive\)/);
    assert.match(evidence, /Not cross-checked \(no verified archive loaded\)/);
  });

  it("surfaces a specific failure notice when the evidence exists but does not verify", () => {
    assert.match(evidence, /V2 evidence failed verification/);
  });
});

// -------------------------------------------------------------------------
// Evidence: legacy V1 CBOR still available under Advanced
// -------------------------------------------------------------------------

describe("Evidence — legacy V1 CBOR", () => {
  it("keeps the legacy V1 CBOR verifier under an Advanced/Legacy disclosure", () => {
    assert.match(evidence, /Legacy V1 evidence verification/);
    assert.match(evidence, /inspectAnchorEvidence\(/);
    // Legacy picker retains the CBOR filter.
    assert.match(evidence, /pickCborFile\("Choose anchor evidence file"\)/);
  });

  it("names the legacy .cbor file explicitly for historical operators", () => {
    assert.match(evidence, /anchor-evidence\.cbor/);
  });
});

// -------------------------------------------------------------------------
// Evidence: no wallet or transaction side effects
// -------------------------------------------------------------------------

describe("Evidence — no side effects", () => {
  it("does not construct any walletd or lifecycle-write command from Evidence", () => {
    // Evidence inspection is READ ONLY: no walletd connect/reconnect/submit,
    // no lifecycle-writing anchor commands, and no anchor publish.
    for (const forbidden of [
      "connectWalletd",
      "reconnectWalletd",
      "runV2LiveAnchorLifecycleStep",
      "runLiveAnchorLifecycleStep",
      "recoverV2LiveAnchor",
      "prepareV2AnchorPublish",
      "writeLiveAnchorConfig",
      "buildV2PublicAnchorPayload",
    ]) {
      assert.ok(
        !evidence.includes(forbidden),
        `Evidence.tsx must not invoke ${forbidden}`,
      );
    }
  });

  it("keeps the readable public summary display purely presentational (no digest recomputation on it)", () => {
    // The pretty-printed public summary is display-only; the canonical bytes
    // used for digest checks are the hex payload the Rust verifier receives.
    // Reject any accidental hashing/digesting call added to the pretty
    // formatter or its downstream renders.
    for (const forbidden of ["crypto.subtle", "Blake3", "blake3", "sha256", "digest(", "Digest("]) {
      assert.ok(
        !evidence.includes(forbidden),
        `Evidence.tsx must not compute digests in the frontend (${forbidden})`,
      );
    }
    // The formatter parses JSON for pretty print and falls back to the raw
    // string; it never touches the payload_hex bytes.
    assert.match(evidence, /function formatPublicSummary\(/);
  });
});

// -------------------------------------------------------------------------
// Evidence: cross-page consistency
// -------------------------------------------------------------------------

describe("Evidence — cross-page identity", () => {
  it("passes the Evidence screen the same navigate prop the other pages get", () => {
    assert.match(app, /section === "evidence" && <Evidence onNavigate=/);
  });
});

// -------------------------------------------------------------------------
// V2 evidence file reader: types + backend wiring
// -------------------------------------------------------------------------

describe("V2 evidence file reader", () => {
  it("declares a schema-validated GuiV2AnchorEvidenceFileV1 type", () => {
    assert.match(apiTypes, /GuiV2AnchorEvidenceFileV1/);
    assert.match(apiTypes, /template_topic: string/);
    assert.match(apiTypes, /anchor_digest_hex: string/);
    assert.match(apiTypes, /payload_hex: string/);
  });

  it("exposes readV2PublicAnchorEvidenceFile on the API client", () => {
    assert.match(apiClient, /readV2PublicAnchorEvidenceFile/);
    assert.match(apiClient, /"read_v2_public_anchor_evidence_file"/);
  });

  it("registers the read command with the Tauri invoke handler", () => {
    assert.match(shellSource, /fn read_v2_public_anchor_evidence_file/);
    assert.match(shellSource, /read_v2_public_anchor_evidence_file,/);
    assert.match(shellSource, /read_v2_public_anchor_evidence_file_core/);
  });

  it("re-exports the Rust reader from gui-core", () => {
    assert.match(guiCoreLib, /read_v2_public_anchor_evidence_file/);
    assert.match(guiCoreLib, /GuiV2AnchorEvidenceFileV1/);
  });

  it("schema-validates fail-closed for malformed JSON and unsupported schemas", () => {
    // The reader must reuse load_evidence (which fails closed on parse
    // errors) and then explicitly reject records whose declared schema is
    // not the current V2 evidence schema.
    assert.match(guiCoreLifecycle, /pub fn read_v2_public_anchor_evidence_file/);
    assert.match(guiCoreLifecycle, /GUI_ANCHOR_V2_EVIDENCE_SCHEMA_UNSUPPORTED/);
    assert.match(guiCoreLifecycle, /GUI_ANCHOR_V2_EVIDENCE_FILE_MISSING/);
  });
});

// -------------------------------------------------------------------------
// Settings
// -------------------------------------------------------------------------

describe("Settings — directory clarity and diagnostics", () => {
  it("keeps automatic, light, and dark theme options", () => {
    assert.match(settings, /value: "system"/);
    assert.match(settings, /value: "light"/);
    assert.match(settings, /value: "dark"/);
  });

  it("explains directory overrides use the application default when blank", () => {
    assert.match(settings, /Using application default/);
    // Both directory fields carry the same neutral placeholder text.
    const placeholders = [...settings.matchAll(/placeholder="Using application default"/g)];
    assert.ok(placeholders.length >= 2, "both directory inputs should share the default placeholder");
    assert.match(settings, /leave blank/);
    assert.match(settings, /does not move existing archives/);
  });

  it("labels developer diagnostics as Advanced and keeps them off by default", () => {
    assert.match(settings, /Advanced \/ Developer diagnostics/);
    assert.match(settings, /Off by default/);
    // No secret-carrying settings are exposed. The Settings surface may only
    // MENTION such categories to explain what diagnostics do not do; it must
    // not expose an input, label, form field, or button that carries a
    // credential, passphrase, wallet secret, or private key.
    for (const forbidden of [
      "type=\"password\"",
      "htmlFor=\"password\"",
      "htmlFor=\"passphrase\"",
      "name=\"password\"",
      "name=\"passphrase\"",
    ]) {
      assert.ok(
        !settings.includes(forbidden),
        `Settings.tsx must not expose ${forbidden}`,
      );
    }
  });

  it("keeps Settings free of wallet / template / experimental toggles", () => {
    for (const forbidden of [
      "connectWalletd",
      "trustedOotle",
      "OotleTemplate",
      "feature toggle",
      "experimentalFlag",
    ]) {
      assert.ok(
        !settings.includes(forbidden),
        `Settings.tsx must not expose ${forbidden}`,
      );
    }
  });
});

// -------------------------------------------------------------------------
// About
// -------------------------------------------------------------------------

describe("About — release status clarity", () => {
  it("adds a distinct Release status field labelled Alpha", () => {
    assert.match(about, /Release status/);
    assert.match(about, /APP_RELEASE_STATUS/);
    assert.match(identity, /export const APP_RELEASE_STATUS = "Alpha"/);
  });

  it("names the Esmeralda testnet as the target network on About", () => {
    assert.match(about, /APP_NETWORK_LABEL/);
    assert.match(identity, /export const APP_NETWORK_LABEL = "Esmeralda Testnet"/);
  });

  it("keeps the governance-pilot purpose label", () => {
    assert.match(about, /Purpose/);
    assert.match(about, /APP_STATUS_LABEL/);
    assert.match(identity, /APP_STATUS_LABEL = "Governance Pilot"/);
  });

  it("retains the independent open-source project disclaimer verbatim", () => {
    assert.match(about, /COMMUNITY_DISCLAIMER/);
    assert.match(
      identity,
      /Private Ballot is an independent open-source project\. It is not affiliated with or endorsed by Tari Labs\./,
    );
  });

  it("keeps donations optional, separate from voting/eligibility", () => {
    assert.match(about, /DONATION_DISCLAIMER/);
    const donationBlock = about.slice(about.indexOf("Donate to the dev"));
    assert.doesNotMatch(donationBlock, /required/i);
    assert.doesNotMatch(donationBlock, /eligibility/i);
    assert.doesNotMatch(donationBlock, /access/i);
  });

  it("does not introduce a fake GitHub / source URL", () => {
    // The repository is not published yet; the About page must not carry a
    // placeholder github.com URL.
    assert.doesNotMatch(about, /github\.com\//);
    // Version stays in step with package.json (existing branding test).
    const pkg = JSON.parse(readProjectFile("package.json"));
    assert.equal(pkg.version, "0.1.0");
  });
});

// -------------------------------------------------------------------------
// Cross-page release labelling consistency
// -------------------------------------------------------------------------

describe("Cross-page release labelling", () => {
  it("keeps the frontend release identity constants in one branding file", () => {
    assert.match(identity, /APP_NAME/);
    assert.match(identity, /APP_IDENTITY_TAG/);
    assert.match(identity, /APP_STATUS_LABEL/);
    assert.match(identity, /APP_RELEASE_STATUS/);
    assert.match(identity, /APP_NETWORK_LABEL/);
    assert.match(identity, /APP_VERSION/);
  });
});
