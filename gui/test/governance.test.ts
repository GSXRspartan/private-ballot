// Pure-logic unit tests for the governance source/voter confirmation helpers
// (Slice 5A8). Runs under Node's built-in test runner with TypeScript type
// stripping. No React harness required (ADR-0007).
//
// Run with: npm test

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import type {
  GuiGovernanceDocumentStatusV1,
  GuiGovernanceMatchStatus,
  GuiGovernanceSourcePinV1,
  GuiVoterElectionConfirmationV1,
} from "../src/api/types";
import {
  ADVANCED_DETAILS_LABEL,
  ADVANCED_PIN_LABEL,
  BOUND_SECTION_LABEL,
  INFORMATIONAL_LABEL,
  PRESENTATION_SECTION_LABEL,
  RECOMMENDED_PIN_LABEL,
  confirmationContinueAvailable,
  documentMatchShortLabel,
  documentMatchTone,
  formatByteSize,
  isContentDigestPin,
  isCryptographicallyMatched,
  isGitCommitPin,
  nextStageIsPlaceholder,
  pinFormatTone,
  pinKindLabel,
} from "../src/governance.ts";

function pin(over: Partial<GuiGovernanceSourcePinV1>): GuiGovernanceSourcePinV1 {
  return {
    normalized: over.normalized ?? "",
    kind: over.kind ?? "UNRECOGNIZED",
    format_valid: over.format_valid ?? false,
    digest_hex: over.digest_hex ?? null,
    git_sha_hex: over.git_sha_hex ?? null,
    message: over.message ?? "",
  };
}

function status(over: Partial<GuiGovernanceDocumentStatusV1>): GuiGovernanceDocumentStatusV1 {
  return {
    governance_source_revision: over.governance_source_revision ?? "",
    pin: over.pin ?? pin({}),
    document: over.document ?? null,
    status: over.status ?? "NOT_APPLICABLE",
    status_label: over.status_label ?? "",
  };
}

describe("governance pin presentation", () => {
  it("identifies a content-digest pin", () => {
    assert.equal(isContentDigestPin(pin({ kind: "BLAKE3_DIGEST", format_valid: true })), true);
    assert.equal(isContentDigestPin(pin({ kind: "BLAKE3_DIGEST", format_valid: false })), false);
    assert.equal(isContentDigestPin(null), false);
  });

  it("identifies a git commit pin", () => {
    assert.equal(isGitCommitPin(pin({ kind: "GIT_COMMIT", format_valid: true })), true);
    assert.equal(isGitCommitPin(pin({ kind: "GIT_COMMIT", format_valid: false })), false);
  });

  it("labels pin kinds", () => {
    assert.equal(pinKindLabel(pin({ kind: "BLAKE3_DIGEST" })), "Content digest");
    assert.equal(pinKindLabel(pin({ kind: "GIT_COMMIT" })), "Git commit SHA");
    assert.equal(pinKindLabel(pin({ kind: "UNRECOGNIZED" })), "Unrecognized reference");
    assert.equal(pinKindLabel(null), "No governance source");
  });

  it("tones pin format validity", () => {
    assert.equal(pinFormatTone(pin({ format_valid: true })), "ok");
    assert.equal(pinFormatTone(pin({ format_valid: false })), "warn");
    assert.equal(pinFormatTone(null), "neutral");
  });
});

describe("governance document match labels", () => {
  it("tones match status, ok only for MATCHED", () => {
    assert.equal(documentMatchTone("MATCHED"), "ok");
    assert.equal(documentMatchTone("MISMATCH"), "error");
    assert.equal(documentMatchTone("OPERATOR_ATTESTED"), "warn");
    assert.equal(documentMatchTone("UNVERIFIED_REFERENCE"), "warn");
    assert.equal(documentMatchTone("NOT_APPLICABLE"), "neutral");
    assert.equal(documentMatchTone(null), "neutral");
  });

  it("short labels match status", () => {
    assert.equal(documentMatchShortLabel("MATCHED"), "Matched");
    assert.equal(documentMatchShortLabel("MISMATCH"), "Mismatch");
    assert.equal(documentMatchShortLabel("OPERATOR_ATTESTED"), "Operator-attested");
    assert.equal(documentMatchShortLabel("UNVERIFIED_REFERENCE"), "Not available");
    assert.equal(documentMatchShortLabel("NOT_APPLICABLE"), "Not applicable");
    assert.equal(documentMatchShortLabel(null), "Not available");
  });

  it("cryptographic match only for MATCHED", () => {
    assert.equal(isCryptographicallyMatched("MATCHED"), true);
    assert.equal(isCryptographicallyMatched("OPERATOR_ATTESTED"), false);
    assert.equal(isCryptographicallyMatched(null), false);
  });

  it("operator-attested label must not claim cryptographic verification", () => {
    const s = status({ status: "OPERATOR_ATTESTED", status_label: "Reference is immutable-format; document correspondence is not independently verified by this application." });
    assert.match(s.status_label, /not independently verified/);
    assert.doesNotMatch(s.status_label, /cryptographically verified/i);
  });
});

describe("byte size formatting", () => {
  it("formats bytes, KiB, MiB", () => {
    assert.equal(formatByteSize(0), "0 bytes");
    assert.equal(formatByteSize(512), "512 bytes");
    assert.equal(formatByteSize(2048), "2.0 KiB");
    assert.equal(formatByteSize(5 * 1024 * 1024), "5.0 MiB");
  });

  it("handles null/undefined/negative", () => {
    assert.equal(formatByteSize(null), "—");
    assert.equal(formatByteSize(undefined), "—");
    assert.equal(formatByteSize(-1), "—");
  });
});

describe("confirmation boundary", () => {
  const confirmation = {
    bound: { manifest_hash_hex: "abcd" },
  } as unknown as GuiVoterElectionConfirmationV1;

  it("continue is available when manifest hash is present", () => {
    assert.equal(confirmationContinueAvailable(confirmation), true);
    assert.equal(confirmationContinueAvailable(null), false);
  });

  it("next stage placeholder stays deferred", () => {
    assert.equal(
      nextStageIsPlaceholder("Credential and proof workflow will be enabled in the next reviewed slice."),
      true,
    );
    assert.equal(nextStageIsPlaceholder("Cast your vote now"), false);
  });

  it("exposes stable section labels", () => {
    assert.equal(BOUND_SECTION_LABEL, "Verified election details");
    assert.equal(PRESENTATION_SECTION_LABEL, "Presentation");
    assert.equal(INFORMATIONAL_LABEL, "Informational");
    assert.equal(ADVANCED_DETAILS_LABEL, "Advanced details");
    assert.match(RECOMMENDED_PIN_LABEL, /Recommended/);
    assert.match(ADVANCED_PIN_LABEL, /Advanced/);
  });
});
