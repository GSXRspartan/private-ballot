import test from "node:test";
import assert from "node:assert/strict";

import type { GuiVoterSelectionStatusV1 } from "../src/api/types.ts";
import {
  noVoterWorkflowSecretFieldNames,
  selectionAtApprovalMax,
  selectionSummaryText,
  workflowTone,
} from "../src/voterWorkflow.ts";

const baseSelection: GuiVoterSelectionStatusV1 = {
  selection_loaded: true,
  selected_option_ids_hex: ["63616e6469646174652d61"],
  selected_display_labels: ["Candidate A"],
  selected_count: 1,
  approval_min: 1,
  approval_max: 2,
  abstention_allowed: false,
  abstaining: false,
  valid: true,
  lifecycle_state: "OPEN",
  can_prepare_ballot: true,
  selection_revision: 1,
  message: "Selection is valid.",
};

test("voter workflow selection summary", () => {
  assert.equal(selectionSummaryText(null), "No selection");
  assert.equal(selectionSummaryText(baseSelection), "1 selected");
  assert.equal(
    selectionSummaryText({ ...baseSelection, selected_count: 0, abstaining: true }),
    "Abstaining",
  );
});

test("voter workflow tone follows Rust state", () => {
  assert.equal(workflowTone("SelectionReady"), "ok");
  assert.equal(workflowTone("CredentialNotEligible"), "warn");
  assert.equal(workflowTone("SelectionIncomplete"), "neutral");
  assert.equal(workflowTone(null), "neutral");
});

test("selection max helper ignores abstention", () => {
  assert.equal(selectionAtApprovalMax(baseSelection), false);
  assert.equal(selectionAtApprovalMax({ ...baseSelection, selected_count: 2 }), true);
  assert.equal(
    selectionAtApprovalMax({ ...baseSelection, selected_count: 2, abstaining: true }),
    false,
  );
});

test("voter workflow api field names stay free of secret-bearing material", () => {
  assert.equal(
    noVoterWorkflowSecretFieldNames([
      "election_binding",
      "credential_generation",
      "selection_revision",
      "preparation_generation",
      "preparation_notice",
    ]),
    true,
  );
  assert.equal(noVoterWorkflowSecretFieldNames(["proof_bytes"]), false);
  assert.equal(noVoterWorkflowSecretFieldNames(["member_index"]), false);
  assert.equal(noVoterWorkflowSecretFieldNames(["passphrase"]), false);
});

test("private submission DTO field names stay voter-safe", () => {
  assert.equal(
    noVoterWorkflowSecretFieldNames([
      "route",
      "receipt_state",
      "retry_status",
      "reduced_anonymity",
      "managed_tor_available",
      "offline_export_available",
    ]),
    true,
  );
  assert.equal(noVoterWorkflowSecretFieldNames(["gateway_receiver_secret"]), false);
  assert.equal(noVoterWorkflowSecretFieldNames(["duplicate_of_sequence"]), false);
});
