import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { describeError } from "../src/api/errorDisplay.ts";
import type { GuiVoterCredentialStatusV1 } from "../src/api/types.ts";
import {
  backupCredentialFlow,
  clearMemoryConfirmationText,
  copyPublicEnrollmentKey,
  createDurableCredentialFlow,
  credentialStorageText,
  importCredentialFlow,
  noSecretFieldNames,
  unlockSavedCredentialFlow,
} from "../src/voterCredential.ts";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const PUBLIC_KEY =
  "6a493210f7499cd17fecb510ae0a23fda0d4b58a1b48d4ecc0f4cbc9423e86f2";

function credential(
  over: Partial<GuiVoterCredentialStatusV1> = {},
): GuiVoterCredentialStatusV1 {
  return {
    credential_loaded: true,
    credential_origin: "DurableCreated",
    public_governance_key_hex: PUBLIC_KEY,
    public_governance_key_abbrev: "6a493210...3e86f2",
    eligibility: "Eligible",
    eligibility_label: "Eligible",
    can_continue: true,
    session_only: false,
    session_notice: "Saved locally",
    saved_locally: true,
    wallet_key_warning: "not a wallet seed",
    enrollment_notice: "Enroll before freeze",
    ...over,
  };
}

test("credential DTO runtime validation rejects forbidden secret-like fields", () => {
  assert.equal(
    noSecretFieldNames([
      "credential_loaded",
      "credential_origin",
      "public_governance_key_hex",
      "public_governance_key_abbrev",
      "eligibility",
      "eligibility_label",
      "can_continue",
      "session_only",
      "session_notice",
      "saved_locally",
      "wallet_key_warning",
      "enrollment_notice",
    ]),
    true,
  );
  for (const field of [
    "secret",
    "scalar",
    "seed",
    "mnemonic",
    "private_key",
    "credential_bytes",
    "nullifier",
    "proof",
    "passphrase",
    "password",
  ]) {
    assert.equal(noSecretFieldNames([field]), false, field);
  }
});

test("create requires matching confirmation before invoking Rust", async () => {
  let calls = 0;
  const result = await createDurableCredentialFlow(
    "alpha",
    "beta",
    async () => {
      calls += 1;
    },
    () => undefined,
  );

  assert.equal(result, null);
  assert.equal(calls, 0);
});

test("create passphrases clear after success and failure", async () => {
  let successClears = 0;
  await createDurableCredentialFlow(
    "alpha",
    "alpha",
    async (passphrase) => {
      assert.equal(passphrase, "alpha");
    },
    () => {
      successClears += 1;
    },
  );
  assert.equal(successClears, 1);

  let failureClears = 0;
  await assert.rejects(
    createDurableCredentialFlow(
      "alpha",
      "alpha",
      async () => {
        throw new Error("backend rejected create");
      },
      () => {
        failureClears += 1;
      },
    ),
  );
  assert.equal(failureClears, 1);
});

test("unlock invokes only public key and passphrase and clears after settle", async () => {
  const calls: unknown[][] = [];
  let clears = 0;
  await unlockSavedCredentialFlow(
    PUBLIC_KEY,
    "unlock passphrase",
    async (...args) => {
      calls.push(args);
    },
    () => {
      clears += 1;
    },
  );

  assert.deepEqual(calls, [[PUBLIC_KEY, "unlock passphrase"]]);
  assert.equal(clears, 1);

  await assert.rejects(
    unlockSavedCredentialFlow(
      PUBLIC_KEY,
      "wrong passphrase",
      async () => {
        throw new Error("unlock failed");
      },
      () => {
        clears += 1;
      },
    ),
  );
  assert.equal(clears, 2);
});

test("import uses external path, passphrase, and persist flag, never raw bytes", async () => {
  const calls: unknown[][] = [];
  let clears = 0;
  await importCredentialFlow(
    "C:\\credentials\\backup.tcbcred",
    "import passphrase",
    false,
    async (...args) => {
      calls.push(args);
    },
    () => {
      clears += 1;
    },
  );

  assert.deepEqual(calls, [["C:\\credentials\\backup.tcbcred", "import passphrase", false]]);
  assert.equal(clears, 1);
});

test("backup uses external path and passphrase, never secret or container bytes", async () => {
  const calls: unknown[][] = [];
  let clears = 0;
  await backupCredentialFlow(
    "C:\\credentials\\voter-credential.tcbcred",
    "backup passphrase",
    "backup passphrase",
    async (...args) => {
      calls.push(args);
    },
    () => {
      clears += 1;
    },
  );

  assert.deepEqual(calls, [["C:\\credentials\\voter-credential.tcbcred", "backup passphrase"]]);
  assert.equal(clears, 1);
});

test("Copy public key copies only public_governance_key_hex", async () => {
  const copied: string[] = [];
  const ok = await copyPublicEnrollmentKey(credential(), async (value) => {
    copied.push(value);
  });

  assert.equal(ok, true);
  assert.deepEqual(copied, [PUBLIC_KEY]);
});

test("Vote renders VoterCredentialCard when election is null", () => {
  const vote = readProjectFile("src/screens/Vote.tsx");
  const credentialCard = vote.indexOf("<VoterCredentialCard");
  const noElectionLoad = vote.indexOf("{!election && (");

  assert.ok(credentialCard > vote.indexOf("<BackendErrorNotice"));
  assert.ok(noElectionLoad > credentialCard);
});

test("Vote still renders Load Election when election is null", () => {
  const vote = readProjectFile("src/screens/Vote.tsx");
  const noElectionBlock = vote.slice(
    vote.indexOf("{!election && ("),
    vote.indexOf("{confirmation && ("),
  );

  assert.match(noElectionBlock, /<Card title="Load Election">/);
  assert.match(noElectionBlock, /onClick=\{\(\) => void onVoterLoadElection\(\)\}/);
});

test("Create credential is reachable before election load", () => {
  const vote = readProjectFile("src/screens/Vote.tsx");
  const card = readProjectFile("src/components/VoterCredentialCard.tsx");
  const preElection = vote.slice(
    vote.indexOf("<VoterCredentialCard"),
    vote.indexOf("{!election && ("),
  );

  assert.match(preElection, /onCreate=\{onCreateCredential\}/);
  assert.match(card, /Create credential/);
  assert.match(card, /onCreate=\{\(\) => openDialog\("create"\)\}/);
});

test("Unlock saved credential is reachable before election load", () => {
  const vote = readProjectFile("src/screens/Vote.tsx");
  const card = readProjectFile("src/components/VoterCredentialCard.tsx");
  const preElection = vote.slice(
    vote.indexOf("<VoterCredentialCard"),
    vote.indexOf("{!election && ("),
  );

  assert.match(preElection, /onUnlock=\{onUnlockCredential\}/);
  assert.match(card, /Unlock saved credential/);
  assert.match(card, /onUnlock=\{\(\) => openDialog\("unlock"\)\}/);
});

test("Import credential is reachable before election load", () => {
  const vote = readProjectFile("src/screens/Vote.tsx");
  const card = readProjectFile("src/components/VoterCredentialCard.tsx");
  const preElection = vote.slice(
    vote.indexOf("<VoterCredentialCard"),
    vote.indexOf("{!election && ("),
  );

  assert.match(preElection, /onImport=\{onImportCredential\}/);
  assert.match(card, /Import credential/);
  assert.match(card, /openImportDialog/);
});

test("Loaded credential on Vote exposes Copy public key before election load", () => {
  const vote = readProjectFile("src/screens/Vote.tsx");
  const card = readProjectFile("src/components/VoterCredentialCard.tsx");
  const preElection = vote.slice(
    vote.indexOf("<VoterCredentialCard"),
    vote.indexOf("{!election && ("),
  );

  assert.match(preElection, /status=\{credential\}/);
  assert.match(preElection, /showFrozenElectionNotice=\{!!election\}/);
  assert.match(card, /<LoadedCredential/);
  assert.match(card, /Public enrollment key/);
  assert.match(card, /Copy public key/);
});

test("different-credential error does not trigger automatic clear or retry", () => {
  const display = describeError({
    code: "GUI_CREDENTIAL_ALREADY_LOADED",
    category: "INVALID_LIFECYCLE_TRANSITION",
    context: "credential",
    message: "a different voter credential is already loaded; clear it before switching",
  });
  const card = readProjectFile("src/components/VoterCredentialCard.tsx");
  const catchBlock = card.slice(
    card.indexOf("async function runDialogOperation"),
    card.indexOf("async function openImportDialog"),
  );

  assert.match(display.message, /Clear it from memory before switching credentials/);
  assert.doesNotMatch(catchBlock, /onClear|clearVoterCredentialFromMemory|retry/i);
});

test("wrong unlock passphrase displays the bounded unlock warning", () => {
  const display = describeError({
    code: "GUI_CREDENTIAL_UNLOCK_FAILED",
    category: "INVALID_INPUT",
    context: "credential-unlock",
    message: "unlock failed",
  });
  const card = readProjectFile("src/components/VoterCredentialCard.tsx");

  assert.equal(display.title, "Credential could not be unlocked");
  assert.match(display.message, /passphrase may be incorrect/);
  assert.match(card, /<BackendErrorNotice/);
  assert.match(card, /operationError/);
});

test("successful unlock retry clears the prior wrong-password warning", () => {
  const vote = readProjectFile("src/screens/Vote.tsx");
  const card = readProjectFile("src/components/VoterCredentialCard.tsx");
  const dialogOperation = card.slice(
    card.indexOf("async function runDialogOperation"),
    card.indexOf("async function openImportDialog"),
  );

  assert.match(vote, /const \[credentialError, setCredentialError\]/);
  assert.match(vote, /onError=\{captureCredentialError\}/);
  assert.match(vote, /operationError=\{credentialError\}/);
  assert.match(vote, /onOperationSuccess=\{\(\) => setCredentialError\(null\)\}/);
  assert.match(dialogOperation, /const finished = await fn\(\)/);
  assert.match(dialogOperation, /if \(finished\) \{\s+onOperationSuccess\?\.\(\);\s+closeDialog\(\);/);
});

test("successful create clears prior credential-operation error", () => {
  const card = readProjectFile("src/components/VoterCredentialCard.tsx");
  const createBlock = card.slice(
    card.indexOf('if (dialog === "create")'),
    card.indexOf('if (dialog === "unlock"'),
  );

  assert.match(createBlock, /createDurableCredentialFlow/);
  assert.match(createBlock, /return true/);
  assert.match(card, /onOperationSuccess\?\.\(\);\s+closeDialog\(\);/);
});

test("successful import clears prior credential-operation error", () => {
  const card = readProjectFile("src/components/VoterCredentialCard.tsx");
  const importBlock = card.slice(
    card.indexOf('if (dialog === "import"'),
    card.indexOf('if (dialog === "backup"'),
  );

  assert.match(importBlock, /importCredentialFlow/);
  assert.match(importBlock, /return true/);
  assert.match(card, /onOperationSuccess\?\.\(\);\s+closeDialog\(\);/);
});

test("successful backup clears prior credential-operation error", () => {
  const card = readProjectFile("src/components/VoterCredentialCard.tsx");
  const backupBlock = card.slice(
    card.indexOf('if (dialog === "backup"'),
    card.indexOf("async function copyPublicKey"),
  );

  assert.match(backupBlock, /backupCredentialFlow/);
  assert.match(backupBlock, /return true/);
  assert.match(card, /onOperationSuccess\?\.\(\);\s+closeDialog\(\);/);
});

test("successful clear and delete do not leave stale credential errors", () => {
  const card = readProjectFile("src/components/VoterCredentialCard.tsx");
  const operation = card.slice(
    card.indexOf("async function runOperation"),
    card.indexOf("async function runDialogOperation"),
  );
  const clearDelete = card.slice(
    card.indexOf("async function confirmClear"),
    card.indexOf("  return (", card.indexOf("async function confirmClear")),
  );

  assert.match(operation, /await fn\(\);\s+onOperationSuccess\?\.\(\);/);
  assert.match(clearDelete, /runOperation\("clear", onClear\)/);
  assert.match(clearDelete, /runOperation\("delete", \(\) => onDeleteSaved\(currentPublicKey\)\)/);
});

test("election-loaded Vote flow still works and does not render duplicate credential cards", () => {
  const vote = readProjectFile("src/screens/Vote.tsx");
  const matches = vote.match(/<VoterCredentialCard/g) ?? [];
  const credentialStage = vote.slice(
    vote.indexOf("{credentialStage && ("),
    vote.indexOf("{selectionStage && confirmation && ("),
  );

  assert.equal(matches.length, 1);
  assert.match(vote, /<Card title="Eligibility">/);
  assert.match(vote, /disabled=\{!canProceedAfterCredential\(credential\) \|\| busy\}/);
  assert.doesNotMatch(credentialStage, /<VoterCredentialCard/);
});

test("delete saved passes public key, not a path", () => {
  const card = readProjectFile("src/components/VoterCredentialCard.tsx");
  const client = readProjectFile("src/api/client.ts");

  assert.match(card, /onDeleteSaved\(currentPublicKey\)/);
  assert.match(client, /deleteSavedVoterCredential: \(publicKeyHex: string\)/);
  assert.match(client, /"delete_saved_voter_credential"/);
  assert.doesNotMatch(client, /deleteSavedVoterCredential: \(path/);
});

test("session-only and memory-only states are truthful", () => {
  assert.equal(
    credentialStorageText(
      credential({
        credential_origin: "ImportedSession",
        session_only: true,
        saved_locally: false,
      }),
    ),
    "Available for this app session only",
  );
  assert.match(
    clearMemoryConfirmationText(
      credential({
        credential_origin: "MemoryOnly",
        session_only: true,
        saved_locally: false,
      }),
      false,
    ),
    /only in memory/,
  );
});

test("saved credential listing never renders absolute paths", () => {
  const types = readProjectFile("src/api/types.ts");
  const card = readProjectFile("src/components/VoterCredentialCard.tsx");
  const summary = types.slice(
    types.indexOf("GuiVoterCredentialFileSummaryV1"),
    types.indexOf("GuiSavedVoterCredentialsV1"),
  );

  assert.doesNotMatch(summary, /\bpath\b|absolute_path/);
  assert.doesNotMatch(card, /credential\.path|absolute_path/);
});

test("visible production flow no longer invokes old session-only generation", () => {
  const vote = readProjectFile("src/screens/Vote.tsx");
  const create = readProjectFile("src/screens/CreateElection.tsx");

  assert.doesNotMatch(vote, /generateVoterGovernanceCredential|generatePendingVoterGovernanceCredential/);
  assert.doesNotMatch(create, /generateVoterGovernanceCredential|generatePendingVoterGovernanceCredential/);
});

test("credential and passphrase state are not written to web storage", () => {
  const card = readProjectFile("src/components/VoterCredentialCard.tsx");
  const state = readProjectFile("src/state/AppState.tsx");

  assert.doesNotMatch(card, /localStorage|sessionStorage/);
  assert.doesNotMatch(state, /credential.*localStorage|passphrase.*localStorage/i);
  assert.doesNotMatch(state, /credential.*sessionStorage|passphrase.*sessionStorage/i);
});

test("canonical ballot question and vote workflow remain wired", () => {
  const vote = readProjectFile("src/screens/Vote.tsx");

  assert.match(vote, /confirmation\.bound\.proposal_question/);
  assert.match(vote, /selectionInstructionText\(selection \?\? confirmation\.bound\)/);
  assert.match(vote, /api\.prepareVoterBallot\(\)/);
  assert.match(vote, /api\.exportPreparedVoterBallot\(path\)/);
});
