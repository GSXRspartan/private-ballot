import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  AnchorBundleError,
  buildBundleFromDesktop,
  canonicalEventTopicFromBindingTopic,
  copyBundleToClipboard,
  parseAnchorBundleJson,
} from "../src/wallet/anchorBundle.ts";
import {
  defaultPublishDriver,
  recoveryWriterFor,
} from "../src/anchor/browserAnchorPublish.ts";
import { pollUntilVerified } from "../src/wallet/verifyPoll.ts";
import { AnchorRecoveryStore } from "../src/wallet/recoveryStore.ts";
import type { RecoveryStorage } from "../src/wallet/recoveryStore.ts";
import { readFileSync } from "node:fs";
import {
  RESULT_JSON_FINALIZED_COMMIT,
  RESULT_JSON_PENDING,
} from "./anchorVectors.generated.ts";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const ESMERALDA_ADDRESS =
  "template_bb539bddc9c264e4744ec462647b076fb97e2bdedb8692ea435804a6eb1eddee";
const ARTIFACT = "ce5334dfc0cdbfe74726accfe7201a778331bf2020865a2fc2b24a68a971d908";
const DIGEST = "67e995cdbc0077967e8ed55ac6f33b6c7df0a369938b4a40bc45e3fe7b2778c7";
const SUMMARY = '{"election_id":"5e50e17c401682fb38dbea349a4c2713"}';

function desktopSource() {
  return {
    network: "esmeralda",
    templateAddress: ESMERALDA_ADDRESS,
    templateArtifactDigestHex: ARTIFACT,
    templateModule: "tari_private_ballot_anchor_v2",
    templateFunction: "publish_anchor_v2",
    preparation: {
      templateEventTopic:
        "tari_private_ballot_anchor_v2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2",
      anchorDigestHex: DIGEST,
      arguments: [DIGEST, "esmeralda", "5e50e17c401682fb38dbea349a4c2713", SUMMARY],
      publicSummaryJson: SUMMARY,
    },
  };
}

describe("desktop bundle composition", () => {
  it("builds a valid bundle from the prepared call and locked deployment", () => {
    const bundle = buildBundleFromDesktop(desktopSource());
    assert.equal(bundle.network, "esmeralda");
    assert.equal(bundle.template.address, ESMERALDA_ADDRESS);
    assert.equal(
      bundle.template.eventTopic,
      "TariPrivateBallotAnchorV2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2",
    );
    assert.deepEqual(bundle.anchorArgs.arguments ?? bundle.anchorArgs, {
      anchorDigestHex: DIGEST,
      network: "esmeralda",
      electionId: "5e50e17c401682fb38dbea349a4c2713",
      publicSummary: SUMMARY,
    });
    assert.doesNotThrow(() => parseAnchorBundleJson(JSON.stringify(bundle)));
  });

  it("rejects preparation whose arguments disagree with the digest or summary", () => {
    const source = desktopSource();
    source.preparation.arguments = [
      "aa".repeat(32),
      "esmeralda",
      "5e50e17c401682fb38dbea349a4c2713",
      SUMMARY,
    ];
    assert.throws(
      () => buildBundleFromDesktop(source),
      (error: unknown) =>
        error instanceof AnchorBundleError && error.reason === "anchor_digest",
    );
  });

  it("rejects an unexpected binding topic suffix", () => {
    assert.throws(
      () => canonicalEventTopicFromBindingTopic("tari_private_ballot_anchor_v2.OTHER"),
      AnchorBundleError,
    );
  });
});

describe("clipboard export", () => {
  it("writes canonical pretty JSON through the clipboard", async () => {
    const written: string[] = [];
    await copyBundleToClipboard(buildBundleFromDesktop(desktopSource()), {
      writeText: async (text) => {
        written.push(text);
      },
    });
    assert.equal(written.length, 1);
    const parsed = JSON.parse(written[0]);
    assert.equal(parsed.schemaVersion, 1);
  });

  it("fails with a bounded message when no clipboard exists", async () => {
    await assert.rejects(
      () => copyBundleToClipboard(buildBundleFromDesktop(desktopSource()), null),
      /clipboard is not available/,
    );
  });
});

describe("verification polling", () => {
  const template = {
    templateAddressHex: "5f1ecbe69b1c6e8b64b97b37f32f6975be4b1e2a1d9c4a5e3f2b6c8d0a9e7f41",
    eventTopic: "TariPrivateBallotAnchorV2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2",
  };
  const payload = {
    anchorDigestHex: DIGEST,
    network: "mainnet",
    electionId: "5e50e17c401682fb38dbea349a4c2713",
    publicSummary:
      '{"election_id":"5e50e17c401682fb38dbea349a4c2713","questions":[{"text":"Adopt the charter?","options":["Yes","No"]}],"ballot_count":10}',
  };

  it("keeps polling while pending and stops at a terminal outcome", async () => {
    let calls = 0;
    const outcome = await pollUntilVerified(
      () => {
        calls += 1;
        if (calls < 3) {
          return Promise.resolve(JSON.parse(RESULT_JSON_PENDING));
        }
        return Promise.resolve(JSON.parse(RESULT_JSON_FINALIZED_COMMIT));
      },
      "9a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b",
      template,
      payload,
      { attempts: 5, intervalMs: 0, sleep: async () => {} },
    );
    assert.equal(outcome.kind, "verified");
    assert.equal(calls, 3);
  });

  it("returns pending after exhausting attempts when the result never settles", async () => {
    let calls = 0;
    const outcome = await pollUntilVerified(
      () => {
        calls += 1;
        return Promise.resolve(JSON.parse(RESULT_JSON_PENDING));
      },
      "aa".repeat(32),
      template,
      payload,
      { attempts: 2, intervalMs: 0, sleep: async () => {} },
    );
    assert.equal(outcome.kind, "pending");
    assert.equal(calls, 2);
  });

  it("treats fetch errors as pending, never as failure", async () => {
    const outcome = await pollUntilVerified(
      () => Promise.reject(new Error("proxy down")),
      "aa".repeat(32),
      template,
      payload,
      { attempts: 2, intervalMs: 0, sleep: async () => {} },
    );
    assert.equal(outcome.kind, "pending");
  });

  it("returns a terminal failure immediately when the chain rejects", async () => {
    let calls = 0;
    const outcome = await pollUntilVerified(
      () => {
        calls += 1;
        return Promise.resolve(JSON.parse('{"result":{"Rejected":{"details":"bad"}}}'));
      },
      "aa".repeat(32),
      template,
      payload,
      { attempts: 5, intervalMs: 0, sleep: async () => {} },
    );
    assert.equal(outcome.kind, "terminal_failure");
    assert.equal(calls, 1);
  });
});

describe("recovery writer", () => {
  function memoryStorage(): RecoveryStorage {
    const map = new Map<string, string>();
    return {
      getItem: (key) => map.get(key) ?? null,
      setItem: (key, value) => {
        map.set(key, value);
      },
      removeItem: (key) => {
        map.delete(key);
      },
    };
  }

  it("persists the request id first and the transaction id after submission", () => {
    const store = new AnchorRecoveryStore(memoryStorage());
    const writer = recoveryWriterFor(store, "bundle-key");
    writer.saveSubmittedAwaitingApproval("req_1");
    const first = store.load("bundle-key");
    assert.equal(first?.phase, "submitted_awaiting_approval");
    assert.equal(first?.requestId, "req_1");
    writer.saveApprovedSubmitted("44".repeat(32));
    const second = store.load("bundle-key");
    assert.equal(second?.phase, "approved_submitted");
    assert.equal(second?.transactionId, "44".repeat(32));
    writer.clear();
    assert.equal(store.load("bundle-key"), null);
  });
});

// -----------------------------------------------------------------------------
// ManageElection surface assertions (source-level, per repo convention).
// -----------------------------------------------------------------------------

const MANAGE = readProjectFile("src/screens/ManageElection.tsx");
const FLAT = MANAGE.replace(/\s+/g, " ");

it("the browser publish panel renders only outside the desktop shell", () => {
  assert.match(FLAT, /!isDesktopShell\(\) && <BrowserAnchorPublishPanel \/>/);
});

it("the desktop bundle export copies verified arguments to the clipboard", () => {
  assert.match(FLAT, /Export browser anchor bundle/);
  assert.match(FLAT, /copyBundleToClipboard/);
  assert.match(FLAT, /buildBundleFromDesktop/);
  assert.match(FLAT, /Save it as a \.json file/);
});

it("the browser panel promises never to recreate or resubmit a transaction", () => {
  const panel = readProjectFile("src/screens/anchor/BrowserAnchorPublishPanel.tsx");
  assert.match(panel, /never recreates or resubmits/);
  assert.doesNotMatch(panel, /localStorage/);
});
