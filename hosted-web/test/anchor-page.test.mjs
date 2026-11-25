import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { JSDOM } from "jsdom";

import {
  ANCHOR_MAX_FEE_CEILING_UNITS,
  ANCHOR_MAX_FEE_UNITS,
  MAINNET_ANCHOR_SUBMISSION_ENABLED,
  buildAnchorBundleFromPayload,
  createGuardedPublishDriver,
  evaluateFeePreflight,
  mountAnchorPanel,
  parseAnchorPayloadResponse,
  submissionDisabledReason,
  submissionGateReason,
} from "../src/anchor.ts";
import { bundleDigestKey, buildBundleFromDesktop } from "../../gui/src/wallet/anchorBundle.ts";
import { browserRecoveryStore, newRecoveryOwnerToken } from "../../gui/src/wallet/recoveryStore.ts";
import {
  MAINNET_V2_ARTIFACT_DIGEST_HEX,
  MAINNET_V2_TEMPLATE_ADDRESS,
  V2_EVENT_TOPIC_SUFFIX,
  v2CanonicalReceiptTopic,
} from "../../gui/src/wallet/anchorDeploymentConfig.ts";
import { verifyV2AnchorTransaction } from "../../gui/src/wallet/verifyReceipt.ts";

const ELECTION_A = "election-a";
const ARCHIVE = "22".repeat(32);
const DIGEST = "67".repeat(32);
const TEMPLATE = MAINNET_V2_TEMPLATE_ADDRESS;
const ARTIFACT = MAINNET_V2_ARTIFACT_DIGEST_HEX;
const BINDING_TOPIC = `tari_private_ballot_anchor_v2.${V2_EVENT_TOPIC_SUFFIX}`;
const RECEIPT_TOPIC = v2CanonicalReceiptTopic();
const REQUEST_ID = "request-1";
const TRANSACTION_ID = "ab".repeat(32);

function canonicalSummary({
  network = "mainnet",
  electionId = ELECTION_A,
  archiveHash = ARCHIVE,
  templateAddress = TEMPLATE,
  artifactDigest = ARTIFACT,
} = {}) {
  return JSON.stringify({
    schema: "TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_PUBLIC_V2",
    version: 2,
    network,
    election_id: electionId,
    question: "Adopt?",
    eligible_voters: 2,
    accepted_ballots: 2,
    rejected_ballots: 0,
    results: [{ label: "Yes", machine_id: "01", votes: 2 }],
    ballot_kind: "approval",
    confidentiality_mode: "aggregate",
    proof_suite: "triptych-v1",
    manifest_hash: "11".repeat(32),
    archive_hash: archiveHash,
    voter_registry_commitment: "33".repeat(32),
    ballot_option_commitment: "44".repeat(32),
    archive_finalized: true,
    finalized_timestamp_unix_secs: null,
    template_address: templateAddress,
    template_module: "tari_private_ballot_anchor_v2",
    template_function: "publish_anchor_v2",
    template_event_topic: BINDING_TOPIC,
    template_artifact_digest: artifactDigest,
  });
}

/** One canonical `/anchor-payload` response, as the Rust endpoint returns it. */
function payloadFixture({
  network = "mainnet",
  electionId = ELECTION_A,
  archiveHash = ARCHIVE,
  digest = DIGEST,
  templateAddress = TEMPLATE,
  templateModule = "tari_private_ballot_anchor_v2",
  templateFunction = "publish_anchor_v2",
  templateEventTopic = BINDING_TOPIC,
  artifactDigest = ARTIFACT,
  publicSummary = canonicalSummary({ network, electionId, archiveHash, templateAddress, artifactDigest }),
} = {}) {
  return {
    election_id: electionId,
    archive_hash_hex: archiveHash,
    v2_anchor_digest_hex: digest,
    payload_hex: Buffer.from(publicSummary, "utf8").toString("hex"),
    public_summary_json: publicSummary,
    network,
    template_address: templateAddress,
    template_module: templateModule,
    template_function: templateFunction,
    template_event_topic: templateEventTopic,
    template_artifact_digest_hex: artifactDigest,
    anchor_args: {
      anchor_digest_hex: digest,
      network,
      election_id: electionId,
      public_summary: publicSummary,
    },
  };
}

class RecordingStorage {
  constructor() {
    this.values = new Map();
  }

  getItem(key) {
    return this.values.get(key) ?? null;
  }

  setItem(key, value) {
    this.values.set(key, value);
  }

  removeItem(key) {
    this.values.delete(key);
  }
}

class ExclusiveLocks {
  constructor() {
    this.held = new Set();
  }

  async request(name, _options, callback) {
    if (this.held.has(name)) return callback(null);
    this.held.add(name);
    try {
      return await callback({ name });
    } finally {
      this.held.delete(name);
    }
  }
}

class FakeWallet {
  constructor({ network = "mainnet", result = { Rejected: { details: "inert test wallet" } }, dryRunResult = { finalize: { total_fees_required: "1000", result: { Accept: {} } } }, dryRunError = null, dryRunIsLocal = true } = {}) {
    this.isTariWallet = true;
    this.accounts = ["account-a"];
    this.network = network;
    this.result = result;
    this.listeners = [];
    this.createCalls = [];
    this.submitCalls = 0;
    this.signAndSubmitCalls = [];
    this.dryRunResult = dryRunResult;
    this.dryRunError = dryRunError;
    this.dryRunIsLocal = dryRunIsLocal;
    this.status = "approved";
    this.callOrder = [];
  }

  on(event, listener) {
    if (event === "accountsChanged") this.listeners.push(listener);
  }

  async request({ method, params }) {
    this.callOrder.push(method);
    switch (method) {
      case "tari_requestAccounts":
        return this.accounts;
      case "tari_getAccounts":
        return this.accounts;
      case "tari_getCapabilities":
        return { transactionRequests: true, transactionResultLookup: true, dryRunIsLocal: this.dryRunIsLocal };
      case "tari_getNetwork":
        return this.network;
      case "tari_createTransactionRequest":
        this.createCalls.push(params);
        return { requestId: REQUEST_ID };
      case "tari_getTransactionRequest":
        return { status: this.status, result: undefined };
      case "tari_submitTransactionRequest":
        this.submitCalls += 1;
        return { transactionId: TRANSACTION_ID };
      case "tari_signAndSubmitTransaction":
        this.signAndSubmitCalls.push(params);
        if (this.dryRunError) throw this.dryRunError;
        return { result: this.dryRunResult };
      case "tari_getTransactionResult":
        return { result: this.result };
      default:
        throw new Error(`unexpected wallet method ${method}`);
    }
  }
}

function defaultFetch(payload = payloadFixture()) {
  return async (input) => {
    const url = new URL(String(input), "https://hosted.example");
    if (url.pathname.endsWith("/anchor-payload")) {
      return { ok: true, status: 200, json: async () => payload };
    }
    if (url.pathname === "/chain/network") {
      return { ok: true, status: 200, json: async () => ({ network: "mainnet", network_byte: 0 }) };
    }
    return { ok: false, status: 404, json: async () => null };
  };
}

function installDom({ wallet = null, fetchImpl = defaultFetch() } = {}) {
  const dom = new JSDOM("<!doctype html><html><body></body></html>", {
    url: "https://hosted.example/anchor",
  });
  const storage = new RecordingStorage();
  const locks = new ExclusiveLocks();
  const previous = new Map();
  const globals = {
    window: dom.window,
    document: dom.window.document,
    navigator: { locks },
    localStorage: storage,
    Event: dom.window.Event,
    HTMLElement: dom.window.HTMLElement,
    fetch: fetchImpl,
  };
  for (const [name, value] of Object.entries(globals)) {
    previous.set(name, Object.getOwnPropertyDescriptor(globalThis, name));
    Object.defineProperty(globalThis, name, { configurable: true, writable: true, value });
  }
  if (wallet) {
    Object.defineProperty(dom.window, "tari", { configurable: true, writable: true, value: wallet });
  }
  return {
    dom,
    storage,
    locks,
    restore() {
      for (const [name, descriptor] of previous.entries()) {
        if (descriptor) Object.defineProperty(globalThis, name, descriptor);
        else delete globalThis[name];
      }
    },
  };
}

function mountInto(dom) {
  const root = dom.window.document.createElement("div");
  dom.window.document.body.append(root);
  mountAnchorPanel(root);
  return root;
}

function byId(root, id) {
  const node = root.querySelector(`#${id}`);
  assert.ok(node, `expected #${id} to be rendered`);
  return node;
}

function findButton(root, label) {
  return [...root.querySelectorAll("button")].find((candidate) => candidate.textContent === label);
}

function button(root, label) {
  const node = findButton(root, label);
  assert.ok(node, `expected a "${label}" button`);
  return node;
}

function statusText(root) {
  return root.querySelector('[role="status"]')?.textContent ?? "";
}

async function click(node) {
  node.dispatchEvent(new node.ownerDocument.defaultView.Event("click"));
  // Let the async handler settle.
  await new Promise((resolve) => setTimeout(resolve, 0));
  await new Promise((resolve) => setTimeout(resolve, 0));
}

async function waitFor(predicate, message, timeoutMs = 2000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  assert.ok(predicate(), message);
}

test("the anchor module mounts into #app on load", async () => {
  const dom = new JSDOM('<!doctype html><html><body><div id="app"></div></body></html>', {
    url: "https://hosted.example/anchor",
  });
  const previous = new Map();
  const globals = {
    window: dom.window,
    document: dom.window.document,
    navigator: { locks: new ExclusiveLocks() },
    localStorage: new RecordingStorage(),
    Event: dom.window.Event,
    HTMLElement: dom.window.HTMLElement,
    fetch: defaultFetch(),
  };
  for (const [name, value] of Object.entries(globals)) {
    previous.set(name, Object.getOwnPropertyDescriptor(globalThis, name));
    Object.defineProperty(globalThis, name, { configurable: true, writable: true, value });
  }
  try {
    await import(`../src/anchor.ts?entrypoint=${Date.now()}`);
    const app = dom.window.document.getElementById("app");
    assert.ok(app?.textContent?.includes("Tari Mainnet Anchor"), "the entrypoint must render into #app");
  } finally {
    for (const [name, descriptor] of previous.entries()) {
      if (descriptor) Object.defineProperty(globalThis, name, descriptor);
      else delete globalThis[name];
    }
  }
});

test("the anchor page renders the required controls", () => {
  const env = installDom();
  try {
    const root = mountInto(env.dom);
    assert.ok(root.textContent.includes("Tari Mainnet Anchor"));
    assert.ok(byId(root, "election-id-input"));
    assert.ok(byId(root, "load-election-btn"));
    assert.ok(button(root, "Connect Sapient"));
    assert.ok(button(root, "Connect Tari Universe"));
    assert.ok(root.textContent.includes(`Maximum authorized fee: 0.005 TARI (${ANCHOR_MAX_FEE_UNITS} µT)`));
    assert.ok(root.textContent.includes(`Release fee ceiling: 10 TARI (${ANCHOR_MAX_FEE_CEILING_UNITS} µT)`));
    assert.ok(root.textContent.includes("Mainnet network status: no wallet connected."));
    assert.ok(root.textContent.includes("Wallet approval: required"));
  } finally {
    env.restore();
  }
});

test("loading a payload renders the canonical anchor preview", async () => {
  const env = installDom();
  try {
    const root = mountInto(env.dom);
    byId(root, "election-id-input").value = ELECTION_A;
    await click(byId(root, "load-election-btn"));
    assert.ok(root.textContent.includes(ELECTION_A), "the election id must be shown");
    assert.ok(root.textContent.includes(ARCHIVE.slice(0, 16)), "the archive identity must be shown");
    assert.ok(root.textContent.includes(DIGEST.slice(0, 16)), "the anchor digest must be shown");
    assert.equal(root.textContent.includes("does not match the current trusted anchor deployment"), false);
  } finally {
    env.restore();
  }
});

test("a payload for a different election is rejected even when internally consistent", async () => {
  const env = installDom({ fetchImpl: recordingFetch(payloadFixture({ electionId: "election-b" })).impl });
  try {
    const root = mountInto(env.dom);
    byId(root, "election-id-input").value = ELECTION_A;
    await click(byId(root, "load-election-btn"));
    assert.match(root.textContent, /returned a payload for a different election/);
    assert.doesNotMatch(root.textContent, /Loaded election election-b/);
  } finally {
    env.restore();
  }
});

test("the server error code is surfaced when the payload is rejected", async () => {
  const env = installDom({
    fetchImpl: async () => ({
      ok: false,
      status: 409,
      json: async () => ({ code: "anchor_privacy_floor_not_met", message: "cohort too small" }),
    }),
  });
  try {
    const root = mountInto(env.dom);
    byId(root, "election-id-input").value = ELECTION_A;
    await click(byId(root, "load-election-btn"));
    assert.match(root.textContent, /cohort too small/);
    assert.match(root.textContent, /anchor_privacy_floor_not_met/);
  } finally {
    env.restore();
  }
});

test("the bundle event topic is canonicalized to the receipt topic", () => {
  const payload = payloadFixture();
  const bundle = buildAnchorBundleFromPayload(payload);
  // The server sends the lowercase module-prefixed binding topic.
  assert.equal(payload.template_event_topic, BINDING_TOPIC);
  // The browser must verify against the topic actually emitted on chain.
  assert.equal(bundle.template.eventTopic, RECEIPT_TOPIC);
  assert.equal(bundle.template.eventTopic, `TariPrivateBallotAnchorV2.${V2_EVENT_TOPIC_SUFFIX}`);
});

test("the Hosted browser bundle is byte-identical to the Desktop preparation", () => {
  const payload = payloadFixture();
  const hosted = buildAnchorBundleFromPayload(payload);
  const desktop = buildBundleFromDesktop({
    network: payload.network,
    templateAddress: payload.template_address,
    templateArtifactDigestHex: payload.template_artifact_digest_hex,
    templateModule: payload.template_module,
    templateFunction: payload.template_function,
    preparation: {
      // The Rust preparation returns the module-prefixed binding topic.
      templateEventTopic: payload.template_event_topic,
      anchorDigestHex: payload.anchor_args.anchor_digest_hex,
      arguments: [
        payload.anchor_args.anchor_digest_hex,
        payload.anchor_args.network,
        payload.anchor_args.election_id,
        payload.anchor_args.public_summary,
      ],
      publicSummaryJson: payload.anchor_args.public_summary,
    },
  });
  assert.deepEqual(hosted, desktop);
  // The server's snake_case anchor_args must map onto the bundle's camelCase
  // arguments exactly.
  assert.deepEqual(
    { ...hosted.anchorArgs },
    {
      anchorDigestHex: payload.anchor_args.anchor_digest_hex,
      network: payload.anchor_args.network,
      electionId: payload.anchor_args.election_id,
      publicSummary: payload.anchor_args.public_summary,
    },
  );
});

test("a wrong template address is rejected before any wallet connection", async () => {
  const payload = payloadFixture({
    templateAddress: `template_${"cd".repeat(32)}`,
    publicSummary: canonicalSummary({ templateAddress: `template_${"cd".repeat(32)}` }),
  });
  const env = installDom({ fetchImpl: defaultFetch(payload) });
  try {
    const root = mountInto(env.dom);
    byId(root, "election-id-input").value = ELECTION_A;
    await click(byId(root, "load-election-btn"));
    assert.match(root.textContent, /does not match the current trusted anchor deployment/);
    assert.equal(button(root, "Connect Sapient").disabled, true);
    assert.equal(button(root, "Connect Tari Universe").disabled, true);
  } finally {
    env.restore();
  }
});

test("a wrong template artifact digest is rejected before any wallet connection", async () => {
  const payload = payloadFixture({
    artifactDigest: "cd".repeat(32),
    publicSummary: canonicalSummary({ artifactDigest: "cd".repeat(32) }),
  });
  const env = installDom({ fetchImpl: defaultFetch(payload) });
  try {
    const root = mountInto(env.dom);
    byId(root, "election-id-input").value = ELECTION_A;
    await click(byId(root, "load-election-btn"));
    assert.match(root.textContent, /does not match the current trusted anchor deployment/);
    assert.equal(button(root, "Connect Sapient").disabled, true);
  } finally {
    env.restore();
  }
});

test("a non-Mainnet payload network has no deployment and is rejected", async () => {
  const payload = payloadFixture({
    network: "esmeralda",
    publicSummary: canonicalSummary({ network: "esmeralda" }),
  });
  const env = installDom({ fetchImpl: defaultFetch(payload) });
  try {
    const root = mountInto(env.dom);
    byId(root, "election-id-input").value = ELECTION_A;
    await click(byId(root, "load-election-btn"));
    assert.match(root.textContent, /No current anchor deployment is configured/);
    assert.equal(button(root, "Connect Sapient").disabled, true);
  } finally {
    env.restore();
  }
});

test("a non-Mainnet wallet is rejected at connect time", async () => {
  const wallet = new FakeWallet({ network: "esmeralda" });
  const env = installDom({ wallet });
  try {
    const root = mountInto(env.dom);
    byId(root, "election-id-input").value = ELECTION_A;
    await click(byId(root, "load-election-btn"));
    await click(button(root, "Connect Sapient"));
    assert.match(statusText(root), /requires a Mainnet wallet/);
    assert.equal(wallet.createCalls.length, 0, "no request may be created for a non-Mainnet wallet");
  } finally {
    env.restore();
  }
});

test("Mainnet submission is enabled only by the reviewed build-time constant", () => {
  assert.equal(MAINNET_ANCHOR_SUBMISSION_ENABLED, true);
  assert.equal(submissionDisabledReason(), null);
  assert.equal(submissionGateReason(true), null);
  const disabled = submissionGateReason(false);
  assert.ok(typeof disabled === "string" && disabled.length > 0);
  assert.match(disabled, /Mainnet publishing not yet enabled/);
});

test("the submission gate is a build-time constant with no runtime bypass", () => {
  const src = readFileSync(new URL("../src/anchorSubmissionPolicy.ts", import.meta.url), "utf8");
  // The gate is a literal constant, not a mutable object or a resolved flag.
  assert.match(src, /export const MAINNET_ANCHOR_SUBMISSION_ENABLED = true/);
  // No mutable policy object that a runtime path could flip.
  assert.doesNotMatch(src, /ANCHOR_SUBMISSION_POLICY/);
  assert.doesNotMatch(src, /mainnetEnabled\s*=/);
  // No storage/config/localStorage read that could enable submission.
  assert.doesNotMatch(src, /localStorage|sessionStorage|import\.meta\.env/);
});

test("a disabled build's guarded driver cannot create, await approval, or submit", () => {
  const calls = [];
  const base = {
    connect: async () => [],
    createRequest: async () => {
      calls.push("create");
      return "request-1";
    },
    estimateFee: async () => ({ kind: "unsupported", reason: "not used" }),
    waitForApproval: async () => {
      calls.push("approval");
      return { status: "approved" };
    },
    submit: async () => {
      calls.push("submit");
      return TRANSACTION_ID;
    },
    verify: async () => ({ kind: "pending" }),
  };
  const guarded = createGuardedPublishDriver(base, false);
  assert.throws(() => guarded.createRequest({}, {}, ANCHOR_MAX_FEE_UNITS), /not yet enabled/);
  assert.throws(() => guarded.waitForApproval({}, "request-1", 1000), /not yet enabled/);
  assert.throws(() => guarded.submit({}, "request-1"), /not yet enabled/);
  assert.deepEqual(calls, [], "the disabled gate must fail before any base driver call");
});

test("an enabled guarded driver delegates to the base driver", async () => {
  const calls = [];
  const base = {
    connect: async () => [],
    createRequest: async () => {
      calls.push("create");
      return "request-1";
    },
    estimateFee: async () => ({ kind: "unsupported", reason: "not used" }),
    waitForApproval: async () => {
      calls.push("approval");
      return { status: "approved" };
    },
    submit: async () => {
      calls.push("submit");
      return TRANSACTION_ID;
    },
    verify: async () => ({ kind: "pending" }),
  };
  const guarded = createGuardedPublishDriver(base, true);
  assert.equal(await guarded.createRequest({}, {}, ANCHOR_MAX_FEE_UNITS), "request-1");
  assert.equal((await guarded.waitForApproval({}, "request-1", 1000)).status, "approved");
  assert.equal(await guarded.submit({}, "request-1"), TRANSACTION_ID);
  assert.deepEqual(calls, ["create", "approval", "submit"]);
});

test("the Sapient publish path runs a fresh fee preflight before creating and submitting", async () => {
  const wallet = new FakeWallet({
    dryRunResult: { finalize: { total_fees_required: "3477", result: { Accept: {} } } },
  });
  const env = installDom({ wallet });
  try {
    const root = mountInto(env.dom);
    byId(root, "election-id-input").value = ELECTION_A;
    await click(byId(root, "load-election-btn"));
    await click(button(root, "Connect Sapient"));
    assert.match(statusText(root), /Sapient connected on mainnet/);

    const publishButton = button(root, "Ask wallet to publish anchor");
    await click(publishButton);
    await waitFor(() => wallet.submitCalls === 1, "publish never reached wallet submit");

    assert.equal(wallet.signAndSubmitCalls.length, 1, "one mandatory dry run per publish attempt");
    assert.equal(wallet.signAndSubmitCalls[0].dryRun, true);
    assert.equal(wallet.signAndSubmitCalls[0].maxFee, String(ANCHOR_MAX_FEE_UNITS));
    assert.equal(wallet.createCalls.length, 1, "one request after the preflight");
    assert.equal(wallet.submitCalls, 1, "one submission after approval");
    assert.ok(
      wallet.callOrder.indexOf("tari_signAndSubmitTransaction") <
        wallet.callOrder.indexOf("tari_createTransactionRequest"),
      "the dry run must precede request creation",
    );
    assert.ok(root.textContent.includes("Estimated transaction fee: 0.003477 TARI"));
  } finally {
    env.restore();
  }
});

test("publishing is blocked if the reduced-anonymity acknowledgement changed after load", async () => {
  const wallet = new FakeWallet({
    dryRunResult: { finalize: { total_fees_required: "3477", result: { Accept: {} } } },
  });
  const env = installDom({ wallet });
  try {
    const root = mountInto(env.dom);
    byId(root, "election-id-input").value = ELECTION_A;
    await click(byId(root, "load-election-btn"));
    await click(button(root, "Connect Sapient"));
    const ack = byId(root, "ack-reduced-anonymity");
    ack.checked = true;
    ack.dispatchEvent(new env.dom.window.Event("change"));
    await click(button(root, "Ask wallet to publish anchor"));
    await waitFor(() => /acknowledgement changed/i.test(statusText(root)), "acknowledgement mismatch not blocked");
    assert.equal(wallet.signAndSubmitCalls.length, 0, "the preflight must not run after the acknowledgement changed");
    assert.equal(wallet.createCalls.length, 0, "no request may be created after the acknowledgement changed");
  } finally {
    env.restore();
  }
});

test("the Web Tari Universe path distinguishes a rejected approval without submitting", async () => {
  const wallet = new FakeWallet();
  wallet.status = "rejected";
  wallet.isEmbedded = true;
  wallet.info = { rdns: "mw.tari.universe", name: "Tari Universe" };
  const env = installDom({ wallet });
  try {
    const root = mountInto(env.dom);
    byId(root, "election-id-input").value = ELECTION_A;
    await click(byId(root, "load-election-btn"));
    await click(button(root, "Connect Tari Universe"));
    assert.match(statusText(root), /Tari Universe connected on mainnet/);

    await click(button(root, "Ask wallet to publish anchor"));
    await waitFor(() => wallet.createCalls.length === 1, "publish never created a request");
    await waitFor(() => /rejected/i.test(statusText(root)), "rejection status not shown");
    assert.equal(wallet.signAndSubmitCalls.length, 1);
    assert.equal(wallet.submitCalls, 0, "a rejected request must never be submitted");
  } finally {
    env.restore();
  }
});

test("recovery paths never create or submit while Mainnet submission is disabled", async () => {
  const wallet = new FakeWallet();
  const env = installDom({ wallet });
  try {
    // Seed a saved request exactly as a prior session would have left it.
    const payload = payloadFixture();
    const bundle = buildAnchorBundleFromPayload(payload);
    const key = bundleDigestKey(bundle);
    const token = newRecoveryOwnerToken();
    browserRecoveryStore().save(key, {
      phase: "submitted_awaiting_approval",
      requestId: "request-saved-1",
      transactionId: null,
      ownerToken: token,
      leaseExpiresAtMs: Date.now() - 1000,
      updatedAtMs: Date.now() - 60_000,
    });

    const root = mountInto(env.dom);
    byId(root, "election-id-input").value = ELECTION_A;
    await click(byId(root, "load-election-btn"));
    await click(button(root, "Connect Sapient"));
    await click(button(root, "Check saved request / transaction"));

    assert.equal(wallet.createCalls.length, 0, "recovery must not create a new request");
    assert.equal(wallet.submitCalls, 0, "recovery must never submit");
    assert.match(statusText(root), /approved|not be submitted|pending|remain/i);
  } finally {
    env.restore();
  }
});

test("a saved transaction is verified but never resubmitted while disabled", async () => {
  const wallet = new FakeWallet();
  const env = installDom({ wallet });
  try {
    const payload = payloadFixture();
    const bundle = buildAnchorBundleFromPayload(payload);
    const key = bundleDigestKey(bundle);
    const token = newRecoveryOwnerToken();
    browserRecoveryStore().save(key, {
      phase: "approved_submitted",
      requestId: null,
      transactionId: TRANSACTION_ID,
      ownerToken: token,
      leaseExpiresAtMs: Date.now() + 5 * 60 * 1000,
      updatedAtMs: Date.now(),
    });

    const root = mountInto(env.dom);
    byId(root, "election-id-input").value = ELECTION_A;
    await click(byId(root, "load-election-btn"));
    await click(button(root, "Connect Sapient"));
    await click(button(root, "Check saved request / transaction"));

    assert.equal(wallet.createCalls.length, 0);
    assert.equal(wallet.submitCalls, 0, "a saved transaction must never be resubmitted");
    assert.doesNotMatch(statusText(root), /submitted again|retried/i);
  } finally {
    env.restore();
  }
});

test("Web Tari Universe embedded provider is accepted", async () => {
  const wallet = new FakeWallet();
  wallet.isEmbedded = true;
  wallet.info = { rdns: "mw.tari.universe", name: "Tari Universe" };
  const env = installDom({ wallet });
  try {
    const root = mountInto(env.dom);
    byId(root, "election-id-input").value = ELECTION_A;
    await click(byId(root, "load-election-btn"));
    await click(button(root, "Connect Tari Universe"));
    assert.match(statusText(root), /Tari Universe connected on mainnet/);
  } finally {
    env.restore();
  }
});

test("the publish action appears only after the payload and a Mainnet wallet are ready", async () => {
  const wallet = new FakeWallet();
  const env = installDom({ wallet });
  try {
    const root = mountInto(env.dom);
    assert.equal(findButton(root, "Ask wallet to publish anchor"), undefined);

    byId(root, "election-id-input").value = ELECTION_A;
    await click(byId(root, "load-election-btn"));
    assert.equal(findButton(root, "Ask wallet to publish anchor"), undefined, "no wallet yet");

    await click(button(root, "Connect Sapient"));
    assert.ok(findButton(root, "Ask wallet to publish anchor"), "publish is offered after connection");
    assert.equal(wallet.createCalls.length, 0, "rendering the action must not create a request");
    assert.equal(wallet.submitCalls, 0, "rendering the action must not submit");
  } finally {
    env.restore();
  }
});

test("a pending result is distinguished from final evidence", () => {
  const outcome = verifyV2AnchorTransaction(TRANSACTION_ID, { templateAddressHex: TEMPLATE.slice("template_".length), eventTopic: RECEIPT_TOPIC }, { anchorDigestHex: DIGEST, network: "mainnet", electionId: ELECTION_A, publicSummary: canonicalSummary() }, { result: "Pending" });
  assert.equal(outcome.kind, "pending");
});

test("the response parser rejects incomplete and non-canonical payloads", () => {
  const payload = payloadFixture();
  assert.ok(parseAnchorPayloadResponse(payload));
  assert.equal(parseAnchorPayloadResponse({ ...payload, archive_hash_hex: undefined }), null);
  assert.equal(parseAnchorPayloadResponse({ ...payload, v2_anchor_digest_hex: "zz" }), null);
  assert.equal(parseAnchorPayloadResponse({ ...payload, anchor_args: { ...payload.anchor_args, network: 7 } }), null);
  assert.equal(parseAnchorPayloadResponse(null), null);
});

test("the fee cap constant never exceeds the release ceiling", () => {
  assert.ok(Number.isInteger(ANCHOR_MAX_FEE_UNITS));
  assert.ok(ANCHOR_MAX_FEE_UNITS >= 1);
  assert.ok(ANCHOR_MAX_FEE_UNITS <= ANCHOR_MAX_FEE_CEILING_UNITS);
  // Sapient Mainnet dry-run evidence: total_fees_required = 3477 µT; with the
  // 12 µT allowance the recommended max_fee is 3489 µT. The cap must exceed it.
  assert.equal(ANCHOR_MAX_FEE_UNITS, 5000);
  assert.ok(ANCHOR_MAX_FEE_UNITS > 3477 + 12, "cap must exceed the allowance-adjusted real fee");
  assert.equal(ANCHOR_MAX_FEE_CEILING_UNITS, 10_000_000);
});

test("the worker allowlist covers the anchor document for Universe embedding", () => {
  const worker = readFileSync(new URL("../src-edge/worker.ts", import.meta.url), "utf8");
  assert.match(worker, /"\/anchor"/);
  assert.match(worker, /"\/anchor\.html"/);
});

// ---------- HTML injection / XSS regression ----------

const XSS_PAYLOADS = [
  `<script>alert(1)</script>`,
  `<img src=x onerror=alert(1)>`,
  `" onfocus="alert(1)`,
  `&lt;svg onload=alert(1)&gt;`,
  `&<>"'`,
];

/** Fails when any active/injected element or event handler made it into the DOM. */
function assertInert(root, message) {
  for (const tag of ["script", "img", "svg", "iframe", "object", "embed", "link", "style"]) {
    assert.equal(root.querySelector(tag), null, `${message}: unexpected <${tag}> element`);
  }
  for (const node of root.querySelectorAll("*")) {
    for (const attr of node.getAttributeNames()) {
      assert.doesNotMatch(attr, /^on/i, `${message}: unexpected event handler attribute ${attr}`);
    }
  }
  assert.equal(root.querySelectorAll("script").length, 0, message);
}

function recordingFetch(payload) {
  const calls = [];
  const impl = async (input) => {
    const url = new URL(String(input), "https://hosted.example");
    calls.push(url);
    if (url.pathname.endsWith("/anchor-payload")) {
      return { ok: true, status: 200, json: async () => payload };
    }
    if (url.pathname === "/chain/network") {
      return { ok: true, status: 200, json: async () => ({ network: "mainnet", network_byte: 0 }) };
    }
    return { ok: false, status: 404, json: async () => null };
  };
  return { calls, impl };
}

test("a hostile election id typed by the user renders inert", async () => {
  for (const hostile of XSS_PAYLOADS) {
    const { impl } = recordingFetch(payloadFixture());
    const env = installDom({ fetchImpl: impl });
    try {
      const root = mountInto(env.dom);
      byId(root, "election-id-input").value = hostile;
      await click(byId(root, "load-election-btn"));
      // The typed value is echoed back through the re-rendered input.
      assert.equal(byId(root, "election-id-input").value, hostile, "typed value must be preserved verbatim");
      assertInert(root, `hostile election id ${JSON.stringify(hostile)}`);
    } finally {
      env.restore();
    }
  }
});

test("a server-supplied election id for a different election is rejected", async () => {
  for (const hostile of XSS_PAYLOADS) {
    const payload = payloadFixture({ electionId: hostile.slice(0, 128) });
    const { impl } = recordingFetch(payload);
    const env = installDom({ fetchImpl: impl });
    try {
      const root = mountInto(env.dom);
      byId(root, "election-id-input").value = ELECTION_A;
      await click(byId(root, "load-election-btn"));
      assert.match(root.textContent, /returned a payload for a different election/);
      assert.doesNotMatch(root.textContent, /Loaded election/);
      assertInert(root, `hostile server election id ${JSON.stringify(hostile)}`);
    } finally {
      env.restore();
    }
  }
});

test("a hostile server error message renders inert text", async () => {
  const hostileMessage = `<img src=x onerror=window.__xss=1><script>alert(1)</script>`;
  const env = installDom({
    fetchImpl: async () => ({
      ok: false,
      status: 409,
      json: async () => ({ code: `anchor_rate_limited`, message: hostileMessage }),
    }),
  });
  try {
    const root = mountInto(env.dom);
    byId(root, "election-id-input").value = ELECTION_A;
    await click(byId(root, "load-election-btn"));
    assertInert(root, "hostile server error message");
    // textContent display keeps the raw string readable but inert.
    assert.ok(root.textContent.includes(hostileMessage), "the message must be shown as text");
  } finally {
    env.restore();
  }
});

test("malicious fetch input never reaches a third-party URL", async () => {
  const hostile = `<script>alert(1)</script>`;
  const { calls, impl } = recordingFetch(payloadFixture());
  const env = installDom({ fetchImpl: impl });
  try {
    const root = mountInto(env.dom);
    byId(root, "election-id-input").value = hostile;
    await click(byId(root, "load-election-btn"));
    for (const url of calls) {
      assert.equal(url.origin, "https://hosted.example", "only same-origin requests are allowed");
      assert.match(url.pathname, /^\/(api\/v1\/elections\/[^/]+\/anchor-payload|chain\/network)$/, "only documented routes are fetched");
    }
    assertInert(root, "hostile fetch input");
  } finally {
    env.restore();
  }
});

test("normal election metadata still renders after the escaping fix", async () => {
  const payload = payloadFixture();
  const { impl } = recordingFetch(payload);
  const env = installDom({ fetchImpl: impl });
  try {
    const root = mountInto(env.dom);
    byId(root, "election-id-input").value = ELECTION_A;
    await click(byId(root, "load-election-btn"));
    assert.ok(root.textContent.includes(ELECTION_A));
    assert.ok(root.textContent.includes(ARCHIVE.slice(0, 16)));
    assert.ok(root.textContent.includes(DIGEST.slice(0, 16)));
    assertInert(root, "normal payload");
  } finally {
    env.restore();
  }
});

// -----------------------------------------------------------------------------
// Non-spending Mainnet fee preflight (Estimate Mainnet Fee).
// -----------------------------------------------------------------------------

test("the anchor page offers Estimate Mainnet Fee once a wallet is connected, and it never submits", async () => {
  // Real Sapient Mainnet dry-run: total_fees_required = 3477 µT (0.003477 TARI).
  const wallet = new FakeWallet({ dryRunResult: { finalize: { total_fees_required: "3477", result: { Accept: {} } } } });
  const env = installDom({ wallet });
  try {
    const root = mountInto(env.dom);
    byId(root, "election-id-input").value = ELECTION_A;
    await click(byId(root, "load-election-btn"));
    await click(button(root, "Connect Sapient"));

    // Publishing is available, but this test only exercises the manual quote.
    assert.ok(findButton(root, "Ask wallet to publish anchor"));

    // The estimate action is present.
    const estimateBtn = button(root, "Estimate Mainnet Fee");
    await click(estimateBtn);

    // A dry-run signAndSubmit was issued with dryRun:true and a decimal-string cap.
    assert.equal(wallet.signAndSubmitCalls.length, 1);
    const params = wallet.signAndSubmitCalls[0];
    assert.equal(params.dryRun, true);
    assert.equal(params.maxFee, String(ANCHOR_MAX_FEE_UNITS));
    assert.equal(params.maxFee, "5000");
    // No approval or submission path was touched.
    assert.equal(wallet.createCalls.length, 0, "estimate must not create a transaction request");
    assert.equal(wallet.submitCalls, 0, "estimate must not submit");

    // The estimate is displayed in TARI as the primary denomination.
    const text = root.textContent;
    assert.ok(text.includes("Estimated transaction fee: 0.003477 TARI"), "TARI estimate shown");
    // Allowance-adjusted minimum = 3477 + 12 = 3489 µT = 0.003489 TARI.
    assert.ok(text.includes("Allowance-adjusted minimum: 0.003489 TARI"), "allowance-adjusted minimum shown");
    assert.ok(text.includes("Maximum authorized fee: 0.005 TARI"), "maximum authorized fee shown");
    assert.ok(text.includes("Release fee ceiling: 10 TARI"), "release ceiling shown");
    assert.ok(text.includes("does not prove a funded transaction will succeed"), "honest caveat shown");
  } finally {
    env.restore();
  }
});

test("estimate warns when the estimated fee exceeds the maximum authorized fee", async () => {
  // 999,999,999 µT = 999.999999 TARI, far above the 0.005 TARI cap.
  const wallet = new FakeWallet({ dryRunResult: { finalize: { total_fees_required: "999999999", result: { Accept: {} } } } });
  const env = installDom({ wallet });
  try {
    const root = mountInto(env.dom);
    byId(root, "election-id-input").value = ELECTION_A;
    await click(byId(root, "load-election-btn"));
    await click(button(root, "Connect Sapient"));
    await click(button(root, "Estimate Mainnet Fee"));
    const text = root.textContent;
    assert.ok(text.includes("exceeds the maximum authorized fee"), "over-cap warning shown");
    assert.ok(text.includes("No transaction request will be created"), "no request created on over-cap");
    assert.ok(findButton(root, "Ask wallet to publish anchor"), "publish remains available for a fresh attempt");
    assert.equal(wallet.createCalls.length, 0);
  } finally {
    env.restore();
  }
});

test("estimate displays Fee estimate unavailable when the wallet exposes no fee field", async () => {
  const wallet = new FakeWallet({ dryRunResult: { finalize: { result: { Accept: {} } } } });
  const env = installDom({ wallet });
  try {
    const root = mountInto(env.dom);
    byId(root, "election-id-input").value = ELECTION_A;
    await click(byId(root, "load-election-btn"));
    await click(button(root, "Connect Sapient"));
    await click(button(root, "Estimate Mainnet Fee"));
    const text = root.textContent;
    assert.ok(/Fee estimate unavailable/i.test(text), "unsupported shown honestly");
    assert.equal(wallet.createCalls.length, 0);
    assert.equal(wallet.submitCalls, 0);
  } finally {
    env.restore();
  }
});

test("estimate fails closed on a provider rejection and never submits", async () => {
  const rejection = new Error("user rejected");
  rejection.code = 4001;
  const wallet = new FakeWallet({ dryRunError: rejection });
  const env = installDom({ wallet });
  try {
    const root = mountInto(env.dom);
    byId(root, "election-id-input").value = ELECTION_A;
    await click(byId(root, "load-election-btn"));
    await click(button(root, "Connect Sapient"));
    await click(button(root, "Estimate Mainnet Fee"));
    assert.ok(/Fee estimate failed/i.test(root.textContent), "error surfaced");
    assert.equal(wallet.createCalls.length, 0);
    assert.equal(wallet.submitCalls, 0);
    assert.ok(findButton(root, "Ask wallet to publish anchor"), "publish remains available for a fresh attempt");
  } finally {
    env.restore();
  }
});

test("estimate is blocked for a non-Mainnet wallet network", async () => {
  const wallet = new FakeWallet({ network: "esmeralda" });
  const env = installDom({ wallet });
  try {
    const root = mountInto(env.dom);
    byId(root, "election-id-input").value = ELECTION_A;
    await click(byId(root, "load-election-btn"));
    await click(button(root, "Connect Sapient"));
    // The wallet is not Mainnet; the estimate action must not run a dry run.
    const estimateBtn = findButton(root, "Estimate Mainnet Fee");
    if (estimateBtn) {
      await click(estimateBtn);
    }
    assert.equal(wallet.signAndSubmitCalls.length, 0, "no dry run on a non-Mainnet wallet");
  } finally {
    env.restore();
  }
});

test("a prior acceptable estimate cannot authorize publish; every attempt re-runs the preflight", async () => {
  const wallet = new FakeWallet({
    dryRunResult: { finalize: { total_fees_required: "3477", result: { Accept: {} } } },
  });
  const env = installDom({ wallet });
  try {
    const root = mountInto(env.dom);
    byId(root, "election-id-input").value = ELECTION_A;
    await click(byId(root, "load-election-btn"));
    await click(button(root, "Connect Sapient"));
    await click(button(root, "Estimate Mainnet Fee"));
    await waitFor(() => wallet.signAndSubmitCalls.length === 1, "manual estimate did not run");
    assert.ok(root.textContent.includes("Estimated transaction fee: 0.003477 TARI"));

    // Change the wallet's fresh quote after the acceptable displayed estimate.
    wallet.dryRunResult = {
      finalize: { total_fees_required: "999999999", result: { Accept: {} } },
    };
    await click(button(root, "Ask wallet to publish anchor"));
    await waitFor(() => wallet.signAndSubmitCalls.length === 2, "publish did not re-run the preflight");

    assert.equal(wallet.createCalls.length, 0, "the stale displayed estimate must not authorize a request");
    assert.equal(wallet.submitCalls, 0);
    assert.match(statusText(root), /exceeds the maximum authorized fee/);
    assert.match(statusText(root), /No transaction request was created/);
  } finally {
    env.restore();
  }
});

test("publish fails closed when the fresh fee preflight is unsupported", async () => {
  const wallet = new FakeWallet({ dryRunResult: { finalize: { result: { Accept: {} } } } });
  const env = installDom({ wallet });
  try {
    const root = mountInto(env.dom);
    byId(root, "election-id-input").value = ELECTION_A;
    await click(byId(root, "load-election-btn"));
    await click(button(root, "Connect Sapient"));
    await click(button(root, "Ask wallet to publish anchor"));
    await waitFor(() => wallet.signAndSubmitCalls.length === 1, "preflight did not run");

    assert.equal(wallet.createCalls.length, 0);
    assert.equal(wallet.submitCalls, 0);
    assert.match(statusText(root), /preflight is unavailable/i);
    assert.match(statusText(root), /No transaction request was created/);
  } finally {
    env.restore();
  }
});

test("publish fails closed when the fresh fee preflight provider rejects", async () => {
  const rejection = new Error("dry run rejected");
  rejection.code = 4001;
  const wallet = new FakeWallet({ dryRunError: rejection });
  const env = installDom({ wallet });
  try {
    const root = mountInto(env.dom);
    byId(root, "election-id-input").value = ELECTION_A;
    await click(byId(root, "load-election-btn"));
    await click(button(root, "Connect Sapient"));
    await click(button(root, "Ask wallet to publish anchor"));
    await waitFor(() => wallet.signAndSubmitCalls.length === 1, "preflight did not run");

    assert.equal(wallet.createCalls.length, 0);
    assert.equal(wallet.submitCalls, 0);
    assert.match(statusText(root), /mandatory non-spending fee preflight failed/i);
    assert.match(statusText(root), /No transaction request was created/);
  } finally {
    env.restore();
  }
});

test("publish requires the allowance-adjusted minimum to fit the authorized cap", async () => {
  // 4995 µT is under the 5000 µT cap, but 4995 + 12 = 5007 µT is over it.
  const wallet = new FakeWallet({
    dryRunResult: { finalize: { total_fees_required: "4995", result: { Accept: {} } } },
  });
  const env = installDom({ wallet });
  try {
    const root = mountInto(env.dom);
    byId(root, "election-id-input").value = ELECTION_A;
    await click(byId(root, "load-election-btn"));
    await click(button(root, "Connect Sapient"));
    await click(button(root, "Ask wallet to publish anchor"));
    await waitFor(() => wallet.signAndSubmitCalls.length === 1, "preflight did not run");

    assert.equal(wallet.createCalls.length, 0);
    assert.equal(wallet.submitCalls, 0);
    assert.match(statusText(root), /allowance-adjusted minimum fee/);
    assert.match(statusText(root), /No transaction request was created/);
  } finally {
    env.restore();
  }
});

test("evaluateFeePreflight accepts only a well-formed quote inside the cap", () => {
  assert.deepEqual(evaluateFeePreflight({ kind: "estimated", requiredFeesMicrotari: "3477" }), {
    ok: true,
    requiredFeesMicrotari: "3477",
    recommendedMaxFeeMicrotari: "3489",
  });
  assert.equal(evaluateFeePreflight({ kind: "unsupported", reason: "no fee field" }).ok, false);
  assert.equal(evaluateFeePreflight({ kind: "estimated", requiredFeesMicrotari: "not-a-number" }).ok, false);
  assert.equal(evaluateFeePreflight({ kind: "estimated", requiredFeesMicrotari: "4995" }).ok, false);
  assert.equal(evaluateFeePreflight({ kind: "estimated", requiredFeesMicrotari: "5001" }).ok, false);
});

test("Mainnet submission remains a build-time gate with a mandatory fresh preflight", () => {
  assert.equal(MAINNET_ANCHOR_SUBMISSION_ENABLED, true);
  const policySrc = readFileSync(new URL("../src/anchorSubmissionPolicy.ts", import.meta.url), "utf8");
  // The gate is a literal build-time constant with no runtime bypass.
  assert.match(policySrc, /export const MAINNET_ANCHOR_SUBMISSION_ENABLED = true/);
  assert.doesNotMatch(policySrc, /ANCHOR_SUBMISSION_POLICY/);
  assert.doesNotMatch(policySrc, /localStorage|sessionStorage|import\.meta\.env/);
  const src = readFileSync(new URL("../src/anchor.ts", import.meta.url), "utf8");
  // The publish path must run the inline preflight before reserving or creating.
  const publishBody = src.slice(
    src.indexOf("async function publishUnlocked"),
    src.indexOf("async function loadPayload"),
  );
  assert.match(publishBody, /runMandatoryFeePreflight\(adapter, snapshot, generation\)/);
  assert.ok(
    publishBody.indexOf("runMandatoryFeePreflight(adapter, snapshot, generation)") <
      publishBody.indexOf("store.reserve("),
    "the fresh preflight must precede the durable request reservation",
  );
  // The dry run must never call the transaction-request approval/submission trio.
  const anchorSrc = readFileSync(new URL("../../gui/src/anchor/browserAnchorPublish.ts", import.meta.url), "utf8");
  const estimateBody = anchorSrc.slice(
    anchorSrc.indexOf("estimateFee:"),
    anchorSrc.indexOf("waitForApproval:"),
  );
  assert.match(estimateBody, /signAndSubmitTransactionDryRun/, "estimate uses the dry-run method");
  assert.doesNotMatch(estimateBody, /createTransactionRequest|submitTransactionRequest/, "estimate never creates or submits");
});

// -----------------------------------------------------------------------------
// Live-qualification failure paths (non-spending only).
// -----------------------------------------------------------------------------

test("accountsChanged clears the wallet, invalidates the quote, and never auto-reconnects", async () => {
  const wallet = new FakeWallet({ dryRunResult: { finalize: { total_fees_required: "3466", result: { Accept: {} } } } });
  const env = installDom({ wallet });
  try {
    const root = mountInto(env.dom);
    byId(root, "election-id-input").value = ELECTION_A;
    await click(byId(root, "load-election-btn"));
    await click(button(root, "Connect Sapient"));
    await click(button(root, "Estimate Mainnet Fee"));
    assert.ok(root.textContent.includes("Estimated transaction fee: 0.003466 TARI"));

    assert.equal(wallet.listeners.length, 1, "the adapter registered exactly one accountsChanged listener");
    wallet.listeners[0]([]);

    assert.match(statusText(root), /Wallet accounts changed\. Reconnect before any anchor action\./);
    assert.ok(!root.textContent.includes("Estimated transaction fee:"), "the stale quote was invalidated");
    assert.ok(findButton(root, "Connect Sapient"), "reconnection is a manual user action");

    const dryRuns = wallet.signAndSubmitCalls.length;
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(wallet.signAndSubmitCalls.length, dryRuns, "no automatic re-quote");
    assert.equal(wallet.createCalls.length, 0);
    assert.equal(wallet.submitCalls, 0);
  } finally {
    env.restore();
  }
});

test("a changed authorized account blocks the quote before any wallet call", async () => {
  const wallet = new FakeWallet({ dryRunResult: { finalize: { total_fees_required: "3466", result: { Accept: {} } } } });
  const env = installDom({ wallet });
  try {
    const root = mountInto(env.dom);
    byId(root, "election-id-input").value = ELECTION_A;
    await click(byId(root, "load-election-btn"));
    await click(button(root, "Connect Sapient"));

    wallet.accounts = [];
    await click(button(root, "Estimate Mainnet Fee"));

    assert.match(root.textContent, /authorized account changed/);
    assert.equal(wallet.signAndSubmitCalls.length, 0, "no fee simulation on a changed account");
    assert.equal(wallet.createCalls.length, 0);
    assert.equal(wallet.submitCalls, 0);
  } finally {
    env.restore();
  }
});

test("a network change after connection blocks the quote before any wallet call", async () => {
  const wallet = new FakeWallet({ dryRunResult: { finalize: { total_fees_required: "3466", result: { Accept: {} } } } });
  const env = installDom({ wallet });
  try {
    const root = mountInto(env.dom);
    byId(root, "election-id-input").value = ELECTION_A;
    await click(byId(root, "load-election-btn"));
    await click(button(root, "Connect Sapient"));

    wallet.network = "esmeralda";
    await click(button(root, "Estimate Mainnet Fee"));

    assert.match(root.textContent, /wallet network changed|does not match the bundle network/i);
    assert.equal(wallet.signAndSubmitCalls.length, 0, "no fee simulation off Mainnet");
    assert.equal(wallet.createCalls.length, 0);
    assert.equal(wallet.submitCalls, 0);
  } finally {
    env.restore();
  }
});

test("no application code calls tari_disconnect and the quote never reads back a fee", () => {
  const sources = [
    "../src/anchor.ts",
    "../src/browserAnchor.ts",
    "../../gui/src/wallet/provider.ts",
    "../../gui/src/wallet/browserWalletRuntime.ts",
    "../../gui/src/anchor/browserAnchorPublish.ts",
  ];
  for (const source of sources) {
    const text = readFileSync(new URL(source, import.meta.url), "utf8");
    assert.doesNotMatch(text, /tari_disconnect/, `${source} must not disconnect wallets implicitly`);
  }
  const anchorSrc = readFileSync(new URL("../src/anchor.ts", import.meta.url), "utf8");
  assert.match(anchorSrc, /the provider exposes no fee read-back/);
  assert.match(anchorSrc, /does not independently prove the wallet enforces the maximum fee/);
});