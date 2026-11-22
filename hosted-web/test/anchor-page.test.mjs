import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { JSDOM } from "jsdom";

import {
  ANCHOR_MAX_FEE_CEILING_UNITS,
  ANCHOR_MAX_FEE_UNITS,
  MAINNET_ANCHOR_SUBMISSION_ENABLED,
  buildAnchorBundleFromPayload,
  mountAnchorPanel,
  parseAnchorPayloadResponse,
  submissionDisabledReason,
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
  constructor({ network = "mainnet", result = { Rejected: { details: "inert test wallet" } } } = {}) {
    this.isTariWallet = true;
    this.accounts = ["account-a"];
    this.network = network;
    this.result = result;
    this.listeners = [];
    this.createCalls = [];
    this.submitCalls = 0;
    this.status = "approved";
  }

  on(event, listener) {
    if (event === "accountsChanged") this.listeners.push(listener);
  }

  async request({ method, params }) {
    switch (method) {
      case "tari_requestAccounts":
        return this.accounts;
      case "tari_getAccounts":
        return this.accounts;
      case "tari_getCapabilities":
        return { transactionRequests: true, transactionResultLookup: true };
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
    assert.ok(root.textContent.includes(`Fee cap: ${ANCHOR_MAX_FEE_UNITS} units`));
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

test("Mainnet submission is disabled by default with a fail-closed reason", () => {
  assert.equal(MAINNET_ANCHOR_SUBMISSION_ENABLED, false);
  const reason = submissionDisabledReason();
  assert.ok(typeof reason === "string" && reason.length > 0);
  assert.match(reason, /Mainnet publishing not yet enabled/);
});

test("the submission gate is a build-time constant with no runtime bypass", () => {
  const src = readFileSync(new URL("../src/anchor.ts", import.meta.url), "utf8");
  // The gate is a literal constant, not a mutable object or a resolved flag.
  assert.match(src, /export const MAINNET_ANCHOR_SUBMISSION_ENABLED = false/);
  // No mutable policy object that a runtime path could flip.
  assert.doesNotMatch(src, /ANCHOR_SUBMISSION_POLICY/);
  assert.doesNotMatch(src, /mainnetEnabled\s*=/);
  // No storage/config/localStorage read that could enable submission.
  assert.doesNotMatch(src, /localStorage|sessionStorage|import\.meta\.env/);
});

test("the Sapient path cannot create or submit a transaction while Mainnet submission is disabled", async () => {
  const wallet = new FakeWallet();
  const env = installDom({ wallet });
  try {
    const root = mountInto(env.dom);
    byId(root, "election-id-input").value = ELECTION_A;
    await click(byId(root, "load-election-btn"));
    await click(button(root, "Connect Sapient"));
    assert.match(statusText(root), /Sapient connected on mainnet/);

    // No publish action is offered while the switch is disabled.
    assert.equal(findButton(root, "Ask wallet to publish anchor"), undefined);
    // The fail-closed notice is displayed clearly.
    assert.match(root.textContent, /Mainnet publishing not yet enabled/);

    // Even a direct invocation cannot reach the wallet: no request creation,
    // no approval wait, no submission.
    assert.equal(wallet.createCalls.length, 0, "no transaction request may be created");
    assert.equal(wallet.submitCalls, 0, "no submission may occur");
  } finally {
    env.restore();
  }
});

test("the Web Tari Universe path cannot create or submit a transaction while Mainnet submission is disabled", async () => {
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

    assert.equal(findButton(root, "Ask wallet to publish anchor"), undefined);
    assert.match(root.textContent, /Mainnet publishing not yet enabled/);
    assert.equal(wallet.createCalls.length, 0, "no transaction request may be created");
    assert.equal(wallet.submitCalls, 0, "no submission may occur");
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

test("the publish action is absent while Mainnet submission is disabled", async () => {
  const wallet = new FakeWallet({ result: { Rejected: { details: "user declined" } } });
  const env = installDom({ wallet });
  try {
    const root = mountInto(env.dom);
    byId(root, "election-id-input").value = ELECTION_A;
    await click(byId(root, "load-election-btn"));
    await click(button(root, "Connect Sapient"));

    assert.equal(findButton(root, "Ask wallet to publish anchor"), undefined);
    assert.equal(wallet.submitCalls, 0, "nothing may be submitted while disabled");
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

test("a hostile server-supplied election id renders inert text", async () => {
  for (const hostile of XSS_PAYLOADS) {
    const payload = payloadFixture({ electionId: hostile.slice(0, 128) });
    const { impl } = recordingFetch(payload);
    const env = installDom({ fetchImpl: impl });
    try {
      const root = mountInto(env.dom);
      byId(root, "election-id-input").value = ELECTION_A;
      await click(byId(root, "load-election-btn"));
      assertInert(root, `hostile server election id ${JSON.stringify(hostile)}`);
      // The hostile string must exist only as inert text content, never as
      // markup or an element attribute value injected by the server.
      assert.ok(
        root.textContent.includes(hostile.slice(0, 128)),
        "the hostile id must be rendered as readable text",
      );
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