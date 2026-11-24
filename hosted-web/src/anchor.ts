/**
 * Hosted web: publish a Mainnet V2 anchor for a finalized election.
 *
 * Security invariants:
 * - Only fetches canonical finalized identity from the backend; the backend
 *   derives it from the independently verified finalized archive and binds it
 *   to the released Mainnet V2 deployment.
 * - Re-validates the canonical public summary locally (strict, byte-exact
 *   re-encode) and cross-checks every field of the server response against
 *   every other field, so a truncated or mixed-up response is rejected before
 *   any wallet interaction.
 * - Binds the bundle to the released Mainnet deployment constants and refuses
 *   any other network, template address, module, function, event topic, or
 *   artifact digest.
 * - Never accepts editable anchor arguments; all arguments derive from the
 *   canonical summary.
 * - Requires a Mainnet wallet network; blocks Esmeralda/testnet/unknown.
 * - Caps the transaction fee and requires explicit wallet approval.
 * - No voter credential, invitation, organizer secret, or ballot plaintext ever
 *   enters the transaction payload.
 *
 * Verification scope (deliberately explicit): the canonical summary encoding,
 * the bundle's internal identity binding, the released deployment identity, and
 * the on-chain receipt are all verified here independently of the response's
 * own claims. The archive-to-summary provenance (tally correctness) is proven
 * by the Hosted backend's canonical archive replay; this page cannot re-replay
 * an archive it does not hold. See docs/hosted/anchor-browser-verification.md.
 */

import {
  APP_ANCHOR_NETWORK,
  APP_DEPLOYMENT_ENVIRONMENT,
} from "./branding/identity.ts";
import {
  bundleDigestKey,
  canonicalEventTopicFromBindingTopic,
  parseAnchorBundleJson,
  type AnchorBundleV1,
} from "../../gui/src/wallet/anchorBundle.ts";
import {
  anchorDeploymentConfig,
  deploymentForNetwork,
  mainnetTransactionExplorerUrl,
  v2CanonicalReceiptTopic,
} from "../../gui/src/wallet/anchorDeploymentConfig.ts";
import { assessAnchorWorkflow, phaseLabel } from "../../gui/src/wallet/anchorWorkflow.ts";
import { networkVerdict } from "../../gui/src/wallet/network.ts";
import { browserRecoveryStore, type AnchorRecoveryRecord } from "../../gui/src/wallet/recoveryStore.ts";
import { newRecoveryOwnerToken, type RecoveryLoadState } from "../../gui/src/wallet/recoveryStore.ts";
import { withExclusiveAnchorOperation } from "../../gui/src/wallet/browserOperationLock.ts";
import { parseCanonicalPublicSummaryV2 } from "../../gui/src/wallet/publicSummary.ts";
import { verifyBrowserAnchorEvidence } from "../../gui/src/wallet/chainEvidence.ts";
import { bundleExpectedPayload, bundleExpectedTemplate } from "../../gui/src/wallet/anchorBundle.ts";
import { hasCapability, type WindowTariProvider } from "../../gui/src/wallet/provider.ts";
import type {
  DryRunFeeEstimate,
  TariCapabilities,
  TransactionRequestSummary,
} from "../../gui/src/wallet/types.ts";
import {
  formatTariFromMicroTari,
  isMicroTariAbove,
  addMicroTari,
} from "../../gui/src/wallet/feeFormat.ts";
import {
  adapterForKind,
  defaultPublishDriver,
  providerErrorMessage,
  type BrowserWalletKind,
} from "../../gui/src/anchor/browserAnchorPublish.ts";
import {
  ANCHOR_MAX_FEE_CEILING_UNITS,
  ANCHOR_MAX_FEE_UNITS,
  createGuardedPublishDriver,
  evaluateFeePreflight,
  FEE_ESTIMATE_ALLOWANCE_UNITS,
  MAINNET_ANCHOR_SUBMISSION_ENABLED,
  submissionDisabledReason,
} from "./anchorSubmissionPolicy.ts";

export {
  ANCHOR_MAX_FEE_CEILING_UNITS,
  ANCHOR_MAX_FEE_UNITS,
  FEE_ESTIMATE_ALLOWANCE_UNITS,
  MAINNET_ANCHOR_SUBMISSION_ENABLED,
  createGuardedPublishDriver,
  evaluateFeePreflight,
  submissionDisabledReason,
  submissionGateReason,
  type FeePreflightDecision,
} from "./anchorSubmissionPolicy.ts";

const REQUIRED_CAPABILITIES = ["transactionRequests", "transactionResultLookup"] as const;
const VERIFY_ATTEMPTS = 30;
const VERIFY_INTERVAL_MS = 4000;
const APPROVAL_TIMEOUT_MS = 10 * 60 * 1000;
const TRANSACTION_ID = /^[0-9a-f]{64}$/;

/** Formats a microTARI amount as a TARI string for display, or "—" if malformed. */
function displayTari(microtari: unknown): string {
  return formatTariFromMicroTari(microtari) ?? "—";
}

/** A pending or resolved fee-estimate view for the current bundle. */
type FeeEstimateState =
  | { kind: "idle" }
  | { kind: "pending" }
  | { kind: "estimated"; requiredFeesMicrotari: string }
  | { kind: "unsupported"; reason: string }
  | { kind: "error"; message: string };

type WalletConnection = {
  kind: BrowserWalletKind;
  adapter: WindowTariProvider;
  accounts: string[];
  network: string;
  capabilities: TariCapabilities;
};

function element<K extends keyof HTMLElementTagNameMap>(tag: K, text?: string): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  return node;
}

function action(text: string, handler: () => void | Promise<void>, disabled: boolean): HTMLButtonElement {
  const node = element("button", text);
  node.type = "button";
  node.disabled = disabled;
  node.addEventListener("click", () => void handler());
  return node;
}

export function submittedTransactionId(summary: TransactionRequestSummary): string | null {
  const result = summary.result;
  const value = typeof result === "string"
    ? result
    : typeof result === "object" && result !== null
      ? (result as Record<string, unknown>).transactionId
      : null;
  return typeof value === "string" && TRANSACTION_ID.test(value) ? value : null;
}

function missingCapability(capabilities: TariCapabilities): string | null {
  return REQUIRED_CAPABILITIES.find((capability) => !hasCapability(capabilities, capability)) ?? null;
}

function sameAccounts(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((account, index) => account === right[index]);
}

type AnchorPayloadResponse = {
  election_id: string;
  archive_hash_hex: string;
  v2_anchor_digest_hex: string;
  payload_hex: string;
  public_summary_json: string;
  network: string;
  template_address: string;
  template_module: string;
  template_function: string;
  template_event_topic: string;
  template_artifact_digest_hex: string;
  anchor_args: {
    anchor_digest_hex: string;
    network: string;
    election_id: string;
    public_summary: string;
  };
};

type ValidatedAnchorBundle = {
  bundle: AnchorBundleV1;
  payload: AnchorPayloadResponse;
};

type AnchorPayloadSuccess = { ok: true; payload: AnchorPayloadResponse };
type AnchorPayloadFailure = { ok: false; code: string; message: string };
type AnchorPayloadResult = AnchorPayloadSuccess | AnchorPayloadFailure;

const HEX_64 = /^[0-9a-f]{64}$/;

/** The exact set of keys the endpoint must return. */
const PAYLOAD_KEYS = [
  "election_id", "archive_hash_hex", "v2_anchor_digest_hex", "payload_hex",
  "public_summary_json", "network", "template_address", "template_module",
  "template_function", "template_event_topic", "template_artifact_digest_hex",
  "anchor_args",
] as const;

function isStringRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Validates the envelope shape of one anchor-payload response.
 *
 * Every field is checked for presence and type, and every digest is checked to
 * be 64 lowercase hex characters. Nothing here trusts the server's claim that
 * the values are consistent; that is done by `bundleIdentityError`.
 */
export function parseAnchorPayloadResponse(data: unknown): AnchorPayloadResponse | null {
  if (!isStringRecord(data)) return null;
  for (const key of PAYLOAD_KEYS) {
    if (!(key in data)) return null;
  }
  for (const key of PAYLOAD_KEYS) {
    if (key === "anchor_args") continue;
    if (typeof data[key] !== "string") return null;
  }
  const args = data["anchor_args"];
  if (!isStringRecord(args)) return null;
  for (const key of ["anchor_digest_hex", "network", "election_id", "public_summary"] as const) {
    if (typeof args[key] !== "string") return null;
  }
  const hexFields = [
    data["archive_hash_hex"],
    data["v2_anchor_digest_hex"],
    data["template_artifact_digest_hex"],
    args["anchor_digest_hex"],
  ];
  if (!hexFields.every((value) => typeof value === "string" && HEX_64.test(value))) return null;
  const payloadHex = data["payload_hex"];
  if (typeof payloadHex !== "string" || payloadHex.length % 2 !== 0 || !/^[0-9a-f]*$/.test(payloadHex)) {
    return null;
  }
  return data as unknown as AnchorPayloadResponse;
}

async function loadAnchorPayload(
  electionId: string,
  acknowledgeReducedAnonymity: boolean,
): Promise<AnchorPayloadResult> {
  const suffix = acknowledgeReducedAnonymity ? "?acknowledge_reduced_anonymity=true" : "";
  let response: Response;
  try {
    response = await fetch(
      `/api/v1/elections/${encodeURIComponent(electionId)}/anchor-payload${suffix}`,
      { headers: { Accept: "application/json" } },
    );
  } catch {
    return {
      ok: false,
      code: "anchor_unreachable",
      message: "The Hosted backend could not be reached.",
    };
  }
  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  if (!response.ok) {
    const record = isStringRecord(body) ? body : {};
    const code = typeof record["code"] === "string" ? record["code"] : `anchor_http_${response.status}`;
    const message = typeof record["message"] === "string"
      ? record["message"]
      : "The anchor payload request was rejected.";
    return { ok: false, code, message };
  }
  const parsed = parseAnchorPayloadResponse(body);
  if (parsed === null) {
    return {
      ok: false,
      code: "anchor_malformed_response",
      message: "The Hosted backend returned an incomplete anchor payload.",
    };
  }
  return { ok: true, payload: parsed };
}

/**
 * Converts one server payload into the canonical browser bundle.
 *
 * The on-chain receipt event topic uses the canonical `TariPrivateBallotAnchorV2`
 * prefix, while the template ABI topic uses the lowercase module prefix. The
 * audited `canonicalEventTopicFromBindingTopic` performs that conversion; it is
 * applied here so the browser verifies against the topic that is actually
 * emitted on chain.
 */
export function buildAnchorBundleFromPayload(payload: AnchorPayloadResponse): AnchorBundleV1 {
  return parseAnchorBundleJson(JSON.stringify({
    schemaVersion: 1,
    network: payload.network,
    template: {
      address: payload.template_address,
      module: payload.template_module,
      function: payload.template_function,
      eventTopic: canonicalEventTopicFromBindingTopic(payload.template_event_topic),
      artifactDigestHex: payload.template_artifact_digest_hex,
    },
    anchorArgs: {
      anchorDigestHex: payload.anchor_args.anchor_digest_hex,
      network: payload.anchor_args.network,
      electionId: payload.anchor_args.election_id,
      publicSummary: payload.anchor_args.public_summary,
    },
  }));
}

export function mountAnchorPanel(root: HTMLElement): void {
  const store = browserRecoveryStore();
  const ownerToken = newRecoveryOwnerToken();
  const baseDriver = defaultPublishDriver({
    verifyAttempts: VERIFY_ATTEMPTS,
    verifyIntervalMs: VERIFY_INTERVAL_MS,
    verifyWithEvidence: (adapter, bundle, transactionId) => verifyBrowserAnchorEvidence(
      adapter,
      transactionId,
      bundleExpectedTemplate(bundle),
      bundleExpectedPayload(bundle),
    ),
  });
  // Fail-closed wrappers: every wallet transaction initiation, approval wait,
  // and submission goes through these guards. Even if a future UI path forgets
  // its own check, a disabled build can never be bypassed into a wallet
  // request or submission. Verification (read-only) is deliberately not
  // guarded; checking an existing receipt is always safe.
  const driver = createGuardedPublishDriver(baseDriver, MAINNET_ANCHOR_SUBMISSION_ENABLED);
  let validatedBundle: ValidatedAnchorBundle | null = null;
  let payloadError: string | null = null;
  let wallet: WalletConnection | null = null;
  let recovery: AnchorRecoveryRecord | null = null;
  let recoveryState: RecoveryLoadState = { kind: "absent" };
  let electionId = "";
  let acknowledgeReducedAnonymity = false;
  let status = "Enter a finalized election ID to load its canonical anchor payload from the Hosted backend.";
  let busy = false;
  let feeEstimate: FeeEstimateState = { kind: "idle" };
  let bundleGeneration = 0;
  let loadedAcknowledgement: boolean | null = null;

  const bundleKey = () => {
    if (!validatedBundle) throw new Error("Load a finalized election first.");
    return bundleDigestKey(validatedBundle.bundle);
  };
  const loadRecovery = () => {
    recoveryState = validatedBundle === null ? { kind: "absent" } : store.loadState(bundleDigestKey(validatedBundle.bundle));
    recovery = recoveryState.kind === "record" ? recoveryState.record : null;
  };
  const invalidateFeeEstimate = () => {
    feeEstimate = { kind: "idle" };
  };
  const saveOwned = (
    phase: AnchorRecoveryRecord["phase"],
    requestId: string | null,
    transactionId: string | null,
    key = bundleKey(),
  ) => {
    const saved = store.saveOwned(key, ownerToken, { phase, requestId, transactionId });
    if (
      transactionId !== null &&
      TRANSACTION_ID.test(transactionId) &&
      (phase === "approved_submitted" || phase === "verifying" || phase === "verified")
    ) {
      store.releaseSubmittedRecoveryLease(key, ownerToken);
    }
    return saved;
  };
  /**
   * Cross-checks every field of the response against every other field.
   *
   * This is a consistency proof, not a provenance proof: it demonstrates that
   * the bundle, the canonical summary, and the response agree with each other
   * and with the canonical summary encoding. It cannot prove that the tally
   * matches the true ballots — only the backend archive replay can.
   */
  const bundleIdentityError = (): string | null => {
    if (!validatedBundle) return "Load a finalized election first.";
    const bundle = validatedBundle.bundle;
    const payload = validatedBundle.payload;
    try {
      const summary = parseCanonicalPublicSummaryV2(bundle.anchorArgs.publicSummary);
      // The canonical summary carries the lowercase module-prefixed ABI topic;
      // the chain emits the canonical receipt topic.
      if (canonicalEventTopicFromBindingTopic(summary.template.eventTopic) !== v2CanonicalReceiptTopic()) {
        return "The canonical summary does not name the deployed receipt event topic.";
      }
      const sameTemplate = summary.template.address === bundle.template.address &&
        summary.template.module === bundle.template.module &&
        summary.template.function === bundle.template.function &&
        canonicalEventTopicFromBindingTopic(summary.template.eventTopic) === bundle.template.eventTopic &&
        summary.template.artifactDigestHex === bundle.template.artifactDigestHex;
      if (bundle.network !== bundle.anchorArgs.network || summary.network !== bundle.network) {
        return "The outer, event, and canonical-summary networks must agree.";
      }
      if (bundle.anchorArgs.electionId !== summary.electionId || summary.electionId !== payload.election_id) {
        return "The bundle does not belong to this finalized election.";
      }
      if (summary.archiveHashHex !== payload.archive_hash_hex) {
        return "The bundle's finalized archive identity does not match this election.";
      }
      if (bundle.anchorArgs.anchorDigestHex !== payload.v2_anchor_digest_hex) {
        return "The bundle's anchor digest does not match the native finalized election identity.";
      }
      if (bundle.anchorArgs.publicSummary !== payload.public_summary_json) {
        return "The bundle's canonical public summary does not match the native finalized election identity.";
      }
      if (bundle.anchorArgs.anchorDigestHex !== payload.anchor_args.anchor_digest_hex) {
        return "The bundle's anchor digest does not match the response arguments.";
      }
      if (!sameTemplate) return "The canonical public summary does not bind this deployment identity.";
      return null;
    } catch (error) {
      return error instanceof Error ? error.message : "The public summary is invalid.";
    }
  };
  const deploymentError = (): string | null => {
    if (!validatedBundle) return "Load a finalized election first.";
    const identity = bundleIdentityError();
    if (identity) return identity;
    const bundle = validatedBundle.bundle;
    const deployment = deploymentForNetwork(anchorDeploymentConfig(), bundle.network);
    if (!deployment) return `No current anchor deployment is configured for ${bundle.network}.`;
    const matches = bundle.template.address === deployment.address &&
      bundle.template.module === deployment.module &&
      bundle.template.function === deployment.function &&
      bundle.template.eventTopic === deployment.eventTopic &&
      bundle.template.artifactDigestHex === deployment.artifactDigestHex;
    return matches ? null : "The bundle does not match the current trusted anchor deployment.";
  };

  async function revalidate(allowRecovery: boolean): Promise<WindowTariProvider> {
    if (!validatedBundle) throw new Error("Load a finalized election first.");
    loadRecovery();
    if (recoveryState.kind === "corrupt") throw new Error(`${recoveryState.message}; browser publishing is blocked.`);
    if (!allowRecovery && recovery !== null) {
      throw new Error("A saved request or transaction exists. Resolve it before creating another request.");
    }
    if (!wallet) throw new Error("Connect a Tari wallet first.");
    const deployment = deploymentError();
    if (deployment) throw new Error(deployment);
    const adapter = wallet.adapter;
    const accounts = await adapter.getAccounts();
    if (accounts.length === 0 || !sameAccounts(accounts, wallet.accounts)) {
      wallet = null;
      invalidateFeeEstimate();
      throw new Error("The wallet's authorized account changed. Reconnect before any anchor action.");
    }
    const capabilities = await adapter.getCapabilities();
    const missing = missingCapability(capabilities);
    if (missing) throw new Error(`The wallet does not support required capability ${missing}.`);
    const network = (await adapter.getNetwork()).network;
    if (network !== wallet.network) {
      wallet = null;
      invalidateFeeEstimate();
      throw new Error("The wallet network changed. Reconnect before any anchor action.");
    }
    if (networkVerdict(validatedBundle.bundle.network, network).kind !== "match") {
      throw new Error("The wallet network does not match the bundle network. Publishing is blocked.");
    }
    wallet = { ...wallet, accounts, network, capabilities };
    return adapter;
  }

  async function verifyExisting(
    adapter: WindowTariProvider,
    transactionId: string,
    snapshot: ValidatedAnchorBundle | null = validatedBundle,
    key: string | null = snapshot ? bundleDigestKey(snapshot.bundle) : null,
  ): Promise<void> {
    if (!snapshot) return;
    const recoveryKey = key ?? bundleDigestKey(snapshot.bundle);
    status = "Verifying the existing on-chain anchor event…";
    render();
    const outcome = await driver.verify(adapter, snapshot.bundle, transactionId);
    if (outcome.kind === "verified") {
      saveOwned("verified", null, transactionId, recoveryKey);
      status = `Verified: the public V2 anchor matches this election (${transactionId.slice(0, 16)}…).`;
    } else if (outcome.kind === "pending") {
      saveOwned("verifying", null, transactionId, recoveryKey);
      status = outcome.detail
        ? `${outcome.detail}. It remains saved for verification and will never be submitted again automatically.`
        : "The transaction is not final yet. It remains saved for verification and will never be submitted again automatically.";
    } else {
      saveOwned("verifying", null, transactionId, recoveryKey);
      status = `${outcome.message}. The saved transaction remains blocked from resubmission.`;
    }
    loadRecovery();
  }

  async function submitApprovedUnlocked(
    requestId: string,
    snapshot: ValidatedAnchorBundle,
    key: string,
    generation: number,
  ): Promise<void> {
    assertBundleSnapshot(snapshot, generation);
    const disabled = submissionDisabledReason();
    if (disabled !== null) throw new Error(disabled);
    busy = true;
    render();
    try {
      const adapter = await revalidate(true);
      assertBundleSnapshot(snapshot, generation);
      loadRecovery();
      if (recovery?.phase !== "submitted_awaiting_approval" || recovery.requestId !== requestId) {
        throw new Error("The saved request changed; do not submit it again.");
      }
      const claimed = store.claim(key, ownerToken);
      if (claimed.kind !== "claimed") throw new Error("Another tab owns this saved anchor operation; do not submit it twice.");
      const current = await adapter.pollTransactionRequest(requestId, { timeoutMs: 1, intervalMs: 0 });
      const existingTransactionId = current.status === "submitted" ? submittedTransactionId(current) : null;
      if (existingTransactionId) {
        saveOwned("approved_submitted", null, existingTransactionId, key);
        await verifyExisting(adapter, existingTransactionId, snapshot, key);
        return;
      }
      if (current.status !== "approved") {
        throw new Error(`The current wallet request is ${current.status}; it will not be submitted.`);
      }
      await revalidate(true);
      assertBundleSnapshot(snapshot, generation);
      saveOwned("submit_in_flight", requestId, null, key);
      loadRecovery();
      status = "Submitting the approved request once…";
      render();
      const transactionId = await driver.submit(adapter, requestId);
      if (!TRANSACTION_ID.test(transactionId)) {
        throw new Error("The wallet returned a malformed transaction id; the request remains blocked.");
      }
      saveOwned("approved_submitted", null, transactionId, key);
      loadRecovery();
      await verifyExisting(adapter, transactionId, snapshot, key);
    } catch (error) {
      status = `${providerErrorMessage(error)} Check wallet history; this request will not be submitted again.`;
    } finally {
      busy = false;
      render();
    }
  }

  async function checkRecovery(): Promise<void> {
    if (busy || !validatedBundle) return;
    const key = bundleKey();
    busy = true;
    render();
    try {
      await withExclusiveAnchorOperation(key, checkRecoveryUnlocked);
    } catch (error) {
      status = providerErrorMessage(error);
    } finally {
      busy = false;
      render();
    }
  }

  async function checkRecoveryUnlocked(): Promise<void> {
    if (!validatedBundle || !recovery) return;
    busy = true;
    render();
    try {
      loadRecovery();
      if (!recovery) throw new Error("No saved request or transaction exists.");
      if (recovery.phase === "creating_request") {
        status = "The wallet request may have been created but its reply was lost. Check wallet history; a new request is blocked.";
        return;
      }
      const claimed = store.claim(bundleKey(), ownerToken);
      if (claimed.kind !== "claimed") throw new Error("Another tab owns this saved anchor operation; wait before trying again.");
      loadRecovery();
      const adapter = await revalidate(true);
      if (recovery.transactionId && TRANSACTION_ID.test(recovery.transactionId)) {
        await verifyExisting(adapter, recovery.transactionId);
        return;
      }
      if (!recovery.requestId) throw new Error("The saved recovery record is incomplete.");
      const saved = recovery;
      let summary: TransactionRequestSummary;
      try {
        summary = await adapter.pollTransactionRequest(saved.requestId!, { timeoutMs: 1, intervalMs: 0 });
      } catch {
        status = "The saved request is pending or unknown. It remains blocked; no request or submit action will be retried.";
        return;
      }
      if (summary.status === "rejected" || summary.status === "failed") {
        status = `The saved request is terminally ${summary.status}. It was not treated as a successful anchor.`;
        return;
      }
      if (summary.status === "approved" && saved.phase === "submitted_awaiting_approval") {
        status = "The saved request is approved, but its original wallet, account, and anchor instructions cannot be proven after recovery. It will not be submitted from this panel.";
        return;
      }
      const transactionId = summary.status === "submitted" ? submittedTransactionId(summary) : null;
      if (transactionId) {
        saveOwned("approved_submitted", null, transactionId);
        loadRecovery();
        await verifyExisting(adapter, transactionId);
        return;
      }
      status = "The request may already have been submitted, but no verifiable transaction id was returned. Check wallet history; do not resubmit.";
    } catch (error) {
      status = providerErrorMessage(error);
    } finally {
      busy = false;
      render();
    }
  }

  async function connect(kind: BrowserWalletKind): Promise<void> {
    invalidateFeeEstimate();
    busy = true;
    render();
    try {
      if (!validatedBundle || deploymentError() !== null) throw new Error("Load a finalized election before connecting a wallet.");
      const adapter = adapterForKind(kind, window).pin();
      const accounts = await adapter.connect();
      if (accounts.length === 0) throw new Error("The wallet did not authorize an account.");
      const capabilities = await adapter.getCapabilities();
      const missing = missingCapability(capabilities);
      if (missing) throw new Error(`The wallet does not support required capability ${missing}.`);
      const network = (await adapter.getNetwork()).network;
      const verdict = networkVerdict(validatedBundle.bundle.network, network);
      if (verdict.kind !== "match") {
        wallet = null;
        throw new Error(`This anchor requires a Mainnet wallet; the wallet reports "${network}".`);
      }
      wallet = { kind, adapter, accounts, network, capabilities };
      adapter.onAccountsChanged(() => {
        wallet = null;
        invalidateFeeEstimate();
        status = "Wallet accounts changed. Reconnect before any anchor action.";
        render();
      });
      status = `${kind === "sapient" ? "Sapient" : "Tari Universe"} connected on ${network}.`;
    } catch (error) {
      wallet = null;
      status = providerErrorMessage(error);
    } finally {
      busy = false;
      render();
    }
  }

  async function publish(): Promise<void> {
    const snapshot = validatedBundle;
    if (!snapshot || busy) return;
    const key = bundleDigestKey(snapshot.bundle);
    const generation = bundleGeneration;
    busy = true;
    render();
    try {
      await withExclusiveAnchorOperation(key, () => publishUnlocked(snapshot, key, generation));
    } catch (error) {
      status = `${providerErrorMessage(error)} No request or transaction will be retried automatically.`;
    } finally {
      busy = false;
      render();
    }
  }

  /**
   * Non-spending Mainnet fee preflight.
   *
   * Revalidates the wallet/network, then asks the wallet to meter the exact
   * anchor instructions with a dryRun signAndSubmit. It never creates a
   * transaction request, never waits for approval, and never submits. The result
   * is displayed as an estimate only; it does not prove a funded transaction will
   * succeed, and it does not prove the wallet enforces `maxFee`.
   */
  async function estimateFee(): Promise<void> {
    if (!validatedBundle) return;
    feeEstimate = { kind: "pending" };
    busy = true;
    render();
    try {
      const adapter = await revalidate(true);
      // The estimate meters the same instructions a real publish would send, at
      // the same configured fee cap, so the quote matches the eventual shape.
      const estimate = await driver.estimateFee(adapter, validatedBundle.bundle, ANCHOR_MAX_FEE_UNITS);
      feeEstimate = estimate;
    } catch (error) {
      feeEstimate = { kind: "error", message: providerErrorMessage(error) };
    } finally {
      busy = false;
      render();
    }
  }

  const assertBundleSnapshot = (snapshot: ValidatedAnchorBundle, generation: number) => {
    if (validatedBundle !== snapshot || bundleGeneration !== generation) {
      throw new Error("The loaded election changed. Load it again before publishing.");
    }
  };

  async function runMandatoryFeePreflight(adapter: WindowTariProvider, snapshot: ValidatedAnchorBundle, generation: number): Promise<void> {
    assertBundleSnapshot(snapshot, generation);
    status = "Running the mandatory non-spending Mainnet fee preflight…";
    feeEstimate = { kind: "pending" };
    render();
    let estimate: DryRunFeeEstimate;
    try {
      estimate = await driver.estimateFee(adapter, snapshot.bundle, ANCHOR_MAX_FEE_UNITS);
    } catch (error) {
      const message = providerErrorMessage(error);
      feeEstimate = { kind: "error", message };
      throw new Error(`The mandatory non-spending fee preflight failed: ${message}. No transaction request was created.`);
    }
    assertBundleSnapshot(snapshot, generation);
    feeEstimate = estimate;
    const decision = evaluateFeePreflight(estimate, ANCHOR_MAX_FEE_UNITS);
    if (!decision.ok) throw new Error(decision.reason);
    await revalidate(false);
    assertBundleSnapshot(snapshot, generation);
    status = `Fee preflight passed: ${displayTari(decision.requiredFeesMicrotari)} TARI required (${displayTari(decision.recommendedMaxFeeMicrotari)} TARI allowance-adjusted) within the ${displayTari(ANCHOR_MAX_FEE_UNITS)} TARI cap. Asking the wallet to approve the anchor…`;
    render();
  }

  async function publishUnlocked(snapshot: ValidatedAnchorBundle, key: string, generation: number): Promise<void> {
    assertBundleSnapshot(snapshot, generation);
    if (loadedAcknowledgement !== acknowledgeReducedAnonymity) {
      throw new Error("The reduced-anonymity acknowledgement changed. Reload the anchor payload before publishing.");
    }
    const disabled = submissionDisabledReason();
    if (disabled !== null) throw new Error(disabled);
    busy = true;
    render();
    try {
      const adapter = await revalidate(false);
      assertBundleSnapshot(snapshot, generation);
      const phase = assessAnchorWorkflow({
        bundle: snapshot.bundle, bundleInvalidReason: null, walletConnected: true, walletNetworkName: wallet?.network ?? null, recovery: null,
      });
      if (phase.kind !== "ready") throw new Error(phaseLabel(phase));
      await runMandatoryFeePreflight(adapter, snapshot, generation);
      const reservation = store.reserve(key, ownerToken);
      if (reservation.kind === "busy") throw new Error("A saved anchor operation already exists. Resolve it before creating another request.");
      if (reservation.kind === "corrupt") throw new Error(`${reservation.message}; no wallet request was created.`);
      if (reservation.kind !== "claimed") throw new Error("The anchor reservation is ambiguous; no wallet request was created.");
      assertBundleSnapshot(snapshot, generation);
      // The fee cap is sent with the request so the wallet enforces it.
      const requestId = await driver.createRequest(adapter, snapshot.bundle, ANCHOR_MAX_FEE_UNITS);
      saveOwned("submitted_awaiting_approval", requestId, null, key);
      loadRecovery();
      status = "The wallet request is waiting for approval. Approve or reject it in the wallet; nothing is submitted until approval.";
      render();
      const summary = await driver.waitForApproval(adapter, requestId, APPROVAL_TIMEOUT_MS);
      if (summary.status === "approved") {
        await submitApprovedUnlocked(requestId, snapshot, key, generation);
        return;
      }
      if (summary.status === "submitted") {
        const transactionId = submittedTransactionId(summary);
        if (!transactionId) throw new Error("The wallet reported submission without a verifiable transaction id.");
        saveOwned("approved_submitted", null, transactionId, key);
        loadRecovery();
        await verifyExisting(adapter, transactionId, snapshot, key);
        return;
      }
      status = `The wallet ${summary.status} the request. It was not treated as a successful anchor.`;
    } catch (error) {
      status = `${providerErrorMessage(error)} No request or transaction will be retried automatically.`;
    } finally {
      busy = false;
      render();
    }
  }

  async function loadPayload(): Promise<void> {
    if (busy) return;
    const input = root.querySelector<HTMLInputElement>("#election-id-input");
    const id = input?.value.trim() ?? "";
    if (!id) {
      status = "Enter a finalized election ID first.";
      render();
      return;
    }
    const generation = ++bundleGeneration;
    validatedBundle = null;
    loadedAcknowledgement = null;
    payloadError = null;
    electionId = id;
    invalidateFeeEstimate();
    loadRecovery();
    busy = true;
    status = "Loading canonical anchor payload from Hosted…";
    render();
    const failLoad = (message: string) => {
      payloadError = message;
      status = "The anchor payload could not be loaded.";
      validatedBundle = null;
      loadedAcknowledgement = null;
      loadRecovery();
    };
    try {
      const result = await loadAnchorPayload(id, acknowledgeReducedAnonymity);
      if (generation !== bundleGeneration) return;
      if (!result.ok) {
        failLoad(`${result.message} (${result.code})`);
        return;
      }
      if (result.payload.election_id !== id || result.payload.anchor_args.election_id !== id) {
        failLoad("The Hosted backend returned a payload for a different election.");
        return;
      }
      let bundle: AnchorBundleV1;
      try {
        bundle = buildAnchorBundleFromPayload(result.payload);
      } catch (error) {
        failLoad(error instanceof Error ? error.message : "The anchor payload is not a valid bundle.");
        return;
      }
      const identityError = deploymentForNetwork(anchorDeploymentConfig(), bundle.network)
        ? null
        : "No current anchor deployment is configured for the payload network.";
      if (identityError) {
        failLoad(identityError);
        return;
      }
      validatedBundle = { bundle, payload: result.payload };
      loadedAcknowledgement = acknowledgeReducedAnonymity;
      payloadError = null;
      loadRecovery();
      status = `Loaded election ${result.payload.election_id}. Archive: ${result.payload.archive_hash_hex.slice(0, 16)}… Anchor: ${result.payload.v2_anchor_digest_hex.slice(0, 16)}… Connect a Mainnet wallet and submit.`;
    } finally {
      if (generation === bundleGeneration) {
        busy = false;
        render();
      }
    }
  }

  function esc(s: string): string {
    return s.replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c] as string)
    );
  }

  function render(): void {
    root.replaceChildren();
    const card = element("section");
    card.className = "card browser-anchor-panel";
    const nav = element("nav");
    nav.className = "anchor-nav";
    nav.setAttribute("aria-label", "Section");
    nav.innerHTML = '<a href="/">Home</a> · <a href="/manage.html">Manage Election</a> · <a href="/archive.html">Archive</a>';
    card.append(nav);
    card.append(element("h2", "Tari Mainnet Anchor"));
    card.append(element("p", `Deployment: ${APP_DEPLOYMENT_ENVIRONMENT} · Anchor network: ${APP_ANCHOR_NETWORK}`));
    card.append(element("p", "This page publishes the canonical V2 anchor for a finalized election. Load the election, connect a Mainnet wallet, review the fee, approve it in the wallet, and submit. No Desktop bundle import is required."));

    const electionSection = element("div");
    electionSection.className = "form-field form-field--full";
    electionSection.innerHTML = `
      <label for="election-id-input">Finalized Election ID</label>
      <input type="text" id="election-id-input" placeholder="e.g. pb-staging-e2e-37a9219" autocomplete="off" value="${esc(electionId)}" ${busy ? "disabled" : ""} />
      <button id="load-election-btn" type="button" class="btn btn-secondary" style="margin-top: 0.5rem;" ${busy ? "disabled" : ""}>Load anchor payload</button>
      <label class="form-hint" for="ack-reduced-anonymity" style="margin-top: 0.5rem;">
        <input type="checkbox" id="ack-reduced-anonymity" ${busy ? "disabled" : ""} />
        I acknowledge that this election's transport binding covers a cohort below the descriptor floor (reduced anonymity).
      </label>
    `;
    card.append(electionSection);

    if (validatedBundle) {
      const payload = validatedBundle.payload;
      const info = element("p");
      info.innerHTML = `Election: <span class="mono">${esc(payload.election_id)}</span> · Archive: <span class="mono">${esc(payload.archive_hash_hex.slice(0, 16))}…</span> · Anchor: <span class="mono">${esc(payload.v2_anchor_digest_hex.slice(0, 16))}…</span>`;
      card.append(info);
    }

    if (payloadError) {
      const error = element("p", payloadError);
      error.className = "error";
      card.append(error);
    }
    if (validatedBundle) {
      const bundle = validatedBundle.bundle;
      card.append(element("p", `Bundle: ${bundle.network} · ${bundle.template.function} · ${bundle.anchorArgs.anchorDigestHex.slice(0, 16)}…`));
      const deployment = deploymentError();
      if (deployment) {
        const error = element("p", deployment);
        error.className = "error";
        card.append(error);
      }
    }

    // Fee and approval policy. The fee is capped client-side and enforced by the
    // wallet from the maxFee request parameter. Displayed in TARI (protocol µT
    // shown in parentheses for operators).
    card.append(element(
      "p",
      `Maximum authorized fee: ${displayTari(ANCHOR_MAX_FEE_UNITS)} TARI (${ANCHOR_MAX_FEE_UNITS} µT) · Release fee ceiling: ${displayTari(ANCHOR_MAX_FEE_CEILING_UNITS)} TARI (${ANCHOR_MAX_FEE_CEILING_UNITS} µT) · Wallet approval: required · Network: ${APP_ANCHOR_NETWORK}`,
    ));
    const disabledReason = submissionDisabledReason();
    if (disabledReason !== null) {
      const notice = element("p", disabledReason);
      notice.className = "notice";
      notice.setAttribute("role", "note");
      card.append(notice);
    }
    if (wallet) {
      const verdict = networkVerdict(validatedBundle?.bundle.network ?? "", wallet.network);
      card.append(element(
        "p",
        verdict.kind === "match"
          ? `Wallet: ${wallet.kind} · ${wallet.network} · ${wallet.accounts.length} authorized account(s) · Mainnet`
          : `Wallet: ${wallet.kind} · ${wallet.network} · not Mainnet — publishing is blocked`,
      ));
    } else {
      card.append(element("p", "Mainnet network status: no wallet connected."));
    }

    // Non-spending fee preflight result. This is an estimate only: it never
    // proves a funded transaction will succeed, and it does not prove the wallet
    // enforces maxFee — the provider exposes no fee read-back. All user-facing
    // amounts are displayed in TARI; protocol accounting stays in integer µT.
    const maxFeeTari = displayTari(ANCHOR_MAX_FEE_UNITS);
    const ceilingTari = displayTari(ANCHOR_MAX_FEE_CEILING_UNITS);
    if (feeEstimate.kind === "pending") {
      card.append(element("p", "Estimating the Mainnet fee (non-spending dry run)…"));
    } else if (feeEstimate.kind === "estimated") {
      const microtari = feeEstimate.requiredFeesMicrotari;
      const tari = displayTari(microtari);
      // Allowance-adjusted recommended max_fee = required + FEE_ESTIMATE_ALLOWANCE.
      const recommendedMicrotari = addMicroTari(microtari, FEE_ESTIMATE_ALLOWANCE_UNITS);
      const recommendedTari = displayTari(recommendedMicrotari);
      // Reject before any transaction request is created when the required fee
      // already exceeds the authorized cap.
      const overCap = isMicroTariAbove(microtari, String(ANCHOR_MAX_FEE_UNITS));
      const estimateLine = element(
        "p",
        `Estimated transaction fee: ${tari} TARI · Allowance-adjusted minimum: ${recommendedTari} TARI · Maximum authorized fee: ${maxFeeTari} TARI · Release fee ceiling: ${ceilingTari} TARI`,
      );
      card.append(estimateLine);
      if (overCap) {
        const warn = element(
          "p",
          `Warning: the estimated fee (${tari} TARI) exceeds the maximum authorized fee (${maxFeeTari} TARI). No transaction request will be created; raise the cap deliberately before proceeding.`,
        );
        warn.className = "error";
        warn.setAttribute("role", "alert");
        card.append(warn);
      } else {
        const okNote = element(
          "p",
          `The estimate is within the authorized cap (${maxFeeTari} TARI). The allowance-adjusted minimum (${recommendedTari} TARI) is the recommended max_fee for a funded transaction.`,
        );
        okNote.className = "form-hint";
        card.append(okNote);
      }
      const caveat = element(
        "p",
        "This estimate is a quote only. It does not prove a funded transaction will succeed, and it does not independently prove the wallet enforces the maximum fee — the provider exposes no fee read-back.",
      );
      caveat.className = "form-hint";
      card.append(caveat);
    } else if (feeEstimate.kind === "unsupported") {
      const unsupported = element(
        "p",
        `Fee estimate unavailable: ${feeEstimate.reason}. No estimate is shown; this is not a zero fee.`,
      );
      unsupported.className = "form-hint";
      card.append(unsupported);
    } else if (feeEstimate.kind === "error") {
      const error = element("p", `Fee estimate failed: ${feeEstimate.message}`);
      error.className = "error";
      card.append(error);
    }

    const state = element("p", status);
    state.setAttribute("role", "status");
    card.append(state);
    const explorerUrl = recovery?.transactionId ? mainnetTransactionExplorerUrl(recovery.transactionId) : null;
    if (explorerUrl !== null && recovery?.transactionId) {
      const link = element("a", `View transaction ${recovery.transactionId.slice(0, 16)}… on the Tari Mainnet explorer`);
      link.href = explorerUrl;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      card.append(link);
    }
    const actions = element("div");
    actions.className = "action-row";
    const readyToConnect = !!validatedBundle && deploymentError() === null;
    actions.append(action("Connect Sapient", () => connect("sapient"), busy || !readyToConnect));
    actions.append(action("Connect Tari Universe", () => connect("universe"), busy || !readyToConnect));
    // Fee preflight is available whenever a Mainnet wallet is connected and the
    // deployment is valid, even while Mainnet submission is disabled. It never
    // creates a request, waits for approval, or submits.
    if (validatedBundle && wallet && deploymentError() === null) {
      actions.append(action("Estimate Mainnet Fee", () => estimateFee(), busy));
    }
    if (recoveryState.kind === "corrupt") {
      const error = element("p", `${recoveryState.message}. Treat this as ambiguous; browser publishing is blocked.`);
      error.className = "error";
      card.append(error);
    } else if (recovery) {
      actions.append(action("Check saved request / transaction", checkRecovery, busy));
    } else if (validatedBundle && wallet && deploymentError() === null && submissionDisabledReason() === null) {
      const phase = assessAnchorWorkflow({ bundle: validatedBundle.bundle, bundleInvalidReason: null, walletConnected: true, walletNetworkName: wallet.network, recovery: null });
      if (phase.kind === "ready") actions.append(action("Ask wallet to publish anchor", publish, busy));
    }
    const note = element("p", "The connector validates its parent by source and uses a wildcard postMessage target. The Worker-delivered frame-ancestors response header is therefore the boundary that limits embedding to Web Tari Universe.");
    note.className = "form-hint";
    card.append(actions);
    card.append(note);
    root.append(card);

    // Bind controls after render.
    root.querySelector<HTMLButtonElement>("#load-election-btn")?.addEventListener("click", () => void loadPayload());
    const ack = root.querySelector<HTMLInputElement>("#ack-reduced-anonymity");
    if (ack) {
      ack.checked = acknowledgeReducedAnonymity;
      ack.addEventListener("change", () => {
        acknowledgeReducedAnonymity = ack.checked;
        invalidateFeeEstimate();
        if (validatedBundle) {
          status = "Acknowledgement changed. Reload the anchor payload to apply it.";
          render();
        }
      });
    }
  }

  render();
}

// Module entrypoint: mount into #app when this script is loaded by the browser.
// The guard keeps the module importable by the Node test runner, which installs
// a DOM only inside individual tests.
const root = typeof document === "undefined" ? null : document.getElementById("app");
if (root !== null) {
  mountAnchorPanel(root);
}