/**
 * Hosted browser publishing for the canonical public V2 anchor bundle.
 * Desktop creates the bundle after archive verification; this code neither
 * recreates its arguments nor stores organizer or voter material.
 */
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
import type { TariCapabilities, TransactionRequestSummary } from "../../gui/src/wallet/types.ts";
import {
  adapterForKind,
  defaultPublishDriver,
  providerErrorMessage,
  type BrowserWalletKind,
} from "../../gui/src/anchor/browserAnchorPublish.ts";
import { formatTariFromMicroTari } from "../../gui/src/wallet/feeFormat.ts";
import {
  ANCHOR_MAX_FEE_CEILING_UNITS,
  ANCHOR_MAX_FEE_UNITS,
  createGuardedPublishDriver,
  evaluateFeePreflight,
  MAINNET_ANCHOR_SUBMISSION_ENABLED,
  submissionDisabledReason,
} from "./anchorSubmissionPolicy.ts";
import type { ManagedFinalizedElectionIdentity } from "./organizer.ts";

const REQUIRED_CAPABILITIES = ["transactionRequests", "transactionResultLookup"] as const;
const VERIFY_ATTEMPTS = 30;
const VERIFY_INTERVAL_MS = 4000;
const APPROVAL_TIMEOUT_MS = 10 * 60 * 1000;
const TRANSACTION_ID = /^[0-9a-f]{64}$/;

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

function displayTari(microtari: unknown): string {
  return formatTariFromMicroTari(microtari) ?? "—";
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

/** Mounts only after the existing organizer lifecycle has finalized the election. */
export function mountBrowserAnchorPanel(root: HTMLElement, managedElection: ManagedFinalizedElectionIdentity): void {
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
  const driver = createGuardedPublishDriver(baseDriver, MAINNET_ANCHOR_SUBMISSION_ENABLED);
  let bundle: AnchorBundleV1 | null = null;
  let bundleError: string | null = null;
  let wallet: WalletConnection | null = null;
  let recovery: AnchorRecoveryRecord | null = null;
  let recoveryState: RecoveryLoadState = { kind: "absent" };
  let status = "Import the canonical bundle exported by the desktop application.";
  let busy = false;
  let bundleGeneration = 0;

  const bundleKey = () => {
    if (!bundle) throw new Error("Import the canonical bundle first.");
    return bundleDigestKey(bundle);
  };
  const loadRecovery = () => {
    recoveryState = bundle === null ? { kind: "absent" } : store.loadState(bundleDigestKey(bundle));
    recovery = recoveryState.kind === "record" ? recoveryState.record : null;
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
      // The write has completed and this record can only resolve the exact
      // transaction id. Releasing this mutation lease cannot enable another
      // create or submit, but allows a reloaded panel to verify immediately.
      store.releaseSubmittedRecoveryLease(key, ownerToken);
    }
    return saved;
  };
  const assertBundleSnapshot = (snapshot: AnchorBundleV1, generation: number) => {
    if (bundle !== snapshot || bundleGeneration !== generation) {
      throw new Error("The imported bundle changed. Import it again before publishing.");
    }
  };
  const bundleIdentityError = (): string | null => {
    if (!bundle) return "Import the canonical bundle first.";
    try {
      const summary = parseCanonicalPublicSummaryV2(bundle.anchorArgs.publicSummary);
      const sameTemplate = summary.template.address === bundle.template.address &&
        summary.template.module === bundle.template.module &&
        summary.template.function === bundle.template.function &&
        canonicalEventTopicFromBindingTopic(summary.template.eventTopic) === bundle.template.eventTopic &&
        summary.template.artifactDigestHex === bundle.template.artifactDigestHex;
      if (bundle.network !== bundle.anchorArgs.network || summary.network !== bundle.network) {
        return "The outer, event, and canonical-summary networks must agree.";
      }
      if (bundle.anchorArgs.electionId !== summary.electionId || summary.electionId !== managedElection.electionId) {
        return "The bundle does not belong to this finalized managed election.";
      }
      if (summary.archiveHashHex !== managedElection.archiveHashHex) {
        return "The bundle's finalized archive identity does not match this managed election.";
      }
      if (bundle.anchorArgs.anchorDigestHex !== managedElection.anchorDigestHex) {
        return "The bundle's anchor digest does not match the native finalized election identity.";
      }
      if (bundle.anchorArgs.publicSummary !== managedElection.publicSummary) {
        return "The bundle's canonical public summary does not match the native finalized election identity.";
      }
      if (!sameTemplate) return "The canonical public summary does not bind this deployment identity.";
      return null;
    } catch (error) {
      return error instanceof Error ? error.message : "The public summary is invalid.";
    }
  };
  const deploymentError = (): string | null => {
    if (!bundle) return "Import the canonical bundle first.";
    const identity = bundleIdentityError();
    if (identity) return identity;
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
    if (!bundle) throw new Error("Import the canonical bundle first.");
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
      throw new Error("The wallet's authorized account changed. Reconnect before any anchor action.");
    }
    const capabilities = await adapter.getCapabilities();
    const missing = missingCapability(capabilities);
    if (missing) throw new Error(`The wallet does not support required capability ${missing}.`);
    const network = (await adapter.getNetwork()).network;
    if (network !== wallet.network) {
      wallet = null;
      throw new Error("The wallet network changed. Reconnect before any anchor action.");
    }
    if (networkVerdict(bundle.network, network).kind !== "match") {
      throw new Error("The wallet network does not match the bundle network.");
    }
    wallet = { ...wallet, accounts, network, capabilities };
    return adapter;
  }

  async function verifyExisting(
    adapter: WindowTariProvider,
    transactionId: string,
    snapshot: AnchorBundleV1 | null = bundle,
    key: string | null = snapshot ? bundleDigestKey(snapshot) : null,
  ): Promise<void> {
    if (!snapshot) return;
    const recoveryKey = key ?? bundleDigestKey(snapshot);
    status = "Verifying the existing on-chain anchor event…";
    render();
    const outcome = await driver.verify(adapter, snapshot, transactionId);
    if (outcome.kind === "verified") {
      saveOwned("verified", null, transactionId, recoveryKey);
      status = `Verified: the public V2 anchor matches this election (${transactionId.slice(0, 16)}…).`;
    } else if (outcome.kind === "pending") {
      saveOwned("verifying", null, transactionId, recoveryKey);
      status = outcome.detail
        ? `${outcome.detail}. It remains saved for verification and will never be submitted again automatically.`
        : "The transaction is not final yet. It remains saved for verification and will never be submitted again automatically.";
    } else {
      // Preserve the identity after a terminal verification failure so the
      // bundle cannot create another request that could duplicate a spend.
      saveOwned("verifying", null, transactionId, recoveryKey);
      status = `${outcome.message}. The saved transaction remains blocked from resubmission.`;
    }
    loadRecovery();
  }

  async function submitApprovedUnlocked(
    requestId: string,
    snapshot: AnchorBundleV1,
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
      // Account/network are read again after status polling and immediately before submit.
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
    if (busy || !bundle) return;
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
    if (!bundle || !recovery) return;
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
        // A durable request id alone does not prove that this newly connected
        // provider/account owns the original request or its four V2 anchor
        // arguments. The currently supported provider API cannot supply that
        // proof, so remount recovery is deliberately status-only.
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
    busy = true;
    render();
    try {
      if (!bundle || deploymentError() !== null) throw new Error("Import a bundle that matches this finalized election before connecting a wallet.");
      const adapter = adapterForKind(kind, window).pin();
      const accounts = await adapter.connect();
      if (accounts.length === 0) throw new Error("The wallet did not authorize an account.");
      const capabilities = await adapter.getCapabilities();
      const missing = missingCapability(capabilities);
      if (missing) throw new Error(`The wallet does not support required capability ${missing}.`);
      const network = (await adapter.getNetwork()).network;
      wallet = { kind, adapter, accounts, network, capabilities };
      adapter.onAccountsChanged(() => {
        wallet = null;
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
    const snapshot = bundle;
    if (!snapshot || busy) return;
    const key = bundleDigestKey(snapshot);
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

  async function publishUnlocked(snapshot: AnchorBundleV1, key: string, generation: number): Promise<void> {
    assertBundleSnapshot(snapshot, generation);
    const disabled = submissionDisabledReason();
    if (disabled !== null) throw new Error(disabled);
    busy = true;
    render();
    try {
      const adapter = await revalidate(false);
      assertBundleSnapshot(snapshot, generation);
      const phase = assessAnchorWorkflow({
        bundle: snapshot, bundleInvalidReason: null, walletConnected: true, walletNetworkName: wallet?.network ?? null, recovery: null,
      });
      if (phase.kind !== "ready") throw new Error(phaseLabel(phase));

      status = `Running the mandatory non-spending fee preflight (cap ${displayTari(ANCHOR_MAX_FEE_UNITS)} TARI)…`;
      render();
      const estimate = await driver.estimateFee(adapter, snapshot, ANCHOR_MAX_FEE_UNITS);
      assertBundleSnapshot(snapshot, generation);
      const decision = evaluateFeePreflight(estimate, ANCHOR_MAX_FEE_UNITS);
      if (!decision.ok) throw new Error(decision.reason);
      await revalidate(false);
      assertBundleSnapshot(snapshot, generation);
      status = `Fee preflight passed: ${displayTari(decision.requiredFeesMicrotari)} TARI required (${displayTari(decision.recommendedMaxFeeMicrotari)} TARI allowance-adjusted) within the ${displayTari(ANCHOR_MAX_FEE_UNITS)} TARI cap. Waiting for wallet approval…`;
      render();

      const reservation = store.reserve(key, ownerToken);
      if (reservation.kind === "busy") throw new Error("A saved anchor operation already exists. Resolve it before creating another request.");
      if (reservation.kind === "corrupt") throw new Error(`${reservation.message}; no wallet request was created.`);
      if (reservation.kind !== "claimed") throw new Error("The anchor reservation is ambiguous; no wallet request was created.");
      assertBundleSnapshot(snapshot, generation);
      const requestId = await driver.createRequest(adapter, snapshot, ANCHOR_MAX_FEE_UNITS);
      saveOwned("submitted_awaiting_approval", requestId, null, key);
      loadRecovery();
      status = "Waiting for the wallet to approve the saved request…";
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

  async function importBundle(file: File): Promise<void> {
    if (busy) return;
    const generation = ++bundleGeneration;
    bundle = null;
    bundleError = null;
    loadRecovery();
    busy = true;
    render();
    try {
      const text = await file.text();
      if (generation !== bundleGeneration) return;
      try {
        const imported = parseAnchorBundleJson(text);
        bundle = imported;
        const identity = deploymentError();
        if (identity) throw new Error(identity);
        bundleError = null;
        loadRecovery();
        status = recoveryState.kind === "corrupt"
          ? `${recoveryState.message}. The existing state is blocked and cannot be treated as absent.`
          : recovery
          ? "A saved request or transaction identity was loaded. Resolve it before creating anything new."
          : "Bundle imported for this finalized election. Connect a wallet and review the deployment checks.";
      } catch (error) {
        bundle = null;
        recovery = null;
        recoveryState = { kind: "absent" };
        bundleError = error instanceof Error ? error.message : "The bundle file is not valid JSON.";
      }
    } catch (error) {
      bundle = null;
      recovery = null;
      recoveryState = { kind: "absent" };
      bundleError = error instanceof Error ? error.message : "The bundle file could not be read.";
    } finally {
      if (generation === bundleGeneration) {
        busy = false;
        render();
      }
    }
  }

  function render(): void {
    root.replaceChildren();
    const card = element("section");
    card.className = "card browser-anchor-panel";
    card.append(element("h2", "Tari Anchor"));
    card.append(element("p", "Import the canonical bundle exported after the desktop application verified the final archive. This page never rebuilds its anchor arguments."));
    card.append(element("p", `Finalized election: ${managedElection.electionId} · archive ${managedElection.archiveHashHex.slice(0, 16)}… · anchor ${managedElection.anchorDigestHex.slice(0, 16)}…`));
    const label = element("label", "Canonical anchor bundle (JSON)");
    label.htmlFor = "browser-anchor-bundle";
    card.append(label);
    const input = element("input");
    input.id = "browser-anchor-bundle";
    input.type = "file";
    input.accept = ".json,application/json";
    input.disabled = busy;
    input.addEventListener("change", () => {
      const file = input.files?.[0];
      if (file) void importBundle(file);
    });
    card.append(input);
    if (bundleError) {
      const error = element("p", bundleError);
      error.className = "error";
      card.append(error);
    }
    if (bundle) {
      card.append(element("p", `Bundle: ${bundle.network} · ${bundle.template.function} · ${bundle.anchorArgs.anchorDigestHex.slice(0, 16)}…`));
      const deployment = deploymentError();
      if (deployment) {
        const error = element("p", deployment);
        error.className = "error";
        card.append(error);
      }
    }
    if (wallet) card.append(element("p", `Wallet: ${wallet.kind} · ${wallet.network} · ${wallet.accounts.length} authorized account(s)`));
    card.append(element("p", `Fee cap: ${displayTari(ANCHOR_MAX_FEE_UNITS)} TARI (${ANCHOR_MAX_FEE_UNITS} microTARI) | release ceiling: ${displayTari(ANCHOR_MAX_FEE_CEILING_UNITS)} TARI | fresh non-spending preflight required`));
    const disabledReason = submissionDisabledReason();
    if (disabledReason) {
      const error = element("p", disabledReason);
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
    const readyToConnect = !!bundle && deploymentError() === null;
    actions.append(action("Connect Sapient", () => connect("sapient"), busy || !readyToConnect));
    actions.append(action("Connect Tari Universe", () => connect("universe"), busy || !readyToConnect));
    if (recoveryState.kind === "corrupt") {
      const error = element("p", `${recoveryState.message}. Treat this as ambiguous; browser publishing is blocked.`);
      error.className = "error";
      card.append(error);
    } else if (recovery) {
      actions.append(action("Check saved request / transaction", checkRecovery, busy));
    } else if (bundle && wallet && deploymentError() === null && submissionDisabledReason() === null) {
      const phase = assessAnchorWorkflow({ bundle, bundleInvalidReason: null, walletConnected: true, walletNetworkName: wallet.network, recovery: null });
      if (phase.kind === "ready") actions.append(action("Ask wallet to publish anchor", publish, busy));
    }
    card.append(actions);
    const note = element("p", "The connector validates its parent by source and uses a wildcard postMessage target. The Worker-delivered frame-ancestors response header is therefore the boundary that limits embedding to Web Tari Universe.");
    note.className = "form-hint";
    card.append(note);
    root.append(card);
  }

  render();
}
