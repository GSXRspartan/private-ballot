import type { AnchorBundleV1, AnchorBundleInvalid } from "./anchorBundle.ts";
import {
  bundleAnchorArgsAsLiterals,
  buildAnchorInstructions,
} from "./anchorBundle.ts";
import {
  anchorDeploymentConfig,
  deploymentForNetwork,
  mainnetPublishBlocker,
  type AnchorDeploymentConfig,
} from "./anchorDeploymentConfig.ts";
import { networkVerdict } from "./network.ts";
import type { AnchorRecoveryRecord } from "./recoveryStore.ts";
import type { VerifiedAnchorEvidence } from "./verifyReceipt.ts";

export type AnchorWorkflowPhase =
  | { kind: "no_bundle" }
  | { kind: "bundle_invalid"; reason: AnchorBundleInvalid }
  | { kind: "mainnet_disabled" }
  | { kind: "deployment_mismatch"; message: string }
  | { kind: "wallet_required" }
  | { kind: "wallet_network_mismatch"; message: string }
  | { kind: "ready" }
  | { kind: "awaiting_approval"; requestId: string }
  | { kind: "submission_unknown"; requestId: string }
  | { kind: "submitted"; transactionId: string }
  | { kind: "verifying"; transactionId: string }
  | { kind: "verified"; evidence: VerifiedAnchorEvidence }
  | { kind: "failed_no_publish"; message: string };

export interface AnchorWorkflowInput {
  bundle: AnchorBundleV1 | null;
  bundleInvalidReason: AnchorBundleInvalid | null;
  walletConnected: boolean;
  walletNetworkName: string | null;
  recovery: AnchorRecoveryRecord | null;
  config?: AnchorDeploymentConfig;
}

export function assessAnchorWorkflow(
  input: AnchorWorkflowInput,
): AnchorWorkflowPhase {
  if (input.bundleInvalidReason !== null) {
    return { kind: "bundle_invalid", reason: input.bundleInvalidReason };
  }
  if (input.bundle === null) {
    return { kind: "no_bundle" };
  }
  if (input.recovery !== null) {
    return resumePhase(input.recovery);
  }
  const config = input.config ?? anchorDeploymentConfig();
  const blocker = mainnetPublishBlocker(config);
  if (input.bundle.network === "mainnet" && blocker !== null) {
    return { kind: "mainnet_disabled" };
  }
  const deployment = deploymentForNetwork(config, input.bundle.network);
  if (deployment === null) {
    return {
      kind: "deployment_mismatch",
      message: `no anchor deployment is configured for network "${input.bundle.network}"`,
    };
  }
  const mismatch = deploymentMismatchMessage(input.bundle, deployment);
  if (mismatch !== null) {
    return { kind: "deployment_mismatch", message: mismatch };
  }
  if (!input.walletConnected || input.walletNetworkName === null) {
    return { kind: "wallet_required" };
  }
  const verdict = networkVerdict(input.bundle.network, input.walletNetworkName);
  if (verdict.kind !== "match") {
    return {
      kind: "wallet_network_mismatch",
      message:
        "the connected wallet is not on the same Ootle network as this anchor deployment",
    };
  }
  return { kind: "ready" };
}

function resumePhase(recovery: AnchorRecoveryRecord): AnchorWorkflowPhase {
  switch (recovery.phase) {
    case "verified":
    case "approved_submitted":
    case "verifying":
      // Even a locally-verified record is re-verified against the chain after
      // a reload (the desktop lifecycle re-fetches the receipt on resume too);
      // no phase ever trusts local state alone.
      return recovery.transactionId === null
        ? { kind: "failed_no_publish", message: "the saved anchor state is incomplete" }
        : { kind: "verifying", transactionId: recovery.transactionId };
    case "submitted_awaiting_approval":
      return recovery.requestId === null
        ? { kind: "failed_no_publish", message: "the saved anchor state is incomplete" }
        : { kind: "awaiting_approval", requestId: recovery.requestId };
    case "submit_in_flight":
      return recovery.requestId === null
        ? { kind: "failed_no_publish", message: "the saved anchor state is incomplete" }
        : { kind: "submission_unknown", requestId: recovery.requestId };
  }
}

function deploymentMismatchMessage(
  bundle: AnchorBundleV1,
  deployment: {
    address: string;
    module: string;
    function: string;
    eventTopic: string;
    artifactDigestHex: string;
  },
): string | null {
  if (bundle.template.address !== deployment.address) {
    return "the bundle's template address does not match the configured anchor deployment";
  }
  if (bundle.template.module !== deployment.module) {
    return "the bundle's template module does not match the configured anchor deployment";
  }
  if (bundle.template.function !== deployment.function) {
    return "the bundle's template function does not match the configured anchor deployment";
  }
  if (bundle.template.eventTopic !== deployment.eventTopic) {
    return "the bundle's event topic does not match the configured anchor deployment";
  }
  if (bundle.template.artifactDigestHex !== deployment.artifactDigestHex) {
    return "the bundle's template artifact digest does not match the configured anchor deployment";
  }
  return null;
}

export function bundleLiteralArgs(bundle: AnchorBundleV1): string[] {
  return bundleAnchorArgsAsLiterals(bundle);
}

export function workflowInstructions(bundle: AnchorBundleV1): unknown[] {
  return buildAnchorInstructions(bundle);
}

export function phaseLabel(phase: AnchorWorkflowPhase): string {
  switch (phase.kind) {
    case "no_bundle":
      return "Import the anchor bundle exported by the desktop application to enable browser publishing.";
    case "bundle_invalid":
      return "The imported anchor bundle is not valid. Re-export it from the desktop application.";
    case "mainnet_disabled":
      return "Mainnet anchor publishing is disabled in this build until a configured mainnet template address is released.";
    case "deployment_mismatch":
      return `${phase.message}. Publishing is blocked.`;
    case "wallet_required":
      return "Connect a Tari wallet in Settings first.";
    case "wallet_network_mismatch":
      return `${phase.message}. Publishing is blocked.`;
    case "ready":
      return "The wallet can be asked to review and approve the anchor transaction.";
    case "awaiting_approval":
      return "Waiting for the wallet to approve the anchor transaction.";
    case "submission_unknown":
      return "The saved request may have been submitted. Check the wallet history; it will never be submitted again automatically.";
    case "submitted":
      return "Submitted to the network. Waiting for finalization.";
    case "verifying":
      return "Verifying the on-chain anchor event against this election.";
    case "verified":
      return "The on-chain anchor matches this election. The anchor is published.";
    case "failed_no_publish":
      return `${phase.message} Nothing was resubmitted; check the wallet history before trying again.`;
  }
}
