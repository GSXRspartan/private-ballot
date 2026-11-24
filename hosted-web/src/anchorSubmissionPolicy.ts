import {
  addMicroTari,
  formatTariFromMicroTari,
  isMicroTariAbove,
  normalizeMicroTari,
} from "../../gui/src/wallet/feeFormat.ts";
import type { DryRunFeeEstimate } from "../../gui/src/wallet/types.ts";
import type { PublishDriver } from "../../gui/src/anchor/browserAnchorPublish.ts";

function displayTari(microtari: unknown): string {
  return formatTariFromMicroTari(microtari) ?? "?";
}

export const ANCHOR_MAX_FEE_UNITS = 5000;

export const ANCHOR_MAX_FEE_CEILING_UNITS = 10_000_000;

export const FEE_ESTIMATE_ALLOWANCE_UNITS = 12;

if (ANCHOR_MAX_FEE_UNITS < 1 || ANCHOR_MAX_FEE_UNITS > ANCHOR_MAX_FEE_CEILING_UNITS) {
  throw new Error("the configured anchor fee cap is outside the release ceiling");
}

export type FeePreflightDecision =
  | {
      ok: true;
      requiredFeesMicrotari: string;
      recommendedMaxFeeMicrotari: string;
    }
  | {
      ok: false;
      reason: string;
      requiredFeesMicrotari?: string;
      recommendedMaxFeeMicrotari?: string;
    };

export function evaluateFeePreflight(
  estimate: DryRunFeeEstimate,
  maxFeeUnits: number = ANCHOR_MAX_FEE_UNITS,
): FeePreflightDecision {
  if (estimate.kind !== "estimated") {
    return {
      ok: false,
      reason: `The non-spending fee preflight is unavailable: ${estimate.reason}. No transaction request was created.`,
    };
  }
  const required = normalizeMicroTari(estimate.requiredFeesMicrotari);
  if (required === null) {
    return {
      ok: false,
      reason: "The non-spending fee preflight returned a malformed fee. No transaction request was created.",
    };
  }
  const recommended = addMicroTari(required, FEE_ESTIMATE_ALLOWANCE_UNITS);
  if (recommended === null) {
    return {
      ok: false,
      requiredFeesMicrotari: required,
      reason: "The non-spending fee preflight could not compute the allowance-adjusted minimum. No transaction request was created.",
    };
  }
  const cap = String(maxFeeUnits);
  if (isMicroTariAbove(required, cap)) {
    return {
      ok: false,
      requiredFeesMicrotari: required,
      recommendedMaxFeeMicrotari: recommended,
      reason: `The estimated fee (${displayTari(required)} TARI) exceeds the maximum authorized fee (${displayTari(cap)} TARI). No transaction request was created.`,
    };
  }
  if (isMicroTariAbove(recommended, cap)) {
    return {
      ok: false,
      requiredFeesMicrotari: required,
      recommendedMaxFeeMicrotari: recommended,
      reason: `The allowance-adjusted minimum fee (${displayTari(recommended)} TARI) exceeds the maximum authorized fee (${displayTari(cap)} TARI). No transaction request was created.`,
    };
  }
  return {
    ok: true,
    requiredFeesMicrotari: required,
    recommendedMaxFeeMicrotari: recommended,
  };
}

export const MAINNET_ANCHOR_SUBMISSION_ENABLED = true;

export function submissionGateReason(enabled: boolean): string | null {
  if (enabled) return null;
  return "Mainnet publishing not yet enabled. Payloads, previews, wallet connection, and network/capability checks stay available; no transaction request can be created, approved, or submitted from this page.";
}

export function submissionDisabledReason(): string | null {
  return submissionGateReason(MAINNET_ANCHOR_SUBMISSION_ENABLED);
}

export function createGuardedPublishDriver(
  base: PublishDriver,
  enabled: boolean,
): PublishDriver {
  const guard = (): void => {
    const reason = submissionGateReason(enabled);
    if (reason !== null) throw new Error(reason);
  };
  return {
    ...base,
    createRequest: (adapter, bundle, maxFee) => {
      guard();
      return base.createRequest(adapter, bundle, maxFee);
    },
    waitForApproval: (adapter, requestId, timeoutMs) => {
      guard();
      return base.waitForApproval(adapter, requestId, timeoutMs);
    },
    submit: (adapter, requestId) => {
      guard();
      return base.submit(adapter, requestId);
    },
  };
}
