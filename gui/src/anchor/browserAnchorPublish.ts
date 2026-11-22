import type { AnchorBundleV1 } from "../wallet/anchorBundle.ts";
import { buildAnchorInstructions, bundleExpectedPayload, bundleExpectedTemplate } from "../wallet/anchorBundle.ts";
import {
  sapientDiscovery,
  universeDiscovery,
  windowTariProvider,
  WalletProviderError,
  type WindowTariProvider,
} from "../wallet/provider.ts";
import type { TransactionRequestSummary } from "../wallet/types.ts";
import { pollUntilVerified } from "../wallet/verifyPoll.ts";
import type { AnchorVerificationOutcome } from "../wallet/verifyReceipt.ts";
import { newRecoveryOwnerToken, type AnchorRecoveryStore } from "../wallet/recoveryStore.ts";
import type { WalletScope } from "../wallet/browserWalletRuntime.ts";

export type BrowserWalletKind = "sapient" | "universe";

export function adapterForKind(
  kind: BrowserWalletKind,
  scope: WalletScope,
): WindowTariProvider {
  const discover = kind === "sapient" ? sapientDiscovery : universeDiscovery;
  return windowTariProvider(kind, kind === "sapient" ? "Sapient" : "Tari Universe", () =>
    discover(scope),
  );
}

export function providerErrorMessage(error: unknown): string {
  if (error instanceof WalletProviderError) {
    return error.message;
  }
  if (error instanceof Error && error.message.length > 0) {
    return error.message;
  }
  return "the wallet operation failed";
}

export interface PublishDriver {
  connect(adapter: WindowTariProvider): Promise<string[]>;
  /**
   * Creates the wallet transaction request.
   *
   * `maxFee` is the hard fee ceiling, in fee units, that the page authorizes.
   * It is forwarded to the wallet as the `maxFee` request parameter so the
   * wallet — not the page — enforces the cap. Callers that omit it inherit the
   * wallet default, which this project never does for Mainnet anchors.
   */
  createRequest(
    adapter: WindowTariProvider,
    bundle: AnchorBundleV1,
    maxFee?: number,
  ): Promise<string>;
  waitForApproval(
    adapter: WindowTariProvider,
    requestId: string,
    timeoutMs?: number,
  ): Promise<TransactionRequestSummary>;
  submit(adapter: WindowTariProvider, requestId: string): Promise<string>;
  verify(
    adapter: WindowTariProvider,
    bundle: AnchorBundleV1,
    transactionId: string,
  ): Promise<AnchorVerificationOutcome>;
}

export function defaultPublishDriver(options: {
  verifyAttempts: number;
  verifyIntervalMs: number;
  verifyWithEvidence?: (
    adapter: WindowTariProvider,
    bundle: AnchorBundleV1,
    transactionId: string,
  ) => Promise<AnchorVerificationOutcome>;
}): PublishDriver {
  return {
    connect: (adapter) => adapter.connect(),
    createRequest: (adapter, bundle, maxFee) =>
      adapter
        // The wallet API schema types maxFee as a decimal string (see
        // docs/tari/wallet-integration.md and the official Tari integration
        // reference). Callers pass a numeric cap; send the documented string
        // form so the wallet enforces it as specified.
        .createTransactionRequest(
          buildAnchorInstructions(bundle),
          maxFee === undefined ? undefined : String(maxFee),
        )
        .then((created) => created.requestId),
    waitForApproval: (adapter, requestId, timeoutMs) =>
      adapter.pollTransactionRequest(requestId, { timeoutMs }),
    submit: async (adapter, requestId) => {
      const submitted = await adapter.submitTransactionRequest(requestId);
      return submitted.transactionId;
    },
    verify: async (adapter, bundle, transactionId) => {
      if (options.verifyWithEvidence) {
        for (let attempt = 0; attempt < options.verifyAttempts; attempt += 1) {
          let outcome: AnchorVerificationOutcome;
          try {
            outcome = await options.verifyWithEvidence(adapter, bundle, transactionId);
          } catch {
            outcome = { kind: "pending" };
          }
          if (outcome.kind !== "pending") return outcome;
          if (attempt + 1 < options.verifyAttempts) {
            await new Promise<void>((resolve) => setTimeout(resolve, options.verifyIntervalMs));
          }
        }
        return { kind: "pending" };
      }
      return pollUntilVerified(
        () => adapter.getTransactionResult(transactionId),
        transactionId,
        bundleExpectedTemplate(bundle),
        bundleExpectedPayload(bundle),
        {
          attempts: options.verifyAttempts,
          intervalMs: options.verifyIntervalMs,
        },
      );
    },
  };
}

export interface RecoveryWriter {
  saveSubmittedAwaitingApproval(requestId: string): void;
  saveSubmitInFlight(requestId: string): void;
  saveApprovedSubmitted(transactionId: string): void;
  saveVerified(transactionId: string): void;
  clear(): void;
}

export function recoveryWriterFor(
  store: AnchorRecoveryStore,
  bundleKey: string,
): RecoveryWriter {
  const ownerToken = newRecoveryOwnerToken();
  const record = (
    phase: "submitted_awaiting_approval" | "submit_in_flight" | "approved_submitted" | "verified",
    requestId: string | null,
    transactionId: string | null,
  ) => ({
    phase,
    requestId,
    transactionId,
    ownerToken,
    leaseExpiresAtMs: Date.now() + 5 * 60 * 1000,
    updatedAtMs: Date.now(),
  });
  return {
    saveSubmittedAwaitingApproval(requestId: string): void {
      store.save(bundleKey, record("submitted_awaiting_approval", requestId, null));
    },
    saveSubmitInFlight(requestId: string): void {
      store.save(bundleKey, record("submit_in_flight", requestId, null));
    },
    saveApprovedSubmitted(transactionId: string): void {
      store.save(bundleKey, record("approved_submitted", null, transactionId));
    },
    saveVerified(transactionId: string): void {
      store.save(bundleKey, record("verified", null, transactionId));
    },
    clear(): void {
      store.clear(bundleKey);
    },
  };
}
