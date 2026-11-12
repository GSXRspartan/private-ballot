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
import { pollUntilVerified, type VerifyPollOptions } from "../wallet/verifyPoll.ts";
import type { AnchorVerificationOutcome } from "../wallet/verifyReceipt.ts";
import type { AnchorRecoveryStore } from "../wallet/recoveryStore.ts";
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
  createRequest(adapter: WindowTariProvider, bundle: AnchorBundleV1): Promise<string>;
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
}): PublishDriver {
  return {
    connect: (adapter) => adapter.connect(),
    createRequest: (adapter, bundle) =>
      adapter.createTransactionRequest(buildAnchorInstructions(bundle)).then((created) => created.requestId),
    waitForApproval: (adapter, requestId, timeoutMs) =>
      adapter.pollTransactionRequest(requestId, { timeoutMs }),
    submit: async (adapter, requestId) => {
      const submitted = await adapter.submitTransactionRequest(requestId);
      return submitted.transactionId;
    },
    verify: async (adapter, bundle, transactionId) =>
      pollUntilVerified(
        () => adapter.getTransactionResult(transactionId),
        transactionId,
        bundleExpectedTemplate(bundle),
        bundleExpectedPayload(bundle),
        {
          attempts: options.verifyAttempts,
          intervalMs: options.verifyIntervalMs,
        },
      ),
  };
}

export interface RecoveryWriter {
  saveSubmittedAwaitingApproval(requestId: string): void;
  saveApprovedSubmitted(transactionId: string): void;
  clear(): void;
}

export function recoveryWriterFor(
  store: AnchorRecoveryStore,
  bundleKey: string,
): RecoveryWriter {
  return {
    saveSubmittedAwaitingApproval(requestId: string): void {
      store.save(bundleKey, {
        phase: "submitted_awaiting_approval",
        requestId,
        transactionId: null,
        updatedAtMs: Date.now(),
      });
    },
    saveApprovedSubmitted(transactionId: string): void {
      store.save(bundleKey, {
        phase: "approved_submitted",
        requestId: null,
        transactionId,
        updatedAtMs: Date.now(),
      });
    },
    clear(): void {
      store.clear(bundleKey);
    },
  };
}
