import type {
  CreateTransactionRequestResult,
  ProviderKind,
  SubmitTransactionRequestResult,
  TariCapabilities,
  TariNetworkAnswer,
  TariProviderLike,
  TransactionRequestStatus,
  TransactionRequestSummary,
  WalletProbeOutcome,
} from "./types.ts";
import {
  describeProviderError,
  providerErrorCode,
  providerErrorMessage,
} from "./errors.ts";

const TERMINAL_STATUSES: readonly TransactionRequestStatus[] = [
  "approved",
  "submitted",
  "rejected",
  "failed",
];

export interface ProviderDiscoveryResult {
  provider: TariProviderLike | null;
  reason: string | null;
}

/** Globals exposed by Sapient and the reviewed Tari Universe connector. */
export interface TariProviderScope {
  tari?: unknown;
  tariUniverse?: unknown;
  tariProviders?: unknown;
}

export interface WindowTariProvider {
  kind: ProviderKind;
  label: string;
  probe(): Promise<WalletProbeOutcome>;
  connect(): Promise<string[]>;
  getNetwork(): Promise<TariNetworkAnswer>;
  getCapabilities(): Promise<TariCapabilities>;
  createTransactionRequest(
    instructions: unknown,
    maxFee?: unknown,
  ): Promise<CreateTransactionRequestResult>;
  pollTransactionRequest(
    requestId: string,
    options?: PollOptions,
  ): Promise<TransactionRequestSummary>;
  submitTransactionRequest(
    requestId: string,
  ): Promise<SubmitTransactionRequestResult>;
  getTransactionResult(transactionId: string): Promise<unknown>;
  onAccountsChanged(listener: (accounts: unknown) => void): void;
}

export interface PollOptions {
  intervalMs?: number;
  timeoutMs?: number;
  sleep?: (ms: number) => Promise<void>;
}

export const DEFAULT_POLL_INTERVAL_MS = 1000;
export const DEFAULT_POLL_TIMEOUT_MS = 10 * 60 * 1000;
export const TARI_INIT_TIMEOUT_MS = 1500;

export class WalletProviderError extends Error {
  readonly code: number | null;

  constructor(message: string, code: number | null) {
    super(message);
    this.name = "WalletProviderError";
    this.code = code;
  }
}

function throwProviderError(error: unknown, context: string): never {
  const code = providerErrorCode(error);
  const detail = providerErrorMessage(error) || context;
  const described = describeProviderError(code, detail);
  const message = described === detail ? described : `${described} (${detail})`;
  throw new WalletProviderError(message, code);
}

function expectRecordSafe(
  value: unknown,
): Record<string, unknown> | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

export function expectRecord(value: unknown, context: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new WalletProviderError(`the wallet returned a malformed ${context}`, null);
  }
  return value as Record<string, unknown>;
}

export function expectString(value: unknown, context: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new WalletProviderError(`the wallet returned a malformed ${context}`, null);
  }
  return value;
}

export function asTransactionRequestStatus(
  value: unknown,
): TransactionRequestStatus | null {
  return value === "pending" ||
    value === "approved" ||
    value === "submitting" ||
    value === "submitted" ||
    value === "rejected" ||
    value === "failed"
    ? value
    : null;
}

export function sleepWithTimeout(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function windowTariProvider(
  kind: ProviderKind,
  label: string,
  discover: () => ProviderDiscoveryResult,
): WindowTariProvider {
  function get(): TariProviderLike {
    const found = discover();
    if (!found.provider) {
      throw new WalletProviderError(
        found.reason || "the wallet is not reachable from this page",
        null,
      );
    }
    return found.provider;
  }

  return {
    kind,
    label,
    async probe(): Promise<WalletProbeOutcome> {
      let provider: TariProviderLike | null = null;
      let discoveryReason: string | null = null;
      try {
        const found = discover();
        provider = found.provider;
        discoveryReason = found.reason;
      } catch (e) {
        discoveryReason = providerErrorMessage(e);
      }
      if (!provider) {
        return {
          available: false,
          state: "unavailable",
          unavailableReason: discoveryReason || "no Tari wallet answered on this page",
          unusableReason: null,
          capabilities: null,
        };
      }
      let answer: unknown;
      try {
        answer = await provider.request({ method: "tari_getCapabilities" });
      } catch (e) {
        const code = providerErrorCode(e);
        if (code === 4100) {
          return {
            available: true,
            state: "needs_connect",
            unavailableReason: null,
            unusableReason:
              "the wallet is not connected to this site yet — press Connect wallet to authorize it",
            capabilities: null,
          };
        }
        return {
          available: false,
          state: code === 4200 || code === -32601 ? "unsupported" : "unavailable",
          unavailableReason: describeProviderError(
            code,
            `tari_getCapabilities failed (${providerErrorMessage(e)})`,
          ),
          unusableReason: null,
          capabilities: null,
        };
      }
      const record = expectRecordSafe(answer);
      if (!record) {
        return {
          available: false,
          state: "unavailable",
          unavailableReason: "the wallet returned a malformed capabilities answer",
          unusableReason: null,
          capabilities: null,
        };
      }
      const list = record.capabilities;
      if (!Array.isArray(list) || !list.every((c) => typeof c === "string")) {
        return {
          available: false,
          state: "unavailable",
          unavailableReason: "the wallet returned a malformed capabilities answer",
          unusableReason: null,
          capabilities: null,
        };
      }
      return {
        available: true,
        state: "available",
        unavailableReason: null,
        unusableReason: null,
        capabilities: { capabilities: list as string[] },
      };
    },
    async connect(): Promise<string[]> {
      const provider = get();
      let answer: unknown;
      try {
        answer = await provider.request({ method: "tari_requestAccounts" });
      } catch (e) {
        throwProviderError(e, "connect");
      }
      if (!Array.isArray(answer) || !answer.every((a) => typeof a === "string" && a.length > 0)) {
        throw new WalletProviderError(
          "the wallet returned a malformed accounts answer",
          null,
        );
      }
      return answer as string[];
    },
    async getNetwork(): Promise<TariNetworkAnswer> {
      const provider = get();
      let answer: unknown;
      try {
        answer = await provider.request({ method: "tari_getNetwork" });
      } catch (e) {
        throwProviderError(e, "network check");
      }
      const record = expectRecord(answer, "network answer");
      const network = expectString(record.network, "network answer");
      return { network };
    },
    async getCapabilities(): Promise<TariCapabilities> {
      const provider = get();
      let answer: unknown;
      try {
        answer = await provider.request({ method: "tari_getCapabilities" });
      } catch (e) {
        throwProviderError(e, "capabilities");
      }
      const record = expectRecord(answer, "capabilities answer");
      const list = record.capabilities;
      if (!Array.isArray(list) || !list.every((c) => typeof c === "string")) {
        throw new WalletProviderError(
          "the wallet returned a malformed capabilities answer",
          null,
        );
      }
      return { capabilities: list as string[] };
    },
    async createTransactionRequest(
      instructions: unknown,
      maxFee?: unknown,
    ): Promise<CreateTransactionRequestResult> {
      const provider = get();
      const params: Record<string, unknown> = {
        kind: "instructions",
        instructions,
      };
      if (maxFee !== undefined) {
        params.maxFee = maxFee;
      }
      let answer: unknown;
      try {
        answer = await provider.request({
          method: "tari_createTransactionRequest",
          params,
        });
      } catch (e) {
        throwProviderError(e, "create transaction request");
      }
      const record = expectRecord(answer, "transaction request answer");
      const requestId = expectString(record.requestId, "transaction request answer");
      return { requestId };
    },
    async pollTransactionRequest(
      requestId,
      options: PollOptions = {},
    ): Promise<TransactionRequestSummary> {
      const provider = get();
      const intervalMs = options.intervalMs ?? DEFAULT_POLL_INTERVAL_MS;
      const timeoutMs = options.timeoutMs ?? DEFAULT_POLL_TIMEOUT_MS;
      const sleep = options.sleep ?? sleepWithTimeout;
      const deadline = Date.now() + timeoutMs;
      for (;;) {
        let answer: unknown;
        try {
          answer = await provider.request({
            method: "tari_getTransactionRequest",
            params: { requestId },
          });
        } catch (e) {
          throwProviderError(e, "transaction request status");
        }
        const record = expectRecord(answer, "transaction request status");
        const status = asTransactionRequestStatus(record.status);
        if (status === null) {
          throw new WalletProviderError(
            "the wallet returned a malformed transaction request status",
            null,
          );
        }
        const summary: TransactionRequestSummary = {
          status,
          result: record.result,
          error: record.error,
        };
        if (TERMINAL_STATUSES.includes(summary.status)) {
          return summary;
        }
        if (Date.now() > deadline) {
          throw new WalletProviderError(
            `the wallet did not settle request ${requestId} within the allotted time; check the wallet's history before trying again`,
            null,
          );
        }
        await sleep(intervalMs);
      }
    },
    async submitTransactionRequest(
      requestId,
    ): Promise<SubmitTransactionRequestResult> {
      const provider = get();
      let answer: unknown;
      try {
        answer = await provider.request({
          method: "tari_submitTransactionRequest",
          params: { requestId },
        });
      } catch (e) {
        throwProviderError(e, "submit");
      }
      const record = expectRecord(answer, "submit answer");
      const transactionId = expectString(record.transactionId, "submit answer");
      return { transactionId };
    },
    async getTransactionResult(transactionId: string): Promise<unknown> {
      const provider = get();
      try {
        return await provider.request({
          method: "tari_getTransactionResult",
          params: { transactionId },
        });
      } catch (e) {
        throwProviderError(e, "transaction result lookup");
      }
    },
    onAccountsChanged(listener: (accounts: unknown) => void): void {
      get().on?.("accountsChanged", listener);
    },
  };
}

export function hasCapability(
  capabilities: TariCapabilities | null,
  name: string,
): boolean {
  return !!capabilities && capabilities.capabilities.includes(name);
}

function asTariProvider(candidate: unknown): TariProviderLike | null {
  if (
    typeof candidate !== "object" ||
    candidate === null ||
    (candidate as TariProviderLike).isTariWallet !== true
  ) {
    return null;
  }
  return candidate as TariProviderLike;
}

function isUniverseBridge(provider: TariProviderLike): boolean {
  return provider.info?.rdns === "mw.tari.universe";
}

function universeCandidates(scope: TariProviderScope): TariProviderLike[] {
  const candidates: unknown[] = [scope.tariUniverse];
  if (Array.isArray(scope.tariProviders)) candidates.push(...scope.tariProviders);
  candidates.push(scope.tari);
  const unique: TariProviderLike[] = [];
  for (const candidate of candidates) {
    const provider = asTariProvider(candidate);
    if (provider && !unique.includes(provider)) unique.push(provider);
  }
  return unique;
}

export function sapientDiscovery(scope: TariProviderScope): ProviderDiscoveryResult {
  const candidate = scope.tari;
  const provider = asTariProvider(candidate);
  // In a normal tab the reviewed Universe connector intentionally does not
  // displace Sapient. If no extension owns `window.tari`, the connector's
  // non-embedded bridge must not be misidentified as a usable extension.
  if (provider && !provider.isEmbedded && !isUniverseBridge(provider)) {
    return { provider, reason: null };
  }
  return {
    provider: null,
    reason:
      "No Tari wallet answered on this page. Install the Sapient extension, or open this dApp inside Tari Universe at universe.tari.mw.",
  };
}

export function universeDiscovery(scope: TariProviderScope): ProviderDiscoveryResult {
  // In an embedded page the connector intentionally owns `window.tari`, but
  // a non-writable extension injection can keep that name. The reviewed
  // connector publishes both a named fallback and a registry, so prefer those
  // before considering the contested global.
  const provider = universeCandidates(scope).find((candidate) => candidate.isEmbedded === true);
  if (provider) return { provider, reason: null };

  const candidate = asTariProvider(scope.tari);
  if (!candidate && universeCandidates(scope).length === 0) {
    return {
      provider: null,
      reason:
        "Not running inside Tari Universe. Open this dApp from its app catalogue at universe.tari.mw; in a plain tab its provider is unreachable by design.",
    };
  }
  return {
    provider: null,
    reason:
      "A Tari wallet is present but this page is not running inside it. Open this dApp from Tari Universe's app catalogue instead of a browser tab.",
  };
}

export function waitForTariInit(scope: {
  addEventListener?: (type: string, listener: () => void) => unknown;
}, timeoutMs: number = TARI_INIT_TIMEOUT_MS): Promise<boolean> {
  const addEventListener = scope.addEventListener;
  if (typeof addEventListener !== "function") {
    return Promise.resolve(false);
  }
  return new Promise((resolve) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        resolve(false);
      }
    }, timeoutMs);
    addEventListener.call(scope, "tari#initialized", () => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve(true);
      }
    });
  });
}
