export interface TariProviderRequest {
  method: string;
  params?: unknown;
}

export interface TariProviderLike {
  request(args: TariProviderRequest): Promise<unknown>;
  on?(event: string, listener: (payload: unknown) => void): unknown;
  isTariWallet?: boolean;
  isEmbedded?: boolean;
  info?: {
    name?: string;
    rdns?: string;
    embedded?: boolean;
  };
}

export type TransactionRequestStatus =
  | "pending"
  | "approved"
  | "submitting"
  | "submitted"
  | "rejected"
  | "failed";

export interface CreateTransactionRequestResult {
  requestId: string;
}

export interface TransactionRequestSummary {
  status: TransactionRequestStatus;
  result?: unknown;
  error?: unknown;
}

export interface SubmitTransactionRequestResult {
  transactionId: string;
}

export interface TariCapabilities {
  /** Published Sapient / Tari Universe capability response fields. */
  transactionRequests: boolean;
  transactionResultLookup: boolean;
  /**
   * `tari_getCapabilities().dryRunIsLocal` — the wallet's own statement that a
   * `tari_signAndSubmitTransaction { dryRun: true }` call is metered locally and
   * never leaves the wallet. `null`/`undefined` when the wallet did not report
   * the field (older wallets). Optional so existing capability fixtures remain
   * valid; absence is treated as "not advertised".
   */
  dryRunIsLocal?: boolean | null;
}

/**
 * Result of a non-spending dry-run fee preflight.
 *
 * A dry run never prompts and never spends. It returns a wallet-specific result
 * whose fee-estimate representation is NOT part of the published contract, so
 * this type distinguishes a recognized estimate from an honest "unsupported".
 */
export type DryRunFeeEstimate =
  | {
      /** A recognized fee figure, in microtari (µT). */
      kind: "estimated";
      requiredFeesMicrotari: string;
    }
  | {
      /** The wallet answered, but no documented fee-estimate field was found. */
      kind: "unsupported";
      reason: string;
    };

export interface TariNetworkAnswer {
  network: string;
}

export type WalletProbeState = "available" | "needs_connect" | "unavailable" | "unsupported";

export interface WalletProbeOutcome {
  available: boolean;
  state: WalletProbeState;
  unavailableReason: string | null;
  unusableReason: string | null;
  capabilities: TariCapabilities | null;
}

export type ProviderKind = "sapient" | "universe";
