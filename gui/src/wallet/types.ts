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
  capabilities: string[];
}

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
