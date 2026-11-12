import type { ProviderKind, WalletProbeOutcome } from "./types.ts";

export type WalletEntryPhase =
  | { kind: "idle" }
  | { kind: "checking" }
  | { kind: "absent"; reason: string }
  | { kind: "ready" }
  | { kind: "needs_connect" }
  | { kind: "unsupported"; reason: string }
  | { kind: "unavailable"; reason: string }
  | { kind: "connecting" }
  | { kind: "connected"; network: string | null }
  | { kind: "connect_failed"; message: string };

export interface WalletEntry {
  kind: ProviderKind;
  label: string;
  phase: WalletEntryPhase;
}

export const WALLET_LABELS: Record<ProviderKind, string> = {
  sapient: "Sapient",
  universe: "Tari Universe",
};

export function initialWalletEntries(): WalletEntry[] {
  return [
    { kind: "sapient", label: WALLET_LABELS.sapient, phase: { kind: "idle" } },
    { kind: "universe", label: WALLET_LABELS.universe, phase: { kind: "idle" } },
  ];
}

export function probeWalletEntry(
  kind: ProviderKind,
  probe: WalletProbeOutcome | null,
  discoveryReason: string | null,
): WalletEntry {
  let phase: WalletEntryPhase;
  if (probe === null) {
    phase = { kind: "absent", reason: discoveryReason || "no wallet answered" };
  } else if (probe.state === "available") {
    phase = { kind: "ready" };
  } else if (probe.state === "needs_connect") {
    phase = { kind: "needs_connect" };
  } else if (probe.state === "unsupported") {
    phase = {
      kind: "unsupported",
      reason: probe.unavailableReason || "this wallet does not support this application",
    };
  } else {
    phase = {
      kind: "unavailable",
      reason: probe.unavailableReason || "the wallet could not be reached",
    };
  }
  return { kind, label: WALLET_LABELS[kind], phase };
}

export function checkingWalletEntry(kind: ProviderKind): WalletEntry {
  return { kind, label: WALLET_LABELS[kind], phase: { kind: "checking" } };
}

export function connectStarted(entry: WalletEntry): WalletEntry {
  return { ...entry, phase: { kind: "connecting" } };
}

export function connectSucceeded(
  entry: WalletEntry,
  network: string | null,
): WalletEntry {
  return { ...entry, phase: { kind: "connected", network } };
}

export function connectFailed(entry: WalletEntry, message: string): WalletEntry {
  return { ...entry, phase: { kind: "connect_failed", message } };
}

export function accountsChanged(entry: WalletEntry, accounts: unknown): WalletEntry {
  if (entry.phase.kind !== "connected") {
    return entry;
  }
  if (Array.isArray(accounts) && accounts.length > 0) {
    return entry;
  }
  return { ...entry, phase: { kind: "needs_connect" } };
}

export function walletEntryStatus(entry: WalletEntry): string {
  switch (entry.phase.kind) {
    case "idle":
      return "Not checked yet.";
    case "checking":
      return "Checking for the wallet…";
    case "absent":
      return "Not detected on this page.";
    case "ready":
      return "Detected and authorized.";
    case "needs_connect":
      return "Detected. Press Connect wallet to authorize this application.";
    case "unsupported":
      return entry.phase.reason;
    case "unavailable":
      return entry.phase.reason;
    case "connecting":
      return "Waiting for the wallet…";
    case "connected":
      return entry.phase.network === null
        ? "Connected. The wallet did not report its network."
        : `Connected. Wallet network: ${entry.phase.network}.`;
    case "connect_failed":
      return entry.phase.message;
  }
}

export function walletEntryButton(entry: WalletEntry): {
  label: string;
  disabled: boolean;
  hidden: boolean;
} {
  switch (entry.phase.kind) {
    case "connecting":
      return { label: "Waiting for wallet…", disabled: true, hidden: false };
    case "connected":
      return { label: "Wallet Connected", disabled: true, hidden: false };
    case "ready":
    case "needs_connect":
      return { label: "Connect wallet", disabled: false, hidden: false };
    default:
      return { label: "Connect wallet", disabled: true, hidden: true };
  }
}
