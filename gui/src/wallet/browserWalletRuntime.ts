import {
  sapientDiscovery,
  universeDiscovery,
  waitForTariInit,
  windowTariProvider,
  WalletProviderError,
} from "./provider.ts";
import type { ProviderKind } from "./types.ts";
import type { TariProviderScope } from "./provider.ts";
import {
  WALLET_LABELS,
  accountsChanged,
  checkingWalletEntry,
  connectFailed,
  connectStarted,
  connectSucceeded,
  probeWalletEntry,
} from "./settingsState.ts";
import type { WalletEntry } from "./settingsState.ts";

export type WalletScope = TariProviderScope & {
  addEventListener?: (type: string, listener: () => void) => unknown;
};

const TARI_INIT_WAIT_MS = 1500;

function errorMessage(error: unknown): string {
  if (error instanceof WalletProviderError) {
    return error.message;
  }
  if (error instanceof Error && error.message.length > 0) {
    return error.message;
  }
  return "Connecting to the wallet failed.";
}

export interface BrowserWalletRuntime {
  probeAll(onEntry: (kind: ProviderKind, entry: WalletEntry) => void): Promise<void>;
  connect(
    kind: ProviderKind,
    onEntry: (kind: ProviderKind, entry: WalletEntry) => void,
  ): Promise<void>;
}

export function createBrowserWalletRuntime(
  scope: WalletScope,
  initWaitMs: number = TARI_INIT_WAIT_MS,
): BrowserWalletRuntime {
  function discover(kind: ProviderKind) {
    return kind === "sapient" ? sapientDiscovery(scope) : universeDiscovery(scope);
  }

  function adapterFor(kind: ProviderKind) {
    return windowTariProvider(kind, WALLET_LABELS[kind], () => discover(kind));
  }

  function freshEntry(kind: ProviderKind): WalletEntry {
    return { kind, label: WALLET_LABELS[kind], phase: { kind: "idle" } };
  }

  return {
    async probeAll(onEntry) {
      onEntry("sapient", checkingWalletEntry("sapient"));
      onEntry("universe", checkingWalletEntry("universe"));
      let sapientFound = discover("sapient");
      let universeFound = discover("universe");
      if (!sapientFound.provider && !universeFound.provider) {
        await waitForTariInit(scope, initWaitMs);
        sapientFound = discover("sapient");
        universeFound = discover("universe");
      }
      for (const [kind, found] of [
        ["sapient", sapientFound],
        ["universe", universeFound],
      ] as const) {
        if (!found.provider) {
          onEntry(kind, probeWalletEntry(kind, null, found.reason));
          continue;
        }
        try {
          const probe = await adapterFor(kind).probe();
          onEntry(kind, probeWalletEntry(kind, probe, null));
        } catch (error) {
          onEntry(
            kind,
            probeWalletEntry(kind, null, errorMessage(error) || "the wallet could not be probed"),
          );
        }
      }
    },
    async connect(kind, onEntry) {
      const adapter = adapterFor(kind);
      const base = freshEntry(kind);
      onEntry(kind, connectStarted(base));
      try {
        await adapter.connect();
        let network: string | null = null;
        try {
          network = (await adapter.getNetwork()).network;
        } catch {
          network = null;
        }
        let current = connectSucceeded(base, network);
        onEntry(kind, current);
        adapter.onAccountsChanged((accounts) => {
          current = accountsChanged(current, accounts);
          onEntry(kind, current);
        });
      } catch (error) {
        onEntry(kind, connectFailed(base, errorMessage(error)));
      }
    },
  };
}
