export interface WalletConnection {
  connected: boolean;
  mode: string | null;
}

export function newWalletConnection(): WalletConnection {
  return { connected: false, mode: null };
}

export function connectedWallet(mode: string): WalletConnection {
  return { connected: true, mode };
}

export function disconnectedWallet(): WalletConnection {
  return newWalletConnection();
}
