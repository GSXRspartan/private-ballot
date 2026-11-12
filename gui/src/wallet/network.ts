export const OOTLE_NETWORK_BYTES = {
  mainnet: 0x00,
  stagenet: 0x01,
  nextnet: 0x02,
  localnet: 0x10,
  igor: 0x24,
  esmeralda: 0x26,
} as const;

export type OotleNetworkName = keyof typeof OOTLE_NETWORK_BYTES;

export function networkByteFromName(name: string): number | null {
  const key = name.trim().toLowerCase();
  return key in OOTLE_NETWORK_BYTES
    ? OOTLE_NETWORK_BYTES[key as OotleNetworkName]
    : null;
}

export type NetworkVerdict =
  | { kind: "match"; byte: number }
  | {
      kind: "mismatch";
      configuredByte: number;
      walletByte: number;
    }
  | { kind: "wallet_network_unknown"; walletName: string }
  | { kind: "configured_network_unknown"; configuredName: string };

export function networkVerdict(
  configuredName: string,
  walletName: string,
): NetworkVerdict {
  const configuredByte = networkByteFromName(configuredName);
  if (configuredByte === null) {
    return { kind: "configured_network_unknown", configuredName };
  }
  const walletByte = networkByteFromName(walletName);
  if (walletByte === null) {
    return { kind: "wallet_network_unknown", walletName };
  }
  if (configuredByte !== walletByte) {
    return { kind: "mismatch", configuredByte, walletByte };
  }
  return { kind: "match", byte: configuredByte };
}

export function networkMatched(verdict: NetworkVerdict): boolean {
  return verdict.kind === "match";
}

export function networkVerdictText(verdict: NetworkVerdict): string {
  switch (verdict.kind) {
    case "match":
      return "The wallet is on the expected network.";
    case "mismatch":
      return "The wallet is on a different Ootle network than the anchor deployment. Publishing is blocked.";
    case "wallet_network_unknown":
      return `The wallet reported an unrecognized network ("${verdict.walletName}"). Publishing is blocked.`;
    case "configured_network_unknown":
      return `The anchor deployment names an unrecognized network ("${verdict.configuredName}"). Publishing is blocked.`;
  }
}
