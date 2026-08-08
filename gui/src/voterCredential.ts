import type { GuiVoterCredentialStatusV1, GuiVoterEligibilityV1 } from "./api/types";

export const WALLET_SEED_WARNING =
  "Governance credentials are separate from wallet keys. Never enter a wallet seed phrase here.";

export function credentialEligibilityTone(
  eligibility: GuiVoterEligibilityV1,
): "ok" | "warn" | "neutral" {
  if (eligibility === "Eligible") return "ok";
  if (eligibility === "NotEligible") return "warn";
  return "neutral";
}

export function canProceedAfterCredential(
  status: GuiVoterCredentialStatusV1 | null,
): boolean {
  return !!status?.credential_loaded && status.eligibility === "Eligible" && status.can_continue;
}

export function publicKeyDisplay(status: GuiVoterCredentialStatusV1 | null): string {
  return status?.public_governance_key_abbrev ?? "Not loaded";
}

export function credentialStatusText(status: GuiVoterCredentialStatusV1 | null): string {
  if (!status?.credential_loaded) return "Not loaded";
  return "Loaded";
}

export function noSecretFieldNames(fieldNames: string[]): boolean {
  const forbidden = [
    "secret",
    "scalar",
    "seed",
    "mnemonic",
    "private",
    "credential_bytes",
    "wallet_seed",
    "registry_index",
    "nullifier",
    "proof",
  ];
  return fieldNames.every((field) => {
    const normalized = field.toLowerCase();
    return forbidden.every((marker) => !normalized.includes(marker));
  });
}
