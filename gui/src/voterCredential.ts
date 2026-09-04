import type { GuiVoterCredentialStatusV1, GuiVoterEligibilityV1 } from "./api/types";

export const WALLET_SEED_WARNING =
  "Your voter credential is your private voting identity. It is not a Tari wallet seed. Never enter a wallet seed phrase here.";

export const CREDENTIAL_RECOVERY_WARNING =
  "Use a passphrase you can remember. Private Ballot cannot recover it.";

export const PASSPHRASE_MISMATCH_MESSAGE =
  "The passphrase confirmation must match exactly.";

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

export function credentialStorageText(status: GuiVoterCredentialStatusV1 | null): string {
  if (!status?.credential_loaded) return "Locked or not loaded";
  if (status.saved_locally) return "Saved locally";
  if (status.credential_origin === "ImportedSession" || status.credential_origin === "MemoryOnly") {
    return "Available for this app session only";
  }
  return status.session_only ? "Available for this app session only" : "Saved locally";
}

export function defaultCredentialBackupFilename(
  status: GuiVoterCredentialStatusV1 | null,
): string {
  const key = status?.public_governance_key_hex;
  if (!key) return "voter-credential.tcbcred";
  return `voter-credential-${key.slice(0, 12)}.tcbcred`;
}

export function clearMemoryConfirmationText(
  status: GuiVoterCredentialStatusV1 | null,
  hasSavedCopy: boolean,
): string {
  if (status?.credential_loaded && !hasSavedCopy) {
    return "This credential is only in memory. Clearing it will remove this session's copy. Make sure you have a backup.";
  }
  return "Lock this credential for the current session? A saved encrypted copy will not be deleted.";
}

export function deleteSavedCopyConfirmationText(
  status: GuiVoterCredentialStatusV1 | null,
): string {
  if (status?.credential_loaded) {
    return "Delete the encrypted saved copy from this computer? The unlocked credential remains usable until cleared or the app exits, but it will become memory-only.";
  }
  return "Delete the encrypted saved copy from this computer?";
}

export function credentialFlowSucceeded(status: GuiVoterCredentialStatusV1): boolean {
  return status.credential_loaded && !!status.public_governance_key_hex;
}

export function noSecretFieldNames(fieldNames: string[]): boolean {
  const forbidden = [
    "secret",
    "scalar",
    "seed",
    "mnemonic",
    "private",
    "private_key",
    "credential_bytes",
    "wallet_seed",
    "registry_index",
    "nullifier",
    "proof",
    "passphrase",
    "password",
  ];
  return fieldNames.every((field) => {
    const normalized = field.toLowerCase();
    return forbidden.every((marker) => !normalized.includes(marker));
  });
}

export async function createDurableCredentialFlow<T>(
  passphrase: string,
  confirmation: string,
  create: (passphrase: string) => Promise<T>,
  clearPassphrases: () => void,
): Promise<T | null> {
  if (passphrase !== confirmation) return null;
  try {
    return await create(passphrase);
  } finally {
    clearPassphrases();
  }
}

export async function unlockSavedCredentialFlow<T>(
  publicKeyHex: string,
  passphrase: string,
  unlock: (publicKeyHex: string, passphrase: string) => Promise<T>,
  clearPassphrase: () => void,
): Promise<T> {
  try {
    return await unlock(publicKeyHex, passphrase);
  } finally {
    clearPassphrase();
  }
}

export async function importCredentialFlow<T>(
  path: string,
  passphrase: string,
  persistLocally: boolean,
  importCredential: (
    path: string,
    passphrase: string,
    persistLocally: boolean,
  ) => Promise<T>,
  clearPassphrase: () => void,
): Promise<T> {
  try {
    return await importCredential(path, passphrase, persistLocally);
  } finally {
    clearPassphrase();
  }
}

export async function backupCredentialFlow<T>(
  path: string,
  passphrase: string,
  confirmation: string,
  backup: (path: string, passphrase: string) => Promise<T>,
  clearPassphrases: () => void,
): Promise<T | null> {
  if (passphrase !== confirmation) return null;
  try {
    return await backup(path, passphrase);
  } finally {
    clearPassphrases();
  }
}

export async function copyPublicEnrollmentKey(
  status: GuiVoterCredentialStatusV1 | null,
  writeText: (value: string) => Promise<void>,
): Promise<boolean> {
  const publicKey = status?.public_governance_key_hex;
  if (!publicKey) return false;
  await writeText(publicKey);
  return true;
}
