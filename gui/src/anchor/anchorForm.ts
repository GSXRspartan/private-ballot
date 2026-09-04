// Anchor operator-config form state: defaults, cross-navigation persistence,
// and the "Use connected wallet" auto-fill mapping.
//
// The frontend has no React mount harness (ADR-0007), so all of this is pure
// logic exercised directly by tests. Two properties matter here:
//
//   * Persistence (Task D): the form survives tab/screen switches and unmount/
//     remount, keyed by (archive hash, deployment template address). Only PUBLIC
//     fields are persisted — never a bearer token or any private key (none of
//     which live in this state to begin with).
//   * One-click wallet fill (Task C): a selected wallet account plus the locked
//     deployment deterministically fills the brittle fields the operator used to
//     hand-type, and crucially never puts a whitespace-bearing display name into
//     the account reference (the historical Prepare failure).

import type {
  GuiWalletdAnchorAccountV1,
  WalletdReadinessKindV1,
} from "../api/types.ts";

export type AnchorSignerMode = "managed-anchor-wallet" | "external-walletd";
export type AnchorVersion = "v1" | "v2";

/** The full set of persisted, non-secret anchor form fields. */
export interface AnchorFormState {
  signerMode: AnchorSignerMode;
  anchorVersion: AnchorVersion;
  network: string;
  walletdEndpoint: string;
  indexerEndpoint: string;
  accountReference: string;
  feeComponent: string;
  sealSignerKind: string;
  sealSignerId: string;
  declaredSealPublicKey: string;
  maxFee: number;
  maxEpochDelta: number;
  acceptedBallotFloor: number;
  dedicatedWallet: boolean;
}

export const DEFAULT_WALLETD_ENDPOINT = "http://127.0.0.1:5100";
export const DEFAULT_INDEXER_ENDPOINT = "https://ootle-indexer-a.tari.com/";
export const DEFAULT_NETWORK = "esmeralda";
/** A safe, whitespace-free fallback fee-account reference. */
export const DEFAULT_ACCOUNT_REFERENCE = "anchor-fee-account";

export function anchorSidecarPaths(archiveDirectory: string): {
  configPath: string;
  snapshotPath: string;
  evidencePath: string;
} {
  return {
    configPath: siblingPath(archiveDirectory, "-anchor-config.cbor"),
    snapshotPath: siblingPath(archiveDirectory, "-anchor-snapshot.cbor"),
    evidencePath: siblingPath(archiveDirectory, "-anchor-evidence.cbor"),
  };
}

function siblingPath(path: string, suffix: string): string {
  const trimmed = path.replace(/[\\/]+$/, "");
  const separatorMatch = trimmed.match(/[\\/]/g);
  const separator = separatorMatch?.[separatorMatch.length - 1] ?? "\\";
  const lastSeparator = Math.max(trimmed.lastIndexOf("\\"), trimmed.lastIndexOf("/"));
  if (lastSeparator < 0) return `${trimmed}${suffix}`;
  const parent = lastSeparator === 0 ? trimmed.slice(0, 1) : trimmed.slice(0, lastSeparator);
  const name = trimmed.slice(lastSeparator + 1);
  return parent.endsWith("\\") || parent.endsWith("/")
    ? `${parent}${name}${suffix}`
    : `${parent}${separator}${name}${suffix}`;
}

export function defaultAnchorFormState(): AnchorFormState {
  return {
    signerMode: "external-walletd",
    anchorVersion: "v1",
    network: DEFAULT_NETWORK,
    walletdEndpoint: DEFAULT_WALLETD_ENDPOINT,
    indexerEndpoint: DEFAULT_INDEXER_ENDPOINT,
    accountReference: DEFAULT_ACCOUNT_REFERENCE,
    feeComponent: "",
    sealSignerKind: "account",
    sealSignerId: "0",
    declaredSealPublicKey: "",
    maxFee: 1000,
    maxEpochDelta: 12,
    acceptedBallotFloor: 2,
    dedicatedWallet: false,
  };
}

/**
 * Produces a whitespace-free, bounded account reference. Never returns the raw
 * wallet display name when it contains spaces (that is the exact input the
 * backend rejects with GUI_LIVE_ANCHOR_ACCOUNT_REFERENCE_FORBIDDEN_CHARACTER).
 * Falls back to a safe constant when nothing usable can be derived.
 */
export function safeAccountReference(source: string | null | undefined): string {
  if (source === null || source === undefined) return DEFAULT_ACCOUNT_REFERENCE;
  const slug = source
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 120);
  return slug.length > 0 ? slug : DEFAULT_ACCOUNT_REFERENCE;
}

/** Locked deployment fields relevant to the form. */
export interface AnchorDeploymentHint {
  network: string;
  template_address: string;
}

/**
 * Applies a selected connected-wallet account (and the locked deployment, when
 * present) to the form, filling the deterministic public fields. The account
 * reference keeps any operator-chosen non-default value; otherwise it is derived
 * safely from the account name — never left as a spaced display name.
 */
export function applyConnectedWallet(
  state: AnchorFormState,
  account: GuiWalletdAnchorAccountV1,
  deployment: AnchorDeploymentHint | null,
): AnchorFormState {
  const keepReference =
    state.accountReference.trim().length > 0 &&
    state.accountReference !== DEFAULT_ACCOUNT_REFERENCE &&
    !/\s/.test(state.accountReference);
  return {
    ...state,
    signerMode: "external-walletd",
    network: deployment?.network ?? state.network,
    walletdEndpoint: DEFAULT_WALLETD_ENDPOINT,
    indexerEndpoint: state.indexerEndpoint.trim().length > 0 ? state.indexerEndpoint : DEFAULT_INDEXER_ENDPOINT,
    feeComponent: account.component_address,
    sealSignerKind: "account",
    sealSignerId: account.key_index !== null ? String(account.key_index) : state.sealSignerId,
    declaredSealPublicKey: account.owner_public_key_hex,
    accountReference: keepReference ? state.accountReference : safeAccountReference(account.name),
  };
}

/**
 * Maps a walletd readiness/account-listing kind to the exact cause shown when
 * "Use connected wallet" cannot fill the form. Every non-ready kind names a
 * distinct, truthful cause — crucially, a reachable daemon whose account list
 * failed (permission gap, call failure) is never reported as "not reachable".
 * Returns an empty string for `ready` (there is no error to show).
 */
export function walletAccountsErrorMessage(kind: WalletdReadinessKindV1): string {
  switch (kind) {
    case "ready":
      return "";
    case "no_credential":
      return "Reconnect Tari Wallet and paste a valid API key first.";
    case "auth_rejected":
      return "Reconnect Tari Wallet: the stored key was rejected";
    case "permission_denied":
      return "The wallet key is valid but lacks the Accounts:Read permission. Reconnect Tari Wallet using an API key that can read accounts.";
    case "call_failed":
      return "walletd is reachable, but the account-list request failed. Check your Tari Wallet and try again.";
    case "unreachable":
      return "Start Tari Wallet: walletd is not reachable";
  }
}

/**
 * Terminal, secret-free status line shown after a "Use connected wallet" click
 * resolves. Every non-ready kind names the specific, actionable cause; a
 * reachable daemon whose account list failed is never reported as "not
 * reachable". Never contains a token or API key.
 */
export function walletActionStatusForKind(kind: WalletdReadinessKindV1): string {
  switch (kind) {
    case "ready":
      return "Wallet account loaded";
    case "no_credential":
      return "No saved wallet credential";
    case "auth_rejected":
      return "Wallet API key rejected";
    case "permission_denied":
      return "Wallet API key missing Accounts:Read";
    case "call_failed":
      return "Walletd reachable — account list failed";
    case "unreachable":
      return "Walletd is not reachable";
  }
}

/** Short readiness label for the Tari Anchor wallet panel. Never a raw status. */
export function walletReadinessLabel(kind: WalletdReadinessKindV1): string {
  switch (kind) {
    case "ready":
      return "Ready";
    case "no_credential":
      return "Connect Tari Wallet";
    case "auth_rejected":
      return "Reconnect Tari Wallet";
    case "permission_denied":
      return "Reconnect with Accounts:Read";
    case "call_failed":
      return "walletd reachable — request failed";
    case "unreachable":
      return "Start Tari Wallet";
  }
}

// ---------------------------------------------------------------------------
// Persistence (Task D). Storage is injected so pure tests can supply a fake and
// so a missing/broken localStorage never throws into React render.
// ---------------------------------------------------------------------------

/** Minimal storage surface (a subset of the DOM `Storage` interface). */
export interface KeyValueStore {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

const STORAGE_PREFIX = "tari-anchor-form:v1";

/** Storage key for a given archive hash and deployment template address. */
export function anchorFormStorageKey(
  archiveHashHex: string | null | undefined,
  templateAddress: string | null | undefined,
): string {
  const archive = (archiveHashHex ?? "no-archive").trim() || "no-archive";
  const template = (templateAddress ?? "no-template").trim() || "no-template";
  return `${STORAGE_PREFIX}:${archive}:${template}`;
}

/** The subset of fields that are persisted. Secrets are structurally absent. */
function serializableState(state: AnchorFormState): AnchorFormState {
  return {
    signerMode: state.signerMode,
    anchorVersion: state.anchorVersion,
    network: state.network,
    walletdEndpoint: state.walletdEndpoint,
    indexerEndpoint: state.indexerEndpoint,
    accountReference: state.accountReference,
    feeComponent: state.feeComponent,
    sealSignerKind: state.sealSignerKind,
    sealSignerId: state.sealSignerId,
    declaredSealPublicKey: state.declaredSealPublicKey,
    maxFee: state.maxFee,
    maxEpochDelta: state.maxEpochDelta,
    acceptedBallotFloor: state.acceptedBallotFloor,
    dedicatedWallet: state.dedicatedWallet,
  };
}

/** Loads persisted form state, merging over defaults; robust to bad JSON. */
export function loadAnchorFormState(
  store: KeyValueStore | null | undefined,
  key: string,
): AnchorFormState {
  const base = defaultAnchorFormState();
  if (!store) return base;
  let raw: string | null = null;
  try {
    raw = store.getItem(key);
  } catch {
    return base;
  }
  if (raw === null) return base;
  try {
    const parsed = JSON.parse(raw) as Partial<AnchorFormState>;
    if (parsed === null || typeof parsed !== "object") return base;
    return { ...base, ...parsed };
  } catch {
    return base;
  }
}

/** Persists form state, silently ignoring storage errors (private mode, etc.). */
export function saveAnchorFormState(
  store: KeyValueStore | null | undefined,
  key: string,
  state: AnchorFormState,
): void {
  if (!store) return;
  try {
    store.setItem(key, JSON.stringify(serializableState(state)));
  } catch {
    // Best-effort only; a per-viewer convenience must never break the form.
  }
}

/** Clears persisted form state for a key (the "Reset anchor form" action). */
export function clearAnchorFormState(
  store: KeyValueStore | null | undefined,
  key: string,
): void {
  if (!store) return;
  try {
    store.removeItem(key);
  } catch {
    // Ignore.
  }
}
