/**
 * Versioned local credential artifact for the Hosted web voter flow.
 *
 * Why a new artifact exists: the Desktop's canonical credential container
 * (`TCB-CRED` V1) is Argon2id(64 MiB)+XChaCha20-Poly1305 encrypted Rust code
 * that the browser WASM build does not (and practically cannot) embed, so the
 * web flow needs its own durable handoff. This artifact is the smallest
 * versioned wrapper around the EXISTING canonical web credential (the 32-byte
 * secret scalar hex) plus its derived public key, so that:
 *   - the exact same cryptographic secret the browser generated is preserved,
 *   - import can prove integrity by re-deriving the public key from the
 *     secret with the canonical WASM code and comparing it byte-for-byte,
 *   - wrong-election and wrong-voter artifacts are rejected by binding,
 *   - the artifact is a file the voter holds (no server custody, no browser
 *     storage, no clipboard, no URL).
 *
 * Security invariants:
 * - The secret only ever lives in this artifact (the voter's own file) and in
 *   page memory. It is never logged, never placed in a URL/query string, and
 *   never stored in localStorage/sessionStorage/IndexedDB.
 * - Producing the file is always an explicit user action (a download button).
 * - Importing is always an explicit user action (a file picker input).
 * - The artifact is validated exactly like any other input: schema, version,
 *   hex formats, election binding, and secret↔public-key consistency.
 */

export const HOSTED_VOTER_CREDENTIAL_ARTIFACT_SCHEMA =
  "private-ballot-hosted-voter-credential-v1";

export type VoterCredentialArtifact = {
  schema: string;
  created_at: string;
  election_id: string;
  public_key_hex: string;
  secret_key_hex: string;
};

export type ParsedVoterCredential =
  | { ok: true; secret_key_hex: string; public_key_hex: string }
  | { ok: false; error: string };

const HEX_64 = /^[0-9a-f]{64}$/;

export function buildVoterCredentialArtifact(
  electionId: string,
  publicKeyHex: string,
  secretKeyHex: string,
  createdAtIso: string
): VoterCredentialArtifact {
  return {
    schema: HOSTED_VOTER_CREDENTIAL_ARTIFACT_SCHEMA,
    created_at: createdAtIso,
    election_id: electionId,
    public_key_hex: publicKeyHex,
    secret_key_hex: secretKeyHex,
  };
}

export function artifactFileName(electionId: string): string {
  return `private-ballot-voter-${encodeURIComponent(electionId)}-credential-v1.json`;
}

/**
 * Parses and fully validates an artifact's text. `derivePublicKeyHex` is the
 * canonical public-key derivation from the existing WASM surface; returning
 * `null` means the derivation itself failed (malformed secret). The derived
 * key must match the stored public key byte-for-byte, so altering either
 * field is rejected and a mismatched voter artifact can never authenticate.
 *
 * `expectedElectionId` may be `null` while the vote page has not loaded an
 * election yet; when provided, a different election's artifact is rejected.
 */
export function parseVoterCredentialArtifact(
  text: string,
  expectedElectionId: string | null,
  derivePublicKeyHex: (secretHex: string) => string | null
): ParsedVoterCredential {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { ok: false, error: "The credential file is not valid JSON." };
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { ok: false, error: "The credential file is not a valid credential artifact." };
  }
  const record = parsed as Record<string, unknown>;
  if (record["schema"] !== HOSTED_VOTER_CREDENTIAL_ARTIFACT_SCHEMA) {
    return {
      ok: false,
      error: `The credential file schema is not ${HOSTED_VOTER_CREDENTIAL_ARTIFACT_SCHEMA}.`,
    };
  }
  const electionId = typeof record["election_id"] === "string" ? record["election_id"] : "";
  if (!electionId) {
    return { ok: false, error: "The credential file does not name an election." };
  }
  if (expectedElectionId !== null && electionId !== expectedElectionId) {
    return {
      ok: false,
      error: "This credential belongs to a different election. Load that election to use it.",
    };
  }
  const secretKeyHex = typeof record["secret_key_hex"] === "string" ? record["secret_key_hex"].trim() : "";
  const publicKeyHex = typeof record["public_key_hex"] === "string" ? record["public_key_hex"].trim() : "";
  if (!HEX_64.test(secretKeyHex)) {
    return { ok: false, error: "The credential file's secret key is missing or malformed." };
  }
  if (!HEX_64.test(publicKeyHex)) {
    return { ok: false, error: "The credential file's public key is missing or malformed." };
  }
  const derived = derivePublicKeyHex(secretKeyHex);
  if (derived === null || derived !== publicKeyHex) {
    return {
      ok: false,
      error: "The credential file failed integrity verification: its secret does not match its public key.",
    };
  }
  return { ok: true, secret_key_hex: secretKeyHex, public_key_hex: publicKeyHex };
}
