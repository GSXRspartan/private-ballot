/**
 * Public product identity constants for Private Ballot.
 *
 * Private Ballot is an independent open-source project. It is not affiliated
 * with or endorsed by Tari Labs. Legitimate textual references to Tari Ootle,
 * Tari Ootle walletd, and the Tari Triptych implementation remain where they
 * accurately describe the underlying technology; the official Tari logo is
 * not used as the application identity.
 */

/** Application name — always the PRIMARY title wherever identity appears. */
export const APP_NAME = "Private Ballot";

/** Identity qualifier: always shown as a smaller subtitle directly
 *  underneath the application name, never appended to it. */
export const APP_IDENTITY_TAG = "Independent Open-Source Project";

/** Purpose label describing the intended scope of this release — not the
 *  software's maturity. Displayed under "Purpose" on About and in the
 *  toolbar/footer where the release identity is summarised. */
export const APP_STATUS_LABEL = "Governance Pilot";

/** Release-maturity label. This describes the SOFTWARE stage independently
 *  from the release's intended purpose (governance pilot) or network
 *  (Esmeralda testnet). "Alpha" is the pre-release maturity level: the
 *  software is functional but not audited for production governance use. */
export const APP_RELEASE_STATUS = "Alpha";

/** Human-readable network the release targets. Kept as a plain, non-secret
 *  string; the actual network id used by the anchor backend is
 *  `esmeralda` (see `src/anchor/anchorForm.ts`). */
export const APP_NETWORK_LABEL = "Esmeralda Testnet";

/** Current application version. Kept in step with package.json; the
 *  branding tests assert the two never drift apart. */
export const APP_VERSION = "0.1.0";

/** Independence disclaimer shown on the About screen. This is separate from
 *  the visual "Independent Open-Source Project" subtitle. */
export const COMMUNITY_DISCLAIMER =
  "Private Ballot is an independent open-source project. It is not affiliated with or endorsed by Tari Labs.";
