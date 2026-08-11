/**
 * Community project identity constants for Tari Private Ballot.
 *
 * This application is an independent community project for the Tari
 * ecosystem. It is not endorsed by or affiliated with Tari Labs, and the
 * official Tari logo is not used as the application identity. Legitimate
 * textual references to Tari, Tari Ootle, and Tari Triptych remain where
 * they accurately describe the underlying technology.
 */

/** Application name — always the PRIMARY title wherever identity appears. */
export const APP_NAME = "Tari Private Ballot";

/** Identity qualifier: always shown as a smaller subtitle directly
 *  underneath the application name, never appended to it. */
export const APP_IDENTITY_TAG = "Community Project";

/** Product-status label for the current release. */
export const APP_STATUS_LABEL = "Governance Pilot";

/** Current application version. Kept in step with package.json; the
 *  branding tests assert the two never drift apart. */
export const APP_VERSION = "0.1.0";

/** Community-project disclaimer shown on the About screen. This is separate
 *  from the visual "Community Project" subtitle. */
export const COMMUNITY_DISCLAIMER =
  "Independent community-built project for the Tari ecosystem. Not endorsed by or affiliated with Tari Labs.";
