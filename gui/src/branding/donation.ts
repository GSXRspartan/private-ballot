/**
 * Voluntary developer donation destinations for Private Ballot.
 *
 * These values are PUBLIC, static constants only. They are never connected
 * to any wallet, election state, eligibility logic, transport, archive, or
 * anchoring flow, and no secret or credential material of any kind exists
 * in this donation surface. Donating is optional and never affects
 * application functionality or election behavior.
 */

/** XTM mainnet one-sided receive address (public, live-tested). Displayed
 *  and copied in full — never truncated. */
export const DONATION_XTM_ADDRESS =
  "1259DG2v4nxMugUpj3pgSheEEhVZmoExr44GhpnC9FGVwiJscmwo2oYnzFTQWxcsHBYjmupCBaWUsNf5gDttKw2Xmg4";

/** Public Yat. The exact Unicode emoji sequence must be preserved as-is:
 *  never normalized, reordered, replaced, or converted. */
export const DONATION_YAT = "🐱🔒🌙🔒🐱";

/** Plain-language disclaimer shown in the donation section. */
export const DONATION_DISCLAIMER =
  "Private Ballot is independently developed and free to use. Donations are optional and never affect voting, verification, access, or election results.";
