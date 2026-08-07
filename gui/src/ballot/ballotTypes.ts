/**
 * Ballot-type presentation model.
 *
 * The protocol's candidate set is an ordered set of selectable OPTIONS with
 * machine IDs and display names; nothing in the backend assumes an election
 * is candidate-based. This module maps a ballot type onto neutral
 * presentation vocabulary so candidate elections, governance proposals, and
 * ballot measures all render from the same option data without
 * candidate-only naming.
 *
 * Current manifests carry `ballot_kind = NON_BINDING_APPROVAL_PILOT` for
 * every election, so the UI must not infer candidacy from the manifest. The
 * ballot type is an explicit presentation choice on placeholder screens; the
 * loaded option set renders identically under each type, with vocabulary
 * adjusted.
 */

import type { GuiElectionSummaryV1 } from "../api/types";

export type BallotType = "candidate" | "governance-proposal" | "ballot-measure";

export interface BallotPresentation {
  type: BallotType;
  /** Noun for the whole option set ("Ballot options" is always safe). */
  optionSetNoun: string;
  /** Singular noun for one option. */
  optionNoun: string;
  /** Heading over the selectable option list. */
  selectionHeading: string;
  /** Short description of what an approval means for this ballot type. */
  approvalMeaning: string;
}

export const BALLOT_PRESENTATIONS: Record<BallotType, BallotPresentation> = {
  candidate: {
    type: "candidate",
    optionSetNoun: "Candidates",
    optionNoun: "candidate",
    selectionHeading: "Approve one or more candidates",
    approvalMeaning: "Each approved candidate receives one approval from this ballot.",
  },
  "governance-proposal": {
    type: "governance-proposal",
    optionSetNoun: "Proposal choices",
    optionNoun: "choice",
    selectionHeading: "Approve one or more proposal choices",
    approvalMeaning: "Each approved choice receives one approval from this ballot.",
  },
  "ballot-measure": {
    type: "ballot-measure",
    optionSetNoun: "Measure options",
    optionNoun: "option",
    selectionHeading: "Approve one or more measure options",
    approvalMeaning: "Each approved option receives one approval from this ballot.",
  },
};

export const BALLOT_TYPE_LABELS: Record<BallotType, string> = {
  candidate: "Candidate election",
  "governance-proposal": "Governance proposal",
  "ballot-measure": "Ballot measure",
};

/**
 * Resolves the presentation for a screen. `requested` wins; otherwise the
 * presentation stays neutral (ballot-measure vocabulary is the most
 * type-neutral) because the current manifest format does not distinguish
 * candidate elections from governance ballots.
 */
export function presentationFor(
  _summary: GuiElectionSummaryV1 | null,
  requested?: BallotType,
): BallotPresentation {
  if (requested) return BALLOT_PRESENTATIONS[requested];
  return BALLOT_PRESENTATIONS["ballot-measure"];
}

/**
 * Human-facing approval-rule sentence derived from the real manifest limits,
 * neutral about what the options represent.
 */
export function approvalRuleText(summary: GuiElectionSummaryV1): string {
  const min = summary.approval_min;
  const max = summary.approval_max;
  const range =
    min === 0 && summary.abstention_allowed
      ? `up to ${max} option${max === 1 ? "" : "s"}`
      : min === max
        ? `exactly ${min} option${min === 1 ? "" : "s"}`
        : `between ${min} and ${max} options`;
  const abstention = summary.abstention_allowed
    ? " Abstaining (an empty selection) is permitted."
    : " Abstaining is not permitted.";
  return `Each ballot approves ${range}.${abstention}`;
}
