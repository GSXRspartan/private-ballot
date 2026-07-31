# ADR-0003: Governance source pinning and MVP election scope

## Status

Accepted for the Phase 1 draft.

## Context

- The Tari Core Contributor Program forum thread provides rationale, privacy
  concerns, and stakeholder expectations for how governance voting should work.
- RFC PR #185 provides the current proposed governance rules.
- PR #185 is still under review and may change before it is merged or
  approved.
- Election software must not silently change behavior when the underlying
  proposal changes. Each election needs to record which version of the
  governance rules it used.

## Decision

1. Every election manifest identifies the governance source used.
2. Before an election is frozen, the manifest must pin an immutable commit hash
   or equivalent immutable revision.
3. During early drafting only, the source revision may be marked visibly as
   unresolved.
4. The MVP begins with `NON_BINDING_APPROVAL_PILOT`.
5. Different governance election types use separate versioned schemas.
6. The MVP uses first-valid-ballot-counts.
7. Unknown and duplicate candidate selections are invalid.
8. Candidate IDs are stable machine identifiers; display names are
   presentation data.
9. Unresolved ties are reported rather than decided alphabetically.
10. Public-ballot anonymity is allowed only for a harmless pilot.
11. Binding Council elections require a separately reviewed sealed-ballot
    design.
12. Multi-seat Council election rules are deferred until Tari governance
    formally selects a method.

## Consequences

- The implementation remains useful even if RFC wording changes, because
  behavior is tied to a pinned revision rather than to whatever the proposal
  currently says.
- Old election archives preserve the exact rules they used at the time they
  were frozen.
- The protocol must support multiple electorate types rather than assuming a
  single electorate.
- The first pilot can validate mechanics without deciding any real governance
  question.
- More complex privacy and tallying (sealed ballots, threshold decryption,
  single-seat IRV, and multi-seat methods) remain explicit later work.

## Sources

- https://community.tari.com/t/the-core-contributor-program/204/47
- https://github.com/tari-project/rfcs/pull/185

## MVP pilot scope clarification

The first implemented pilot is a harmless non-binding approval poll
using a volunteer or synthetic electorate.

The pilot exists to test protocol, archive, verification, tally, receipt,
and anchoring behavior. It does not decide Core Contributor admission,
removal, Council membership, protocol amendments, treasury actions, or
another binding governance matter.

A binding election remains prohibited until its exact governance rules,
production cryptographic suite, ballot-secrecy design, operational
procedures, and independent review requirements are satisfied.
