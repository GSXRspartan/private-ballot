# Governance Source Snapshot

## Status

Recorded for the Phase 1 specification draft.

This source snapshot does not claim that the proposed governance rules are
merged, approved, final, or binding.

## Project baseline

- Repository branch: `phase1/spec-finalization`
- Starting project commit: `dbeeabdabd62574ab103fc52fe018f5a80b2ce7d`
- Starting commit subject: `docs: establish private ballot phase 1 baseline`

## Tari forum source

- Discussion: Tari Core Contributor Program
- Relevant post: 47 and surrounding discussion
- URL: https://community.tari.com/t/the-core-contributor-program/204/47
- Recorded date: 2026-07-31

The forum discussion supplies design rationale, privacy concerns, stakeholder
expectations, and possible implementation directions. A forum URL is not an
immutable protocol revision and must not be treated as one.

## Tari RFC source

- Repository: https://github.com/tari-project/rfcs.git
- Pull request: https://github.com/tari-project/rfcs/pull/185
- Pull request ref: `refs/pull/185/head`
- Observed head commit: `f9e86cca3b5229ec4ecec356d0838bd7f8730ccd`
- Recorded date: 2026-07-31

The observed revision was retrieved with:

```text
git ls-remote https://github.com/tari-project/rfcs.git refs/pull/185/head
```

Expected result:

```text
f9e86cca3b5229ec4ecec356d0838bd7f8730ccd refs/pull/185/head
```

## Project use

This revision is the governance source used while preparing the Phase 1
specification.

Every future election manifest must record the exact immutable governance
revision used for that election.

A draft election may visibly mark its governance revision as unresolved. An
election may not enter the `FROZEN` state while that value remains unresolved.

Later changes to PR #185 or a successor RFC do not retroactively alter:

- an already frozen election manifest;
- its registry snapshots;
- its ballot validation rules;
- its tally rules;
- its privacy policy;
- its final archive.

## Limitations

This snapshot records the observed PR head commit. It does not establish that:

- the pull request was merged;
- Tari governance approved the proposal;
- the proposal remained unchanged afterward;
- all unresolved election procedures were settled;
- the forum discussion is immutable.

Before a binding election, the project must pin the exact approved governance
source and preserve enough source evidence for an independent reviewer to
reconstruct the rules used.
