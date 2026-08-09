# Phase 5 Slice 5A12A: private transport design review

## Scope and 5A11 handoff

Architecture/threat-model documentation only. No Rust, TypeScript, canonical
format, network, Tor, relay, walletd, indexer, or Ootle transaction code changes.

Before design work, the required handoff was confirmed:

- branch: phase5/gui-core-foundation;
- clean worktree;
- current HEAD: d7874942177f64ef8a4afe6b52dc00b993a28506;
- immediate parent: efd5957a280a12f3d5ed1e3f501d30d4e2686f79;
- subject: feat: integrate local voter ballot office workflow;
- 5A11 review exists; and
- 5A11 documents GuiElectionSessionV1::intake_ballot_package_bytes with exact
  bytes through strict decode, verifier, lifecycle, nullifier duplicate check,
  and acceptance/rejection. Its documented targeted tests cover export,
  accepted once, and duplicate rejection.

No private transport requires a BallotPackageV1 change in this design.

## Artifacts

- docs/transport/PRIVATE_BALLOT_TRANSPORT_ARCHITECTURE_V1.md
- docs/transport/PRIVATE_BALLOT_TRANSPORT_THREAT_MODEL_V1.md
- docs/transport/PRIVATE_BALLOT_TRANSPORT_PRIVACY_CLAIMS_V1.md
- docs/decisions/ADR-0009-private-ballot-internet-transport.md

## Self-attack checklist

| Question | Answer |
| --- | --- |
| Can gateway learn voter IP? | Not directly in compliant Tor onion/relay mode; collusion, logs, compromise, or global observation can defeat this. |
| Can relay read ballot? | Not compliant HPKE/OHTTP plaintext; it can drop, delay, fingerprint, and log. |
| Can one operator learn both? | A low-cost single-admin profile can; hardened profile aims to prevent it under non-collusion. |
| What if relay+gateway collude? | Split-trust anonymity fails. |
| Can timestamps correlate ballots? | Yes; batching/padding reduce, not eliminate, correlation. |
| What if batch has one voter? | Mark reduced anonymity and make no meaningful batch claim. |
| Can size reveal choice? | Fixed padding reduces routine leakage; other traffic facts remain. |
| Can logs deanonymize? | Yes; explicit logging/proxy policy is mandatory. |
| Can organizer inject ballots? | Not valid votes without existing Triptych eligibility/frozen registry; operator control is still a risk. |
| Can organizer delete ballots silently? | It can suppress; acknowledgement plus missing inclusion is evidence, not compulsion. |
| Can voter detect exclusion? | With retained acknowledgement and missing inclusion, as an unresolved/suppression signal. |
| Can voter vote twice via circuits? | No second acceptance: the election-scoped nullifier decides it. |
| Can replay create a second vote? | No; it is duplicate after first valid acceptance. |
| Can malicious config redirect voter? | Not after reviewed descriptor authentication; V1 lacks it now, so online production remains disabled. |
| Can failure silently direct-fallback? | No; the route policy forbids it. |
| Can a receipt enable coercion? | Potentially; V1 claims no receipt-freeness. |
| Can public archive reveal voting order? | Not with post-seal digest order and no ingress time/order; public-content limits remain. |
| What does a global observer learn? | Potential timing/volume and enough data for correlation. |
| What if Tor is blocked? | Explicit safe relay selection if configured, or offline export; no direct fallback. |
| What if relay disappears? | Tor and offline export remain. |
| Can election still work offline? | Yes, existing canonical export/import remains. |
| Does voter need tTARI? | No. |
| Does voter need Tari wallet? | No. |
| Is a website required? | No; ballot office is a service/API. |
| Can gateway run on existing infrastructure? | Yes, with bounded queue/workers/storage; proof verification is main CPU cost. |

## Open security questions

1. Select reviewed HPKE/OHTTP suites and interoperability approach from primary
   standards/documentation during 5A12B/5A12D.
2. Decide and review descriptor signer authentication, then bind its hash in a
   future manifest version where feasible.
3. Measure package maxima and choose/test a fixed padding profile.
4. Select election-appropriate population/time thresholds and close policy.
5. Define canonical BatchCommitmentV1 labels/encoding and independent vectors.
6. Review Tor lifecycle, onion keys, relay agreements, cloud/proxy settings, and
   deletion/forensics behavior.
7. Assess accessibility, censorship, and abuse-control impact before any
   proof-of-work-like mechanism.

## Outcome

**CONDITIONAL READY FOR OPUS SECURITY/PRIVACY REVIEW.** The design retains the
5A11 byte boundary, requires no voter identity/wallet, and rejects a
direct-IP-to-readable-ballot normal route. It is conditional because descriptor
authentication, cryptographic suite selection, operational thresholds, and
runtime evidence remain future work; documentation is not a production
anonymity guarantee.
