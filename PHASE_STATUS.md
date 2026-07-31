# Phase Status

## Overall

Current phase: Phase 1<br>
Current objective: Finalize a review-ready Phase 1 protocol package aligned
with the Tari forum discussion and RFC PR #185.

Phase 1 is not complete.

## Phase 1 checklist

### A. Decisions locked for the MVP

- [x] Offline archive is authoritative during testnet development
- [x] Ootle is an append-only commitment and lifecycle anchor
- [x] Governance keys are separate from wallet keys
- [x] Testnet reset recovery uses transparent re-anchoring
- [x] First real-world pilot is harmless and non-binding
- [x] MVP pilot ballot type is a non-binding approval poll
- [x] MVP duplicate policy is "first valid ballot counts"
- [x] Candidate choices use stable machine identifiers rather than display names
- [x] Duplicate or unknown candidate identifiers are rejected
- [x] An unresolved tie is reported as a tie rather than resolved alphabetically
- [x] Each election manifest records the governance source revision used
- [x] Production cryptography is not copied directly from the Python proof of concept

### B. Unresolved governance or review questions

- [ ] Exact anonymous-membership construction
- [ ] Exact sealed-ballot construction
- [ ] Registry-authorizing body and required signatures
- [ ] Governance-key compromise procedure
- [ ] Anonymous negative-feedback handling
- [ ] Exact binding-election tie rules
- [ ] Exact single-seat IRV rules
- [ ] Multi-seat Council election method
- [ ] Ootle anchor authorization model
- [ ] Binding-election dispute period
- [ ] Independent reviewer or second implementation requirements

### C. Work that must not start yet

- production cryptographic code
- voter GUI
- walletd integration
- Ootle template
- binding election
