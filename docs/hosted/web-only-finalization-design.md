# Web-only finalization design (NOT implemented)

Status: **design only**. This document records the smallest secure change that would
let a Hosted organizer finalize an election that used only Hosted HTTPS voting, without
a Desktop transport-binding handoff. Nothing in this document is implemented in the
current change set, and `do_finalize` is unchanged.

## 1. Why Desktop is currently required

`do_finalize` (`crates/hosted/src/lib.rs`) refuses to finalize without a stored
finalized transport binding:

```
authoritative_transport_binding_bytes(loaded, storage, ledger.accepted_ballots().len())?
    -> 409 transport_binding_required
```

Only `do_store_finalized_transport_binding` writes that row, and it is reachable only
through `POST /api/v1/organizer/elections/{id}/transport-binding` with a
**Desktop-produced** `DesktopBindingHandoffV1`.

Crucially, that handler already derives the expected binding from Hosted's own data
and requires the Desktop bytes to match it exactly:

```rust
let accepted_digests = ballots.map(|b| H(HashDomain::BallotPackageV1, b.package_cbor));
let expected = finalized_transport_archive_binding_from_accepted_digests_v1(
    &issued_descriptor, &accepted_digests)?;
if expected.to_canonical_cbor()? != binding_cbor { return Err(binding_error(...)) }
```

So the Desktop is **not** a cryptographic necessity. The binding is a deterministic
function of `(stored authoritative descriptor, accepted-package ledger)`, both of which
Hosted already holds. The Desktop today acts as an organizational witness that the
accepted set is the intended one.

### A vs B

- **A. Hosted HTTPS ballots.** Recorded in Hosted's own canonical ledger
  (`submissions/*.cbor`, replayed by `LoadedElection::replay_ledger`). Hosted is the
  authoritative recorder.
- **B. Desktop Tor ballots.** Recorded in the organizer Desktop's local transport
  history. Hosted only ever sees the Desktop's exported binding, so for a mixed
  election the Desktop remains the only producer of the batch-set commitment.

## 2. Proposed endpoint

```
POST /api/v1/organizer/elections/{id}/transport-binding/derive
Headers:  x-private-ballot-organizer: <election-scoped capability secret>
Body:     {
            "confirm": "derive-from-hosted-ledger",
            "acknowledge_reduced_anonymity": <bool>
          }
```

Handler steps (all server-side, no client binding bytes accepted):

1. `check_organizer(&state, &headers, &id)` and `organizer_rate(&state, &id)`.
2. `LoadedElection::load`; require `state == "closed"`.
3. Require exactly one stored authoritative descriptor issuance
   (`get_any_descriptor_issuance`); decode with `HostedDescriptorResponseV1` and
   `descriptor.verify(&state.config.transport_authority_root, manifest_hash)`.
   Reject if the descriptor's election id or manifest hash differs.
4. `loaded.replay_ledger(...)`; require a non-empty accepted set.
5. `finalized_transport_archive_binding_from_accepted_digests_v1(&descriptor, &digests)`.
6. Enforce policy from the derived binding:
   - `accepted_unique_count >= GUI_OOTLE_ANCHOR_PUBLISH_MIN_ACCEPTED_BALLOT_FLOOR_V1`
     (else `409 anchor_privacy_floor_not_met`);
   - if any batch reports `reduced_anonymity`, require
     `acknowledge_reduced_anonymity == true` (else
     `409 anchor_reduced_anonymity_ack_required`).
7. `put_finalized_transport_binding(...)`. The existing immutability check makes this
   first-writer-wins; a second call returns `409 transport_binding_immutable`.
8. Return the derived `archive_hash_hex` and `anchor_eligible: true`.

`do_finalize` is **not** modified: it re-validates whatever row exists through
`validate_transport_binding_bytes` and `build_archive_files`.

## 3. Required properties and how they are met

| Property | Mechanism |
|---|---|
| Authorized organizer only | `check_organizer` (election-scoped verifier, constant-time compare) |
| Closed election only | explicit `state == "closed"` guard |
| Authoritative descriptor required | stored issuance, signature-verified against the release root |
| Exact Hosted accepted-package ledger | `replay_ledger` over persisted canonical CBOR |
| Deterministic derivation | `finalized_transport_archive_binding_from_accepted_digests_v1` |
| No client-provided binding bytes | request body carries only a confirmation string and a boolean |
| Immutable / first-writer-wins | existing `put_finalized_transport_binding` guard |
| Reduced-anonymity policy preserved | explicit acknowledgement gate on the derived binding |
| Finalization validation unchanged | `do_finalize` untouched |
| Desktop handoff preserved | existing route retained as an alternative producer |
| Explicit organizer approval | `confirm` string must equal the exact constant |
| Documented trust-model change | this file plus a release note |

## 4. Trust-model change to document at ship time

After this change, for an HTTPS-only election the organizer's *own* Hosted capability
credential authorizes the binding derivation. The Desktop is no longer a witness for
that case. The trust statement becomes: "the ballot office's accepted-package ledger is
authoritative for elections whose ballots were all cast over Hosted HTTPS; Desktop
remains authoritative for elections that include Desktop/Tor ballots." This must be
stated in the organizer UI before the derive action is enabled.

## 5. Recommended tests

Backend (`crates/hosted/src/tests.rs`):

1. Derive on a closed HTTPS-only election returns the same
   `binding_cbor` as the Desktop handoff path for an identical ledger (byte equality).
2. Derive on an `open` election returns `409 invalid_state`.
3. Derive without an organizer credential returns the generic `401`.
4. A foreign-election capability credential returns `401`.
5. Derive without a stored descriptor issuance returns `409`.
6. Derive with a descriptor signed by an untrusted root returns `409`.
7. Derive twice returns `409 transport_binding_immutable`.
8. Derive below the accepted-ballot floor returns `409 anchor_privacy_floor_not_met`.
9. Derive with `reduced_anonymity` and no acknowledgement returns
   `409 anchor_reduced_anonymity_ack_required`; with the acknowledgement returns `200`.
10. A client-supplied `transport_binding_cbor_hex` in the body is ignored (send
    garbage; the derived binding must still win).
11. End-to-end: derive -> finalize -> archive -> anchor-payload, and assert the
    resulting `archive_hash_hex`, `v2_anchor_digest_hex`, and `public_summary_json`
    equal the Desktop-handoff path for the same election.
12. Desktop handoff still works for a mixed election (regression).

Browser (`hosted-web/test/`):

13. The organizer console shows the derivation action only for closed elections, with
    the trust-model disclosure, and requires an explicit confirmation click.
14. The reduced-anonymity acknowledgement checkbox is mandatory when the derived
    binding reports reduced anonymity.

## 6. Explicit non-goals

- No change to `validate_transport_binding_bytes`.
- No relaxation of `do_finalize`.
- No client-supplied binding bytes.
- No new dependency on Desktop availability for HTTPS-only elections.
- No change to the transport authority root or its keys.