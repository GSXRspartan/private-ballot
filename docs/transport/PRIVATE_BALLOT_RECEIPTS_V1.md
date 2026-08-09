# Private Ballot Receipts V1

`VoterTransportReceiptV1` contains only a coarse state and retry status. It
never serializes `GuiBallotIntakeResultV1`; consequently it carries no sequence,
duplicate sequence, raw nullifier, registry index, source metadata, identity,
or precise timestamp. This slice can return `RECEIVED`, `ACCEPTED`, or the
coarse `REJECTED`; `INCLUDED` and `ANCHORED` remain unimplemented.

The gateway records the actual safe terminal outcome. Retrying the same
capability and package therefore preserves an earlier duplicate/rejection;
only an earlier accepted package returns `PreviousDeliveryAccepted`. Reusing a
capability for different bytes returns a generic rejected response.

The client generates a new random 32-byte capability per submission. The
gateway retains only its domain-separated commitment plus package digest and
coarse receipt state, with no source metadata. Retention/deletion period must
be configured before online use; this in-memory simulator has process-lifetime
retention only. Same bytes/capability return prior acceptance; a different
package remains a generic duplicate response.
