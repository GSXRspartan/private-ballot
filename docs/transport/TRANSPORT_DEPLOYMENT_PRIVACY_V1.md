# Transport deployment and privacy V1

Default transport errors are coarse. The implemented process, relay, and
gateway boundaries have no source-IP, forwarded-header, client-clock, voter
credential, raw ballot, raw nullifier, receiver-secret, or root-private-key
logging interface. No telemetry is introduced.

Production online submission remains disabled while the root is
`PRODUCTION_TRANSPORT_ROOT_NOT_YET_PROVISIONED`. A release-pinned root set
supports a current root, verification-only historical roots, and explicit
revocation; descriptors choose a known root and cannot install trust roots.
Test roots must be injected explicitly and must never be used as a production
default.
