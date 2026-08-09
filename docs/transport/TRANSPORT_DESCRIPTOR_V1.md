# Transport Descriptor V1

`TransportDescriptorV1` is a separate canonical CBOR auxiliary object; it does
not alter `ElectionManifestV1`. Its unsigned canonical form is domain-separated
as `tari-cc-private-ballot/transport-descriptor/v1` before an RFC 8032 Ed25519
signature. The signed object binds protocol/version, election ID, manifest hash,
generation, route policy/endpoints, the fixed HPKE suite and gateway key ID/key,
receipt keys, padding/batch policy, optional coarse validity end, and root key ID.

Verification requires the released `TransportAuthorityRootV1` pin, the expected
manifest hash, the exact supported suite, and the signature. A descriptor key
inside the descriptor is never a trust root. Production currently exposes only
`PRODUCTION_TRANSPORT_ROOT_NOT_YET_PROVISIONED`; online transport remains off.

One descriptor fingerprint is pinned per election and generation. A different
valid body for an already-pinned pair is an equivocation conflict, never a
replacement. Later archives must retain the final descriptor and fingerprint.
First-seen pinning does not detect an attacker that controls the first trusted
load; a release-pinned root and future transparency/archive review mitigate it.

Root rotation requires a new release/bootstrap pin with key ID, overlap window,
revocation record, and retained old descriptors/keys for old-election checks.
