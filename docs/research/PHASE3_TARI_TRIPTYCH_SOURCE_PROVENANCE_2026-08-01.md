# Tari Triptych source provenance

Status: imported for Phase 3 prototype integration only

This repository contains an exact tracked-source import of the official Tari
Triptych repository for isolated, local, offline prototype work.

## Upstream identity

- Origin: `https://github.com/tari-project/triptych.git`
- Commit: `bf0cb42fff55636a8bb037020411fb3a050af23f`
- Tree: `6825e30904a7815f16987e9fb891ca197e415d08`
- Package: `triptych`
- Version: `0.1.1`
- License: `BSD-3-Clause`
- Imported tracked files: `29`
- Deterministic source digest: `15574CEC65FA148DDD13AC0C05AB5203C6AEB3D1349D1FE57F0BE35656C69555`

The digest frames each sorted UTF-8 path with its byte length and exact blob
length before hashing the exact tracked bytes with SHA-256.

## Integration boundary

- Import path: `third_party/tari-triptych`
- Workspace policy: excluded path dependency
- Crypto dependency features: `default-features = false`
- Project curve substrate: `curve25519-dalek 5.0.0`
- Triptych private substrate: `curve25519-dalek 4.1.3`
- Cross-version boundary: canonical compressed point and proof bytes only

The imported source is not edited or reformatted. Project code must not expose
Triptych or its dalek types through public protocol APIs.

## Security status

Triptych describes itself as experimental. This source import does not establish
the security of the election-scoped generator construction, authorize a binding
election, authorize production deployment, implement proof verification, or add
Ootle-native verification.

Independent cryptographic review remains required.
