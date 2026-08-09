# Transport admission and close V1

The authoritative online cutoff is successful gateway/core admission while the
transport gate and core election are both `OPEN`. Client clocks, relay arrival,
and queue arrival are not authority. The gate transitions `OPEN -> CLOSING ->
CLOSED`; closing rejects new work, lets already admitted work drain, and closes
the core only after drain completion or expiry. A drain generation invalidates
expired work before core intake, preventing a generic post-close path.

This implementation exposes a caller-driven bounded drain primitive; binding it
to a production monotonic scheduler remains required before public operation.
