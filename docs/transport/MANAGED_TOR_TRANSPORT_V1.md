# Managed Tor transport V1

`transport-network` owns the managed-Tor process boundary; `gui-core` never
starts a process or opens a socket. A configured executable, application-owned
data directory, config file, loopback SOCKS port, and startup timeout are
validated before use. The system spawner uses argument vectors (`tor -f
<config>`) with null stdio and never constructs a shell command.

The generated config is client-only and binds the SOCKS listener to loopback.
Readiness is an injected loopback boundary; test fakes do not contact the
Internet. A timeout or child exit produces only `PRIVATE TRANSPORT UNAVAILABLE`.
Route resolution has no direct-gateway variant: a managed-Tor failure requires
an explicit relay selection or offline export. This is a transport privacy
boundary, not a claim of protection against a global observer.

Executable packaging, licensing, signed updates, and a real multi-machine
rehearsal remain release blockers.
