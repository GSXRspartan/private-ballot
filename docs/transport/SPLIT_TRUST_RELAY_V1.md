# Split-trust relay V1

The relay boundary accepts only `POST /v1/opaque-envelope`, a fixed transport
content type, no query string, and an exactly configured opaque envelope size.
The forwarding interface has no field for source address, credentials, query
parameters, decrypted ballots, or organizer intake DTOs. Inbound headers,
including `Forwarded`, `X-Forwarded-For`, and `X-Real-IP`, are ignored before
forwarding.

The relay can observe a network source but cannot open the HPKE envelope; the
gateway opens the envelope but receives no application-level source metadata.
Relay/gateway collusion is not protected. Loopback/fake tests cover the strict
envelope boundary; deploying an HTTP listener and completing a multi-machine
rehearsal remain release blockers.
