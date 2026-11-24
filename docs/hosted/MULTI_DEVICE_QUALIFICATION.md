# Multi-device qualification (Phase 18) — staging

## Status

REMOTE UI builds pass locally. No physical-device interaction has been
performed in this branch. Do not fabricate coverage: the matrix below is
the plan, not a result.

**REMOTE WEB QUALIFIED** refers to the local E2E proof (browser WASM
against the local backend) carried over from Stage 2 plus the Stage 3
plane tests. **MULTI-DEVICE MANUAL QUALIFICATION PENDING.**

## Why one headless browser is insufficient

WASM proof generation needs JIT-free WebAssembly + `crypto.getRandomValues`.
Those are exercised headlessly, but device-specific failure modes (mobile
Safari memory limits, WebCrypto subtle-crypto throttling, clipboard/QR
workflows) need real devices.

## Test URL preparation

- Publish the staging Worker (`private-ballot-staging` on
  `*.workers.dev` or a staging hostname) per `CLOUDFLARE_STAGE3.md`.
- Generate a QR code for the staging URL (any QR generator; do not encode
  voter secrets — the URL is public staging, secrets live in memory only).
- Follow test flow: load → privacy notice → election package → voter
  credential → WASM proof → submit → receipt → exact retry → refresh
  receipt lookup.

## Device matrix (record per device)

| device | browser | WASM init | election load | proof | submit | receipt | refresh | notes |
|---|---|---|---|---|---|---|---|---|
| desktop (dev machine) | TBD | TBD | TBD | TBD | TBD | TBD | TBD | — |
| second desktop/laptop | TBD | TBD | TBD | TBD | TBD | TBD | TBD | if available |
| Android | TBD | TBD | TBD | TBD | TBD | TBD | TBD | if available |
| iOS | TBD | TBD | TBD | TBD | TBD | TBD | TBD | if available |

TBD = not yet tested. Update this table with actual browser family,
version, and observed results; a device left TBD is explicitly PENDING.

## Blocking rule

Do not block Stage 3 engineering on a phone that is not physically
attached. Stage 3 closes with the matrix above honestly marked pending
until a human runs the devices.
