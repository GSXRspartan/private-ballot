# Contributing to Private Ballot

Thanks for your interest in improving Private Ballot. This is an independent
open-source project aimed at supporting non-binding governance pilots — with
optional public anchoring on Tari Ootle Esmeralda testnet — and contributions
are welcome.

## License of contributions

Unless you explicitly state otherwise, any contribution you intentionally
submit for inclusion in this project — as defined in the Apache License,
Version 2.0 — is dual-licensed under either of:

* MIT License ([LICENSE-MIT](LICENSE-MIT))
* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at the option of the recipient, matching the project license, with no
additional terms or conditions.

This project does not require a Contributor License Agreement (CLA) and does
not require a Developer Certificate of Origin (DCO) sign-off. If you feel the
matter needs a paper trail (for example, you are contributing on behalf of an
employer with an IP policy) please note that in the pull request description.

Do not contribute code you do not have the right to license under these
terms. In particular, do not paste code copied from a source-available,
copyleft-only, or otherwise incompatibly licensed project.

## Third-party material

If your change adds or updates a vendored library, font, icon, or other
third-party asset:

1. Preserve the upstream license file verbatim.
2. Record the component, upstream, version, and license in
   [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
3. Do not relabel upstream code as project-owned; keep third-party licensing
   distinct from the project license.

The transitive Rust and npm license reports live under
[docs/release/licenses/](docs/release/licenses/). Please regenerate them if
your change adds or removes dependencies (see the header of each report for
the exact command).

## Style and safety expectations

The workspace enforces strict lints (`unsafe_code = forbid`, no `unwrap`,
`expect`, `todo`, `unimplemented`, or `dbg!` in production code). Contributions
that trigger these lints will not be accepted.

Please keep changes focused: a bug fix should not carry unrelated refactors,
and new features should ship with tests that live next to existing tests for
that crate. If you are unsure whether a change fits, open a short issue first.

## Building and testing

See the top-level [README](README.md) and
[docs/OPERATOR_SETUP.md](docs/OPERATOR_SETUP.md) for how to build and run the
Rust workspace, the Tauri desktop shell, and the frontend test suite.

## Reporting security issues

Please read [SECURITY.md](SECURITY.md) before opening a public issue for a
suspected vulnerability. In particular, never attach real election archives,
voter credentials, wallet API keys, transport authority keys, or Tor service
keys to a bug report.

## Tari trademarks

Private Ballot uses the "Tari" and "Tari Ootle" names to describe the
underlying open-source technology it integrates with (Tari Ootle anchoring,
Tari Ootle walletd, and the Tari Triptych implementation). This project is
not an official Tari Labs product, and this license does not grant
permission to use Tari, Ootle, or related trademarks for anything beyond
accurately describing that technology relationship. See
[docs/release/BRAND_TRADEMARK_REVIEW.md](docs/release/BRAND_TRADEMARK_REVIEW.md)
for the current brand-review status.
