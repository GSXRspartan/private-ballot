# Linux release artifacts — Private Ballot 0.1.0

Captured from a clean-clone Tauri 2 release build on Ubuntu 24.04 LTS
Noble Numbat (WSL2, kernel 5.10.16.3, GLIBC 2.39, Rust
`1.97.1-x86_64-unknown-linux-gnu`, Node 24.14.0, cargo 1.97.1).

## Artifacts and SHA-256

```
6f05cc97e87db5ca96813fa8cd60acd1b76e04eea8aa611377fd6f27d35aa0ae  Private Ballot_0.1.0_amd64.deb
c8f99702264f57508faadfbcf6fa806c9355d6936f62259bd3fd549819cea4e9  Private Ballot-0.1.0-1.x86_64.rpm
2dd8227968756bfce54820c53017a61f051d17f58f2666dbe45420cfb05afe59  Private Ballot_0.1.0_amd64.AppImage
2f3e9ab74abd84539115868261e24ba19dc04ca9a75b552aa0f1129e35695b0c  tari-cc-private-ballot-gui  (release ELF binary, PIE, glibc 2.39)
```

Sizes:

| Artifact | Bytes | Notes |
| --- | --- | --- |
| `Private Ballot_0.1.0_amd64.deb` | 14,278,154 | `Depends: libwebkit2gtk-4.1-0, libgtk-3-0` |
| `Private Ballot-0.1.0-1.x86_64.rpm` | 14,280,355 | rpm auto-Requires from ELF NEEDED |
| `Private Ballot_0.1.0_amd64.AppImage` | 88,508,920 | self-contained; `linuxdeploy` bundles GTK/GDK/X11/Wayland/freetype/etc. |
| `tari-cc-private-ballot-gui` | 36,576,568 | ELF64 PIE, BIND_NOW, not stripped |

Note: the raw ELF binary is NOT a shipped installer format. It is
listed only as the underlying build output and cross-check for `.deb`
and `.rpm` payloads.

## Release configuration verified

* Product name in `.deb` control: `Package: private-ballot`,
  `Description: Private Ballot desktop client (independent open-source
  project)`.
* `.desktop` entry: `Name=Private Ballot`, `Categories=Utility;`,
  `Exec=tari-cc-private-ballot-gui`,
  `StartupWMClass=tari-cc-private-ballot-gui`.
* Feature graph: `default = ["managed-tor"]` (production managed-Tor
  enabled by default; see [`gui/src-tauri/Cargo.toml:47`](../../gui/src-tauri/Cargo.toml)).
* Rust toolchain resolved by `rust-toolchain.toml`:
  `1.97.1-x86_64-unknown-linux-gnu`.
* No `libssl.so`/`libcrypto.so` runtime linkage
  (see [`licenses/LINUX_NATIVE_DEPENDENCIES.md`](licenses/LINUX_NATIVE_DEPENDENCIES.md)).

## Not covered by this build

* No physical GUI runtime smoke test (this qualification host is WSL2
  without WSLg / DISPLAY). Recorded as "PHYSICAL / INTERACTIVE
  RUNTIME TESTING PENDING", not FAILED.
* No live managed-Tor smoke test — the `tor` binary was not installed
  on the qualification host, and the Linux qualification did not include
  installing it. The transport-gateway managed-tor test suite (69/0/1/10)
  covers the source-level behaviour.
* No code signing. Linux does not require it, but distributions that
  bind a package to a repo signature (apt/rpm) will need the maintainer
  to sign the release before publication.
