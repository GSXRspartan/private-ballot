# Windows native dependency license notes

Companion to the Rust and npm transitive reports. Applies to the current
Windows release configuration (Rust `1.97.1-x86_64-pc-windows-msvc`, vcpkg
triplet `x64-windows-static-md`, Tauri 2 MSI/NSIS bundle).

## OpenSSL

The detached Tauri crate resolves the following Rust bindings:

* `openssl` 0.10.81 — Apache-2.0 (crate manifest).
* `openssl-sys` 0.9.117 — MIT (crate manifest).
* `openssl-probe` 0.1.6 — MIT OR Apache-2.0.

These are Rust wrappers; the actual OpenSSL C library is provided by vcpkg
via the `x64-windows-static-md` triplet and statically linked into the
release binary (`OPENSSL_STATIC=1` in
[../../../tools/load-test/RUN_SCALE_QUALIFICATION.ps1](../../../tools/load-test/RUN_SCALE_QUALIFICATION.ps1)
and the `README.md` Windows build recipe).

OpenSSL is licensed under the [Apache License, Version 2.0](https://openssl-library.org/source/license/index.html)
since OpenSSL 3.0 (the current major release). Older OpenSSL 1.1.x lines used
the dual OpenSSL + SSLeay licenses. Because the OpenSSL bytes are statically
linked into a distributed binary, the Apache-2.0 notice for OpenSSL must be
reproduced next to the installed program (for example, as a `NOTICES` file in
the MSI/NSIS install directory).

### Release-build capture (Private Ballot 0.1.0)

Captured from the actual configured vcpkg installation used by this build
(`C:\purr-tools\vcpkg\installed\x64-windows-static-md`):

* **OpenSSL version:** `3.6.3` (from
  `share/openssl/OpenSSLConfigVersion.cmake` — `set(PACKAGE_VERSION 3.6.3)`).
* **vcpkg tool build:** `vcpkg-2026-05-27-d5b6777d666efc1a7f491babfcdab37794c1ae3e`
  (from `share/openssl/vcpkg.spdx.json`, `creationInfo.creators`).
* **vcpkg port package identifier (SPDX):**
  `openssl:x64-windows-static-md@3.6.3 fd95c6bd33ce123369793019c61f104e3f1d0e58a0b6e7b55aa7ca88672d3305`.
* **Upstream source pinned in SPDX:**
  `git+https://github.com/openssl/openssl@openssl-3.6.3`.
* **Static-link configuration:** `x64-windows-static-md` (static libs against
  the dynamic Universal CRT). Only `lib\libssl.lib` and `lib\libcrypto.lib`
  are exposed; no DLLs are produced by this triplet for OpenSSL.
* **License (per SPDX `licenseConcluded`):** `Apache-2.0`. The full text is
  distributed as `share/openssl/copyright` in the vcpkg tree — copy it as the
  installed-side `NOTICES` entry for OpenSSL.

### Linkage verification for the shipped executable

Ran `dumpbin /dependents` from Visual Studio 2022 Build Tools 14.44.35207
against the release GUI binary
(`gui\src-tauri\target\release\tari-cc-private-ballot-gui.exe`):

* Zero references to any OpenSSL DLL name (`libssl-3-x64.dll`,
  `libcrypto-3-x64.dll`, `ssleay32.dll`, `libeay32.dll`).
* Cryptography imports are Windows-native only: `bcrypt.dll`,
  `bcryptprimitives.dll`, `crypt32.dll`.

This confirms OpenSSL is fully statically linked and the release MSI/NSIS
installers do not need to ship an OpenSSL DLL beside the executable. No
dynamic loader dependency on a system OpenSSL exists.

### Redistribution deliverables (still to place beside the installer)

* A `NOTICES\OpenSSL-LICENSE.txt` containing the Apache-2.0 text from
  `C:\purr-tools\vcpkg\installed\x64-windows-static-md\share\openssl\copyright`
  and a plain-text note that OpenSSL 3.6.3 is statically linked into
  `tari-cc-private-ballot-gui.exe`.
* Cross-reference from the Windows Add/Remove Programs registry entry
  (Tauri's installer control panel banner) to that NOTICES file.

## Other statically-linked native libraries

The vcpkg static-MD triplet installed on this build machine surfaces the
following ports under `share/`:

* `openssl` — handled above.
* `sqlite3` (and `unofficial-sqlite3`) — Public Domain (SQLite is a
  documented dedication to the public domain by the SQLite authors).
  `sqlite3.lib` is present under the same static-MD triplet; it is pulled
  in transitively by Tauri storage bindings.

Historically the static-MD triplet was expected to also surface `zlib` and
`bzip2` — those are NOT present in this build machine's vcpkg installation
today and are not directly linked. Any future addition (e.g. if a Tauri
version bump reintroduces a compression dependency) MUST be recorded here
and cross-referenced in `THIRD_PARTY_NOTICES.md`.

* WebView2 runtime — this is a Microsoft-provided runtime component, not
  a static library. The MSI installer relies on a system-installed WebView2;
  users on Windows 11 already have it. Its distribution terms are governed
  by the Microsoft Edge WebView2 runtime distribution license.

Regenerate this note whenever the vcpkg triplet, Tauri major version, or the
Rust `openssl-sys` version changes.
