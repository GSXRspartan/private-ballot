# Phase 4 Slice 4A5 — Pinned Tari Ootle Transaction-Construction Adapter

**Date:** 2026-08-04
**Crate added:** `tari-cc-private-ballot-ootle-anchor-adapter` (`crates/ootle-anchor-adapter`)
**Status:** implemented, validated, and staged — **not committed**.

---

## 1. Repository preconditions

| Check | Result |
|---|---|
| Branch | `phase4/ootle-testnet-anchor-prototype` |
| Required starting HEAD | `2f2a71f62e29f7ab843284ef646271d00cbf3411` |
| HEAD after work (unchanged) | `2f2a71f62e29f7ab843284ef646271d00cbf3411` |
| Working tree before work | clean (`git status --porcelain` empty) |
| Rust version | `rustc 1.97.1 (8bab26f4f 2026-07-14)` |

### Toolchain note (Rust 1.97.1)

The repository pins `channel = "1.97.1"` (`rust-toolchain.toml`); the active host is
`1.97.1-x86_64-pc-windows-gnu`. That GNU toolchain's bundled `self-contained`
binutils ships `dlltool.exe` but **not** `as.exe`, and no `as.exe`/`llvm-dlltool`
exists anywhere under `~/.rustup`. The pinned Ootle stack transitively pulls
`getrandom v0.4.3`, whose Windows `raw-dylib` linking requires a complete
binutils on the GNU target, so **full codegen (build/test) fails on the GNU host
offline** with `dlltool: CreateProcess`. `cargo check` (no dep codegen) succeeds
on GNU.

All build/test/clippy validation was therefore run with the **co-installed
`stable-x86_64-pc-windows-msvc` toolchain, which is byte-identical Rust 1.97.1**
(`rustc 1.97.1 (8bab26f4f 2026-07-14)`); MSVC supports `raw-dylib` natively and
needs no `dlltool`. This is a local, offline toolchain selection only: the host
ABI is a linker detail, not the Rust version, and no source change was made to
accommodate it. Resolving the GNU `raw-dylib` gap (installing MinGW binutils)
requires the network and is out of scope; see §17 unresolved questions.

Every Cargo operation used `--locked --offline` after the lockfile was
established.

---

## 2. Pinned Tari Ootle dependency

| Field | Value |
|---|---|
| Git URL | `https://github.com/tari-project/tari-ootle` |
| Pinned `rev` | `92023e0` |
| Resolved full commit | `92023e0b7c2fabf7df2f8ee23a2cc252d3c34f9f` |
| Commit subject | `fix(mempool): withhold invalid transactions from gossip propagation (#2362)` |
| Commit date | 2026-07-20 |
| Ootle workspace version | v0.37.0 |
| Local checkout | `C:\Users\pdark\.cargo\git\checkouts\tari-ootle-fb4571cb31b11274\92023e0` |
| Local git db | `C:\Users\pdark\.cargo\git\db\tari-ootle-fb4571cb31b11274` |

Offline resolution was verified before any implementation: `cargo metadata
--offline` resolved `rev = "92023e0"` to the full commit and pulled all Ootle
crates + 125 transitive packages from the local cache with **zero network
access**. The canonical GitHub URL hashes to the pre-existing cache directory
`fb4571cb31b11274`, confirmed empirically by the successful offline resolve.

### Direct dependencies added (pinned, exact-rev)

```toml
tari_ootle_transaction  = { git = "https://github.com/tari-project/tari-ootle", rev = "92023e0" }  # 0.37.0
tari_template_lib_types = { git = "https://github.com/tari-project/tari-ootle", rev = "92023e0" }  # 0.29.0
minicbor = { version = "2.2", default-features = false, features = ["alloc"] }                      # resolved 2.3.0
```

No branch dependency, no tag-only dependency, no wildcard, no floating Git HEAD.
The confirmed-API crates come from the git checkout (no crates.io substitution).
`minicbor` is a normal third-party crate (canonical CBOR encoder for the
fingerprint) pinned to the version already in the Ootle tree, so no new version
is introduced. Project path deps: `tari-cc-private-ballot-anchor-transport`,
`tari-cc-private-ballot-anchor`, `tari-cc-private-ballot-protocol` (production
BLAKE3 provider, reused only for the adapter fingerprint).

`Network` is consumed via `tari_ootle_transaction::Network` (re-exported), so no
separate `ootle-network` direct dependency is needed.

---

## 3. Confirmed local API inventory (matches the 4A3 inventory)

| Type / fn | Local source (rev 92023e0) | Confirmed shape |
|---|---|---|
| `Instruction::EmitLog` | `crates/transaction/src/v1/instruction.rs:74-81` | `{ level: LogLevel, message: MaxString<{ limits::ENGINE_LIMITS.max_log_size_bytes }> }` |
| `LogLevel` | `crates/template_lib_types/src/log_level.rs:17-26` | `Error, Warn, Info, Debug` |
| `MaxString<const N>` | `crates/template_lib_types/src/max_string.rs:13` (`TryFrom<String>` at `:113`) | `MaxString<const N: usize>(Box<str>)` |
| `max_log_size_bytes` | `crates/engine_types/src/limits.rs:110` | `32 * 1024 = 32768` |
| `TransactionBuilder::new` / `add_instruction` / `build_unsigned` | `crates/transaction/src/builder/mod.rs:82` / `:800` / `:259` | `new<N: Into<u8>>` → `add_instruction(Instruction) -> Self` → `build_unsigned() -> UnsignedTransaction` |
| `Network` | `crates/ootle_network/src/lib.rs:20-34` (re-export `crates/transaction/src/lib.rs:39`) | `MainNet=0x00, StageNet=0x01, NextNet=0x02, LocalNet=0x10, Igor=0x24, Esmeralda=0x26` |
| `UnsignedTransaction` | `crates/transaction/src/unsigned_transaction.rs:28` | `enum { V1(..) }`; `minicbor::Encode/Decode/CborLen`; `schema_version()->u16 :42`, `network()->u8 :55`, `instructions()->&[Instruction] :92`, `fee_instructions()->&[Instruction] :80`, `inputs()->&IndexSet<..> :110`, `blobs()->&Blobs :216` |
| walletd `CallInstructionRequest` | `clients/wallet_daemon_client/src/types.rs:111-134` | `{ instructions: Vec<Instruction>, fee_account: ComponentAddressOrName, max_fee: u64, .. }` |

**No material differences from the 4A3 inventory were found.**

---

## 4. Fee architecture decision (confirmed from source)

**Decision: walletd-injected fees. The adapter constructs only the normal
instruction list (one `EmitLog`) as a real, fee-less `UnsignedTransaction`, plus
an offline project-owned walletd preparation DTO carrying the fee account and
maximum fee. It never invents fee instructions.**

Evidence:

1. The wallet daemon's `CallInstructionRequest`
   (`clients/wallet_daemon_client/src/types.rs:111-134`) takes a bare
   `instructions: Vec<Instruction>` **plus separate** `fee_account:
   ComponentAddressOrName` and `max_fee: u64`; walletd resolves the account and
   injects the fee instructions during preparation.
2. The project account reference (`AnchorAccountReference`) is an **opaque
   bounded string**, not a resolved Ootle `ComponentAddress`, so this adapter
   cannot call `pay_fee_from_component(...)` even if it wanted to.
3. `pay_fee_from_component` produces a component `CallMethod` fee instruction,
   which would violate the "no component call" inspection invariant.

Consequently `fee_instructions_present == false` on every build, and the fee
account / max fee are preserved verbatim in `OotleWalletdAnchorPreparationV1` for
Slice 4A6.

---

## 5. Transaction construction decision

`build_unsigned_anchor_transaction` builds:

```text
TransactionBuilder::new(<mapped Network>)
    .add_instruction(EmitLog { level: Info, message: <103-byte payload> })
    .build_unsigned()
```

The result is a real pinned `UnsignedTransaction::V1` with exactly one normal
instruction, **zero** fee instructions, **zero** inputs (`fill_inputs` defaults
false; `EmitLog` adds no inputs — `builder/mod.rs:870-939`), **zero** blobs, and
no signatures/id (guaranteed by the `UnsignedTransaction` type, which carries
neither — those exist only after sealing). The unsigned transaction is reachable
only inside this leaf crate, via `OotleAnchorBuildResultV1::unsigned_transaction`.

---

## 6. Emitted payload (exact)

```text
TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V1:<64 lowercase hex digest>
```

* Fixed prefix (38 bytes) + `:` (1 byte) + 64 hex chars = **exactly 103 bytes**.
* Level: `LogLevel::Info` (reliably persisted; does not imply error/warning).
* The message is byte-for-byte `AnchorLogPayloadV1::to_encoded_string()`: no case
  change, prefix change, whitespace, newline, JSON wrapper, CBOR-to-hex, or
  election hashing. Proven by `construction.rs::anchor_emit_log_message_is_byte_for_byte_the_payload_and_103_bytes`.

Example (digest = 0x22 × 32):
`TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V1:2222222222222222222222222222222222222222222222222222222222222222`

---

## 7. Network mapping (Section B)

`map_ootle_network(&OotleNetworkIdV1)` is an explicit, exhaustive, exact-match
table — no default, no env fallback, no address inference, no string passthrough,
no `Network::from_str`:

| Project id (exact, lowercase) | Ootle `Network` |
|---|---|
| `esmeralda` | `Network::Esmeralda` (0x26) |
| `igor` | `Network::Igor` (0x24) |
| `localnet` | `Network::LocalNet` (0x10) |

Rejected with `UnsupportedNetwork`: `mainnet`, `stagenet`, `nextnet`
(out of scope for a non-binding testnet pilot); casing variants (`Esmeralda`,
`ESMERALDA`); the `esme` alias; and any similar/separated name. Covered by the 6
`network_mapping.rs` tests.

---

## 8. Inspection & evidence (Sections E/F)

`inspect_unsigned_anchor_transaction` is a pure validator that both produces the
build evidence and rejects invalid/mutated transactions. On success it proves:
intended network matches; exactly one anchor `EmitLog` at index 0 with the exact
expected digest; no conflicting/duplicate anchor log; no unexpected instruction;
no component call; no resource transfer; no fee instruction; no input; no blob;
schema version 1. It returns `OotleUnsignedAnchorTransactionEvidenceV1`
(network, ootle network byte, account, digest, exact payload, instruction count,
anchor index, `fee_instructions_present=false`, input/blob counts, schema
version, and a domain-separated BLAKE3 **inspection fingerprint** — explicitly
**not** a transaction id). Signer/key fields and a transaction id are impossible
by the `UnsignedTransaction` type itself.

The fingerprint frames
`b"tari-cc-private-ballot/ootle-anchor-adapter/unsigned-inspection-fingerprint/v1"
|| 0x00 || minicbor(unsigned_tx)` through the production BLAKE3-256 provider —
distinct from the protocol and anchor-record frames.

---

## 9. Error mapping (Section G)

`OotleAnchorAdapterError` variants: `UnsupportedNetwork`,
`InvalidFeeConfiguration`, `PayloadConversion`, `BoundedStringConversion`,
`TransactionBuilderFailure`, `UnexpectedInstruction`, `MissingAnchorInstruction`,
`DuplicateAnchorInstruction`, `ConflictingAnchorInstruction`,
`ComponentCallPresent`, `ResourceTransferPresent`, `ArbitraryBlobAttached`,
`UnexpectedInput`, `UnexpectedFeeInstruction`, `MalformedAnchorPayload`,
`AnchorDigestMismatch`, `NetworkBindingMismatch`, `UnsupportedTransactionSchema`,
`UnsignedInspectionFailure`, `FingerprintFailure`. Diagnostics are fixed strings
or the already-bounded, non-secret network name; no raw third-party error is
leaked and no account secret appears in `Debug`/`Display`
(`AnchorAccountReference` `Debug` is redacted upstream).

---

## 10. Mutation-test results (Sections F/J) — all rejected, no panics

| Mutation | Rejection |
|---|---|
| wrong network | `NetworkBindingMismatch` |
| missing `EmitLog` | `MissingAnchorInstruction` |
| duplicate identical anchor logs | `DuplicateAnchorInstruction` |
| conflicting anchor logs | `ConflictingAnchorInstruction` |
| malformed anchor prefix | `MalformedAnchorPayload` |
| uppercase digest | `MalformedAnchorPayload` |
| wrong digest | `AnchorDigestMismatch` |
| unrelated log only | `MissingAnchorInstruction` |
| anchor + component call | `ComponentCallPresent` |
| anchor + resource transfer | `ResourceTransferPresent` |
| anchor + arbitrary blob | `ArbitraryBlobAttached` |
| unexpected fee instruction | `UnexpectedFeeInstruction` |
| anchor + extra instruction | `UnexpectedInstruction` |
| altered ordering (anchor not first) | `UnexpectedInstruction` |

Unsupported transaction schema is structurally unreachable (single-variant
`UnsignedTransaction` enum); the valid path asserts schema version 1.

---

## 11. Fake/real parity (Section I) & archive independence (Section L)

* **Parity** (`fake_real_parity.rs`): the deterministic 4A4
  `DeterministicAnchorFake` and the real Ootle adapter agree on anchor digest,
  exact anchor payload bytes, network, account reference, fee policy, and client
  reference; neither claims a transaction id before submission or any finality.
  The fake's post-submission id remains fake-only and is never compared to the
  unsigned Ootle transaction.
* **Archive independence** (`archive_independence.rs`): a real
  `OotleAnchorRecordV1` + `ArchiveHashV1` + `ManifestHash` are byte-identical
  (canonical CBOR, digests, raw hashes) after a successful construction and after
  network-mapping and mainnet-rejection failures. The adapter only ever receives
  the frozen digest (via the payload), never the record.

---

## 12. Dependency & feature audit (Section K)

* Normal runtime graph: **139 crates**. Full offline `cargo tree --edges normal`
  scanned for `tokio, async-std, smol, mio, reqwest, hyper, isahc, ureq, surf,
  rustls, openssl, native-tls, libp2p, multiaddr, quinn, axum, tonic, jsonrpsee,
  wallet_daemon, walletd, indexer, hazmat` → **NONE FOUND**.
* No async runtime, no HTTP client, no TLS, no P2P, no walletd/indexer client.
* Crypto/serialization transitives (expected, via `tari_crypto`/`tari_hashing`/
  protocol): `tari_crypto 0.23.2, curve25519-dalek 5.0.0, blake2 0.10.6,
  blake3 1.8.5, sha2 0.10.9, sha3 0.10.9, chacha20 0.10.1, zeroize 1.9.0,
  subtle 2.6.1, ff 0.14.0, group 0.14.0, digest 0.10/0.11, rand 0.10.2,
  getrandom 0.4.3`. These back the Ristretto types that appear in transaction
  types; the adapter never constructs or handles a secret key.
* Feature audit: `tari_crypto` is enabled with only the **`borsh`** feature — no
  `hazmat`, no variable-time-crypto feature, no local-signing feature.
* `tari_ootle_transaction` default features pull no networking or signing;
  serde/ts are not enabled.

---

## 13. Validation summary (all Rust 1.97.1, `--locked --offline`)

| Step | Result |
|---|---|
| rustfmt (adapter package) `--check` | clean |
| adapter crate tests | **33 passed**, 0 failed (network 6, construction 7, inspection 15, parity 2, archive 1, dep-audit 2) |
| anchor-transport regression tests | **72 passed** |
| anchor regression tests | passed (canonical Ootle anchor vectors) |
| protocol regression tests | **30 passed** |
| workspace `cargo check` | clean (only pre-existing vendored `triptych` warning) |
| workspace tests (ignored suites skipped) | all passed — crypto 48, registry 19, tally 6, verifier 27, verifier/real_triptych 10, plus cli non-ignored; heavy suites (`large_scale_real_triptych_elections`, `triptych_padding_boundary_assurance`, `triptych_adversarial_assurance`, `triptych_performance_harness`, `triptych_protocol_limit`) are `#[ignore]`d and were not run |
| clippy `-p adapter --all-targets -- -D warnings` | clean |
| offline `cargo tree` audit | clean (see §12) |

No `unwrap()`, `expect()`, `todo!()`, `unimplemented!()`, `unsafe`, or warning
suppression in adapter code; `#![forbid(unsafe_code)]` present.

The large election suite, padding-boundary long suite, timing suite, fuzz
campaigns, and network tests were **not** run.

---

## 14. Change scope — vendored & Phase 1–3 source unchanged

`git diff --name-only HEAD` (tracked): only `Cargo.toml` (+1 line: new member)
and `Cargo.lock` (Ootle deps). Untracked: `crates/ootle-anchor-adapter/`. **No
Phase 1–3 protocol/crypto/archive/verifier/tally/ballot/registry source, no
`third_party/tari-triptych` vendored source, and no anchor/anchor-transport
source was modified.** The adapter is a leaf crate depended on by nothing.

---

## 15. Staged blobs (byte count + SHA-256)

| Staged path | Bytes | SHA-256 |
|---|---:|---|
| `Cargo.lock` | 43111 | `462e392c1bafdbb1d1cfe8e8308ed1b7b419217094ca9461098ffe9ee9d4ca0f` |
| `Cargo.toml` | 570 | `918bc49c3d15749e9e9c7ee58205faaa82d4f4258710a6fbde57ca2e47abdb25` |
| `crates/ootle-anchor-adapter/Cargo.toml` | 2702 | `16950d206cf5eda794649f4be20f442dddf93b6b71d2da855d25f489d2d5fa03` |
| `crates/ootle-anchor-adapter/src/build.rs` | 6758 | `3ff676eb4e928059d3554af94500a608adc9b7e9ff30a59423b562976778facd` |
| `crates/ootle-anchor-adapter/src/constructor.rs` | 1925 | `cbf0fd2ed2da28a85d671ce36d6d60811e9d8fda2635020c1421b48aa7623f4e` |
| `crates/ootle-anchor-adapter/src/errors.rs` | 6554 | `ff80e18c972d124c21d605eddd2e467d5b9481a25bab61628d49b171fd374824` |
| `crates/ootle-anchor-adapter/src/evidence.rs` | 4327 | `6f6636ca31f7a7c73e3c515ac17ce0855ccf72d1eb56df37493eb6210055cdf3` |
| `crates/ootle-anchor-adapter/src/inspect.rs` | 10827 | `be2fb35030c057e6c3f951d01f50fe3ab661ac2cfc262e679cfbc4a4a017140e` |
| `crates/ootle-anchor-adapter/src/lib.rs` | 2262 | `f30828bf05830aa092d4e3fa625e006b5984b56d243b9c33e5660bf30ed67ec2` |
| `crates/ootle-anchor-adapter/src/log_instruction.rs` | 1913 | `08802681d8fb17232c6826a065467ddfda3d21974fe896f5e19347ce419dab05` |
| `crates/ootle-anchor-adapter/src/network.rs` | 2467 | `6641caed657a0c8d034cfb809b57f5dd9850b3a958dfd4924f67aa677dde95f2` |
| `crates/ootle-anchor-adapter/src/request.rs` | 2830 | `6493ffbf653705e583c3954baf6b54cd8af82e4f651bf9e6b9d2d9331b55268e` |
| `crates/ootle-anchor-adapter/tests/archive_independence.rs` | 3598 | `a3dd47a1f0d6823a02cd97770128a4dad98a21d6000346ed56d6bbc1aa84694d` |
| `crates/ootle-anchor-adapter/tests/common/mod.rs` | 2828 | `6a81aaaf6adbfc1ae0db718bf42d21c7748d4bceda85d1c018605993221aaff1` |
| `crates/ootle-anchor-adapter/tests/construction.rs` | 6331 | `464ce8b90d15a3801b6b6ca70ac39c30a4b82dccba2d66538a2125531e1414b1` |
| `crates/ootle-anchor-adapter/tests/dependency_audit.rs` | 2103 | `f537a9558927edf10d66fab74a32ed932cd2177b3bf8c3acaabafd879327e763` |
| `crates/ootle-anchor-adapter/tests/fake_real_parity.rs` | 5220 | `064e8c4b792379077ef84c980f7b42dc7d6bfd9ca9af4b6a8c158f9697d86745` |
| `crates/ootle-anchor-adapter/tests/inspection_mutations.rs` | 8463 | `2de908bfa64c05c5f3f34fea56f4c1dd7aa69ae10a5b0d710eefeb178f002b0b` |
| `crates/ootle-anchor-adapter/tests/network_mapping.rs` | 3344 | `dac3d2b2facab910369f311331696b7fc1fc99e3e740c9672bddc84d13ceb77d` |

This evidence file (`docs/reviews/PHASE4_SLICE4A5_PINNED_OOTLE_TRANSACTION_ADAPTER_2026-08-04.md`)
is the 20th staged file; its own SHA-256 and the binary-patch size + SHA-256 are
reported in the session's final output (a file cannot embed its own final hash).
`git diff --cached --check` reports no whitespace errors.

---

## 16. Confirmations

* **No transaction was submitted.** The adapter only constructs an
  `UnsignedTransaction`; it never seals, signs, or submits.
* **No network contact occurred.** All Cargo operations ran `--offline`; the
  adapter contains no networking, walletd, or indexer code.
* **No walletd / indexer connection** and **no testnet funds spent.**
* **No commit was created.**
* **No private-key or wallet-secret code exists** in the adapter.

---

## 17. Unresolved questions for the walletd adapter (Slice 4A6)

1. **Fee injection & account resolution.** 4A6 must resolve the opaque
   `AnchorAccountReference` to a walletd `ComponentAddressOrName` and submit via
   `CallInstructionRequest { instructions, fee_account, max_fee }`. The exact
   idempotency/`proof_ids`/`inputs` semantics for a bare `EmitLog` need
   confirmation against a live walletd.
2. **Active target network.** The mapping supports `esmeralda`/`igor`/`localnet`;
   final testnet selection is deferred to a configuration slice.
3. **Transaction id & receipt.** The sealed transaction id and ordered receipt
   logs are only observable after 4A6 submission; the fake models them but the
   real id encoding is not yet pinned.
4. **GNU toolchain `raw-dylib`.** Building on the pinned
   `1.97.1-x86_64-pc-windows-gnu` host offline requires a complete MinGW
   binutils (`as`); currently only the MSVC 1.97.1 host builds the Ootle stack
   offline. CI/host provisioning should install MinGW binutils or standardise on
   the MSVC host for Ootle-dependent crates.

---

## 18. Go / no-go recommendation for Slice 4A6

**GO.** The pinned Ootle transaction-construction boundary is proven offline: the
exact revision resolves and builds from local cache, the API matches the 4A3
inventory, the fee architecture is confirmed (walletd-injected), the single
`EmitLog` anchor transaction is constructed and fully inspected, all 33 adapter
tests plus Phase 1–3 regressions pass, and the dependency/feature audit is clean
(no networking, key custody, async, or TLS). Slice 4A6 can consume
`OotleAnchorBuildResultV1` (unsigned transaction + `OotleWalletdAnchorPreparationV1`)
directly. The only environment caveat is the GNU-host `raw-dylib` gap (§17.4).
