# Changelog

All notable changes to `psrp-rs` are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [2.0.2] — 2026-09-04

Disconnect/reconnect now works against a live server. It never did before —
the path was only ever exercised by `MockTransport`. Requires `winrm-rs`
1.2.2, which makes the underlying WinRM shell disconnectable.

### Fixed

- **Reconnect replayed the PSRP handshake and then timed out.**
  `DisconnectedPool::reconnect` re-sent `SessionCapability` +
  `ConnectRunspacePool` and waited for a fresh `RunspacePoolState=Opened`,
  but after an existing-client WSMan `Reconnect` — same `SessionId`, so the
  server keeps the runspace `Opened` — there was nothing more for the server
  to send, and the follow-up Receive died with `w:TimedOut`. Reconnect now
  resumes straight to `Opened` with no PSRP message, matching pypsrp's
  `_connect_existing_client`. The state machine only resumes a genuinely
  resumable pool (`BeforeOpen` or `Disconnected`); a fuzz run caught the
  first cut resurrecting a closed pool into `Opened`, so the guard is now
  explicit. Verified live on Server 2025: open, run, disconnect, reconnect,
  run again, close. (`src/runspace/pool.rs`, `src/runspace/state.rs`)

## [2.0.1] — 2026-09-04

A shell-lifecycle leak, found by running the crate against live Windows
hosts — Server 2012 R2 and Server 2025 — rather than by reading it. It pairs
with the two leaks fixed in `winrm-rs` 1.2.1, which this release now
requires: without that one, closing a PSRP pool addressed the Delete to the
`cmd` plugin, the server answered `InvalidSelectors: the shell was not
found`, and the runspace kept running.

### Fixed

- **A failed `RunspacePool::disconnect` abandoned the runspace.**
  `disconnect` takes `self`, so an error from the transport destroyed the
  pool — and with it the caller's only handle to a runspace that was still
  live on the server. The WinRS PowerShell plugin rejects Disconnect on both
  Server 2012 R2 and Server 2025, so every attempt leaked one runspace
  against `MaxShellsPerUser` (30 by default), after which every new pool
  failed to open with `InternalError`. The shell is now closed through the
  transport before the original error is surfaced.
  (`src/runspace/pool.rs`)

### Changed

- **`winrm-rs` requirement raised to `"1.2.1"`** (from `"1.2"`). 1.2.1 is
  what makes `Shell::close` address Delete under the shell's own
  ResourceURI, which is the other half of the leak above.

### Known

- `live_disconnect_reconnect_pool` still exercises nothing on a real server.
  Server 2025 refuses the Disconnect with `This WinRS shell instance does not
  support disconnect and reconnect operations because it was created by an
  older WinRS client`, so the shells created through `WinrmPsrpTransport` are
  not marked disconnect-capable on any Windows tested. The whole
  disconnect/reconnect path remains covered by `MockTransport` only.

## [2.0.0] — 2026-09-03

Also ships everything listed under [1.1.0](#110--2026-06-03), which was
**never released** — it was only ever a version number in `Cargo.toml`,
with no tag and nothing published. 1.0.0 was the last release, so
upgrading from it picks up the SSH transport and host-key verification
as well as everything below.

### Breaking changes

- **`SshConfig` is now `#[non_exhaustive]`, and gains a builder**
  (`ssh` feature). The 1.1.0 work added a `host_key_policy` field to a
  struct that could be built with an exhaustive literal, which
  `cargo semver-checks` correctly flags as a major-version break. Rather
  than repeat that on the next field, the struct is now non-exhaustive —
  which means a struct expression from another crate is rejected
  outright, *including* `..SshConfig::default()`. Construct one with
  `SshConfig::new(host, username, auth)` plus `with_port`,
  `with_subsystem`, `with_connect_timeout` and `with_host_key_policy`:

  ```rust
  // before
  SshConfig { host: "h".into(), port: 2222, username: "u".into(),
              auth: SshAuth::Agent, ..Default::default() }
  // after
  SshConfig::new("h", "u", SshAuth::Agent).with_port(2222)
  ```

  The fields stay public, so an existing value can still be read and
  mutated in place.
- **MSRV raised to 1.98** (from 1.94).
- **`winrm-rs` requirement raised to `"1.2"`** (from `"1.0"`), so the
  fixed SOAP envelope builder cannot be resolved away. See below.

### Security

- **Remote denial of service in the CLIXML parser.** `parse_clixml` is
  recursive and the document comes from the remote host; with no depth
  limit, roughly 10 KiB of nested `<Obj><MS>` overflowed the stack and
  **aborted the process** (a stack overflow is not a catchable panic, so
  `#![forbid(unsafe_code)]` offered no protection). Nesting is now capped
  by the new public constant `MAX_NESTING_DEPTH` (64) and an over-deep
  document returns a structured error. Found by fuzzing.
- **Denial of service in SSH host-key verification.** The `known_hosts`
  glob matcher was recursive and explored every way of distributing the
  hostname across `*` wildcards, so a pattern such as `*a*a*a*a*b`
  against a long hostname hung the trust decision itself. Replaced with
  an iterative single-backtrack matcher: `O(n*m)`, no recursion, same
  semantics. Found by the `known_hosts_match` fuzz target.
- OpenSSH host **certificates** are now refused under every
  `HostKeyPolicy` except `AcceptAny`, since the crate carries no CA
  trust store. (russh 0.63 started surfacing them.)
- **A closed or broken runspace pool could be re-opened by the client.**
  `RunspacePoolStateMachine::open` / `connect` overwrote the state
  unconditionally, so a terminal machine could be driven back through
  the handshake into `Opened` — the very resurrection
  `is_legal_server_transition` already refused on the server side. Both
  now refuse once the machine is terminal, exposed as `is_terminal()`.
  Found by the `runspace_state_machine` fuzz target.

### Fixed

- **CLIXML attribute values were never XML-unescaped.** A property name
  containing `&`, `<`, `>`, `"` or `'` came back still escaped, and the
  encoder escaped it again on the next hop, so `&lt;` grew into
  `&amp;lt;` and onwards without bound. Attribute values are now
  normalised and `_xHHHH_`-decoded, mirroring the encoder exactly.
- **Tabs, CRs and LFs inside a property name were folded to spaces** by
  XML attribute-value normalisation. The encoder now emits them as
  `_xHHHH_` in attribute position (element text is unaffected).
- **A list or dictionary stored under the synthetic `_value` property
  did not round-trip.** The encoder wrote `<Obj><Obj><LST/></Obj></Obj>`;
  the decoder skips the inner `<Obj>` as an unknown element, silently
  dropping the container. The bare `<LST>` / `<DCT>` is now emitted.

### Added

- **Sixteen fuzz targets** (up from three), in five layers: raw wire
  decoders, structure-aware round-trips, the typed record/metadata/host
  decoders, the runspace state machine and the real async pool over a
  mock transport, and the small hand-rolled codecs. Beyond panic-freedom
  they assert protocol properties — reassembly is independent of byte
  chunking, the .NET mixed-endian GUIDs survive the header, the CLIXML
  codec reaches a fixed point, a closed or broken pool never returns to
  `Opened`, and the wrong session key never yields the right plaintext.
- Fuzzing infrastructure: `Arbitrary` value generators and round-trip
  semantics in `fuzz/src/lib.rs`, libFuzzer dictionaries for CLIXML /
  PSRP / `known_hosts`, a version-controlled seed corpus under
  `fuzz/seeds/`, a rewritten `fuzz/run.sh` (target auto-discovery,
  dictionaries, corpus seeding, `smoke` / `cmin` / `list` modes) and a
  new `fuzz/coverage.sh`.
- `MAX_NESTING_DEPTH` is re-exported at the crate root.
- GitHub Actions: a `CI` workflow (test matrix over the feature flags,
  fmt/clippy/docs, an **MSRV job that builds with exactly the declared
  `rust-version`**, and `cargo-deny`) and a `Fuzz` workflow (target build
  + seed-freshness check, a 60s smoke pass per target on pull requests,
  and a nightly 15-minute deep run with a persistent corpus cache).
- `deny.toml`, documenting why RUSTSEC-2023-0071 (`rsa`, no fixed
  release upstream) is accepted and what the exposure actually is.

### Changed

- **MSRV raised to 1.98** (`rust-version = "1.98"`), plus a
  `rust-toolchain.toml` pinning the `stable` channel with `clippy` and
  `rustfmt` for day-to-day work.
- **`quick-xml` 0.41 → 0.42.** The 0.42 event API is `str`-based instead
  of `[u8]`-based: `QName::as_ref`, `Attribute::key`/`value`,
  `BytesText`, `BytesCData` and `BytesRef` all yield `str` now.
  `clixml/decode.rs` was ported accordingly — behaviour is unchanged.
- **`russh` 0.62 → 0.63** (`ssh` feature). `Handler::check_server_key`
  now receives a `PublicKeyOrCertificate`. OpenSSH host *certificates*
  are refused (fail-closed) under every policy except
  `HostKeyPolicy::AcceptAny`, because the crate has no CA trust store.
- **`winrm-rs` 1.1.2 → 1.2.0, and the requirement raised from `"1.0"` to
  `"1.2"`.** 1.2.0 fixes an XML injection in the SOAP `ResourceURI`
  header and raises its own MSRV to 1.98 to match ours. `psrp-rs` passes
  a constant resource URI, so its own API does not reach the injection,
  but every request it makes goes through that envelope builder — and
  leaving the requirement at `"1.0"` would let a consumer resolve the
  unfixed version. Also pulls in `base64` 0.23.
- Routine bumps: `tokio` 1.53, `tokio-util` 0.7.19, `uuid` 1.26,
  `thiserror` 2.0.20, `indexmap` 2.14.1, `serde` 1.0.229, `aes` 0.9.3,
  `async-trait` 0.1.92.
- `hmac`, `rand` and `sha1` deliberately stay on the pre-`digest 0.11`
  generation (0.12 / 0.8 / 0.10): `rsa` 0.9 — the only stable release —
  pins `digest 0.10` and `rand_core 0.6`. Moving them would require
  `rsa 0.10.0-rc`, a pre-release that carries the *same* open advisory
  (RUSTSEC-2023-0071) and therefore buys no security.

## [1.1.0] — 2026-06-03

> **Never released.** This version number was set in `Cargo.toml` but
> never tagged and never published to crates.io; its contents ship as
> part of 2.0.0. Kept as its own section so the history stays readable.

### Added

- **SSH transport host-key verification**: new `HostKeyPolicy` enum on
  `SshConfig` with three modes — `KnownHosts` (default, consults
  `~/.ssh/known_hosts`), `Pinned` (accept only a key matching a given
  SHA-256 fingerprint), and `AcceptAny` (disables verification,
  opt-in only). Includes a `known_hosts` parser with glob host-pattern
  matching, hashed-host support, and constant-time key comparison.
- **Runspace pool state-machine validation**: `is_legal_server_transition`
  rejects illegal server-driven `RunspacePoolState` transitions
  (skipping negotiation, resurrecting a closed pool, etc.).

### Changed

- **CreatePipeline CLIXML construction** moved out of `pipeline.rs` into
  `clixml/encode.rs`, consolidating CLIXML fragment building in one place.

### Security

- Key material in `crypto` and `shared` is now wrapped with
  `ZeroizeOnDrop` and explicitly `zeroize()`d after use, so session and
  exchange keys are scrubbed from memory on drop.

### Dependencies

- Added `zeroize` (with `zeroize_derive`); added `hmac` under the `ssh`
  feature for hashed `known_hosts` entry matching.

## [1.0.0] — 2026-04-12

### Added

- **CLIXML primitives**: `<DT>`, `<TS>`, `<G>`, `<BA>`, `<C>`, `<By>`,
  `<SB>`, `<I16>`, `<U16>`, `<U32>`, `<U64>`, `<Sg>`, `<D>`, `<URI>`,
  `<Version>`, `<XD>`, `<SCT>`, `<SS>`. `PsValue` now carries each as a
  distinct variant so round-tripping through PowerShell preserves the
  tag.
- **`RefIdAllocator`**: monotonic ref-id numbering for CLIXML
  encoders. `escape` is now public so callers building CLIXML fragments
  outside the library can reuse the same escaping rules.
- **`PsObject::with_type_names`** and `PsObject.to_string` for full
  object fidelity.
- **Command positional arguments + switches**: `Command::with_argument`
  and `Command::with_switch`. The `Argument` enum is now public.
- **Error-stream merging**: `Command::merging_errors_to_output()` sets
  `MergeMyResult=Error` / `MergeToResult=Output` in the `CreatePipeline`
  body.
- **Pipeline input streaming**: `Pipeline::start` returns a
  `PipelineHandle` that exposes `write_input` / `end_input` / `stop` /
  `collect`. `Pipeline::with_input(true)` flips the `NoInput` flag off.
- **Stop / cancel**: every `run_*` method on `RunspacePool` and
  `Pipeline` has a `*_with_cancel` variant taking a
  `tokio_util::sync::CancellationToken`. Cancellation triggers
  `signal_ctrl_c` and returns `PsrpError::Cancelled` once the server
  ACKs `Stopped`.
- **Typed record accessors**: `records` module with `ErrorRecord`,
  `WarningRecord`, `InformationRecord`, `ProgressRecord`, `TraceRecord`,
  `ExceptionInfo`, `ErrorCategoryInfo`, `InvocationInfo`, plus
  `FromPsObject` trait. `PipelineResult::typed_errors()`,
  `typed_warnings()`, `typed_information()`, `typed_progress()`,
  `typed_verbose()`, `typed_debug()`.
- **Host call dispatch**: `host` module with `PsHost` trait,
  `NoInteractionHost` (default, safe for non-interactive), and
  `BufferedHost` (captures writes). `RunspacePool::open_with_options_and_host`
  plugs a custom host into the runspace. The receive loop intercepts
  `RunspacePoolHostCall` / `PipelineHostCall` messages and replies with
  the matching `*HostResponse`. `HostMethodId` enumerates the MS-PSRP
  §2.2.6 method ids.
- **Session-key cryptography**: `crypto` module with `ClientSessionKey`
  (pure-Rust RSA 2048 keygen + Windows `PUBLICKEYBLOB` format) and
  `SessionKey` (AES-256-CBC with PKCS#7 padding, UTF-16LE plaintext).
  `RunspacePool::request_session_key` drives the
  `PublicKey` → `EncryptedSessionKey` exchange.
  `RunspacePool::{encrypt,decrypt}_secure_string` give callers direct
  access to the negotiated key.
- **Concurrent pipelines**: `SharedRunspacePool<T>` wraps a pool in an
  `Arc<tokio::sync::Mutex<_>>` so multiple clones can submit scripts
  against the same long-lived pool. True wire-level concurrency is
  still serialised at the transport layer; concurrent API ergonomics
  are supported.
- **`get_command_metadata`**: a new pipeline kind used by implicit
  remoting. `CommandType` bitflags, `CommandMetadata` and
  `ParameterMetadata` structs expose the server's response.
- **`disconnect` / `DisconnectedPool::reconnect`** placeholders —
  return `PsrpError::Protocol` until `winrm-rs` exposes
  `Shell::disconnect` / `Shell::reconnect` upstream.
- **Fuzz targets** (`fuzz/fuzz_targets/`): `fragment_reassembler`,
  `clixml_decoder`, `message_decode`. Each ships a seed corpus
  generated by `examples/generate_fuzz_corpus.rs` and a wrapper
  `fuzz/run.sh` runner that drives them via the nightly toolchain.
- **`serde` feature** (optional): enable `Serialize` / `Deserialize`
  derives on `PsValue` / `PsObject` for JSON interop.
- **Integration test VM**: `Vagrantfile` for a Windows Server 2025
  Standard Eval Hyper-V box pre-provisioned with WinRM + PSRP enabled.
- **Live tests**: `tests/integration_real.rs` runs 7 scenarios
  (`1+1`, `Get-Date`, `Get-Process`, pipeline builder, Error stream,
  Warning stream, multi-pipeline) against the Vagrant box. All gated
  by `PSRP_INTEGRATION_HOST` env var.

### Changed

- `PsValue::as_str` now returns a match for every string-like variant
  (`String`, `Version`, `Uri`, `Xml`, `ScriptBlock`, `Decimal`,
  `DateTime`, `Duration`, `SecureString`).
- `PsValue::as_i32` narrows from any signed or unsigned integer variant
  that fits; `PsValue::as_i64` widens the same set.
- `runspace/` is now a module directory with a pure sync state machine
  in `state.rs` and the async driver in `pool.rs`.

### Fixed

- `PsrpMessage::decode` now succeeds on exactly-40-byte inputs (empty
  body). The off-by-one check previously rejected the boundary case.
- `escape` no longer escapes U+0020 (space) — only characters strictly
  below `0x20` are emitted as `_xHHHH_`.

## [0.1.0] — Initial skeleton

- Fragment layer, message header, basic CLIXML primitives, runspace
  pool, pipeline builder, transport trait, live Vagrant integration.
