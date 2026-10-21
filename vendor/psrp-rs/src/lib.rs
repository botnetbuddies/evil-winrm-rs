//! Async [MS-PSRP] client for Rust, built on top of [`winrm-rs`].
//!
//! `psrp-rs` implements the PowerShell Remoting Protocol on top of
//! WS-Management. It reuses `winrm-rs` for transport, authentication and
//! SOAP envelope handling, and layers the PSRP fragment/CLIXML protocol on
//! top to deliver:
//!
//! - typed PowerShell objects on the `Output` stream;
//! - isolated `Error`, `Warning`, `Verbose`, `Debug`, `Information` and
//!   `Progress` streams;
//! - a persistent [`RunspacePool`] that keeps a `powershell.exe` process
//!   alive across many pipelines;
//! - a builder-style [`Pipeline`] API.
//!
//! [MS-PSRP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/
//! [`winrm-rs`]: https://docs.rs/winrm-rs
//!
//! # Example
//!
//! ```no_run
//! use psrp_rs::{RunspacePool, WinrmPsrpTransport};
//! use winrm_rs::{AuthMethod, WinrmClient, WinrmConfig, WinrmCredentials};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = WinrmClient::new(
//!     WinrmConfig {
//!         auth_method: AuthMethod::Ntlm,
//!         ..Default::default()
//!     },
//!     WinrmCredentials::new("administrator", "Passw0rd!", ""),
//! )?;
//!
//! let (rpid, creation) = RunspacePool::<WinrmPsrpTransport>::build_creation_fragments(1, 1)?;
//! let transport = WinrmPsrpTransport::open(&client, "win-host.lab", &creation).await?;
//! let mut pool = RunspacePool::open_from_transport(transport, rpid, 1, 1).await?;
//!
//! let objects = pool
//!     .run_script("Get-Process | Select-Object -First 5 Name, Id")
//!     .await?;
//! for obj in objects {
//!     println!("{obj:?}");
//! }
//!
//! pool.close().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Scope
//!
//! P0 covers: fragment/CLIXML primitives, opening a pool, running a script,
//! collecting every standard stream. P1 extends to per-stream processing
//! via the [`Pipeline`] builder (already available here) and a blocking
//! wrapper in the [`blocking`] module. P2 items — `<Ref>`-based CLIXML
//! round-tripping, pipeline input streaming, reconnect/disconnect — are
//! still on the roadmap.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod blocking;
pub mod clixml;
pub mod crypto;
pub mod error;
pub mod fragment;
pub mod host;
#[cfg(feature = "__internal")]
pub mod internal;
pub mod message;
pub mod metadata;
pub mod pipeline;
pub mod records;
pub mod runspace;
pub mod shared;
#[cfg(feature = "ssh")]
pub mod ssh;
#[cfg(feature = "ssh")]
pub use ssh::{SshAuth, SshConfig, SshPsrpTransport};
pub mod transport;

pub use clixml::{MAX_NESTING_DEPTH, PsObject, PsValue, RefIdAllocator, parse_clixml, to_clixml};
pub use crypto::{ClientSessionKey, SessionKey};
pub use error::{PsrpError, Result};
pub use host::{BufferedHost, HostCallKind, HostMethodId, NoInteractionHost, PsHost};
pub use metadata::{CommandMetadata, CommandType, ParameterMetadata};
pub use pipeline::{Argument, Command, Pipeline, PipelineHandle, PipelineResult, PipelineState};
pub use records::{
    ErrorCategoryInfo, ErrorRecord, ExceptionInfo, FromPsObject, InformationRecord, InvocationInfo,
    ProgressRecord, TraceRecord, WarningRecord,
};
pub use runspace::{
    DisconnectedPool, PROTOCOL_VERSION, RunspacePool, RunspacePoolState, RunspacePoolStateMachine,
};
pub use shared::SharedRunspacePool;
pub use transport::{PsrpTransport, WinrmPsrpTransport};

// Re-export the `winrm-rs` types commonly needed by callers so they
// don't have to depend on `winrm-rs` directly.
pub use winrm_rs::{AuthMethod, WinrmClient, WinrmConfig, WinrmCredentials, WinrmError};
