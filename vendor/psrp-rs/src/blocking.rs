//! Synchronous wrapper around the async API.
//!
//! `reqwest::blocking`-style: a single dedicated current-thread Tokio runtime
//! is created on demand and used to drive the async implementation. Suitable
//! for command-line tools or contexts where async is inconvenient.

use std::sync::OnceLock;

use tokio::runtime::Runtime;
use winrm_rs::WinrmClient;

use crate::clixml::PsValue;
use crate::error::Result;
use crate::pipeline::{Pipeline, PipelineResult};
use crate::runspace::RunspacePool;
use crate::transport::WinrmPsrpTransport;

fn runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build blocking psrp-rs Tokio runtime")
    })
}

/// Run a single PowerShell script against `host` via a freshly-opened pool.
///
/// The pool is closed cleanly before returning.
pub fn run_script(client: &WinrmClient, host: &str, script: &str) -> Result<Vec<PsValue>> {
    runtime().block_on(async move {
        let (rpid, creation) =
            RunspacePool::<WinrmPsrpTransport<'_>>::build_creation_fragments(1, 1)?;
        let transport = WinrmPsrpTransport::open(client, host, &creation).await?;
        let mut pool = RunspacePool::open_from_transport(transport, rpid, 1, 1).await?;
        let result = pool.run_script(script).await;
        let _ = pool.close().await;
        result
    })
}

/// Run a pre-built [`Pipeline`] against `host` via a freshly-opened pool,
/// returning every stream.
pub fn run_pipeline(
    client: &WinrmClient,
    host: &str,
    pipeline: Pipeline,
) -> Result<PipelineResult> {
    runtime().block_on(async move {
        let (rpid, creation) =
            RunspacePool::<WinrmPsrpTransport<'_>>::build_creation_fragments(1, 1)?;
        let transport = WinrmPsrpTransport::open(client, host, &creation).await?;
        let mut pool = RunspacePool::open_from_transport(transport, rpid, 1, 1).await?;
        let result = pipeline.run_all_streams(&mut pool).await;
        let _ = pool.close().await;
        result
    })
}

/// Run a PowerShell script over SSH. The pool is opened and closed
/// within the call.
#[cfg(feature = "ssh")]
pub fn run_script_ssh(config: crate::ssh::SshConfig, script: &str) -> Result<Vec<PsValue>> {
    runtime().block_on(async move {
        let transport = crate::ssh::SshPsrpTransport::connect(config).await?;
        let mut pool = RunspacePool::open_with_transport(transport).await?;
        let result = pool.run_script(script).await;
        let _ = pool.close().await;
        result
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_is_reusable() {
        // Touch the runtime twice to exercise the OnceLock fast path.
        let rt1 = runtime() as *const _;
        let rt2 = runtime() as *const _;
        assert_eq!(rt1, rt2);
        runtime().block_on(async { 1 + 1 });
    }
}
