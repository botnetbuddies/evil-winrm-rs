//! Connection setup, persistent runspace ownership and the serialized request loop.
use super::host::HostBuffer;
use super::{Request, Session};
use anyhow::{Context, Result};
use psrp_rs::{Pipeline, PsValue, PsrpError};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::{mpsc, oneshot};
use winrm_rs::{WinrmConfig, WinrmCredentials};
impl Session {
    pub async fn connect(
        host: String,
        config: WinrmConfig,
        credentials: WinrmCredentials,
        configuration: String,
    ) -> Result<Self> {
        let max_output_bytes = config.max_output_bytes;
        let output_budget = Arc::new(super::limits::OutputBudget::new(max_output_bytes));
        let (tx, mut rx) = mpsc::channel::<Request>(16);
        let (ready_tx, ready_rx) = oneshot::channel();
        let active = Arc::new(Mutex::new(None));
        let worker_active = active.clone();
        let alive = Arc::new(AtomicBool::new(false));
        let worker_alive = alive.clone();
        tokio::spawn(async move {
            struct StateGuard(Arc<AtomicBool>);
            impl Drop for StateGuard {
                fn drop(&mut self) {
                    self.0.store(false, Ordering::Release);
                }
            }
            let _state_guard = StateGuard(worker_alive.clone());
            let prepared = match super::open::client(&host, config, credentials).await {
                Ok(prepared) => prepared,
                Err(error) => {
                    let _ = ready_tx.send(Err(error));
                    return;
                }
            };
            let host_buffer = Arc::new(HostBuffer::default());
            let open = super::open::runspace(
                &prepared,
                &host,
                &configuration,
                host_buffer.clone(),
                output_budget.clone(),
            );
            let open = tokio::time::timeout(std::time::Duration::from_secs(60), open)
                .await
                .context("PowerShell runspace opening timed out")
                .and_then(|result| result);
            let super::open::OpenedRunspace {
                mut pool,
                jea,
                initial_functions,
            } = match open {
                Ok(p) => p,
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            };
            worker_alive.store(true, Ordering::Release);
            if ready_tx.send(Ok((jea, initial_functions))).is_err() {
                let _ = pool.close().await;
                return;
            }
            let mut keepalive = tokio::time::interval(std::time::Duration::from_secs(30));
            keepalive.tick().await;
            loop {
                tokio::select! {
                    request = rx.recv() => match request {
                        Some(Request::Execute { text, raw, status, input, cancel, reply }) => {
                            pool.reset_output_limit(max_output_bytes);
                            output_budget.start();
                            tracing::debug!(raw, streaming_input = input.is_some(), "PowerShell request started");
                            *worker_active.lock().unwrap() = Some(cancel.clone());
                            host_buffer.0.lock().unwrap().clear();
                            *host_buffer.1.lock().unwrap() = None;
                            let command = super::execution::Execution { text, raw, status, input, cancel };
                            let result = super::execution::run(&mut pool, &host_buffer, jea, command).await;
                            let fatal = result.as_ref().err()
                                .and_then(|error| error.downcast_ref::<PsrpError>())
                                .is_some_and(fatal_error);
                            output_budget.stop();
                            *worker_active.lock().unwrap() = None;
                            tracing::debug!(fatal, "PowerShell request finished");
                            if fatal {
                                worker_alive.store(false, Ordering::Release);
                            }
                            let _ = reply.send(result);
                            if fatal { break; }
                        }
                        Some(Request::Close(reply)) => {
                            worker_alive.store(false, Ordering::Release);
                            let _ = reply.send(pool.close().await.map_err(Into::into));
                            return;
                        }
                        None => break,
                    },
                    _ = keepalive.tick() => {
                        pool.reset_output_limit(None);
                        tracing::debug!("PowerShell keepalive started");
                        let command = psrp_rs::Command::new("Get-Command")
                            .with_parameter("Name", PsValue::String("Get-Command".into()));
                        let ping = Pipeline::empty().add_command(command);
                        if ping.run(&mut pool).await.is_err() { break; }
                        tracing::debug!("PowerShell keepalive finished");
                    }
                }
            }
            worker_alive.store(false, Ordering::Release);
            let _ = pool.close().await;
        });
        let (jea, initial_functions) = ready_rx
            .await
            .context("session task stopped while connecting")??;
        Ok(Self {
            tx,
            jea,
            active,
            alive,
            initial_functions: Arc::new(initial_functions),
        })
    }
}

fn fatal_error(error: &PsrpError) -> bool {
    !matches!(
        error,
        PsrpError::Cancelled | PsrpError::Stopped | PsrpError::PipelineFailed(_)
    )
}
