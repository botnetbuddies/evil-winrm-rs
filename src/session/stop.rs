//! Keep the stop request in flight while the transport drains pipeline output.
use psrp_rs::{PsrpError, Result};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use tokio::task::JoinHandle;
use winrm_rs::{OwnedShell, WinrmError};

#[derive(Default)]
pub(super) struct StopRequest {
    acknowledged: Arc<AtomicBool>,
    pending: Mutex<Option<JoinHandle<std::result::Result<(), WinrmError>>>>,
}

impl StopRequest {
    pub fn start(&self, shell: OwnedShell, command_id: String) {
        let mut pending = self.pending.lock().unwrap();
        if pending.is_some() || self.acknowledged() {
            return;
        }
        let acknowledged = self.acknowledged.clone();
        *pending = Some(tokio::spawn(async move {
            tracing::debug!("sending PowerShell stop request");
            shell.signal_ctrl_c(&command_id).await?;
            acknowledged.store(true, Ordering::Release);
            tracing::debug!("PowerShell stop acknowledged");
            Ok(())
        }));
    }

    pub fn acknowledged(&self) -> bool {
        self.acknowledged.load(Ordering::Acquire)
    }

    pub fn is_pending(&mut self) -> bool {
        self.pending.get_mut().unwrap().is_some()
    }

    /// Cancellation-safe: retain the task until its result has been consumed.
    pub async fn complete(&mut self) -> Result<()> {
        let pending = self.pending.get_mut().unwrap();
        if let Some(task) = pending.as_mut() {
            let result = task.await;
            *pending = None;
            result.map_err(|error| PsrpError::Protocol(format!("stop task failed: {error}")))??;
        }
        Ok(())
    }

    pub fn reset(&mut self) {
        debug_assert!(!self.is_pending());
        self.acknowledged.store(false, Ordering::Release);
    }
}

impl Drop for StopRequest {
    fn drop(&mut self) {
        if let Some(task) = self.pending.get_mut().unwrap().take() {
            task.abort();
        }
    }
}
