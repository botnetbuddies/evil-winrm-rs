//! PSRP framing, WSMan pipeline ownership, cancellation and output byte budgets.
use anyhow::Result;
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use psrp_rs::{PsrpError, PsrpTransport};
use std::sync::Arc;
use winrm_rs::{OwnedShell, WinrmError};
/// Owns a WSMan shell while borrowing the client kept alive by the session task.
pub(super) struct Transport {
    pub(super) shell: Option<OwnedShell>,
    pub(super) command_id: String,
    pub(super) pending_receive:
        Option<tokio::task::JoinHandle<Result<winrm_rs::ReceiveOutput, WinrmError>>>,
    pub(super) stop: super::stop::StopRequest,
    pub(super) max_send_bytes: usize,
    pub(super) output_budget: Arc<super::limits::OutputBudget>,
}

fn command_is_missing(error: &WinrmError) -> bool {
    matches!(error, WinrmError::Soap(winrm_rs::SoapError::Fault { code, .. })
        if code.rsplit(':').next() == Some("InvalidSelectors"))
}

fn fragments(mut bytes: &[u8]) -> psrp_rs::Result<Vec<&[u8]>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 21 {
            return Err(PsrpError::Fragment(
                "truncated outgoing fragment header".into(),
            ));
        }
        let size = 21 + u32::from_be_bytes(bytes[17..21].try_into().unwrap()) as usize;
        if size > bytes.len() {
            return Err(PsrpError::Fragment(
                "truncated outgoing fragment body".into(),
            ));
        }
        out.push(&bytes[..size]);
        bytes = &bytes[size..];
    }
    Ok(out)
}

/// Coalesce whole PSRP fragments while leaving room for SOAP/base64 framing.
fn fragment_batches(bytes: &[u8], limit: usize) -> psrp_rs::Result<Vec<&[u8]>> {
    let mut batches = Vec::new();
    let mut start = 0;
    let mut end = 0;
    for fragment in fragments(bytes)? {
        if fragment.len() > limit {
            return Err(PsrpError::Fragment(
                "PSRP fragment exceeds the configured SOAP envelope capacity".into(),
            ));
        }
        if end - start + fragment.len() > limit {
            batches.push(&bytes[start..end]);
            start = end;
        }
        end += fragment.len();
    }
    if end > start {
        batches.push(&bytes[start..end]);
    }
    Ok(batches)
}
#[async_trait]
impl PsrpTransport for Transport {
    async fn send_fragment(&self, bytes: &[u8]) -> psrp_rs::Result<()> {
        let shell = self
            .shell
            .as_ref()
            .ok_or_else(|| PsrpError::Protocol("closed shell".into()))?;
        for fragment in fragment_batches(bytes, self.max_send_bytes)? {
            shell.send_input(&self.command_id, fragment, false).await?;
        }
        Ok(())
    }
    async fn send_host_response(&mut self, bytes: &[u8]) -> psrp_rs::Result<()> {
        let shell = self
            .shell
            .as_ref()
            .ok_or_else(|| PsrpError::Protocol("closed shell".into()))?;
        for fragment in fragment_batches(bytes, self.max_send_bytes)? {
            shell
                .send_input_stream(&self.command_id, fragment, false, "pr")
                .await?;
        }
        Ok(())
    }
    async fn recv_chunk(&mut self) -> psrp_rs::Result<Vec<u8>> {
        loop {
            if self.pending_receive.is_none() {
                let shell = self
                    .shell
                    .as_ref()
                    .ok_or_else(|| PsrpError::Protocol("closed shell".into()))?
                    .clone();
                let id = self.command_id.clone();
                self.pending_receive =
                    Some(tokio::spawn(async move { shell.receive_next(&id).await }));
            }
            // Keep the receive task in the transport when cancellation selects
            // the stop branch. Dropping a Receive request can discard the
            // server's terminal pipeline state and hang cancellation forever.
            let response = tokio::select! {
                biased;
                result = self.stop.complete(), if self.stop.is_pending() => {
                    result?;
                    continue;
                }
                response = self.pending_receive.as_mut().unwrap() => {
                    response.map_err(|e| PsrpError::Protocol(format!("receive task failed: {e}")))?
                }
            };
            self.pending_receive = None;
            match response {
                Ok(out) if !out.stdout.is_empty() => {
                    self.output_budget.accept(out.stdout.len())?;
                    return Ok(out.stdout);
                }
                Ok(out) if out.done => {
                    self.stop.complete().await?;
                    if self.stop.acknowledged() {
                        return Err(PsrpError::Cancelled);
                    }
                    return Err(PsrpError::Protocol(
                        "remote shell closed without a terminal PSRP state".into(),
                    ));
                }
                Ok(_) | Err(WinrmError::Timeout(_)) => continue,
                Err(WinrmError::Soap(winrm_rs::SoapError::Fault { code, .. }))
                    if code.rsplit(':').next() == Some("TimedOut") =>
                {
                    continue;
                }
                Err(e) if self.stop.acknowledged() && command_is_missing(&e) => {
                    // Windows may dispose the command immediately after the
                    // acknowledged stop, without a final PSRP Stopped packet.
                    return Err(PsrpError::Cancelled);
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
    async fn execute_pipeline(&mut self, bytes: &[u8], id: uuid::Uuid) -> psrp_rs::Result<()> {
        // A terminal PSRP state can arrive just before the Signal HTTP reply.
        self.stop.complete().await?;
        let fragments = fragment_batches(bytes, self.max_send_bytes)?;
        let first = fragments
            .first()
            .ok_or_else(|| PsrpError::Fragment("empty outgoing pipeline".into()))?;
        let shell = self
            .shell
            .as_ref()
            .ok_or_else(|| PsrpError::Protocol("closed shell".into()))?;
        // WSMan retains completed command output until acknowledged. This must
        // happen before creating the next pipeline, including after Ctrl+C.
        if !self.command_id.is_empty() && self.command_id != shell.shell_id() {
            if let Err(e) = shell.signal_terminate(&self.command_id).await
                && !(self.stop.acknowledged() && command_is_missing(&e))
            {
                return Err(e.into());
            }
            self.command_id.clear();
        }
        self.stop.reset();
        self.command_id = shell
            .start_command_with_id("", &[&B64.encode(first)], &id.to_string())
            .await?;
        for fragment in &fragments[1..] {
            self.shell
                .as_ref()
                .unwrap()
                .send_input(&self.command_id, fragment, false)
                .await?;
        }
        Ok(())
    }
    async fn signal_stop(&self) -> psrp_rs::Result<()> {
        let shell = self
            .shell
            .as_ref()
            .ok_or_else(|| PsrpError::Protocol("closed shell".into()))?;
        // Windows may wait for queued output to drain before acknowledging a
        // stop. Continue Receive calls while that independent request runs.
        self.stop.start(shell.clone(), self.command_id.clone());
        Ok(())
    }
    async fn close_shell(&mut self) -> psrp_rs::Result<()> {
        self.stop.complete().await?;
        if let Some(task) = self.pending_receive.take() {
            task.abort();
        }
        if let Some(shell) = self.shell.take() {
            shell.close().await?;
        }
        Ok(())
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        if let Some(task) = self.pending_receive.take() {
            task.abort();
        }
        if let Some(shell) = self.shell.take()
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            runtime.spawn(async move {
                let _ = shell.close().await;
            });
        }
    }
}

#[cfg(all(test, feature = "mcp"))]
mod cancellation_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragment_batches_preserve_frames_and_envelope_limit() {
        fn frame(body: usize) -> Vec<u8> {
            let mut frame = vec![0; 21 + body];
            frame[17..21].copy_from_slice(&(body as u32).to_be_bytes());
            frame
        }
        let frames = [frame(20), frame(15), frame(25)];
        let bytes = frames.concat();
        let batches = fragment_batches(&bytes, 77).unwrap();
        assert_eq!(
            batches.iter().map(|b| b.len()).collect::<Vec<_>>(),
            [77, 46]
        );
        assert_eq!(batches.concat(), bytes);
        for batch in batches {
            assert!(!fragments(batch).unwrap().is_empty());
        }
        assert!(fragment_batches(&bytes, 40).is_err());
        assert!(fragment_batches(&bytes[..bytes.len() - 1], 77).is_err());
        assert!(fragment_batches(&[0; 20], 77).is_err());
        assert!(fragment_batches(&[], 77).unwrap().is_empty());
    }
}
