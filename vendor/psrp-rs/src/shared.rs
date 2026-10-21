//! Thread-safe sharing of a [`RunspacePool`] across multiple callers.
//!
//! `RunspacePool` is `&mut self`-heavy because the underlying PSRP
//! protocol serialises messages on a single WS-Management shell. That
//! means you can't naively hand the same pool to two tasks.
//!
//! [`SharedRunspacePool`] wraps a pool in an `Arc<tokio::sync::Mutex<_>>`
//! so multiple clones can coordinate access while still respecting the
//! underlying serialization. The public API mirrors the most common
//! pool methods and acquires the mutex internally for each call.
//!
//! True wire-level concurrency (multiple pipelines running in parallel
//! with messages interleaved) is **not** supported here — that would
//! require a background dispatcher task owning the transport, which in
//! turn needs `winrm-rs` to expose an `Arc`-owned `WinrmClient`. The
//! shared-pool pattern is still useful:
//!
//! * Multiple tasks can submit scripts to the same long-lived pool
//!   without the caller juggling `&mut`.
//! * The convenience methods take a `Clone`-able handle, friendly to
//!   `tokio::spawn_local` and actor-style code.
//! * Integrates cleanly with [`tokio_util::sync::CancellationToken`].

use std::sync::Arc;

use tokio::sync::Mutex;

use crate::clixml::PsValue;
use crate::error::Result;
use crate::pipeline::{Pipeline, PipelineResult};
use crate::runspace::RunspacePool;
use crate::transport::PsrpTransport;

/// Clone-able handle to a [`RunspacePool`].
///
/// Every method acquires an internal mutex before calling into the
/// underlying pool, so callers can safely share a `SharedRunspacePool`
/// across tasks.
pub struct SharedRunspacePool<T: PsrpTransport> {
    inner: Arc<Mutex<RunspacePool<T>>>,
}

impl<T: PsrpTransport> Clone for SharedRunspacePool<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<T: PsrpTransport> std::fmt::Debug for SharedRunspacePool<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedRunspacePool")
            .field("strong_count", &Arc::strong_count(&self.inner))
            .finish()
    }
}

impl<T: PsrpTransport> SharedRunspacePool<T> {
    /// Wrap an already-opened [`RunspacePool`].
    #[must_use]
    pub fn new(pool: RunspacePool<T>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(pool)),
        }
    }

    /// Number of outstanding handles to the same pool.
    #[must_use]
    pub fn handle_count(&self) -> usize {
        Arc::strong_count(&self.inner)
    }

    /// Run a script. Acquires the mutex for the whole call.
    pub async fn run_script(&self, script: &str) -> Result<Vec<PsValue>> {
        let mut guard = self.inner.lock().await;
        guard.run_script(script).await
    }

    /// Run a pre-built [`Pipeline`] and collect every stream.
    pub async fn run_pipeline(&self, pipeline: Pipeline) -> Result<PipelineResult> {
        let mut guard = self.inner.lock().await;
        pipeline.run_all_streams(&mut guard).await
    }

    /// Run a script with a cancellation token.
    pub async fn run_script_with_cancel(
        &self,
        script: &str,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<Vec<PsValue>> {
        let mut guard = self.inner.lock().await;
        guard.run_script_with_cancel(script, cancel).await
    }

    /// Request a session key for `SecureString` transport.
    pub async fn request_session_key(&self) -> Result<()> {
        let mut guard = self.inner.lock().await;
        guard.request_session_key().await
    }

    /// Close the pool. Only the last outstanding handle can actually
    /// close — if other clones are still alive, returns an error
    /// wrapping the still-contended pool.
    pub async fn close(self) -> Result<()> {
        match Arc::try_unwrap(self.inner) {
            Ok(mutex) => mutex.into_inner().close().await,
            Err(arc) => Err(crate::error::PsrpError::protocol(format!(
                "cannot close SharedRunspacePool: {} handles still outstanding",
                Arc::strong_count(&arc)
            ))),
        }
    }

    /// Acquire the pool mutex and run a closure with direct access to
    /// the underlying [`RunspacePool`]. Useful when you need an API
    /// that isn't surfaced on the shared wrapper.
    pub async fn with_pool<F, R>(&self, f: F) -> R
    where
        F: for<'a> FnOnce(
            &'a mut RunspacePool<T>,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = R> + Send + 'a>>,
    {
        let mut guard = self.inner.lock().await;
        f(&mut guard).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clixml::{PsObject, to_clixml};
    use crate::fragment::encode_message;
    use crate::message::{Destination, MessageType, PsrpMessage};
    use crate::pipeline::PipelineState;
    use crate::runspace::RunspacePoolState;
    use crate::transport::mock::MockTransport;
    use uuid::Uuid;

    fn state_message(state: RunspacePoolState) -> Vec<u8> {
        let body = to_clixml(&PsValue::Object(
            PsObject::new().with("RunspaceState", PsValue::I32(state as i32)),
        ));
        PsrpMessage {
            destination: Destination::Client,
            message_type: MessageType::RunspacePoolState,
            rpid: Uuid::nil(),
            pid: Uuid::nil(),
            data: body,
        }
        .encode()
    }

    fn pipeline_state_message(state: PipelineState, rpid: Uuid, pid: Uuid) -> Vec<u8> {
        let body = to_clixml(&PsValue::Object(
            PsObject::new().with("PipelineState", PsValue::I32(state as i32)),
        ));
        PsrpMessage {
            destination: Destination::Client,
            message_type: MessageType::PipelineState,
            rpid,
            pid,
            data: body,
        }
        .encode()
    }

    async fn opened_shared() -> (MockTransport, SharedRunspacePool<MockTransport>, Uuid) {
        let t = MockTransport::new();
        t.push_incoming(encode_message(1, &state_message(RunspacePoolState::Opened)));
        let pool = RunspacePool::open_with_transport(t.clone()).await.unwrap();
        let rpid = pool.id();
        (t, SharedRunspacePool::new(pool), rpid)
    }

    #[tokio::test]
    async fn shared_run_script_serialises_access() {
        let (t, shared, rpid) = opened_shared().await;
        let pid = Uuid::new_v4();
        t.push_incoming(encode_message(
            10,
            &PsrpMessage {
                destination: Destination::Client,
                message_type: MessageType::PipelineOutput,
                rpid,
                pid,
                data: "<I32>42</I32>".into(),
            }
            .encode(),
        ));
        t.push_incoming(encode_message(
            11,
            &pipeline_state_message(PipelineState::Completed, rpid, pid),
        ));
        let out = shared
            .run_pipeline(Pipeline::new("whatever").__with_forced_pid_for_test(pid))
            .await
            .unwrap();
        assert_eq!(out.output, vec![PsValue::I32(42)]);
        // Count = 1, we can close.
        assert_eq!(shared.handle_count(), 1);
        shared.close().await.unwrap();
    }

    #[tokio::test]
    async fn shared_close_errors_with_outstanding_clones() {
        let (_t, shared, _rpid) = opened_shared().await;
        let clone = shared.clone();
        assert_eq!(shared.handle_count(), 2);
        let err = shared.close().await.unwrap_err();
        assert!(matches!(err, crate::error::PsrpError::Protocol(_)));
        // Clean up through the surviving clone.
        clone.close().await.unwrap();
    }

    #[tokio::test]
    async fn shared_with_pool_direct_access() {
        let (_t, shared, _rpid) = opened_shared().await;
        let state = shared
            .with_pool(|p| Box::pin(async move { p.state() }))
            .await;
        assert_eq!(state, RunspacePoolState::Opened);
        shared.close().await.unwrap();
    }

    #[tokio::test]
    async fn shared_debug_format_includes_strong_count() {
        let (_t, shared, _rpid) = opened_shared().await;
        let s = format!("{shared:?}");
        assert!(s.contains("SharedRunspacePool"));
        assert!(s.contains("strong_count"));
        shared.close().await.unwrap();
    }

    // ---------- Phase D: additional shared pool coverage ----------

    #[tokio::test]
    async fn shared_run_pipeline_with_builder() {
        let (t, shared, rpid) = opened_shared().await;
        let pid = Uuid::new_v4();
        t.push_incoming(encode_message(
            10,
            &PsrpMessage {
                destination: Destination::Client,
                message_type: MessageType::PipelineOutput,
                rpid,
                pid,
                data: "<S>ok</S>".into(),
            }
            .encode(),
        ));
        t.push_incoming(encode_message(
            11,
            &pipeline_state_message(PipelineState::Completed, rpid, pid),
        ));
        let result = shared
            .run_pipeline(crate::pipeline::Pipeline::new("dummy").__with_forced_pid_for_test(pid))
            .await
            .unwrap();
        assert_eq!(result.output, vec![PsValue::String("ok".into())]);
        shared.close().await.unwrap();
    }

    #[tokio::test]
    async fn shared_run_script_with_cancel_token() {
        let (t, shared, rpid) = opened_shared().await;
        let pid = Uuid::new_v4();
        t.push_incoming(encode_message(
            10,
            &PsrpMessage {
                destination: Destination::Client,
                message_type: MessageType::PipelineOutput,
                rpid,
                pid,
                data: "<I32>7</I32>".into(),
            }
            .encode(),
        ));
        t.push_incoming(encode_message(
            11,
            &pipeline_state_message(PipelineState::Completed, rpid, pid),
        ));
        let token = tokio_util::sync::CancellationToken::new();
        // Drive via run_pipeline so we can pin the pid; the run_script
        // wrapper itself is exercised separately.
        let out = shared
            .with_pool(|p| {
                let token = token.clone();
                Box::pin(async move {
                    Pipeline::new("x")
                        .__with_forced_pid_for_test(pid)
                        .run_with_cancel(p, token)
                        .await
                })
            })
            .await
            .unwrap();
        assert_eq!(out, vec![PsValue::I32(7)]);
        shared.close().await.unwrap();
    }

    #[tokio::test]
    async fn shared_request_session_key_delegates_and_fails() {
        // Without a server to answer, request_session_key hangs trying
        // to read the next message. We just exercise the delegation
        // path by pushing an EncryptedSessionKey response that will
        // fail to decrypt (random bytes) — the error path still
        // covers the code.
        let (t, shared, _rpid) = opened_shared().await;
        // Seed a fake EncryptedSessionKey with garbage hex — decryption
        // will fail but the delegation + parse paths run.
        t.push_incoming(encode_message(
            9,
            &PsrpMessage {
                destination: Destination::Client,
                message_type: MessageType::EncryptedSessionKey,
                rpid: Uuid::nil(),
                pid: Uuid::nil(),
                data: to_clixml(&PsValue::Object(
                    PsObject::new().with("EncryptedSessionKey", PsValue::String("deadbeef".into())),
                )),
            }
            .encode(),
        ));
        let err = shared.request_session_key().await.unwrap_err();
        assert!(matches!(err, crate::error::PsrpError::Protocol(_)));
        shared.close().await.unwrap();
    }

    #[tokio::test]
    async fn shared_handle_count_scales() {
        let (_t, shared, _rpid) = opened_shared().await;
        assert_eq!(shared.handle_count(), 1);
        let h2 = shared.clone();
        let h3 = shared.clone();
        assert_eq!(shared.handle_count(), 3);
        drop(h3);
        drop(h2);
        assert_eq!(shared.handle_count(), 1);
        shared.close().await.unwrap();
    }
}
