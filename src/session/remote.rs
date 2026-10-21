//! Adapt broker RPC to the same queued session API used by the direct CLI.
use super::{Request, Session};
use crate::broker::{
    client::Client,
    models::{AttachInfo, ExecutionRequest},
};
use anyhow::Result;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::mpsc;
impl Session {
    pub(crate) fn attach_broker(client: Client, attached: AttachInfo) -> Self {
        let (tx, mut rx) = mpsc::channel::<Request>(16);
        let active = Arc::new(Mutex::new(None));
        let alive = Arc::new(AtomicBool::new(true));
        let worker_active = active.clone();
        let worker_alive = alive.clone();
        let id = attached.info.session_id;
        tokio::spawn(async move {
            while let Some(request) = rx.recv().await {
                match request {
                    Request::Close(reply) => {
                        let _ = reply.send(Ok(()));
                        break;
                    }
                    Request::Execute {
                        text,
                        raw,
                        status,
                        input,
                        cancel,
                        reply,
                    } => {
                        *worker_active.lock().unwrap() = Some(cancel.clone());
                        let args = ExecutionRequest {
                            session_id: Some(id),
                            text,
                            raw,
                            status,
                            request_id: uuid::Uuid::new_v4().to_string(),
                        };
                        let response = client.execute(args, input, cancel).await;
                        let result: Result<_> = match response {
                            Ok(mut result) => {
                                worker_alive.store(result.open, Ordering::Release);
                                match result.error {
                                    Some(error) => Err(anyhow::anyhow!(error)),
                                    None => {
                                        let mut output = result.output.take().unwrap_or_default();
                                        output.console = result.console;
                                        Ok(output)
                                    }
                                }
                            }
                            Err(error) => {
                                worker_alive.store(false, Ordering::Release);
                                Err(error)
                            }
                        };
                        *worker_active.lock().unwrap() = None;
                        let _ = reply.send(result);
                        if !worker_alive.load(Ordering::Acquire) {
                            break;
                        }
                    }
                }
            }
            worker_alive.store(false, Ordering::Release);
        });
        Self {
            tx,
            jea: attached.info.jea,
            active,
            alive,
            initial_functions: Arc::new(attached.initial_functions),
        }
    }
}
