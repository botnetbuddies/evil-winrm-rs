//! End-to-end PSRP tests against fixture byte streams.
//!
//! These exercise the full public API (`RunspacePool::open_with_transport`,
//! `run_script`, `Pipeline::run_all_streams`) without any network I/O, by
//! feeding pre-built PSRP messages into a test-only transport.

use psrp_rs::fragment::encode_message;
use psrp_rs::message::{Destination, MessageType, PsrpMessage};
use psrp_rs::pipeline::PipelineState;
use psrp_rs::{
    Command, Pipeline, PsObject, PsValue, PsrpTransport, Result, RunspacePool, to_clixml,
};
use psrp_rs::{PsrpError, RunspacePoolState};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// A transport backed by two in-memory queues.
#[derive(Clone, Default)]
pub struct VecTransport {
    pub inbox: Arc<Mutex<VecDeque<Vec<u8>>>>,
    pub outbox: Arc<Mutex<Vec<Vec<u8>>>>,
    pub closed: Arc<Mutex<bool>>,
    pub stopped: Arc<Mutex<bool>>,
}

impl VecTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&self, bytes: Vec<u8>) {
        self.inbox.lock().unwrap().push_back(bytes);
    }

    pub fn push_front(&self, bytes: Vec<u8>) {
        self.inbox.lock().unwrap().push_front(bytes);
    }

    pub fn sent(&self) -> Vec<Vec<u8>> {
        self.outbox.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl PsrpTransport for VecTransport {
    async fn send_fragment(&self, bytes: &[u8]) -> Result<()> {
        self.outbox.lock().unwrap().push(bytes.to_vec());
        Ok(())
    }

    async fn recv_chunk(&mut self) -> Result<Vec<u8>> {
        self.inbox
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| PsrpError::Protocol("inbox empty".into()))
    }

    async fn signal_stop(&self) -> Result<()> {
        *self.stopped.lock().unwrap() = true;
        Ok(())
    }

    async fn close_shell(&mut self) -> Result<()> {
        *self.closed.lock().unwrap() = true;
        Ok(())
    }
}

fn wire_msg(mt: MessageType, data: String) -> Vec<u8> {
    wire_msg_with(mt, data, Uuid::nil(), Uuid::nil())
}

fn wire_msg_with(mt: MessageType, data: String, rpid: Uuid, pid: Uuid) -> Vec<u8> {
    let msg = PsrpMessage {
        destination: Destination::Client,
        message_type: mt,
        rpid,
        pid,
        data,
    };
    msg.encode()
}

fn opened_state_message() -> Vec<u8> {
    let body = to_clixml(&PsValue::Object(PsObject::new().with(
        "RunspaceState",
        PsValue::I32(RunspacePoolState::Opened as i32),
    )));
    wire_msg(MessageType::RunspacePoolState, body)
}

fn pipeline_state_message(state: PipelineState, rpid: Uuid, pid: Uuid) -> Vec<u8> {
    let body = to_clixml(&PsValue::Object(
        PsObject::new().with("PipelineState", PsValue::I32(state as i32)),
    ));
    wire_msg_with(MessageType::PipelineState, body, rpid, pid)
}

#[tokio::test]
async fn open_pool_and_run_script() {
    let transport = VecTransport::new();
    // Open handshake first; pipeline messages get pushed once we know the
    // pool's RPID (and we can force a known PID on the pipeline).
    transport.push(encode_message(1, &opened_state_message()));
    let mut pool = RunspacePool::open_with_transport(transport.clone())
        .await
        .unwrap();
    assert_eq!(pool.state(), RunspacePoolState::Opened);
    let rpid = pool.id();
    let pid = Uuid::new_v4();
    transport.push(encode_message(
        10,
        &wire_msg_with(
            MessageType::PipelineOutput,
            "<S>hello</S>".into(),
            rpid,
            pid,
        ),
    ));
    transport.push(encode_message(
        11,
        &wire_msg_with(
            MessageType::PipelineOutput,
            "<I32>42</I32>".into(),
            rpid,
            pid,
        ),
    ));
    transport.push(encode_message(
        12,
        &pipeline_state_message(PipelineState::Completed, rpid, pid),
    ));
    let out = Pipeline::new("whatever")
        .__with_forced_pid_for_test(pid)
        .run(&mut pool)
        .await
        .unwrap();
    assert_eq!(out, vec![PsValue::String("hello".into()), PsValue::I32(42)]);
    pool.close().await.unwrap();
    assert!(*transport.closed.lock().unwrap());
    assert!(!transport.sent().is_empty());
}

#[tokio::test]
async fn pipeline_with_command_builder() {
    let transport = VecTransport::new();
    transport.push(encode_message(1, &opened_state_message()));
    let mut pool = RunspacePool::open_with_transport(transport.clone())
        .await
        .unwrap();
    let rpid = pool.id();
    let pid = Uuid::new_v4();
    transport.push(encode_message(
        2,
        &wire_msg_with(
            MessageType::PipelineOutput,
            to_clixml(&PsValue::Object(
                PsObject::new()
                    .with("Name", PsValue::String("svchost".into()))
                    .with("Id", PsValue::I32(1234)),
            )),
            rpid,
            pid,
        ),
    ));
    transport.push(encode_message(
        3,
        &pipeline_state_message(PipelineState::Completed, rpid, pid),
    ));

    let pipeline = Pipeline::empty()
        .add_command(
            Command::new("Get-Process").with_parameter("Name", PsValue::String("svchost".into())),
        )
        .add_command(Command::new("Select-Object").with_parameter("First", PsValue::I32(1)))
        .__with_forced_pid_for_test(pid);

    let result = pipeline.run_all_streams(&mut pool).await.unwrap();
    assert_eq!(result.state, PipelineState::Completed);
    assert_eq!(result.output.len(), 1);
    let props = result.output[0].properties().unwrap();
    assert_eq!(props.get("Name").and_then(PsValue::as_str), Some("svchost"));
    assert_eq!(props.get("Id").and_then(PsValue::as_i32), Some(1234));

    pool.close().await.unwrap();
}

#[tokio::test]
async fn handshake_sends_expected_messages() {
    let transport = VecTransport::new();
    transport.push(encode_message(1, &opened_state_message()));
    let pool = RunspacePool::open_with_transport(transport.clone())
        .await
        .unwrap();
    // We must have sent exactly two fragments: SessionCapability + InitRunspacePool.
    assert_eq!(transport.sent().len(), 2);
    pool.close().await.unwrap();
    // After close we sent one more message (CloseRunspacePool).
    assert_eq!(transport.sent().len(), 3);
}

/// Live integration test against a real Windows host. Gated by env vars
/// so it never runs in CI by default.
#[tokio::test]
#[ignore = "requires a live Windows host; enable with PSRP_INTEGRATION_HOST"]
async fn live_run_get_date() {
    let host = match std::env::var("PSRP_INTEGRATION_HOST") {
        Ok(h) => h,
        Err(_) => return,
    };
    let user = std::env::var("PSRP_INTEGRATION_USER").expect("PSRP_INTEGRATION_USER");
    let pass = std::env::var("PSRP_INTEGRATION_PASS").expect("PSRP_INTEGRATION_PASS");

    let client = psrp_rs::WinrmClient::new(
        psrp_rs::WinrmConfig {
            auth_method: psrp_rs::AuthMethod::Ntlm,
            ..Default::default()
        },
        psrp_rs::WinrmCredentials::new(user, pass, ""),
    )
    .unwrap();
    let (rpid, creation) =
        RunspacePool::<psrp_rs::WinrmPsrpTransport<'_>>::build_creation_fragments(1, 1).unwrap();
    let transport = psrp_rs::WinrmPsrpTransport::open(&client, &host, &creation)
        .await
        .unwrap();
    let mut pool = RunspacePool::open_from_transport(transport, rpid, 1, 1)
        .await
        .unwrap();
    let out = pool.run_script("Get-Date").await.unwrap();
    println!("live output: {out:?}");
    pool.close().await.unwrap();
}
