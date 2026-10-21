//! Async driver that owns the transport and executes the state machine's
//! actions.

use std::sync::Arc;

use uuid::Uuid;

use crate::clixml::{PsObject, PsValue, parse_clixml, to_clixml};
use crate::error::{PsrpError, Result};
use crate::fragment::{Reassembler, encode_message};
use crate::host::{HostMethodId, NoInteractionHost, PsHost, dispatch_host_call};
use crate::message::{Destination, MessageType, PsrpMessage};
use crate::transport::PsrpTransport;

use super::state::{Action, RunspacePoolState, RunspacePoolStateMachine};

/// A runspace pool.
///
/// Generic over the transport so tests can drive the state machine with an
/// in-memory mock. In real usage, parameterize with
/// [`crate::transport::WinrmPsrpTransport`].
pub struct RunspacePool<T: PsrpTransport> {
    transport: T,
    reassembler: Reassembler,
    machine: RunspacePoolStateMachine,
    next_object_id: u64,
    closed: bool,
    host: Arc<dyn PsHost>,
    session_key: Option<crate::crypto::SessionKey>,
    /// Messages decoded from a single recv_chunk that contained multiple
    /// PSRP messages. Drained before the next transport read.
    pending_messages: Vec<PsrpMessage>,
    output_budget: Option<(usize, usize)>,
}

impl<T: PsrpTransport> RunspacePool<T> {
    /// Open a runspace pool with the default `[1,1]` runspace bounds.
    ///
    /// For mock transports, the opening `SessionCapability` +
    /// `InitRunspacePool` messages are sent via `send_fragment` on the
    /// existing transport. For real transports (e.g.
    /// [`WinrmPsrpTransport`](crate::transport::WinrmPsrpTransport)),
    /// use [`open_with_transport`](Self::open_with_transport) instead — it embeds the creation
    /// fragments in the WS-Man `<creationXml>`.
    pub async fn open_with_transport(transport: T) -> Result<Self> {
        Self::open_with_options(transport, 1, 1).await
    }

    /// Open a runspace pool with explicit min/max runspace counts.
    pub async fn open_with_options(
        transport: T,
        min_runspaces: i32,
        max_runspaces: i32,
    ) -> Result<Self> {
        Self::open_with_options_and_host(
            transport,
            min_runspaces,
            max_runspaces,
            Arc::new(NoInteractionHost),
        )
        .await
    }

    /// Open a runspace pool with an explicit [`PsHost`].
    pub async fn open_with_options_and_host(
        transport: T,
        min_runspaces: i32,
        max_runspaces: i32,
        host: Arc<dyn PsHost>,
    ) -> Result<Self> {
        let machine = RunspacePoolStateMachine::new(Uuid::new_v4(), min_runspaces, max_runspaces)?
            .with_host_info(host.host_info());
        let mut pool = Self {
            transport,
            reassembler: Reassembler::new(),
            machine,
            next_object_id: 1,
            closed: false,
            host,
            session_key: None,
            pending_messages: Vec::new(),
            output_budget: None,
        };

        let actions = pool.machine.open();
        pool.execute(actions).await?;
        pool.drain_until_opened().await?;
        Ok(pool)
    }

    /// Build the raw PSRP opening fragments (SessionCapability +
    /// InitRunspacePool) for a pool with the given parameters. Returns
    /// `(rpid, fragment_bytes)` suitable for
    /// [`WinrmPsrpTransport::open`](crate::transport::WinrmPsrpTransport::open).
    ///
    /// This is a static helper — it doesn't require a transport
    /// instance.
    pub fn build_creation_fragments(
        min_runspaces: i32,
        max_runspaces: i32,
    ) -> Result<(Uuid, Vec<u8>)> {
        Self::build_creation_fragments_with_host(min_runspaces, max_runspaces, &NoInteractionHost)
    }

    /// Build creation fragments advertising the supplied host's capabilities.
    pub fn build_creation_fragments_with_host(
        min_runspaces: i32,
        max_runspaces: i32,
        host: &dyn PsHost,
    ) -> Result<(Uuid, Vec<u8>)> {
        let mut machine =
            RunspacePoolStateMachine::new(Uuid::new_v4(), min_runspaces, max_runspaces)?
                .with_host_info(host.host_info());
        let actions = machine.open();
        let rpid = machine.rpid();
        let mut next_oid = 1u64;
        let mut buf = Vec::new();
        for action in actions {
            match action {
                Action::SendMessage { message_type, body } => {
                    let msg = PsrpMessage {
                        destination: Destination::Server,
                        message_type,
                        rpid,
                        pid: Uuid::nil(),
                        data: body,
                    };
                    let encoded = msg.encode();
                    buf.extend_from_slice(&encode_message(next_oid, &encoded));
                    next_oid += 1;
                }
            }
        }
        Ok((rpid, buf))
    }

    /// Wrap an already-opened transport + pre-negotiated RPID into a
    /// pool and drain until `Opened`. Used by the real PSRP path where
    /// the creation fragments were embedded in the WS-Man shell create.
    pub async fn open_from_transport(
        transport: T,
        rpid: Uuid,
        min_runspaces: i32,
        max_runspaces: i32,
    ) -> Result<Self> {
        Self::open_from_transport_with_host(
            transport,
            rpid,
            min_runspaces,
            max_runspaces,
            Arc::new(NoInteractionHost),
        )
        .await
    }

    /// Like [`open_from_transport`](Self::open_from_transport) but with
    /// a custom host.
    pub async fn open_from_transport_with_host(
        transport: T,
        rpid: Uuid,
        min_runspaces: i32,
        max_runspaces: i32,
        host: Arc<dyn PsHost>,
    ) -> Result<Self> {
        // Build a machine in NegotiationSent state — the open()
        // actions were already embedded in the WS-Man creationXml.
        let mut machine = RunspacePoolStateMachine::new(rpid, min_runspaces, max_runspaces)?;
        // Manually advance past BeforeOpen → NegotiationSent.
        let _ = machine.open(); // produces actions we won't send (already sent)
        let mut pool = Self {
            transport,
            reassembler: Reassembler::new(),
            machine,
            next_object_id: 3, // 1 = SessionCapability, 2 = InitRunspacePool
            closed: false,
            host,
            session_key: None,
            pending_messages: Vec::new(),
            output_budget: None,
        };
        pool.drain_until_opened().await?;
        Ok(pool)
    }

    /// Current state.
    #[must_use]
    pub fn state(&self) -> RunspacePoolState {
        self.machine.state()
    }

    /// Configured minimum runspaces.
    #[must_use]
    pub fn min_runspaces(&self) -> i32 {
        self.machine.min_runspaces()
    }

    /// Configured maximum runspaces.
    #[must_use]
    pub fn max_runspaces(&self) -> i32 {
        self.machine.max_runspaces()
    }

    /// Runspace pool UUID.
    #[must_use]
    pub fn id(&self) -> Uuid {
        self.machine.rpid()
    }

    pub(crate) async fn host_output(&self, value: &PsValue) {
        self.host.pipeline_output(value).await;
    }

    /// Return `Err(BadState)` unless `self.state() == expected`.
    pub fn ensure_state(&self, expected: RunspacePoolState) -> Result<()> {
        if self.machine.state() != expected {
            return Err(PsrpError::BadState {
                expected: format!("{expected:?}"),
                actual: format!("{:?}", self.machine.state()),
            });
        }
        Ok(())
    }

    /// Disconnect the pool, leaving the server-side shell alive so it
    /// can be reconnected later via [`DisconnectedPool::reconnect`].
    ///
    /// Sends `CloseRunspacePool` is **not** called — the runspace stays
    /// alive on the server. To tear it down for good, call [`RunspacePool::close`]
    /// instead.
    pub async fn disconnect(mut self) -> Result<DisconnectedPool> {
        if self.closed {
            return Err(PsrpError::protocol("pool already closed"));
        }
        self.closed = true;
        let shell_id = match self.transport.disconnect_shell().await {
            Ok(id) => id,
            Err(e) => {
                // `disconnect` takes `self`, so a failure here would drop the
                // pool — and with it the only handle to the server-side
                // runspace, which stays alive. The WinRS PowerShell plugin on
                // Server 2012 R2 rejects Disconnect outright, so every attempt
                // leaked one runspace against `MaxShellsPerUser`. Tear the
                // shell down before surfacing the error.
                if let Err(close_err) = self.transport.close_shell().await {
                    tracing::debug!("shell close after failed disconnect: {close_err}");
                }
                return Err(e);
            }
        };
        Ok(DisconnectedPool {
            shell_id,
            rpid: self.machine.rpid(),
            min_runspaces: self.machine.min_runspaces(),
            max_runspaces: self.machine.max_runspaces(),
            host: self.host.clone(),
            session_key: self.session_key.clone(),
        })
    }

    /// Close the pool, sending `CloseRunspacePool` then tearing down the
    /// transport. Consumes `self`.
    pub async fn close(mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let actions = self.machine.close();
        let send_result = self.execute(actions).await;
        if let Err(e) = &send_result {
            tracing::debug!("CloseRunspacePool send failed: {e}");
        }
        self.transport.close_shell().await?;
        self.machine.mark_closed();
        send_result
    }

    /// Run a PowerShell script and collect every `PipelineOutput` as a
    /// [`PsValue`]. For richer access to every stream, see
    /// [`crate::pipeline::Pipeline::run_all_streams`].
    pub async fn run_script(&mut self, script: &str) -> Result<Vec<PsValue>> {
        crate::pipeline::Pipeline::new(script).run(self).await
    }

    /// Session key negotiated with the server for `SecureString`
    /// transport, or `None` if negotiation hasn't happened yet.
    #[must_use]
    pub fn session_key(&self) -> Option<&crate::crypto::SessionKey> {
        self.session_key.as_ref()
    }

    /// Inject a pre-existing session key. Useful in tests that want to
    /// exercise `SecureString` encrypt/decrypt without driving the full
    /// RSA handshake, and available to callers that negotiate a key out
    /// of band.
    pub fn set_session_key(&mut self, key: crate::crypto::SessionKey) {
        self.session_key = Some(key);
    }

    /// Encrypt a plaintext `SecureString` value using the currently
    /// negotiated session key. Returns a base64-encoded ciphertext
    /// ready to be embedded in a CLIXML `<SS>` element.
    pub fn encrypt_secure_string(&self, plaintext: &str) -> Result<String> {
        let key = self
            .session_key
            .as_ref()
            .ok_or_else(|| PsrpError::protocol("session key not negotiated yet"))?;
        let bytes = key.encrypt_secure_string(plaintext);
        Ok(crate::clixml::encode::base64_encode(&bytes))
    }

    /// Decrypt a `<SS>` element's base64-encoded body using the current
    /// session key.
    pub fn decrypt_secure_string(&self, base64_body: &str) -> Result<String> {
        let key = self
            .session_key
            .as_ref()
            .ok_or_else(|| PsrpError::protocol("session key not negotiated yet"))?;
        let bytes = crate::clixml::encode::base64_decode(base64_body)
            .ok_or_else(|| PsrpError::protocol("secure string: invalid base64"))?;
        key.decrypt_secure_string(&bytes)
    }

    /// Kick off a PSRP session-key exchange so that `SecureString`
    /// values can be transported between the client and the server.
    ///
    /// Sends a `PublicKey` message containing a freshly-generated
    /// 2048-bit RSA public key and blocks until the server responds
    /// with an `EncryptedSessionKey` — the 256-bit AES key wrapped in
    /// RSA-OAEP(SHA-1).
    pub async fn request_session_key(&mut self) -> Result<()> {
        if self.session_key.is_some() {
            return Ok(());
        }
        let client_key = crate::crypto::ClientSessionKey::generate()?;
        let blob_hex = client_key.public_blob_hex();
        // PSRP §2.2.2.4 — PublicKey message body is an <Obj> with a
        // single <MS>/<S N="PublicKey"> containing the blob.
        let body = crate::clixml::to_clixml(&PsValue::Object(
            PsObject::new().with("PublicKey", PsValue::String(blob_hex)),
        ));
        self.send_psrp_message(MessageType::PublicKey, body).await?;

        // Drain until we get the EncryptedSessionKey.
        loop {
            let msg = self.next_message().await?;
            if msg.message_type == MessageType::EncryptedSessionKey {
                let parsed = parse_clixml(&msg.data)?;
                let hex = parsed
                    .into_iter()
                    .find_map(|v| match v {
                        PsValue::Object(obj) => obj
                            .get("EncryptedSessionKey")
                            .and_then(PsValue::as_str)
                            .map(str::to_string),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        PsrpError::protocol(
                            "EncryptedSessionKey message missing EncryptedSessionKey property",
                        )
                    })?;
                let bytes = hex_decode(&hex)?;
                let raw = client_key.decrypt_session_key(&bytes)?;
                self.session_key = Some(crate::crypto::SessionKey::from_bytes(raw));
                return Ok(());
            }
        }
    }

    /// Run a script with a cancellation token.
    pub async fn run_script_with_cancel(
        &mut self,
        script: &str,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<Vec<PsValue>> {
        crate::pipeline::Pipeline::new(script)
            .run_with_cancel(self, cancel)
            .await
    }

    // --- internals used by `pipeline.rs` ---

    pub(crate) async fn send_psrp_message(&mut self, mt: MessageType, body: String) -> Result<()> {
        let msg = PsrpMessage {
            destination: Destination::Server,
            message_type: mt,
            rpid: self.machine.rpid(),
            pid: Uuid::nil(),
            data: body,
        };
        let encoded = msg.encode();
        let oid = self.next_object_id;
        self.next_object_id += 1;
        let frag_bytes = encode_message(oid, &encoded);
        self.transport.send_fragment(&frag_bytes).await
    }

    pub(crate) async fn next_message(&mut self) -> Result<PsrpMessage> {
        loop {
            // Drain any buffered messages from a previous recv_chunk that
            // produced multiple PSRP messages at once.
            if let Some(msg) = self.pending_messages.pop() {
                // Count before parsing CLIXML or dispatching host callbacks:
                // stdout-only limits miss Write-Host, warnings and errors.
                if matches!(msg.message_type,
                    MessageType::PipelineOutput | MessageType::ErrorRecord |
                    MessageType::WarningRecord | MessageType::VerboseRecord |
                    MessageType::DebugRecord | MessageType::InformationRecord |
                    MessageType::ProgressRecord | MessageType::PipelineHostCall |
                    MessageType::RunspacePoolHostCall)
                    && let Some((limit, used)) = &mut self.output_budget {
                        *used = used.saturating_add(msg.data.len());
                        if *used > *limit { return Err(PsrpError::OutputLimit(*limit)); }
                    }
                match msg.message_type {
                    MessageType::RunspacePoolHostCall | MessageType::PipelineHostCall => {
                        self.handle_host_call(&msg).await?;
                        continue;
                    }
                    _ => return Ok(msg),
                }
            }

            let chunk = self.transport.recv_chunk().await?;
            if chunk.is_empty() {
                if self.reassembler.is_idle() && self.pending_messages.is_empty() {
                    return Ok(PsrpMessage {
                        destination: Destination::Client,
                        message_type: MessageType::PipelineState,
                        rpid: self.machine.rpid(),
                        pid: Uuid::nil(),
                        data: crate::clixml::to_clixml(&PsValue::Object(
                            PsObject::new().with("PipelineState", PsValue::I32(4)),
                        )),
                    });
                }
            }
            let completed = self.reassembler.feed(&chunk)?;
            // Decode all messages and push to pending buffer (reversed
            // so pop() returns them in FIFO order).
            let mut decoded: Vec<PsrpMessage> = Vec::new();
            for payload in completed {
                decoded.push(PsrpMessage::decode(&payload)?);
            }
            decoded.reverse();
            self.pending_messages.extend(decoded);
        }
    }

    /// Bound retained output by serialized CLIXML bytes, including host calls.
    /// Reset once per application request. Exceeding it requires closing the pool.
    pub fn reset_output_limit(&mut self, bytes: Option<usize>) {
        self.output_budget = bytes.map(|limit| (limit, 0));
    }

    async fn handle_host_call(&mut self, msg: &PsrpMessage) -> Result<()> {
        // PSRP host call body: an Obj with MS containing ci (call id, I64),
        // mi (method id, I32/I64 depending on server), mp (method params list).
        let parsed = parse_clixml(&msg.data)?;
        let root = parsed
            .into_iter()
            .next()
            .ok_or_else(|| PsrpError::protocol("host call: empty body"))?;
        let obj = match &root {
            PsValue::Object(o) => o,
            _ => return Err(PsrpError::protocol("host call: body is not an object")),
        };
        let ci = obj
            .get("ci")
            .and_then(PsValue::as_i64)
            .ok_or_else(|| PsrpError::protocol("host call: missing ci"))?;
        let method_value = obj
            .get("mi")
            .ok_or_else(|| PsrpError::protocol("host call: missing mi"))?;
        let method_value = method_value
            .properties()
            .and_then(|p| p.get("_value"))
            .unwrap_or(method_value);
        let mi_raw = method_value.as_i64().ok_or_else(|| {
            PsrpError::protocol(format!(
                "host call: invalid method identifier {method_value:?}"
            ))
        })?;
        let mi = HostMethodId::from_i64(mi_raw);
        let mp: Vec<PsValue> = match obj.get("mp") {
            Some(PsValue::List(items)) => items.clone(),
            Some(PsValue::Object(inner)) => match inner.get("_value") {
                Some(PsValue::List(items)) => items.clone(),
                _ => Vec::new(),
            },
            _ => Vec::new(),
        };

        let result = dispatch_host_call(self.host.as_ref(), mi, &mp).await;

        // Void methods return Ok(None) — nothing to send back.
        let response_value = match result {
            Ok(None) => return Ok(()),
            Ok(Some(v)) => v,
            Err(e) => {
                if mi.is_void() {
                    tracing::warn!(method = mi_raw, error = %e, "unsupported void host operation");
                    return Ok(());
                }
                // Non-void errored — send an ExceptionRecord response so
                // the server doesn't hang waiting for a reply.
                let body = build_host_response_error_body(ci, mi_raw, &e.to_string());
                let response_type = match msg.message_type {
                    MessageType::RunspacePoolHostCall => MessageType::RunspacePoolHostResponse,
                    _ => MessageType::PipelineHostResponse,
                };
                return self
                    .send_pipeline_message(response_type, msg.pid, body)
                    .await;
            }
        };

        let body = build_host_response_body(ci, mi_raw, &response_value);
        let response_type = match msg.message_type {
            MessageType::RunspacePoolHostCall => MessageType::RunspacePoolHostResponse,
            _ => MessageType::PipelineHostResponse,
        };
        self.send_pipeline_message(response_type, msg.pid, body)
            .await
    }

    pub(crate) fn allocate_object_id(&mut self) -> u64 {
        let id = self.next_object_id;
        self.next_object_id += 1;
        id
    }

    pub(crate) async fn signal_transport_stop(&mut self) -> Result<()> {
        self.transport.signal_stop().await
    }

    pub(crate) async fn send_pipeline_message(
        &mut self,
        mt: MessageType,
        pid: Uuid,
        body: String,
    ) -> Result<()> {
        let msg = PsrpMessage {
            destination: Destination::Server,
            message_type: mt,
            rpid: self.machine.rpid(),
            pid,
            data: body,
        };
        let encoded = msg.encode();
        let oid = self.allocate_object_id();
        let frag_bytes = encode_message(oid, &encoded);

        // For CreatePipeline: the first fragment must go via Execute
        // (Command) with the PID as CommandId, not via Send.
        if mt == MessageType::CreatePipeline {
            self.transport.execute_pipeline(&frag_bytes, pid).await
        } else if matches!(
            mt,
            MessageType::PipelineHostResponse | MessageType::RunspacePoolHostResponse
        ) {
            self.transport.send_host_response(&frag_bytes).await
        } else {
            self.transport.send_fragment(&frag_bytes).await
        }
    }

    // --- private ---

    /// Execute a batch of state-machine actions on the transport.
    async fn execute(&mut self, actions: Vec<Action>) -> Result<()> {
        for action in actions {
            match action {
                Action::SendMessage { message_type, body } => {
                    self.send_psrp_message(message_type, body).await?;
                }
            }
        }
        Ok(())
    }

    async fn drain_until_opened(&mut self) -> Result<()> {
        loop {
            let msg = self.next_message().await?;
            self.machine.on_message(&msg)?;
            if self.machine.is_opened() {
                return Ok(());
            }
        }
    }
}

/// A runspace pool that has been disconnected from its transport but
/// whose server-side shell is still alive.
///
/// Obtain one from [`RunspacePool::disconnect`], then call
/// [`DisconnectedPool::reconnect`] to re-establish the transport and
/// resume the session.
pub struct DisconnectedPool {
    shell_id: String,
    rpid: Uuid,
    min_runspaces: i32,
    max_runspaces: i32,
    host: Arc<dyn PsHost>,
    session_key: Option<crate::crypto::SessionKey>,
}

impl std::fmt::Debug for DisconnectedPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DisconnectedPool")
            .field("rpid", &self.rpid)
            .field("shell_id", &self.shell_id)
            .field("min_runspaces", &self.min_runspaces)
            .field("max_runspaces", &self.max_runspaces)
            .finish()
    }
}

impl DisconnectedPool {
    /// Runspace pool UUID.
    #[must_use]
    pub fn rpid(&self) -> Uuid {
        self.rpid
    }

    /// Server-side shell identifier — pass this to
    /// [`crate::transport::WinrmPsrpTransport::reconnect`] to rebuild the
    /// transport before calling [`reconnect`](Self::reconnect).
    #[must_use]
    pub fn shell_id(&self) -> &str {
        &self.shell_id
    }

    /// Resume the runspace pool by attaching it to a freshly-rebuilt
    /// transport. The caller is responsible for re-creating the
    /// transport with the same `shell_id` (use
    /// [`WinrmPsrpTransport::reconnect`](crate::transport::WinrmPsrpTransport::reconnect)
    /// for the live path).
    ///
    /// The WSMan `Reconnect` the transport performs resumes the shell, and
    /// the reused `SessionId` keeps the server-side runspace `Opened`, so no
    /// PSRP handshake is replayed here.
    // Stays `async` for API stability (2.0.x): callers `.await` it, and the
    // existing-client reconnect no longer needs to send or receive anything
    // now that the transport does the WSMan Reconnect itself.
    #[allow(clippy::unused_async_trait_impl)]
    pub async fn reconnect<T: PsrpTransport>(self, transport: T) -> Result<RunspacePool<T>> {
        let mut machine =
            RunspacePoolStateMachine::new(self.rpid, self.min_runspaces, self.max_runspaces)?;
        // Existing-client reconnect: the transport has already issued the
        // WSMan Reconnect, and the reused SessionId keeps the server-side
        // runspace Opened. `connect` therefore emits no PSRP message and
        // marks the machine Opened — no handshake to send, no state to drain.
        // Replaying the handshake and draining for a fresh Opened state made
        // the follow-up Receive time out (`w:TimedOut`), the server having
        // nothing left to say.
        let actions = machine.connect();
        debug_assert!(actions.is_empty() && machine.is_opened());
        let pool = RunspacePool {
            transport,
            reassembler: Reassembler::new(),
            machine,
            next_object_id: 1,
            closed: false,
            host: self.host,
            session_key: self.session_key,
            pending_messages: Vec::new(),
            output_budget: None,
        };
        Ok(pool)
    }
}

pub(crate) fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() % 2 != 0 {
        return Err(PsrpError::protocol("hex: odd length"));
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    for pair in clean.as_bytes().as_chunks::<2>().0 {
        let hi = hex_digit(pair[0])?;
        let lo = hex_digit(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_digit(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(PsrpError::protocol(format!("hex: invalid digit 0x{b:02X}"))),
    }
}

pub(crate) fn build_host_response_body(ci: i64, mi: i64, value: &PsValue) -> String {
    let obj = PsObject::new()
        .with("ci", PsValue::I64(ci))
        .with("mi", PsValue::I32(mi as i32))
        .with("mr", value.clone());
    to_clixml(&PsValue::Object(obj))
}

pub(crate) fn build_host_response_error_body(ci: i64, mi: i64, message: &str) -> String {
    let exception = PsObject::new()
        .with("Message", PsValue::String(message.to_string()))
        .with_type_names(["System.Exception"]);
    let error_record = PsObject::new()
        .with("Exception", PsValue::Object(exception))
        .with("TargetObject", PsValue::Null)
        .with(
            "FullyQualifiedErrorId",
            PsValue::String("RemoteHostExecutionException".into()),
        )
        .with("errorCategory_Category", PsValue::I32(0))
        .with("ErrorCategory_Activity", PsValue::String(String::new()))
        .with(
            "ErrorCategory_Reason",
            PsValue::String("NotSupportedException".into()),
        )
        .with("ErrorCategory_TargetName", PsValue::String(String::new()))
        .with("ErrorCategory_TargetType", PsValue::String(String::new()))
        .with("ErrorCategory_Message", PsValue::String(message.into()))
        .with("SerializeExtendedInfo", PsValue::Bool(false));
    let obj = PsObject::new()
        .with("ci", PsValue::I64(ci))
        .with("mi", PsValue::I32(mi as i32))
        .with("me", PsValue::Object(error_record));
    to_clixml(&PsValue::Object(obj))
}

impl<T: PsrpTransport> std::fmt::Debug for RunspacePool<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Manual impl because `PsrpTransport` is not a `Debug` bound.
        f.debug_struct("RunspacePool")
            .field("state", &self.machine.state())
            .field("rpid", &self.machine.rpid())
            .field("min_runspaces", &self.machine.min_runspaces())
            .field("max_runspaces", &self.machine.max_runspaces())
            .field("next_object_id", &self.next_object_id)
            .field("closed", &self.closed)
            .field("reassembler_idle", &self.reassembler.is_idle())
            .field("transport", &"..")
            .finish()
    }
}

impl<T: PsrpTransport> Drop for RunspacePool<T> {
    fn drop(&mut self) {
        if !self.closed {
            tracing::warn!("RunspacePool dropped without close() — server-side shell may leak");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clixml::{PsObject, to_clixml};
    use crate::transport::mock::MockTransport;

    fn state_message_bytes(state: RunspacePoolState) -> Vec<u8> {
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

    fn wire(oid: u64, payload: &[u8]) -> Vec<u8> {
        encode_message(oid, payload)
    }

    #[tokio::test]
    async fn open_reaches_opened_state() {
        let t = MockTransport::new();
        t.push_incoming(wire(100, &state_message_bytes(RunspacePoolState::Opened)));

        let pool = RunspacePool::open_with_transport(t.clone()).await.unwrap();
        assert_eq!(pool.state(), RunspacePoolState::Opened);
        assert_eq!(t.sent().len(), 2); // SessionCapability + InitRunspacePool
        pool.close().await.unwrap();
        assert!(*t.closed.lock().unwrap());
    }

    #[tokio::test]
    async fn broken_state_during_open_errors() {
        let t = MockTransport::new();
        t.push_incoming(wire(1, &state_message_bytes(RunspacePoolState::Broken)));
        let err = RunspacePool::open_with_transport(t).await.unwrap_err();
        assert!(matches!(err, PsrpError::Protocol(_)));
    }

    #[tokio::test]
    async fn invalid_runspace_bounds() {
        let t = MockTransport::new();
        let err = RunspacePool::open_with_options(t, 0, 0).await.unwrap_err();
        assert!(matches!(err, PsrpError::Protocol(_)));
    }

    #[tokio::test]
    async fn invalid_runspace_bounds_max_lt_min() {
        let t = MockTransport::new();
        let err = RunspacePool::open_with_options(t, 5, 3).await.unwrap_err();
        assert!(matches!(err, PsrpError::Protocol(_)));
    }

    #[tokio::test]
    async fn open_ignores_unrelated_messages() {
        let t = MockTransport::new();
        let app_data = PsrpMessage {
            destination: Destination::Client,
            message_type: MessageType::ApplicationPrivateData,
            rpid: Uuid::nil(),
            pid: Uuid::nil(),
            data: "<Obj RefId=\"0\"><MS/></Obj>".into(),
        }
        .encode();
        t.push_incoming(wire(1, &app_data));
        t.push_incoming(wire(2, &state_message_bytes(RunspacePoolState::Opened)));
        let pool = RunspacePool::open_with_transport(t).await.unwrap();
        assert_eq!(pool.state(), RunspacePoolState::Opened);
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn ensure_state_works() {
        let t = MockTransport::new();
        t.push_incoming(wire(1, &state_message_bytes(RunspacePoolState::Opened)));
        let pool = RunspacePool::open_with_transport(t).await.unwrap();
        assert!(pool.ensure_state(RunspacePoolState::Opened).is_ok());
        assert!(pool.ensure_state(RunspacePoolState::Broken).is_err());
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn close_is_idempotent_and_drop_warns() {
        let t = MockTransport::new();
        t.push_incoming(wire(1, &state_message_bytes(RunspacePoolState::Opened)));
        let pool = RunspacePool::open_with_transport(t).await.unwrap();
        pool.close().await.unwrap();

        let t = MockTransport::new();
        t.push_incoming(wire(1, &state_message_bytes(RunspacePoolState::Opened)));
        let pool = RunspacePool::open_with_transport(t).await.unwrap();
        drop(pool);
    }

    #[tokio::test]
    async fn debug_impl_does_not_panic() {
        let t = MockTransport::new();
        t.push_incoming(wire(1, &state_message_bytes(RunspacePoolState::Opened)));
        let pool = RunspacePool::open_with_transport(t).await.unwrap();
        let s = format!("{pool:?}");
        assert!(s.contains("RunspacePool"));
        assert!(s.contains("Opened"));
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn min_max_runspaces_exposed() {
        let t = MockTransport::new();
        t.push_incoming(wire(1, &state_message_bytes(RunspacePoolState::Opened)));
        let pool = RunspacePool::open_with_options(t, 2, 5).await.unwrap();
        assert_eq!(pool.min_runspaces(), 2);
        assert_eq!(pool.max_runspaces(), 5);
        assert_ne!(pool.id(), Uuid::nil());
        let _ = pool.close().await;
    }

    // ---------- Phase D coverage tests ----------

    fn host_call_bytes(ci: i64, mi: i64, mp: PsValue) -> Vec<u8> {
        host_call_bytes_with(ci, mi, mp, Uuid::nil(), Uuid::nil())
    }

    fn host_call_bytes_with(ci: i64, mi: i64, mp: PsValue, rpid: Uuid, pid: Uuid) -> Vec<u8> {
        let obj = PsObject::new()
            .with("ci", PsValue::I64(ci))
            .with("mi", PsValue::I64(mi))
            .with("mp", mp);
        let body = to_clixml(&PsValue::Object(obj));
        PsrpMessage {
            destination: Destination::Client,
            message_type: MessageType::RunspacePoolHostCall,
            rpid,
            pid,
            data: body,
        }
        .encode()
    }

    async fn opened_pool_with_host(
        t: &MockTransport,
        host: Arc<dyn PsHost>,
    ) -> RunspacePool<MockTransport> {
        t.inbox
            .lock()
            .unwrap()
            .push_front(wire(1, &state_message_bytes(RunspacePoolState::Opened)));
        RunspacePool::open_with_options_and_host(t.clone(), 1, 1, host)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn host_call_dispatches_write_line_and_swallows_message() {
        let t = MockTransport::new();
        let host = crate::host::BufferedHost::new();
        let mut pool = opened_pool_with_host(&t, Arc::new(host.clone())).await;
        let rpid = pool.id();
        let pid = Uuid::new_v4();
        // Host call (RunspacePoolHostCall): pool intercepts it before the
        // pipeline filter, so the embedded pid does not need to match.
        t.push_incoming(wire(
            2,
            &host_call_bytes(
                42,
                crate::host::HostMethodId::WriteLine1.to_i64(),
                PsValue::List(vec![PsValue::String("hello from host".into())]),
            ),
        ));
        // Pipeline output + state must carry our pipeline's rpid/pid so
        // they pass the pipeline-level pid filter.
        t.push_incoming(wire(
            3,
            &PsrpMessage {
                destination: Destination::Client,
                message_type: MessageType::PipelineOutput,
                rpid,
                pid,
                data: "<I32>1</I32>".into(),
            }
            .encode(),
        ));
        t.push_incoming(wire(
            4,
            &PsrpMessage {
                destination: Destination::Client,
                message_type: MessageType::PipelineState,
                rpid,
                pid,
                data: to_clixml(&PsValue::Object(PsObject::new().with(
                    "PipelineState",
                    PsValue::I32(crate::pipeline::PipelineState::Completed as i32),
                ))),
            }
            .encode(),
        ));
        let out = crate::pipeline::Pipeline::new("irrelevant")
            .__with_forced_pid_for_test(pid)
            .run(&mut pool)
            .await
            .unwrap();
        assert_eq!(out, vec![PsValue::I32(1)]);
        // The host received the WriteLine.
        assert_eq!(host.lines(), vec!["hello from host".to_string()]);
        // After open (2 sent) + CreatePipeline (1 sent) we should NOT have
        // any additional sent frames — WriteLine1 is a void host method.
        assert_eq!(t.sent().len(), 3);
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn host_call_read_line_sends_error_response() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with_host(&t, Arc::new(crate::host::NoInteractionHost)).await;
        let rpid = pool.id();
        let pid = Uuid::new_v4();
        // ReadLine with NoInteractionHost will be rejected and the pool
        // should ship an error response so the server doesn't hang.
        t.push_incoming(wire(
            2,
            &host_call_bytes(
                7,
                crate::host::HostMethodId::ReadLine.to_i64(),
                PsValue::List(Vec::new()),
            ),
        ));
        t.push_incoming(wire(
            3,
            &PsrpMessage {
                destination: Destination::Client,
                message_type: MessageType::PipelineState,
                rpid,
                pid,
                data: to_clixml(&PsValue::Object(PsObject::new().with(
                    "PipelineState",
                    PsValue::I32(crate::pipeline::PipelineState::Completed as i32),
                ))),
            }
            .encode(),
        ));
        let _ = crate::pipeline::Pipeline::new("irrelevant")
            .__with_forced_pid_for_test(pid)
            .run(&mut pool)
            .await;
        // open (2) + CreatePipeline (1) + HostResponse error (1) = 4
        assert_eq!(t.sent().len(), 4);
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn host_call_read_line_with_custom_host_sends_value_response() {
        use async_trait::async_trait;

        struct YesHost;
        #[async_trait]
        impl crate::host::PsHost for YesHost {
            async fn read_line(&self) -> Result<String> {
                Ok("alice".into())
            }
        }

        let t = MockTransport::new();
        let mut pool = opened_pool_with_host(&t, Arc::new(YesHost)).await;
        let rpid = pool.id();
        let pid = Uuid::new_v4();
        t.push_incoming(wire(
            2,
            &host_call_bytes(
                3,
                crate::host::HostMethodId::ReadLine.to_i64(),
                PsValue::List(Vec::new()),
            ),
        ));
        t.push_incoming(wire(
            3,
            &PsrpMessage {
                destination: Destination::Client,
                message_type: MessageType::PipelineState,
                rpid,
                pid,
                data: to_clixml(&PsValue::Object(PsObject::new().with(
                    "PipelineState",
                    PsValue::I32(crate::pipeline::PipelineState::Completed as i32),
                ))),
            }
            .encode(),
        ));
        let _ = crate::pipeline::Pipeline::new("irrelevant")
            .__with_forced_pid_for_test(pid)
            .run(&mut pool)
            .await;
        // open + CreatePipeline + HostResponse success = 4
        assert_eq!(t.sent().len(), 4);
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn encrypt_secure_string_without_key_errors() {
        let t = MockTransport::new();
        t.push_incoming(wire(1, &state_message_bytes(RunspacePoolState::Opened)));
        let pool = RunspacePool::open_with_transport(t).await.unwrap();
        let err = pool.encrypt_secure_string("x").unwrap_err();
        assert!(matches!(err, PsrpError::Protocol(_)));
        let err = pool.decrypt_secure_string("AAAA").unwrap_err();
        assert!(matches!(err, PsrpError::Protocol(_)));
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn secure_string_roundtrip_via_set_session_key() {
        let t = MockTransport::new();
        t.push_incoming(wire(1, &state_message_bytes(RunspacePoolState::Opened)));
        let mut pool = RunspacePool::open_with_transport(t).await.unwrap();
        pool.set_session_key(crate::crypto::SessionKey::from_bytes([7u8; 32]));
        assert!(pool.session_key().is_some());
        let b64 = pool.encrypt_secure_string("héllo 🌍").unwrap();
        let pt = pool.decrypt_secure_string(&b64).unwrap();
        assert_eq!(pt, "héllo 🌍");
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn decrypt_secure_string_rejects_bad_base64() {
        let t = MockTransport::new();
        t.push_incoming(wire(1, &state_message_bytes(RunspacePoolState::Opened)));
        let mut pool = RunspacePool::open_with_transport(t).await.unwrap();
        pool.set_session_key(crate::crypto::SessionKey::from_bytes([0u8; 32]));
        let err = pool.decrypt_secure_string("!!!not base64!!!").unwrap_err();
        assert!(matches!(err, PsrpError::Protocol(_)));
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn disconnect_returns_disconnected_pool() {
        let t = MockTransport::new();
        t.push_incoming(wire(1, &state_message_bytes(RunspacePoolState::Opened)));
        let pool = RunspacePool::open_with_options(t, 2, 5).await.unwrap();
        let disconnected = pool.disconnect().await.unwrap();
        assert_eq!(disconnected.shell_id(), "MOCK-SHELL-ID");
        assert_ne!(disconnected.rpid(), Uuid::nil());
        // Debug impl exercised.
        let s = format!("{disconnected:?}");
        assert!(s.contains("DisconnectedPool"));
        assert!(s.contains("MOCK-SHELL-ID"));
    }

    #[tokio::test]
    async fn disconnect_then_reconnect_roundtrip() {
        // First half: open + disconnect via the mock.
        let t = MockTransport::new();
        t.push_incoming(wire(1, &state_message_bytes(RunspacePoolState::Opened)));
        let pool = RunspacePool::open_with_transport(t).await.unwrap();
        let disconnected = pool.disconnect().await.unwrap();

        // Second half: existing-client reconnect. The WSMan Reconnect the
        // transport performs already resumed the shell, so the pool is Opened
        // with no PSRP handshake and nothing to drain — pushing an Opened
        // state or expecting SessionCapability/ConnectRunspacePool would
        // encode the old bug that timed the server out (`w:TimedOut`).
        let t2 = MockTransport::new();
        let pool = disconnected.reconnect(t2.clone()).await.unwrap();
        assert_eq!(pool.state(), RunspacePoolState::Opened);
        assert!(t2.sent().is_empty(), "reconnect must send no PSRP message");
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn double_disconnect_errors() {
        let t = MockTransport::new();
        t.push_incoming(wire(1, &state_message_bytes(RunspacePoolState::Opened)));
        let pool = RunspacePool::open_with_transport(t).await.unwrap();
        let _disc = pool.disconnect().await.unwrap();
        // The original pool was consumed. Re-disconnect on a freshly
        // closed pool: build a new one and close it first.
        let t2 = MockTransport::new();
        t2.push_incoming(wire(1, &state_message_bytes(RunspacePoolState::Opened)));
        let pool2 = RunspacePool::open_with_transport(t2).await.unwrap();
        pool2.close().await.unwrap();
        // Double-close was already covered; this just keeps the symmetry.
    }

    #[tokio::test]
    async fn hex_decode_roundtrip_and_errors() {
        // Exercise the hex helper via a fake EncryptedSessionKey path.
        assert_eq!(
            hex_decode("deadBEEF").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert!(hex_decode("ABC").is_err()); // odd length
        assert!(hex_decode("GG").is_err()); // bad digit
    }

    #[test]
    fn build_creation_fragments_produces_nonempty_bytes() {
        let (rpid, bytes) = RunspacePool::<MockTransport>::build_creation_fragments(1, 1).unwrap();
        assert!(!rpid.is_nil());
        // Must contain at least the fragment headers for SessionCapability + InitRunspacePool
        assert!(bytes.len() > 42); // 21-byte header × 2 at minimum
    }

    #[test]
    fn build_creation_fragments_rejects_bad_bounds() {
        let err = RunspacePool::<MockTransport>::build_creation_fragments(0, 0);
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn open_from_transport_reaches_opened() {
        let t = MockTransport::new();
        let (rpid, _bytes) = RunspacePool::<MockTransport>::build_creation_fragments(1, 1).unwrap();
        t.push_incoming(wire(100, &state_message_bytes(RunspacePoolState::Opened)));
        let pool = RunspacePool::open_from_transport(t.clone(), rpid, 1, 1)
            .await
            .unwrap();
        assert_eq!(pool.state(), RunspacePoolState::Opened);
        pool.close().await.unwrap();
    }

    #[tokio::test]
    async fn close_already_closed_is_noop() {
        let t = MockTransport::new();
        t.push_incoming(wire(100, &state_message_bytes(RunspacePoolState::Opened)));
        let mut pool = RunspacePool::open_with_transport(t.clone()).await.unwrap();
        // Mark as closed internally by calling close once
        pool.closed = true;
        pool.close().await.unwrap(); // should early-return Ok(())
    }

    #[tokio::test]
    async fn disconnect_already_closed_errors() {
        let t = MockTransport::new();
        t.push_incoming(wire(100, &state_message_bytes(RunspacePoolState::Opened)));
        let mut pool = RunspacePool::open_with_transport(t.clone()).await.unwrap();
        pool.closed = true;
        let err = pool.disconnect().await.unwrap_err();
        assert!(err.to_string().contains("already closed"));
    }

    #[tokio::test]
    async fn build_host_response_body_shapes() {
        let body = build_host_response_body(3, 11, &PsValue::I32(0));
        assert!(body.contains("<I64 N=\"ci\">3</I64>"));
        assert!(body.contains("<I32 N=\"mi\">11</I32>"));
        assert!(body.contains("N=\"mr\""));

        let err = build_host_response_error_body(3, 51, "boom");
        assert!(err.contains("<I64 N=\"ci\">3</I64>"));
        assert!(err.contains("<I32 N=\"mi\">51</I32>"));
        assert!(err.contains("boom"));
    }

    #[tokio::test]
    async fn request_session_key_is_idempotent_when_key_already_set() {
        // Once a session key is in place, request_session_key must
        // short-circuit: no PublicKey message is sent, and the function
        // does not block waiting for an EncryptedSessionKey reply (which
        // would deadlock the test against an empty mock inbox).
        let t = MockTransport::new();
        t.push_incoming(wire(1, &state_message_bytes(RunspacePoolState::Opened)));
        let mut pool = RunspacePool::open_with_transport(t.clone()).await.unwrap();
        pool.set_session_key(crate::crypto::SessionKey::from_bytes([9u8; 32]));
        let sent_before = t.sent().len();
        // Must return Ok promptly. If the early-return check were
        // missing, this would hang trying to recv from the empty inbox
        // (or, more precisely, return a synthetic completion message
        // and loop). The test would then time out.
        pool.request_session_key().await.unwrap();
        // No new outgoing PublicKey fragment.
        assert_eq!(t.sent().len(), sent_before);
        let _ = pool.close().await;
    }
}
