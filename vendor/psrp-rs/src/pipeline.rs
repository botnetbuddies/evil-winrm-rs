//! Pipeline builder and executor.

use uuid::Uuid;

#[cfg(test)]
use crate::clixml::PsObject;
use crate::clixml::{PsValue, parse_clixml};
use crate::error::{PsrpError, Result};
use crate::message::MessageType;
use crate::records::{
    ErrorRecord, FromPsObject, InformationRecord, ProgressRecord, TraceRecord, WarningRecord,
};
use crate::runspace::RunspacePool;
use crate::transport::PsrpTransport;

impl PipelineResult {
    /// Decode every value on the `errors` stream as an [`ErrorRecord`],
    /// dropping any that don't match the expected shape.
    #[must_use]
    pub fn typed_errors(&self) -> Vec<ErrorRecord> {
        self.errors
            .iter()
            .filter_map(ErrorRecord::from_ps_object)
            .collect()
    }

    /// Decode every value on the `warnings` stream as a [`WarningRecord`].
    #[must_use]
    pub fn typed_warnings(&self) -> Vec<WarningRecord> {
        self.warnings
            .iter()
            .filter_map(WarningRecord::from_ps_object)
            .collect()
    }

    /// Decode every value on the `information` stream as an
    /// [`InformationRecord`].
    #[must_use]
    pub fn typed_information(&self) -> Vec<InformationRecord> {
        self.information
            .iter()
            .filter_map(InformationRecord::from_ps_object)
            .collect()
    }

    /// Decode every value on the `progress` stream as a [`ProgressRecord`].
    #[must_use]
    pub fn typed_progress(&self) -> Vec<ProgressRecord> {
        self.progress
            .iter()
            .filter_map(ProgressRecord::from_ps_object)
            .collect()
    }

    /// Decode every value on the `verbose` stream as a [`TraceRecord`].
    #[must_use]
    pub fn typed_verbose(&self) -> Vec<TraceRecord> {
        self.verbose
            .iter()
            .filter_map(TraceRecord::from_ps_object)
            .collect()
    }

    /// Decode every value on the `debug` stream as a [`TraceRecord`].
    #[must_use]
    pub fn typed_debug(&self) -> Vec<TraceRecord> {
        self.debug
            .iter()
            .filter_map(TraceRecord::from_ps_object)
            .collect()
    }
}

/// Result of a completed pipeline run, carrying every PSRP stream separately.
#[derive(Debug, Default, Clone)]
pub struct PipelineResult {
    pub output: Vec<PsValue>,
    pub errors: Vec<PsValue>,
    pub warnings: Vec<PsValue>,
    pub verbose: Vec<PsValue>,
    pub debug: Vec<PsValue>,
    pub information: Vec<PsValue>,
    pub progress: Vec<PsValue>,
    pub state: PipelineState,
}

/// Server-reported pipeline state (MS-PSRP §2.2.3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PipelineState {
    #[default]
    NotStarted,
    Running,
    Stopping,
    Stopped,
    Completed,
    Failed,
    Disconnected,
    Unknown,
}

impl PipelineState {
    fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::NotStarted,
            1 => Self::Running,
            2 => Self::Stopping,
            3 => Self::Stopped,
            4 => Self::Completed,
            5 => Self::Failed,
            6 => Self::Disconnected,
            _ => Self::Unknown,
        }
    }

    /// True when the pipeline has reached a terminal state.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Stopped | Self::Disconnected
        )
    }
}

/// One argument to a [`Command`].
///
/// PowerShell commands accept three kinds of argument:
/// * **Named**: `-Name svchost` — a name/value pair.
/// * **Positional**: `svchost` — a bare value, bound by position.
/// * **Switch**: `-Force` — a flag, no value.
#[derive(Debug, Clone)]
pub enum Argument {
    /// `-Name value`
    Named { name: String, value: PsValue },
    /// Positional argument (no name).
    Positional(PsValue),
    /// `-SwitchName` — boolean flag, no value.
    Switch(String),
}

/// A single command within a pipeline.
#[derive(Debug, Clone)]
pub struct Command {
    pub name: String,
    pub arguments: Vec<Argument>,
    pub is_script: bool,
    /// If true, errors from this command are merged into the output stream
    /// (equivalent to `2>&1` in PowerShell pipes).
    pub merge_errors_to_output: bool,
}

impl Command {
    /// Build a command invoking `name` (a cmdlet or function).
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            arguments: Vec::new(),
            is_script: false,
            merge_errors_to_output: false,
        }
    }

    /// Build a command that runs a raw script block.
    pub fn script(script: impl Into<String>) -> Self {
        Self {
            name: script.into(),
            arguments: Vec::new(),
            is_script: true,
            merge_errors_to_output: false,
        }
    }

    /// Add a named parameter (builder style).
    #[must_use]
    pub fn with_parameter(mut self, name: impl Into<String>, value: PsValue) -> Self {
        self.arguments.push(Argument::Named {
            name: name.into(),
            value,
        });
        self
    }

    /// Add a positional argument (builder style).
    #[must_use]
    pub fn with_argument(mut self, value: PsValue) -> Self {
        self.arguments.push(Argument::Positional(value));
        self
    }

    /// Add a switch parameter (builder style). Emits `-SwitchName` with no
    /// value, as PowerShell expects for boolean flags.
    #[must_use]
    pub fn with_switch(mut self, name: impl Into<String>) -> Self {
        self.arguments.push(Argument::Switch(name.into()));
        self
    }

    /// Merge the error stream of this command into the output stream,
    /// equivalent to appending `2>&1` in a PowerShell pipe.
    #[must_use]
    pub fn merging_errors_to_output(mut self) -> Self {
        self.merge_errors_to_output = true;
        self
    }
}

#[derive(Debug, Clone, Copy)]
enum FailureMode {
    ReturnError,
    ReturnStreams,
}

/// A pipeline is an ordered list of commands.
#[derive(Debug, Clone)]
pub struct Pipeline {
    commands: Vec<Command>,
    /// When `false`, the pipeline expects the client to stream input
    /// objects via `PipelineInput` messages followed by `EndOfPipelineInput`.
    /// Defaults to `true` (closed input, script runs once).
    pub(crate) no_input: bool,
    /// When `true`, invocation info is included in every record. Default `true`.
    pub(crate) add_invocation_info: bool,
    /// When `true`, the command is added to the server's session history.
    pub(crate) add_to_history: bool,
    /// Test-only override for the pipeline PID. `None` in production (a
    /// fresh v4 UUID is generated). Set via the doc-hidden
    /// `__with_forced_pid_for_test` to allow unit tests to seed mock
    /// inboxes with messages targeting a known PID.
    pub(crate) forced_pid: Option<Uuid>,
    failure_mode: FailureMode,
}

impl Pipeline {
    /// Create a pipeline running a single raw script block.
    pub fn new(script: impl Into<String>) -> Self {
        Self {
            commands: vec![Command::script(script)],
            no_input: true,
            add_invocation_info: true,
            add_to_history: false,
            forced_pid: None,
            failure_mode: FailureMode::ReturnError,
        }
    }

    /// Create an empty pipeline (use [`Pipeline::add_command`] to populate).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            commands: Vec::new(),
            no_input: true,
            add_invocation_info: true,
            add_to_history: false,
            forced_pid: None,
            failure_mode: FailureMode::ReturnError,
        }
    }

    /// Test-only: pin the pipeline's PID to a known value so unit tests
    /// can seed mock inboxes with matching messages. Never call from
    /// production code — the security check that filters incoming
    /// messages by PID relies on the PID being unguessable.
    #[doc(hidden)]
    #[must_use]
    pub fn __with_forced_pid_for_test(mut self, pid: Uuid) -> Self {
        self.forced_pid = Some(pid);
        self
    }

    /// Enable client-to-server input streaming for this pipeline.
    ///
    /// Setting this to `true` (the default for [`start`](Self::start)-based
    /// streaming) signals the server that it should wait for
    /// `PipelineInput` messages before running.
    #[must_use]
    pub fn with_input(mut self, streaming: bool) -> Self {
        self.no_input = !streaming;
        self
    }

    /// Enable or disable `AddToHistory` on the remote side.
    #[must_use]
    pub fn with_history(mut self, add_to_history: bool) -> Self {
        self.add_to_history = add_to_history;
        self
    }

    /// Return collected streams and `Failed` state when the server reports a
    /// terminating error, preserving output produced before that error.
    /// Transport errors and cancellation still return `Err`.
    #[must_use]
    pub fn retaining_failed_output(mut self) -> Self {
        self.failure_mode = FailureMode::ReturnStreams;
        self
    }

    /// Push a command at the end of the pipeline.
    #[must_use]
    pub fn add_command(mut self, command: Command) -> Self {
        self.commands.push(command);
        self
    }

    /// Number of commands in the pipeline.
    #[must_use]
    pub fn len(&self) -> usize {
        self.commands.len()
    }

    /// True if there are no commands.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }

    /// Execute the pipeline and return only its `Output` stream.
    pub async fn run<T: PsrpTransport>(self, pool: &mut RunspacePool<T>) -> Result<Vec<PsValue>> {
        let result = self.run_all_streams(pool).await?;
        if result.state == PipelineState::Failed {
            return Err(PsrpError::PipelineFailed(describe_errors(&result.errors)));
        }
        Ok(result.output)
    }

    /// Execute the pipeline with a cancellation token. When the token is
    /// cancelled the pipeline is stopped cleanly (`signal_ctrl_c`) and a
    /// [`PsrpError::Cancelled`] is returned.
    pub async fn run_with_cancel<T: PsrpTransport>(
        self,
        pool: &mut RunspacePool<T>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<Vec<PsValue>> {
        let result = self.run_all_streams_with_cancel(pool, cancel).await?;
        if result.state == PipelineState::Failed {
            return Err(PsrpError::PipelineFailed(describe_errors(&result.errors)));
        }
        Ok(result.output)
    }

    /// Execute the pipeline and return a fully-decoded [`PipelineResult`].
    pub async fn run_all_streams<T: PsrpTransport>(
        self,
        pool: &mut RunspacePool<T>,
    ) -> Result<PipelineResult> {
        self.run_all_streams_with_cancel(
            pool,
            tokio_util::sync::CancellationToken::new(), // never cancelled
        )
        .await
    }

    /// Start the pipeline on the server and return a [`PipelineHandle`]
    /// that can be used to stream input objects, then collect the output.
    ///
    /// The handle borrows the pool mutably, so only one pipeline can run
    /// at a time. This is the recommended path when you need to feed
    /// input via [`PipelineHandle::write_input`].
    pub async fn start<T: PsrpTransport>(
        self,
        pool: &mut RunspacePool<T>,
    ) -> Result<PipelineHandle<'_, T>> {
        if self.commands.is_empty() {
            return Err(PsrpError::protocol("pipeline is empty"));
        }
        let pid = self.forced_pid.unwrap_or_else(Uuid::new_v4);
        let rpid = pool.id();
        let body = self.create_pipeline_xml();
        pool.send_pipeline_message(MessageType::CreatePipeline, pid, body)
            .await?;
        Ok(PipelineHandle {
            pool,
            pid,
            rpid,
            input_closed: self.no_input,
            failure_mode: self.failure_mode,
        })
    }

    /// Execute the pipeline with a cancellation token and return a
    /// [`PipelineResult`]. If `cancel` fires, the pipeline is stopped
    /// via `signal_ctrl_c` and [`PsrpError::Cancelled`] is returned after
    /// the server ACKs `Stopped`.
    pub async fn run_all_streams_with_cancel<T: PsrpTransport>(
        self,
        pool: &mut RunspacePool<T>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<PipelineResult> {
        if self.commands.is_empty() {
            return Err(PsrpError::protocol("pipeline is empty"));
        }
        let pid = self.forced_pid.unwrap_or_else(Uuid::new_v4);
        let rpid = pool.id();
        let body = self.create_pipeline_xml();
        pool.send_pipeline_message(MessageType::CreatePipeline, pid, body)
            .await?;

        let mut cancel_signalled = false;

        let mut result = PipelineResult {
            state: PipelineState::Running,
            ..PipelineResult::default()
        };

        loop {
            // If the caller asked to cancel, fire a stop signal (once) then
            // keep draining until the server confirms `Stopped`.
            if !cancel_signalled && cancel.is_cancelled() {
                pool.signal_transport_stop().await?;
                cancel_signalled = true;
            }
            let msg = tokio::select! {
                biased;
                () = cancel.cancelled(), if !cancel_signalled => {
                    pool.signal_transport_stop().await?;
                    cancel_signalled = true;
                    continue;
                }
                msg = pool.next_message() => msg?,
            };
            // Drop messages that don't belong to this pipeline. A
            // malicious or buggy server can otherwise smuggle output,
            // errors, or terminal-state ACKs from a different pipeline
            // (or a forged PID) into this pipeline's result.
            if msg.pid != pid || msg.rpid != rpid {
                tracing::debug!(
                    expected_pid = %pid,
                    got_pid = %msg.pid,
                    expected_rpid = %rpid,
                    got_rpid = %msg.rpid,
                    mt = ?msg.message_type,
                    "dropping pipeline message with mismatched pid/rpid",
                );
                continue;
            }
            match msg.message_type {
                MessageType::PipelineOutput => {
                    for v in parse_clixml(&msg.data)? {
                        pool.host_output(&v).await;
                        result.output.push(v);
                    }
                }
                MessageType::ErrorRecord => {
                    for v in parse_clixml(&msg.data)? {
                        result.errors.push(v);
                    }
                }
                MessageType::WarningRecord => {
                    for v in parse_clixml(&msg.data)? {
                        result.warnings.push(v);
                    }
                }
                MessageType::VerboseRecord => {
                    for v in parse_clixml(&msg.data)? {
                        result.verbose.push(v);
                    }
                }
                MessageType::DebugRecord => {
                    for v in parse_clixml(&msg.data)? {
                        result.debug.push(v);
                    }
                }
                MessageType::InformationRecord => {
                    for v in parse_clixml(&msg.data)? {
                        result.information.push(v);
                    }
                }
                MessageType::ProgressRecord => {
                    for v in parse_clixml(&msg.data)? {
                        result.progress.push(v);
                    }
                }
                MessageType::PipelineState => {
                    let state = extract_pipeline_state(&msg.data)?;
                    result.state = state;
                    if state.is_terminal() {
                        if state == PipelineState::Failed {
                            append_terminal_error(&msg.data, &mut result)?;
                            if matches!(self.failure_mode, FailureMode::ReturnError) {
                                return Err(PsrpError::PipelineFailed(describe_errors(
                                    &result.errors,
                                )));
                            }
                        }
                        if state == PipelineState::Stopped {
                            if cancel_signalled {
                                return Err(PsrpError::Cancelled);
                            }
                            return Err(PsrpError::Stopped);
                        }
                        return Ok(result);
                    }
                }
                _ => continue,
            }
        }
    }

    fn create_pipeline_xml(&self) -> String {
        use crate::clixml::encode::{
            PipelineArgSpec, PipelineCommandSpec, build_create_pipeline_xml,
        };

        let specs: Vec<PipelineCommandSpec<'_>> = self
            .commands
            .iter()
            .map(|c| PipelineCommandSpec {
                name: &c.name,
                is_script: c.is_script,
                merge_errors_to_output: c.merge_errors_to_output,
                args: c
                    .arguments
                    .iter()
                    .map(|a| match a {
                        Argument::Named { name, value } => PipelineArgSpec::Named { name, value },
                        Argument::Positional(v) => PipelineArgSpec::Positional(v),
                        Argument::Switch(name) => PipelineArgSpec::Switch(name),
                    })
                    .collect(),
            })
            .collect();

        build_create_pipeline_xml(
            self.no_input,
            self.add_to_history,
            self.add_invocation_info,
            &specs,
        )
    }

    /// Build the outer `CreatePipeline` XML that wraps the command list.
    #[doc(hidden)]
    pub fn __create_pipeline_xml_for_test(&self) -> String {
        self.create_pipeline_xml()
    }
}

/// Live handle to a running pipeline.
///
/// Created by [`Pipeline::start`]. Lets the caller stream input objects,
/// then drives the receive loop with [`PipelineHandle::collect`] or
/// [`PipelineHandle::collect_with_cancel`].
///
/// The handle borrows the pool mutably, so exactly one pipeline can be
/// alive at a time. Drop the handle without calling `collect` to abort
/// locally (the server will still process the pipeline, but the handle
/// won't drain its output).
pub struct PipelineHandle<'p, T: PsrpTransport> {
    pool: &'p mut RunspacePool<T>,
    pid: Uuid,
    rpid: Uuid,
    input_closed: bool,
    failure_mode: FailureMode,
}

impl<T: PsrpTransport> std::fmt::Debug for PipelineHandle<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipelineHandle")
            .field("pid", &self.pid)
            .field("rpid", &self.rpid)
            .field("input_closed", &self.input_closed)
            .finish()
    }
}

impl<T: PsrpTransport> PipelineHandle<'_, T> {
    /// Send one input object to the pipeline.
    ///
    /// Errors if the pipeline was configured with `no_input = true`
    /// (the default) — use [`Pipeline::with_input`] with `true` before
    /// calling `start` to enable streaming.
    pub async fn write_input(&mut self, value: PsValue) -> Result<()> {
        if self.input_closed {
            return Err(PsrpError::protocol(
                "pipeline was created with NoInput=true; cannot stream input",
            ));
        }
        let body = crate::clixml::to_clixml(&value);
        self.pool
            .send_pipeline_message(MessageType::PipelineInput, self.pid, body)
            .await
    }

    /// Close the input stream with an `EndOfPipelineInput` message.
    ///
    /// After this call, further `write_input` calls are rejected.
    pub async fn end_input(&mut self) -> Result<()> {
        if self.input_closed {
            return Ok(());
        }
        self.input_closed = true;
        self.pool
            .send_pipeline_message(MessageType::EndOfPipelineInput, self.pid, String::new())
            .await
    }

    /// Drain every server message until the pipeline reaches a terminal
    /// state and return the collected [`PipelineResult`].
    pub async fn collect(mut self) -> Result<PipelineResult> {
        self.end_input().await?;
        self.drain_loop(tokio_util::sync::CancellationToken::new())
            .await
    }

    /// Drain with cancellation support.
    pub async fn collect_with_cancel(
        mut self,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<PipelineResult> {
        self.end_input().await?;
        self.drain_loop(cancel).await
    }

    /// Ask the server to stop the pipeline. Returns immediately; call
    /// [`collect`](Self::collect) afterwards to drain the `Stopped` ACK.
    pub async fn stop(&mut self) -> Result<()> {
        self.pool.signal_transport_stop().await
    }

    /// Pipeline PID.
    #[must_use]
    pub fn pid(&self) -> Uuid {
        self.pid
    }

    async fn drain_loop(
        &mut self,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<PipelineResult> {
        let mut result = PipelineResult {
            state: PipelineState::Running,
            ..PipelineResult::default()
        };
        let mut cancel_signalled = false;
        loop {
            if !cancel_signalled && cancel.is_cancelled() {
                self.pool.signal_transport_stop().await?;
                cancel_signalled = true;
            }
            let msg = tokio::select! {
                biased;
                () = cancel.cancelled(), if !cancel_signalled => {
                    self.pool.signal_transport_stop().await?;
                    cancel_signalled = true;
                    continue;
                }
                msg = self.pool.next_message() => msg?,
            };
            if msg.pid != self.pid || msg.rpid != self.rpid {
                tracing::debug!(
                    expected_pid = %self.pid,
                    got_pid = %msg.pid,
                    expected_rpid = %self.rpid,
                    got_rpid = %msg.rpid,
                    mt = ?msg.message_type,
                    "dropping pipeline message with mismatched pid/rpid",
                );
                continue;
            }
            match msg.message_type {
                MessageType::PipelineOutput => {
                    for v in parse_clixml(&msg.data)? {
                        self.pool.host_output(&v).await;
                        result.output.push(v);
                    }
                }
                MessageType::ErrorRecord => {
                    for v in parse_clixml(&msg.data)? {
                        result.errors.push(v);
                    }
                }
                MessageType::WarningRecord => {
                    for v in parse_clixml(&msg.data)? {
                        result.warnings.push(v);
                    }
                }
                MessageType::VerboseRecord => {
                    for v in parse_clixml(&msg.data)? {
                        result.verbose.push(v);
                    }
                }
                MessageType::DebugRecord => {
                    for v in parse_clixml(&msg.data)? {
                        result.debug.push(v);
                    }
                }
                MessageType::InformationRecord => {
                    for v in parse_clixml(&msg.data)? {
                        result.information.push(v);
                    }
                }
                MessageType::ProgressRecord => {
                    for v in parse_clixml(&msg.data)? {
                        result.progress.push(v);
                    }
                }
                MessageType::PipelineState => {
                    let state = extract_pipeline_state(&msg.data)?;
                    result.state = state;
                    if state.is_terminal() {
                        if state == PipelineState::Failed {
                            append_terminal_error(&msg.data, &mut result)?;
                            if matches!(self.failure_mode, FailureMode::ReturnError) {
                                return Err(PsrpError::PipelineFailed(describe_errors(
                                    &result.errors,
                                )));
                            }
                        }
                        if state == PipelineState::Stopped {
                            if cancel_signalled {
                                return Err(PsrpError::Cancelled);
                            }
                            return Err(PsrpError::Stopped);
                        }
                        return Ok(result);
                    }
                }
                _ => continue,
            }
        }
    }
}

fn append_terminal_error(xml: &str, result: &mut PipelineResult) -> Result<()> {
    for value in parse_clixml(xml)? {
        if let PsValue::Object(object) = value
            && let Some(error) = object.get("ExceptionAsErrorRecord")
            && !matches!(error, PsValue::Null)
            && !result.errors.contains(error)
        {
            result.errors.push(error.clone());
        }
    }
    Ok(())
}

pub(crate) fn extract_pipeline_state(xml: &str) -> Result<PipelineState> {
    let parsed = parse_clixml(xml)?;
    for v in parsed {
        if let PsValue::Object(obj) = v
            && let Some(PsValue::I32(code)) = obj.get("PipelineState")
        {
            return Ok(PipelineState::from_i32(*code));
        }
    }
    Err(PsrpError::protocol("missing PipelineState property"))
}

pub(crate) fn describe_errors(errors: &[PsValue]) -> String {
    if errors.is_empty() {
        return "unknown error".into();
    }
    errors
        .iter()
        .filter_map(|v| match v {
            PsValue::String(s) => Some(s.clone()),
            PsValue::Object(o) => o
                .get("Exception")
                .and_then(PsValue::as_str)
                .or_else(|| o.get("ErrorRecord_Exception").and_then(PsValue::as_str))
                .or_else(|| o.get("Exception_Message").and_then(PsValue::as_str))
                .map(str::to_string)
                .or_else(|| Some(format!("{o:?}"))),
            other => Some(format!("{other:?}")),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clixml::to_clixml;
    use crate::fragment::encode_message;
    use crate::message::{Destination, PsrpMessage};
    use crate::runspace::RunspacePoolState;
    use crate::transport::mock::MockTransport;

    fn make_state_message<T: Into<i32> + Copy>(
        mt: MessageType,
        prop: &str,
        code: T,
        rpid: Uuid,
        pid: Uuid,
    ) -> Vec<u8> {
        let body = to_clixml(&PsValue::Object(
            PsObject::new().with(prop, PsValue::I32(code.into())),
        ));
        PsrpMessage {
            destination: Destination::Client,
            message_type: mt,
            rpid,
            pid,
            data: body,
        }
        .encode()
    }

    fn make_data_message(mt: MessageType, data: String, rpid: Uuid, pid: Uuid) -> Vec<u8> {
        PsrpMessage {
            destination: Destination::Client,
            message_type: mt,
            rpid,
            pid,
            data,
        }
        .encode()
    }

    /// Seed a MockTransport with an `Opened` state message, open a pool,
    /// then hand the handle back. The transport is cloned so the test can
    /// still queue additional incoming messages afterwards.
    async fn opened_pool_with(t: &MockTransport) -> RunspacePool<MockTransport> {
        let opened = make_state_message(
            MessageType::RunspacePoolState,
            "RunspaceState",
            RunspacePoolState::Opened as i32,
            Uuid::nil(),
            Uuid::nil(),
        );
        // Push Opened at the FRONT so open consumes it first regardless of
        // messages queued by the test before this call.
        t.inbox
            .lock()
            .unwrap()
            .push_front(encode_message(1, &opened));
        RunspacePool::open_with_transport(t.clone()).await.unwrap()
    }

    #[tokio::test]
    async fn pipeline_state_ok() {
        assert!(!PipelineState::Running.is_terminal());
        assert!(PipelineState::Completed.is_terminal());
        assert!(PipelineState::Failed.is_terminal());
        assert!(PipelineState::Stopped.is_terminal());
    }

    #[tokio::test]
    async fn empty_pipeline_errors() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with(&t).await;
        let err = Pipeline::empty().run(&mut pool).await.unwrap_err();
        assert!(matches!(err, PsrpError::Protocol(_)));
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn run_script_collects_output() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with(&t).await;
        let rpid = pool.id();
        let pid = Uuid::new_v4();
        let out1 = make_data_message(
            MessageType::PipelineOutput,
            "<I32>1</I32>".into(),
            rpid,
            pid,
        );
        let out2 = make_data_message(
            MessageType::PipelineOutput,
            "<I32>2</I32>".into(),
            rpid,
            pid,
        );
        let done = make_state_message(
            MessageType::PipelineState,
            "PipelineState",
            PipelineState::Completed as i32,
            rpid,
            pid,
        );
        t.push_incoming(encode_message(10, &out1));
        t.push_incoming(encode_message(11, &out2));
        t.push_incoming(encode_message(12, &done));
        let result = Pipeline::new("1..2")
            .__with_forced_pid_for_test(pid)
            .run(&mut pool)
            .await
            .unwrap();
        assert_eq!(result, vec![PsValue::I32(1), PsValue::I32(2)]);
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn run_all_streams_collects_every_stream() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with(&t).await;
        let rpid = pool.id();
        let pid = Uuid::new_v4();
        t.push_incoming(encode_message(
            1,
            &make_data_message(MessageType::PipelineOutput, "<S>out</S>".into(), rpid, pid),
        ));
        t.push_incoming(encode_message(
            2,
            &make_data_message(MessageType::WarningRecord, "<S>warn</S>".into(), rpid, pid),
        ));
        t.push_incoming(encode_message(
            3,
            &make_data_message(
                MessageType::VerboseRecord,
                "<S>verbose</S>".into(),
                rpid,
                pid,
            ),
        ));
        t.push_incoming(encode_message(
            4,
            &make_data_message(MessageType::DebugRecord, "<S>debug</S>".into(), rpid, pid),
        ));
        t.push_incoming(encode_message(
            5,
            &make_data_message(
                MessageType::InformationRecord,
                "<S>info</S>".into(),
                rpid,
                pid,
            ),
        ));
        t.push_incoming(encode_message(
            6,
            &make_data_message(MessageType::ProgressRecord, "<S>prog</S>".into(), rpid, pid),
        ));
        t.push_incoming(encode_message(
            7,
            &make_data_message(MessageType::ErrorRecord, "<S>err</S>".into(), rpid, pid),
        ));
        t.push_incoming(encode_message(
            8,
            &make_state_message(
                MessageType::PipelineState,
                "PipelineState",
                PipelineState::Completed as i32,
                rpid,
                pid,
            ),
        ));
        let result = Pipeline::new("whatever")
            .__with_forced_pid_for_test(pid)
            .run_all_streams(&mut pool)
            .await
            .unwrap();
        assert_eq!(result.output, vec![PsValue::String("out".into())]);
        assert_eq!(result.warnings, vec![PsValue::String("warn".into())]);
        assert_eq!(result.verbose, vec![PsValue::String("verbose".into())]);
        assert_eq!(result.debug, vec![PsValue::String("debug".into())]);
        assert_eq!(result.information, vec![PsValue::String("info".into())]);
        assert_eq!(result.progress, vec![PsValue::String("prog".into())]);
        assert_eq!(result.errors, vec![PsValue::String("err".into())]);
        assert_eq!(result.state, PipelineState::Completed);
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn retained_failure_preserves_output_and_terminal_exception() {
        for streaming in [false, true] {
            let t = MockTransport::new();
            let mut pool = opened_pool_with(&t).await;
            let rpid = pool.id();
            let pid = Uuid::new_v4();
            t.push_incoming(encode_message(
                1,
                &make_data_message(
                    MessageType::PipelineOutput,
                    "<S>before failure</S>".into(),
                    rpid,
                    pid,
                ),
            ));
            let terminal = crate::PsObject::new()
                .with("PipelineState", PsValue::I32(PipelineState::Failed as i32))
                .with(
                    "ExceptionAsErrorRecord",
                    PsValue::String("terminal failure".into()),
                );
            t.push_incoming(encode_message(
                2,
                &make_data_message(
                    MessageType::PipelineState,
                    to_clixml(&PsValue::Object(terminal)),
                    rpid,
                    pid,
                ),
            ));
            let pipeline = Pipeline::new("fail")
                .__with_forced_pid_for_test(pid)
                .retaining_failed_output();
            let result = if streaming {
                pipeline
                    .start(&mut pool)
                    .await
                    .unwrap()
                    .collect()
                    .await
                    .unwrap()
            } else {
                pipeline.run_all_streams(&mut pool).await.unwrap()
            };
            assert_eq!(result.state, PipelineState::Failed);
            assert_eq!(
                result.output,
                vec![PsValue::String("before failure".into())]
            );
            assert_eq!(
                result.errors,
                vec![PsValue::String("terminal failure".into())]
            );
            let _ = pool.close().await;
        }
    }

    #[tokio::test]
    async fn failed_pipeline_produces_error() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with(&t).await;
        let rpid = pool.id();
        let pid = Uuid::new_v4();
        t.push_incoming(encode_message(
            1,
            &make_data_message(MessageType::ErrorRecord, "<S>boom</S>".into(), rpid, pid),
        ));
        t.push_incoming(encode_message(
            2,
            &make_state_message(
                MessageType::PipelineState,
                "PipelineState",
                PipelineState::Failed as i32,
                rpid,
                pid,
            ),
        ));
        let err = Pipeline::new("fail")
            .__with_forced_pid_for_test(pid)
            .run(&mut pool)
            .await
            .unwrap_err();
        assert!(matches!(err, PsrpError::PipelineFailed(_)));
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn stopped_pipeline_produces_stopped_error() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with(&t).await;
        let rpid = pool.id();
        let pid = Uuid::new_v4();
        t.push_incoming(encode_message(
            1,
            &make_state_message(
                MessageType::PipelineState,
                "PipelineState",
                PipelineState::Stopped as i32,
                rpid,
                pid,
            ),
        ));
        let err = Pipeline::new("x")
            .__with_forced_pid_for_test(pid)
            .run(&mut pool)
            .await
            .unwrap_err();
        assert!(matches!(err, PsrpError::Stopped));
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn pipeline_drops_messages_with_wrong_pid() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with(&t).await;
        let rpid = pool.id();
        let pid = Uuid::new_v4();
        let foreign_pid = Uuid::new_v4();
        // Foreign-pid message must be dropped.
        t.push_incoming(encode_message(
            1,
            &make_data_message(
                MessageType::PipelineOutput,
                "<I32>666</I32>".into(),
                rpid,
                foreign_pid,
            ),
        ));
        // Wrong-rpid message must also be dropped.
        t.push_incoming(encode_message(
            2,
            &make_data_message(
                MessageType::PipelineOutput,
                "<I32>777</I32>".into(),
                Uuid::new_v4(),
                pid,
            ),
        ));
        // Real message for our pipeline.
        t.push_incoming(encode_message(
            3,
            &make_data_message(
                MessageType::PipelineOutput,
                "<I32>42</I32>".into(),
                rpid,
                pid,
            ),
        ));
        t.push_incoming(encode_message(
            4,
            &make_state_message(
                MessageType::PipelineState,
                "PipelineState",
                PipelineState::Completed as i32,
                rpid,
                pid,
            ),
        ));
        let result = Pipeline::new("x")
            .__with_forced_pid_for_test(pid)
            .run_all_streams(&mut pool)
            .await
            .unwrap();
        assert_eq!(result.output, vec![PsValue::I32(42)]);
        let _ = pool.close().await;
    }

    // ---------- Phase D: PipelineHandle streaming tests ----------

    #[tokio::test]
    async fn pipeline_handle_streams_input() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with(&t).await;
        let rpid = pool.id();
        let pid = Uuid::new_v4();
        t.push_incoming(encode_message(
            10,
            &make_data_message(
                MessageType::PipelineOutput,
                "<I32>99</I32>".into(),
                rpid,
                pid,
            ),
        ));
        t.push_incoming(encode_message(
            11,
            &make_state_message(
                MessageType::PipelineState,
                "PipelineState",
                PipelineState::Completed as i32,
                rpid,
                pid,
            ),
        ));
        let mut handle = Pipeline::new("$input | Measure-Object -Sum")
            .__with_forced_pid_for_test(pid)
            .with_input(true)
            .start(&mut pool)
            .await
            .unwrap();

        handle.write_input(PsValue::I32(1)).await.unwrap();
        handle.write_input(PsValue::I32(2)).await.unwrap();
        handle.write_input(PsValue::I32(3)).await.unwrap();

        let result = handle.collect().await.unwrap();
        assert_eq!(result.output, vec![PsValue::I32(99)]);
        assert_eq!(result.state, PipelineState::Completed);

        // Two outgoing frames for open + 1 CreatePipeline + 3 PipelineInput
        // + 1 EndOfPipelineInput = 7.
        assert_eq!(t.sent().len(), 7);
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn pipeline_handle_write_input_rejected_when_no_input_true() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with(&t).await;
        let rpid = pool.id();
        let pid = Uuid::new_v4();
        t.push_incoming(encode_message(
            10,
            &make_state_message(
                MessageType::PipelineState,
                "PipelineState",
                PipelineState::Completed as i32,
                rpid,
                pid,
            ),
        ));
        let mut handle = Pipeline::new("whatever")
            .__with_forced_pid_for_test(pid)
            .start(&mut pool)
            .await
            .unwrap();
        let err = handle.write_input(PsValue::I32(1)).await.unwrap_err();
        assert!(matches!(err, PsrpError::Protocol(_)));
        // Pipeline identifier is exposed.
        assert_ne!(handle.pid(), Uuid::nil());
        let _result = handle.collect().await.unwrap();
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn pipeline_handle_cancel_during_collect() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with(&t).await;
        let rpid = pool.id();
        let pid = Uuid::new_v4();
        t.push_incoming(encode_message(
            10,
            &make_state_message(
                MessageType::PipelineState,
                "PipelineState",
                PipelineState::Stopped as i32,
                rpid,
                pid,
            ),
        ));
        let handle = Pipeline::new("long-running")
            .__with_forced_pid_for_test(pid)
            .start(&mut pool)
            .await
            .unwrap();
        let token = tokio_util::sync::CancellationToken::new();
        token.cancel();
        let err = handle.collect_with_cancel(token).await.unwrap_err();
        assert!(matches!(err, PsrpError::Cancelled));
        assert!(*t.stopped.lock().unwrap());
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn pipeline_handle_explicit_stop() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with(&t).await;
        let rpid = pool.id();
        let pid = Uuid::new_v4();
        t.push_incoming(encode_message(
            10,
            &make_state_message(
                MessageType::PipelineState,
                "PipelineState",
                PipelineState::Stopped as i32,
                rpid,
                pid,
            ),
        ));
        let mut handle = Pipeline::new("whatever")
            .__with_forced_pid_for_test(pid)
            .start(&mut pool)
            .await
            .unwrap();
        handle.stop().await.unwrap();
        assert!(*t.stopped.lock().unwrap());
        let err = handle.collect().await.unwrap_err();
        assert!(matches!(err, PsrpError::Stopped));
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn pipeline_run_with_cancel_returns_cancelled() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with(&t).await;
        let rpid = pool.id();
        let pid = Uuid::new_v4();
        t.push_incoming(encode_message(
            10,
            &make_state_message(
                MessageType::PipelineState,
                "PipelineState",
                PipelineState::Stopped as i32,
                rpid,
                pid,
            ),
        ));
        let token = tokio_util::sync::CancellationToken::new();
        token.cancel();
        let err = Pipeline::new("slow")
            .__with_forced_pid_for_test(pid)
            .run_with_cancel(&mut pool, token)
            .await
            .unwrap_err();
        assert!(matches!(err, PsrpError::Cancelled));
        let _ = pool.close().await;
    }

    #[test]
    fn pipeline_handle_debug_format() {
        // Just ensure the Debug impl compiles for the public types.
        fn assert_debug<T: std::fmt::Debug>() {}
        assert_debug::<PipelineResult>();
    }

    #[test]
    fn pipeline_state_from_i32_covers_all_known() {
        for (code, expected) in [
            (0, PipelineState::NotStarted),
            (1, PipelineState::Running),
            (2, PipelineState::Stopping),
            (3, PipelineState::Stopped),
            (4, PipelineState::Completed),
            (5, PipelineState::Failed),
            (6, PipelineState::Disconnected),
            (99, PipelineState::Unknown),
        ] {
            assert_eq!(PipelineState::from_i32(code), expected);
        }
    }

    #[test]
    fn command_builder_named_positional_switch() {
        let c = Command::new("Get-Process")
            .with_parameter("Name", PsValue::String("svchost".into()))
            .with_argument(PsValue::String("explorer".into()))
            .with_switch("FileVersionInfo");
        assert!(!c.is_script);
        assert_eq!(c.arguments.len(), 3);
        match &c.arguments[0] {
            Argument::Named { name, value } => {
                assert_eq!(name, "Name");
                assert_eq!(value, &PsValue::String("svchost".into()));
            }
            _ => panic!(),
        }
        match &c.arguments[1] {
            Argument::Positional(v) => assert_eq!(v, &PsValue::String("explorer".into())),
            _ => panic!(),
        }
        match &c.arguments[2] {
            Argument::Switch(name) => assert_eq!(name, "FileVersionInfo"),
            _ => panic!(),
        }
        let s = Command::script("1+1");
        assert!(s.is_script);
    }

    #[test]
    fn command_merging_errors_to_output() {
        let c = Command::new("Invoke-Foo").merging_errors_to_output();
        assert!(c.merge_errors_to_output);
    }

    #[test]
    fn pipeline_builder() {
        let p = Pipeline::empty()
            .add_command(Command::new("Get-Process"))
            .add_command(Command::new("Select-Object").with_parameter("First", PsValue::I32(5)));
        assert_eq!(p.len(), 2);
        assert!(!p.is_empty());
        let xml = p.__create_pipeline_xml_for_test();
        assert!(xml.contains("Get-Process"));
        assert!(xml.contains("Select-Object"));
        assert!(xml.contains("First"));
    }

    #[test]
    fn pipeline_xml_emits_switch_as_true_bool() {
        let p = Pipeline::empty()
            .add_command(Command::new("Get-Process").with_switch("FileVersionInfo"));
        let xml = p.__create_pipeline_xml_for_test();
        assert!(xml.contains("<S N=\"N\">FileVersionInfo</S>"));
        assert!(xml.contains("<B N=\"V\">true</B>"));
    }

    #[test]
    fn pipeline_xml_positional_has_nil_name() {
        let p = Pipeline::empty().add_command(
            Command::new("Get-Process").with_argument(PsValue::String("svchost".into())),
        );
        let xml = p.__create_pipeline_xml_for_test();
        assert!(xml.contains("<Nil N=\"N\"/>"));
        assert!(xml.contains("<S N=\"V\">svchost</S>"));
    }

    #[test]
    fn pipeline_with_input_flips_no_input() {
        let p = Pipeline::new("whatever").with_input(true);
        assert!(!p.no_input);
        let xml = p.__create_pipeline_xml_for_test();
        assert!(xml.contains("<B N=\"NoInput\">false</B>"));
    }

    #[test]
    fn pipeline_with_history() {
        let p = Pipeline::new("whatever").with_history(true);
        assert!(p.add_to_history);
        let xml = p.__create_pipeline_xml_for_test();
        assert!(xml.contains("<B N=\"AddToHistory\">true</B>"));
    }

    #[test]
    fn describe_errors_formats_variants() {
        assert_eq!(describe_errors(&[]), "unknown error");
        let desc = describe_errors(&[PsValue::String("x".into())]);
        assert_eq!(desc, "x");
        let obj = PsObject::new().with("Exception", PsValue::String("boom".into()));
        let desc = describe_errors(&[PsValue::Object(obj)]);
        assert!(desc.contains("boom"));
    }

    #[test]
    fn pipeline_state_is_terminal() {
        assert!(PipelineState::Completed.is_terminal());
        assert!(PipelineState::Failed.is_terminal());
        assert!(PipelineState::Stopped.is_terminal());
        assert!(PipelineState::Disconnected.is_terminal());
        assert!(!PipelineState::NotStarted.is_terminal());
        assert!(!PipelineState::Running.is_terminal());
        assert!(!PipelineState::Stopping.is_terminal());
        assert!(!PipelineState::Unknown.is_terminal());
    }

    #[test]
    fn typed_errors_parses_error_records() {
        let err_obj = PsObject::new()
            .with(
                "Exception",
                PsValue::Object(PsObject::new().with("Message", PsValue::String("boom".into()))),
            )
            .with("FullyQualifiedErrorId", PsValue::String("Err1".into()));
        let r = PipelineResult {
            errors: vec![
                PsValue::Object(err_obj),
                PsValue::String("not an object".into()),
            ],
            ..Default::default()
        };
        let typed = r.typed_errors();
        assert_eq!(typed.len(), 1);
        assert_eq!(
            typed[0].exception.as_ref().unwrap().message.as_deref(),
            Some("boom")
        );
    }

    #[test]
    fn typed_warnings_parses_warning_records() {
        let warn_obj = PsObject::new().with("Message", PsValue::String("careful".into()));
        let r = PipelineResult {
            warnings: vec![PsValue::Object(warn_obj)],
            ..Default::default()
        };
        let typed = r.typed_warnings();
        assert_eq!(typed.len(), 1);
        assert_eq!(typed[0].message, "careful");
    }

    #[test]
    fn typed_information_parses() {
        let info_obj = PsObject::new()
            .with("MessageData", PsValue::String("info".into()))
            .with("Source", PsValue::String("src".into()));
        let r = PipelineResult {
            information: vec![PsValue::Object(info_obj)],
            ..Default::default()
        };
        let typed = r.typed_information();
        assert_eq!(typed.len(), 1);
    }

    #[test]
    fn typed_progress_parses() {
        let progress_obj = PsObject::new()
            .with("Activity", PsValue::String("doing".into()))
            .with("PercentComplete", PsValue::I32(50));
        let r = PipelineResult {
            progress: vec![PsValue::Object(progress_obj)],
            ..Default::default()
        };
        let typed = r.typed_progress();
        assert_eq!(typed.len(), 1);
        assert_eq!(typed[0].percent_complete, Some(50));
    }

    #[test]
    fn typed_verbose_and_debug() {
        let trace_obj = PsObject::new().with("Message", PsValue::String("trace".into()));
        let r = PipelineResult {
            verbose: vec![PsValue::Object(trace_obj.clone())],
            debug: vec![PsValue::Object(trace_obj)],
            ..Default::default()
        };
        assert_eq!(r.typed_verbose().len(), 1);
        assert_eq!(r.typed_debug().len(), 1);
    }

    #[test]
    fn pipeline_empty() {
        let p = Pipeline::empty();
        assert!(p.is_empty());
        assert_eq!(p.len(), 0);
    }

    #[test]
    fn extract_pipeline_state_errors_when_missing() {
        assert!(extract_pipeline_state("<Obj RefId=\"0\"><MS/></Obj>").is_err());
    }

    #[test]
    fn extract_pipeline_state_ok() {
        let xml = to_clixml(&PsValue::Object(
            PsObject::new().with("PipelineState", PsValue::I32(4)),
        ));
        assert_eq!(
            extract_pipeline_state(&xml).unwrap(),
            PipelineState::Completed
        );
    }
}
