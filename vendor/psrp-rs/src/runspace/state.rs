//! Pure state machine for a runspace pool.
//!
//! This module is fully sync and does no I/O: it just maps `(state, event)`
//! to `(new state, actions)`. The async driver (`pool.rs`) owns the
//! transport and executes the actions.
//!
//! Modelling the lifecycle this way makes every transition trivially
//! exhaustible from a unit test (no `tokio::test`, no mock transport).

use uuid::Uuid;

use crate::clixml::{PsObject, PsValue, parse_clixml, to_clixml};
use crate::error::{PsrpError, Result};
use crate::message::{MessageType, PsrpMessage};

/// Minimum PSRP protocol version we advertise (`2.3` — matches Windows
/// PowerShell 5.1 and PowerShell 7+).
pub const PROTOCOL_VERSION: &str = "2.3";
pub(crate) const PS_VERSION: &str = "2.0";
pub(crate) const SERIALIZATION_VERSION: &str = "1.1.0.1";

/// Lifecycle states of a runspace pool (MS-PSRP §2.2.3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunspacePoolState {
    BeforeOpen = 0,
    Opening = 1,
    Opened = 2,
    Closed = 3,
    Closing = 4,
    Broken = 5,
    Disconnecting = 6,
    Disconnected = 7,
    Connecting = 8,
    NegotiationSent = 9,
    NegotiationSucceeded = 10,
}

impl RunspacePoolState {
    pub(crate) fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::BeforeOpen,
            1 => Self::Opening,
            2 => Self::Opened,
            3 => Self::Closed,
            4 => Self::Closing,
            5 => Self::Broken,
            6 => Self::Disconnecting,
            7 => Self::Disconnected,
            8 => Self::Connecting,
            9 => Self::NegotiationSent,
            10 => Self::NegotiationSucceeded,
            _ => Self::Broken,
        }
    }
}

/// An action that the state machine wants the async driver to perform.
///
/// Currently only `SendMessage` is used; this stays open for future
/// primitives like `SignalStop` or `CloseTransport`.
#[derive(Debug, Clone)]
pub enum Action {
    SendMessage {
        message_type: MessageType,
        body: String,
    },
}

/// Pure state machine for the runspace pool lifecycle.
///
/// The driver calls [`open`](Self::open) once to start the handshake, then
/// feeds every server-originated message through
/// [`on_message`](Self::on_message). The machine produces a list of
/// [`Action`]s to execute and transitions its internal state accordingly.
#[derive(Debug)]
pub struct RunspacePoolStateMachine {
    state: RunspacePoolState,
    rpid: Uuid,
    min_runspaces: i32,
    max_runspaces: i32,
    host_info: PsValue,
}

impl RunspacePoolStateMachine {
    /// Build a new machine. `rpid` should typically be a freshly-generated v4 UUID.
    pub fn new(rpid: Uuid, min_runspaces: i32, max_runspaces: i32) -> Result<Self> {
        if min_runspaces < 1 || max_runspaces < min_runspaces {
            return Err(PsrpError::protocol(format!(
                "invalid runspace bounds: min={min_runspaces} max={max_runspaces}"
            )));
        }
        Ok(Self {
            state: RunspacePoolState::BeforeOpen,
            rpid,
            min_runspaces,
            max_runspaces,
            host_info: crate::clixml::ps_host_info_null(),
        })
    }

    pub(crate) fn with_host_info(mut self, host_info: PsValue) -> Self {
        self.host_info = host_info;
        self
    }

    /// Current lifecycle state.
    #[must_use]
    pub fn state(&self) -> RunspacePoolState {
        self.state
    }

    /// Runspace pool identifier.
    #[must_use]
    pub fn rpid(&self) -> Uuid {
        self.rpid
    }

    /// Configured minimum runspaces.
    #[must_use]
    pub fn min_runspaces(&self) -> i32 {
        self.min_runspaces
    }

    /// Configured maximum runspaces.
    #[must_use]
    pub fn max_runspaces(&self) -> i32 {
        self.max_runspaces
    }

    /// Produce the actions required to start the opening handshake.
    ///
    /// Transitions the state from `BeforeOpen` to `NegotiationSent`.
    ///
    /// A machine that has already reached a terminal state (`Closed` or
    /// `Broken`) refuses: it returns no actions and stays where it is.
    /// The server-driven path is guarded by the crate-private
    /// `is_legal_server_transition`; this is the matching guard for the
    /// client-driven one, so a pool cannot be resurrected from either
    /// side. Every caller inside the crate drives a freshly
    /// constructed machine, so nothing legitimate hits this.
    pub fn open(&mut self) -> Vec<Action> {
        if self.is_terminal() {
            return Vec::new();
        }
        self.state = RunspacePoolState::Opening;
        let actions = vec![
            Action::SendMessage {
                message_type: MessageType::SessionCapability,
                body: session_capability_xml(),
            },
            Action::SendMessage {
                message_type: MessageType::InitRunspacePool,
                body: init_runspace_pool_xml_with_host(
                    self.min_runspaces,
                    self.max_runspaces,
                    self.host_info.clone(),
                ),
            },
        ];
        self.state = RunspacePoolState::NegotiationSent;
        actions
    }

    /// Produce the actions required to **reconnect** to a previously
    /// disconnected runspace pool.
    ///
    /// PSRP §3.1.4.1 — the client sends a `ConnectRunspacePool` (`0x0002_100B`)
    /// message and the server responds with the current pool state. We
    /// re-emit the `SessionCapability` first to renegotiate protocol
    /// versions.
    ///
    /// Like [`open`](Self::open), a terminal machine refuses.
    pub fn connect(&mut self) -> Vec<Action> {
        if self.is_terminal() {
            return Vec::new();
        }
        // Existing-client reconnect (MS-PSRP §3.1.4 / MS-WSMV Reconnect). The
        // transport already issued the WSMan `Reconnect`, and because the
        // client kept the same `wsmv:SessionId`, the server treats the
        // runspace as still Opened and replays no state. So the machine emits
        // no PSRP message and goes straight to Opened — this mirrors
        // pypsrp's `_connect_existing_client`, which sends
        // SessionCapability/ConnectRunspacePool only for a *different* client
        // (the `connectXml` path), a case this crate never hits because every
        // reconnect reuses the original transport's SessionId.
        //
        // The previous version replayed the full handshake and then waited
        // for a fresh RunspacePoolState=Opened; the server had nothing new to
        // send, so the follow-up Receive died with `w:TimedOut`.
        //
        // Only resume a genuinely resumable pool: the fresh machine
        // `DisconnectedPool::reconnect` builds (`BeforeOpen`), or a live pool
        // the server moved to `Disconnected`. From anything else — a
        // mid-handshake, closing, or terminal pool — reconnect must not
        // fabricate an `Opened` state (fuzz-guarded: a closed pool must never
        // resurrect).
        if !matches!(
            self.state,
            RunspacePoolState::BeforeOpen | RunspacePoolState::Disconnected
        ) {
            return Vec::new();
        }
        self.state = RunspacePoolState::Opened;
        Vec::new()
    }

    /// Feed a server-originated message into the machine.
    ///
    /// Returns `Ok(())` on a valid transition. Unknown message types are
    /// silently ignored. A `RunspacePoolState=Broken/Closed` received
    /// during the opening handshake is reported as a protocol error.
    /// Server-driven transitions that violate the MS-PSRP §2.2.3.4
    /// lifecycle are rejected with `PsrpError::Protocol` so a malicious
    /// or buggy server cannot push the client into an arbitrary state.
    pub fn on_message(&mut self, msg: &PsrpMessage) -> Result<()> {
        match msg.message_type {
            MessageType::RunspacePoolState => {
                let new_state = extract_runspace_state(&msg.data)?;
                if !is_legal_server_transition(self.state, new_state) {
                    return Err(PsrpError::protocol(format!(
                        "illegal RunspacePool transition {:?} -> {:?}",
                        self.state, new_state
                    )));
                }
                self.state = new_state;
                match new_state {
                    RunspacePoolState::Broken | RunspacePoolState::Closed => {
                        return Err(PsrpError::protocol(format!(
                            "runspace pool entered terminal state {new_state:?}"
                        )));
                    }
                    _ => {}
                }
            }
            // These are informational during handshake — ignored silently.
            MessageType::SessionCapability
            | MessageType::ApplicationPrivateData
            | MessageType::RunspacePoolInitData
            | MessageType::EncryptedSessionKey
            | MessageType::PublicKeyRequest => {}
            _ => {}
        }
        Ok(())
    }

    /// True once the machine has reached [`RunspacePoolState::Opened`].
    #[must_use]
    pub fn is_opened(&self) -> bool {
        self.state == RunspacePoolState::Opened
    }

    /// True once the pool is dead for good — no further handshake may be
    /// started on this machine.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            RunspacePoolState::Closed | RunspacePoolState::Broken
        )
    }

    /// Produce the actions required to close the pool.
    pub fn close(&mut self) -> Vec<Action> {
        self.state = RunspacePoolState::Closing;
        vec![Action::SendMessage {
            message_type: MessageType::CloseRunspacePool,
            body: "<Obj RefId=\"0\"><MS/></Obj>".into(),
        }]
    }

    /// Mark the machine as fully closed (after the transport has torn down).
    pub fn mark_closed(&mut self) {
        self.state = RunspacePoolState::Closed;
    }
}

/// Whether the server is allowed to drive the pool from `from` into `to`.
///
/// Mirrors MS-PSRP §2.2.3.4. The client never accepts a server-asserted
/// transition that skips negotiation steps or jumps from a closed pool
/// back to an open one — a malicious server attempting that gets a
/// protocol error rather than a silently-mutated state machine.
fn is_legal_server_transition(from: RunspacePoolState, to: RunspacePoolState) -> bool {
    use RunspacePoolState::{
        BeforeOpen, Broken, Closed, Closing, Connecting, Disconnected, Disconnecting,
        NegotiationSent, NegotiationSucceeded, Opened, Opening,
    };
    if from == to {
        return true;
    }
    // Broken is reachable from any non-terminal state — the server can
    // always inform us that the runspace died.
    if to == Broken && !matches!(from, Closed) {
        return true;
    }
    matches!(
        (from, to),
        (BeforeOpen, Opening | NegotiationSent)
            | (Opening, NegotiationSent | NegotiationSucceeded | Opened)
            | (
                NegotiationSent,
                NegotiationSucceeded | Opened | Closed | Disconnected
            )
            | (NegotiationSucceeded, Opened | Closed | Disconnected)
            | (Opened, Closing | Closed | Disconnecting | Disconnected)
            | (Closing, Closed)
            | (Disconnecting, Disconnected)
            | (Disconnected, Connecting)
            | (
                Connecting,
                NegotiationSent | NegotiationSucceeded | Opened | Disconnected
            )
    )
}

pub(crate) fn session_capability_xml() -> String {
    // PSRP §2.2.2.1: PSVersion / protocolversion / SerializationVersion
    // are typed `Version` on the wire, NOT plain strings. Some servers
    // accept the looser <S> form but the strict ones reject it.
    let obj = PsValue::Object(
        PsObject::new()
            .with("PSVersion", PsValue::Version(PS_VERSION.into()))
            .with("protocolversion", PsValue::Version(PROTOCOL_VERSION.into()))
            .with(
                "SerializationVersion",
                PsValue::Version(SERIALIZATION_VERSION.into()),
            ),
    );
    to_clixml(&obj)
}

#[cfg(test)]
pub(crate) fn init_runspace_pool_xml(min: i32, max: i32) -> String {
    init_runspace_pool_xml_with_host(min, max, crate::clixml::ps_host_info_null())
}

fn init_runspace_pool_xml_with_host(min: i32, max: i32, host_info: PsValue) -> String {
    // PSRP §2.2.2.2 — InitRunspacePool requires the following member set:
    //   MinRunspaces (I32), MaxRunspaces (I32),
    //   PSThreadOptions (enum), ApartmentState (enum),
    //   HostInfo (Obj), ApplicationArguments (DCT or Nil)
    //
    // Strict server-side deserialisers reject messages that omit any
    // of these. We emit each enum with its full .NET type hierarchy via
    // `crate::clixml::encode::ps_enum`.
    use crate::clixml::encode::ps_enum;

    let obj = PsValue::Object(
        PsObject::new()
            .with("MinRunspaces", PsValue::I32(min))
            .with("MaxRunspaces", PsValue::I32(max))
            .with(
                "PSThreadOptions",
                ps_enum(
                    "System.Management.Automation.Runspaces.PSThreadOptions",
                    "Default",
                    0,
                ),
            )
            .with(
                "ApartmentState",
                ps_enum(
                    "System.Management.Automation.Runspaces.ApartmentState",
                    "UNKNOWN",
                    2,
                ),
            )
            .with("HostInfo", host_info)
            .with("ApplicationArguments", PsValue::Null),
    );
    to_clixml(&obj)
}

pub(crate) fn extract_runspace_state(xml: &str) -> Result<RunspacePoolState> {
    let parsed = parse_clixml(xml)?;
    for value in parsed {
        if let PsValue::Object(obj) = value
            && let Some(PsValue::I32(code)) = obj.get("RunspaceState")
        {
            return Ok(RunspacePoolState::from_i32(*code));
        }
    }
    Err(PsrpError::protocol(
        "RunspacePoolState message missing RunspaceState property",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Destination;

    fn state_msg(state: RunspacePoolState) -> PsrpMessage {
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
    }

    #[test]
    fn new_rejects_bad_bounds() {
        assert!(RunspacePoolStateMachine::new(Uuid::nil(), 0, 0).is_err());
        assert!(RunspacePoolStateMachine::new(Uuid::nil(), 5, 3).is_err());
    }

    #[test]
    fn new_accepts_valid_bounds() {
        let m = RunspacePoolStateMachine::new(Uuid::nil(), 2, 5).unwrap();
        assert_eq!(m.min_runspaces(), 2);
        assert_eq!(m.max_runspaces(), 5);
        assert_eq!(m.state(), RunspacePoolState::BeforeOpen);
    }

    #[test]
    fn open_produces_two_messages_and_transitions() {
        let mut m = RunspacePoolStateMachine::new(Uuid::nil(), 1, 1).unwrap();
        let actions = m.open();
        assert_eq!(actions.len(), 2);
        match &actions[0] {
            Action::SendMessage { message_type, body } => {
                assert_eq!(*message_type, MessageType::SessionCapability);
                assert!(body.contains(PROTOCOL_VERSION));
            }
        }
        match &actions[1] {
            Action::SendMessage { message_type, body } => {
                assert_eq!(*message_type, MessageType::InitRunspacePool);
                assert!(body.contains("MinRunspaces"));
                assert!(body.contains("MaxRunspaces"));
            }
        }
        assert_eq!(m.state(), RunspacePoolState::NegotiationSent);
    }

    #[test]
    fn on_message_runspace_opened_sets_state() {
        let mut m = RunspacePoolStateMachine::new(Uuid::nil(), 1, 1).unwrap();
        m.open();
        m.on_message(&state_msg(RunspacePoolState::Opened)).unwrap();
        assert!(m.is_opened());
        assert_eq!(m.state(), RunspacePoolState::Opened);
    }

    #[test]
    fn on_message_broken_is_error() {
        let mut m = RunspacePoolStateMachine::new(Uuid::nil(), 1, 1).unwrap();
        m.open();
        let err = m
            .on_message(&state_msg(RunspacePoolState::Broken))
            .unwrap_err();
        assert!(matches!(err, PsrpError::Protocol(_)));
        assert_eq!(m.state(), RunspacePoolState::Broken);
    }

    #[test]
    fn on_message_closed_is_error() {
        let mut m = RunspacePoolStateMachine::new(Uuid::nil(), 1, 1).unwrap();
        let err = m
            .on_message(&state_msg(RunspacePoolState::Closed))
            .unwrap_err();
        assert!(matches!(err, PsrpError::Protocol(_)));
    }

    #[test]
    fn on_message_ignores_informational_types() {
        let mut m = RunspacePoolStateMachine::new(Uuid::nil(), 1, 1).unwrap();
        m.open();
        for mt in [
            MessageType::SessionCapability,
            MessageType::ApplicationPrivateData,
            MessageType::RunspacePoolInitData,
            MessageType::EncryptedSessionKey,
            MessageType::PublicKeyRequest,
            MessageType::PipelineOutput,
        ] {
            let msg = PsrpMessage {
                destination: Destination::Client,
                message_type: mt,
                rpid: Uuid::nil(),
                pid: Uuid::nil(),
                data: "<Nil/>".into(),
            };
            m.on_message(&msg).unwrap();
        }
        // Still in NegotiationSent, none of the above transition.
        assert_eq!(m.state(), RunspacePoolState::NegotiationSent);
    }

    #[test]
    fn on_message_intermediate_state_keeps_machine_alive() {
        let mut m = RunspacePoolStateMachine::new(Uuid::nil(), 1, 1).unwrap();
        m.open();
        m.on_message(&state_msg(RunspacePoolState::NegotiationSucceeded))
            .unwrap();
        assert_eq!(m.state(), RunspacePoolState::NegotiationSucceeded);
        assert!(!m.is_opened());
    }

    #[test]
    fn close_produces_action_and_mark_closed() {
        let mut m = RunspacePoolStateMachine::new(Uuid::nil(), 1, 1).unwrap();
        let actions = m.close();
        assert_eq!(actions.len(), 1);
        assert_eq!(m.state(), RunspacePoolState::Closing);
        m.mark_closed();
        assert_eq!(m.state(), RunspacePoolState::Closed);
    }

    #[test]
    fn rpid_is_preserved() {
        let id = Uuid::parse_str("11112222-3333-4444-5555-666677778888").unwrap();
        let m = RunspacePoolStateMachine::new(id, 1, 1).unwrap();
        assert_eq!(m.rpid(), id);
    }

    #[test]
    fn state_from_i32_covers_all_known() {
        for (code, expected) in [
            (0, RunspacePoolState::BeforeOpen),
            (1, RunspacePoolState::Opening),
            (2, RunspacePoolState::Opened),
            (3, RunspacePoolState::Closed),
            (4, RunspacePoolState::Closing),
            (5, RunspacePoolState::Broken),
            (6, RunspacePoolState::Disconnecting),
            (7, RunspacePoolState::Disconnected),
            (8, RunspacePoolState::Connecting),
            (9, RunspacePoolState::NegotiationSent),
            (10, RunspacePoolState::NegotiationSucceeded),
            (99, RunspacePoolState::Broken),
        ] {
            assert_eq!(RunspacePoolState::from_i32(code), expected);
        }
    }

    #[test]
    fn extract_runspace_state_missing_property() {
        assert!(extract_runspace_state("<Obj RefId=\"0\"><MS/></Obj>").is_err());
    }

    #[test]
    fn extract_runspace_state_ok() {
        let xml = to_clixml(&PsValue::Object(
            PsObject::new().with("RunspaceState", PsValue::I32(2)),
        ));
        assert_eq!(
            extract_runspace_state(&xml).unwrap(),
            RunspacePoolState::Opened
        );
    }

    #[test]
    fn session_capability_xml_has_protocol_version() {
        let xml = session_capability_xml();
        assert!(xml.contains(PROTOCOL_VERSION));
        assert!(xml.contains(SERIALIZATION_VERSION));
    }

    #[test]
    fn init_runspace_pool_xml_has_counts() {
        let xml = init_runspace_pool_xml(2, 7);
        assert!(xml.contains("<I32 N=\"MinRunspaces\">2</I32>"));
        assert!(xml.contains("<I32 N=\"MaxRunspaces\">7</I32>"));
    }

    #[test]
    fn init_runspace_pool_xml_has_full_enum_hierarchy() {
        let xml = init_runspace_pool_xml(1, 1);
        // PSThreadOptions enum with full type chain
        assert!(xml.contains("System.Management.Automation.Runspaces.PSThreadOptions"));
        assert!(xml.contains("System.Enum"));
        assert!(xml.contains("System.ValueType"));
        assert!(xml.contains("System.Object"));
        assert!(xml.contains("<ToString>Default</ToString>"));
        // ApartmentState enum value (Unknown == 2)
        assert!(xml.contains("System.Management.Automation.Runspaces.ApartmentState"));
        assert!(xml.contains("<ToString>UNKNOWN</ToString>"));
    }

    #[test]
    fn init_runspace_pool_xml_has_host_info_and_application_args() {
        let xml = init_runspace_pool_xml(1, 1);
        assert!(xml.contains("N=\"HostInfo\""));
        assert!(xml.contains("_isHostNull"));
        assert!(xml.contains("N=\"ApplicationArguments\""));
    }

    #[test]
    fn session_capability_emits_version_tags() {
        let xml = session_capability_xml();
        // Plain `<Version>` rather than `<S>`.
        assert!(xml.contains("<Version N=\"PSVersion\">"));
        assert!(xml.contains("<Version N=\"protocolversion\">"));
        assert!(xml.contains("<Version N=\"SerializationVersion\">"));
        assert!(!xml.contains("<S N=\"PSVersion\">"));
    }

    #[test]
    fn rejects_server_skipping_negotiation_to_opened() {
        // Fresh machine, no `open()` call: state is BeforeOpen. Server
        // pushing Opened directly should be rejected, not silently
        // accepted as it was previously.
        let mut m = RunspacePoolStateMachine::new(Uuid::nil(), 1, 1).unwrap();
        let err = m
            .on_message(&state_msg(RunspacePoolState::Opened))
            .unwrap_err();
        assert!(matches!(err, PsrpError::Protocol(_)));
        assert_eq!(m.state(), RunspacePoolState::BeforeOpen);
    }

    #[test]
    fn connect_resumes_existing_client_straight_to_opened() {
        // Existing-client reconnect: the WSMan Reconnect already resumed the
        // shell at the transport layer, so the machine emits no PSRP message
        // and is immediately Opened. Replaying the handshake made the server
        // time out (w:TimedOut) because it had nothing new to send.
        let mut m = RunspacePoolStateMachine::new(Uuid::nil(), 1, 1).unwrap();
        assert!(
            m.connect().is_empty(),
            "existing-client reconnect sends nothing"
        );
        assert!(m.is_opened(), "pool must be Opened right after reconnect");
    }

    /// Regression (found by the `runspace_state_machine` fuzz target):
    /// `open` used to overwrite the state unconditionally, so a client
    /// could re-drive a closed machine back to `Opened` — the exact
    /// resurrection `is_legal_server_transition` refuses on the server
    /// side.
    #[test]
    fn rejects_client_reopening_a_terminal_pool() {
        for terminal in [RunspacePoolState::Closed, RunspacePoolState::Broken] {
            let mut m = RunspacePoolStateMachine::new(Uuid::nil(), 1, 1).unwrap();
            let _ = m.open();
            m.state = terminal;

            assert!(m.is_terminal());
            assert!(m.open().is_empty(), "open() acted on a {terminal:?} pool");
            assert_eq!(m.state(), terminal, "open() moved a {terminal:?} pool");
            assert!(
                m.connect().is_empty(),
                "connect() acted on a {terminal:?} pool"
            );
            assert_eq!(m.state(), terminal, "connect() moved a {terminal:?} pool");
            assert!(!m.is_opened());
        }
    }

    #[test]
    fn rejects_server_resurrecting_closed_pool() {
        let mut m = RunspacePoolStateMachine::new(Uuid::nil(), 1, 1).unwrap();
        m.mark_closed();
        let err = m
            .on_message(&state_msg(RunspacePoolState::Opened))
            .unwrap_err();
        assert!(matches!(err, PsrpError::Protocol(_)));
        assert_eq!(m.state(), RunspacePoolState::Closed);
    }

    #[test]
    fn rejects_server_jumping_opened_to_negotiation() {
        let mut m = RunspacePoolStateMachine::new(Uuid::nil(), 1, 1).unwrap();
        m.open();
        m.on_message(&state_msg(RunspacePoolState::Opened)).unwrap();
        let err = m
            .on_message(&state_msg(RunspacePoolState::NegotiationSent))
            .unwrap_err();
        assert!(matches!(err, PsrpError::Protocol(_)));
        assert_eq!(m.state(), RunspacePoolState::Opened);
    }

    #[test]
    fn legal_negotiation_then_opened_path() {
        let mut m = RunspacePoolStateMachine::new(Uuid::nil(), 1, 1).unwrap();
        m.open();
        m.on_message(&state_msg(RunspacePoolState::NegotiationSucceeded))
            .unwrap();
        m.on_message(&state_msg(RunspacePoolState::Opened)).unwrap();
        assert!(m.is_opened());
    }

    #[test]
    fn broken_always_reachable_from_non_closed() {
        for from in [
            RunspacePoolState::BeforeOpen,
            RunspacePoolState::NegotiationSent,
            RunspacePoolState::NegotiationSucceeded,
            RunspacePoolState::Opened,
            RunspacePoolState::Disconnected,
            RunspacePoolState::Connecting,
        ] {
            assert!(
                is_legal_server_transition(from, RunspacePoolState::Broken),
                "broken should be reachable from {from:?}"
            );
        }
        assert!(!is_legal_server_transition(
            RunspacePoolState::Closed,
            RunspacePoolState::Broken
        ));
    }
}
