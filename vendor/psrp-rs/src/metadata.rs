//! `Get-Command` metadata pipeline — a special kind of PSRP pipeline
//! that asks the server which commands are available.
//!
//! The server uses this to implement implicit remoting (`Import-PSSession`).
//! Unlike a normal `CreatePipeline`, the body is a `GetCommandMetadata`
//! message (`0x0002_100A`) that carries a list of name patterns and the
//! command types to return.

use uuid::Uuid;

use crate::clixml::{PsObject, PsValue, parse_clixml, to_clixml};
use crate::error::{PsrpError, Result};
use crate::message::MessageType;
use crate::pipeline::PipelineState;
use crate::runspace::RunspacePool;
use crate::transport::PsrpTransport;

/// Bitmask of command types to query, mirroring
/// `System.Management.Automation.CommandTypes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandType(u32);

impl CommandType {
    pub const ALIAS: Self = Self(0x0001);
    pub const FUNCTION: Self = Self(0x0002);
    pub const FILTER: Self = Self(0x0004);
    pub const CMDLET: Self = Self(0x0008);
    pub const EXTERNAL_SCRIPT: Self = Self(0x0010);
    pub const APPLICATION: Self = Self(0x0020);
    pub const SCRIPT: Self = Self(0x0040);
    pub const WORKFLOW: Self = Self(0x0080);
    pub const CONFIGURATION: Self = Self(0x0100);
    pub const ALL: Self = Self(0x01FF);

    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl std::ops::BitOr for CommandType {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitAnd for CommandType {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

/// Describe one command returned by a metadata query.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CommandMetadata {
    pub name: String,
    pub namespace: Option<String>,
    pub has_common_parameters: Option<bool>,
    pub command_type: Option<i32>,
    pub parameters: Vec<ParameterMetadata>,
}

/// One parameter of a [`CommandMetadata`] entry.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ParameterMetadata {
    pub name: String,
    pub parameter_type: Option<String>,
    pub is_mandatory: Option<bool>,
    pub position: Option<i32>,
}

impl CommandMetadata {
    pub(crate) fn from_ps_object(value: &PsValue) -> Option<Self> {
        let obj = value.properties()?;
        Some(Self {
            name: obj
                .get("Name")
                .and_then(PsValue::as_str)
                .unwrap_or_default()
                .to_string(),
            namespace: obj
                .get("Namespace")
                .and_then(PsValue::as_str)
                .map(str::to_string),
            has_common_parameters: obj.get("HasCommonParameters").and_then(PsValue::as_bool),
            command_type: obj.get("CommandType").and_then(PsValue::as_i32),
            parameters: match obj.get("Parameters") {
                Some(PsValue::List(list)) => list
                    .iter()
                    .filter_map(ParameterMetadata::from_ps_value)
                    .collect(),
                _ => Vec::new(),
            },
        })
    }
}

impl ParameterMetadata {
    pub(crate) fn from_ps_value(value: &PsValue) -> Option<Self> {
        let obj = value.properties()?;
        Some(Self {
            name: obj
                .get("Name")
                .and_then(PsValue::as_str)
                .unwrap_or_default()
                .to_string(),
            parameter_type: obj
                .get("ParameterType")
                .and_then(PsValue::as_str)
                .map(str::to_string),
            is_mandatory: obj.get("IsMandatory").and_then(PsValue::as_bool),
            position: obj.get("Position").and_then(PsValue::as_i32),
        })
    }
}

impl<T: PsrpTransport> RunspacePool<T> {
    /// Ask the server for metadata about every command matching `patterns`
    /// (wildcards accepted) whose type intersects `command_type`.
    ///
    /// Sends a `GetCommandMetadata` message, drains the resulting
    /// pipeline, and returns a decoded [`CommandMetadata`] list.
    pub async fn get_command_metadata(
        &mut self,
        patterns: &[&str],
        command_type: CommandType,
    ) -> Result<Vec<CommandMetadata>> {
        let pid = Uuid::new_v4();
        let body = build_get_command_metadata_body(patterns, command_type);
        self.send_pipeline_message(MessageType::GetCommandMetadata, pid, body)
            .await?;

        let mut out = Vec::new();
        loop {
            let msg = self.next_message().await?;
            match msg.message_type {
                MessageType::PipelineOutput => {
                    for v in parse_clixml(&msg.data)? {
                        if let Some(cm) = CommandMetadata::from_ps_object(&v) {
                            out.push(cm);
                        }
                    }
                }
                MessageType::PipelineState => {
                    if let Some(state) = state_from_xml(&msg.data) {
                        if state.is_terminal() {
                            if state == PipelineState::Failed {
                                return Err(PsrpError::PipelineFailed(
                                    "GetCommandMetadata pipeline failed".into(),
                                ));
                            }
                            return Ok(out);
                        }
                    }
                }
                _ => continue,
            }
        }
    }
}

pub(crate) fn state_from_xml(xml: &str) -> Option<PipelineState> {
    parse_clixml(xml).ok().and_then(|values| {
        values.into_iter().find_map(|v| match v {
            PsValue::Object(obj) => obj
                .get("PipelineState")
                .and_then(PsValue::as_i32)
                .map(pipeline_state_from_i32),
            _ => None,
        })
    })
}

fn pipeline_state_from_i32(v: i32) -> PipelineState {
    // Mirror pipeline::PipelineState::from_i32 without exposing it.
    match v {
        0 => PipelineState::NotStarted,
        1 => PipelineState::Running,
        2 => PipelineState::Stopping,
        3 => PipelineState::Stopped,
        4 => PipelineState::Completed,
        5 => PipelineState::Failed,
        6 => PipelineState::Disconnected,
        _ => PipelineState::Unknown,
    }
}

fn build_get_command_metadata_body(patterns: &[&str], command_type: CommandType) -> String {
    let names = PsValue::List(
        patterns
            .iter()
            .map(|p| PsValue::String((*p).to_string()))
            .collect(),
    );
    let obj = PsObject::new()
        .with("Name", names)
        .with("CommandType", PsValue::I32(command_type.bits() as i32))
        .with("Namespace", PsValue::List(Vec::new()))
        .with("ArgumentList", PsValue::List(Vec::new()));
    to_clixml(&PsValue::Object(obj))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clixml::PsObject;

    #[test]
    fn command_type_constants() {
        assert_eq!(CommandType::CMDLET.bits(), 0x0008);
        assert_eq!(CommandType::ALL.bits(), 0x01FF);
        let combo = CommandType::CMDLET | CommandType::FUNCTION;
        assert!(combo.contains(CommandType::CMDLET));
        assert!(combo.contains(CommandType::FUNCTION));
        assert!(!combo.contains(CommandType::ALIAS));
    }

    #[test]
    fn get_command_metadata_body_contains_name_and_type() {
        let body = build_get_command_metadata_body(&["Get-*", "Set-*"], CommandType::CMDLET);
        assert!(body.contains("<S>Get-*</S>"));
        assert!(body.contains("<S>Set-*</S>"));
        // CommandType::CMDLET = 0x0008 = 8
        assert!(body.contains("<I32 N=\"CommandType\">8</I32>"));
    }

    #[test]
    fn decode_command_metadata_object() {
        let obj = PsObject::new()
            .with("Name", PsValue::String("Get-Date".into()))
            .with("HasCommonParameters", PsValue::Bool(true))
            .with("CommandType", PsValue::I32(8))
            .with(
                "Parameters",
                PsValue::List(vec![PsValue::Object(
                    PsObject::new()
                        .with("Name", PsValue::String("Format".into()))
                        .with("ParameterType", PsValue::String("System.String".into()))
                        .with("IsMandatory", PsValue::Bool(false))
                        .with("Position", PsValue::I32(0)),
                )]),
            );
        let cm = CommandMetadata::from_ps_object(&PsValue::Object(obj)).unwrap();
        assert_eq!(cm.name, "Get-Date");
        assert_eq!(cm.has_common_parameters, Some(true));
        assert_eq!(cm.command_type, Some(8));
        assert_eq!(cm.parameters.len(), 1);
        assert_eq!(cm.parameters[0].name, "Format");
        assert_eq!(
            cm.parameters[0].parameter_type.as_deref(),
            Some("System.String")
        );
    }

    #[test]
    fn decode_rejects_non_object() {
        assert!(CommandMetadata::from_ps_object(&PsValue::I32(1)).is_none());
    }

    #[test]
    fn pipeline_state_shim_matches() {
        assert_eq!(pipeline_state_from_i32(0), PipelineState::NotStarted);
        assert_eq!(pipeline_state_from_i32(1), PipelineState::Running);
        assert_eq!(pipeline_state_from_i32(2), PipelineState::Stopping);
        assert_eq!(pipeline_state_from_i32(3), PipelineState::Stopped);
        assert_eq!(pipeline_state_from_i32(4), PipelineState::Completed);
        assert_eq!(pipeline_state_from_i32(5), PipelineState::Failed);
        assert_eq!(pipeline_state_from_i32(6), PipelineState::Disconnected);
        assert_eq!(pipeline_state_from_i32(99), PipelineState::Unknown);
    }

    #[test]
    fn state_from_xml_missing_is_none() {
        assert!(state_from_xml("<Obj RefId=\"0\"><MS/></Obj>").is_none());
    }

    #[test]
    fn state_from_xml_ok() {
        let xml = to_clixml(&PsValue::Object(
            PsObject::new().with("PipelineState", PsValue::I32(4)),
        ));
        assert_eq!(state_from_xml(&xml), Some(PipelineState::Completed));
    }

    // ---------- Phase D: end-to-end tests ----------

    use crate::fragment::encode_message;
    use crate::message::{Destination, PsrpMessage};
    use crate::runspace::RunspacePoolState;
    use crate::transport::mock::MockTransport;
    use uuid::Uuid;

    fn wire_msg(mt: MessageType, data: String) -> Vec<u8> {
        PsrpMessage {
            destination: Destination::Client,
            message_type: mt,
            rpid: Uuid::nil(),
            pid: Uuid::nil(),
            data,
        }
        .encode()
    }

    fn opened_state() -> Vec<u8> {
        wire_msg(
            MessageType::RunspacePoolState,
            to_clixml(&PsValue::Object(PsObject::new().with(
                "RunspaceState",
                PsValue::I32(RunspacePoolState::Opened as i32),
            ))),
        )
    }

    fn pipeline_state(state: PipelineState) -> Vec<u8> {
        wire_msg(
            MessageType::PipelineState,
            to_clixml(&PsValue::Object(
                PsObject::new().with("PipelineState", PsValue::I32(state as i32)),
            )),
        )
    }

    #[tokio::test]
    async fn get_command_metadata_returns_items() {
        let t = MockTransport::new();
        t.push_incoming(encode_message(1, &opened_state()));

        // Two cmdlets emitted as PipelineOutput.
        let cmd = |name: &str| {
            to_clixml(&PsValue::Object(
                PsObject::new()
                    .with("Name", PsValue::String(name.into()))
                    .with("CommandType", PsValue::I32(8)),
            ))
        };
        t.push_incoming(encode_message(
            10,
            &wire_msg(MessageType::PipelineOutput, cmd("Get-Date")),
        ));
        t.push_incoming(encode_message(
            11,
            &wire_msg(MessageType::PipelineOutput, cmd("Get-Process")),
        ));
        t.push_incoming(encode_message(
            12,
            &pipeline_state(PipelineState::Completed),
        ));

        let mut pool = crate::runspace::RunspacePool::open_with_transport(t.clone())
            .await
            .unwrap();
        let cmds = pool
            .get_command_metadata(&["Get-*"], CommandType::CMDLET)
            .await
            .unwrap();
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].name, "Get-Date");
        assert_eq!(cmds[1].name, "Get-Process");
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn get_command_metadata_failed_pipeline_errors() {
        let t = MockTransport::new();
        t.push_incoming(encode_message(1, &opened_state()));
        t.push_incoming(encode_message(10, &pipeline_state(PipelineState::Failed)));
        let mut pool = crate::runspace::RunspacePool::open_with_transport(t)
            .await
            .unwrap();
        let err = pool
            .get_command_metadata(&["Nothing"], CommandType::ALL)
            .await
            .unwrap_err();
        assert!(matches!(err, crate::error::PsrpError::PipelineFailed(_)));
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn get_command_metadata_empty_result() {
        let t = MockTransport::new();
        t.push_incoming(encode_message(1, &opened_state()));
        t.push_incoming(encode_message(
            10,
            &pipeline_state(PipelineState::Completed),
        ));
        let mut pool = crate::runspace::RunspacePool::open_with_transport(t)
            .await
            .unwrap();
        let cmds = pool
            .get_command_metadata(&["None-*"], CommandType::CMDLET)
            .await
            .unwrap();
        assert!(cmds.is_empty());
        let _ = pool.close().await;
    }

    #[test]
    fn command_type_bit_and() {
        let mask = CommandType::ALL & CommandType::CMDLET;
        assert_eq!(mask.bits(), CommandType::CMDLET.bits());
        let empty = CommandType::empty();
        assert_eq!(empty.bits(), 0);
    }

    #[test]
    fn command_type_bit_or() {
        let combined = CommandType::CMDLET | CommandType::FUNCTION;
        assert!(combined.contains(CommandType::CMDLET));
        assert!(combined.contains(CommandType::FUNCTION));
        assert!(!combined.contains(CommandType::ALIAS));
        // Verify OR produces the correct bits (not XOR)
        assert_eq!(
            combined.bits(),
            CommandType::CMDLET.bits() | CommandType::FUNCTION.bits()
        );
        // OR with self should be idempotent (XOR would zero it out)
        let double = CommandType::CMDLET | CommandType::CMDLET;
        assert!(double.contains(CommandType::CMDLET));
        assert_eq!(double.bits(), CommandType::CMDLET.bits());
    }
}
