//! PSRP message layer (MS-PSRP §2.2.1, §2.2.2).
//!
//! A PSRP *message* is the payload carried by one or more fragments. The
//! first 40 bytes are a fixed header:
//!
//! ```text
//!  0       4       8                                  24                                 40
//! +-------+-------+----------------------------------+----------------------------------+
//! | Dest. | MType |            RPID (Guid)           |             PID (Guid)           |
//! +-------+-------+----------------------------------+----------------------------------+
//!   u32LE   u32LE   16 bytes (Microsoft mixed-endian)  16 bytes (Microsoft mixed-endian)
//! ```
//!
//! Followed by the CLIXML body (UTF-8, optionally prefixed with a BOM — we
//! accept both on decode and never emit a BOM on encode).

use uuid::Uuid;

use crate::error::{PsrpError, Result};

/// Length of the PSRP message header in bytes.
pub const HEADER_LEN: usize = 40;

/// Fixed UTF-8 BOM that Windows PowerShell sometimes emits before CLIXML.
const BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

/// Destination of a PSRP message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Destination {
    /// Message is going to the client (server-originated).
    Client = 1,
    /// Message is going to the server (client-originated).
    Server = 2,
}

impl Destination {
    fn from_u32(v: u32) -> Result<Self> {
        match v {
            1 => Ok(Self::Client),
            2 => Ok(Self::Server),
            other => Err(PsrpError::protocol(format!("unknown destination {other}"))),
        }
    }
}

/// MS-PSRP message type codes (§2.2.2.1).
///
/// Only the types needed for the P0/P1 scope are enumerated. Unknown codes
/// decode to [`MessageType::Unknown`] so callers can still inspect the raw
/// value for diagnostic purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    SessionCapability,
    InitRunspacePool,
    PublicKey,
    EncryptedSessionKey,
    PublicKeyRequest,
    SetMaxRunspaces,
    SetMinRunspaces,
    RunspaceAvailability,
    RunspacePoolState,
    CreatePipeline,
    GetAvailableRunspaces,
    UserEvent,
    ApplicationPrivateData,
    GetCommandMetadata,
    RunspacePoolHostCall,
    RunspacePoolHostResponse,
    PipelineInput,
    EndOfPipelineInput,
    PipelineOutput,
    ErrorRecord,
    PipelineState,
    DebugRecord,
    VerboseRecord,
    WarningRecord,
    ProgressRecord,
    InformationRecord,
    PipelineHostCall,
    PipelineHostResponse,
    ConnectRunspacePool,
    RunspacePoolInitData,
    ResetRunspaceState,
    CloseRunspacePool,
    Unknown(u32),
}

impl MessageType {
    /// Numeric wire code.
    #[must_use]
    pub fn to_u32(self) -> u32 {
        match self {
            Self::SessionCapability => 0x0001_0002,
            Self::InitRunspacePool => 0x0001_0004,
            Self::PublicKey => 0x0001_0005,
            Self::EncryptedSessionKey => 0x0001_0006,
            Self::PublicKeyRequest => 0x0001_0007,
            Self::ConnectRunspacePool => 0x0002_100B,
            Self::SetMaxRunspaces => 0x0002_1002,
            Self::SetMinRunspaces => 0x0002_1003,
            Self::RunspaceAvailability => 0x0002_1004,
            Self::RunspacePoolState => 0x0002_1005,
            Self::CreatePipeline => 0x0002_1006,
            Self::GetAvailableRunspaces => 0x0002_1007,
            Self::UserEvent => 0x0002_1008,
            Self::ApplicationPrivateData => 0x0002_1009,
            Self::GetCommandMetadata => 0x0002_100A,
            Self::RunspacePoolInitData => 0x0002_100C,
            Self::ResetRunspaceState => 0x0002_100D,
            Self::RunspacePoolHostCall => 0x0002_1100,
            Self::RunspacePoolHostResponse => 0x0002_1101,
            Self::PipelineInput => 0x0004_1002,
            Self::EndOfPipelineInput => 0x0004_1003,
            Self::PipelineOutput => 0x0004_1004,
            Self::ErrorRecord => 0x0004_1005,
            Self::PipelineState => 0x0004_1006,
            Self::DebugRecord => 0x0004_1007,
            Self::VerboseRecord => 0x0004_1008,
            Self::WarningRecord => 0x0004_1009,
            Self::ProgressRecord => 0x0004_1010,
            Self::InformationRecord => 0x0004_1011,
            Self::PipelineHostCall => 0x0004_1100,
            Self::PipelineHostResponse => 0x0004_1101,
            Self::CloseRunspacePool => 0x0002_100E,
            Self::Unknown(v) => v,
        }
    }

    /// Decode from a wire code.
    #[must_use]
    pub fn from_u32(v: u32) -> Self {
        match v {
            0x0001_0002 => Self::SessionCapability,
            0x0001_0004 => Self::InitRunspacePool,
            0x0001_0005 => Self::PublicKey,
            0x0001_0006 => Self::EncryptedSessionKey,
            0x0001_0007 => Self::PublicKeyRequest,
            0x0002_1002 => Self::SetMaxRunspaces,
            0x0002_1003 => Self::SetMinRunspaces,
            0x0002_1004 => Self::RunspaceAvailability,
            0x0002_1005 => Self::RunspacePoolState,
            0x0002_1006 => Self::CreatePipeline,
            0x0002_1007 => Self::GetAvailableRunspaces,
            0x0002_1008 => Self::UserEvent,
            0x0002_1009 => Self::ApplicationPrivateData,
            0x0002_100A => Self::GetCommandMetadata,
            0x0002_100B => Self::ConnectRunspacePool,
            0x0002_100C => Self::RunspacePoolInitData,
            0x0002_100D => Self::ResetRunspaceState,
            0x0002_100E => Self::CloseRunspacePool,
            0x0002_1100 => Self::RunspacePoolHostCall,
            0x0002_1101 => Self::RunspacePoolHostResponse,
            0x0004_1002 => Self::PipelineInput,
            0x0004_1003 => Self::EndOfPipelineInput,
            0x0004_1004 => Self::PipelineOutput,
            0x0004_1005 => Self::ErrorRecord,
            0x0004_1006 => Self::PipelineState,
            0x0004_1007 => Self::DebugRecord,
            0x0004_1008 => Self::VerboseRecord,
            0x0004_1009 => Self::WarningRecord,
            0x0004_1010 => Self::ProgressRecord,
            0x0004_1011 => Self::InformationRecord,
            0x0004_1100 => Self::PipelineHostCall,
            0x0004_1101 => Self::PipelineHostResponse,
            other => Self::Unknown(other),
        }
    }
}

/// A decoded PSRP message: header + UTF-8 CLIXML body.
#[derive(Debug, Clone)]
pub struct PsrpMessage {
    pub destination: Destination,
    pub message_type: MessageType,
    pub rpid: Uuid,
    pub pid: Uuid,
    pub data: String,
}

impl PsrpMessage {
    /// Build a message destined for the server.
    pub fn to_server(message_type: MessageType, rpid: Uuid, pid: Uuid, data: String) -> Self {
        Self {
            destination: Destination::Server,
            message_type,
            rpid,
            pid,
            data,
        }
    }

    /// Serialize to the wire format (header + body, no BOM).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let body = self.data.as_bytes();
        let mut out = Vec::with_capacity(HEADER_LEN + body.len());
        out.extend_from_slice(&(self.destination as u32).to_le_bytes());
        out.extend_from_slice(&self.message_type.to_u32().to_le_bytes());
        out.extend_from_slice(&self.rpid.to_bytes_le());
        out.extend_from_slice(&self.pid.to_bytes_le());
        out.extend_from_slice(body);
        out
    }

    /// Parse a message from the wire format.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(PsrpError::protocol(format!(
                "message too short: {} bytes",
                bytes.len()
            )));
        }
        let dest = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let mt = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let rpid_bytes: [u8; 16] = bytes[8..24].try_into().unwrap();
        let pid_bytes: [u8; 16] = bytes[24..40].try_into().unwrap();
        let destination = Destination::from_u32(dest)?;
        let message_type = MessageType::from_u32(mt);
        let rpid = Uuid::from_bytes_le(rpid_bytes);
        let pid = Uuid::from_bytes_le(pid_bytes);

        let mut body = &bytes[HEADER_LEN..];
        if body.starts_with(BOM) {
            body = &body[BOM.len()..];
        }
        let data = String::from_utf8(body.to_vec())
            .map_err(|e| PsrpError::protocol(format!("invalid UTF-8 in message body: {e}")))?;

        Ok(Self {
            destination,
            message_type,
            rpid,
            pid,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zero_uuid() -> Uuid {
        Uuid::nil()
    }

    #[test]
    fn roundtrip_server_message() {
        let rpid = Uuid::parse_str("11112222-3333-4444-5555-666677778888").unwrap();
        let pid = Uuid::parse_str("aaaabbbb-cccc-dddd-eeee-ffff00001111").unwrap();
        let msg =
            PsrpMessage::to_server(MessageType::SessionCapability, rpid, pid, "<Obj/>".into());
        let bytes = msg.encode();
        assert_eq!(bytes.len(), HEADER_LEN + 6);
        let decoded = PsrpMessage::decode(&bytes).unwrap();
        assert_eq!(decoded.destination, Destination::Server);
        assert_eq!(decoded.message_type, MessageType::SessionCapability);
        assert_eq!(decoded.rpid, rpid);
        assert_eq!(decoded.pid, pid);
        assert_eq!(decoded.data, "<Obj/>");
    }

    #[test]
    fn decode_accepts_utf8_bom() {
        let msg = PsrpMessage {
            destination: Destination::Client,
            message_type: MessageType::PipelineOutput,
            rpid: zero_uuid(),
            pid: zero_uuid(),
            data: String::new(),
        };
        let mut bytes = msg.encode();
        // Insert BOM right after header
        bytes.extend_from_slice(b"<X/>");
        bytes.splice(HEADER_LEN..HEADER_LEN, BOM.iter().copied());
        let decoded = PsrpMessage::decode(&bytes).unwrap();
        assert_eq!(decoded.data, "<X/>");
    }

    #[test]
    fn decode_short_header_errors() {
        let err = PsrpMessage::decode(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, PsrpError::Protocol(_)));
    }

    #[test]
    fn decode_exactly_header_len_ok() {
        // `bytes.len() == HEADER_LEN` is the boundary: it must succeed
        // (empty body). Kills the `< → <=` mutant on the length check.
        let bytes = vec![0u8; HEADER_LEN];
        // destination=0 is invalid so we set it to 1 (Client)
        let mut bytes = bytes;
        bytes[0] = 1;
        let msg = PsrpMessage::decode(&bytes).unwrap();
        assert_eq!(msg.data, "");
    }

    #[test]
    fn decode_bad_destination_errors() {
        let mut bytes = vec![0u8; HEADER_LEN];
        bytes[0] = 9; // invalid destination
        let err = PsrpMessage::decode(&bytes).unwrap_err();
        assert!(matches!(err, PsrpError::Protocol(_)));
    }

    #[test]
    fn decode_bad_utf8_errors() {
        let mut msg = PsrpMessage {
            destination: Destination::Server,
            message_type: MessageType::SessionCapability,
            rpid: zero_uuid(),
            pid: zero_uuid(),
            data: String::new(),
        }
        .encode();
        msg.extend_from_slice(&[0xFF, 0xFE, 0xFD]);
        let err = PsrpMessage::decode(&msg).unwrap_err();
        assert!(matches!(err, PsrpError::Protocol(_)));
    }

    #[test]
    fn message_type_roundtrip_all_known_variants() {
        let all = [
            MessageType::SessionCapability,
            MessageType::InitRunspacePool,
            MessageType::PublicKey,
            MessageType::EncryptedSessionKey,
            MessageType::PublicKeyRequest,
            MessageType::SetMaxRunspaces,
            MessageType::SetMinRunspaces,
            MessageType::RunspaceAvailability,
            MessageType::RunspacePoolState,
            MessageType::CreatePipeline,
            MessageType::GetAvailableRunspaces,
            MessageType::UserEvent,
            MessageType::ApplicationPrivateData,
            MessageType::GetCommandMetadata,
            MessageType::ConnectRunspacePool,
            MessageType::RunspacePoolInitData,
            MessageType::ResetRunspaceState,
            MessageType::CloseRunspacePool,
            MessageType::RunspacePoolHostCall,
            MessageType::RunspacePoolHostResponse,
            MessageType::PipelineInput,
            MessageType::EndOfPipelineInput,
            MessageType::PipelineOutput,
            MessageType::ErrorRecord,
            MessageType::PipelineState,
            MessageType::DebugRecord,
            MessageType::VerboseRecord,
            MessageType::WarningRecord,
            MessageType::ProgressRecord,
            MessageType::InformationRecord,
            MessageType::PipelineHostCall,
            MessageType::PipelineHostResponse,
        ];
        for mt in all {
            assert_eq!(MessageType::from_u32(mt.to_u32()), mt, "{mt:?}");
        }
    }

    #[test]
    fn unknown_message_type_preserved() {
        let mt = MessageType::from_u32(0xDEAD_BEEF);
        assert_eq!(mt, MessageType::Unknown(0xDEAD_BEEF));
        assert_eq!(mt.to_u32(), 0xDEAD_BEEF);
    }
}
