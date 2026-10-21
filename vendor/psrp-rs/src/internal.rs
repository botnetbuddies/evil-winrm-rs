//! Internal entry points for the `fuzz/` targets. **Not a public API.**
//!
//! Everything here is gated behind the `__internal` feature. It exists so
//! that `fuzz/fuzz_targets/*` can reach parsers and helpers that are
//! deliberately *not* part of the crate's published surface — the
//! alternative would be to widen the real API just to make it fuzzable,
//! which is worse.
//!
//! The items below are thin `pub` wrappers around `pub(crate)` functions
//! rather than `pub use` re-exports, precisely so that turning the
//! feature off leaves the real API untouched.
//!
//! Do not enable `__internal` from downstream code: any item below may
//! change signature or disappear without a SemVer bump.

use crate::clixml::PsValue;
use crate::error::Result;
use crate::pipeline::PipelineState;

/// Base64 helpers behind the CLIXML `<BA>` codec.
pub mod base64 {
    /// The CLIXML `<BA>` base64 encoder (`clixml::encode::base64_encode`).
    #[must_use]
    pub fn encode(bytes: &[u8]) -> String {
        crate::clixml::encode::base64_encode(bytes)
    }

    /// The CLIXML `<BA>` base64 decoder (`clixml::encode::base64_decode`).
    #[must_use]
    pub fn decode(s: &str) -> Option<Vec<u8>> {
        crate::clixml::encode::base64_decode(s)
    }
}

/// Small parsers that live inside larger async modules and are otherwise
/// unreachable from outside the crate.
pub mod parse {
    use super::{PipelineState, PsValue, Result};

    /// Extract a `<PipelineState>` value out of a `PipelineState` message body.
    pub fn extract_pipeline_state(xml: &str) -> Result<PipelineState> {
        crate::pipeline::extract_pipeline_state(xml)
    }

    /// Render a list of CLIXML error values into a human-readable string.
    #[must_use]
    pub fn describe_errors(errors: &[PsValue]) -> String {
        crate::pipeline::describe_errors(errors)
    }

    /// Best-effort `PipelineState` extraction used by the metadata helper.
    #[must_use]
    pub fn state_from_xml(xml: &str) -> Option<PipelineState> {
        crate::metadata::state_from_xml(xml)
    }

    /// Decode the hex-encoded body of an `EncryptedSessionKey` message.
    pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
        crate::runspace::pool::hex_decode(s)
    }

    /// Decode a `Get-Command` metadata object.
    #[must_use]
    pub fn command_metadata(value: &PsValue) -> Option<crate::metadata::CommandMetadata> {
        crate::metadata::CommandMetadata::from_ps_object(value)
    }

    /// Decode a single parameter descriptor out of a metadata object.
    #[must_use]
    pub fn parameter_metadata(value: &PsValue) -> Option<crate::metadata::ParameterMetadata> {
        crate::metadata::ParameterMetadata::from_ps_value(value)
    }
}

/// CLIXML builders that embed untrusted values into XML.
pub mod build {
    use super::PsValue;

    /// Build the CLIXML body of a successful host-call response.
    #[must_use]
    pub fn host_response_body(ci: i64, mi: i64, value: &PsValue) -> String {
        crate::runspace::pool::build_host_response_body(ci, mi, value)
    }

    /// Build the CLIXML body of a failed host-call response.
    #[must_use]
    pub fn host_response_error_body(ci: i64, mi: i64, message: &str) -> String {
        crate::runspace::pool::build_host_response_error_body(ci, mi, message)
    }
}

/// The in-memory transport, so a fuzz target can drive the real async
/// runspace pool with attacker-controlled bytes and no network.
pub mod transport {
    pub use crate::transport::mock::MockTransport;
}

/// Direct access to the runspace pool's receive loop.
pub mod pool {
    use crate::error::Result;
    use crate::message::PsrpMessage;
    use crate::runspace::RunspacePool;
    use crate::transport::PsrpTransport;

    /// Pull and decode the next PSRP message, exactly as the pool's own
    /// drivers do.
    pub async fn next_message<T: PsrpTransport>(pool: &mut RunspacePool<T>) -> Result<PsrpMessage> {
        pool.next_message().await
    }
}

/// `known_hosts` host-pattern matching (SSH transport).
#[cfg(feature = "ssh")]
pub mod ssh {
    /// OpenSSH glob matching (`*` / `?`, case-insensitive).
    #[must_use]
    pub fn glob_match(pattern: &str, target: &str) -> bool {
        crate::ssh::glob_match(pattern, target)
    }

    /// Split a `[host]:port` pattern into its parts.
    #[must_use]
    pub fn parse_pattern_host_port(pattern: &str) -> (&str, Option<u16>) {
        crate::ssh::parse_pattern_host_port(pattern)
    }

    /// Match a host/port against a `known_hosts` pattern list.
    #[must_use]
    pub fn host_matches_patterns(patterns: &[String], host: &str, port: u16) -> bool {
        crate::ssh::host_matches_patterns(patterns, host, port)
    }

    /// Match a host against a hashed (`|1|salt|hash`) `known_hosts` entry.
    #[must_use]
    pub fn host_matches_hashed(salt: &[u8], expected: &[u8; 20], host: &str) -> bool {
        crate::ssh::host_matches_hashed(salt, expected, host)
    }

    /// Length-checked constant-time byte comparison.
    #[must_use]
    pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        crate::ssh::constant_time_eq(a, b)
    }
}
