//! Error type for the `psrp-rs` crate.

use thiserror::Error;

/// Errors raised by `psrp-rs` operations.
///
/// Transport-level failures from `winrm-rs` are wrapped via `From<WinrmError>`.
#[derive(Debug, Error)]
pub enum PsrpError {
    /// Transport-level error from `winrm-rs`.
    #[error(transparent)]
    Winrm(#[from] winrm_rs::WinrmError),

    /// PSRP protocol-level error (unexpected message, bad state transition, …).
    #[error("PSRP protocol: {0}")]
    Protocol(String),

    /// CLIXML parse / encode failure.
    #[error("CLIXML: {0}")]
    Clixml(String),

    /// Fragment reassembly failure (truncated header, inconsistent blob length, …).
    #[error("fragment reassembly: {0}")]
    Fragment(String),

    /// The runspace pool was in the wrong state for the requested operation.
    #[error("runspace pool not in state {expected}, got {actual}")]
    BadState {
        /// The state that was expected.
        expected: String,
        /// The state that was actually observed.
        actual: String,
    },

    /// The pipeline was stopped by the caller or by the server.
    #[error("pipeline stopped")]
    Stopped,

    /// The pipeline failed on the server side (a `PipelineState=Failed` message).
    #[error("pipeline failed: {0}")]
    PipelineFailed(String),

    /// An operation was cancelled.
    #[error("operation cancelled")]
    Cancelled,

    /// Serialized output records exceeded the caller's per-request budget.
    #[error("PSRP output exceeded {0} bytes; session closed")]
    OutputLimit(usize),
}

impl PsrpError {
    pub(crate) fn protocol(msg: impl Into<String>) -> Self {
        Self::Protocol(msg.into())
    }

    pub(crate) fn clixml(msg: impl Into<String>) -> Self {
        Self::Clixml(msg.into())
    }

    pub(crate) fn fragment(msg: impl Into<String>) -> Self {
        Self::Fragment(msg.into())
    }
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, PsrpError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_variants() {
        assert!(
            PsrpError::protocol("x")
                .to_string()
                .contains("PSRP protocol")
        );
        assert!(PsrpError::clixml("x").to_string().contains("CLIXML"));
        assert!(
            PsrpError::fragment("x")
                .to_string()
                .contains("fragment reassembly")
        );
        assert!(
            PsrpError::BadState {
                expected: "Opened".into(),
                actual: "Opening".into(),
            }
            .to_string()
            .contains("Opened")
        );
        assert_eq!(PsrpError::Stopped.to_string(), "pipeline stopped");
        assert!(
            PsrpError::PipelineFailed("boom".into())
                .to_string()
                .contains("boom")
        );
        assert_eq!(PsrpError::Cancelled.to_string(), "operation cancelled");
    }

    #[test]
    fn from_winrm_error() {
        let we = winrm_rs::WinrmError::Timeout(5);
        let pe: PsrpError = we.into();
        assert!(matches!(pe, PsrpError::Winrm(_)));
    }
}
