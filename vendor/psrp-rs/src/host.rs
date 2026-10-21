//! PowerShell host interface — handles server → client callbacks.
//!
//! When a remote script calls `Read-Host`, `Write-Host`,
//! `$Host.UI.PromptForChoice`, or any other API that needs to interact
//! with the caller, the server emits a `RunspacePoolHostCall` or
//! `PipelineHostCall` PSRP message. The client is expected to reply with
//! a matching `*HostResponse` message carrying the result (or an error).
//!
//! The [`PsHost`] trait is the contract. Implement it to customise the
//! host behaviour. The default [`NoInteractionHost`] rejects every
//! interactive call with an error — good enough for non-interactive
//! automation and never hangs.

use async_trait::async_trait;

use crate::clixml::PsValue;
use crate::error::{PsrpError, Result};

/// Reason passed to [`PsHost::rejection_for`] when the default host
/// rejects an interactive call. Callers can match on it to produce
/// user-friendly diagnostics.
#[derive(Debug, Clone)]
pub enum HostCallKind {
    /// `Read-Host`, `ReadLine`, …
    ReadInput,
    /// `Read-Host -AsSecureString`.
    ReadSecureInput,
    /// `$Host.UI.PromptForChoice`.
    PromptForChoice,
    /// `$Host.UI.Prompt`.
    Prompt,
    /// `Get-Credential`.
    GetCredential,
    /// Unknown / unhandled host method id.
    Other(i64),
}

/// PowerShell host interface.
///
/// All methods default to [`HostCallKind`]-aware errors via
/// `rejection_for`, so implementers only override the ones they care
/// about. Every method is `async` so concrete hosts can do I/O.
#[async_trait]
pub trait PsHost: Send + Sync {
    /// Capabilities advertised when opening the runspace pool.
    fn host_info(&self) -> PsValue {
        crate::clixml::ps_host_info_null()
    }
    /// Observe output in wire order relative to host callbacks.
    async fn pipeline_output(&self, _value: &PsValue) {}
    /// Handle a RawUI operation (MS-PSRP host methods 27 through 51).
    async fn raw_ui(&self, method: i64, _parameters: &[PsValue]) -> Result<Option<PsValue>> {
        Err(self.rejection_for(HostCallKind::Other(method)))
    }
    /// Observe a remote `exit <code>` request (MS-PSRP host method 6).
    async fn set_should_exit(&self, _exit_code: i32) -> Result<()> {
        Err(self.rejection_for(HostCallKind::Other(6)))
    }
    /// Write a line to the host's stdout equivalent.
    async fn write_line(&self, _text: &str) {}
    /// Write without a trailing newline.
    async fn write(&self, _text: &str) {}
    /// Write to the error stream.
    async fn write_error_line(&self, _text: &str) {}
    /// Write a warning.
    async fn write_warning_line(&self, _text: &str) {}
    /// Write a verbose line.
    async fn write_verbose_line(&self, _text: &str) {}
    /// Write a debug line.
    async fn write_debug_line(&self, _text: &str) {}
    /// Update a progress record.
    async fn write_progress(&self, _source_id: i64, _record: PsValue) {}

    /// Read a line from the host's stdin equivalent.
    async fn read_line(&self) -> Result<String> {
        Err(self.rejection_for(HostCallKind::ReadInput))
    }
    /// Read a secure string from the host.
    async fn read_line_as_secure_string(&self) -> Result<String> {
        Err(self.rejection_for(HostCallKind::ReadSecureInput))
    }
    /// Prompt the user to choose among labelled choices.
    async fn prompt_for_choice(
        &self,
        _caption: &str,
        _message: &str,
        _choices: &[(String, String)],
        _default: i32,
    ) -> Result<i32> {
        Err(self.rejection_for(HostCallKind::PromptForChoice))
    }
    /// Generic prompt.
    async fn prompt(
        &self,
        _caption: &str,
        _message: &str,
        _fields: &[String],
    ) -> Result<Vec<PsValue>> {
        Err(self.rejection_for(HostCallKind::Prompt))
    }
    /// `Get-Credential`.
    async fn get_credential(
        &self,
        _caption: &str,
        _message: &str,
        _user: &str,
    ) -> Result<(String, String)> {
        Err(self.rejection_for(HostCallKind::GetCredential))
    }

    /// Build the error returned for a rejected host call.
    fn rejection_for(&self, kind: HostCallKind) -> PsrpError {
        PsrpError::protocol(format!(
            "this host does not support {kind:?} — implement PsHost to handle it"
        ))
    }
}

/// A host that rejects every interactive call with an error and silently
/// drops every write. Suitable for non-interactive pipelines; avoids
/// hangs on `Read-Host`-style prompts.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoInteractionHost;

#[async_trait]
impl PsHost for NoInteractionHost {}

/// A host that captures every write into shared buffers and rejects
/// every interactive read. Useful in tests.
#[derive(Debug, Clone, Default)]
pub struct BufferedHost {
    inner: std::sync::Arc<std::sync::Mutex<BufferedHostInner>>,
}

#[derive(Debug, Default)]
struct BufferedHostInner {
    pub lines: Vec<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub verbose: Vec<String>,
    pub debug: Vec<String>,
}

impl BufferedHost {
    /// Create an empty buffered host.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of everything written to the "write line" stream.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        self.inner.lock().unwrap().lines.clone()
    }

    /// Snapshot of warnings.
    #[must_use]
    pub fn warnings(&self) -> Vec<String> {
        self.inner.lock().unwrap().warnings.clone()
    }

    /// Snapshot of errors.
    #[must_use]
    pub fn errors(&self) -> Vec<String> {
        self.inner.lock().unwrap().errors.clone()
    }
}

#[async_trait]
impl PsHost for BufferedHost {
    async fn write_line(&self, text: &str) {
        self.inner.lock().unwrap().lines.push(text.to_string());
    }
    async fn write(&self, text: &str) {
        self.inner.lock().unwrap().lines.push(text.to_string());
    }
    async fn write_error_line(&self, text: &str) {
        self.inner.lock().unwrap().errors.push(text.to_string());
    }
    async fn write_warning_line(&self, text: &str) {
        self.inner.lock().unwrap().warnings.push(text.to_string());
    }
    async fn write_verbose_line(&self, text: &str) {
        self.inner.lock().unwrap().verbose.push(text.to_string());
    }
    async fn write_debug_line(&self, text: &str) {
        self.inner.lock().unwrap().debug.push(text.to_string());
    }
}

/// MS-PSRP §2.2.6 — host method identifiers we care about.
///
/// Only a subset is enumerated; unknown ids decode to
/// [`HostMethodId::Other`] and are rejected by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostMethodId {
    Write1,
    Write2,
    WriteLine1,
    WriteLine2,
    WriteLine3,
    WriteErrorLine,
    WriteWarningLine,
    WriteVerboseLine,
    WriteDebugLine,
    WriteProgress,
    ReadLine,
    ReadLineAsSecureString,
    PromptForChoice,
    Prompt,
    PromptForCredential,
    Other(i64),
}

impl HostMethodId {
    /// Decode a host method id from the PSRP wire value.
    #[must_use]
    pub fn from_i64(v: i64) -> Self {
        match v {
            11 => Self::ReadLine,
            12 => Self::ReadLineAsSecureString,
            13 => Self::Write1,
            14 => Self::Write2,
            15 => Self::WriteLine1,
            16 => Self::WriteLine2,
            17 => Self::WriteLine3,
            18 => Self::WriteErrorLine,
            19 => Self::WriteDebugLine,
            20 => Self::WriteProgress,
            21 => Self::WriteVerboseLine,
            22 => Self::WriteWarningLine,
            23 => Self::Prompt,
            24 | 25 => Self::PromptForCredential,
            26 => Self::PromptForChoice,
            other => Self::Other(other),
        }
    }

    /// Encode back to the wire value.
    #[must_use]
    pub fn to_i64(self) -> i64 {
        match self {
            Self::ReadLine => 11,
            Self::ReadLineAsSecureString => 12,
            Self::Write1 => 13,
            Self::Write2 => 14,
            Self::WriteLine1 => 15,
            Self::WriteLine2 => 16,
            Self::WriteLine3 => 17,
            Self::WriteErrorLine => 18,
            Self::WriteDebugLine => 19,
            Self::WriteProgress => 20,
            Self::WriteVerboseLine => 21,
            Self::WriteWarningLine => 22,
            Self::Prompt => 23,
            Self::PromptForCredential => 24,
            Self::PromptForChoice => 26,
            Self::Other(v) => v,
        }
    }

    /// High-level category — what kind of host call is this?
    #[must_use]
    pub fn kind(self) -> HostCallKind {
        match self {
            Self::ReadLine => HostCallKind::ReadInput,
            Self::ReadLineAsSecureString => HostCallKind::ReadSecureInput,
            Self::PromptForChoice => HostCallKind::PromptForChoice,
            Self::Prompt => HostCallKind::Prompt,
            Self::PromptForCredential => HostCallKind::GetCredential,
            Self::Other(v) => HostCallKind::Other(v),
            _ => HostCallKind::Other(self.to_i64()),
        }
    }

    /// True for write-only host methods (fire-and-forget, no response
    /// required by the protocol).
    #[must_use]
    pub fn is_void(self) -> bool {
        matches!(
            self,
            Self::Write1
                | Self::Write2
                | Self::WriteLine1
                | Self::WriteLine2
                | Self::WriteLine3
                | Self::WriteErrorLine
                | Self::WriteWarningLine
                | Self::WriteVerboseLine
                | Self::WriteDebugLine
                | Self::WriteProgress
                | Self::Other(6 | 28 | 30 | 32 | 34 | 36 | 38 | 40 | 42 | 47 | 48 | 49 | 51)
        )
    }
}

/// Dispatch a host method call to a [`PsHost`] implementation.
///
/// `mi` is the method id extracted from the PSRP `*HostCall` message,
/// `mp` is the ordered argument list. The function returns an `Option<PsValue>`:
/// `None` for void methods (no response expected), `Some` for methods
/// that require a `*HostResponse` carrying the return value.
pub async fn dispatch_host_call(
    host: &dyn PsHost,
    mi: HostMethodId,
    mp: &[PsValue],
) -> Result<Option<PsValue>> {
    if mi == HostMethodId::Other(6) {
        let code = mp
            .first()
            .and_then(PsValue::as_i32)
            .ok_or_else(|| PsrpError::protocol("SetShouldExit requires an Int32 exit code"))?;
        host.set_should_exit(code).await?;
        return Ok(None);
    }
    if let HostMethodId::Other(method @ 27..=51) = mi {
        return host.raw_ui(method, mp).await;
    }
    // Void methods: fire-and-forget.
    if mi.is_void() {
        let text = mp
            .iter()
            .filter_map(PsValue::as_str)
            .collect::<Vec<_>>()
            .join(" ");
        match mi {
            HostMethodId::Write1 | HostMethodId::Write2 => host.write(&text).await,
            HostMethodId::WriteLine1 | HostMethodId::WriteLine2 | HostMethodId::WriteLine3 => {
                host.write_line(&text).await;
            }
            HostMethodId::WriteErrorLine => host.write_error_line(&text).await,
            HostMethodId::WriteWarningLine => host.write_warning_line(&text).await,
            HostMethodId::WriteVerboseLine => host.write_verbose_line(&text).await,
            HostMethodId::WriteDebugLine => host.write_debug_line(&text).await,
            HostMethodId::WriteProgress => {
                let source_id = mp.first().and_then(PsValue::as_i64).unwrap_or(0);
                let record = mp.get(1).cloned().unwrap_or(PsValue::Null);
                host.write_progress(source_id, record).await;
            }
            _ => {}
        }
        return Ok(None);
    }

    // Interactive methods: return a value (or an error) wrapped in Some.
    match mi {
        HostMethodId::ReadLine => Ok(Some(PsValue::String(host.read_line().await?))),
        HostMethodId::ReadLineAsSecureString => Ok(Some(PsValue::SecureString(
            host.read_line_as_secure_string().await?,
        ))),
        HostMethodId::PromptForChoice => {
            let caption = mp.first().and_then(PsValue::as_str).unwrap_or_default();
            let message = mp.get(1).and_then(PsValue::as_str).unwrap_or_default();
            let choices: Vec<(String, String)> = match mp.get(2) {
                Some(PsValue::List(list)) => list
                    .iter()
                    .filter_map(|v| {
                        v.properties().map(|p| {
                            (
                                p.get("Label")
                                    .and_then(PsValue::as_str)
                                    .unwrap_or("")
                                    .to_string(),
                                p.get("HelpMessage")
                                    .and_then(PsValue::as_str)
                                    .unwrap_or("")
                                    .to_string(),
                            )
                        })
                    })
                    .collect(),
                _ => Vec::new(),
            };
            let default = mp.get(3).and_then(PsValue::as_i32).unwrap_or(0);
            let choice = host
                .prompt_for_choice(caption, message, &choices, default)
                .await?;
            Ok(Some(PsValue::I32(choice)))
        }
        HostMethodId::Prompt => {
            let caption = mp.first().and_then(PsValue::as_str).unwrap_or_default();
            let message = mp.get(1).and_then(PsValue::as_str).unwrap_or_default();
            // The `fields` argument in PSRP is a list of FieldDescription objects.
            let fields: Vec<String> = match mp.get(2) {
                Some(PsValue::List(list)) => list
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect(),
                _ => Vec::new(),
            };
            let out = host.prompt(caption, message, &fields).await?;
            Ok(Some(PsValue::List(out)))
        }
        HostMethodId::PromptForCredential => {
            let caption = mp.first().and_then(PsValue::as_str).unwrap_or_default();
            let message = mp.get(1).and_then(PsValue::as_str).unwrap_or_default();
            let user = mp.get(2).and_then(PsValue::as_str).unwrap_or_default();
            let (u, p) = host.get_credential(caption, message, user).await?;
            let obj = crate::clixml::PsObject::new()
                .with("UserName", PsValue::String(u))
                .with("Password", PsValue::SecureString(p));
            Ok(Some(PsValue::Object(obj)))
        }
        _ => Err(host.rejection_for(mi.kind())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_interaction_rejects_reads() {
        let h = NoInteractionHost;
        assert!(h.read_line().await.is_err());
        assert!(h.read_line_as_secure_string().await.is_err());
        assert!(h.prompt_for_choice("", "", &[], 0).await.is_err());
        assert!(h.prompt("", "", &[]).await.is_err());
        assert!(h.get_credential("", "", "").await.is_err());
    }

    #[tokio::test]
    async fn no_interaction_accepts_writes() {
        let h = NoInteractionHost;
        h.write_line("x").await;
        h.write("x").await;
        h.write_error_line("x").await;
        h.write_warning_line("x").await;
        h.write_verbose_line("x").await;
        h.write_debug_line("x").await;
        h.write_progress(0, PsValue::Null).await;
    }

    #[tokio::test]
    async fn buffered_host_captures_lines() {
        let h = BufferedHost::new();
        h.write_line("hello").await;
        h.write_warning_line("warn").await;
        h.write_error_line("err").await;
        assert_eq!(h.lines(), vec!["hello".to_string()]);
        assert_eq!(h.warnings(), vec!["warn".to_string()]);
        assert_eq!(h.errors(), vec!["err".to_string()]);
    }

    #[tokio::test]
    async fn dispatch_void_write_line() {
        let h = BufferedHost::new();
        let out = dispatch_host_call(
            &h,
            HostMethodId::WriteLine1,
            &[PsValue::String("hi".into())],
        )
        .await
        .unwrap();
        assert!(out.is_none());
        assert_eq!(h.lines(), vec!["hi".to_string()]);
    }

    #[tokio::test]
    async fn dispatch_read_line_rejected_by_default() {
        let h = NoInteractionHost;
        let err = dispatch_host_call(&h, HostMethodId::ReadLine, &[])
            .await
            .unwrap_err();
        assert!(matches!(err, PsrpError::Protocol(_)));
    }

    #[tokio::test]
    async fn dispatch_read_line_custom_host() {
        struct Yes;
        #[async_trait]
        impl PsHost for Yes {
            async fn read_line(&self) -> Result<String> {
                Ok("yes".into())
            }
        }
        let out = dispatch_host_call(&Yes, HostMethodId::ReadLine, &[])
            .await
            .unwrap();
        assert_eq!(out, Some(PsValue::String("yes".into())));
    }

    #[test]
    fn host_method_id_roundtrip() {
        for (n, expected) in [
            (11i64, HostMethodId::ReadLine),
            (13, HostMethodId::Write1),
            (14, HostMethodId::Write2),
            (15, HostMethodId::WriteLine1),
            (16, HostMethodId::WriteLine2),
            (18, HostMethodId::WriteErrorLine),
            (26, HostMethodId::PromptForChoice),
            (32, HostMethodId::Other(32)),
            (48, HostMethodId::Other(48)),
            (999, HostMethodId::Other(999)),
        ] {
            let id = HostMethodId::from_i64(n);
            assert_eq!(id, expected);
            assert_eq!(id.to_i64(), n);
        }
    }

    #[test]
    fn is_void_is_correct() {
        assert!(HostMethodId::WriteLine1.is_void());
        assert!(HostMethodId::WriteProgress.is_void());
        assert!(!HostMethodId::ReadLine.is_void());
        assert!(!HostMethodId::PromptForChoice.is_void());
    }

    // ---------- Phase D: dispatch coverage ----------

    #[tokio::test]
    async fn dispatch_write_error_line() {
        let h = BufferedHost::new();
        dispatch_host_call(
            &h,
            HostMethodId::WriteErrorLine,
            &[PsValue::String("oops".into())],
        )
        .await
        .unwrap();
        assert_eq!(h.errors(), vec!["oops".to_string()]);
    }

    #[tokio::test]
    async fn dispatch_write_warning_line() {
        let h = BufferedHost::new();
        dispatch_host_call(
            &h,
            HostMethodId::WriteWarningLine,
            &[PsValue::String("warn".into())],
        )
        .await
        .unwrap();
        assert_eq!(h.warnings(), vec!["warn".to_string()]);
    }

    #[tokio::test]
    async fn dispatch_write_verbose_debug_progress() {
        let h = BufferedHost::new();
        dispatch_host_call(
            &h,
            HostMethodId::WriteVerboseLine,
            &[PsValue::String("v".into())],
        )
        .await
        .unwrap();
        dispatch_host_call(
            &h,
            HostMethodId::WriteDebugLine,
            &[PsValue::String("d".into())],
        )
        .await
        .unwrap();
        dispatch_host_call(
            &h,
            HostMethodId::WriteProgress,
            &[PsValue::I64(0), PsValue::Null],
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn dispatch_prompt_for_choice_custom_host() {
        use async_trait::async_trait;
        struct Chooser;
        #[async_trait]
        impl PsHost for Chooser {
            async fn prompt_for_choice(
                &self,
                caption: &str,
                message: &str,
                choices: &[(String, String)],
                default: i32,
            ) -> Result<i32> {
                assert_eq!(caption, "Cap");
                assert_eq!(message, "Msg");
                assert_eq!(choices.len(), 2);
                assert_eq!(default, 1);
                Ok(1)
            }
        }

        let choice_obj = |label: &str, help: &str| {
            PsValue::Object(
                crate::clixml::PsObject::new()
                    .with("Label", PsValue::String(label.into()))
                    .with("HelpMessage", PsValue::String(help.into())),
            )
        };
        let out = dispatch_host_call(
            &Chooser,
            HostMethodId::PromptForChoice,
            &[
                PsValue::String("Cap".into()),
                PsValue::String("Msg".into()),
                PsValue::List(vec![choice_obj("A", "a-help"), choice_obj("B", "b-help")]),
                PsValue::I32(1),
            ],
        )
        .await
        .unwrap();
        assert_eq!(out, Some(PsValue::I32(1)));
    }

    #[tokio::test]
    async fn dispatch_prompt_custom_host() {
        use async_trait::async_trait;
        struct Prompter;
        #[async_trait]
        impl PsHost for Prompter {
            async fn prompt(
                &self,
                _caption: &str,
                _message: &str,
                _fields: &[String],
            ) -> Result<Vec<PsValue>> {
                Ok(vec![PsValue::String("ok".into())])
            }
        }

        let out = dispatch_host_call(
            &Prompter,
            HostMethodId::Prompt,
            &[
                PsValue::String("Cap".into()),
                PsValue::String("Msg".into()),
                PsValue::List(vec![PsValue::String("f1".into())]),
            ],
        )
        .await
        .unwrap();
        match out {
            Some(PsValue::List(items)) => {
                assert_eq!(items, vec![PsValue::String("ok".into())]);
            }
            _ => panic!("expected list"),
        }
    }

    #[tokio::test]
    async fn dispatch_get_credential_custom_host() {
        use async_trait::async_trait;
        struct Creds;
        #[async_trait]
        impl PsHost for Creds {
            async fn get_credential(
                &self,
                _caption: &str,
                _message: &str,
                _user: &str,
            ) -> Result<(String, String)> {
                Ok(("alice".into(), "s3cret".into()))
            }
        }

        let out = dispatch_host_call(
            &Creds,
            HostMethodId::PromptForCredential,
            &[
                PsValue::String(String::new()),
                PsValue::String(String::new()),
                PsValue::String("alice".into()),
            ],
        )
        .await
        .unwrap();
        match out {
            Some(PsValue::Object(o)) => {
                assert_eq!(o.get("UserName"), Some(&PsValue::String("alice".into())));
                assert_eq!(
                    o.get("Password"),
                    Some(&PsValue::SecureString("s3cret".into()))
                );
            }
            _ => panic!("expected PsObject"),
        }
    }

    #[tokio::test]
    async fn dispatch_read_secure_string_custom_host() {
        use async_trait::async_trait;
        struct Secret;
        #[async_trait]
        impl PsHost for Secret {
            async fn read_line_as_secure_string(&self) -> Result<String> {
                Ok("hidden".into())
            }
        }
        let out = dispatch_host_call(&Secret, HostMethodId::ReadLineAsSecureString, &[])
            .await
            .unwrap();
        assert_eq!(out, Some(PsValue::SecureString("hidden".into())));
    }

    #[tokio::test]
    async fn dispatch_unknown_method_rejected() {
        let h = NoInteractionHost;
        // method id 999 → HostMethodId::Other → rejection
        let err = dispatch_host_call(&h, HostMethodId::Other(999), &[])
            .await
            .unwrap_err();
        assert!(matches!(err, PsrpError::Protocol(_)));
    }

    #[tokio::test]
    async fn dispatch_writeline2_and_writeline3() {
        let h = BufferedHost::new();
        dispatch_host_call(
            &h,
            HostMethodId::WriteLine2,
            &[PsValue::String("line2".into())],
        )
        .await
        .unwrap();
        dispatch_host_call(
            &h,
            HostMethodId::WriteLine3,
            &[PsValue::String("line3".into())],
        )
        .await
        .unwrap();
        assert_eq!(h.lines(), vec!["line2".to_string(), "line3".to_string()]);
    }

    #[tokio::test]
    async fn dispatch_prompt_for_choice_non_list_choices() {
        // When choices is not a PsValue::List, should default to empty Vec
        use async_trait::async_trait;
        struct Chooser;
        #[async_trait]
        impl PsHost for Chooser {
            async fn prompt_for_choice(
                &self,
                _caption: &str,
                _message: &str,
                choices: &[(String, String)],
                _default: i32,
            ) -> Result<i32> {
                assert!(choices.is_empty());
                Ok(0)
            }
        }
        let out = dispatch_host_call(
            &Chooser,
            HostMethodId::PromptForChoice,
            &[
                PsValue::String("Cap".into()),
                PsValue::String("Msg".into()),
                PsValue::I32(42), // not a list
                PsValue::I32(0),
            ],
        )
        .await
        .unwrap();
        assert_eq!(out, Some(PsValue::I32(0)));
    }

    #[tokio::test]
    async fn dispatch_prompt_non_list_fields() {
        use async_trait::async_trait;
        struct Prompter;
        #[async_trait]
        impl PsHost for Prompter {
            async fn prompt(
                &self,
                _caption: &str,
                _message: &str,
                fields: &[String],
            ) -> Result<Vec<PsValue>> {
                assert!(fields.is_empty());
                Ok(vec![])
            }
        }
        let out = dispatch_host_call(
            &Prompter,
            HostMethodId::Prompt,
            &[
                PsValue::String("C".into()),
                PsValue::String("M".into()),
                PsValue::I32(999), // not a list
            ],
        )
        .await
        .unwrap();
        assert_eq!(out, Some(PsValue::List(vec![])));
    }

    #[test]
    fn host_call_kind_debug() {
        // Ensure every HostCallKind variant formats so the rejection
        // message paths stay test-covered.
        for k in [
            HostCallKind::ReadInput,
            HostCallKind::ReadSecureInput,
            HostCallKind::PromptForChoice,
            HostCallKind::Prompt,
            HostCallKind::GetCredential,
            HostCallKind::Other(7),
        ] {
            let _ = format!("{k:?}");
        }
    }
}
