//! Ordered console events and display rendering of PSRP values.
use anyhow::{Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use psrp_rs::{PipelineResult, PipelineState, PsValue};
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct Output {
    pub stdout: String,
    #[serde(skip)]
    pub console: Vec<ConsoleEvent>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub verbose: Vec<String>,
    pub debug: Vec<String>,
    pub information: Vec<String>,
    pub failed: bool,
    #[serde(rename = "remote_exit_code")]
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ConsoleEvent {
    Text(String),
    ClearScreen,
}
impl Output {
    pub fn checked(self) -> Result<String> {
        if self.failed || !self.errors.is_empty() {
            bail!("{}\n{}", self.stdout, self.errors.join("\n"));
        }
        Ok(self.stdout)
    }
    pub(super) fn append(&mut self, result: PipelineResult) {
        for value in result.output {
            let text = render(&value);
            self.stdout.push_str(&text);
            if !text.ends_with('\n') {
                self.stdout.push('\n');
            }
        }
        self.errors.extend(result.errors.iter().map(render));
        self.warnings.extend(result.warnings.iter().map(render));
        self.verbose.extend(result.verbose.iter().map(render));
        self.debug.extend(result.debug.iter().map(render));
        self.information
            .extend(result.information.iter().filter(|record| {
                !record.properties().and_then(|properties| properties.get("MessageData"))
                    .is_some_and(|data| matches!(data, PsValue::Object(object)
                        if object.type_names.iter().any(|name| name == "System.Management.Automation.HostInformationMessage")))
            }).map(render));
        self.failed |= result.state == PipelineState::Failed;
    }
}

pub fn render(value: &PsValue) -> String {
    match value {
        PsValue::Null => String::new(),
        PsValue::Object(o) => {
            if let Some(s) = &o.to_string
                && !o
                    .type_names
                    .iter()
                    .any(|name| name == s || name.strip_prefix("Deserialized.") == Some(s))
            {
                return s.clone();
            }
            for name in [
                "Message",
                "MessageData",
                "InformationalRecord_Message",
                "Exception",
            ] {
                if let Some(v) = o.properties.get(name) {
                    return render(v);
                }
            }
            o.properties
                .iter()
                .map(|(k, v)| format!("{k} : {}", render(v)))
                .collect::<Vec<_>>()
                .join("\n")
        }
        PsValue::List(v) => v.iter().map(render).collect::<Vec<_>>().join("\n"),
        PsValue::Dict(v) => v
            .iter()
            .map(|(k, v)| format!("{} : {}", render(k), render(v)))
            .collect::<Vec<_>>()
            .join("\n"),
        PsValue::SecureString(_) => "[SecureString]".into(),
        PsValue::Bool(v) => v.to_string(),
        PsValue::I8(v) => v.to_string(),
        PsValue::U8(v) => v.to_string(),
        PsValue::I16(v) => v.to_string(),
        PsValue::U16(v) => v.to_string(),
        PsValue::I32(v) => v.to_string(),
        PsValue::U32(v) => v.to_string(),
        PsValue::I64(v) => v.to_string(),
        PsValue::U64(v) => v.to_string(),
        PsValue::F32(v) => v.to_string(),
        PsValue::Double(v) => v.to_string(),
        PsValue::Char(v) => v.to_string(),
        PsValue::Guid(v) => v.to_string(),
        PsValue::Bytes(v) => B64.encode(v),
        v => v.as_str().unwrap_or("").into(),
    }
}
