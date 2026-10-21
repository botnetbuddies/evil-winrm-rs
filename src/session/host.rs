//! Noninteractive PowerShell host callbacks and RawUI metadata.
use super::output::{ConsoleEvent, render};
use async_trait::async_trait;
use psrp_rs::{PsHost, PsValue};
use std::sync::Mutex;
#[derive(Default)]
pub(super) struct HostBuffer(
    pub(super) Mutex<Vec<ConsoleEvent>>,
    pub(super) Mutex<Option<i32>>,
);
#[async_trait]
impl PsHost for HostBuffer {
    async fn set_should_exit(&self, exit_code: i32) -> psrp_rs::Result<()> {
        *self.1.lock().unwrap() = Some(exit_code);
        Ok(())
    }
    fn host_info(&self) -> PsValue {
        use psrp_rs::clixml::PsObject;
        let object = |fields: Vec<(&str, PsValue)>| {
            let mut value = PsObject::new();
            for (name, field) in fields {
                value = value.with(name, field);
            }
            PsValue::Object(value)
        };
        let point = || object(vec![("x", PsValue::I32(0)), ("y", PsValue::I32(0))]);
        let size = || {
            object(vec![
                ("width", PsValue::I32(120)),
                ("height", PsValue::I32(30)),
            ])
        };
        let defaults = [
            ("System.ConsoleColor", PsValue::I32(7)),
            ("System.ConsoleColor", PsValue::I32(0)),
            ("System.Management.Automation.Host.Coordinates", point()),
            ("System.Management.Automation.Host.Coordinates", point()),
            ("System.Int32", PsValue::I32(25)),
            ("System.Management.Automation.Host.Size", size()),
            ("System.Management.Automation.Host.Size", size()),
            ("System.Management.Automation.Host.Size", size()),
            ("System.Management.Automation.Host.Size", size()),
            ("System.String", PsValue::String("evil-winrm-rs".into())),
        ];
        object(vec![
            ("_isHostNull", PsValue::Bool(false)),
            ("_isHostUINull", PsValue::Bool(false)),
            ("_isHostRawUINull", PsValue::Bool(false)),
            ("_useRunspaceHost", PsValue::Bool(false)),
            (
                "_hostDefaultData",
                object(vec![(
                    "data",
                    PsValue::Dict(
                        defaults
                            .into_iter()
                            .enumerate()
                            .map(|(index, (name, value))| {
                                (
                                    PsValue::I32(index as i32),
                                    object(vec![("T", PsValue::String(name.into())), ("V", value)]),
                                )
                            })
                            .collect(),
                    ),
                )]),
            ),
        ])
    }

    async fn pipeline_output(&self, value: &PsValue) {
        let mut text = render(value);
        if !text.ends_with('\n') {
            text.push('\n');
        }
        self.0.lock().unwrap().push(ConsoleEvent::Text(text));
    }

    async fn raw_ui(
        &self,
        method: i64,
        parameters: &[PsValue],
    ) -> psrp_rs::Result<Option<PsValue>> {
        match method {
            // RawUI setters are cached by the server; this host doesn't resize
            // the user's terminal or change its colors on remote request.
            28 | 30 | 32 | 34 | 36 | 38 | 40 | 42 | 47 => Ok(None),
            48 if parameters
                .first()
                .and_then(PsValue::properties)
                .is_some_and(|rectangle| {
                    ["left", "top", "right", "bottom"].iter().all(|name| {
                        rectangle
                            .iter()
                            .find(|(key, _)| key.eq_ignore_ascii_case(name))
                            .and_then(|(_, value)| value.as_i64())
                            == Some(-1)
                    })
                }) =>
            {
                self.0.lock().unwrap().push(ConsoleEvent::ClearScreen);
                Ok(None)
            }
            _ => Err(self.rejection_for(psrp_rs::HostCallKind::Other(method))),
        }
    }

    async fn write(&self, text: &str) {
        self.0.lock().unwrap().push(ConsoleEvent::Text(text.into()));
    }
    async fn write_line(&self, text: &str) {
        self.0
            .lock()
            .unwrap()
            .push(ConsoleEvent::Text(format!("{text}\n")));
    }
    async fn write_error_line(&self, text: &str) {
        self.0
            .lock()
            .unwrap()
            .push(ConsoleEvent::Text(format!("{text}\n")));
    }
}
