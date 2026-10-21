//! Stable one-command result envelope for JSON and process exit status.
use crate::session::Output;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CommandReport {
    pub success: bool,
    pub exit_code: i32,
    #[serde(flatten)]
    pub output: Output,
    pub error: Option<String>,
}
impl CommandReport {
    pub fn new(output: Output, error: Option<String>) -> Self {
        let mut exit_code = output.exit_code.unwrap_or(0);
        if (output.failed || !output.errors.is_empty() || error.is_some()) && exit_code == 0 {
            exit_code = 1;
        }
        Self {
            success: exit_code == 0 && error.is_none(),
            exit_code,
            output,
            error,
        }
    }
    pub fn failure(error: &anyhow::Error) -> Self {
        Self::new(Output::default(), Some(format!("{error:#}")))
    }
    pub fn process_code(&self, remote: bool) -> i32 {
        if remote {
            self.exit_code
        } else {
            i32::from(!self.success)
        }
    }
}

pub struct RunResult {
    pub code: i32,
    pub report: Option<CommandReport>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn numeric_status_and_output_remain_independent_of_process_mapping() {
        let report = CommandReport::new(
            Output {
                stdout: "before\n".into(),
                exit_code: Some(300),
                ..Default::default()
            },
            None,
        );
        assert_eq!(report.process_code(false), 1);
        assert_eq!(report.process_code(true), 300);
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["exit_code"], 300);
        assert_eq!(json["remote_exit_code"], 300);
        assert_eq!(json["stdout"], "before\n");
        assert_eq!(json["success"], false);
        let report = CommandReport::new(
            Output {
                errors: vec!["failure".into()],
                exit_code: Some(0),
                ..Default::default()
            },
            None,
        );
        assert_eq!(report.exit_code, 1);
        assert!(!report.success);
    }
}
