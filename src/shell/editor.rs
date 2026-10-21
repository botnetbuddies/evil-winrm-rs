//! Parser-aware multiline validation for the line editor.
use super::completion::ShellHelper;
use rustyline::{
    error::ReadlineError,
    validate::{ValidationContext, ValidationResult, Validator},
};
impl Validator for ShellHelper {
    fn validate(&self, context: &mut ValidationContext<'_>) -> rustyline::Result<ValidationResult> {
        if context.input().trim().is_empty() {
            return Ok(ValidationResult::Valid(None));
        }
        let incomplete = self
            .runtime
            .block_on(self.session.input_is_incomplete(context.input()))
            .map_err(|error| {
                ReadlineError::Io(std::io::Error::other(format!(
                    "checking PowerShell input: {error:#}"
                )))
            })?;
        Ok(if incomplete {
            ValidationResult::Incomplete
        } else {
            ValidationResult::Valid(None)
        })
    }
}
