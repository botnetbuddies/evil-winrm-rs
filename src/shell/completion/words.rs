//! Token boundaries and PowerShell-safe path replacements.
use crate::command::{arguments, quote};
pub(in crate::shell) fn explicit_remote_path(prefix: &str) -> bool {
    prefix.contains(['\\', '/']) || prefix.as_bytes().get(1) == Some(&b':')
}

pub(in crate::shell) fn remote_path_replacement(path: &str, command_position: bool) -> String {
    let needs_quote = path.contains([' ', '\'', '"', '`', '$', ';', '&', '|', '(', ')', '[', ']']);
    if needs_quote {
        let quoted = quote(path);
        if command_position && !path.ends_with(['\\', '/']) {
            format!("& {quoted}")
        } else {
            quoted
        }
    } else {
        path.into()
    }
}

/// Find the current token while retaining quoted paths with spaces.
pub(in crate::shell) fn token_start(line: &str) -> usize {
    let mut quote = None;
    let mut start = 0;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if c == '`' && quote != Some('\'') {
            escaped = true;
            continue;
        }
        if quote == Some(c) {
            quote = None;
        } else if quote.is_none() && matches!(c, '\'' | '"') {
            quote = Some(c);
        } else if quote.is_none() && (c.is_whitespace() || c == '|') {
            start = i + c.len_utf8();
        }
    }
    start
}

pub(in crate::shell) fn completion_word(text: &str) -> String {
    if let Ok(words) = arguments(text) {
        return words.into_iter().next().unwrap_or_default();
    }
    if let Some(first) = text.chars().next().filter(|c| matches!(c, '\'' | '"'))
        && let Ok(words) = arguments(&format!("{text}{first}"))
    {
        return words.into_iter().next().unwrap_or_default();
    }
    text.to_owned()
}
