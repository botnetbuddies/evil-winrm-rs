//! Local path candidates with shell quoting and file-type filters.
use super::super::paths::{has_extension, local_path};
use crate::command::quote;
use rustyline::completion::Pair;
use std::path::{Path, PathBuf};
pub(in crate::shell) fn local_candidates(prefix: &str, extensions: &[&str]) -> Vec<Pair> {
    let expanded = local_path(prefix);
    let (directory, partial) = if prefix.is_empty() {
        (Path::new("."), String::new())
    } else if prefix == "~" || prefix.ends_with(std::path::MAIN_SEPARATOR) || prefix.ends_with('/')
    {
        (expanded.as_path(), String::new())
    } else {
        (
            expanded
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
            expanded
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
        )
    };
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_dir = entry.path().is_dir();
        if !name.to_lowercase().starts_with(&partial.to_lowercase())
            || (!is_dir && !extensions.is_empty() && !has_extension(&entry.path(), extensions))
        {
            continue;
        }
        let candidate = if directory == Path::new(".") {
            PathBuf::from(&name)
        } else {
            directory.join(&name)
        };
        let mut value = candidate.to_string_lossy().into_owned();
        if prefix.starts_with('~')
            && let Some(home) =
                dirs::home_dir().and_then(|h| candidate.strip_prefix(h).ok().map(Path::to_path_buf))
        {
            value = format!("~{}{}", std::path::MAIN_SEPARATOR, home.display());
        }
        if is_dir {
            value.push(std::path::MAIN_SEPARATOR);
        }
        out.push(Pair {
            display: if prefix.starts_with('~') {
                value.clone()
            } else {
                name
            },
            replacement: quote(&value),
        });
    }
    out.sort_by(|a, b| a.display.cmp(&b.display));
    out
}
