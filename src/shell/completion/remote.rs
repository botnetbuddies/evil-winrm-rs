//! Filter remote directory listings and preserve typed path prefixes.
use super::{RemoteEntry, words::remote_path_replacement};
use rustyline::completion::Pair;
pub(in crate::shell) fn remote_directory(prefix: &str) -> (&str, &str) {
    match prefix.rfind(['\\', '/']) {
        Some(index) => (&prefix[..=index], &prefix[index + 1..]),
        None => ("", prefix),
    }
}

pub(in crate::shell) fn remote_candidates(
    prefix: &str,
    entries: &[RemoteEntry],
    directories_only: bool,
    command_position: bool,
) -> Vec<Pair> {
    let (directory, leaf) = remote_directory(prefix);
    let mut pairs: Vec<_> = entries
        .iter()
        .filter(|entry| {
            (!directories_only || entry.directory)
                && entry.name.to_lowercase().starts_with(&leaf.to_lowercase())
        })
        .map(|entry| {
            let path = format!(
                "{directory}{}{}",
                entry.name,
                if entry.directory { "\\" } else { "" }
            );
            Pair {
                display: path.clone(),
                replacement: remote_path_replacement(&path, command_position),
            }
        })
        .collect();
    pairs.sort_by(|a, b| a.display.cmp(&b.display));
    pairs
}
