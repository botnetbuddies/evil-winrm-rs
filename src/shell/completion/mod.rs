//! Command and path completion, with a ten-second remote directory cache.
mod local;
mod remote;
pub(super) mod words;
use super::{
    menu::{BUILTINS, helper_available},
    paths::{SCRIPT_EXTENSIONS, has_extension, local_path},
};
use crate::{
    command::{arguments, quote},
    session::Session,
};
use local::local_candidates;
use remote::{remote_candidates, remote_directory};
use rustyline::{
    Helper, Highlighter, Hinter,
    completion::{Completer, Pair},
};
use std::{
    cell::RefCell,
    collections::HashMap,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use words::{completion_word, explicit_remote_path, token_start};
#[derive(Helper, Hinter, Highlighter)]
pub(super) struct ShellHelper {
    pub(super) session: Session,
    pub(super) runtime: tokio::runtime::Handle,
    pub(super) remote_paths: bool,
    pub(super) scripts: Option<PathBuf>,
    pub(super) executables: Option<PathBuf>,
    pub(super) cwd: String,
    pub(super) remote_cache: RefCell<HashMap<(String, String), RemoteListing>>,
}

pub(super) struct RemoteListing {
    fetched: Instant,
    entries: Vec<RemoteEntry>,
}

#[derive(Clone, serde::Deserialize)]
pub(super) struct RemoteEntry {
    pub(super) name: String,
    pub(super) directory: bool,
}

impl Completer for ShellHelper {
    type Candidate = Pair;
    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let text = &line[..pos];
        let start = token_start(text);
        let prefix_value = completion_word(&text[start..]);
        let prefix = prefix_value.as_str();
        let parts = arguments(&text[..start]).unwrap_or_default();
        let command = text
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        let before = text[..start].trim();
        let local = (matches!(
            command.as_str(),
            "upload" | "loadps" | "runps" | "loaddll" | "runexe" | "invoke-binary"
        ) && parts.len() == 1)
            || (command == "download" && parts.len() == 2)
            || (command == "donut-loader"
                && parts
                    .last()
                    .is_some_and(|s| s.eq_ignore_ascii_case("-donutfile")));
        if self.session.jea && !parts.is_empty() && !helper_available(&command, true) {
            return Ok((start, Vec::new()));
        }
        if local {
            let extensions = match command.as_str() {
                "loadps" | "runps" => SCRIPT_EXTENSIONS,
                "loaddll" => &["dll"][..],
                "runexe" | "invoke-binary" => &["exe"][..],
                _ => &[],
            };
            let mut matches = local_candidates(prefix, extensions);
            let search = match command.as_str() {
                "loadps" | "runps" => self.scripts.as_ref(),
                "loaddll" | "runexe" | "invoke-binary" | "donut-loader" => {
                    self.executables.as_ref()
                }
                _ => None,
            };
            if !explicit_remote_path(prefix)
                && !prefix.starts_with('~')
                && let Some(directory) = search
            {
                matches.extend(local_candidates(
                    &local_path(&directory.to_string_lossy())
                        .join(prefix)
                        .to_string_lossy(),
                    extensions,
                ));
            }
            matches.sort_by(|a, b| a.replacement.cmp(&b.replacement));
            matches.dedup_by(|a, b| a.replacement == b.replacement);
            return Ok((start, matches));
        }
        let command_position = before.is_empty() || before.ends_with('|');
        let help_completion = text.eq_ignore_ascii_case("help") || command == "help";
        let discovery_prefix = if text.eq_ignore_ascii_case("help") {
            ""
        } else {
            prefix
        };
        if (command_position || help_completion) && !explicit_remote_path(prefix) {
            let mut names: Vec<String> = BUILTINS
                .iter()
                .filter(|s| helper_available(s, self.session.jea))
                .map(|s| (*s).into())
                .collect();
            if help_completion {
                if !self.session.jea
                    && let Ok(functions) = self.runtime.block_on(self.session.loaded_functions())
                {
                    names.extend(functions);
                }
            } else {
                let command = if self.session.jea {
                    format!(
                        "Get-Command -Name {}",
                        quote(&format!("{discovery_prefix}*"))
                    )
                } else {
                    format!(
                        "Get-Command -Name {} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name",
                        quote(&format!("{discovery_prefix}*"))
                    )
                };
                if let Ok(result) = self
                    .runtime
                    .block_on(self.session.execute(&command, CancellationToken::new()))
                {
                    names.extend(result.stdout.lines().map(str::to_owned));
                }
            }
            if !self.session.jea
                && let Some(directory) = &self.scripts
                && let Ok(entries) = std::fs::read_dir(local_path(&directory.to_string_lossy()))
            {
                names.extend(
                    entries
                        .flatten()
                        .filter(|e| {
                            e.path().is_file() && has_extension(&e.path(), SCRIPT_EXTENSIONS)
                        })
                        .map(|e| e.file_name().to_string_lossy().into_owned()),
                );
            }
            if !self.session.jea
                && let Ok(methods) = self
                    .runtime
                    .block_on(self.session.raw("$global:showmethods"))
            {
                names.extend(methods.lines().map(str::to_owned));
            }
            names.sort();
            names.dedup();
            let pairs = names
                .into_iter()
                .filter(|n| {
                    n.to_lowercase()
                        .starts_with(&discovery_prefix.to_lowercase())
                })
                .map(|n| Pair {
                    display: n.clone(),
                    replacement: if has_extension(Path::new(&n), SCRIPT_EXTENSIONS)
                        && self
                            .scripts
                            .as_ref()
                            .is_some_and(|dir| dir.join(&n).is_file())
                    {
                        quote(&n)
                    } else {
                        n
                    },
                })
                .collect();
            let mut pairs: Vec<Pair> = pairs;
            if help_completion {
                for pair in &mut pairs {
                    pair.replacement = format!("help {}", pair.replacement);
                }
                return Ok((0, pairs));
            }
            return Ok((start, pairs));
        }
        if !self.remote_paths || self.session.jea {
            return Ok((start, Vec::new()));
        }
        let (directory, _) = remote_directory(prefix);
        let key = (self.cwd.clone(), directory.to_owned());
        let cached = self
            .remote_cache
            .borrow()
            .get(&key)
            .filter(|listing| listing.fetched.elapsed() < Duration::from_secs(10))
            .map(|listing| listing.entries.clone());
        let entries = if let Some(entries) = cached {
            entries
        } else {
            let script = format!(
                "ConvertTo-Json -Compress -InputObject @(Get-ChildItem -LiteralPath {} -Force -ErrorAction Stop | ForEach-Object {{ @{{name=$_.Name;directory=[bool]$_.PSIsContainer}} }})",
                quote(if directory.is_empty() { "." } else { directory })
            );
            let entries: Vec<RemoteEntry> = match self.runtime.block_on(self.session.raw(&script)) {
                Ok(output) => serde_json::from_str(output.trim()).unwrap_or_default(),
                Err(_) => return Ok((start, Vec::new())),
            };
            let mut cache = self.remote_cache.borrow_mut();
            cache.retain(|_, listing| listing.fetched.elapsed() < Duration::from_secs(10));
            cache.insert(
                key,
                RemoteListing {
                    fetched: Instant::now(),
                    entries: entries.clone(),
                },
            );
            entries
        };
        Ok((
            start,
            remote_candidates(
                prefix,
                &entries,
                matches!(command.as_str(), "cd" | "chdir" | "sl" | "set-location"),
                command_position,
            ),
        ))
    }
}

#[cfg(test)]
pub(super) use local::local_candidates as test_local_candidates;
#[cfg(test)]
pub(super) use remote::remote_candidates as test_remote_candidates;
