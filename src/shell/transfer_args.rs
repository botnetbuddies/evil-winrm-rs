//! Transfer options are local helper syntax, separate from PowerShell parsing.
use crate::{cli::Cli, command::arguments, transfer::Options};
use anyhow::{Result, bail};
pub(super) fn parse(line: &str, args: &Cli) -> Result<(Vec<String>, Options)> {
    let mut options = Options {
        resume: args.resume,
        compress: args.compress,
    };
    let mut positional = Vec::new();
    let mut literal = false;
    for word in arguments(line)?.into_iter().skip(1) {
        match word.as_str() {
            "--" if !literal => literal = true,
            "--resume" if !literal => options.resume = true,
            "--compress" if !literal => options.compress = true,
            _ => positional.push(word),
        }
    }
    if !(1..=2).contains(&positional.len()) {
        bail!("usage: upload/download [--resume] [--compress] <source> [destination]");
    }
    Ok((positional, options))
}
