//! Readable PowerShell templates and their small, quoting-aware Rust adapters.
use super::Options;
use crate::command::quote;
pub(super) fn upload(stream: &str, path: &str, offset: u64, size: u64, options: Options) -> String {
    let mode = if options.resume {
        "OpenOrCreate"
    } else {
        "CreateNew"
    };
    let settings = format!(
        "$ewrStagingPath={}; $ewrOffset=[long]{offset}; $ewrExpectedLength=[long]{size}; $ewrCompressed=${}; $ewrMode=[IO.FileMode]::{mode};",
        quote(path),
        options.compress
    );
    include_str!("scripts/upload.ps1")
        .replace("__STREAM__", stream)
        .replace("__SETTINGS__", &settings)
}
pub(super) fn partial_state(path: &str) -> String {
    format!(
        "& {{\n{}\n}} {}",
        include_str!("scripts/partial_state.ps1"),
        quote(path)
    )
}
pub(super) fn download_chunk(path: &str, offset: u64, count: u64, compress: bool) -> String {
    format!(
        "& {{\n{}\n}} {} {offset} {count} ${compress}",
        include_str!("scripts/download_chunk.ps1"),
        quote(path)
    )
}
pub(super) fn prefix_hash(path: &str, length: u64) -> String {
    format!(
        "& {{\n{}\n}} {} {length}",
        include_str!("scripts/prefix_hash.ps1"),
        quote(path)
    )
}
pub(super) fn listing(path: &str, wildcard: bool) -> String {
    format!(
        "& {{\n{}\n}} {} ${wildcard}",
        include_str!("scripts/listing.ps1"),
        quote(path)
    )
}
pub(super) fn metadata(path: &str) -> String {
    format!(
        "& {{\n{}\n}} {}",
        include_str!("scripts/metadata.ps1"),
        quote(path)
    )
}
pub(super) fn destination(path: &str, filename: &str) -> String {
    format!(
        "& {{\n{}\n}} {} {}",
        include_str!("scripts/destination.ps1"),
        quote(path),
        quote(filename)
    )
}
