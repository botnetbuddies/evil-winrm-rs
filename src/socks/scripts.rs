//! Script templates receive values as quoted arguments; only generated identifiers are substituted.
use crate::command::quote;
pub(super) fn connect(id: &str, host: &str, port: u16) -> String {
    let body = include_str!("scripts/connect.ps1").replace("__SOCKET__", id);
    format!("& {{\n{body}\n}} {} {port}", quote(host))
}
pub(super) fn poll(id: &str, payload: &str, close_send: bool) -> String {
    let body = include_str!("scripts/poll.ps1").replace("__SOCKET__", id);
    format!("& {{\n{body}\n}} {} ${}", quote(payload), close_send)
}
pub(super) fn close(id: &str) -> String {
    format!(
        "if($global:{id}) {{ $global:{id}.client.Dispose(); Remove-Variable -Name {id} -Scope Global }}"
    )
}
