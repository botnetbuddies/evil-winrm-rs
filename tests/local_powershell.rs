//! Opted-in integration suites backed by real PowerShell and a strict WSMan adapter.
#![cfg(feature = "mcp")]
#[path = "local_powershell/assemblies.rs"]
mod assemblies;
#[path = "local_powershell/cli.rs"]
mod cli;
#[path = "local_powershell/editor.rs"]
mod editor;
#[path = "local_powershell/faults.rs"]
mod faults;
#[path = "local_powershell/fixture.rs"]
mod fixture;
#[path = "local_powershell/limits.rs"]
mod limits;
#[path = "local_powershell/mcp.rs"]
mod mcp;
#[path = "local_powershell/persistent.rs"]
mod persistent;
#[path = "local_powershell/resuming.rs"]
mod resuming;
#[path = "local_powershell/session.rs"]
mod session;

#[path = "local_powershell/broker.rs"]
mod broker;
#[path = "local_powershell/empty_upload.rs"]
mod empty_upload;
#[path = "local_powershell/mcp_client.rs"]
mod mcp_client;
