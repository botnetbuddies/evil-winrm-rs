//! Command-line schema; connection policy and secret handling live separately.
mod connection;
mod control;
pub(crate) use connection::initialize;
mod credentials;
#[cfg(test)]
mod tests;
use clap::{Parser, ValueEnum};
use credentials::parse_environment;
pub use credentials::{parse_hash, read_password_line, split_username};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Authentication {
    Ntlm,
    Kerberos,
    Certificate,
    Credssp,
    Basic,
    Negotiate,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum Encryption {
    #[default]
    Auto,
    Always,
    Never,
}

/// Native Rust PowerShell remoting shell.
#[derive(Parser)]
#[command(version, disable_version_flag = true)]
pub struct Cli {
    #[command(flatten)]
    pub control: control::ControlOptions,
    /// Keep verified partial transfer files and resume matching content.
    #[arg(long, conflicts_with = "mcp")]
    pub resume: bool,
    /// Compress transfer chunks with gzip before sending them.
    #[arg(long, conflicts_with = "mcp")]
    pub compress: bool,
    #[arg(short = 'i', long = "ip", required_unless_present_any=["mcp","daemon","broker"])]
    pub host: Option<String>,
    #[arg(short = 'u', long = "user")]
    pub user: Option<String>,
    #[arg(short = 'p', long, conflicts_with = "hash")]
    pub password: Option<String>,
    /// Read one password line from stdin, preserving spaces (strip only its line ending).
    #[arg(long, conflicts_with_all=["password", "hash", "no_pass", "mcp"])]
    pub password_stdin: bool,
    /// Read one password line from a file instead of exposing it in process arguments.
    #[arg(long, conflicts_with_all=["password", "password_stdin", "hash", "no_pass", "mcp"])]
    pub password_file: Option<PathBuf>,
    /// Route WinRM through an HTTP(S) or SOCKS5 proxy URL.
    #[arg(long, conflicts_with = "mcp")]
    pub proxy: Option<String>,
    /// Select authentication; existing Kerberos/certificate options still work.
    #[arg(long, value_enum, conflicts_with = "mcp")]
    pub auth: Option<Authentication>,
    /// Select CredSSP authentication and HTTPS (requires the credssp build feature).
    #[arg(long, conflicts_with = "mcp")]
    pub credssp: bool,
    /// SOAP message sealing policy; HTTPS transport encryption remains independent.
    #[arg(long, value_enum, default_value = "auto", conflicts_with = "mcp")]
    pub encryption: Encryption,
    #[arg(short = 'H', long)]
    pub hash: Option<String>,
    #[arg(short = 'S', long = "ssl")]
    pub tls: bool,
    #[arg(short = 'P', long, value_parser = clap::value_parser!(u16).range(1..))]
    pub port: Option<u16>,
    #[arg(
        short = 'U',
        long = "uri",
        visible_alias = "url",
        default_value = "/wsman"
    )]
    pub uri: String,
    #[arg(
        short = 'a',
        long = "user-agent",
        visible_alias = "ua",
        default_value = "Microsoft WinRM Client"
    )]
    pub user_agent: String,
    #[arg(long = "pub-key", visible_alias = "cert-pem", requires = "private_key")]
    pub certificate: Option<PathBuf>,
    #[arg(
        long = "priv-key",
        visible_alias = "priv-key-pem",
        requires = "certificate"
    )]
    pub private_key: Option<PathBuf>,
    /// PKCS#12 client identity (selects certificate authentication and HTTPS).
    #[arg(long, conflicts_with_all=["certificate", "private_key", "mcp"])]
    pub pfx: Option<PathBuf>,
    /// Read the PKCS#12 container password from a file.
    #[arg(long, requires = "pfx", conflicts_with = "mcp")]
    pub pfx_password_file: Option<PathBuf>,
    #[arg(short = 'c', long, default_value = "Microsoft.PowerShell")]
    pub configuration_name: String,
    #[arg(short = 'k', long)]
    pub kerberos: bool,
    #[arg(short = 'r', long)]
    pub realm: Option<String>,
    #[arg(short = 'K', long)]
    pub ccache: Option<PathBuf>,
    /// Acquire Kerberos credentials from a keytab; requires --user user@REALM.
    #[arg(long, conflicts_with_all=["ccache", "password", "password_stdin", "password_file", "hash", "mcp"])]
    pub keytab: Option<PathBuf>,
    #[arg(long = "spn-prefix", visible_alias = "spn", default_value = "HTTP")]
    pub spn_prefix: String,
    #[arg(long)]
    pub spn_hostname: Option<String>,
    #[arg(long)]
    pub no_pass: bool,
    #[arg(short = 's', long)]
    pub scripts: Option<PathBuf>,
    #[arg(short = 'e', long)]
    pub executables: Option<PathBuf>,
    #[arg(short = 'n', long)]
    pub no_colors: bool,
    #[arg(short = 'N', long)]
    pub no_rpath_completion: bool,
    #[arg(short = 'l', long)]
    pub log: bool,
    #[arg(long)]
    pub log_file: Option<PathBuf>,
    #[arg(long)]
    pub debug: bool,
    /// Verify the server TLS certificate (upstreams accept self-signed certificates).
    #[arg(long)]
    pub verify_tls: bool,
    /// Add PEM CA trust anchors and enable certificate verification.
    #[arg(long, conflicts_with = "mcp")]
    pub ca_cert: Option<PathBuf>,
    /// Override origin TLS SNI and certificate name without changing the destination.
    #[arg(long, conflicts_with = "mcp")]
    pub tls_server_name: Option<String>,
    /// Initial remote PowerShell directory (full-language endpoints).
    #[arg(long = "cd", conflicts_with = "mcp")]
    pub directory: Option<String>,
    /// Set a remote process environment variable; repeat for multiple values.
    #[arg(long = "env", value_name = "KEY=VALUE", value_parser = parse_environment, conflicts_with = "mcp")]
    pub environment: Vec<(String, String)>,
    /// Requested remote shell idle timeout in seconds; subject to server policy.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=86400), conflicts_with = "mcp")]
    pub idle_timeout: Option<u64>,
    /// Retry transient HTTP failures (not authentication or SOAP faults).
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u32).range(0..=10), conflicts_with = "mcp")]
    pub retries: u32,
    /// TCP/proxy connect timeout in seconds.
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=86400), conflicts_with = "mcp")]
    pub connect_timeout: u64,
    /// WSMan receive-poll timeout in seconds, rather than a command execution deadline.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..=86400), conflicts_with = "mcp")]
    pub operation_timeout: u64,
    /// Maximum SOAP envelope size in bytes; must also be accepted by the server.
    #[arg(long, default_value_t = 153600, value_parser = clap::value_parser!(u32).range(65536..=16777216), conflicts_with = "mcp")]
    pub max_envelope: u32,
    /// Per-request serialized PSRP output limit in bytes; 0 disables it. Exceeding it closes the session.
    #[arg(long, default_value_t = 67108864, conflicts_with = "mcp")]
    pub max_output: usize,
    #[arg(long)]
    pub command: Option<String>,
    /// Emit one JSON result object for --command, including output streams and status.
    #[arg(long, requires = "command", conflicts_with = "mcp")]
    pub json: bool,
    /// Return the remote numeric exit code for --command (otherwise failures return 1).
    #[arg(long, requires = "command", conflicts_with = "mcp")]
    pub exit_code: bool,
    #[arg(long)]
    pub mcp: bool,
    #[arg(long, default_value = "127.0.0.1")]
    pub mcp_host: String,
    #[arg(long, default_value_t = 8000, value_parser = clap::value_parser!(u16).range(1..))]
    pub mcp_port: u16,
    #[arg(short = 'V', long, action = clap::ArgAction::Version)]
    pub version: (),
}

pub fn parse() -> Cli {
    let mut cli = Cli::parse();
    cli.no_colors |= std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty());
    cli
}

pub fn connect_profile(args: &mut Cli) -> anyhow::Result<crate::connection::ConnectionProfile> {
    crate::connection::ConnectionProfile::from_cli(args)
}
