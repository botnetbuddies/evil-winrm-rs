//! Local broker and SOCKS command-line options.
#[derive(clap::Args, Default)]
pub struct ControlOptions {
    /// Own persistent runspaces and expose local CLI/MCP control.
    #[arg(long,conflicts_with_all=["mcp","broker","command","json","exit_code"])]
    pub daemon: bool,
    /// Start the broker in a detached process.
    #[arg(long, requires = "daemon")]
    pub detach: bool,
    #[arg(long, hide = true, requires = "daemon")]
    pub daemon_child: bool,
    /// Private broker connection file; defaults to the user's state directory.
    #[arg(long)]
    pub daemon_state: Option<std::path::PathBuf>,
    /// Broker loopback HTTP port; 0 selects an available port.
    #[arg(long, default_value_t = 0)]
    pub daemon_port: u16,
    /// Use the local broker's runspaces; exiting the CLI leaves them alive.
    #[arg(long,conflicts_with_all=["mcp","daemon"])]
    pub broker: bool,
    #[arg(long, requires = "broker")]
    pub session: Option<u64>,
    #[arg(long,requires="broker",conflicts_with_all=["command","disconnect","shutdown_daemon"])]
    pub list_sessions: bool,
    #[arg(long,requires="broker",conflicts_with_all=["command","shutdown_daemon"])]
    pub disconnect: bool,
    #[arg(long,requires="broker",conflicts_with_all=["command","session"])]
    pub shutdown_daemon: bool,
    /// Serve a local SOCKS5 CONNECT listener through Windows.
    #[arg(long,num_args=0..=1,default_missing_value="127.0.0.1:1080",conflicts_with_all=["mcp","command","json","exit_code","list_sessions","disconnect","shutdown_daemon"])]
    pub socks: Option<std::net::SocketAddr>,
    #[arg(long,default_value_t=4,value_parser=clap::value_parser!(u16).range(1..=128))]
    pub socks_max_connections: u16,
}
