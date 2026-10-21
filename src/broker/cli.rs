//! CLI commands attach to broker-owned sessions; closing a client does not log out.
use super::{
    client::Client,
    models::{AttachInfo, SessionId, SessionInfo, SocksStart},
};
use crate::{cli::Cli, output::RunResult, session::Session};
use anyhow::Result;
pub fn run(runtime: &tokio::runtime::Runtime, args: &mut Cli) -> Result<RunResult> {
    let client = Client::from_file(args.control.daemon_state.as_deref())?;
    let mut selected = args.control.session;
    if args.host.is_some() {
        let profile = crate::connection::ConnectionProfile::from_cli(args)?;
        let info: SessionInfo =
            runtime.block_on(client.post("/login", &profile.login_request()))?;
        selected = Some(info.session_id);
        eprintln!("{}. session_id={}", info.description, info.session_id);
    }
    if args.control.list_sessions {
        let sessions: serde_json::Value = runtime.block_on(client.get("/sessions"))?;
        println!("{sessions}");
        return Ok(done());
    }
    if args.control.disconnect {
        let closed: serde_json::Value = runtime.block_on(client.post(
            "/logout",
            &SessionId {
                session_id: selected,
            },
        ))?;
        println!("{closed}");
        return Ok(done());
    }
    if args.control.shutdown_daemon {
        let result: serde_json::Value = runtime.block_on(client.post("/shutdown", &()))?;
        println!("{result}");
        return Ok(done());
    }
    if let Some(bind) = args.control.socks {
        let info: crate::socks::ListenerInfo = runtime.block_on(client.post(
            "/socks",
            &SocksStart {
                session_id: selected,
                bind,
                max_connections: args.control.socks_max_connections as usize,
            },
        ))?;
        println!("{}", serde_json::to_string(&info)?);
        return Ok(done());
    }
    let attached: AttachInfo = runtime.block_on(client.post(
        "/attach",
        &SessionId {
            session_id: selected,
        },
    ))?;
    args.host = Some(attached.info.host.clone());
    args.user = Some(attached.info.username.clone());
    // Building the queued adapter requires a live Tokio runtime.
    let session = {
        let _entered = runtime.enter();
        Session::attach_broker(client, attached)
    };
    let result = crate::shell::run(runtime, session.clone(), args);
    let _ = runtime.block_on(session.close());
    result
}
pub fn login_after_detach(runtime: &tokio::runtime::Runtime, args: &mut Cli) -> Result<()> {
    if args.host.is_some() {
        let client = Client::from_file(args.control.daemon_state.as_deref())?;
        let profile = crate::connection::ConnectionProfile::from_cli(args)?;
        let info: SessionInfo =
            runtime.block_on(client.post("/login", &profile.login_request()))?;
        eprintln!("{}. session_id={}", info.description, info.session_id);
        if let Some(bind) = args.control.socks {
            let listener: crate::socks::ListenerInfo = runtime.block_on(client.post(
                "/socks",
                &SocksStart {
                    session_id: Some(info.session_id),
                    bind,
                    max_connections: args.control.socks_max_connections as usize,
                },
            ))?;
            eprintln!("SOCKS listening on {}", listener.address);
        }
    }
    Ok(())
}
fn done() -> RunResult {
    RunResult {
        code: 0,
        report: None,
    }
}
