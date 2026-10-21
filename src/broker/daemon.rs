//! Host the session broker and MCP on one authenticated loopback listener.
use super::{Broker, api, state};
use crate::cli::Cli;
use anyhow::{Context, Result};
use axum::{
    extract::Request,
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use std::{
    path::Path,
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};
pub fn detach(args: &Cli) -> Result<()> {
    validate_initial_listener(args)?;
    let selected = state::path(args.control.daemon_state.as_deref());
    let parent = selected
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let log_path = selected.with_extension("log");
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let log = options.open(&log_path)?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["--daemon", "--daemon-child", "--daemon-state"])
        .arg(&selected)
        .args(["--daemon-port", &args.control.daemon_port.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x00000008 | 0x00000200);
    }
    #[cfg(windows)]
    let inherited = super::windows::StandardHandleGuard::exclude_from_children()?;
    let mut child = command.spawn().context("starting broker daemon")?;
    #[cfg(windows)]
    drop(inherited);
    for _ in 0..100 {
        if state::read(&selected).is_ok_and(|state| state.pid == child.id()) {
            return Ok(());
        }
        if child.try_wait()?.is_some() {
            anyhow::bail!("broker startup failed; see {}", log_path.display());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    anyhow::bail!("broker startup timed out; see {}", log_path.display())
}
pub async fn serve(args: &mut Cli) -> Result<()> {
    validate_initial_listener(args)?;
    let broker = Broker::default();
    if args.host.is_some() {
        let info = broker
            .open(crate::connection::ConnectionProfile::from_cli(args)?)
            .await?;
        eprintln!("{}. session_id={}", info.description, info.session_id);
        if let Some(bind) = args.control.socks {
            let listener = broker
                .start_socks(super::models::SocksStart {
                    session_id: Some(info.session_id),
                    bind,
                    max_connections: args.control.socks_max_connections as usize,
                })
                .await?;
            eprintln!("SOCKS listening on {}", listener.address);
        }
    }
    let listener =
        tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, args.control.daemon_port))
            .await?;
    let state = state::State {
        address: listener.local_addr()?,
        token: format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        ),
        pid: std::process::id(),
    };
    let selected = state::path(args.control.daemon_state.as_deref());
    state::save(&selected, &state)?;
    let secret = Arc::new(state.token.clone());
    let app = api::router(broker.clone())
        .merge(crate::mcp::broker_router(broker.clone()))
        .layer(middleware::from_fn(move |req, next| {
            authorize(req, next, secret.clone())
        }));
    eprintln!(
        "Broker listening on http://{}; state {}",
        state.address,
        selected.display()
    );
    let stopped = broker.shutdown.clone();
    let served = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            tokio::select! {
                _ = stopped.cancelled() => {},
                _ = shutdown_signal() => stopped.cancel(),
            }
        })
        .await;
    broker.close().await;
    state::remove_owned(&selected, &state);
    served?;
    Ok(())
}
fn validate_initial_listener(args: &Cli) -> Result<()> {
    if args.control.socks.is_some() && args.host.is_none() {
        anyhow::bail!("--daemon --socks requires -i to create an initial session");
    }
    Ok(())
}
async fn authorize(request: Request, next: Next, secret: Arc<String>) -> Response {
    let valid = request
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .is_some_and(|candidate| constant_time_eq(candidate.as_bytes(), secret.as_bytes()));
    if valid {
        next.run(request).await
    } else {
        (StatusCode::UNAUTHORIZED, "broker authentication required").into_response()
    }
}
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = signal.recv() => {},
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
