//! Loopback SOCKS5 listeners with bounded concurrency and explicit lifetimes.
mod protocol;
mod scripts;
mod tunnel;
use crate::connection::ConnectionProfile;
use anyhow::{Result, bail};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
};
use tokio_util::sync::CancellationToken;
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ListenerInfo {
    pub listener_id: u64,
    pub session_id: u64,
    pub address: SocketAddr,
    pub max_connections: usize,
}
pub(crate) struct Listener {
    pub info: ListenerInfo,
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}
pub async fn serve(profile: ConnectionProfile, address: SocketAddr, max: usize) -> Result<()> {
    let stopped = CancellationToken::new();
    let listener = Listener::start(0, 0, address, max, profile, &stopped).await?;
    eprintln!("SOCKS listening on {}", listener.info.address);
    let signal = tokio::signal::ctrl_c().await;
    listener.stop().await;
    signal?;
    Ok(())
}
impl Listener {
    pub async fn start(
        id: u64,
        session_id: u64,
        address: SocketAddr,
        max: usize,
        profile: ConnectionProfile,
        parent: &CancellationToken,
    ) -> Result<Self> {
        if !address.ip().is_loopback() {
            bail!("SOCKS listeners must bind a loopback address");
        }
        if !(1..=128).contains(&max) {
            bail!("SOCKS connection limit must be between 1 and 128");
        }
        let listener = TcpListener::bind(address).await?;
        let address = listener.local_addr()?;
        let info = ListenerInfo {
            listener_id: id,
            session_id,
            address,
            max_connections: max,
        };
        let cancel = parent.child_token();
        let stopped = cancel.clone();
        let task = tokio::spawn(async move {
            let slots = Arc::new(Semaphore::new(max));
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = stopped.cancelled() => break,
                    Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break };
                        let permit = slots.clone().try_acquire_owned().ok();
                        tasks.spawn(connection(stream, permit, profile.clone(), stopped.child_token()));
                    }
                }
            }
            while tasks.join_next().await.is_some() {}
        });
        Ok(Self { info, cancel, task })
    }
    pub async fn stop(mut self) {
        self.cancel.cancel();
        if tokio::time::timeout(Duration::from_secs(20), &mut self.task)
            .await
            .is_err()
        {
            self.task.abort();
        }
    }
}

async fn connection(
    mut stream: TcpStream,
    permit: Option<OwnedSemaphorePermit>,
    profile: ConnectionProfile,
    cancel: CancellationToken,
) {
    let _ = stream.set_nodelay(true);
    let destination = tokio::select! {
        _ = cancel.cancelled() => return,
        result = tokio::time::timeout(Duration::from_secs(10), protocol::negotiate(&mut stream)) => {
            match result {
                Ok(Ok(destination)) => destination,
                _ => return,
            }
        }
    };
    let Some(_permit) = permit else {
        let _ = protocol::reply(&mut stream, 1).await;
        return;
    };
    if let Err(error) = tunnel::run(stream, profile, destination, cancel).await {
        tracing::debug!(error = %error, "SOCKS connection closed");
    }
}
