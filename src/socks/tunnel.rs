//! Per-connection runspace ownership, bounded duplex forwarding and cleanup.
use super::protocol::{Destination, reply};
use crate::{connection::ConnectionProfile, session::Session};
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde::Deserialize;
use std::time::Duration;
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_util::sync::CancellationToken;
const BLOCK: usize = 64 * 1024;

#[derive(Deserialize)]
struct Poll {
    data: String,
    closed: bool,
}
struct RemoteSocket {
    session: Session,
    id: String,
}
impl RemoteSocket {
    async fn open(
        profile: ConnectionProfile,
        destination: Destination,
        cancel: &CancellationToken,
    ) -> Result<Self> {
        let session = tokio::select! {
            _ = cancel.cancelled() => bail!("SOCKS connection cancelled"),
            session = profile.connect() => session?,
        };
        let socket = Self {
            session,
            id: format!("ewrSocket{}", uuid::Uuid::new_v4().simple()),
        };
        let connect = super::scripts::connect(&socket.id, &destination.host, destination.port);
        let result = socket
            .session
            .raw_cancellable(&connect, cancel.child_token())
            .await;
        if let Err(error) = result {
            socket.close().await;
            return Err(error.context("remote SOCKS connection"));
        }
        Ok(socket)
    }
    async fn exchange(
        &self,
        bytes: &[u8],
        close_send: bool,
        cancel: &CancellationToken,
    ) -> Result<Poll> {
        let script = super::scripts::poll(&self.id, &B64.encode(bytes), close_send);
        let output = self
            .session
            .raw_cancellable(&script, cancel.child_token())
            .await?;
        serde_json::from_str(output.trim()).context("decoding remote SOCKS poll")
    }
    async fn close(self) {
        let _ = tokio::time::timeout(
            Duration::from_secs(3),
            self.session.raw(&super::scripts::close(&self.id)),
        )
        .await;
        let _ = tokio::time::timeout(Duration::from_secs(10), self.session.close()).await;
    }
}
pub(super) async fn run(
    mut local: TcpStream,
    profile: ConnectionProfile,
    destination: Destination,
    cancel: CancellationToken,
) -> Result<()> {
    let remote = match RemoteSocket::open(profile, destination, &cancel).await {
        Ok(remote) => remote,
        Err(error) => {
            let _ = reply(&mut local, 5).await;
            return Err(error);
        }
    };
    let result = pump(&mut local, &remote, &cancel).await;
    remote.close().await;
    result
}
async fn pump(
    local: &mut TcpStream,
    remote: &RemoteSocket,
    cancel: &CancellationToken,
) -> Result<()> {
    reply(local, 0).await?;
    let mut buffer = vec![0; BLOCK];
    let mut eof = false;
    let mut shutdown_sent = false;
    let mut idle = 0u32;
    loop {
        if cancel.is_cancelled() {
            break;
        }
        let count = if eof {
            0
        } else {
            match local.try_read(&mut buffer) {
                Ok(0) => {
                    eof = true;
                    0
                }
                Ok(count) => count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => 0,
                Err(error) => return Err(error.into()),
            }
        };
        let close_send = eof && !shutdown_sent;
        shutdown_sent |= close_send;
        let response = match remote.exchange(&buffer[..count], close_send, cancel).await {
            Ok(response) => response,
            Err(_) if cancel.is_cancelled() => break,
            Err(error) => return Err(error),
        };
        let bytes = B64.decode(&response.data)?;
        tracing::debug!(
            sent = count,
            received = bytes.len(),
            close_send,
            remote_closed = response.closed,
            "SOCKS exchange"
        );
        if bytes.len() > BLOCK {
            bail!("remote SOCKS read exceeded limit");
        }
        if !bytes.is_empty() {
            tokio::select! {
                _ = cancel.cancelled() => break,
                result = local.write_all(&bytes) => result?,
            }
        }
        if response.closed {
            let _ = local.shutdown().await;
            break;
        }
        if count == 0 && bytes.is_empty() {
            idle = idle.saturating_add(1);
            let delay = Duration::from_millis(u64::from(idle.min(20)));
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(delay) => {},
                _ = local.readable(), if !eof => {},
            }
        } else {
            idle = 0;
        }
    }
    Ok(())
}
