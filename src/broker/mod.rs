//! One owner for persistent sessions, shared by CLI control and MCP adapters.
mod api;
pub mod cli;
pub mod client;
pub mod daemon;
mod execution;
mod login;
pub mod models;
mod socks;
mod state;
mod stream;
#[cfg(windows)]
mod windows;
use crate::{connection::ConnectionProfile, session::Session};
use anyhow::{Context, Result, bail};
use models::{Login, SessionInfo};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub(crate) struct Entry {
    pub session: Session,
    pub profile: ConnectionProfile,
    pub info: SessionInfo,
    pub lease: Arc<Mutex<()>>,
}
#[derive(Clone)]
pub struct Broker {
    sessions: Arc<Mutex<BTreeMap<u64, Entry>>>,
    jobs: Arc<Mutex<BTreeMap<(u64, String), CancellationToken>>>,
    next_id: Arc<AtomicU64>,
    next_listener: Arc<AtomicU64>,
    listeners: Arc<Mutex<BTreeMap<u64, crate::socks::Listener>>>,
    pub(crate) shutdown: CancellationToken,
}
impl Default for Broker {
    fn default() -> Self {
        Self {
            sessions: Default::default(),
            jobs: Default::default(),
            next_id: Arc::new(AtomicU64::new(1)),
            next_listener: Arc::new(AtomicU64::new(1)),
            listeners: Default::default(),
            shutdown: CancellationToken::new(),
        }
    }
}
impl Broker {
    pub async fn login(&self, args: Login) -> Result<SessionInfo> {
        self.open(args.profile()?).await
    }
    pub(crate) async fn open(&self, profile: ConnectionProfile) -> Result<SessionInfo> {
        if self.shutdown.is_cancelled() {
            bail!("broker is shutting down");
        }
        let session = profile.connect().await?;
        let mut sessions = self.sessions.lock().await;
        if self.shutdown.is_cancelled() {
            drop(sessions);
            let _ = session.close().await;
            bail!("broker is shutting down");
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let info = SessionInfo {
            host: profile.host.clone(),
            username: profile.username(),
            session_id: id,
            jea: session.jea,
            description: format!(
                "connected to {}:{} as {}{}",
                profile.host,
                profile.config.port,
                profile.username(),
                if session.jea { " [JEA]" } else { "" }
            ),
        };
        sessions.insert(
            id,
            Entry {
                session,
                profile,
                info: info.clone(),
                lease: Arc::new(Mutex::new(())),
            },
        );
        Ok(info)
    }
    pub(crate) async fn resolve(&self, id: Option<u64>) -> Result<(u64, Entry)> {
        let mut sessions = self.sessions.lock().await;
        sessions.retain(|_, entry| entry.session.is_open());
        let id = match id {
            Some(id) => id,
            None if sessions.len() == 1 => *sessions.first_key_value().unwrap().0,
            None if sessions.is_empty() => {
                bail!("No active WinRM session. Call winrm_login first.")
            }
            None => bail!("Multiple sessions are active. Pass session_id to choose one."),
        };
        Ok((
            id,
            sessions
                .get(&id)
                .cloned()
                .context("No active session with this id")?,
        ))
    }
    pub async fn list(&self) -> Vec<SessionInfo> {
        let mut sessions = self.sessions.lock().await;
        sessions.retain(|_, entry| entry.session.is_open());
        sessions.values().map(|entry| entry.info.clone()).collect()
    }
    pub async fn logout(&self, id: Option<u64>) -> Result<u64> {
        let (id, entry) = self.resolve(id).await?;
        self.sessions.lock().await.remove(&id);
        self.stop_session_listeners(id).await;
        entry.session.cancel_current();
        let _lease = entry.lease.lock().await;
        entry.session.close().await?;
        Ok(id)
    }
    pub async fn close(&self) {
        self.shutdown.cancel();
        let listeners = std::mem::take(&mut *self.listeners.lock().await);
        for (_, listener) in listeners {
            listener.stop().await;
        }
        let entries = std::mem::take(&mut *self.sessions.lock().await);
        let mut cleanup = tokio::task::JoinSet::new();
        for (_, entry) in entries {
            entry.session.cancel_current();
            cleanup.spawn(async move {
                let _ =
                    tokio::time::timeout(std::time::Duration::from_secs(15), entry.session.close())
                        .await;
            });
        }
        while cleanup.join_next().await.is_some() {}
    }
}
