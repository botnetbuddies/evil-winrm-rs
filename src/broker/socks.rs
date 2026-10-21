//! Listener ownership follows its parent broker session.
use super::{
    Broker,
    models::{SocksStart, SocksStop},
};
use crate::socks::{Listener, ListenerInfo};
use anyhow::{Context, Result, bail};
impl Broker {
    pub async fn start_socks(&self, args: SocksStart) -> Result<ListenerInfo> {
        let (id, entry) = self.resolve(args.session_id).await?;
        if entry.session.jea {
            bail!("SOCKS requires a full-language endpoint");
        }
        let listener_id = self
            .next_listener
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let listener = Listener::start(
            listener_id,
            id,
            args.bind,
            args.max_connections,
            entry.profile,
            &self.shutdown,
        )
        .await?;
        let info = listener.info.clone();
        self.listeners.lock().await.insert(listener_id, listener);
        Ok(info)
    }
    pub async fn list_socks(&self) -> Vec<ListenerInfo> {
        self.listeners
            .lock()
            .await
            .values()
            .map(|l| l.info.clone())
            .collect()
    }
    pub async fn stop_socks(&self, args: SocksStop) -> Result<()> {
        let listener = self
            .listeners
            .lock()
            .await
            .remove(&args.listener_id)
            .context("unknown SOCKS listener")?;
        listener.stop().await;
        Ok(())
    }
    pub(super) async fn stop_session_listeners(&self, id: u64) {
        let mut listeners = self.listeners.lock().await;
        let ids: Vec<_> = listeners
            .iter()
            .filter(|(_, l)| l.info.session_id == id)
            .map(|(id, _)| *id)
            .collect();
        let stopped: Vec<_> = ids
            .into_iter()
            .filter_map(|id| listeners.remove(&id))
            .collect();
        drop(listeners);
        for listener in stopped {
            listener.stop().await;
        }
    }
}
