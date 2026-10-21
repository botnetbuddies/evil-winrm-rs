//! Streamable HTTP hosting and graceful broker cleanup.
use super::Server;
use crate::broker::Broker;
use anyhow::Result;
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use std::sync::Arc;
pub async fn serve(host: String, port: u16) -> Result<()> {
    let broker = Broker::default();
    let mut config = StreamableHttpServerConfig::default();
    if matches!(host.as_str(), "0.0.0.0" | "::") {
        config = config.disable_allowed_hosts();
    } else {
        config.allowed_hosts.push(host.clone());
    }
    let app = app(broker.clone(), config);
    let listener = tokio::net::TcpListener::bind((host.as_str(), port)).await?;
    eprintln!("MCP listening on http://{host}:{port}/mcp");
    let shutdown = broker.shutdown.clone();
    let served = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            shutdown.cancel();
        })
        .await;
    broker.close().await;
    served?;
    Ok(())
}
pub fn router() -> axum::Router {
    app(Broker::default(), Default::default())
}
pub(crate) fn app(broker: Broker, mut config: StreamableHttpServerConfig) -> axum::Router {
    config.cancellation_token = broker.shutdown.clone();
    let factory = Server::new(broker);
    let service = StreamableHttpService::new(
        move || Ok(factory.clone()),
        Arc::new(LocalSessionManager::default()),
        config,
    );
    axum::Router::new().nest_service("/mcp", service)
}
