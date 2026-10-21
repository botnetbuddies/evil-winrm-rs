//! MCP transport and schemas; the broker owns all persistent sessions.
mod http;
mod tools;
use crate::broker::Broker;
pub use http::{router, serve};
use rmcp::{
    ServerHandler,
    handler::server::router::tool::ToolRouter,
    model::{ServerCapabilities, ServerConfig},
    tool_handler,
};
#[derive(Clone)]
struct Server {
    broker: Broker,
    tool_router: ToolRouter<Self>,
}
#[tool_handler(router = self.tool_router)]
impl ServerHandler for Server {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(rmcp::model::Implementation::new("evil-winrm-rs",env!("CARGO_PKG_VERSION")))
            .with_instructions("Call winrm_login first; use the returned session_id with winrm_execute, winrm_upload, winrm_download and winrm_logout. Transfer local_path values refer to the MCP server machine.")
    }
}

pub(crate) fn broker_router(broker: Broker) -> axum::Router {
    http::app(broker, Default::default())
}
