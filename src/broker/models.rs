//! Wire types shared by local control clients and MCP tool schemas.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Default, Deserialize, Serialize, JsonSchema)]
pub struct Login {
    pub ip: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    pub port: Option<u16>,
    #[serde(default)]
    pub ssl: bool,
    pub uri: Option<String>,
    pub auth: Option<String>,
    pub encryption: Option<String>,
    pub proxy: Option<String>,
    pub ua: Option<String>,
    pub spn_prefix: Option<String>,
    pub spn_hostname: Option<String>,
    pub priv_key_pem: Option<String>,
    pub cert_pem: Option<String>,
    pub pfx: Option<String>,
    pub pfx_password_file: Option<String>,
    pub pfx_password: Option<String>,
    pub ca_cert: Option<String>,
    pub tls_server_name: Option<String>,
    #[serde(default)]
    pub verify_tls: bool,
    pub ccache: Option<String>,
    pub keytab: Option<String>,
    pub realm: Option<String>,
    pub configuration_name: Option<String>,
    pub max_output: Option<usize>,
    pub hash: Option<String>,
    pub directory: Option<String>,
    #[serde(default)]
    pub environment: Vec<(String, String)>,
    pub connect_timeout: Option<u64>,
    pub operation_timeout: Option<u64>,
    pub idle_timeout: Option<u64>,
    pub retries: Option<u32>,
    pub max_envelope: Option<u32>,
}
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct Execute {
    pub command: String,
    pub session_id: Option<u64>,
}
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct SessionId {
    pub session_id: Option<u64>,
}
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct Upload {
    /// Path on the broker/MCP server machine.
    pub local_path: String,
    pub remote_path: Option<String>,
    pub session_id: Option<u64>,
    #[serde(default)]
    pub resume: bool,
    #[serde(default)]
    pub compress: bool,
}
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct Download {
    pub remote_path: String,
    /// Path on the broker/MCP server machine.
    pub local_path: String,
    pub session_id: Option<u64>,
    #[serde(default)]
    pub resume: bool,
    #[serde(default)]
    pub compress: bool,
}
#[derive(Clone, Deserialize, Serialize)]
pub struct SessionInfo {
    pub host: String,
    pub username: String,
    pub session_id: u64,
    pub description: String,
    pub jea: bool,
}
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct SocksStart {
    pub session_id: Option<u64>,
    #[serde(default = "default_socks_bind")]
    pub bind: std::net::SocketAddr,
    #[serde(default = "default_socks_max")]
    pub max_connections: usize,
}
fn default_socks_bind() -> std::net::SocketAddr {
    "127.0.0.1:1080".parse().unwrap()
}
fn default_socks_max() -> usize {
    4
}
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct SocksStop {
    pub listener_id: u64,
}
#[derive(Deserialize, Serialize)]
pub struct ExecutionRequest {
    pub session_id: Option<u64>,
    pub text: String,
    #[serde(default)]
    pub raw: bool,
    #[serde(default)]
    pub status: bool,
    #[serde(default = "request_id")]
    pub request_id: String,
}
fn request_id() -> String {
    uuid::Uuid::new_v4().to_string()
}
#[derive(Deserialize, Serialize)]
pub struct ExecutionReply {
    pub output: Option<crate::session::Output>,
    pub console: Vec<crate::session::ConsoleEvent>,
    pub error: Option<String>,
    pub open: bool,
}
#[derive(Deserialize, Serialize)]
pub struct AttachInfo {
    pub info: SessionInfo,
    pub initial_functions: Vec<String>,
}
#[derive(Deserialize, Serialize)]
pub struct Cancel {
    pub session_id: Option<u64>,
    pub request_id: String,
}
