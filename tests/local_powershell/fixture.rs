//! Development-only WSMan fixture backed by a real local PowerShell process.
//! Authentication and Windows-specific helpers still need the Windows lab.
use anyhow::{Context, Result, bail};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use evil_winrm_rs::session::Session;
use std::{process::Stdio, sync::Arc};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin},
    sync::{Mutex, Notify, mpsc},
};
use winrm_rs::{AuthMethod, WinrmConfig, WinrmCredentials};

struct Backend {
    resource_uri: String,
    stdin: Arc<Mutex<ChildStdin>>,
    child: Mutex<Child>,
    output: Mutex<mpsc::Receiver<Vec<u8>>>,
    command_ack: Arc<Notify>,
    close_ack: Arc<Notify>,
    data_ack: Arc<Notify>,
    last_command: Mutex<Option<String>>,
}
impl Backend {
    async fn data(&self, text: &str) -> Result<()> {
        self.send(text).await?;
        self.data_ack.notified().await;
        Ok(())
    }
    async fn send(&self, text: &str) -> Result<()> {
        let mut stdin = self.stdin.lock().await;
        stdin.write_all(text.as_bytes()).await?;
        stdin.write_all(b"\n").await?;
        stdin.flush().await?;
        Ok(())
    }
}
fn envelope(body: &str) -> String {
    format!(
        "<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:rsp='http://schemas.microsoft.com/wbem/wsman/1/windows/shell'><s:Body>{body}</s:Body></s:Envelope>"
    )
}

async fn request(
    State(backend): State<Arc<Backend>>,
    headers: HeaderMap,
    body: String,
) -> (StatusCode, String) {
    let result = handle(&backend, &headers, &body).await;
    match result {
        Ok(body) => (StatusCode::OK, envelope(&body)),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}
async fn handle(backend: &Backend, headers: &HeaderMap, body: &str) -> Result<String> {
    if body.len() > 153_600 {
        bail!("SOAP envelope exceeds advertised MaxEnvelopeSize");
    }
    if !headers
        .get("authorization")
        .context("missing basic auth")?
        .to_str()?
        .starts_with("Basic ")
    {
        bail!("wrong authentication in fixture");
    }
    if headers.get("user-agent").context("missing user agent")? != "Ewr-Integration-Test" {
        bail!("custom user agent not forwarded");
    }
    let xml = roxmltree::Document::parse(body)?;
    let text = |name: &str| {
        xml.descendants()
            .find(|n| n.tag_name().name() == name)
            .and_then(|n| n.text())
    };
    let action = text("Action").context("missing action")?;
    if text("ResourceURI") != Some(backend.resource_uri.as_str()) {
        bail!("request addressed the wrong PowerShell endpoint");
    }
    if std::env::var_os("EWR_TRACE_FIXTURE").is_some() {
        eprintln!("action {action}");
    }
    if action.ends_with("/Create") {
        let fragments = text("creationXml").context("missing creation fragments")?;
        backend
            .data(&format!(
                "<Data Stream='Default' PSGuid='{}'>{fragments}</Data>",
                uuid::Uuid::nil()
            ))
            .await?;
        Ok("<rsp:Shell><rsp:ShellId>LOCAL-POWERSHELL</rsp:ShellId></rsp:Shell>".into())
    } else if action.ends_with("/Command") {
        let id = xml
            .descendants()
            .find(|n| n.tag_name().name() == "CommandLine")
            .and_then(|n| n.attribute("CommandId"))
            .context("missing pipeline id")?;
        let mut last_command = backend.last_command.lock().await;
        if last_command.is_some() {
            bail!("previous command was not acknowledged with a terminate signal");
        }
        *last_command = Some(id.into());
        drop(last_command);
        backend.send(&format!("<Command PSGuid='{id}' />")).await?;
        backend.command_ack.notified().await;
        let fragments = text("Arguments").context("missing command fragments")?;
        backend
            .data(&format!(
                "<Data Stream='Default' PSGuid='{id}'>{fragments}</Data>"
            ))
            .await?;
        Ok(format!(
            "<rsp:CommandResponse><rsp:CommandId>{id}</rsp:CommandId></rsp:CommandResponse>"
        ))
    } else if action.ends_with("/Send") {
        let stream = xml
            .descendants()
            .find(|n| n.tag_name().name() == "Stream")
            .context("missing input stream")?;
        let id = stream
            .attribute("CommandId")
            .unwrap_or("00000000-0000-0000-0000-000000000000");
        let priority = if stream.attribute("Name") == Some("pr") {
            "PromptResponse"
        } else {
            "Default"
        };
        backend
            .data(&format!(
                "<Data Stream='{priority}' PSGuid='{id}'>{}</Data>",
                stream.text().unwrap_or("")
            ))
            .await?;
        Ok("<rsp:SendResponse/>".into())
    } else if action.ends_with("/Receive") {
        let mut output = backend.output.lock().await;
        // Real WinRM long polls return an HTTP 500 SOAP TimedOut fault while
        // a pipeline is running. Reproduce this without a ten-second delay.
        let data = tokio::time::timeout(std::time::Duration::from_millis(100), output.recv())
            .await.map_err(|_| anyhow::anyhow!("<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope'><s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value><s:Subcode><s:Value>w:TimedOut</s:Value></s:Subcode></s:Code><s:Reason><s:Text>Receive poll timed out</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>"))?
            .context("PowerShell exited")?;
        Ok(format!(
            "<rsp:ReceiveResponse><rsp:Stream Name='stdout'>{}</rsp:Stream></rsp:ReceiveResponse>",
            B64.encode(data)
        ))
    } else if action.ends_with("/Signal") {
        let mut last_command = backend.last_command.lock().await;
        let id = last_command.as_ref().context("signal without a command")?;
        let signal = xml
            .descendants()
            .find(|n| n.tag_name().name() == "Signal")
            .context("missing signal")?;
        if signal.attribute("CommandId") != Some(id.as_str()) {
            bail!("signal addressed the wrong command");
        }
        if text("Code")
            .context("missing signal code")?
            .to_ascii_lowercase()
            .ends_with("/terminate")
        {
            backend.send(&format!("<Close PSGuid='{id}' />")).await?;
            backend.close_ack.notified().await;
            *last_command = None;
        } else {
            if text("Code") != Some("powershell/signal/ctrl_c") {
                bail!("PowerShell pipelines require the PSRP Ctrl+C signal code");
            }
            backend.send(&format!("<Signal PSGuid='{id}' />")).await?;
        }
        Ok("<rsp:SignalResponse/>".into())
    } else if action.ends_with("/Delete") {
        backend.child.lock().await.kill().await?;
        Ok(String::new())
    } else {
        bail!("unsupported fixture action: {action}");
    }
}

pub(super) async fn fixture() -> Result<(u16, tokio::task::JoinHandle<()>)> {
    fixture_with_configuration("Microsoft.PowerShell", None).await
}

pub(super) async fn fixture_with_configuration(
    configuration: &str,
    file: Option<&std::path::Path>,
) -> Result<(u16, tokio::task::JoinHandle<()>)> {
    let mut command = tokio::process::Command::new("pwsh");
    command.args([
        "-NoLogo",
        "-NoProfile",
        if file.is_some() {
            "-SSHServerMode"
        } else {
            "-ServerMode"
        },
    ]);
    if let Some(file) = file {
        command.arg("-ConfigurationFile").arg(file);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .context("pwsh is required for this ignored test")?;
    let stdin = Arc::new(Mutex::new(child.stdin.take().unwrap()));
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let (tx, rx) = mpsc::channel(128);
    let command_ack = Arc::new(Notify::new());
    let close_ack = Arc::new(Notify::new());
    let close_ack_reader = close_ack.clone();
    let data_ack = Arc::new(Notify::new());
    let data_ack_reader = data_ack.clone();
    let ack = command_ack.clone();
    tokio::spawn(async move {
        while let Ok(Some(line)) = lines.next_line().await {
            if let Ok(xml) = roxmltree::Document::parse(&line) {
                let node = xml.root_element();
                if std::env::var_os("EWR_TRACE_FIXTURE").is_some() {
                    eprintln!("frame {}", node.tag_name().name());
                }
                if node.tag_name().name() == "Data" {
                    let data = B64.decode(node.text().unwrap_or("")).unwrap();
                    if tx.send(data).await.is_err() {
                        break;
                    }
                } else if node.tag_name().name() == "CommandAck" {
                    ack.notify_one();
                } else if node.tag_name().name() == "CloseAck" {
                    close_ack_reader.notify_one();
                } else if node.tag_name().name() == "DataAck" {
                    data_ack_reader.notify_one();
                }
            }
        }
    });
    let backend = Arc::new(Backend {
        resource_uri: format!("http://schemas.microsoft.com/powershell/{configuration}"),
        stdin,
        child: Mutex::new(child),
        output: Mutex::new(rx),
        command_ack,
        close_ack,
        data_ack,
        last_command: Mutex::new(None),
    });
    let app = axum::Router::new()
        .route("/custom/wsman", post(request))
        .with_state(backend);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Ok((port, task))
}

pub(super) async fn fixture_session(port: u16, configuration: &str) -> Result<Session> {
    Session::connect(
        "127.0.0.1".into(),
        WinrmConfig {
            port,
            auth_method: AuthMethod::Basic,
            endpoint_path: "/custom/wsman".into(),
            user_agent: Some("Ewr-Integration-Test".into()),
            ..Default::default()
        },
        WinrmCredentials::new("fixture", "fixture", ""),
        configuration.into(),
    )
    .await
}
