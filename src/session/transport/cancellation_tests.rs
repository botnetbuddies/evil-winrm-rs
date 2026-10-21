//! A stop acknowledgement can depend on more than one outstanding Receive.
use super::*;
use axum::{extract::State, http::StatusCode, routing::post};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Notify;
use winrm_rs::{AuthMethod, WinrmClient, WinrmConfig, WinrmCredentials};

#[derive(Default)]
struct Server {
    receives: AtomicUsize,
    drained: Notify,
    reject_stop: bool,
}

async fn request(State(state): State<Arc<Server>>, body: String) -> (StatusCode, String) {
    let xml = roxmltree::Document::parse(&body).unwrap();
    let action = xml
        .descendants()
        .find(|node| node.tag_name().name() == "Action")
        .unwrap()
        .text()
        .unwrap()
        .to_owned();
    // Do not hold the XML document (which is not Send) across await.
    drop(xml);
    let response = if action.ends_with("/Create") {
        "<rsp:Shell><rsp:ShellId>CANCEL-TEST</rsp:ShellId></rsp:Shell>".into()
    } else if action.ends_with("/Receive") {
        let n = state.receives.fetch_add(1, Ordering::SeqCst) + 1;
        state.drained.notify_one();
        format!(
            "<rsp:ReceiveResponse><rsp:Stream Name='stdout'>{}</rsp:Stream></rsp:ReceiveResponse>",
            B64.encode([n as u8])
        )
    } else if action.ends_with("/Signal") {
        if state.reject_stop {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope'><s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value><s:Subcode><s:Value>w:AccessDenied</s:Value></s:Subcode></s:Code><s:Reason><s:Text>stop denied</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>".into(),
            );
        }
        // One in-flight Receive is insufficient. A client which waits for
        // Signal before polling again will deadlock here.
        while state.receives.load(Ordering::SeqCst) < 2 {
            state.drained.notified().await;
        }
        "<rsp:SignalResponse/>".into()
    } else if action.ends_with("/Delete") {
        String::new()
    } else {
        panic!("unexpected SOAP action: {action}");
    };
    (
        StatusCode::OK,
        format!(
            "<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:rsp='http://schemas.microsoft.com/wbem/wsman/1/windows/shell'><s:Body>{response}</s:Body></s:Envelope>"
        ),
    )
}

async fn fixture(reject_stop: bool) -> (Transport, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = Server {
        reject_stop,
        ..Default::default()
    };
    let app = axum::Router::new()
        .route("/wsman", post(request))
        .with_state(Arc::new(server));
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = WinrmClient::new(
        WinrmConfig {
            port,
            auth_method: AuthMethod::Basic,
            ..Default::default()
        },
        WinrmCredentials::new("fixture", "fixture", ""),
    )
    .unwrap();
    let shell = client
        .open_psrp_shell(
            "127.0.0.1",
            "",
            "http://schemas.microsoft.com/powershell/Microsoft.PowerShell",
        )
        .await
        .unwrap()
        .into_owned();
    (
        Transport {
            shell: Some(shell),
            command_id: "PIPELINE-TEST".into(),
            pending_receive: None,
            stop: super::super::stop::StopRequest::default(),
            max_send_bytes: 100_000,
            output_budget: Arc::new(super::super::limits::OutputBudget::new(None)),
        },
        task,
    )
}

#[tokio::test]
async fn stop_drains_multiple_receives_before_acknowledgement() {
    let (mut transport, server) = fixture(false).await;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        transport.signal_stop().await.unwrap();
        assert_eq!(transport.recv_chunk().await.unwrap(), [1]);
        assert_eq!(transport.recv_chunk().await.unwrap(), [2]);
        transport.stop.complete().await.unwrap();
        assert!(transport.stop.acknowledged());
        // Completing/cancelling stop must leave the transport usable.
        assert_eq!(transport.recv_chunk().await.unwrap(), [3]);
        transport.close_shell().await.unwrap();
    })
    .await
    .expect("stop waited for an acknowledgement instead of draining output");
    server.abort();
}

#[tokio::test]
async fn asynchronous_stop_errors_are_not_discarded() {
    let (mut transport, server) = fixture(true).await;
    transport.signal_stop().await.unwrap();
    let error = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if let Err(error) = transport.recv_chunk().await {
                break error;
            }
        }
    })
    .await
    .expect("stop failure was never observed");
    assert!(error.to_string().contains("stop denied"), "{error}");
    transport.close_shell().await.unwrap();
    server.abort();
}
