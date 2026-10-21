//! Opted-in network interoperability: only a temporary loopback echo server is created.
#![cfg(feature = "mcp")]
use anyhow::{Context, Result};
use evil_winrm_rs::{
    broker::{
        Broker,
        models::{ExecutionRequest, Login, SocksStart, SocksStop},
    },
    command::quote,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

async fn command(broker: &Broker, text: String) -> Result<String> {
    let reply = broker
        .execute(
            ExecutionRequest {
                session_id: None,
                text,
                raw: true,
                status: false,
                request_id: uuid::Uuid::new_v4().to_string(),
            },
            None,
        )
        .await?;
    if let Some(error) = reply.error {
        anyhow::bail!(error);
    }
    reply.output.context("missing output")?.checked()
}

#[tokio::test]
#[ignore = "requires WINRM_HOST/USER/PASSWORD and a full-language Windows endpoint"]
async fn socks_preserves_binary_data_half_close_and_listener_ownership() -> Result<()> {
    let get = |name| std::env::var(name).ok();
    let broker = Broker::default();
    broker
        .login(Login {
            ip: get("WINRM_HOST").context("set WINRM_HOST")?,
            username: get("WINRM_USER").unwrap_or_default(),
            password: get("WINRM_PASSWORD").unwrap_or_default(),
            auth: Some(get("WINRM_AUTH").unwrap_or_else(|| "ntlm".into())),
            ssl: get("WINRM_TLS").as_deref() == Some("1"),
            cert_pem: get("WINRM_CERT_PEM"),
            priv_key_pem: get("WINRM_KEY_PEM"),
            ccache: get("WINRM_CCACHE"),
            spn_hostname: get("WINRM_SPN_HOSTNAME"),
            ..Default::default()
        })
        .await?;
    let result = async {
        let ports = command(&broker, format!(
            "Add-Type -TypeDefinition {}; $global:ewrEcho4=New-Object EwrTcpEcho($false); $global:ewrEcho6=New-Object EwrTcpEcho($true); @{{v4=$global:ewrEcho4.Port;v6=$global:ewrEcho6.Port}}|ConvertTo-Json -Compress",
            quote(include_str!("fixtures/tcp_echo.cs"))
        )).await?;
        let ports: serde_json::Value = serde_json::from_str(ports.trim())?;
        let listener = broker
            .start_socks(SocksStart {
                session_id: None,
                bind: "127.0.0.1:0".parse()?,
                max_connections: 2,
            })
            .await?;
        for (kind, host, port) in [
            (
                1u8,
                vec![127, 0, 0, 1],
                ports["v4"].as_u64().unwrap() as u16,
            ),
            (
                3u8,
                b"\x09localhost".to_vec(),
                ports["v4"].as_u64().unwrap() as u16,
            ),
            (
                4u8,
                std::net::Ipv6Addr::LOCALHOST.octets().to_vec(),
                ports["v6"].as_u64().unwrap() as u16,
            ),
        ] {
            let mut socket = TcpStream::connect(listener.address).await?;
            socket.write_all(&[5, 1, 0]).await?;
            let mut method = [0; 2];
            socket.read_exact(&mut method).await?;
            assert_eq!(method, [5, 0]);
            let mut request = vec![5, 1, 0, kind];
            request.extend(host);
            request.extend(port.to_be_bytes());
            socket.write_all(&request).await?;
            let mut response = [0; 10];
            socket.read_exact(&mut response).await?;
            assert_eq!(response[1], 0);
            let mut hello = [0; 5];
            socket.read_exact(&mut hello).await?;
            assert_eq!(&hello, b"HELLO");
            let data: Vec<_> = (0..262_193).map(|i| (i % 251) as u8).collect();
            let (mut read, mut write) = socket.into_split();
            let send = async {
                write.write_all(&data).await?;
                write.shutdown().await
            };
            let receive = async {
                let mut output = Vec::new();
                read.read_to_end(&mut output).await?;
                Ok::<_, std::io::Error>(output)
            };
            let (_, output) = tokio::try_join!(send, receive)?;
            assert_eq!(&output[..data.len()], data.as_slice());
            assert_eq!(&output[data.len()..], b"BYE");
        }
        broker
            .stop_socks(SocksStop {
                listener_id: listener.listener_id,
            })
            .await?;
        assert!(broker.list_socks().await.is_empty());
        command(
            &broker,
            "$global:ewrEcho4.Dispose(); $global:ewrEcho6.Dispose()".into(),
        )
        .await?;
        broker.logout(None).await?;
        assert!(broker.list().await.is_empty());
        Ok::<_, anyhow::Error>(())
    };
    let result = tokio::time::timeout(std::time::Duration::from_secs(90), result).await;
    // These also run if an assertion above fails through an ordinary error path.
    let _ = command(
        &broker,
        "$global:ewrEcho4.Dispose(); $global:ewrEcho6.Dispose()".into(),
    )
    .await;
    let _ = broker.logout(None).await;
    broker.close().await;
    result?
}
