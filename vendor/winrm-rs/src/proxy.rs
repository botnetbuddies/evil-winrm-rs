//! Explicit proxy validation and the connection tunnel used by CredSSP.
use crate::WinrmError;

/// Validate a supported explicit proxy without including its credentials in errors.
pub fn validate(value: &str) -> Result<reqwest::Url, WinrmError> {
    let url = reqwest::Url::parse(value).map_err(|_| invalid("invalid proxy URL"))?;
    if !matches!(url.scheme(), "http" | "https" | "socks5" | "socks5h")
        || url.host_str().is_none()
        || url.port() == Some(0)
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid(
            "proxy must be an http://, https://, socks5:// or socks5h:// URL with a host and optional credentials/port",
        ));
    }
    Ok(url)
}
fn invalid(message: &str) -> WinrmError {
    WinrmError::AuthFailed(message.into())
}

#[cfg(feature = "credssp")]
mod tunnel {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use std::{net::IpAddr, sync::Arc};
    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
        net::TcpStream,
    };

    pub(crate) trait Socket: AsyncRead + AsyncWrite + Unpin + Send {}
    impl<T: AsyncRead + AsyncWrite + Unpin + Send> Socket for T {}
    pub(crate) type Stream = Box<dyn Socket>;

    async fn tcp(host: &str, port: u16) -> Result<Stream, WinrmError> {
        let stream = TcpStream::connect((host.trim_matches(['[', ']']), port))
            .await
            .map_err(|_| invalid("proxy/target TCP connection failed"))?;
        stream.set_nodelay(true).ok();
        Ok(Box::new(stream))
    }
    fn decode(value: &str) -> Result<Vec<u8>, WinrmError> {
        let bytes = value.as_bytes();
        let mut result = Vec::new();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'%' {
                let digits = bytes
                    .get(index + 1..index + 3)
                    .ok_or_else(|| invalid("invalid proxy credential encoding"))?;
                let digit = |b: u8| (b as char).to_digit(16).map(|n| n as u8);
                result.push(
                    digit(digits[0])
                        .zip(digit(digits[1]))
                        .map(|(a, b)| a * 16 + b)
                        .ok_or_else(|| invalid("invalid proxy credential encoding"))?,
                );
                index += 3;
            } else {
                result.push(bytes[index]);
                index += 1;
            }
        }
        Ok(result)
    }
    #[cfg(test)]
    pub(crate) async fn connect(
        proxy: Option<&str>,
        host: &str,
        port: u16,
        insecure: bool,
    ) -> Result<Stream, WinrmError> {
        connect_with_ca(proxy, host, port, insecure, None).await
    }
    pub(crate) async fn connect_with_ca(
        proxy: Option<&str>,
        host: &str,
        port: u16,
        insecure: bool,
        ca_cert: Option<&str>,
    ) -> Result<Stream, WinrmError> {
        let Some(proxy) = proxy else {
            return tcp(host, port).await;
        };
        let proxy = validate(proxy)?;
        let proxy_host = proxy.host_str().unwrap().trim_matches(['[', ']']);
        let proxy_port = proxy.port().unwrap_or(match proxy.scheme() {
            "http" => 80,
            "https" => 443,
            _ => 1080,
        });
        let mut stream = tcp(proxy_host, proxy_port).await?;
        if proxy.scheme() == "https" {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let verifier = crate::tls::verifier(&crate::WinrmConfig {
                accept_invalid_certs: insecure,
                ca_cert: ca_cert.map(str::to_owned),
                ..Default::default()
            })?;
            let config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth();
            let name = rustls::pki_types::ServerName::try_from(proxy_host.to_owned())
                .map_err(|_| invalid("invalid proxy TLS hostname"))?;
            stream = Box::new(
                tokio_rustls::TlsConnector::from(Arc::new(config))
                    .connect(name, stream)
                    .await
                    .map_err(|_| invalid("proxy TLS negotiation failed"))?,
            );
        }
        if matches!(proxy.scheme(), "http" | "https") {
            let target = if host.contains(':') {
                format!("[{}]:{port}", host.trim_matches(['[', ']']))
            } else {
                format!("{host}:{port}")
            };
            let mut request =
                zeroize::Zeroizing::new(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"));
            if !proxy.username().is_empty() || proxy.password().is_some() {
                let mut credentials = zeroize::Zeroizing::new(decode(proxy.username())?);
                credentials.push(b':');
                credentials.extend(decode(proxy.password().unwrap_or(""))?);
                request.push_str(&format!(
                    "Proxy-Authorization: Basic {}\r\n",
                    STANDARD.encode(&*credentials)
                ));
            }
            request.push_str("\r\n");
            stream
                .write_all(request.as_bytes())
                .await
                .map_err(|_| invalid("proxy CONNECT write failed"))?;
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                if header.len() >= 16384 {
                    return Err(invalid("proxy CONNECT response headers are too large"));
                }
                header.push(
                    stream
                        .read_u8()
                        .await
                        .map_err(|_| invalid("proxy CONNECT response was incomplete"))?,
                );
            }
            let status = std::str::from_utf8(&header)
                .ok()
                .and_then(|h| h.lines().next())
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|code| code.parse::<u16>().ok());
            if status != Some(200) {
                return Err(invalid(&format!(
                    "proxy CONNECT rejected (HTTP {})",
                    status.unwrap_or(0)
                )));
            }
        } else {
            socks(&mut stream, &proxy, host, port).await?;
        }
        Ok(stream)
    }
    async fn socks(
        stream: &mut Stream,
        proxy: &reqwest::Url,
        host: &str,
        port: u16,
    ) -> Result<(), WinrmError> {
        let auth = !proxy.username().is_empty() || proxy.password().is_some();
        stream
            .write_all(if auth { &[5, 2, 0, 2] } else { &[5, 1, 0] })
            .await
            .map_err(|_| invalid("SOCKS5 greeting failed"))?;
        let mut response = [0; 2];
        stream
            .read_exact(&mut response)
            .await
            .map_err(|_| invalid("SOCKS5 greeting response failed"))?;
        match response {
            [5, 0] => (),
            [5, 2] if auth => {
                let username = zeroize::Zeroizing::new(decode(proxy.username())?);
                let password = zeroize::Zeroizing::new(decode(proxy.password().unwrap_or(""))?);
                if username.len() > 255 || password.len() > 255 {
                    return Err(invalid("SOCKS5 credentials exceed 255 bytes"));
                }
                let mut message = zeroize::Zeroizing::new(vec![1, username.len() as u8]);
                message.extend(&*username);
                message.push(password.len() as u8);
                message.extend(&*password);
                stream
                    .write_all(&message)
                    .await
                    .map_err(|_| invalid("SOCKS5 authentication write failed"))?;
                stream
                    .read_exact(&mut response)
                    .await
                    .map_err(|_| invalid("SOCKS5 authentication response failed"))?;
                if response != [1, 0] {
                    return Err(invalid("SOCKS5 authentication rejected"));
                }
            }
            _ => return Err(invalid("SOCKS5 authentication method rejected")),
        }
        let host = host.trim_matches(['[', ']']);
        let mut ip = host.parse::<IpAddr>().ok();
        if ip.is_none() && proxy.scheme() == "socks5" {
            ip = tokio::net::lookup_host((host, port))
                .await
                .map_err(|_| invalid("SOCKS5 local target DNS lookup failed"))?
                .next()
                .map(|addr| addr.ip());
            if ip.is_none() {
                return Err(invalid("SOCKS5 target resolved to no addresses"));
            }
        }
        let mut request = vec![5, 1, 0];
        match ip {
            Some(IpAddr::V4(ip)) => {
                request.push(1);
                request.extend(ip.octets());
            }
            Some(IpAddr::V6(ip)) => {
                request.push(4);
                request.extend(ip.octets());
            }
            None => {
                if host.len() > 255 {
                    return Err(invalid("SOCKS5 hostname exceeds 255 bytes"));
                }
                request.extend([3, host.len() as u8]);
                request.extend(host.as_bytes());
            }
        }
        request.extend(port.to_be_bytes());
        stream
            .write_all(&request)
            .await
            .map_err(|_| invalid("SOCKS5 CONNECT write failed"))?;
        let mut header = [0; 4];
        stream
            .read_exact(&mut header)
            .await
            .map_err(|_| invalid("SOCKS5 CONNECT response failed"))?;
        if header[0] != 5 || header[1] != 0 || header[2] != 0 {
            return Err(invalid(&format!(
                "SOCKS5 CONNECT rejected (status {})",
                header[1]
            )));
        }
        let length = match header[3] {
            1 => 4,
            4 => 16,
            3 => usize::from(
                stream
                    .read_u8()
                    .await
                    .map_err(|_| invalid("SOCKS5 bound address missing"))?,
            ),
            _ => return Err(invalid("SOCKS5 invalid address type")),
        };
        let mut address = vec![0; length + 2];
        stream
            .read_exact(&mut address)
            .await
            .map_err(|_| invalid("SOCKS5 bound address incomplete"))?;
        Ok(())
    }
}
#[cfg(all(test, feature = "credssp"))]
use tunnel::connect;
#[cfg(feature = "credssp")]
pub(crate) use tunnel::{Stream, connect_with_ca};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validation_rejects_invalid_proxies_without_echoing_credentials() {
        for value in [
            "http://127.0.0.1:8080",
            "https://user:secret@example.test:443",
            "socks5h://example.test:1080",
            "socks5://[::1]:1080",
        ] {
            assert!(validate(value).is_ok());
        }
        for value in [
            "bad",
            "ftp://user:secret@example.test",
            "http://example.test/path",
            "http://example.test:0",
        ] {
            let error = validate(value).unwrap_err().to_string();
            assert!(!error.contains("secret"));
        }
    }
    #[cfg(feature = "credssp")]
    #[tokio::test]
    async fn connect_tunnels_preserve_remote_target_and_proxy_authentication() {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        for socks in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                if socks {
                    let mut greeting = [0; 4];
                    stream.read_exact(&mut greeting).await.unwrap();
                    assert_eq!(greeting, [5, 2, 0, 2]);
                    stream.write_all(&[5, 2]).await.unwrap();
                    let mut auth = [0; 2];
                    stream.read_exact(&mut auth).await.unwrap();
                    assert_eq!(auth, [1, 4]);
                    let mut username = [0; 4];
                    stream.read_exact(&mut username).await.unwrap();
                    assert_eq!(&username, b"user");
                    assert_eq!(stream.read_u8().await.unwrap(), 5);
                    let mut password = [0; 5];
                    stream.read_exact(&mut password).await.unwrap();
                    assert_eq!(&password, b"p@ ss");
                    stream.write_all(&[1, 0]).await.unwrap();
                    let mut head = [0; 4];
                    stream.read_exact(&mut head).await.unwrap();
                    assert_eq!(head, [5, 1, 0, 3]);
                    let len = usize::from(stream.read_u8().await.unwrap());
                    let mut target = vec![0; len + 2];
                    stream.read_exact(&mut target).await.unwrap();
                    assert_eq!(&target[..len], b"proxy-only.invalid");
                    assert_eq!(&target[len..], &5986u16.to_be_bytes());
                    stream
                        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                        .await
                        .unwrap();
                } else {
                    let mut header = Vec::new();
                    while !header.ends_with(b"\r\n\r\n") {
                        header.push(stream.read_u8().await.unwrap());
                    }
                    let header = String::from_utf8(header).unwrap();
                    assert!(header.starts_with("CONNECT proxy-only.invalid:5986 HTTP/1.1\r\n"));
                    assert!(header.contains("Proxy-Authorization: Basic dXNlcjpwQCBzcw==\r\n"));
                    stream
                        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await
                        .unwrap();
                }
                let mut payload = [0; 4];
                stream.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"ping");
                stream.write_all(b"pong").await.unwrap();
            });
            let url = format!(
                "{}://user:p%40%20ss@127.0.0.1:{port}",
                if socks { "socks5h" } else { "http" }
            );
            let mut stream = connect(Some(&url), "proxy-only.invalid", 5986, false)
                .await
                .unwrap();
            stream.write_all(b"ping").await.unwrap();
            let mut reply = [0; 4];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"pong");
            server.await.unwrap();
        }
    }
    #[cfg(feature = "credssp")]
    #[tokio::test]
    async fn rejected_connect_does_not_fall_back_to_direct_connection() {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.unwrap());
            }
            stream
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let error = match connect(
            Some(&format!("http://user:super-secret@127.0.0.1:{port}")),
            "proxy-only.invalid",
            5986,
            false,
        )
        .await
        {
            Err(error) => error.to_string(),
            Ok(_) => panic!("unexpected tunnel"),
        };
        assert!(error.contains("407"));
        assert!(!error.contains("super-secret"));
        server.await.unwrap();
    }
}
