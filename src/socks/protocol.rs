//! SOCKS5 CONNECT negotiation; address names are resolved on Windows.
use anyhow::{Result, bail};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
pub(super) struct Destination {
    pub host: String,
    pub port: u16,
}
pub(super) async fn negotiate(stream: &mut TcpStream) -> Result<Destination> {
    if stream.read_u8().await? != 5 {
        bail!("unsupported SOCKS version");
    }
    let count = stream.read_u8().await? as usize;
    let mut methods = vec![0; count];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        stream.write_all(&[5, 255]).await?;
        bail!("client did not offer no-authentication SOCKS5");
    }
    stream.write_all(&[5, 0]).await?;
    let mut request = [0; 4];
    stream.read_exact(&mut request).await?;
    if request[0] != 5 || request[2] != 0 {
        reply(stream, 1).await?;
        bail!("invalid SOCKS5 request");
    }
    if request[1] != 1 {
        reply(stream, 7).await?;
        bail!("only SOCKS CONNECT is supported");
    }
    let host = match request[3] {
        1 => {
            let mut ip = [0; 4];
            stream.read_exact(&mut ip).await?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        4 => {
            let mut ip = [0; 16];
            stream.read_exact(&mut ip).await?;
            std::net::Ipv6Addr::from(ip).to_string()
        }
        3 => {
            let len = stream.read_u8().await? as usize;
            let mut name = vec![0; len];
            stream.read_exact(&mut name).await?;
            String::from_utf8(name)?
        }
        _ => {
            reply(stream, 8).await?;
            bail!("unsupported SOCKS address type");
        }
    };
    let port = stream.read_u16().await?;
    if host.is_empty() || host.contains(['\0', '\r', '\n']) || port == 0 {
        reply(stream, 1).await?;
        bail!("invalid SOCKS destination");
    }
    Ok(Destination { host, port })
}
pub(super) async fn reply(stream: &mut TcpStream, status: u8) -> Result<()> {
    stream
        .write_all(&[5, status, 0, 1, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}
