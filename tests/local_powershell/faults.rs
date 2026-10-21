//! Development-only WSMan fixture backed by a real local PowerShell process.
//! Authentication and Windows-specific helpers still need the Windows lab.
use anyhow::{Context, Result};
use evil_winrm_rs::{command::quote, transfer};
use tokio_util::sync::CancellationToken;

use super::fixture::{fixture, fixture_session};
async fn disconnecting_proxy(
    target: u16,
) -> Result<(u16, CancellationToken, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let disconnect = CancellationToken::new();
    let token = disconnect.clone();
    let task = tokio::spawn(async move {
        while let Ok((mut incoming, _)) = listener.accept().await {
            let token = token.clone();
            tokio::spawn(async move {
                if let Ok(mut outgoing) =
                    tokio::net::TcpStream::connect(("127.0.0.1", target)).await
                {
                    tokio::select! {
                        _ = token.cancelled() => {},
                        _ = tokio::io::copy_bidirectional(&mut incoming, &mut outgoing) => {},
                    }
                }
            });
        }
    });
    Ok((port, disconnect, task))
}

#[tokio::test]
#[ignore = "requires local pwsh; adversarial transfer metadata and corrupted chunks"]
async fn transfer_faults_preserve_destinations_and_reject_traversal() -> Result<()> {
    let (port, server) = fixture().await?;
    let session = fixture_session(port, "Microsoft.PowerShell").await?;
    let root = tempfile::tempdir()?;
    let remote = root.path().join("remote.bin");
    let local = root.path().join("local.bin");
    let input = root.path().join("input.bin");
    std::fs::write(&remote, b"original remote destination")?;
    std::fs::write(&local, b"original local destination")?;
    std::fs::write(&input, vec![17; 150_000])?;
    session
        .raw("function global:Get-FileHash { [pscustomobject]@{ Hash=('0'*32) } }")
        .await?;
    let error = transfer::upload(&session, &input, Some(remote.to_str().unwrap()))
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("upload checksum mismatch"));
    assert_eq!(std::fs::read(&remote)?, b"original remote destination");
    assert!(
        !std::fs::read_dir(root.path())?.any(|e| e
            .unwrap()
            .path()
            .extension()
            .is_some_and(|e| e == "part"))
    );
    let error = transfer::download(&session, remote.to_str().unwrap(), Some(&local))
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("download checksum mismatch"));
    assert_eq!(std::fs::read(&local)?, b"original local destination");
    session.raw("Remove-Item Function:\\Get-FileHash").await?;
    std::fs::write(&remote, vec![42; 2_100_000])?;
    for allocation in ["0", "$Count+1"] {
        session.raw(&format!("function global:New-Object {{ param([string]$TypeName,[int]$Count) Write-Output -NoEnumerate ([byte[]]::new({allocation})) }}")).await?;
        let error = transfer::download(&session, remote.to_str().unwrap(), Some(&local))
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("invalid chunk"), "{error:#}");
        assert_eq!(std::fs::read(&local)?, b"original local destination");
        session.raw("Remove-Item Function:\\New-Object").await?;
    }
    let tree = root.path().join("tree");
    let destination = root.path().join("download");
    std::fs::create_dir(&tree)?;
    std::fs::create_dir(&destination)?;
    for relative in [
        "../escape",
        "..\\escape",
        "C:\\escape",
        "nested/../../escape",
    ] {
        let fake = format!("{}/{relative}", tree.display());
        session.raw(&format!("function global:Get-ChildItem {{ [pscustomobject]@{{ FullName={}; PSIsContainer=$false }} }}", quote(&fake))).await?;
        let error = transfer::download(&session, tree.to_str().unwrap(), Some(&destination))
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("unsafe remote filename"),
            "{error:#}"
        );
        assert!(!root.path().join("escape").exists());
        assert!(std::fs::read_dir(&destination)?.next().is_none());
        session.raw("Remove-Item Function:\\Get-ChildItem").await?;
    }
    transfer::download(&session, remote.to_str().unwrap(), Some(&local)).await?;
    assert_eq!(std::fs::read(&local)?, vec![42; 2_100_000]);
    session.close().await?;
    server.abort();
    Ok(())
}

#[tokio::test]
#[ignore = "requires local pwsh; drops TCP connections during real multi-chunk transfers"]
async fn interrupted_transfers_preserve_existing_destinations() -> Result<()> {
    for upload in [true, false] {
        let (backend_port, backend) = fixture().await?;
        let (port, disconnect, proxy) = disconnecting_proxy(backend_port).await?;
        let session = fixture_session(port, "Microsoft.PowerShell").await?;
        let root = tempfile::tempdir()?;
        let remote = root.path().join("remote.bin");
        let local = root.path().join("local.bin");
        let payload = vec![91; 4 * 1024 * 1024];
        std::fs::write(
            &remote,
            if upload {
                b"remote sentinel".as_slice()
            } else {
                &payload
            },
        )?;
        std::fs::write(
            &local,
            if upload {
                &payload
            } else {
                b"local sentinel".as_slice()
            },
        )?;
        let worker = session.clone();
        let remote_path = remote.clone();
        let local_path = local.clone();
        let transfer = tokio::spawn(async move {
            if upload {
                transfer::upload(&worker, &local_path, Some(remote_path.to_str().unwrap())).await
            } else {
                transfer::download(&worker, remote_path.to_str().unwrap(), Some(&local_path)).await
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let staged = std::fs::read_dir(root.path())
                    .unwrap()
                    .flatten()
                    .any(|entry| {
                        let path = entry.path();
                        path != remote
                            && path != local
                            && path.metadata().is_ok_and(|m| m.len() > 0)
                    });
                if staged {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .context("transfer never wrote its first staging chunk")?;
        disconnect.cancel();
        let error = tokio::time::timeout(std::time::Duration::from_secs(15), transfer)
            .await??
            .err()
            .context("transfer unexpectedly survived disconnection")?;
        assert!(!format!("{error:#}").is_empty());
        if upload {
            assert_eq!(std::fs::read(&remote)?, b"remote sentinel");
        } else {
            assert_eq!(std::fs::read(&local)?, b"local sentinel");
            assert_eq!(
                std::fs::read_dir(root.path())?.count(),
                2,
                "partial local download leaked"
            );
        }
        assert!(!session.is_open());
        proxy.abort();
        backend.abort();
    }
    Ok(())
}
