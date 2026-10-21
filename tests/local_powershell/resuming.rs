use super::fixture::{fixture, fixture_session};
use anyhow::Result;
use evil_winrm_rs::{
    command::quote,
    transfer::{self, Options},
};
use md5::{Digest, Md5};
#[tokio::test]
#[ignore = "requires local pwsh; verifies partial-prefix validation and bounded compressed round trips"]
async fn resumable_compressed_transfers_preserve_destinations() -> Result<()> {
    let (port, server) = fixture().await?;
    let session = fixture_session(port, "Microsoft.PowerShell").await?;
    let root = tempfile::tempdir()?;
    let source = root.path().join("source.bin");
    let remote = root.path().join("remote.bin");
    let local = root.path().join("local.bin");
    let payload: Vec<_> = (0..1_340_013).map(|i| ((i * 29) % 251) as u8).collect();
    let hash = hex::encode(Md5::digest(&payload));
    std::fs::write(&source, &payload)?;
    for compress in [false, true] {
        std::fs::write(&remote, b"old remote")?;
        std::fs::write(&local, b"old local")?;
        let upload_part = std::path::PathBuf::from(format!("{}.{}.part", remote.display(), hash));
        std::fs::write(&upload_part, &payload[..131_113])?;
        let options = Options {
            resume: true,
            compress,
        };
        transfer::upload_with_options(&session, &source, Some(remote.to_str().unwrap()), options)
            .await?;
        assert_eq!(std::fs::read(&remote)?, payload);
        assert!(!upload_part.exists());
        let download_part = std::path::PathBuf::from(format!("{}.{}.part", local.display(), hash));
        std::fs::write(&download_part, &payload[..93_777])?;
        transfer::download_with_options(&session, remote.to_str().unwrap(), Some(&local), options)
            .await?;
        assert_eq!(std::fs::read(&local)?, payload);
        assert!(!download_part.exists());
        std::fs::write(&download_part, b"corrupt prefix")?;
        std::fs::write(&local, b"keep destination")?;
        assert!(
            transfer::download_with_options(
                &session,
                remote.to_str().unwrap(),
                Some(&local),
                options
            )
            .await
            .is_err()
        );
        assert_eq!(std::fs::read(&local)?, b"keep destination");
        std::fs::remove_file(download_part)?;
        std::fs::write(&upload_part, b"corrupt prefix")?;
        assert!(
            transfer::upload_with_options(
                &session,
                &source,
                Some(remote.to_str().unwrap()),
                options
            )
            .await
            .is_err()
        );
        assert_eq!(std::fs::read(&remote)?, payload);
        std::fs::remove_file(upload_part)?;
    }
    // A compressed empty file must still validate and atomically replace its destination.
    std::fs::write(&source, b"")?;
    transfer::upload_with_options(
        &session,
        &source,
        Some(remote.to_str().unwrap()),
        Options {
            resume: true,
            compress: true,
        },
    )
    .await?;
    transfer::download_with_options(
        &session,
        remote.to_str().unwrap(),
        Some(&local),
        Options {
            resume: true,
            compress: true,
        },
    )
    .await?;
    assert!(std::fs::read(&local)?.is_empty());
    assert_eq!(
        session
            .raw(&format!(
                "@(Get-Variable -Scope Global -Name 'ewrUpload*').Count; {}",
                quote("done")
            ))
            .await?
            .trim(),
        "0\ndone"
    );
    session.close().await?;
    server.abort();
    Ok(())
}
