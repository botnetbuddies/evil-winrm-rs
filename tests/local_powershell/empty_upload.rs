//! An empty input stream can enter PowerShell's process block once with null.
use anyhow::Result;
use evil_winrm_rs::command::quote;

use super::fixture::{fixture, fixture_session};

#[tokio::test]
#[ignore = "requires local pwsh; forces the null-input path in empty uploads"]
async fn empty_upload_without_input_objects() -> Result<()> {
    let (port, server) = fixture().await?;
    let session = fixture_session(port, "Microsoft.PowerShell").await?;
    let root = tempfile::tempdir()?;
    for compressed in [false, true] {
        let path = root.path().join(format!("empty-{compressed}.bin"));
        let settings = format!(
            "$ewrStagingPath={}; $ewrOffset=[long]0; $ewrExpectedLength=[long]0; $ewrCompressed=${compressed}; $ewrMode=[IO.FileMode]::CreateNew;",
            quote(path.to_str().unwrap())
        );
        let script = include_str!("../../src/transfer/scripts/upload.ps1")
            .replace("__SETTINGS__", &settings)
            .replace("__STREAM__", "ewrEmptyUploadRegression");
        // No pipeline input forces process to run with null, without relying on timing.
        let hash = session.raw(&script).await?;
        assert_eq!(
            hash.trim().to_ascii_lowercase(),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
        assert_eq!(std::fs::metadata(path)?.len(), 0);
    }
    session.close().await?;
    server.abort();
    Ok(())
}
