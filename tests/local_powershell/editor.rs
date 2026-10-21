//! Development-only WSMan fixture backed by a real local PowerShell process.
//! Authentication and Windows-specific helpers still need the Windows lab.
use anyhow::Result;

use super::fixture::{fixture, fixture_session};
#[tokio::test]
#[ignore = "requires local pwsh; checks native PowerShell multiline parsing without execution"]
async fn multiline_parser_is_grammar_aware_and_does_not_execute_input() -> Result<()> {
    let (port, server) = fixture().await?;
    let session = fixture_session(port, "Microsoft.PowerShell").await?;
    session.raw("$global:ewrParseSideEffect=0").await?;
    for input in [
        "Get-Command |",
        "Get-Date `",
        "& {",
        "'unclosed",
        "@(1,",
        "@'\ntext",
        "$x =",
    ] {
        assert!(
            session.input_is_incomplete(input).await?,
            "did not request continuation: {input:?}"
        );
    }
    for input in [
        "Get-Command |\n Select-Object Name",
        "Get-Date `\n -Format yyyy",
        "& {\n 'block'\n}",
        "'C:\\'",
        "# { unmatched bracket in comment",
        "@'\ntext\n'@",
        "$global:ewrParseSideEffect=99",
    ] {
        assert!(
            !session.input_is_incomplete(input).await?,
            "complete input rejected: {input:?}"
        );
    }
    assert_eq!(session.raw("$global:ewrParseSideEffect").await?.trim(), "0");
    assert!(
        session
            .raw("Get-Date `\n -Format yyyy")
            .await?
            .trim()
            .parse::<u16>()
            .is_ok()
    );
    assert_eq!(
        session
            .raw("Write-Output first |\n ForEach-Object { $_ + '-multiline' }")
            .await?
            .trim(),
        "first-multiline"
    );
    session.close().await?;
    server.abort();
    Ok(())
}
