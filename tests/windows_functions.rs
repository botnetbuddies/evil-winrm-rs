//! Opted-in Windows shell helper, .NET Framework, and restricted-endpoint checks.
use anyhow::{Context, Result};
use evil_winrm_rs::{command::quote, transfer};
use tokio_util::sync::CancellationToken;
#[path = "support/windows.rs"]
mod windows;
use windows::connect;

#[tokio::test]
#[ignore = "requires two lab hosts, admin C$ credentials, WINRM_PEER_HOST/CERT_PEM/KEY_PEM"]
async fn cross_machine_http_and_smb_dll_loading() -> Result<()> {
    use clap::Parser;
    use evil_winrm_rs::{cli::Cli, session::Session, shell::execute_line};
    use winrm_rs::{AuthMethod, WinrmConfig, WinrmCredentials};
    let host = std::env::var("WINRM_HOST")?;
    let peer_host = std::env::var("WINRM_PEER_HOST")?;
    anyhow::ensure!(host != peer_host, "select two different Windows hosts");
    let peer_addresses = tokio::net::lookup_host((peer_host.as_str(), 0))
        .await?
        .map(|address| quote(&address.ip().to_string()))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(",");
    anyhow::ensure!(
        !peer_addresses.is_empty(),
        "the peer host resolved no addresses"
    );
    let source = connect().await?;
    let peer = Session::connect(
        peer_host,
        WinrmConfig {
            port: 5986,
            use_tls: true,
            auth_method: AuthMethod::Certificate,
            accept_invalid_certs: true,
            client_cert_pem: Some(std::env::var("WINRM_PEER_CERT_PEM")?),
            client_key_pem: Some(std::env::var("WINRM_PEER_KEY_PEM")?),
            ..Default::default()
        },
        WinrmCredentials::new("", "", ""),
        "Microsoft.PowerShell".into(),
    )
    .await?;
    let id = uuid::Uuid::new_v4().simple().to_string();
    let namespace = format!("EwrCross{id}");
    let directory = format!("C:\\ProgramData\\EwrLab\\cross-{id}");
    let firewall = format!("EwrLab-Http-{id}");
    let drive = format!("Ewr{id}");
    let result=async {
        let args=Cli::try_parse_from(["test","-i","unused","--no-colors"])?;
        source.raw(&format!("[IO.Directory]::CreateDirectory({}) | Out-Null; $compiler=Join-Path ([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()) 'csc.exe'",quote(&directory))).await?;
        for mode in ["Http","Smb"] {
            let code=format!("namespace {namespace} {{ public static class {mode}Probe {{ public static string Echo() {{ return \"cross-{mode}-passed\"; }} }} }}");
            source.raw(&format!("[IO.File]::WriteAllText({},{}); & $compiler /nologo /target:library {} {}; if ($LASTEXITCODE) {{throw 'cross-machine fixture compilation failed'}}",quote(&format!("{directory}\\{mode}.cs")),quote(&code),quote(&format!("/out:{directory}\\{mode}.dll")),quote(&format!("{directory}\\{mode}.cs")))).await?;
        }
        let http_source=include_str!("support/windows_http_fixture.cs").replace("EwrHttpFixture",&namespace);
        source.raw(&format!("Add-Type -TypeDefinition {}; [{namespace}.HttpFixture]::Start({}, {})",quote(&http_source),quote(&format!("{directory}\\Http.dll")),quote(&host))).await?;
        let port=source.raw(&format!("[{namespace}.HttpFixture]::Port")).await?.trim().parse::<u16>()?;
        source.raw(&format!("New-NetFirewallRule -Name {} -DisplayName {} -Direction Inbound -Action Allow -Protocol TCP -LocalAddress {} -LocalPort {port} -RemoteAddress {peer_addresses} | Out-Null",quote(&firewall),quote(&firewall),quote(&host))).await?;
        execute_line(&peer,&format!("Dll-Loader -http -path 'http://{host}:{port}/Http.dll'"),&args,&mut None).await?;
        assert_eq!(peer.raw(&format!("[{namespace}.HttpProbe]::Echo()")).await?.trim(),"cross-Http-passed");
        let unc=format!("\\\\{host}\\C$\\ProgramData\\EwrLab\\cross-{id}");
        let password=std::env::var("WINRM_PASSWORD")?;
        let username=std::env::var("WINRM_USER")?;
        peer.raw(&format!("$credential=New-Object Management.Automation.PSCredential({},(ConvertTo-SecureString {} -AsPlainText -Force)); New-PSDrive -Name {} -PSProvider FileSystem -Root {} -Credential $credential -Scope Global | Out-Null; Remove-Variable credential",quote(&username),quote(&password),quote(&drive),quote(&format!("\\\\{host}\\C$")))).await?;
        execute_line(&peer,&format!("Dll-Loader -smb -path {}",quote(&format!("{unc}\\Smb.dll"))),&args,&mut None).await?;
        assert_eq!(peer.raw(&format!("[{namespace}.SmbProbe]::Echo()")).await?.trim(),"cross-Smb-passed");
        source.raw(&format!("[{namespace}.HttpFixture]::Stop(); if ([{namespace}.HttpFixture]::Error) {{throw [{namespace}.HttpFixture]::Error}}; if (-not [{namespace}.HttpFixture]::Completed) {{throw 'cross-machine HTTP fixture not consumed'}}")).await?;
        Ok::<_,anyhow::Error>(())
    }.await;
    let _ = peer
        .raw(&format!(
            "Remove-PSDrive -Name {} -Force -ErrorAction SilentlyContinue",
            quote(&drive)
        ))
        .await;
    let _=source.raw(&format!("[{namespace}.HttpFixture]::Stop(); Remove-NetFirewallRule -Name {} -ErrorAction SilentlyContinue; Remove-Item -LiteralPath {} -Recurse -Force -ErrorAction SilentlyContinue",quote(&firewall),quote(&directory))).await;
    let source_closed = source.close().await;
    let peer_closed = peer.close().await;
    result?;
    source_closed?;
    peer_closed
}

#[tokio::test]
#[ignore = "requires dedicated WINRM_CONFIGURATION with MaxShellsPerUser=2 and no other sessions"]
async fn quota_rejection_explicit_close_and_drop_cleanup() -> Result<()> {
    let first = connect().await?;
    let second = connect().await?;
    assert!(!first.jea, "use a full-language quota fixture endpoint");
    let rejected = match connect().await {
        Ok(session) => {
            session.close().await?;
            first.close().await?;
            second.close().await?;
            anyhow::bail!("quota endpoint allowed a third shell")
        }
        Err(error) => error,
    };
    let message = format!("{rejected:#}").to_ascii_lowercase();
    assert!(
        message.contains("quota") || message.contains("maximum") || message.contains("concurrent"),
        "unexpected quota error: {message}"
    );
    first.close().await?;
    let replacement = connect().await?;
    assert_eq!(
        replacement.raw("'slot reused after close'").await?.trim(),
        "slot reused after close"
    );
    drop(second);
    let mut after_drop = None;
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if let Ok(session) = connect().await {
            after_drop = Some(session);
            break;
        }
    }
    let after_drop = after_drop.context("dropped session did not release its server quota slot")?;
    for _ in 0..10 {
        replacement.raw("'still isolated'").await?;
        after_drop.raw("'still usable'").await?;
    }
    replacement.close().await?;
    after_drop.close().await?;
    for _ in 0..10 {
        connect().await?.close().await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires Windows administrator, CredSSP, C$ access and the Framework C# compiler"]
async fn benign_dll_loader_local_http_and_smb() -> Result<()> {
    use clap::Parser;
    use evil_winrm_rs::{cli::Cli, shell::execute_line};
    anyhow::ensure!(
        std::env::var("WINRM_AUTH").as_deref() == Ok("credssp"),
        "select CredSSP for the SMB fixture"
    );
    let session = connect().await?;
    let id = uuid::Uuid::new_v4().simple().to_string();
    let remote = format!("C:\\ProgramData\\EwrLab\\dll-fixture-{id}");
    let namespace = format!("EwrDll{id}");
    let test=async {
        let args=Cli::try_parse_from(["test","-i","unused","--no-colors"])?;
        session.raw(&format!("[IO.Directory]::CreateDirectory({}) | Out-Null; $compiler=Join-Path ([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()) 'csc.exe'",quote(&remote))).await?;
        for mode in ["Local","Http","Smb"] {
            let source=format!("namespace {namespace} {{ public static class {mode}Probe {{ public static string Echo(string text) {{ return \"{mode}:\"+text; }} }} }}");
            session.raw(&format!("[IO.File]::WriteAllText({},{}); & $compiler /nologo /target:library {} {}; if($LASTEXITCODE -ne 0) {{throw 'benign DLL fixture compilation failed'}}",quote(&format!("{remote}\\{mode}.cs")),quote(&source),quote(&format!("/out:{remote}\\{mode}.dll")),quote(&format!("{remote}\\{mode}.cs")))).await?;
        }
        // Bind only on Windows loopback: this exercises the actual HTTP helper
        // without opening a lab firewall or depending on a route to the client.
        let http_source=include_str!("support/windows_http_fixture.cs").replace("EwrHttpFixture",&namespace);
        session.raw(&format!("Add-Type -TypeDefinition {}; [{namespace}.HttpFixture]::Start({})",quote(&http_source),quote(&format!("{remote}\\Http.dll")))).await?;
        let port=session.raw(&format!("[{namespace}.HttpFixture]::Port")).await?.trim().parse::<u16>()?;
        let computer=session.raw("$env:COMPUTERNAME").await?.trim().to_owned();
        for (mode,option,path) in [
            ("Local","-local",format!("{remote}\\Local.dll")),
            ("Http","-http",format!("http://127.0.0.1:{port}/Http.dll")),
            ("Smb","-smb",format!("\\\\{computer}\\C$\\ProgramData\\EwrLab\\dll-fixture-{id}\\Smb.dll")),
        ] {
            execute_line(&session,&format!("Dll-Loader {option} -path {}",quote(&path)),&args,&mut None).await?;
            anyhow::ensure!(session.raw(&format!("[{namespace}.{mode}Probe]::Echo('verified')")).await?.trim()==format!("{mode}:verified"),"{mode} assembly did not execute");
            anyhow::ensure!(session.raw("$global:showmethods").await?.contains(&format!("[{namespace}.{mode}Probe]::Echo()")),"{mode} static-method completion missing");
        }
        session.raw(&format!("[{namespace}.HttpFixture]::Stop(); if ([{namespace}.HttpFixture]::Error) {{ throw [{namespace}.HttpFixture]::Error }}; if (-not [{namespace}.HttpFixture]::Completed) {{throw 'HTTP fixture was not consumed'}}")).await?;
        Ok::<_,anyhow::Error>(())
    }.await;
    let _ = session
        .raw(&format!("[{namespace}.HttpFixture]::Stop()"))
        .await;
    let _ = session
        .raw(&format!(
            "Remove-Item -LiteralPath {} -Recurse -Force -ErrorAction SilentlyContinue",
            quote(&remote)
        ))
        .await;
    let closed = session.close().await;
    test?;
    closed
}

#[tokio::test]
#[ignore = "requires Windows; waits 85 seconds beyond a requested 60-second idle timeout"]
async fn idle_keepalive_beyond_server_timeout() -> Result<()> {
    let session = windows::connect_with_idle_timeout(Some(60)).await?;
    let test = async {
        session
            .raw("$global:ewrIdleState='retained after idle'")
            .await?;
        tokio::time::sleep(std::time::Duration::from_secs(85)).await;
        anyhow::ensure!(session.is_open(), "session closed during idle period");
        anyhow::ensure!(
            session.raw("$global:ewrIdleState").await?.trim() == "retained after idle",
            "idle session lost its state"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let closed = session.close().await;
    test?;
    closed
}

#[tokio::test]
#[ignore = "requires a Windows administrator lab; creates a stopped temporary service"]
async fn scripts_services_transcripts_and_wildcards() -> Result<()> {
    use clap::Parser;
    use evil_winrm_rs::{cli::Cli, shell::execute_line};
    let session = connect().await?;
    let local = tempfile::tempdir()?;
    let id = uuid::Uuid::new_v4().simple().to_string();
    let service = format!("EwrLab{id}");
    let remote = session
        .raw(&format!(
            "Join-Path ([IO.Path]::GetTempPath()) 'ewr-functions-{id}'"
        ))
        .await?
        .trim()
        .to_owned();
    let args = Cli::try_parse_from([
        "test",
        "-i",
        "unused",
        "--no-colors",
        "--scripts",
        local.path().to_str().context("UTF-8 temporary path")?,
    ])?;
    let transcript = local.path().join("transcript.log");
    let mut log = Some(std::fs::File::create(&transcript)?);
    let test = async {
        session.raw(&format!("[IO.Directory]::CreateDirectory({}) | Out-Null; New-Service -Name {} -BinaryPathName '\"C:\\Program Files\\EwrLab\\never-started.exe\"' -StartupType Manual | Out-Null",quote(&remote),quote(&service))).await?;
        let script = local.path().join("script with spaces.ps1");
        std::fs::write(&script, "function Test-EwrLoadedFunction { 'héllo 世界' }")?;
        execute_line(&session, "loadps 'script with spaces.ps1'", &args, &mut log).await?;
        assert_eq!(session.raw("Test-EwrLoadedFunction").await?.trim(), "héllo 世界");
        std::fs::write(&script, "$ewrRunScope = 'local'; Write-Output 'runps output'")?;
        execute_line(&session, "runps 'script with spaces.ps1'", &args, &mut log).await?;
        assert_eq!(session.raw("$null -eq (Get-Variable ewrRunScope -ErrorAction SilentlyContinue)").await?.trim().to_ascii_lowercase(), "true");
        let utf16: Vec<_> = [0xff, 0xfe].into_iter().chain("function Test-EwrUtf16 { 'UTF16 世界' }".encode_utf16().flat_map(u16::to_le_bytes)).collect();
        std::fs::write(local.path().join("unicode.ps1"), utf16)?;
        execute_line(&session, "unicode.ps1", &args, &mut log).await?;
        assert_eq!(session.raw("Test-EwrUtf16").await?.trim(), "UTF16 世界");
        let large = format!("#{}\n'large Windows script'", "padding".repeat(40_000));
        assert_eq!(session.raw(&large).await?.trim(), "large Windows script");
        execute_line(&session, "services", &args, &mut log).await?;
        execute_line(&session, "menu", &args, &mut log).await?;
        execute_line(&session, "$VerbosePreference='Continue'; $DebugPreference='Continue'; Write-Output 'transcript stdout'; Write-Warning 'transcript warning'; Write-Verbose 'transcript verbose'; Write-Debug 'transcript debug'; Write-Information 'transcript information'; Write-Error 'transcript error'", &args, &mut log).await.expect_err("the shell must report a remote error");
        let text = std::fs::read_to_string(&transcript)?;
        for expected in [&service, "Stopped", "True", "Test-EwrLoadedFunction", "transcript stdout", "Warning: transcript warning", "Verbose: transcript verbose", "Debug: transcript debug", "Information: transcript information", "Error: transcript error", "runps output"] {
            anyhow::ensure!(text.contains(expected), "transcript is missing {expected}");
        }
        for (name, bytes) in [("a's 世界.txt", b"first".as_slice()), ("second.txt", b"second"), ("excluded.bin", b"excluded")] {
            let input = local.path().join(name);
            std::fs::write(&input, bytes)?;
            transfer::upload(&session, &input, Some(&format!("{remote}\\{name}"))).await?;
        }
        let downloaded = local.path().join("wildcard results");
        transfer::download(&session, &format!("{remote}\\*.txt"), Some(&downloaded)).await?;
        assert_eq!(std::fs::read(downloaded.join("a's 世界.txt"))?, b"first");
        assert_eq!(std::fs::read(downloaded.join("second.txt"))?, b"second");
        assert!(!downloaded.join("excluded.bin").exists());
        assert!(!execute_line(&session, "exit", &args, &mut log).await?);
        Ok::<_, anyhow::Error>(())
    }.await;
    let _ = session.raw(&format!("& sc.exe delete {} | Out-Null; Remove-Item -LiteralPath {} -Recurse -Force -ErrorAction SilentlyContinue",quote(&service),quote(&remote))).await;
    let closed = session.close().await;
    test?;
    closed
}

#[tokio::test]
#[ignore = "requires Windows x64, Framework csc.exe and the local .NET 8 SDK; validates benign runtime/architecture cases"]
async fn managed_architecture_and_runtime_compatibility() -> Result<()> {
    use clap::Parser;
    use evil_winrm_rs::{cli::Cli, shell::execute_line};
    let local = tempfile::tempdir()?;
    let source = local.path().join("source");
    std::fs::create_dir(&source)?;
    std::fs::write(
        source.join("Probe.csproj"),
        include_str!("fixtures/managed/Probe.csproj"),
    )?;
    std::fs::write(
        source.join("Program.cs"),
        include_str!("fixtures/managed/Program.cs"),
    )?;
    let build = tokio::process::Command::new("dotnet")
        .args(["build", "--nologo", "--verbosity", "quiet", "--output"])
        .arg(local.path().join("out"))
        .arg(source.join("Probe.csproj"))
        .arg("-p:RestoreIgnoreFailedSources=true")
        .kill_on_drop(true)
        .output()
        .await?;
    anyhow::ensure!(
        build.status.success(),
        ".NET fixture build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );
    let session = connect().await?;
    let remote = session
        .raw(&format!(
            "Join-Path $env:TEMP 'ewr-architecture-{}'",
            uuid::Uuid::new_v4()
        ))
        .await?
        .trim()
        .to_owned();
    let test = async {
        assert_eq!(session.raw("[Environment]::Is64BitProcess").await?.trim().to_ascii_lowercase(), "true");
        let core = session.raw("$PSEdition").await?.trim() == "Core";
        let args = Cli::try_parse_from(["test", "-i", "unused", "--no-colors"])?;
        let log_path = local.path().join("compatibility.log");
        let mut log = Some(std::fs::File::create(&log_path)?);
        session.raw(&format!("[IO.Directory]::CreateDirectory({}) | Out-Null; $compiler=Join-Path $env:WINDIR 'Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe'; $global:ewrPreviousOut=[Console]::Out; $global:ewrPreviousError=[Console]::Error", quote(&remote))).await?;
        for platform in ["anycpu", "x64", "x86"] {
            let code = format!("public static class Ewr{platform}Probe {{ public static void Main(string[] args) {{ System.Console.WriteLine(\"architecture:{platform}\"); }} }}");
            let assembly = format!("{remote}\\{platform}.exe");
            let code_path = format!("{remote}\\{platform}.cs");
            session.raw(&format!("[IO.File]::WriteAllText({},{}); & $compiler /nologo /target:exe {} {} {}; if($LASTEXITCODE -ne 0) {{throw 'Architecture fixture compilation failed'}}", quote(&code_path), quote(&code), quote(&format!("/platform:{platform}")), quote(&format!("/out:{assembly}")), quote(&code_path))).await?;
            let input = local.path().join(format!("{platform}.exe"));
            transfer::download(&session, &assembly, Some(&input)).await?;
            let result = execute_line(&session, &format!("runexe {}", quote(input.to_str().unwrap())), &args, &mut log).await;
            if core && platform == "x86" {
                let error = result.expect_err("PowerShell 7 x64 must reject an x86-only assembly");
                anyhow::ensure!(format!("{error:#}").contains("architecture"), "unexpected x86 rejection: {error:#}");
            } else {
                result?;
                anyhow::ensure!(std::fs::read_to_string(&log_path)?.contains(&format!("architecture:{platform}")), "missing {platform} fixture output");
            }
        }
        let native = local.path().join("native.exe");
        let native_remote = session.raw("Join-Path $env:WINDIR 'System32\\whoami.exe'").await?;
        transfer::download(&session, native_remote.trim(), Some(&native)).await?;
        assert!(execute_line(&session, &format!("runexe {}", quote(native.to_str().unwrap())), &args, &mut log).await.is_err(), "native PE was accepted as a managed assembly");
        let modern = local.path().join("out/EwrParityProbe.dll");
        let result = execute_line(&session, &format!("runexe {} 'runtime-probe'", quote(modern.to_str().unwrap())), &args, &mut log).await;
        if core {
            result?;
            assert!(std::fs::read_to_string(&log_path)?.contains("stdout:runtime-probe"));
        } else {
            assert!(result.is_err(), ".NET 8 fixture unexpectedly ran on .NET Framework");
        }
        assert_eq!(session.raw("[object]::ReferenceEquals($global:ewrPreviousOut,[Console]::Out) -and [object]::ReferenceEquals($global:ewrPreviousError,[Console]::Error)").await?.trim().to_ascii_lowercase(), "true");
        assert_eq!(session.raw("@(Get-Variable -Scope Global -Name 'ewr*' | Where-Object { $_.Value -is [IO.MemoryStream] }).Count").await?.trim(), "0");
        Ok::<_, anyhow::Error>(())
    }.await;
    let _ = session
        .raw(&format!(
            "Remove-Item -LiteralPath {} -Recurse -Force -ErrorAction SilentlyContinue",
            quote(&remote)
        ))
        .await;
    let closed = session.close().await;
    test?;
    closed
}

#[tokio::test]
#[ignore = "requires Windows PowerShell 5.1 and its .NET Framework C# compiler"]
async fn managed_framework_assembly_arguments_and_cleanup() -> Result<()> {
    use clap::Parser;
    use evil_winrm_rs::{cli::Cli, shell::execute_line};
    let session = connect().await?;
    let local = tempfile::tempdir()?;
    let remote = session
        .raw(&format!(
            "Join-Path ([IO.Path]::GetTempPath()) 'ewr-framework-{}'",
            uuid::Uuid::new_v4()
        ))
        .await?
        .trim()
        .to_owned();
    let test = async {
        let source = r#"using System;
namespace EwrFrameworkProbe {
 public static class Program {
  public static string Echo(string text) { return "echo:" + text; }
  public static int Main(string[] args) {
   AppDomain.CurrentDomain.SetData("ewrFrameworkArgs", args);
   Console.WriteLine("stdout:" + string.Join("|", args));
   Console.Error.WriteLine("stderr:framework");
   if(args.Length > 0 && args[0] == "throw") throw new InvalidOperationException("framework-test-error");
   return 42;
  }
 }
}"#;
        let assembly = format!("{remote}\\EwrFrameworkProbe.exe");
        session.raw(&format!("[IO.Directory]::CreateDirectory({}) | Out-Null; [IO.File]::WriteAllText({},{}); $compiler=Join-Path ([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()) 'csc.exe'; & $compiler /nologo /target:exe {} {}; if($LASTEXITCODE -ne 0) {{throw 'Framework C# compilation failed'}}",quote(&remote),quote(&format!("{remote}\\Program.cs")),quote(source),quote(&format!("/out:{assembly}")),quote(&format!("{remote}\\Program.cs")))).await?;
        let input = local.path().join("EwrFrameworkProbe.exe");
        transfer::download(&session, &assembly, Some(&input)).await?;
        let args = Cli::try_parse_from([
            "test", "-i", "unused", "--no-colors", "--executables",
            local.path().to_str().context("UTF-8 executable search path")?,
        ])?;
        let transcript = local.path().join("managed.log");
        let mut log = Some(std::fs::File::create(&transcript)?);
        session.raw("$global:ewrPreviousOut=[Console]::Out; $global:ewrPreviousError=[Console]::Error").await?;
        execute_line(&session,"runexe EwrFrameworkProbe.exe 'a b' '' 'a|b;c' 'héllo 世界'",&args,&mut log).await?;
        assert_eq!(session.raw("ConvertTo-Json -InputObject ([AppDomain]::CurrentDomain.GetData('ewrFrameworkArgs')) -Compress").await?.trim(),r#"["a b","","a|b;c","héllo 世界"]"#);
        let text = std::fs::read_to_string(transcript)?;
        assert!(text.contains("stdout:a b||a|b;c|héllo 世界"));
        assert!(text.contains("stderr:framework"));
        let module_source = "using System.Management.Automation; [Cmdlet(VerbsCommon.Get, \"EwrFrameworkFixture\")] public sealed class EwrFrameworkCmdlet : Cmdlet { protected override void ProcessRecord() { WriteObject(\"framework-cmdlet\"); } }";
        let module_remote = format!("{remote}\\EwrFrameworkModule.dll");
        session.raw(&format!("[IO.File]::WriteAllText({},{}); $automation=[System.Management.Automation.PSObject].Assembly.Location; & $compiler /nologo /target:library (\"/reference:\"+$automation) {} {}; if($LASTEXITCODE -ne 0) {{throw 'Framework module compilation failed'}}",quote(&format!("{remote}\\Module.cs")),quote(module_source),quote(&format!("/out:{module_remote}")),quote(&format!("{remote}\\Module.cs")))).await?;
        let module_input=local.path().join("EwrFrameworkModule.dll");
        transfer::download(&session,&module_remote,Some(&module_input)).await?;
        execute_line(&session,"loaddll EwrFrameworkModule.dll",&args,&mut log).await?;
        assert_eq!(session.raw("Get-EwrFrameworkFixture").await?.trim(),"framework-cmdlet");
        assert_eq!(session.raw("[EwrFrameworkProbe.Program]::Echo('loaded')").await?.trim(),"echo:loaded");
        let error=execute_line(&session,"Invoke-Binary EwrFrameworkProbe.exe throw",&args,&mut log).await.expect_err("managed exception should propagate");
        assert!(format!("{error:#}").contains("framework-test-error"),"{error:#}");
        assert_eq!(session.raw("[object]::ReferenceEquals($global:ewrPreviousOut,[Console]::Out) -and [object]::ReferenceEquals($global:ewrPreviousError,[Console]::Error)").await?.trim().to_ascii_lowercase(),"true");
        assert_eq!(session.raw("@(Get-Variable -Scope Global -Name 'ewr*' | Where-Object { $_.Value -is [IO.MemoryStream] }).Count").await?.trim(),"0");
        Ok::<_,anyhow::Error>(())
    }.await;
    let _ = session
        .raw(&format!(
            "Remove-Item -LiteralPath {} -Recurse -Force -ErrorAction SilentlyContinue",
            quote(&remote)
        ))
        .await;
    let closed = session.close().await;
    test?;
    closed
}

#[tokio::test]
#[ignore = "requires a real restricted Windows endpoint selected by WINRM_CONFIGURATION"]
async fn jea_role_policy_and_helper_rejection() -> Result<()> {
    use clap::Parser;
    use evil_winrm_rs::{cli::Cli, shell::execute_line};
    let session = connect().await?;
    let test = async {
        assert!(
            session.jea,
            "select a restricted endpoint with WINRM_CONFIGURATION"
        );
        assert_eq!(
            session
                .execute("Write-Output 'a|b;c'", CancellationToken::new())
                .await?
                .checked()?
                .trim(),
            "a|b;c"
        );
        let text = session
            .execute(
                "Get-Command -Name Get-Date | Select-Object -Property Name",
                CancellationToken::new(),
            )
            .await?
            .checked()?;
        assert!(text.contains("Get-Date"), "{text}");
        assert_eq!(
            session
                .execute(
                    "Write-Output first; Write-Output second",
                    CancellationToken::new()
                )
                .await?
                .checked()?
                .trim(),
            "first\nsecond"
        );
        for command in ["Invoke-Expression -Command '1 + 1'", "Get-Process"] {
            let result = session.execute(command, CancellationToken::new()).await?;
            assert!(
                result.failed || !result.errors.is_empty(),
                "JEA accepted {command}"
            );
        }
        assert!(session.raw("1 + 1").await.is_err());
        let args = Cli::try_parse_from(["test", "-i", "unused", "--no-colors"])?;
        for command in [
            "services",
            "upload unused",
            "download unused",
            "loadps unused",
            "runexe unused",
        ] {
            let error = execute_line(&session, command, &args, &mut None)
                .await
                .expect_err("JEA must reject scripting helpers");
            assert!(error.to_string().contains("unavailable in JEA"));
        }
        assert_eq!(
            session
                .execute("Write-Output recovered", CancellationToken::new())
                .await?
                .checked()?
                .trim(),
            "recovered"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let closed = session.close().await;
    test?;
    closed
}
