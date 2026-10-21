//! Dispatch shell helpers; ordinary PowerShell passes through unchanged.
use super::{
    assemblies::{donut_loader_blocked_by_amsi, load_assembly, stage_bytes, unstage_bytes},
    completion::words::explicit_remote_path,
    menu::menu_help,
    output::{CommandSink, cancellable, command_output, emit, print_output, script_output},
    paths::{SCRIPT_EXTENSIONS, has_extension, local_path, resolve_local},
    scripts::{read_script, read_script_source, script_invocation},
};
use crate::{
    cli::Cli,
    command::arguments,
    session::{Output, Session},
    transfer,
};
use anyhow::{Result, bail};
use std::{
    fs::File,
    io::{IsTerminal, Write},
    path::Path,
};
/// Dispatch one shell line through the same helpers used by the interactive UI.
pub async fn execute_line(
    session: &Session,
    line: &str,
    args: &Cli,
    log: &mut Option<File>,
) -> Result<bool> {
    let mut sink = CommandSink {
        log,
        output: Output::default(),
        capture: false,
        status: false,
    };
    execute_line_to(session, line, args, &mut sink).await
}

pub(super) async fn execute_line_to(
    session: &Session,
    line: &str,
    args: &Cli,
    log: &mut CommandSink<'_>,
) -> Result<bool> {
    if let Some(log) = &mut *log.log {
        writeln!(log, "PS> {line}")?;
    }
    // Parse helper arguments only after matching the complete command word.
    // Arbitrary PowerShell, including unmatched quote characters in comments, passes through.
    let name = line
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if matches!(name.as_str(), "exit" | "quit") && line.split_whitespace().count() == 1 {
        return Ok(false);
    }
    if matches!(name.as_str(), "clear" | "cls") {
        if !log.capture {
            print!("\x1b[2J\x1b[H");
            std::io::stdout().flush()?;
        }
        return Ok(true);
    }
    if name == "menu" {
        emit(&menu_help(session.jea), log)?;
        if !session.jea {
            let functions = session.loaded_functions().await?;
            if !functions.is_empty() {
                emit("\nFunctions added in this session\n", log)?;
                for function in functions {
                    emit(&format!("  {function}\n"), log)?;
                }
            }
        }
        return Ok(true);
    }
    if session.jea
        && matches!(
            name.as_str(),
            "services"
                | "upload"
                | "download"
                | "loadps"
                | "runps"
                | "loaddll"
                | "runexe"
                | "invoke-binary"
                | "dll-loader"
                | "donut-loader"
                | "bypass-4msi"
                | "patch-etw"
        )
    {
        bail!("{name} requires scripting and is unavailable in JEA mode");
    }
    match name.as_str() {
        "services" => emit(&session.raw("Get-ItemProperty 'registry::HKLM\\System\\CurrentControlSet\\Services\\*' | Where-Object { $_.ImagePath -notmatch 'system' -and $_.ImagePath } | ForEach-Object { $service = Get-Service -Name $_.PSChildName -ErrorAction SilentlyContinue; [pscustomobject]@{Service=$_.PSChildName;Path=$_.ImagePath;State=$service.Status;Privileges=[bool]$service} } | Out-String -Width 200").await?,log)?,
        "upload" => {
            let (words,options)=super::transfer_args::parse(line,args)?;
            transfer::upload_with_options(session,&local_path(&words[0]),words.get(1).map(String::as_str),options).await?;
        }
        "download" => {
            let (words,options)=super::transfer_args::parse(line,args)?;
            let destination=words.get(1).map(|value|local_path(value));
            transfer::download_with_options(session,&words[0],destination.as_deref(),options).await?;
        }
        "loadps"|"runps" => {
            let words = arguments(line)?;
            if words.len() < 2 || (name == "loadps" && words.len() != 2) { bail!("usage: {}", if name == "runps" { "runps <script.ps1|-|https://…> [arguments...]" } else { "loadps <local.ps1>" }); }
            let script = if name == "runps" { read_script_source(&words[1], args).await? } else { read_script(&resolve_local(&words[1], args.scripts.as_deref()))? };
            let script = if name == "loadps" { format!(". {{\n{script}\n}}") } else { script_invocation(&script, &words[2..]) };
            script_output(session,&script,log).await?;
        }
        "loaddll"|"runexe"|"invoke-binary" => {
            let words = arguments(line)?; if words.len() < 2 { bail!("usage: {name} <local_file> [arguments...]"); }
            let path = resolve_local(&words[1],args.executables.as_deref());
            emit(&load_assembly(session,&path,name=="loaddll",&words[2..]).await?,log)?;
        }
        "dll-loader" => {
            crate::helpers::install_dll_loader(session).await?;
            print_output(command_output(session,line,false,log).await?,log,!args.no_colors && std::io::stderr().is_terminal())?;
        }
        "donut-loader" => {
            let words=arguments(line)?;
            let pid=words.iter().position(|w|w.eq_ignore_ascii_case("-process_id")).and_then(|i|words.get(i+1));
            let file=words.iter().position(|w|w.eq_ignore_ascii_case("-donutfile")).and_then(|i|words.get(i+1));
            crate::helpers::install_donut_loader(session).await?;
            if let (Some(pid),Some(file))=(pid,file) {
                let path=resolve_local(file,args.executables.as_deref());
                let id=stage_bytes(session,&path).await?;
                let command=format!("Donut-Loader -process_id ({pid}) -donutfile ([Convert]::ToBase64String($global:{id}.ToArray()))");
                let mut result=session.raw(&command).await;
                // Defender AMSI-scans assemblies loaded with Assembly.Load(byte[]),
                // which makes the embedded loader fail with an opaque
                // BadImageFormatException. Patch AMSI once and retry rather than
                // requiring an explicit Bypass-4MSI first.
                if matches!(&result, Err(error) if donut_loader_blocked_by_amsi(error)) {
                    crate::helpers::patch_amsi(session).await?;
                    result=session.raw(&command).await;
                }
                unstage_bytes(session,&id).await;
                emit(&result?,log)?;
            } else { print_output(cancellable(session,"Donut-Loader").await?,log,!args.no_colors && std::io::stderr().is_terminal())?; }
        }
        "bypass-4msi" => emit(&crate::helpers::patch_amsi_and_etw(session).await?,log)?,
        "patch-etw" => emit(&crate::helpers::patch_etw(session).await?,log)?,
        _ => {
            if args.scripts.is_some()
                && let Ok(words) = arguments(line)
                && words.len() == 1
                && !explicit_remote_path(&words[0])
                && has_extension(Path::new(&words[0]), SCRIPT_EXTENSIONS)
            {
                let path = resolve_local(&words[0], args.scripts.as_deref());
                if path.is_file() {
                    let script = read_script(&path)?;
                    script_output(session,&format!(". {{\n{script}\n}}"),log).await?; return Ok(true);
                }
            }
            print_output(command_output(session,line,false,log).await?,log,!args.no_colors && std::io::stderr().is_terminal())?;
        }
    }
    Ok(true)
}
