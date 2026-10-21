//! Built-in command discovery and concise help.
pub(super) const BUILTINS: &[&str] = &[
    "menu",
    "services",
    "upload",
    "download",
    "loadps",
    "runps",
    "loaddll",
    "runexe",
    "Invoke-Binary",
    "Dll-Loader",
    "Donut-Loader",
    "Bypass-4MSI",
    "Patch-ETW",
    "clear",
    "cls",
    "exit",
    "quit",
];

pub(super) fn menu_help(jea: bool) -> String {
    let mut text = String::from("Shell commands\n");
    for (usage, description) in [
        ("menu", "Show this help and loaded functions"),
        ("clear, cls", "Clear the terminal"),
        ("exit, quit", "Close the session"),
    ] {
        text.push_str(&format!("  {usage:<39} {description}\n"));
    }
    for (section, commands) in [
        (
            "Files and scripts",
            &[
                ("upload <local> [remote]", "Upload a file or directory"),
                ("download <remote> [local]", "Download a file or directory"),
                ("loadps <local.ps1>", "Load functions into this session"),
                (
                    "runps <file|-|URL> [args]",
                    "Run a script with arguments in a child scope",
                ),
            ][..],
        ),
        (
            "Managed assemblies and services",
            &[
                ("loaddll <local.dll>", "Import managed assembly cmdlets"),
                (
                    "runexe <local.exe> [args...]",
                    "Run a managed assembly entry point",
                ),
                ("Invoke-Binary <local.exe> [args...]", "Alias for runexe"),
                ("Dll-Loader <mode> -path <remote>", "Load a managed DLL"),
                ("services", "List services and their executable paths"),
            ][..],
        ),
        (
            "Additional helpers",
            &[("Donut-Loader", ""), ("Bypass-4MSI", ""), ("Patch-ETW", "")][..],
        ),
    ] {
        text.push_str(&format!("\n{section}\n"));
        for (usage, description) in commands {
            if jea {
                text.push_str(&format!("  {usage} (Disabled in JEA)\n"));
            } else if description.is_empty() {
                text.push_str(&format!("  {usage}\n"));
            } else {
                text.push_str(&format!("  {usage:<39} {description}\n"));
            }
        }
    }
    if !jea {
        text.push_str("\nDll-Loader modes: -local, -http, -smb.\n");
    }
    text.push_str("\nRun PowerShell commands directly; use Get-Command to browse them.\nTab completes commands and paths. Quote paths containing spaces.\n");
    if !jea {
        text.push_str("Backticks, trailing pipes, and open blocks continue onto the next line.\n");
    }
    text.push_str("Ctrl+C cancels input or a running command; Ctrl+D closes the session.\n");
    text
}

pub(super) fn helper_available(name: &str, jea: bool) -> bool {
    !jea || !BUILTINS
        .iter()
        .any(|builtin| builtin.eq_ignore_ascii_case(name))
        || matches!(
            name.to_ascii_lowercase().as_str(),
            "menu" | "clear" | "cls" | "exit" | "quit"
        )
}
