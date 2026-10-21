use super::menu::{BUILTINS, helper_available};
use super::{
    assemblies::donut_loader_blocked_by_amsi,
    completion::{
        RemoteEntry, test_local_candidates as local_candidates,
        test_remote_candidates as remote_candidates, words::*,
    },
    paths::*,
    scripts::read_script,
};
use crate::command::arguments;

#[test]
fn recognizes_amsi_blocked_donut_loader_errors() {
    assert!(donut_loader_blocked_by_amsi(&anyhow::anyhow!(
        "Exception calling \"Load\": ... An attempt was made to load a program with an incorrect format."
    )));
    assert!(donut_loader_blocked_by_amsi(&anyhow::anyhow!(
        "Could not load file or assembly '12288 bytes loaded from ...'"
    )));
    assert!(!donut_loader_blocked_by_amsi(&anyhow::anyhow!(
        "Process with an Id of 999999 is not running."
    )));
}

#[test]
fn explicit_remote_command_paths_and_quoted_invocation() {
    for path in [
        r".\",
        r"..\file.ps1",
        r"C:\Windows\",
        "/tmp/file",
        r"\\server\share",
    ] {
        assert!(explicit_remote_path(path));
    }
    assert!(!explicit_remote_path("Get-ChildItem"));
    assert!(!explicit_remote_path("[Example]::Echo()"));
    assert_eq!(
        remote_path_replacement(r".\a's file.ps1", true),
        "& '.\\a''s file.ps1'"
    );
    assert_eq!(
        remote_path_replacement(r".\a's file.ps1", false),
        "'.\\a''s file.ps1'"
    );
    assert_eq!(
        remote_path_replacement(r".\a folder\", true),
        "'.\\a folder\\'"
    );
}

#[test]
fn local_completion_quotes_paths_for_the_shell_parser() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("a's file.txt");
    std::fs::write(&file, b"fixture").unwrap();
    let prefix = format!("{}/a", directory.path().display());
    let candidates = local_candidates(&prefix, &[]);
    assert_eq!(candidates.len(), 1);
    assert_eq!(
        arguments(&format!("upload {}", candidates[0].replacement)).unwrap()[1],
        file.to_string_lossy()
    );
    assert_eq!(completion_word("'path with space"), "path with space");
    assert_eq!(completion_word("'path with space'"), "path with space");
}
#[test]
fn scripts_decode_bom_and_unicode() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("test.ps1");
    let text = "Write-Output 'héllo 世界'";
    let bytes: Vec<_> = [0xff, 0xfe]
        .into_iter()
        .chain(text.encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    std::fs::write(&file, bytes).unwrap();
    assert_eq!(read_script(&file).unwrap(), text);
}
#[test]
fn completion_preserves_quoted_path_token() {
    assert_eq!(token_start("download 'C:\\Program Files\\a"), 9);
}
#[test]
fn local_completion_filters_files_but_retains_directories() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["a.ps1", "b.DLL", "c.exe", "d.psm1", "e.psd1", "f.txt"] {
        std::fs::write(dir.path().join(name), b"fixture").unwrap();
    }
    std::fs::create_dir(dir.path().join("folder")).unwrap();
    let prefix = format!("{}/", dir.path().display());
    for (extensions, expected) in [
        (
            SCRIPT_EXTENSIONS,
            vec!["a.ps1", "d.psm1", "e.psd1", "folder"],
        ),
        (&["dll"][..], vec!["b.DLL", "folder"]),
        (&["exe"][..], vec!["c.exe", "folder"]),
    ] {
        let candidates = local_candidates(&prefix, extensions);
        assert_eq!(
            candidates
                .iter()
                .map(|p| p.display.as_str())
                .collect::<Vec<_>>(),
            expected
        );
    }
}

#[test]
fn tilde_expansion_and_configured_directory_resolution() {
    let home = dirs::home_dir().unwrap();
    assert_eq!(local_path("~"), home);
    assert_eq!(local_path("~/a b"), home.join("a b"));
    assert_eq!(local_path(r"~\a b"), home.join("a b"));
    let directory = tempfile::Builder::new()
        .prefix("ewr-completion-")
        .tempdir_in(&home)
        .unwrap();
    std::fs::write(directory.path().join("a b.ps1"), b"fixture").unwrap();
    let relative = directory
        .path()
        .strip_prefix(&home)
        .unwrap()
        .to_string_lossy();
    let prefix = format!("~/{relative}/a");
    let candidates = local_candidates(&prefix, SCRIPT_EXTENSIONS);
    assert_eq!(candidates.len(), 1);
    assert!(candidates[0].display.starts_with('~'));
    let completed = arguments(&format!("loadps {}", candidates[0].replacement)).unwrap();
    assert_eq!(
        resolve_local(&completed[1], None),
        directory.path().join("a b.ps1")
    );
    assert_eq!(
        resolve_local("a b.ps1", Some(directory.path())),
        directory.path().join("a b.ps1")
    );
}

#[test]
fn remote_listing_filters_directories_and_preserves_paths() {
    let entries = vec![
        RemoteEntry {
            name: "log.txt".into(),
            directory: false,
        },
        RemoteEntry {
            name: "logs".into(),
            directory: true,
        },
    ];
    let all = remote_candidates(r".\lo", &entries, false, false);
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].replacement, r".\log.txt");
    let folders = remote_candidates(r".\lo", &entries, true, false);
    assert_eq!(folders.len(), 1);
    assert_eq!(folders[0].replacement, r".\logs\");
    for name in BUILTINS {
        assert_eq!(
            helper_available(name, true),
            matches!(*name, "menu" | "clear" | "cls" | "exit" | "quit")
        );
    }
}
