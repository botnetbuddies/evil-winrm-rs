//! CLI automation failures must still produce one usable JSON result.
use std::{
    io::Write,
    process::{Command, Stdio},
};

fn invoke(flags: &[&str], password: &[u8]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_evil-winrm-rs"));
    command
        .args([
            "-i",
            "127.0.0.1",
            "-u",
            "fixture",
            "--password-stdin",
            "--json",
            "--command",
            "Get-Date",
        ])
        .args(flags)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(password).unwrap();
    child.wait_with_output().unwrap()
}
#[test]
fn stdin_eof_and_invalid_proxy_return_json_without_a_prompt_or_secret() {
    for (flags, password, message) in [
        (vec![], &b""[..], "stdin contained no password line"),
        (
            vec!["--proxy", "ftp://user:proxy-secret@example.test"],
            &b"stdin-secret\n"[..],
            "proxy",
        ),
    ] {
        let output = invoke(&flags, password);
        assert_eq!(output.status.code(), Some(1));
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(json["success"], false);
        assert_eq!(json["exit_code"], 1);
        assert!(json["error"].as_str().unwrap().contains(message));
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !combined.contains("stdin-secret")
                && !combined.contains("proxy-secret")
                && !combined.contains("Password:")
        );
        assert!(!combined.contains('\x1b'));
    }
}
#[test]
fn automation_flags_require_one_command() {
    for flag in ["--json", "--exit-code"] {
        let output = Command::new(env!("CARGO_BIN_EXE_evil-winrm-rs"))
            .args(["-i", "127.0.0.1", flag])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("--command"));
    }
}
