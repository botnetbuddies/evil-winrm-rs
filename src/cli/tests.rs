use super::*;
use winrm_rs::EncryptionMode;

#[test]
fn tls_selects_5986_and_custom_port_wins() {
    let mut args =
        Cli::try_parse_from(["ewr", "-i", "host", "-u", "user", "--no-pass", "--ssl"]).unwrap();
    assert_eq!(args.connection().unwrap().1.port, 5986);
    args.port = Some(12345);
    assert_eq!(args.connection().unwrap().1.port, 12345);
}
#[test]
fn hash_forms_validate_without_treating_a_hash_as_a_password() {
    assert_eq!(
        parse_hash("00000000000000000000000000000000:a4f49c406510bdcab6824ee7c30fd852").unwrap(),
        parse_hash("a4f49c406510bdcab6824ee7c30fd852").unwrap()
    );
    for hash in [
        "short",
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        "éééééééééééééééé",
    ] {
        assert!(parse_hash(hash).is_err());
    }
}
#[test]
fn password_and_hash_conflict() {
    assert!(
        Cli::try_parse_from([
            "ewr",
            "-i",
            "host",
            "-u",
            "user",
            "-p",
            "secret",
            "-H",
            "a4f49c406510bdcab6824ee7c30fd852"
        ])
        .is_err()
    );
}
#[test]
fn mcp_mode_needs_no_target() {
    assert!(Cli::try_parse_from(["ewr", "--mcp"]).is_ok());
}
#[test]
fn operational_options_validate_and_password_file_preserves_spaces() {
    for flags in [
        vec!["--env", "NOVALUE"],
        vec!["--env", "=empty"],
        vec!["--connect-timeout", "0"],
        vec!["--operation-timeout", "0"],
        vec!["--max-envelope", "4096"],
        vec!["--retries", "11"],
        vec!["--password-file", "file", "--password-stdin"],
    ] {
        assert!(
            Cli::try_parse_from([vec!["ewr", "-i", "host", "-u", "user"], flags].concat()).is_err()
        );
    }
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), b" password with spaces \r\nignored").unwrap();
    let mut args = Cli::try_parse_from([
        "ewr",
        "-i",
        "host",
        "-u",
        "user",
        "--password-file",
        file.path().to_str().unwrap(),
        "--env",
        "A=a=b",
        "--env",
        "EMPTY=",
        "--cd",
        "C:\\path ' space",
        "--idle-timeout",
        "90",
        "--connect-timeout",
        "7",
        "--operation-timeout",
        "4",
        "--retries",
        "2",
        "--max-envelope",
        "131072",
    ])
    .unwrap();
    let (_, config, credentials) = args.connection().unwrap();
    assert_eq!(
        args.environment,
        [("A".into(), "a=b".into()), ("EMPTY".into(), "".into())]
    );
    assert_eq!(config.connect_timeout_secs, 7);
    assert_eq!(config.operation_timeout_secs, 4);
    assert_eq!(config.idle_timeout_secs, Some(90));
    assert_eq!(config.max_envelope_size, 131072);
    assert_eq!(config.max_retries, 2);
    // Reading the secret must leave no copy in the parsed CLI options or Debug output.
    assert_eq!(
        format!("{credentials:?}")
            .matches("password with spaces")
            .count(),
        0
    );
    assert!(args.password.is_none());
}
#[test]
fn stdin_password_preserves_spaces_and_only_strips_line_endings() {
    for (input, expected) in [
        (" password \r\n", " password "),
        ("hello\nignored", "hello"),
        ("\n", ""),
        ("hello", "hello"),
        ("hello\r", "hello"),
    ] {
        assert_eq!(
            read_password_line(std::io::Cursor::new(input)).unwrap(),
            expected
        );
    }
    assert!(read_password_line(std::io::Cursor::new("")).is_err());
    assert!(read_password_line(std::io::Cursor::new("x".repeat(65537))).is_err());
}
#[test]
fn new_options_validate_conflicts_and_authentication_config() {
    for flags in [
        vec!["--password-stdin", "-p", "secret"],
        vec!["--password-stdin", "--no-pass"],
        vec!["--json"],
        vec!["--exit-code"],
    ] {
        assert!(
            Cli::try_parse_from([vec!["ewr", "-i", "host", "-u", "user"], flags].concat()).is_err()
        );
    }
    for auth in [
        "ntlm",
        "basic",
        "kerberos",
        "certificate",
        "credssp",
        "negotiate",
    ] {
        let mut values = vec![
            "ewr",
            "-i",
            "host",
            "-u",
            "user",
            "--no-pass",
            "--auth",
            auth,
        ];
        if auth == "certificate" {
            values.extend(["--cert-pem", "client.pem", "--priv-key-pem", "key.pem"]);
        }
        let mut args = Cli::try_parse_from(values).unwrap();
        if (auth == "kerberos" && !cfg!(feature = "kerberos"))
            || (auth == "credssp" && !cfg!(feature = "credssp"))
        {
            assert!(args.connection().is_err());
            continue;
        }
        let (_, config, _) = args.connection().unwrap();
        assert_eq!(config.use_tls, matches!(auth, "certificate" | "credssp"));
    }
    for flags in [
        vec!["--auth", "ntlm", "--kerberos"],
        vec!["--auth", "basic", "--credssp"],
        vec!["--auth", "certificate"],
        vec!["--auth", "basic", "--encryption", "always"],
    ] {
        let mut args = Cli::try_parse_from(
            [vec!["ewr", "-i", "host", "-u", "user", "--no-pass"], flags].concat(),
        )
        .unwrap();
        assert!(args.connection().is_err());
    }
    let mut args = Cli::try_parse_from([
        "ewr",
        "-i",
        "host",
        "-u",
        "user",
        "--no-pass",
        "--proxy",
        "socks5h://proxy.test:1080",
        "--encryption",
        "always",
    ])
    .unwrap();
    let config = args.connection().unwrap().1;
    assert_eq!(config.proxy.as_deref(), Some("socks5h://proxy.test:1080"));
    assert_eq!(config.encryption, EncryptionMode::Always);
}
