//! Live integration tests against a real Windows host.
//!
//! Every test in this file is `#[ignore]`-d by default. They only run
//! when the caller explicitly passes `--ignored` **and** provides the
//! required env vars. See [Vagrantfile](../Vagrantfile) for how to
//! spin up a disposable VM.
//!
//! ```bash
//! vagrant.exe up --provider=hyperv
//! vagrant.exe ssh -c "ipconfig"     # grab the VM IP
//! PSRP_INTEGRATION_HOST=<ip> \
//! PSRP_INTEGRATION_USER=vagrant \
//! PSRP_INTEGRATION_PASS=vagrant \
//!   cargo test --test integration_real -- --ignored
//! ```
//!
//! Set `PSRP_INTEGRATION_TLS=1` to use HTTPS on port 5986, or the env var
//! `PSRP_INTEGRATION_PORT` to override the port.

use std::env;

use psrp_rs::{
    AuthMethod, Command, Pipeline, PipelineState, PsValue, RunspacePool, WinrmClient, WinrmConfig,
    WinrmCredentials, WinrmPsrpTransport,
};

struct LiveConfig {
    host: String,
    user: String,
    pass: String,
    port: u16,
    tls: bool,
}

impl LiveConfig {
    fn from_env() -> Option<Self> {
        let host = env::var("PSRP_INTEGRATION_HOST").ok()?;
        let user = env::var("PSRP_INTEGRATION_USER").unwrap_or_else(|_| "vagrant".into());
        let pass = env::var("PSRP_INTEGRATION_PASS").unwrap_or_else(|_| "vagrant".into());
        let tls = env::var("PSRP_INTEGRATION_TLS")
            .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
        let default_port = if tls { 5986 } else { 5985 };
        let port = env::var("PSRP_INTEGRATION_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(default_port);
        Some(Self {
            host,
            user,
            pass,
            port,
            tls,
        })
    }
}

fn build_client(cfg: &LiveConfig) -> WinrmClient {
    // Use the auth method specified by env, defaulting to Basic for HTTP
    // (works through WSL → Hyper-V proxies) and NTLM for HTTPS.
    let auth_method = match std::env::var("PSRP_INTEGRATION_AUTH").ok().as_deref() {
        Some("ntlm") => AuthMethod::Ntlm,
        Some("basic") => AuthMethod::Basic,
        _ => {
            if cfg.tls {
                AuthMethod::Ntlm
            } else {
                AuthMethod::Basic
            }
        }
    };
    WinrmClient::new(
        WinrmConfig {
            auth_method,
            port: cfg.port,
            use_tls: cfg.tls,
            accept_invalid_certs: cfg.tls, // eval box, self-signed
            operation_timeout_secs: 20,
            ..Default::default()
        },
        WinrmCredentials::new(cfg.user.clone(), cfg.pass.clone(), ""),
    )
    .expect("build WinrmClient")
}

async fn open_pool<'c>(
    client: &'c WinrmClient,
    host: &str,
) -> RunspacePool<WinrmPsrpTransport<'c>> {
    let (rpid, creation) = RunspacePool::<WinrmPsrpTransport<'_>>::build_creation_fragments(1, 1)
        .expect("build creation fragments");
    let transport = WinrmPsrpTransport::open(client, host, &creation)
        .await
        .expect("open transport");
    RunspacePool::open_from_transport(transport, rpid, 1, 1)
        .await
        .expect("open runspace pool")
}

#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_HOST"]
async fn live_smoke_one_plus_one() {
    let Some(cfg) = LiveConfig::from_env() else {
        return;
    };
    let client = build_client(&cfg);
    let mut pool = open_pool(&client, &cfg.host).await;

    let out = pool.run_script("1 + 1").await.expect("run_script");
    assert_eq!(out.len(), 1, "expected a single result, got {out:?}");
    assert_eq!(out[0].as_i32(), Some(2), "got {out:?}");

    // Close may fail if the server already tore down the shell after
    // CommandState/Done. This is expected and harmless.
    let _ = pool.close().await;
}

#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_HOST"]
async fn live_get_date_returns_object() {
    let Some(cfg) = LiveConfig::from_env() else {
        return;
    };
    let client = build_client(&cfg);
    let mut pool = open_pool(&client, &cfg.host).await;

    let out = pool.run_script("Get-Date").await.expect("run_script");
    assert!(!out.is_empty(), "Get-Date returned nothing");
    // DateTime is emitted either as <DT> (future) or an Obj containing one.
    // Until we implement <DT>, just assert we got *something* back.
    let _ = pool.close().await;
}

#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_HOST"]
async fn live_get_process_select_name_id() {
    let Some(cfg) = LiveConfig::from_env() else {
        return;
    };
    let client = build_client(&cfg);
    let mut pool = open_pool(&client, &cfg.host).await;

    let out = pool
        .run_script("Get-Process | Select-Object -First 3 Name, Id")
        .await
        .expect("run_script");
    assert_eq!(out.len(), 3, "expected exactly 3 rows, got {}", out.len());
    for row in &out {
        let props = row.properties().expect("row is an Obj with MS");
        assert!(props.get("Name").is_some(), "Name missing");
        assert!(props.get("Id").is_some(), "Id missing");
    }
    let _ = pool.close().await;
}

#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_HOST"]
async fn live_pipeline_builder_with_parameter() {
    let Some(cfg) = LiveConfig::from_env() else {
        return;
    };
    let client = build_client(&cfg);
    let mut pool = open_pool(&client, &cfg.host).await;

    // `Write-Output 42` via builder instead of raw script.
    let pipeline = Pipeline::empty()
        .add_command(Command::new("Write-Output").with_parameter("InputObject", PsValue::I32(42)));

    let result = pipeline
        .run_all_streams(&mut pool)
        .await
        .expect("run_all_streams");
    assert_eq!(result.state, PipelineState::Completed);
    assert_eq!(result.output, vec![PsValue::I32(42)]);
    assert!(result.errors.is_empty());

    let _ = pool.close().await;
}

#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_HOST"]
async fn live_error_stream_is_captured() {
    let Some(cfg) = LiveConfig::from_env() else {
        return;
    };
    let client = build_client(&cfg);
    let mut pool = open_pool(&client, &cfg.host).await;

    // `Write-Error` sends on the error stream without terminating the pipeline.
    let result = Pipeline::new("Write-Error 'boom' -ErrorAction Continue; 'after'")
        .run_all_streams(&mut pool)
        .await
        .expect("run_all_streams");
    assert_eq!(result.state, PipelineState::Completed);
    assert!(
        !result.errors.is_empty(),
        "expected an ErrorRecord, got {result:?}"
    );
    assert_eq!(result.output, vec![PsValue::String("after".into())]);

    let _ = pool.close().await;
}

#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_HOST"]
async fn live_warning_stream_is_captured() {
    let Some(cfg) = LiveConfig::from_env() else {
        return;
    };
    let client = build_client(&cfg);
    let mut pool = open_pool(&client, &cfg.host).await;

    let result = Pipeline::new("Write-Warning 'careful'; 'done'")
        .run_all_streams(&mut pool)
        .await
        .expect("run_all_streams");
    assert_eq!(result.state, PipelineState::Completed);
    assert!(
        !result.warnings.is_empty(),
        "expected a warning record, got {result:?}"
    );

    let _ = pool.close().await;
}

#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_HOST"]
async fn live_disconnect_reconnect_pool() {
    let Some(cfg) = LiveConfig::from_env() else {
        return;
    };
    let client = build_client(&cfg);

    // Open + run something + disconnect.
    let mut pool = open_pool(&client, &cfg.host).await;
    let pre = pool.run_script("'before'").await.unwrap();
    assert_eq!(pre, vec![PsValue::String("before".into())]);
    let disconnect_result = pool.disconnect().await;
    // The PowerShell provider (pwrshplugin.dll) on some Windows versions
    // does not support disconnect/reconnect for PSRP shells. When the
    // server rejects it, we skip the rest of the test rather than fail.
    let disconnected = match disconnect_result {
        Ok(d) => d,
        Err(e) => {
            eprintln!("disconnect not supported on this server: {e}");
            return;
        }
    };

    // Rebuild the transport with the same shell id and reconnect.
    let transport =
        psrp_rs::WinrmPsrpTransport::reconnect(&client, &cfg.host, disconnected.shell_id())
            .await
            .expect("rebuild transport");
    let mut pool = disconnected.reconnect(transport).await.expect("reconnect");
    let post = pool.run_script("'after'").await.unwrap();
    assert_eq!(post, vec![PsValue::String("after".into())]);
    let _ = pool.close().await;
}

#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_HOST"]
async fn live_pool_survives_multiple_pipelines() {
    let Some(cfg) = LiveConfig::from_env() else {
        return;
    };
    let client = build_client(&cfg);
    let mut pool = open_pool(&client, &cfg.host).await;

    for i in 1..=3i32 {
        let out = pool
            .run_script(&format!("{i} * 10"))
            .await
            .expect("run_script");
        assert_eq!(out, vec![PsValue::I32(i * 10)]);
    }

    let _ = pool.close().await;
}

// ---- SSH transport tests ----

#[cfg(feature = "ssh")]
#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_SSH_HOST"]
async fn live_ssh_one_plus_one() {
    let host = match std::env::var("PSRP_INTEGRATION_SSH_HOST") {
        Ok(h) => h,
        Err(_) => return,
    };
    let user = std::env::var("PSRP_INTEGRATION_SSH_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("PSRP_INTEGRATION_SSH_PASS").unwrap_or_else(|_| "vagrant".into());
    let port: u16 = std::env::var("PSRP_INTEGRATION_SSH_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(22);

    let transport = psrp_rs::SshPsrpTransport::connect(
        psrp_rs::SshConfig::new(host, user, psrp_rs::SshAuth::Password(pass)).with_port(port),
    )
    .await
    .expect("SSH connect");

    let mut pool = psrp_rs::RunspacePool::open_with_transport(transport)
        .await
        .expect("open pool over SSH");
    let out = pool.run_script("1 + 1").await.expect("run_script");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].as_i32(), Some(2));
    let _ = pool.close().await;
}

#[cfg(feature = "ssh")]
#[tokio::test]
#[ignore = "requires PSRP_INTEGRATION_SSH_HOST"]
async fn live_ssh_multiple_scripts() {
    let host = match std::env::var("PSRP_INTEGRATION_SSH_HOST") {
        Ok(h) => h,
        Err(_) => return,
    };
    let user = std::env::var("PSRP_INTEGRATION_SSH_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("PSRP_INTEGRATION_SSH_PASS").unwrap_or_else(|_| "vagrant".into());

    let transport = psrp_rs::SshPsrpTransport::connect(psrp_rs::SshConfig::new(
        host,
        user,
        psrp_rs::SshAuth::Password(pass),
    ))
    .await
    .expect("SSH connect");

    let mut pool = psrp_rs::RunspacePool::open_with_transport(transport)
        .await
        .expect("open pool over SSH");
    for i in 1..=3i32 {
        let out = pool
            .run_script(&format!("{i} * 10"))
            .await
            .expect("run_script");
        assert_eq!(out, vec![PsValue::I32(i * 10)]);
    }
    let _ = pool.close().await;
}
