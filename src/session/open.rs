//! Client credential preparation and PSRP runspace negotiation.
use super::{Output, host::HostBuffer, limits::OutputBudget, transport::Transport};
#[cfg(feature = "kerberos")]
use anyhow::Context;
use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use psrp_rs::{Pipeline, RunspacePool};
use std::sync::{Arc, atomic::AtomicBool};
use winrm_rs::{WinrmClient, WinrmConfig, WinrmCredentials};
pub(super) struct PreparedClient {
    pub client: WinrmClient,
    _ticket: Option<tempfile::NamedTempFile>,
    _keytab_cache: Option<tempfile::NamedTempFile>,
    pub max_send_bytes: usize,
}
pub(super) struct OpenedRunspace {
    pub pool: RunspacePool<Transport>,
    pub jea: bool,
    pub initial_functions: Vec<String>,
}
pub(super) async fn client(
    host: &str,
    config: WinrmConfig,
    credentials: WinrmCredentials,
) -> Result<PreparedClient> {
    let mut config = config;
    #[cfg(feature = "kerberos")]
    let keytab_cache = if let Some(path) = config.kerberos_keytab.take() {
        use std::io::Write;
        let mut cache = tempfile::NamedTempFile::new()?;
        let principal = if credentials.username.contains('@') {
            credentials.username.clone()
        } else {
            format!(
                "{}@{}",
                credentials.username,
                config
                    .kerberos_realm
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .context("--keytab requires a UPN or --realm")?
            )
        };
        let bytes = zeroize::Zeroizing::new(
            kerberos_cache::login_keytab(std::path::Path::new(&path), &principal).await?,
        );
        cache.write_all(&bytes)?;
        cache.flush()?;
        config.kerberos_ccache = Some(cache.path().to_string_lossy().into_owned());
        Some(cache)
    } else {
        None
    };
    if matches!(config.auth_method, winrm_rs::AuthMethod::Kerberos)
        && config.kerberos_hostname.is_none()
        && let Ok(ip) = host.trim_matches(['[', ']']).parse::<std::net::IpAddr>()
        && let Ok(Ok(name)) =
            tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip)).await
    {
        config.kerberos_hostname = Some(name.trim_end_matches('.').to_ascii_lowercase());
    }
    let ticket = config
        .kerberos_ccache
        .as_deref()
        .map(crate::ticket::prepare)
        .transpose()?
        .flatten();
    if let Some(file) = &ticket {
        config.kerberos_ccache = Some(file.path().to_string_lossy().into_owned());
    }
    let max_send_bytes = (config.max_envelope_size as usize).saturating_sub(8192) / 4 * 3;
    let client = WinrmClient::new(config, credentials)?;
    #[cfg(not(feature = "kerberos"))]
    let keytab_cache: Option<tempfile::NamedTempFile> = None;
    Ok(PreparedClient {
        client,
        _ticket: ticket,
        _keytab_cache: keytab_cache,
        max_send_bytes,
    })
}

pub(super) async fn runspace(
    prepared: &PreparedClient,
    host: &str,
    configuration: &str,
    host_buffer: Arc<HostBuffer>,
    output_budget: Arc<OutputBudget>,
) -> Result<OpenedRunspace> {
    let (id, fragments) =
        RunspacePool::<Transport>::build_creation_fragments_with_host(1, 1, host_buffer.as_ref())?;
    let uri = format!("http://schemas.microsoft.com/powershell/{configuration}");
    let shell = prepared
        .client
        .open_psrp_shell(host, &B64.encode(fragments), &uri)
        .await?;
    let command_id = shell.shell_id().into();
    let transport = Transport {
        shell: Some(shell.into_owned()),
        command_id,
        pending_receive: None,
        stop_acknowledged: AtomicBool::new(false),
        max_send_bytes: prepared.max_send_bytes,
        output_budget: output_budget.clone(),
    };
    let mut pool =
        RunspacePool::open_from_transport_with_host(transport, id, 1, 1, host_buffer.clone())
            .await?;
    // Endpoint names do not describe their policy: PowerShell.7
    // and other named endpoints can provide FullLanguage. A
    // restricted endpoint rejects this read-only script; retain
    // that failure so its runspace remains usable for cmdlets.
    let capability = Pipeline::new("$ExecutionContext.SessionState.LanguageMode.ToString()")
        .retaining_failed_output()
        .run_all_streams(&mut pool)
        .await;
    let result = match capability {
        Ok(result) => result,
        Err(error) => {
            let _ = pool.close().await;
            return Err(error.into());
        }
    };
    let mut mode = Output::default();
    mode.append(result);
    let jea = mode.failed || !mode.errors.is_empty() || mode.stdout.trim() != "FullLanguage";
    let mut initial_functions = Output::default();
    if !jea {
        initial_functions.append(
            Pipeline::new("Get-ChildItem Function: | Select-Object -ExpandProperty Name")
                .retaining_failed_output()
                .run_all_streams(&mut pool)
                .await?,
        );
    }
    let initial_functions = initial_functions
        .checked()?
        .lines()
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    Ok(OpenedRunspace {
        pool,
        jea,
        initial_functions,
    })
}
