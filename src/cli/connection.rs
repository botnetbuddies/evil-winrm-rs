//! Resolve authentication and transport settings, then initialize PSRP session state.
use super::credentials::{parse_hash, read_password_line, split_username};
use super::{Authentication, Cli, Encryption};
use anyhow::{Context, Result, bail};
use std::io::IsTerminal;
use winrm_rs::{AuthMethod, EncryptionMode, WinrmConfig, WinrmCredentials};
impl Cli {
    pub fn connection(&mut self) -> Result<(String, WinrmConfig, WinrmCredentials)> {
        if !(1..=86400).contains(&self.connect_timeout)
            || !(1..=86400).contains(&self.operation_timeout)
            || self.idle_timeout.is_some_and(|v| !(1..=86400).contains(&v))
        {
            bail!("timeouts must be between 1 and 86400 seconds");
        }
        if self.retries > 10 || !(65536..=16777216).contains(&self.max_envelope) {
            bail!("invalid retry count or envelope size");
        }
        let host = self.host.clone().context("a target host is required")?;
        if host.contains(['/', '@', '?', '#']) {
            bail!("--ip must be a hostname or IP address");
        }
        if !self.uri.starts_with('/') {
            self.uri.insert(0, '/');
        }
        if self.uri.contains(['?', '#', '\r', '\n']) {
            bail!("invalid WSMan URI path");
        }
        for path in [&self.scripts, &self.executables].into_iter().flatten() {
            if !path.is_dir() {
                bail!("{} is not a directory", path.display());
            }
        }
        let kerberos_options =
            self.kerberos || self.realm.is_some() || self.ccache.is_some() || self.keytab.is_some();
        if self.keytab.is_some() && self.user.as_deref().is_none_or(str::is_empty) {
            bail!("--keytab requires --user user@REALM");
        }
        let auth = self.auth.unwrap_or(if self.credssp {
            Authentication::Credssp
        } else if kerberos_options {
            Authentication::Kerberos
        } else if self.certificate.is_some() || self.pfx.is_some() {
            Authentication::Certificate
        } else {
            Authentication::Ntlm
        });
        if self.credssp && auth != Authentication::Credssp {
            bail!("--credssp conflicts with the selected --auth method");
        }
        if kerberos_options && !matches!(auth, Authentication::Kerberos | Authentication::Negotiate)
        {
            bail!("Kerberos options conflict with the selected authentication method");
        }
        if (self.certificate.is_some() || self.pfx.is_some()) && auth != Authentication::Certificate
        {
            bail!("certificate options conflict with the selected authentication method");
        }
        if auth == Authentication::Certificate && self.certificate.is_none() && self.pfx.is_none() {
            bail!("--auth certificate requires --cert-pem/--priv-key-pem or --pfx");
        }
        if self.pfx.is_some() && !cfg!(feature = "pkcs12") {
            bail!("rebuild with the pkcs12 feature enabled");
        }
        if let Some(name) = &self.tls_server_name
            && (name.is_empty() || name.contains(['/', '\\', '@', '?', '#', ':', ' ', '\r', '\n']))
        {
            bail!("--tls-server-name must be a DNS hostname");
        }
        if self.hash.is_some() && auth != Authentication::Ntlm {
            bail!("--hash requires NTLM authentication");
        }
        if auth == Authentication::Kerberos && !cfg!(feature = "kerberos") {
            bail!("rebuild with the kerberos feature enabled");
        }
        if auth == Authentication::Credssp && !cfg!(feature = "credssp") {
            bail!(
                "rebuild with the credssp feature enabled (cargo build --release --features credssp)"
            );
        }
        if self.encryption == Encryption::Always
            && !matches!(
                auth,
                Authentication::Ntlm | Authentication::Kerberos | Authentication::Negotiate
            )
        {
            bail!("--encryption always requires NTLM or Kerberos authentication");
        }
        if let Some(proxy) = &self.proxy {
            winrm_rs::proxy::validate(proxy)?;
        }
        let kerberos = matches!(auth, Authentication::Kerberos | Authentication::Negotiate);
        if let Some(cache) = &self.ccache {
            let data =
                std::fs::read(cache).with_context(|| format!("reading {}", cache.display()))?;
            if !data.starts_with(&[5, 4])
                && !data.starts_with(&[5, 3])
                && data.first() != Some(&0x76)
            {
                bail!("unrecognized Kerberos ticket format");
            }
            // Per-client selection avoids mutating process-wide Kerberos state in MCP mode.
        }
        if (matches!(
            auth,
            Authentication::Ntlm | Authentication::Basic | Authentication::Credssp
        ) || self.password_stdin
            || self.password_file.is_some())
            && self.user.as_deref().is_none_or(str::is_empty)
        {
            bail!("--user is required for the selected authentication method");
        }
        if self.password_stdin {
            if std::io::stdin().is_terminal() {
                bail!("--password-stdin requires piped or redirected input");
            }
            self.password = Some(read_password_line(std::io::stdin().lock())?);
        }
        if let Some(path) = &self.password_file {
            let file = std::fs::File::open(path).context("opening password file")?;
            self.password = Some(read_password_line(std::io::BufReader::new(file))?);
        }
        if self.password.is_none()
            && self.hash.is_none()
            && auth != Authentication::Certificate
            && !kerberos
            && !self.no_pass
        {
            self.password = Some(rpassword::prompt_password("Password: ")?);
        }
        let (domain, mut username) = split_username(self.user.as_deref().unwrap_or(""));
        if kerberos
            && !username.contains('@')
            && domain.is_empty()
            && let Some(realm) = &self.realm
        {
            username = format!("{username}@{realm}");
        }
        let mut credentials =
            WinrmCredentials::new(username, self.password.take().unwrap_or_default(), domain);
        if let Some(hash) = &self.hash {
            credentials.nt_hash = Some(zeroize::Zeroizing::new(parse_hash(hash)?));
        }
        let config = WinrmConfig {
            operation_timeout_secs: self.operation_timeout,
            connect_timeout_secs: self.connect_timeout,
            max_retries: self.retries,
            max_envelope_size: self.max_envelope,
            max_output_bytes: (self.max_output != 0).then_some(self.max_output),
            idle_timeout_secs: self.idle_timeout,
            port: self.port.unwrap_or(
                if self.tls || matches!(auth, Authentication::Certificate | Authentication::Credssp)
                {
                    5986
                } else {
                    5985
                },
            ),
            use_tls: self.tls
                || matches!(auth, Authentication::Certificate | Authentication::Credssp),
            accept_invalid_certs: !self.verify_tls && self.ca_cert.is_none(),
            ca_cert: self
                .ca_cert
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
            tls_server_name: self.tls_server_name.clone(),
            client_pfx: self.pfx.as_ref().map(|p| p.to_string_lossy().into_owned()),
            client_pfx_password: self
                .pfx_password_file
                .as_ref()
                .map(|path| -> Result<_> {
                    let file = std::fs::File::open(path).context("opening PFX password file")?;
                    Ok(read_password_line(std::io::BufReader::new(file))?.into())
                })
                .transpose()?,
            auth_method: match auth {
                Authentication::Ntlm => AuthMethod::Ntlm,
                Authentication::Kerberos => AuthMethod::Kerberos,
                Authentication::Negotiate if cfg!(feature = "kerberos") => AuthMethod::Kerberos,
                Authentication::Negotiate => AuthMethod::Ntlm,
                Authentication::Certificate => AuthMethod::Certificate,
                Authentication::Credssp => AuthMethod::CredSsp,
                Authentication::Basic => AuthMethod::Basic,
            },
            proxy: self.proxy.clone(),
            encryption: match self.encryption {
                Encryption::Auto => EncryptionMode::Auto,
                Encryption::Always => EncryptionMode::Always,
                Encryption::Never => EncryptionMode::Never,
            },
            client_cert_pem: self
                .certificate
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
            client_key_pem: self
                .private_key
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
            user_agent: Some(self.user_agent.clone()),
            endpoint_path: self.uri.clone(),
            kerberos_service: self.spn_prefix.clone(),
            kerberos_hostname: self.spn_hostname.clone(),
            kerberos_realm: self.realm.clone(),
            kerberos_ccache: self
                .ccache
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
            kerberos_keytab: self
                .keytab
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
            ..Default::default()
        };
        Ok((host, config, credentials))
    }
}

/// Apply PSRP initialization independently of command-line parsing.
pub(crate) async fn initialize(
    session: &crate::session::Session,
    directory: Option<&str>,
    environment: &[(String, String)],
) -> Result<()> {
    if directory.is_none() && environment.is_empty() {
        return Ok(());
    }
    if session.jea {
        bail!("--cd and --env require a full-language PowerShell endpoint");
    }
    let mut script = String::from("& { $ErrorActionPreference = 'Stop'; ");
    for (key, value) in environment {
        script.push_str(&format!(
            "[Environment]::SetEnvironmentVariable({}, {}, 'Process'); ",
            crate::command::quote(key),
            crate::command::quote(value)
        ));
    }
    if let Some(directory) = directory {
        script.push_str(&format!(
            "Set-Location -LiteralPath {} -ErrorAction Stop; ",
            crate::command::quote(directory)
        ));
    }
    script.push('}');
    session
        .raw(&script)
        .await
        .context("applying remote session settings")?;
    Ok(())
}
