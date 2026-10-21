//! Reusable connection policy shared by direct CLI, broker sessions and tunnels.
use crate::{
    cli::{Authentication, Cli},
    session::Session,
};
use anyhow::Result;
use winrm_rs::{AuthMethod, WinrmConfig, WinrmCredentials};

#[derive(Clone)]
pub struct ConnectionProfile {
    pub host: String,
    pub config: WinrmConfig,
    credentials: WinrmCredentials,
    configuration: String,
    negotiate: bool,
    directory: Option<String>,
    environment: Vec<(String, String)>,
}
impl ConnectionProfile {
    pub fn from_cli(args: &mut Cli) -> Result<Self> {
        let (host, config, credentials) = args.connection()?;
        Ok(Self {
            host,
            config,
            credentials,
            configuration: args.configuration_name.clone(),
            negotiate: args.auth == Some(Authentication::Negotiate),
            directory: args.directory.clone(),
            environment: args.environment.clone(),
        })
    }
    #[cfg(feature = "mcp")]
    pub(crate) fn login_request(&self) -> crate::broker::models::Login {
        use crate::broker::models::Login;
        use secrecy::ExposeSecret;
        let c = &self.config;
        Login {
            ip: self.host.clone(),
            username: self.username(),
            password: self.credentials.password.expose_secret().to_owned(),
            port: Some(c.port),
            ssl: c.use_tls,
            uri: Some(c.endpoint_path.clone()),
            auth: Some(
                if self.negotiate {
                    "negotiate"
                } else {
                    match c.auth_method {
                        AuthMethod::Ntlm => "ntlm",
                        AuthMethod::Kerberos => "kerberos",
                        AuthMethod::Certificate => "certificate",
                        AuthMethod::CredSsp => "credssp",
                        AuthMethod::Basic => "basic",
                    }
                }
                .into(),
            ),
            encryption: Some(
                match c.encryption {
                    winrm_rs::EncryptionMode::Auto => "auto",
                    winrm_rs::EncryptionMode::Always => "always",
                    winrm_rs::EncryptionMode::Never => "never",
                }
                .into(),
            ),
            proxy: c.proxy.clone(),
            ua: c.user_agent.clone(),
            spn_prefix: Some(c.kerberos_service.clone()),
            spn_hostname: c.kerberos_hostname.clone(),
            cert_pem: c.client_cert_pem.clone(),
            priv_key_pem: c.client_key_pem.clone(),
            pfx: c.client_pfx.clone(),
            pfx_password_file: None,
            pfx_password: c
                .client_pfx_password
                .as_ref()
                .map(|p| p.expose_secret().to_owned()),
            ca_cert: c.ca_cert.clone(),
            tls_server_name: c.tls_server_name.clone(),
            verify_tls: !c.accept_invalid_certs,
            ccache: c.kerberos_ccache.clone(),
            keytab: c.kerberos_keytab.clone(),
            realm: c.kerberos_realm.clone(),
            configuration_name: Some(self.configuration.clone()),
            max_output: Some(c.max_output_bytes.unwrap_or(0)),
            hash: self.credentials.nt_hash.as_ref().map(|h| hex::encode(**h)),
            directory: self.directory.clone(),
            environment: self.environment.clone(),
            connect_timeout: Some(c.connect_timeout_secs),
            operation_timeout: Some(c.operation_timeout_secs),
            idle_timeout: c.idle_timeout_secs,
            retries: Some(c.max_retries),
            max_envelope: Some(c.max_envelope_size),
        }
    }
    pub fn username(&self) -> String {
        if self.credentials.domain.is_empty() {
            self.credentials.username.clone()
        } else {
            format!("{}\\{}", self.credentials.domain, self.credentials.username)
        }
    }
    pub async fn connect(&self) -> Result<Session> {
        let first = Session::connect(
            self.host.clone(),
            self.config.clone(),
            self.credentials.clone(),
            self.configuration.clone(),
        )
        .await;
        let session = match first {
            Err(_) if self.negotiate && matches!(self.config.auth_method, AuthMethod::Kerberos) => {
                let mut config = self.config.clone();
                config.auth_method = AuthMethod::Ntlm;
                Session::connect(
                    self.host.clone(),
                    config,
                    self.credentials.clone(),
                    self.configuration.clone(),
                )
                .await?
            }
            other => other?,
        };
        if let Err(error) =
            crate::cli::initialize(&session, self.directory.as_deref(), &self.environment).await
        {
            let _ = session.close().await;
            return Err(error);
        }
        Ok(session)
    }
}
