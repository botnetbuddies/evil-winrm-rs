//! Adapt connector inputs to the CLI's shared authentication policy.
use super::models::Login;
use crate::{
    cli::{Authentication, Cli, Encryption},
    connection::ConnectionProfile,
};
use anyhow::Result;
use clap::{Parser, ValueEnum};
impl Login {
    pub(crate) fn profile(self) -> Result<ConnectionProfile> {
        let mut args = Cli::try_parse_from(["broker", "--mcp"])?;
        args.mcp = false;
        args.host = Some(self.ip);
        args.user = Some(self.username);
        args.password = Some(self.password);
        args.auth = Some(
            Authentication::from_str(self.auth.as_deref().unwrap_or("negotiate"), true)
                .map_err(anyhow::Error::msg)?,
        );
        args.encryption = Encryption::from_str(self.encryption.as_deref().unwrap_or("auto"), true)
            .map_err(anyhow::Error::msg)?;
        args.port = self.port;
        args.tls = self.ssl;
        if let Some(uri) = self.uri {
            args.uri = uri;
        }
        if let Some(agent) = self.ua {
            args.user_agent = agent;
        }
        if let Some(spn) = self.spn_prefix {
            args.spn_prefix = spn;
        }
        args.spn_hostname = self.spn_hostname;
        args.proxy = self.proxy;
        args.certificate = self.cert_pem.map(Into::into);
        args.private_key = self.priv_key_pem.map(Into::into);
        args.pfx = self.pfx.map(Into::into);
        args.pfx_password_file = self.pfx_password_file.map(Into::into);
        args.ca_cert = self.ca_cert.map(Into::into);
        args.tls_server_name = self.tls_server_name;
        args.verify_tls = self.verify_tls;
        args.ccache = self.ccache.map(Into::into);
        args.keytab = self.keytab.map(Into::into);
        args.realm = self.realm;
        if let Some(name) = self.configuration_name {
            args.configuration_name = name;
        }
        if let Some(limit) = self.max_output {
            args.max_output = limit;
        }
        args.hash = self.hash;
        args.directory = self.directory;
        args.environment = self.environment;
        if let Some(value) = self.connect_timeout {
            args.connect_timeout = value;
        }
        if let Some(value) = self.operation_timeout {
            args.operation_timeout = value;
        }
        args.idle_timeout = self.idle_timeout;
        if let Some(value) = self.retries {
            args.retries = value;
        }
        if let Some(value) = self.max_envelope {
            args.max_envelope = value;
        }
        let mut profile = ConnectionProfile::from_cli(&mut args)?;
        if let Some(password) = self.pfx_password {
            profile.config.client_pfx_password = Some(password.into());
        }
        Ok(profile)
    }
}
