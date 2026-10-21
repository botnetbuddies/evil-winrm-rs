//! Per-session file credentials, mutual authentication, and WinRM message sealing.
//! No changes to the process environment or Windows logon session are needed.

use anyhow::{Context as _, Result, bail, ensure};
use md5::{Digest, Md5};
use rskrb5::{
    Config, Principal,
    client::{ApReqOptions, KdcProtocol, TgsRepSession, TokioClient, build_ap_req_with_confounder},
    crypto::KerberosEtype,
    keytab::EncryptionKey,
    spnego::{self, InitiatorContext, Krb5MechToken, NegTokenInit, SpnegoToken, WrapToken},
};
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

fn config_from_text(text: &str) -> Result<Config> {
    // The application supplies the resolved/overridden SPN. rskrb5 models
    // canonicalization as a bool, whereas MIT also accepts `fallback`.
    let text = text
        .lines()
        .map(|line| {
            if let Some((key, value)) = line.split_once('=')
                && key.trim().eq_ignore_ascii_case("dns_canonicalize_hostname")
                && value
                    .split(['#', ';'])
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case("fallback")
            {
                "dns_canonicalize_hostname = false"
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    Ok(Config::parse(&text)?)
}

fn load_config() -> Result<Config> {
    let configured = std::env::var_os("KRB5_CONFIG");
    let paths: Vec<std::path::PathBuf> = if let Some(value) = &configured {
        std::env::split_paths(value).collect()
    } else {
        #[cfg(windows)]
        {
            let data = std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into());
            let windows = std::env::var_os("WINDIR").unwrap_or_else(|| r"C:\Windows".into());
            vec![
                std::path::PathBuf::from(data).join(r"MIT\Kerberos5\krb5.ini"),
                std::path::PathBuf::from(windows).join("krb5.ini"),
            ]
        }
        #[cfg(not(windows))]
        {
            vec!["/etc/krb5.conf".into()]
        }
    };
    let mut text = String::new();
    for path in paths {
        match std::fs::read_to_string(&path) {
            Ok(file) => {
                text.push_str(&file);
                text.push('\n');
            }
            Err(error) if configured.is_none() && error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
        }
    }
    config_from_text(&text)
}

/// Acquire a TGT into an application-owned cache without changing process defaults.
pub async fn login_keytab(path: &Path, principal: &str) -> Result<Vec<u8>> {
    let config = load_config().context("loading Kerberos configuration")?;
    let principal =
        Principal::parse_user(principal).context("parsing keytab principal (use user@REALM)")?;
    let keys = rskrb5::keytab::Keytab::load(path).context("reading keytab")?;
    // Windows KDCs do not supply the FAST-negotiation response expected by
    // rskrb5's optional extension. Use standard Kerberos preauthentication,
    // matching the existing MIT/SSPI authentication paths.
    let mut client = TokioClient::with_keytab(config, KdcProtocol::Auto, principal, keys)
        .with_fast_negotiation(false);
    client.login().await.context("keytab Kerberos login")?;
    Ok(client.to_ccache()?.to_bytes()?)
}

mod rc4_wrap;

pub struct PendingContext {
    initiator: InitiatorContext,
    initiator_key: EncryptionKey,
}

impl PendingContext {
    /// Read a named ccache and obtain the requested service ticket. A cached
    /// service ticket needs no KDC; a TGT uses krb5.conf or DNS KDC discovery.
    pub async fn from_cache(
        path: &Path,
        spn: &str,
        channel_binding: Option<&[u8]>,
    ) -> Result<Self> {
        let cache = rskrb5::ccache::CCache::load(path).context("reading Kerberos cache")?;
        let config = load_config().context("loading Kerberos configuration")?;
        let service = match spn.rsplit_once('@') {
            Some(_) => Principal::parse_service(spn)?,
            None => {
                let (service, host) = spn.split_once('/').context("invalid service principal")?;
                Principal::host_based_service(service, host)?
            }
        };
        let mut client = TokioClient::from_ccache(config, KdcProtocol::Auto, &cache);
        let ticket = client
            .get_service_ticket(service)
            .await
            .context("obtaining cached Kerberos service ticket")?;
        Self::from_ticket(&ticket, channel_binding)
    }

    fn from_ticket(ticket: &TgsRepSession, binding: Option<&[u8]>) -> Result<Self> {
        let etype = KerberosEtype::from_etype_id(ticket.session_key.etype)
            .context("unsupported Kerberos ticket encryption type")?;
        let mut confounder = vec![0; etype.confounder_len()];
        getrandom::fill(&mut confounder)?;
        let mut key = vec![0; ticket.session_key.value.len()];
        getrandom::fill(&mut key)?;
        let initiator_key = EncryptionKey {
            etype: ticket.session_key.etype,
            value: key,
        };
        let mut sequence = [0; 4];
        getrandom::fill(&mut sequence)?;
        let sequence = u32::from_le_bytes(sequence) & 0x3fff_ffff;
        let mut checksum = spnego::authenticator_checksum(&[
            spnego::CONTEXT_FLAG_MUTUAL,
            spnego::CONTEXT_FLAG_REPLAY,
            spnego::CONTEXT_FLAG_SEQUENCE,
            spnego::CONTEXT_FLAG_CONF,
            spnego::CONTEXT_FLAG_INTEG,
        ]);
        if let Some(binding) = binding {
            // RFC 4121: MD5 over the GSS channel-binding structure, with empty
            // initiator/acceptor addresses and the TLS application binding.
            let mut hash = Md5::new();
            hash.update([0; 16]);
            hash.update(u32::try_from(binding.len())?.to_le_bytes());
            hash.update(binding);
            checksum[4..20].copy_from_slice(&hash.finalize());
        }
        let options = ApReqOptions::new()
            .with_ap_option_bits(0x2000_0000)
            .with_checksum(Some(rasn_kerberos::Checksum {
                r#type: 0x8003,
                checksum: checksum.into(),
            }))
            .with_subkey(Some(initiator_key.clone()))
            .with_sequence_number(Some(sequence));
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let built = build_ap_req_with_confounder(
            ticket,
            options,
            UNIX_EPOCH + std::time::Duration::from_secs(now.as_secs()),
            now.subsec_micros(),
            &confounder,
        )?;
        let krb5_token = Krb5MechToken::ap_req(built.der.clone());
        let spnego_token = SpnegoToken::Init(NegTokenInit::krb5(krb5_token.encode()?));
        let header = spnego::negotiate_header(&spnego_token)?;
        Ok(Self {
            initiator: InitiatorContext {
                ap_req: built.message,
                ap_req_der: built.der,
                krb5_token,
                spnego_token,
                header,
                client: built.client,
                service: built.service,
                session_key: built.session_key,
                authenticator_ctime: built.authenticator_ctime,
                authenticator_cusec: built.authenticator_cusec,
                authenticator_time: built.authenticator_time,
                sequence_number: built.sequence_number,
            },
            initiator_key,
        })
    }

    pub fn authorization_header(&self) -> &str {
        &self.initiator.header
    }

    /// Require a valid AP-REP before allowing message encryption or accepting
    /// authenticated output. Rejecting the reply never falls back to SSPI.
    pub fn complete(self, response_header: &str) -> Result<Context> {
        if let SpnegoToken::Resp(response) = spnego::parse_negotiate_header(response_header)? {
            ensure!(
                response.neg_state != Some(spnego::NegState::Reject),
                "server rejected SPNEGO authentication"
            );
            ensure!(
                response
                    .supported_mech
                    .as_ref()
                    .is_none_or(|mech| mech.is_kerberos_mechanism()),
                "server selected a non-Kerberos mechanism"
            );
        }
        let reply = self
            .initiator
            .verify_ap_rep_response_header(response_header)
            .context("verifying Kerberos mutual authentication")?;
        let send_sequence = u64::from(
            self.initiator
                .sequence_number
                .context("missing client sequence")?,
        );
        Ok(Context {
            initiator_key: self.initiator_key,
            acceptor_key: reply.subkey,
            send_sequence,
            receive_sequence: u64::from(reply.sequence_number.unwrap_or(send_sequence as u32)),
        })
    }
}

pub struct Context {
    initiator_key: EncryptionKey,
    acceptor_key: Option<EncryptionKey>,
    send_sequence: u64,
    receive_sequence: u64,
}

pub struct SealedMessage {
    pub header_length: usize,
    pub padding_length: usize,
    pub data: Vec<u8>,
}

impl Context {
    /// Return the WinRM token-header length and contiguous GSS encrypted bytes.
    pub fn seal(&mut self, data: &[u8]) -> Result<SealedMessage> {
        let key = self.acceptor_key.as_ref().unwrap_or(&self.initiator_key);
        if key.etype == 23 {
            let (header_length, data) = rc4_wrap::seal(&key.value, self.send_sequence, data)?;
            self.send_sequence = self
                .send_sequence
                .checked_add(1)
                .context("Kerberos sequence exhausted")?;
            return Ok(SealedMessage {
                header_length,
                padding_length: 1,
                data,
            });
        }
        ensure!(
            matches!(key.etype, 17..=20),
            "WinRM cache sealing requires an AES session key (received {})",
            key.etype
        );
        let etype = KerberosEtype::from_etype_id(key.etype).context("unsupported sealing key")?;
        let trailer_length = 16 + etype.hmac_len();
        let mut token = WrapToken::new(
            if self.acceptor_key.is_some() {
                spnego::GSS_TOKEN_FLAG_ACCEPTOR_SUBKEY
            } else {
                0
            },
            self.send_sequence,
        )
        .with_payload(data.to_vec());
        // Put the encrypted trailer/checksum before the confounder and data,
        // matching the SSPI TOKEN + DATA layout used by WinRM.
        token.rrc = u16::try_from(trailer_length)?;
        let mut confounder = vec![0; etype.confounder_len()];
        getrandom::fill(&mut confounder)?;
        token.encrypt_payload_with_confounder(
            key,
            spnego::GSSAPI_INITIATOR_SEAL_USAGE,
            &confounder,
        )?;
        let encoded = token.encode()?;
        self.send_sequence = self
            .send_sequence
            .checked_add(1)
            .context("Kerberos sequence exhausted")?;
        Ok(SealedMessage {
            header_length: 16 + trailer_length + etype.confounder_len(),
            padding_length: 0,
            data: encoded,
        })
    }

    pub fn unseal(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.unseal_with_padding(data, true)
    }

    /// Decode a WinRM SOAP response, including SSPI RC4 tokens without a
    /// padding buffer. Integrity, sender direction and sequence remain checked.
    pub fn unseal_winrm(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.unseal_with_padding(data, false)
    }

    fn unseal_with_padding(&mut self, data: &[u8], require_gss_padding: bool) -> Result<Vec<u8>> {
        let key = self.acceptor_key.as_ref().unwrap_or(&self.initiator_key);
        if key.etype == 23 {
            let plain =
                rc4_wrap::unseal(&key.value, self.receive_sequence, data, require_gss_padding)?;
            self.receive_sequence = self
                .receive_sequence
                .checked_add(1)
                .context("Kerberos sequence exhausted")?;
            return Ok(plain);
        }
        let token = WrapToken::decode(data, true)?;
        ensure!(
            token.is_sealed(),
            "server returned an unencrypted Kerberos token"
        );
        ensure!(
            token.snd_seq_num == self.receive_sequence,
            "unexpected Kerberos message sequence"
        );
        let key = if token.flags & spnego::GSS_TOKEN_FLAG_ACCEPTOR_SUBKEY != 0 {
            self.acceptor_key
                .as_ref()
                .context("server selected an unnegotiated acceptor subkey")?
        } else {
            &self.initiator_key
        };
        if !matches!(key.etype, 17..=20) {
            bail!(
                "WinRM cache unsealing requires an AES session key (received {})",
                key.etype
            );
        }
        let plain = token.decrypt_payload(key, spnego::GSSAPI_ACCEPTOR_SEAL_USAGE)?;
        self.receive_sequence = self
            .receive_sequence
            .checked_add(1)
            .context("Kerberos sequence exhausted")?;
        Ok(plain)
    }
}

#[cfg(test)]
mod tests;
