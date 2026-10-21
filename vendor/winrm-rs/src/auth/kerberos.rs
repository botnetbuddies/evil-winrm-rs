//! Stateful Kerberos authentication and WSMan message sealing.
use crate::{auth::AuthTransport, config::WinrmCredentials, error::WinrmError};
use tokio::sync::Mutex;

pub(crate) struct KerberosSession {
    #[cfg(feature = "kerberos")]
    context: KerberosContext,
    #[cfg(feature = "kerberos")]
    principal: String,
}

#[cfg(feature = "kerberos")]
enum KerberosContext {
    Native(cross_krb5::ClientCtx),
    #[cfg(windows)]
    FileCache(kerberos_cache::Context),
}

#[cfg(feature = "kerberos")]
struct SealedMessage {
    header_length: usize,
    padding_length: usize,
    data: Vec<u8>,
}

#[cfg(all(feature = "kerberos", unix))]
fn gssapi_winrm_message(
    header: &[u8],
    data: &[u8],
    padding: &[u8],
    trailer: &[u8],
) -> Result<SealedMessage, WinrmError> {
    let mut message = Vec::with_capacity(header.len() + data.len() + padding.len() + trailer.len());
    message.extend_from_slice(header);
    message.extend_from_slice(data);
    message.extend_from_slice(padding);
    message.extend_from_slice(trailer);
    if !trailer.is_empty() {
        if header.len() < 16 || header[..2] != [5, 4] {
            return Err(auth_error("unexpected GSSAPI trailer layout"));
        }
        let rotation = u16::from_be_bytes([header[6], header[7]])
            .checked_add(u16::try_from(trailer.len()).map_err(auth_error)?)
            .ok_or_else(|| auth_error("GSSAPI rotation overflow"))?;
        // Four-buffer GSSAPI places the encrypted trailer last. WinRM uses
        // the SSPI TOKEN + DATA layout: rotate that trailer into the header
        // and record the rotation in the RFC 4121 token header.
        message[16..].rotate_right(trailer.len());
        message[6..8].copy_from_slice(&rotation.to_be_bytes());
    }
    Ok(SealedMessage {
        header_length: header.len() + trailer.len(),
        padding_length: padding.len(),
        data: message,
    })
}

#[cfg(feature = "kerberos")]
impl KerberosContext {
    fn seal(&mut self, body: &[u8]) -> Result<SealedMessage, WinrmError> {
        #[cfg(windows)]
        use bytes::Buf;
        use bytes::BytesMut;
        use cross_krb5::K5Ctx;
        match self {
            Self::Native(context) => {
                let wrapped = context
                    .wrap_iov(true, BytesMut::from(body))
                    .map_err(auth_error)?;
                #[cfg(unix)]
                {
                    let (header, rest) = wrapped.into_inner();
                    let (data, rest) = rest.into_inner();
                    let (padding, trailer) = rest.into_inner();
                    gssapi_winrm_message(&header, &data, &padding, &trailer)
                }
                #[cfg(windows)]
                {
                    let mut wrapped = wrapped;
                    let header_length = wrapped.chunk().len();
                    let length = wrapped.remaining();
                    let padding_length = length
                        .checked_sub(header_length + body.len())
                        .ok_or_else(|| auth_error("unexpected SSPI padding length"))?;
                    Ok(SealedMessage {
                        header_length,
                        padding_length,
                        data: wrapped.copy_to_bytes(length).to_vec(),
                    })
                }
            }
            #[cfg(windows)]
            Self::FileCache(context) => context
                .seal(body)
                .map(|message| SealedMessage {
                    header_length: message.header_length,
                    padding_length: message.padding_length,
                    data: message.data,
                })
                .map_err(auth_error),
        }
    }
    fn unseal(&mut self, body: &[u8]) -> Result<Vec<u8>, WinrmError> {
        use cross_krb5::K5Ctx;
        match self {
            Self::Native(context) => context
                .unwrap(body)
                .map(|plain| plain.to_vec())
                .map_err(auth_error),
            #[cfg(windows)]
            Self::FileCache(context) => context.unseal_winrm(body).map_err(auth_error),
        }
    }
}
#[cfg_attr(not(feature = "kerberos"), allow(dead_code))]
pub(crate) struct KerberosAuth<'a> {
    pub(crate) service_principal: String,
    pub(crate) credentials: &'a WinrmCredentials,
    pub(crate) ccache: Option<&'a str>,
    pub(crate) encrypt: bool,
    pub(crate) cache: &'a Mutex<Option<KerberosSession>>,
    pub(crate) cert_handle: Option<&'a crate::tls::CertHandle>,
}
#[cfg(feature = "kerberos")]
fn auth_error(e: impl std::fmt::Display) -> WinrmError {
    WinrmError::AuthFailed(format!("Kerberos: {e:#}"))
}

/// Acquire from a named cache without changing process-wide Kerberos state.
#[cfg(all(feature = "kerberos", unix))]
fn cache_credential(path: &str) -> Result<cross_krb5::Cred, WinrmError> {
    gssapi_cache::acquire(path)
        .map(Into::into)
        .map_err(auth_error)
}

#[cfg(feature = "kerberos")]
impl KerberosAuth<'_> {
    async fn establish(
        &self,
        http: &reqwest::Client,
        url: &str,
    ) -> Result<KerberosContext, WinrmError> {
        // Populate TLS certificate capture before calculating channel bindings.
        let initial = http
            .post(url)
            .header(reqwest::header::CONTENT_LENGTH, "0")
            .body("")
            .send()
            .await
            .map_err(WinrmError::Http)?;
        let _ = initial.bytes().await.map_err(WinrmError::Http)?;
        let binding = self.cert_handle.and_then(|h| h.get()).map(|cert| {
            use sha2::{Digest, Sha256};
            let mut b = b"tls-server-end-point:".to_vec();
            b.extend_from_slice(&Sha256::digest(&cert));
            b
        });
        #[cfg(windows)]
        if let Some(path) = self.ccache {
            let pending = kerberos_cache::PendingContext::from_cache(
                std::path::Path::new(path),
                &self.service_principal,
                binding.as_deref(),
            )
            .await
            .map_err(auth_error)?;
            let response = http
                .post(url)
                .header("Authorization", pending.authorization_header())
                .header(reqwest::header::CONTENT_LENGTH, "0")
                .body("")
                .send()
                .await
                .map_err(WinrmError::Http)?;
            let status = response.status();
            let header = response
                .headers()
                .get_all("WWW-Authenticate")
                .iter()
                .filter_map(|h| h.to_str().ok())
                .find(|h| {
                    h.split_once(' ')
                        .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("Negotiate"))
                })
                .map(str::to_owned);
            let _ = response.bytes().await.map_err(WinrmError::Http)?;
            if !status.is_success() {
                return Err(auth_error(format!(
                    "cache authentication rejected (HTTP {status})"
                )));
            }
            let context = pending
                .complete(
                    header
                        .as_deref()
                        .ok_or_else(|| auth_error("missing mutual authentication token"))?,
                )
                .map_err(auth_error)?;
            return Ok(KerberosContext::FileCache(context));
        }
        self.establish_native(http, url, binding.as_deref())
            .await
            .map(KerberosContext::Native)
    }

    async fn establish_native(
        &self,
        http: &reqwest::Client,
        url: &str,
        binding: Option<&[u8]>,
    ) -> Result<cross_krb5::ClientCtx, WinrmError> {
        use base64::{Engine, engine::general_purpose::STANDARD as B64};
        use cross_krb5::{ClientCtx, InitiateFlags, Step};
        use secrecy::ExposeSecret;
        let password = self.credentials.password.expose_secret();
        let (mut pending, mut token) = {
            #[cfg(unix)]
            {
                let credential = if let Some(path) = self.ccache {
                    Some(cache_credential(path)?)
                } else if !password.is_empty() {
                    use libgssapi::{
                        credential::{Cred, CredUsage},
                        name::Name,
                        oid::{GSS_MECH_KRB5, GSS_NT_KRB5_PRINCIPAL, OidSet},
                    };
                    let realm = self
                        .service_principal
                        .rsplit_once('@')
                        .map(|(_, r)| r)
                        .or_else(|| {
                            (!self.credentials.domain.is_empty())
                                .then_some(self.credentials.domain.as_str())
                        });
                    let username = match realm {
                        Some(realm) if !self.credentials.username.contains('@') => {
                            format!("{}@{}", self.credentials.username, realm)
                        }
                        _ => self.credentials.username.clone(),
                    };
                    let name = Name::new(username.as_bytes(), Some(GSS_NT_KRB5_PRINCIPAL))
                        .map_err(auth_error)?;
                    let mechanisms = OidSet::singleton(GSS_MECH_KRB5).map_err(auth_error)?;
                    Some(
                        Cred::acquire_with_password(
                            Some(&name),
                            password,
                            None,
                            CredUsage::Initiate,
                            Some(&mechanisms),
                        )
                        .map_err(auth_error)?
                        .into(),
                    )
                } else {
                    None
                };
                if let Some(credential) = credential {
                    let (p, t) = ClientCtx::new_with_cred(
                        InitiateFlags::empty(),
                        credential,
                        &self.service_principal,
                        binding,
                    )
                    .map_err(auth_error)?;
                    (p, t.to_vec())
                } else {
                    let (p, t) = ClientCtx::new(
                        InitiateFlags::empty(),
                        None,
                        &self.service_principal,
                        binding,
                    )
                    .map_err(auth_error)?;
                    (p, t.to_vec())
                }
            }
            #[cfg(windows)]
            {
                if !password.is_empty() {
                    let realm = self
                        .service_principal
                        .rsplit_once('@')
                        .map_or(self.credentials.domain.as_str(), |(_, r)| r);
                    let credential = sspi_credentials::acquire_password(
                        &self.credentials.username,
                        realm,
                        password,
                    )
                    .map_err(auth_error)?;
                    let (p, t) = ClientCtx::new_with_cred(
                        InitiateFlags::NEGOTIATE_TOKEN,
                        credential,
                        &self.service_principal,
                        binding,
                    )
                    .map_err(auth_error)?;
                    (p, t.to_vec())
                } else {
                    let (p, t) = ClientCtx::new(
                        InitiateFlags::NEGOTIATE_TOKEN,
                        None,
                        &self.service_principal,
                        binding,
                    )
                    .map_err(auth_error)?;
                    (p, t.to_vec())
                }
            }
        };
        for _ in 0..8 {
            let response = http
                .post(url)
                .header("Authorization", format!("Negotiate {}", B64.encode(&token)))
                .header(reqwest::header::CONTENT_LENGTH, "0")
                .body("")
                .send()
                .await
                .map_err(WinrmError::Http)?;
            let header = response
                .headers()
                .get_all("WWW-Authenticate")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .find_map(|s| s.strip_prefix("Negotiate "))
                .map(str::to_owned);
            let status = response.status();
            let _ = response.bytes().await.map_err(WinrmError::Http)?;
            let incoming = B64
                .decode(header.ok_or_else(|| {
                    auth_error(format!(
                        "missing mutual authentication token (HTTP {status})"
                    ))
                })?)
                .map_err(auth_error)?;
            match pending.step(&incoming).map_err(auth_error)? {
                Step::Finished((context, final_token)) => {
                    if let Some(token) = final_token {
                        let r = http
                            .post(url)
                            .header(
                                "Authorization",
                                format!("Negotiate {}", B64.encode(&*token)),
                            )
                            .header(reqwest::header::CONTENT_LENGTH, "0")
                            .body("")
                            .send()
                            .await
                            .map_err(WinrmError::Http)?;
                        if !r.status().is_success() {
                            return Err(auth_error("final token rejected"));
                        }
                        let _ = r.bytes().await;
                    }
                    if !status.is_success() {
                        return Err(auth_error(format!(
                            "authentication rejected (HTTP {status})"
                        )));
                    }
                    return Ok(context);
                }
                Step::Continue((next, t)) => {
                    pending = next;
                    token = t.to_vec();
                }
            }
        }
        Err(auth_error("too many authentication round trips"))
    }
}

#[cfg(feature = "kerberos")]
impl AuthTransport for KerberosAuth<'_> {
    async fn send_authenticated(
        &self,
        http: &reqwest::Client,
        url: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        let mut cache = self.cache.lock().await;
        if cache
            .as_ref()
            .is_none_or(|c| c.principal != self.service_principal)
        {
            *cache = Some(KerberosSession {
                context: self.establish(http, url).await?,
                principal: self.service_principal.clone(),
            });
        }
        let context = &mut cache.as_mut().unwrap().context;
        let request = if self.encrypt {
            let sealed = context.seal(body.as_bytes())?;
            let mut mime = format!("--Encrypted Boundary\r\n\tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length={}\r\n--Encrypted Boundary\r\n\tContent-Type: application/octet-stream\r\n",body.len() + sealed.padding_length).into_bytes();
            mime.extend_from_slice(&(sealed.header_length as u32).to_le_bytes());
            mime.extend_from_slice(&sealed.data);
            mime.extend_from_slice(b"--Encrypted Boundary--\r\n");
            http.post(url).header("Content-Type","multipart/encrypted;protocol=\"application/HTTP-SPNEGO-session-encrypted\";boundary=\"Encrypted Boundary\"").body(mime)
        } else {
            http.post(url)
                .header("Content-Type", "application/soap+xml;charset=UTF-8")
                .body(body)
        };
        let response = request.send().await.map_err(WinrmError::Http)?;
        let status = response.status();
        let encrypted = response
            .headers()
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|s| s.contains("multipart/encrypted"));
        let data = response.bytes().await.map_err(WinrmError::Http)?;
        if status.as_u16() == 401 {
            *cache = None;
            return Err(auth_error("authenticated connection expired"));
        }
        let text = if encrypted {
            let marker = b"application/octet-stream\r\n";
            let start = data
                .windows(marker.len())
                .position(|w| w == marker)
                .ok_or_else(|| auth_error("missing encrypted MIME data"))?
                + marker.len();
            let end_marker = b"--Encrypted Boundary--";
            let end = data
                .windows(end_marker.len())
                .rposition(|w| w == end_marker)
                .ok_or_else(|| auth_error("missing encrypted MIME boundary"))?;
            if start + 4 > end {
                return Err(auth_error("truncated encrypted MIME data"));
            }
            let plain = context.unseal(&data[start + 4..end])?;
            String::from_utf8(plain).map_err(auth_error)?
        } else {
            String::from_utf8(data.to_vec()).map_err(auth_error)?
        };
        if !status.is_success() {
            crate::soap::check_soap_fault(&text).map_err(WinrmError::Soap)?;
            return Err(auth_error(format!("HTTP {status}: {text}")));
        }
        Ok(text)
    }
}
#[cfg(not(feature = "kerberos"))]
impl AuthTransport for KerberosAuth<'_> {
    async fn send_authenticated(
        &self,
        _: &reqwest::Client,
        _: &str,
        _: String,
    ) -> Result<String, WinrmError> {
        Err(WinrmError::AuthFailed(
            "Kerberos requires the kerberos cargo feature".into(),
        ))
    }
}
