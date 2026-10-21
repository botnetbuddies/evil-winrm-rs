use anyhow::{Context, Result, bail};
use evil_winrm_rs::{
    cli::{parse_hash, split_username},
    session::Session,
};
use winrm_rs::{AuthMethod, WinrmConfig, WinrmCredentials};

pub async fn connect() -> Result<Session> {
    connect_with_idle_timeout(None).await
}

pub async fn connect_with_idle_timeout(idle_timeout_secs: Option<u64>) -> Result<Session> {
    let get = |name: &str| std::env::var(name).ok();
    let host =
        get("WINRM_HOST").context("set WINRM_HOST before running the ignored Windows tests")?;
    let auth = match get("WINRM_AUTH").as_deref().unwrap_or("ntlm") {
        "ntlm" => AuthMethod::Ntlm,
        "kerberos" => AuthMethod::Kerberos,
        "certificate" => AuthMethod::Certificate,
        "basic" => AuthMethod::Basic,
        "credssp" => AuthMethod::CredSsp,
        _ => bail!("unrecognized WINRM_AUTH"),
    };
    let tls = get("WINRM_TLS").is_some_and(|s| s == "1")
        || matches!(auth, AuthMethod::Certificate | AuthMethod::CredSsp);
    let (domain, user) = split_username(&get("WINRM_USER").unwrap_or_default());
    let mut credentials =
        WinrmCredentials::new(user, get("WINRM_PASSWORD").unwrap_or_default(), domain);
    if let Some(hash) = get("WINRM_HASH") {
        credentials.nt_hash = Some(zeroize::Zeroizing::new(parse_hash(&hash)?));
    }
    let config = WinrmConfig {
        port: get("WINRM_PORT")
            .map(|p| p.parse())
            .transpose()?
            .unwrap_or(if tls { 5986 } else { 5985 }),
        use_tls: tls,
        auth_method: auth,
        accept_invalid_certs: get("WINRM_VERIFY_TLS").as_deref() != Some("1"),
        client_cert_pem: get("WINRM_CERT_PEM"),
        client_key_pem: get("WINRM_KEY_PEM"),
        endpoint_path: get("WINRM_URI").unwrap_or_else(|| "/wsman".into()),
        kerberos_service: get("WINRM_SPN_PREFIX").unwrap_or_else(|| "HTTP".into()),
        kerberos_hostname: get("WINRM_SPN_HOSTNAME"),
        kerberos_realm: get("WINRM_REALM"),
        kerberos_ccache: get("WINRM_CCACHE"),
        user_agent: Some("evil-winrm-rs interoperability test".into()),
        operation_timeout_secs: 10,
        idle_timeout_secs,
        ..Default::default()
    };
    Session::connect(
        host,
        config,
        credentials,
        get("WINRM_CONFIGURATION").unwrap_or_else(|| "Microsoft.PowerShell".into()),
    )
    .await
}
