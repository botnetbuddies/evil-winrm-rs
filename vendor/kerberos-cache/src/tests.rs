use super::*;
use rskrb5::ccache::{CCache, Principal as CachePrincipal};
use std::time::Duration;

#[test]
fn winrm_rc4_accepts_sspi_without_gss_padding_and_checks_integrity() -> Result<()> {
    // Independent Python HMAC/MD5 + cryptography ARC4 fixture. This invented
    // key and fixed confounder contain no Windows lab credentials or traffic.
    let decode = |value: &str| -> Vec<u8> {
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    };
    let unpadded = decode(
        "604706092a864886f712010202020111001000ffff2f1a4b8758f6188ce2c6eafbe21bb524e3dd7b8b4d51a65c9016dcb5fb29376d1ac826358ba7ea275d918577e1f822fef5e0d150",
    );
    let padded = decode(
        "604806092a864886f712010202020111001000ffffc194a900ba530502ab5693e42bb0c561e3dd7b8b4d51a65c9016dcb5fb29376d1ac826358ba7ea275d918577e1f822fef5e0d150f5",
    );
    let context = || Context {
        initiator_key: EncryptionKey {
            etype: 23,
            value: vec![0x42; 16],
        },
        acceptor_key: None,
        send_sequence: 0,
        receive_sequence: 0x10203,
    };
    assert!(context().unseal(&unpadded).is_err());
    assert_eq!(context().unseal(&padded)?, b"<Envelope>fixture</Envelope>");
    for token in [unpadded, padded] {
        let mut client = context();
        let mut corrupt = token.clone();
        *corrupt.last_mut().unwrap() ^= 0x80;
        assert!(client.unseal_winrm(&corrupt).is_err());
        assert_eq!(
            client.unseal_winrm(&token)?,
            b"<Envelope>fixture</Envelope>"
        );
        assert!(client.unseal_winrm(&token).is_err(), "replay accepted");
    }
    Ok(())
}

/// Synthetic credentials for a local, invented realm. No domain credentials or
/// external KDC are used by these tests.
fn credentials(etype: i32) -> Result<(TgsRepSession, rskrb5::keytab::Keytab)> {
    let realm = "EXAMPLE.TEST";
    let host = "server.example.test";
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let now = UNIX_EPOCH + Duration::from_secs(now.as_secs());
    let start = now - Duration::from_secs(60);
    let end = now + Duration::from_secs(3600);
    let time = |value: SystemTime| {
        rasn_kerberos::KerberosTime(chrono::DateTime::<chrono::Utc>::from(value).fixed_offset())
    };
    let client_name = rasn_kerberos::PrincipalName {
        r#type: 1,
        string: vec!["fixture".try_into()?],
    };
    let service_name = rasn_kerberos::PrincipalName {
        r#type: 2,
        string: vec!["HTTP".try_into()?, host.try_into()?],
    };
    let session_key = EncryptionKey {
        etype,
        value: vec![
            0x42;
            if matches!(etype, 17 | 19 | 23) {
                16
            } else {
                32
            }
        ],
    };
    let service_key = EncryptionKey {
        etype: 18,
        value: vec![0x24; 32],
    };
    let part = rasn_kerberos::EncTicketPart {
        flags: rasn_kerberos::TicketFlags(rasn_kerberos::KerberosFlags::from_slice(&[0; 4])),
        key: rasn_kerberos::EncryptionKey {
            r#type: etype,
            value: session_key.value.clone().into(),
        },
        crealm: realm.try_into()?,
        cname: client_name,
        transited: rasn_kerberos::TransitedEncoding {
            r#type: 0,
            contents: Vec::new().into(),
        },
        auth_time: time(start),
        start_time: Some(time(start)),
        end_time: time(end),
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let ticket = rskrb5::ticket::build_ticket(
        realm.try_into()?,
        service_name,
        &part,
        &service_key,
        Some(1),
    )?;
    let mut keytab = rskrb5::keytab::Keytab::new();
    keytab.entries_mut().push(rskrb5::keytab::Entry {
        principal: rskrb5::keytab::Principal::new(realm, 2, ["HTTP", host]),
        timestamp: start.duration_since(UNIX_EPOCH)?.as_secs().try_into()?,
        kvno8: 1,
        key: service_key,
        kvno: 1,
    });
    Ok((
        TgsRepSession {
            client: Principal::user(realm, "fixture"),
            service: Principal::host_based_service_in_realm("HTTP", host, realm)?,
            session_key,
            ticket: rskrb5::ticket::encode_ticket(&ticket)?,
            ticket_flags: [0; 4],
            auth_time: start,
            start_time: start,
            end_time: end,
            renew_till: None,
            key_expiration: None,
        },
        keytab,
    ))
}

fn write_cache(ticket: &TgsRepSession, path: &Path) -> Result<()> {
    let mut cache = CCache::new(CachePrincipal::new(
        "EXAMPLE.TEST",
        1,
        vec!["fixture".into()],
    ));
    cache.credentials_mut().push(ticket.to_ccache_credential()?);
    cache.save(path)?;
    Ok(())
}

#[tokio::test]
async fn cached_service_ticket_needs_no_kdc_and_bad_cache_returns_error() -> Result<()> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("ticket.ccache");
    let (ticket, _) = credentials(18)?;
    write_cache(&ticket, &path)?;
    let pending =
        PendingContext::from_cache(&path, "HTTP/server.example.test@EXAMPLE.TEST", None).await?;
    assert!(pending.authorization_header().starts_with("Negotiate "));
    assert!(pending.complete("Negotiate invalid-base64").is_err());
    std::fs::write(&path, b"not a cache")?;
    assert!(
        PendingContext::from_cache(&path, "HTTP/server.example.test", None)
            .await
            .is_err()
    );
    Ok(())
}

#[test]
fn mit_fallback_canonicalization_config_keeps_the_explicit_spn() -> Result<()> {
    let config = config_from_text(
        "[libdefaults]\ndns_canonicalize_hostname = fallback\ndefault_realm = EXAMPLE.TEST\n",
    )?;
    assert!(!config.libdefaults.dns_canonicalize_hostname);
    assert_eq!(config.libdefaults.default_realm, "EXAMPLE.TEST");
    Ok(())
}

#[test]
fn cannot_complete_without_a_mutual_authentication_reply() -> Result<()> {
    let (ticket, _) = credentials(18)?;
    let pending = PendingContext::from_ticket(&ticket, None)?;
    assert!(
        pending
            .complete(&spnego::accept_completed_header()?)
            .is_err()
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn interoperates_with_native_gssapi_and_rejects_replays_and_tampering() -> Result<()> {
    native_round_trips(&[17, 18, 19, 20]).await
}

#[cfg(unix)]
async fn native_round_trips(enctypes: &[i32]) -> Result<()> {
    use base64::{Engine, engine::general_purpose::STANDARD as B64};
    use bytes::{Buf, BytesMut};
    use cross_krb5::{AcceptFlags, K5Ctx, ServerCtx, Step};
    for &etype in enctypes {
        for binding in [None, Some(&b"tls-server-end-point:fixture"[..])] {
            let root = tempfile::tempdir()?;
            let (ticket, keytab) = credentials(etype)?;
            let path = root.path().join("ticket.ccache");
            write_cache(&ticket, &path)?;
            let keytab_path = root.path().join("server.keytab");
            keytab.save(&keytab_path)?;
            let credential = gssapi_cache::acquire_acceptor(keytab_path.to_str().unwrap())
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            let server =
                ServerCtx::new_with_cred(AcceptFlags::empty(), credential.into(), binding)?;
            let pending =
                PendingContext::from_cache(&path, "HTTP/server.example.test", binding).await?;
            let request = B64.decode(
                pending
                    .authorization_header()
                    .strip_prefix("Negotiate ")
                    .unwrap(),
            )?;
            let (mut server, reply) =
                match server.step(&request).context("native AP-REQ acceptance")? {
                    Step::Finished(result) => result,
                    Step::Continue(_) => bail!("native acceptor needs an unexpected extra step"),
                };
            let reply = reply.context("native acceptor omitted mutual authentication")?;
            let mut client = pending
                .complete(&format!("Negotiate {}", B64.encode(&*reply)))
                .context("AP-REP verification")?;
            for payload in [b"".as_slice(), b"short", &vec![0x5a; 49_153]] {
                let sealed = client.seal(payload)?;
                let encoded = sealed.data;
                assert_eq!(sealed.padding_length, usize::from(etype == 23));
                assert_eq!(
                    encoded.len() - sealed.header_length,
                    payload.len() + sealed.padding_length
                );
                assert_eq!(&*server.unwrap(&encoded).context("native unwrap")?, payload);
                let mut wrapped = server.wrap_iov(true, BytesMut::from(payload))?;
                let length = wrapped.remaining();
                let encoded = wrapped.copy_to_bytes(length);
                let mut corrupt = encoded.to_vec();
                *corrupt.last_mut().unwrap() ^= 1;
                assert!(client.unseal(&corrupt).is_err());
                assert_eq!(client.unseal(&encoded)?, payload);
                assert!(client.unseal(&encoded).is_err());
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn legacy_rc4_interoperates_in_an_isolated_test_process() -> Result<()> {
    if std::env::var_os("EWR_KERBEROS_RC4_TEST_CHILD").is_some() {
        return native_round_trips(&[23]).await;
    }
    let root = tempfile::tempdir()?;
    let config = root.path().join("krb5.conf");
    std::fs::write(
        &config,
        "[libdefaults]\n default_realm = EXAMPLE.TEST\n allow_weak_crypto = true\n allow_rc4 = true\n permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 arcfour-hmac\n",
    )?;
    let output = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "tests::legacy_rc4_interoperates_in_an_isolated_test_process",
            "--nocapture",
        ])
        .env("EWR_KERBEROS_RC4_TEST_CHILD", "1")
        .env("KRB5_CONFIG", config)
        .output()?;
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn native_acceptor_rejects_a_different_channel_binding() -> Result<()> {
    use base64::{Engine, engine::general_purpose::STANDARD as B64};
    use cross_krb5::{AcceptFlags, ServerCtx};
    let root = tempfile::tempdir()?;
    let (ticket, keytab) = credentials(18)?;
    let path = root.path().join("server.keytab");
    keytab.save(&path)?;
    let credential = gssapi_cache::acquire_acceptor(path.to_str().unwrap())
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let server =
        ServerCtx::new_with_cred(AcceptFlags::empty(), credential.into(), Some(b"expected"))?;
    let pending = PendingContext::from_ticket(&ticket, Some(b"different"))?;
    let request = B64.decode(
        pending
            .authorization_header()
            .strip_prefix("Negotiate ")
            .unwrap(),
    )?;
    assert!(server.step(&request).is_err());
    Ok(())
}
