// Custom TLS certificate verifier that captures the server certificate.
//
// Used for NTLM Channel Binding Tokens (CBT) — the server certificate
// hash is injected into the NTLM Type 3 message to bind authentication
// to the TLS channel, preventing relay attacks.

use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};

pub(crate) fn verifier(
    config: &crate::WinrmConfig,
) -> Result<Arc<dyn ServerCertVerifier>, crate::WinrmError> {
    if config.accept_invalid_certs {
        return Ok(Arc::new(NoVerifier));
    }
    use rustls::pki_types::pem::PemObject;
    let mut roots =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    if let Some(path) = &config.ca_cert {
        let pem = std::fs::read(path)
            .map_err(|e| crate::WinrmError::AuthFailed(format!("reading CA bundle: {e}")))?;
        let mut count = 0;
        for cert in CertificateDer::pem_slice_iter(&pem) {
            roots
                .add(cert.map_err(|e| {
                    crate::WinrmError::AuthFailed(format!("invalid CA bundle: {e}"))
                })?)
                .map_err(|e| {
                    crate::WinrmError::AuthFailed(format!("invalid CA certificate: {e}"))
                })?;
            count += 1;
        }
        if count == 0 {
            return Err(crate::WinrmError::AuthFailed(
                "CA bundle contains no certificates".into(),
            ));
        }
    }
    Ok(
        rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| crate::WinrmError::AuthFailed(format!("TLS verifier: {e}")))?,
    )
}

pub(crate) fn client_identity(
    config: &crate::WinrmConfig,
) -> Result<
    (
        Vec<CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ),
    crate::WinrmError,
> {
    use crate::WinrmError;
    use rustls::pki_types::{PrivateKeyDer, pem::PemObject};
    let failed = |message: String| WinrmError::AuthFailed(message);
    if let Some(path) = &config.client_pfx {
        #[cfg(feature = "pkcs12")]
        {
            use secrecy::ExposeSecret;
            let bytes = zeroize::Zeroizing::new(
                std::fs::read(path).map_err(|e| failed(format!("reading PFX: {e}")))?,
            );
            let pfx = openssl::pkcs12::Pkcs12::from_der(&bytes)
                .map_err(|_| failed("invalid PKCS#12 container".into()))?;
            let parsed = pfx
                .parse2(
                    config
                        .client_pfx_password
                        .as_ref()
                        .map_or("", |s| s.expose_secret()),
                )
                .map_err(|_| failed("cannot decrypt PFX; check --pfx-password-file".into()))?;
            let mut chain = vec![CertificateDer::from(
                parsed
                    .cert
                    .ok_or_else(|| failed("PFX contains no certificate".into()))?
                    .to_der()
                    .map_err(|e| failed(e.to_string()))?,
            )];
            if let Some(certs) = parsed.ca {
                for cert in certs {
                    chain.push(CertificateDer::from(
                        cert.to_der().map_err(|e| failed(e.to_string()))?,
                    ));
                }
            }
            let key = parsed
                .pkey
                .ok_or_else(|| failed("PFX contains no private key".into()))?
                .private_key_to_pkcs8()
                .map_err(|e| failed(e.to_string()))?;
            return Ok((
                chain,
                rustls::pki_types::PrivatePkcs8KeyDer::from(key).into(),
            ));
        }
        #[cfg(not(feature = "pkcs12"))]
        {
            let _ = path;
            return Err(failed("PFX requires the pkcs12 build feature".into()));
        }
    }
    let cert_path = config.client_cert_pem.as_deref().ok_or_else(|| {
        failed("certificate authentication requires client_cert_pem or client_pfx".into())
    })?;
    let key_path = config
        .client_key_pem
        .as_deref()
        .ok_or_else(|| failed("certificate authentication requires client_key_pem".into()))?;
    let cert =
        std::fs::read(cert_path).map_err(|e| failed(format!("reading client certificate: {e}")))?;
    let key = zeroize::Zeroizing::new(
        std::fs::read(key_path).map_err(|e| failed(format!("reading client key: {e}")))?,
    );
    let chain = CertificateDer::pem_slice_iter(&cert)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| failed(format!("invalid client certificate: {e}")))?;
    let key = PrivateKeyDer::from_pem_slice(&key)
        .map_err(|e| failed(format!("invalid client private key: {e}")))?;
    Ok((chain, key))
}

/// A [`ServerCertVerifier`] wrapper that captures the server's end-entity
/// certificate (DER bytes) during the TLS handshake, then delegates all
/// verification to an inner verifier.
///
/// The captured certificate is used to compute NTLM Channel Binding Tokens.
#[derive(Debug)]
pub(crate) struct CertCapturingVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    captured_cert: Arc<Mutex<Option<Vec<u8>>>>,
}

impl CertCapturingVerifier {
    /// Wrap an existing verifier, capturing the server certificate on each handshake.
    pub(crate) fn new(inner: Arc<dyn ServerCertVerifier>) -> Self {
        Self {
            inner,
            captured_cert: Arc::new(Mutex::new(None)),
        }
    }

    /// Return a clone-able handle to retrieve the captured certificate.
    pub(crate) fn cert_handle(&self) -> CertHandle {
        CertHandle {
            captured_cert: Arc::clone(&self.captured_cert),
        }
    }
}

impl ServerCertVerifier for CertCapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // Capture the end-entity certificate (DER bytes).
        //
        // Mutex poisoning is rare but possible if a previous handshake
        // panicked mid-capture. Log loudly because losing the cert here
        // means NTLM will fall back to non-CBT silently.
        match self.captured_cert.lock() {
            Ok(mut captured) => *captured = Some(end_entity.to_vec()),
            Err(_) => tracing::error!(
                "CertCapturingVerifier mutex poisoned — server cert not stored, \
                 NTLM Channel Binding will be skipped"
            ),
        }
        // Delegate actual verification to the inner verifier
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Clone-able handle to retrieve the captured server certificate.
#[derive(Clone, Debug)]
pub(crate) struct CertHandle {
    captured_cert: Arc<Mutex<Option<Vec<u8>>>>,
}

impl CertHandle {
    /// Return the DER-encoded server certificate, if one has been captured.
    pub(crate) fn get(&self) -> Option<Vec<u8>> {
        self.captured_cert.lock().ok()?.clone()
    }
}

/// A no-op verifier that accepts any certificate. Used as inner verifier when
/// `accept_invalid_certs` is enabled.
#[derive(Debug)]
pub(crate) struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::internal::msgs::codec::{Codec, Reader};

    /// Build a `DigitallySignedStruct` from raw wire bytes.
    /// Wire format: 2-byte scheme + 2-byte length + signature bytes.
    fn make_dss() -> DigitallySignedStruct {
        let mut buf = Vec::new();
        // RSA_PKCS1_SHA256 = 0x0401
        buf.extend_from_slice(&[0x04, 0x01]);
        // 64-byte signature, length prefix
        buf.extend_from_slice(&[0x00, 0x40]);
        buf.extend_from_slice(&[0u8; 64]);
        let mut reader = Reader::init(&buf);
        DigitallySignedStruct::read(&mut reader).unwrap()
    }

    /// Dummy verifier that always succeeds, for testing.
    #[derive(Debug)]
    struct AcceptAllVerifier;

    impl ServerCertVerifier for AcceptAllVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::RSA_PKCS1_SHA256]
        }
    }

    #[test]
    fn captures_server_certificate() {
        let inner = Arc::new(AcceptAllVerifier);
        let verifier = CertCapturingVerifier::new(inner);
        let handle = verifier.cert_handle();

        // No cert captured yet
        assert!(handle.get().is_none());

        // Simulate a handshake
        let fake_cert = CertificateDer::from(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let server_name = ServerName::try_from("example.com").unwrap();
        let result =
            verifier.verify_server_cert(&fake_cert, &[], &server_name, &[], UnixTime::now());
        assert!(result.is_ok());

        // Cert should be captured
        let captured = handle.get().unwrap();
        assert_eq!(captured, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn handle_is_cloneable() {
        let inner = Arc::new(AcceptAllVerifier);
        let verifier = CertCapturingVerifier::new(inner);
        let handle1 = verifier.cert_handle();
        let handle2 = handle1.clone();

        let fake_cert = CertificateDer::from(vec![1, 2, 3]);
        let server_name = ServerName::try_from("test.local").unwrap();
        let _ = verifier.verify_server_cert(&fake_cert, &[], &server_name, &[], UnixTime::now());

        assert_eq!(handle1.get(), handle2.get());
    }

    #[test]
    fn no_verifier_accepts_any_cert() {
        let verifier = NoVerifier;
        let cert = CertificateDer::from(vec![0xFF; 100]);
        let name = ServerName::try_from("any.host").unwrap();
        assert!(
            verifier
                .verify_server_cert(&cert, &[], &name, &[], UnixTime::now())
                .is_ok()
        );
    }

    #[test]
    fn no_verifier_supported_schemes_not_empty() {
        let verifier = NoVerifier;
        assert!(!verifier.supported_verify_schemes().is_empty());
    }

    #[test]
    fn cert_handle_returns_none_when_nothing_captured() {
        let inner = Arc::new(AcceptAllVerifier);
        let verifier = CertCapturingVerifier::new(inner);
        let handle = verifier.cert_handle();
        assert!(handle.get().is_none());
    }

    #[test]
    fn capturing_verifier_delegates_supported_schemes() {
        let inner = Arc::new(AcceptAllVerifier);
        let verifier = CertCapturingVerifier::new(inner);
        assert_eq!(
            verifier.supported_verify_schemes(),
            vec![SignatureScheme::RSA_PKCS1_SHA256]
        );
    }

    #[test]
    fn capturing_verifier_delegates_tls12_signature() {
        let inner = Arc::new(AcceptAllVerifier);
        let verifier = CertCapturingVerifier::new(inner);
        let cert = CertificateDer::from(vec![0xAA; 32]);
        let dss = make_dss();
        let result = verifier.verify_tls12_signature(b"hello", &cert, &dss);
        assert!(result.is_ok());
    }

    #[test]
    fn capturing_verifier_delegates_tls13_signature() {
        let inner = Arc::new(AcceptAllVerifier);
        let verifier = CertCapturingVerifier::new(inner);
        let cert = CertificateDer::from(vec![0xBB; 32]);
        let dss = make_dss();
        let result = verifier.verify_tls13_signature(b"hello", &cert, &dss);
        assert!(result.is_ok());
    }

    #[test]
    fn no_verifier_accepts_tls12_signature() {
        let verifier = NoVerifier;
        let cert = CertificateDer::from(vec![0xCC; 32]);
        let dss = make_dss();
        let result = verifier.verify_tls12_signature(b"message", &cert, &dss);
        assert!(result.is_ok());
    }

    #[test]
    fn no_verifier_accepts_tls13_signature() {
        let verifier = NoVerifier;
        let cert = CertificateDer::from(vec![0xDD; 32]);
        let dss = make_dss();
        let result = verifier.verify_tls13_signature(b"message", &cert, &dss);
        assert!(result.is_ok());
    }
}
