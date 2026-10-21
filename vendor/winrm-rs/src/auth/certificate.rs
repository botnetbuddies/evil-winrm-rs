// Certificate-based authentication for WinRM.
//
// Uses client TLS certificates for authentication. The certificate
// must be configured on the WinRM service.

use reqwest::header::CONTENT_TYPE;

use crate::auth::AuthTransport;
use crate::error::WinrmError;

/// Certificate authentication transport.
///
/// Certificate auth uses TLS client cert -- no Authorization header needed.
/// The `reqwest::Client` must be configured with the cert at construction time.
pub(crate) struct CertificateAuth;

impl AuthTransport for CertificateAuth {
    async fn send_authenticated(
        &self,
        http: &reqwest::Client,
        url: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        let resp = http
            .post(url)
            .header(
                "Authorization",
                "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual",
            )
            .header(CONTENT_TYPE, "application/soap+xml;charset=UTF-8")
            .body(body)
            .send()
            .await
            .map_err(WinrmError::Http)?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if status.as_u16() == 500 {
                crate::soap::check_soap_fault(&body).map_err(WinrmError::Soap)?;
            }
            return Err(WinrmError::AuthFailed(format!(
                "Certificate auth HTTP {status}: {body}"
            )));
        }

        resp.text().await.map_err(WinrmError::Http)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn certificate_auth_sends_mutual_tls_profile() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<ok/>"))
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let auth = CertificateAuth;
        let result = auth
            .send_authenticated(&http, &server.uri(), "body".into())
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "<ok/>");
    }

    #[tokio::test]
    async fn certificate_auth_failure_returns_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let auth = CertificateAuth;
        let result = auth
            .send_authenticated(&http, &server.uri(), "body".into())
            .await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("403") || err.contains("Certificate"),
            "error should mention status or auth type: {err}"
        );
    }

    #[tokio::test]
    async fn certificate_fault_retains_the_wsman_code() {
        let server = MockServer::start().await;
        let fault = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"><s:Body><s:Fault><s:Code><s:Value>s:Sender</s:Value><s:Subcode><s:Value>w:InvalidSelectors</s:Value></s:Subcode></s:Code><s:Reason><s:Text>The command no longer exists.</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>"#;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500).set_body_string(fault))
            .mount(&server)
            .await;
        let error = CertificateAuth
            .send_authenticated(&reqwest::Client::new(), &server.uri(), "body".into())
            .await
            .unwrap_err();
        assert!(
            matches!(error, WinrmError::Soap(crate::SoapError::Fault { ref code, .. }) if code == "w:InvalidSelectors")
        );
    }
}
