//! Own an explicit SSPI credential without changing the current logon identity.
#![cfg(windows)]

use anyhow::{Context, Result, ensure};
use windows::{
    Win32::{
        Security::{
            Authentication::Identity::{AcquireCredentialsHandleW, SECPKG_CRED_OUTBOUND},
            Credentials::SecHandle,
        },
        System::Rpc::{SEC_WINNT_AUTH_IDENTITY_UNICODE, SEC_WINNT_AUTH_IDENTITY_W},
    },
    core::{PCWSTR, w},
};
use zeroize::Zeroizing;

/// Acquire outbound Kerberos credentials scoped to the returned handle.
/// The caller retains responsibility for the lifetime of its input password.
pub fn acquire_password(username: &str, domain: &str, password: &str) -> Result<cross_krb5::Cred> {
    ensure!(
        !username.is_empty(),
        "Kerberos password authentication requires a username"
    );
    // A UPN already identifies its realm; passing a second domain can make
    // SSPI reinterpret it as a SAM account in an unrelated domain.
    let domain = if username.contains('@') { "" } else { domain };
    let mut user: Vec<u16> = username.encode_utf16().collect();
    let mut domain: Vec<u16> = domain.encode_utf16().collect();
    let mut password = Zeroizing::new(password.encode_utf16().collect::<Vec<u16>>());
    let identity = SEC_WINNT_AUTH_IDENTITY_W {
        User: user.as_mut_ptr(),
        UserLength: user.len().try_into()?,
        Domain: domain.as_mut_ptr(),
        DomainLength: domain.len().try_into()?,
        Password: password.as_mut_ptr(),
        PasswordLength: password.len().try_into()?,
        Flags: SEC_WINNT_AUTH_IDENTITY_UNICODE,
    };
    let mut handle = SecHandle::default();
    // SAFETY: the identity and its counted UTF-16 buffers remain alive for the
    // synchronous acquisition call. No default logon credentials are modified.
    unsafe {
        AcquireCredentialsHandleW(
            PCWSTR::null(),
            w!("Negotiate"),
            SECPKG_CRED_OUTBOUND,
            None,
            Some((&identity as *const SEC_WINNT_AUTH_IDENTITY_W).cast()),
            None,
            None,
            &mut handle,
            None,
        )
    }
    .context("acquiring explicit Kerberos credentials from SSPI")?;
    // SAFETY: SSPI returned a live credential handle. Ownership is transferred
    // exactly once; cross-krb5 frees it after the security context is dropped.
    Ok(unsafe { cross_krb5::Cred::from_raw(handle) })
}
