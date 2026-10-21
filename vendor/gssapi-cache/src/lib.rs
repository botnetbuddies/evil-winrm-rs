//! Minimal safe ownership wrapper for the GSSAPI credential-store extension.
use libgssapi::{
    credential::Cred,
    error::{Error, MajorFlags},
};
use libgssapi_sys::*;

pub fn acquire(path: &str) -> Result<Cred, Box<dyn std::error::Error + Send + Sync>> {
    acquire_store(c"ccache", path, 1)
}

/// Acquire an acceptor credential from an explicit keytab without changing the
/// process's KRB5_KTNAME. Used by portable-context interoperability tests.
pub fn acquire_acceptor(path: &str) -> Result<Cred, Box<dyn std::error::Error + Send + Sync>> {
    acquire_store(c"keytab", path, 2)
}

fn acquire_store(
    key: &std::ffi::CStr,
    path: &str,
    usage: gss_cred_usage_t,
) -> Result<Cred, Box<dyn std::error::Error + Send + Sync>> {
    let path = std::ffi::CString::new(path)?;
    let mut element = gss_key_value_element_desc {
        key: key.as_ptr(),
        value: path.as_ptr(),
    };
    let store = gss_key_value_set_desc {
        count: 1,
        elements: &mut element,
    };
    let mut minor = 0;
    let mut raw = std::ptr::null_mut();
    // SAFETY: all pointers reference live storage; output pointers start null.
    // GSS allocates the credential and transfers ownership only on success.
    let major = unsafe {
        gss_acquire_cred_from(
            &mut minor,
            std::ptr::null_mut(),
            u32::MAX,
            std::ptr::null_mut(),
            usage,
            &store,
            &mut raw,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if major != 0 {
        if !raw.is_null() {
            // SAFETY: a failed call may return a partially acquired handle.
            // Release that handle once before propagating the original error.
            let mut ignored = 0;
            unsafe {
                gss_release_cred(&mut ignored, &mut raw);
            }
        }
        return Err(Box::new(Error {
            major: MajorFlags::from_bits_retain(major),
            minor,
        }));
    }
    if raw.is_null() {
        return Err("GSSAPI returned an empty credential handle".into());
    }
    // SAFETY: ownership of the non-null, successfully acquired handle transfers
    // exactly once to Cred, whose Drop implementation releases it.
    Ok(unsafe { Cred::from_c(raw) })
}
