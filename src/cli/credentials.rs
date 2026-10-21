//! Bounded secret inputs and credential syntax.
use anyhow::{Context, Result, bail};
use std::io::BufRead;
pub(super) fn parse_environment(value: &str) -> std::result::Result<(String, String), String> {
    let (key, value) = value.split_once('=').ok_or("expected KEY=VALUE")?;
    if key.is_empty() || key.contains('\0') || value.contains('\0') {
        return Err("environment names must be nonempty and values cannot contain NUL".into());
    }
    Ok((key.to_owned(), value.to_owned()))
}

pub fn read_password_line(reader: impl BufRead) -> Result<String> {
    let mut value = zeroize::Zeroizing::new(String::new());
    let size = reader
        .take(65537)
        .read_line(&mut value)
        .context("reading password from stdin")?;
    if size == 0 {
        bail!("stdin contained no password line");
    }
    if size > 65536 {
        bail!("password line is too long");
    }
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    } else if value.ends_with('\r') {
        value.pop();
    }
    Ok(std::mem::take(&mut *value))
}

pub fn split_username(user: &str) -> (String, String) {
    match user.split_once('\\') {
        Some((domain, name)) => (domain.into(), name.into()),
        None => (String::new(), user.into()), // UPNs are passed intact for NTLM.
    }
}

pub fn parse_hash(input: &str) -> Result<[u8; 16]> {
    let hash = input.rsplit_once(':').map_or(input, |(_, nt)| nt);
    if hash.len() != 32 || !hash.bytes().all(|c| c.is_ascii_hexdigit()) {
        bail!("NT hash must contain exactly 32 hexadecimal characters");
    }
    let mut value = [0; 16];
    for (i, out) in value.iter_mut().enumerate() {
        *out = u8::from_str_radix(&hash[i * 2..i * 2 + 2], 16)?;
    }
    Ok(value)
}
