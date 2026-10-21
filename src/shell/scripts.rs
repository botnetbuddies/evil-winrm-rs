//! Decode script files, bounded stdin/URL sources, and literal script arguments.
use super::paths::resolve_local;
use crate::{cli::Cli, command::quote};
use anyhow::{Context, Result, bail};
use std::{
    io::{IsTerminal, Read},
    path::Path,
};
pub fn read_script(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    decode_script(&bytes)
}

const MAX_SCRIPT_BYTES: usize = 16 * 1024 * 1024;

pub(super) async fn read_script_source(source: &str, args: &Cli) -> Result<String> {
    if source == "-" {
        if args.command.is_none() || std::io::stdin().is_terminal() {
            bail!(
                "runps - requires piped script input and --command; use --password-file or a hidden password prompt"
            );
        }
        if args.password_stdin {
            bail!("runps - cannot share stdin with --password-stdin; use --password-file");
        }
        let mut bytes = Vec::new();
        std::io::stdin()
            .take((MAX_SCRIPT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_SCRIPT_BYTES {
            bail!("stdin script exceeds 16 MiB");
        }
        return decode_script(&bytes);
    }
    if source.starts_with("http://") || source.starts_with("https://") {
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(args.connect_timeout))
            .timeout(std::time::Duration::from_secs(
                args.operation_timeout.saturating_add(10),
            ))
            .danger_accept_invalid_certs(!args.verify_tls && args.ca_cert.is_none());
        if let Some(path) = &args.ca_cert {
            for cert in reqwest::Certificate::from_pem_bundle(&std::fs::read(path)?)? {
                builder = builder.add_root_certificate(cert);
            }
        }
        if let Some(proxy) = &args.proxy {
            builder = builder.proxy(reqwest::Proxy::all(proxy)?);
        }
        let mut response = builder
            .build()?
            .get(source)
            .send()
            .await
            .context("fetching script URL")?
            .error_for_status()?;
        if !response.status().is_success() {
            bail!("script URL returned HTTP {}", response.status());
        }
        if response
            .content_length()
            .is_some_and(|size| size > MAX_SCRIPT_BYTES as u64)
        {
            bail!("URL script exceeds 16 MiB");
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if bytes.len().saturating_add(chunk.len()) > MAX_SCRIPT_BYTES {
                bail!("URL script exceeds 16 MiB");
            }
            bytes.extend_from_slice(&chunk);
        }
        return decode_script(&bytes);
    }
    read_script(&resolve_local(source, args.scripts.as_deref()))
}

/// Preserve parameter binding while keeping values literal, including quotes/separators.
pub(super) fn script_invocation(script: &str, args: &[String]) -> String {
    let mut command = format!("& {{\n{script}\n}}");
    for arg in args {
        command.push(' ');
        let parameter = arg.strip_prefix('-').filter(|name| {
            let name = name.split_once(':').map_or(*name, |(name, _)| name);
            !name.is_empty()
                && name
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        });
        if let Some(parameter) = parameter {
            if let Some((name, value)) = parameter.split_once(':') {
                command.push_str(&format!(
                    "-{name}:{}",
                    if value.eq_ignore_ascii_case("$true") {
                        "$true".into()
                    } else if value.eq_ignore_ascii_case("$false") {
                        "$false".into()
                    } else {
                        quote(value)
                    }
                ));
            } else {
                command.push_str(arg);
            }
        } else {
            command.push_str(&quote(arg));
        }
    }
    command
}

fn decode_script(bytes: &[u8]) -> Result<String> {
    if let Some(body) = bytes.strip_prefix(&[0xff, 0xfe]) {
        let (text, errors) = encoding_rs::UTF_16LE.decode_without_bom_handling(body);
        if errors {
            bail!("invalid UTF-16LE script");
        }
        return Ok(text.into_owned());
    }
    if let Some(body) = bytes.strip_prefix(&[0xfe, 0xff]) {
        let (text, errors) = encoding_rs::UTF_16BE.decode_without_bom_handling(body);
        if errors {
            bail!("invalid UTF-16BE script");
        }
        return Ok(text.into_owned());
    }
    let body = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    // Match upstream's Latin-1 fallback after the Unicode encodings.
    Ok(String::from_utf8(body.to_vec())
        .unwrap_or_else(|_| body.iter().map(|b| char::from(*b)).collect()))
}
