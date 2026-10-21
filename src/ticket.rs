//! KRB-CRED (kirbi) to MIT ccache v4 conversion. No external converter process.
use anyhow::{Context, Result, bail};

#[derive(Clone, Copy)]
struct Der<'a> {
    tag: u8,
    body: &'a [u8],
    encoded: &'a [u8],
}
fn parse(data: &[u8]) -> Result<(Der<'_>, &[u8])> {
    if data.len() < 2 {
        bail!("truncated DER header");
    }
    let tag = data[0];
    let first = data[1];
    let (length, header) = if first < 128 {
        (usize::from(first), 2)
    } else {
        let n = usize::from(first & 127);
        if n == 0 || n > 4 || data.len() < 2 + n {
            bail!("invalid DER length");
        }
        let length = data[2..2 + n]
            .iter()
            .fold(0usize, |a, b| (a << 8) | usize::from(*b));
        (length, 2 + n)
    };
    let end = header.checked_add(length).context("DER length overflow")?;
    if end > data.len() {
        bail!("truncated DER body");
    }
    Ok((
        Der {
            tag,
            body: &data[header..end],
            encoded: &data[..end],
        },
        &data[end..],
    ))
}
impl<'a> Der<'a> {
    fn one(self) -> Result<Self> {
        let (v, rest) = parse(self.body)?;
        if !rest.is_empty() {
            bail!("unexpected trailing DER data");
        }
        Ok(v)
    }
    fn children(self) -> Result<Vec<Self>> {
        let mut data = self.body;
        let mut out = Vec::new();
        while !data.is_empty() {
            let (item, rest) = parse(data)?;
            out.push(item);
            data = rest;
        }
        Ok(out)
    }
    fn field(self, n: u8) -> Result<Self> {
        self.children()?
            .into_iter()
            .find(|v| v.tag == 0xa0 + n)
            .with_context(|| format!("missing Kerberos field {n}"))?
            .one()
    }
    fn optional(self, n: u8) -> Result<Option<Self>> {
        self.children()?
            .into_iter()
            .find(|v| v.tag == 0xa0 + n)
            .map(Der::one)
            .transpose()
    }
    fn integer(self) -> Result<u32> {
        if self.tag != 2
            || self.body.is_empty()
            || self.body.len() > 5
            || (self.body.len() == 5 && self.body[0] != 0)
        {
            bail!("invalid Kerberos integer");
        }
        Ok(self.body.iter().fold(0u32, |a, b| (a << 8) | u32::from(*b)))
    }
}
fn counted(out: &mut Vec<u8>, data: &[u8]) -> Result<()> {
    out.extend_from_slice(&u32::try_from(data.len())?.to_be_bytes());
    out.extend_from_slice(data);
    Ok(())
}
fn principal(out: &mut Vec<u8>, realm: Der<'_>, name: Der<'_>) -> Result<()> {
    let kind = name.field(0)?.integer()?;
    let names = name.field(1)?.children()?;
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&u32::try_from(names.len())?.to_be_bytes());
    counted(out, realm.body)?;
    for name in names {
        counted(out, name.body)?;
    }
    Ok(())
}
fn timestamp(value: Option<Der<'_>>) -> Result<u32> {
    let Some(value) = value else {
        return Ok(0);
    };
    if value.tag != 0x18 {
        bail!("invalid Kerberos time");
    }
    let text = std::str::from_utf8(value.body)?;
    let time = chrono::NaiveDateTime::parse_from_str(text, "%Y%m%d%H%M%SZ")?
        .and_utc()
        .timestamp();
    u32::try_from(time).context("Kerberos timestamp outside ccache range")
}

pub fn kirbi_to_ccache(input: &[u8]) -> Result<Vec<u8>> {
    let (cred, rest) = parse(input)?;
    if cred.tag != 0x76 || !rest.is_empty() {
        bail!("expected a KRB-CRED ticket");
    }
    let cred = cred.one()?;
    if cred.field(0)?.integer()? != 5 || cred.field(1)?.integer()? != 22 {
        bail!("invalid KRB-CRED version or message type");
    }
    let tickets = cred.field(2)?.children()?;
    let encrypted = cred.field(3)?;
    if encrypted.field(0)?.integer()? != 0 {
        bail!("encrypted kirbi files require decryption before import");
    }
    let cipher = encrypted.field(2)?;
    if cipher.tag != 4 {
        bail!("invalid KRB-CRED cipher");
    }
    let (part, rest) = parse(cipher.body)?;
    if part.tag != 0x7d || !rest.is_empty() {
        bail!("invalid EncKrbCredPart");
    }
    let info = part.one()?.field(0)?.children()?;
    if info.is_empty() || info.len() != tickets.len() {
        bail!("ticket and credential counts do not match");
    }
    let mut out = vec![5, 4, 0, 0];
    principal(&mut out, info[0].field(1)?, info[0].field(2)?)?;
    for (info, ticket) in info.into_iter().zip(tickets) {
        principal(&mut out, info.field(1)?, info.field(2)?)?;
        principal(&mut out, info.field(8)?, info.field(9)?)?;
        let key = info.field(0)?;
        let kind = u16::try_from(key.field(0)?.integer()?)?;
        let bytes = key.field(1)?;
        out.extend_from_slice(&kind.to_be_bytes());
        counted(&mut out, bytes.body)?;
        let auth = timestamp(info.optional(4)?)?;
        let start = timestamp(info.optional(5)?)?;
        for time in [
            auth,
            if start == 0 { auth } else { start },
            timestamp(info.optional(6)?)?,
            timestamp(info.optional(7)?)?,
        ] {
            out.extend_from_slice(&time.to_be_bytes());
        }
        out.push(0); // is_skey
        let flags = info
            .optional(3)?
            .map(|v| v.body)
            .unwrap_or(&[0, 0, 0, 0, 0]);
        if flags.len() != 5 || flags[0] != 0 {
            bail!("invalid Kerberos flags bit string");
        }
        out.extend_from_slice(&flags[1..]);
        out.extend_from_slice(&0u32.to_be_bytes()); // addresses
        out.extend_from_slice(&0u32.to_be_bytes()); // authdata
        counted(&mut out, ticket.encoded)?;
        counted(&mut out, &[])?;
    }
    Ok(out)
}

/// Keep the returned temporary file alive for the entire connection lifetime.
pub fn prepare(path: &str) -> Result<Option<tempfile::NamedTempFile>> {
    let bytes = std::fs::read(path)?;
    if bytes.starts_with(&[5, 4]) || bytes.starts_with(&[5, 3]) {
        return Ok(None);
    }
    let converted = kirbi_to_ccache(&bytes)?;
    let mut file = tempfile::NamedTempFile::new()?;
    use std::io::Write;
    file.write_all(&converted)?;
    file.flush()?;
    Ok(Some(file))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn der(tag: u8, data: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if data.len() < 128 {
            out.push(data.len() as u8);
        } else {
            out.extend_from_slice(&[0x82, (data.len() >> 8) as u8, data.len() as u8]);
        }
        out.extend_from_slice(data);
        out
    }
    fn field(n: u8, body: Vec<u8>) -> Vec<u8> {
        der(0xa0 + n, &body)
    }
    fn sequence(parts: Vec<Vec<u8>>) -> Vec<u8> {
        der(0x30, &parts.concat())
    }
    fn name(parts: &[&str]) -> Vec<u8> {
        sequence(vec![
            field(0, der(2, &[1])),
            field(
                1,
                sequence(parts.iter().map(|s| der(0x1b, s.as_bytes())).collect()),
            ),
        ])
    }
    #[test]
    fn converts_synthetic_ticket_and_preserves_key_and_ticket() {
        let realm = der(0x1b, b"EXAMPLE.TEST");
        let ticket = der(0x61, &sequence(vec![]));
        let info = sequence(vec![
            field(
                0,
                sequence(vec![field(0, der(2, &[18])), field(1, der(4, &[0xab; 32]))]),
            ),
            field(1, realm.clone()),
            field(2, name(&["alice"])),
            field(3, der(3, &[0, 0x40, 0, 0, 0])),
            field(6, der(0x18, b"20261020120000Z")),
            field(8, realm),
            field(9, name(&["HTTP", "server.example.test"])),
        ]);
        let cipher = der(0x7d, &sequence(vec![field(0, sequence(vec![info]))]));
        let input = der(
            0x76,
            &sequence(vec![
                field(0, der(2, &[5])),
                field(1, der(2, &[22])),
                field(2, sequence(vec![ticket.clone()])),
                field(
                    3,
                    sequence(vec![field(0, der(2, &[0])), field(2, der(4, &cipher))]),
                ),
            ]),
        );
        let out = kirbi_to_ccache(&input).unwrap();
        let parsed = rskrb5::ccache::CCache::parse(&out).unwrap();
        assert_eq!(parsed.client_name(), "alice");
        assert_eq!(parsed.client_realm(), "EXAMPLE.TEST");
        assert_eq!(parsed.credentials().len(), 1);
        assert_eq!(parsed.credentials()[0].key.value, vec![0xab; 32]);
        assert_eq!(parsed.credentials()[0].ticket, ticket);
        assert!(out.starts_with(&[5, 4, 0, 0]));
        assert!(out.windows(32).any(|w| w == [0xab; 32]));
        assert!(out.ends_with(&[ticket.as_slice(), &[0; 4]].concat()));
    }
    #[test]
    fn malformed_ticket_lengths_return_errors() {
        for bytes in [
            &b""[..],
            &[0x76, 0x80],
            &[0x76, 0x84, 0xff, 0xff, 0xff, 0xff],
            &[0x76, 1, 0],
            &[0x30, 0],
        ] {
            assert!(kirbi_to_ccache(bytes).is_err());
        }
    }
}
