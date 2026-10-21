//! RFC 4757 section 7.3 legacy GSS wrapping, implemented with RustCrypto.
use anyhow::{Context as _, Result, ensure};
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use rc4::{KeyInit, Rc4, StreamCipher};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const OID: &[u8] = &[6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 1, 2, 2];
const HEADER: &[u8] = &[2, 1, 0x11, 0, 0x10, 0, 0xff, 0xff];

fn hmac(key: &[u8], data: &[u8]) -> Zeroizing<[u8; 16]> {
    let mut mac =
        <Hmac<Md5> as hmac::KeyInit>::new_from_slice(key).expect("HMAC accepts every key length");
    mac.update(data);
    Zeroizing::new(mac.finalize().into_bytes().into())
}

fn apply(key: &[u8], data: &mut [u8]) -> Result<()> {
    Rc4::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("invalid RC4 key"))?
        .apply_keystream(data);
    Ok(())
}

fn crypt_key(key: &[u8], sequence: &[u8]) -> Zeroizing<[u8; 16]> {
    let mut local = Zeroizing::new([0u8; 16]);
    for (out, value) in local.iter_mut().zip(key) {
        *out = value ^ 0xf0;
    }
    hmac(hmac(&local[..], &[0; 4]).as_ref(), sequence)
}

fn checksum(key: &[u8], header: &[u8], data: &[u8]) -> Zeroizing<[u8; 16]> {
    let signing = hmac(key, b"signaturekey\0");
    let mut hash = Md5::new();
    hash.update(13u32.to_le_bytes()); // RFC 4757 errata: WRAP uses usage 13.
    hash.update(header);
    hash.update(data);
    hmac(&signing[..], &hash.finalize())
}

fn frame(body: &[u8]) -> Vec<u8> {
    let size = OID.len() + body.len();
    let mut out = vec![0x60];
    if size < 128 {
        out.push(size as u8);
    } else {
        let bytes = size.to_be_bytes();
        let first = bytes.iter().position(|n| *n != 0).unwrap();
        out.push(0x80 | (bytes.len() - first) as u8);
        out.extend_from_slice(&bytes[first..]);
    }
    out.extend_from_slice(OID);
    out.extend_from_slice(body);
    out
}

fn body(data: &[u8]) -> Result<&[u8]> {
    ensure!(data.len() >= 2 && data[0] == 0x60, "invalid RC4 GSS token");
    let (length, start) = if data[1] < 128 {
        (usize::from(data[1]), 2)
    } else {
        let count = usize::from(data[1] & 0x7f);
        ensure!(
            count > 0 && count <= std::mem::size_of::<usize>() && data.len() >= 2 + count,
            "invalid RC4 token length"
        );
        let length = data[2..2 + count]
            .iter()
            .try_fold(0usize, |n, b| {
                n.checked_mul(256)?.checked_add(usize::from(*b))
            })
            .context("RC4 token length overflow")?;
        (length, 2 + count)
    };
    ensure!(
        length == data.len() - start && data[start..].starts_with(OID),
        "invalid RC4 GSS framing"
    );
    Ok(&data[start + OID.len()..])
}

pub(super) fn seal(key: &[u8], sequence: u64, data: &[u8]) -> Result<(usize, Vec<u8>)> {
    ensure!(key.len() == 16, "invalid RC4 session key length");
    let sequence: u32 = sequence.try_into().context("RC4 sequence exhausted")?;
    let sequence_bytes = sequence.to_be_bytes();
    let mut plain = vec![0; 8];
    getrandom::fill(&mut plain)?;
    plain.extend_from_slice(data);
    plain.push(1);
    let signature = checksum(key, HEADER, &plain);
    let encryption = crypt_key(key, &sequence_bytes);
    apply(&encryption[..], &mut plain)?;
    let seq_key = hmac(hmac(key, &[0; 4]).as_ref(), &signature[..8]);
    let mut encrypted_sequence = [0; 8];
    encrypted_sequence[..4].copy_from_slice(&sequence_bytes);
    apply(&seq_key[..], &mut encrypted_sequence)?;
    let mut token = HEADER.to_vec();
    token.extend_from_slice(&encrypted_sequence);
    token.extend_from_slice(&signature[..8]);
    token.extend_from_slice(&plain);
    let encoded = frame(&token);
    Ok((encoded.len() - data.len() - 1, encoded))
}

pub(super) fn unseal(
    key: &[u8],
    expected_sequence: u64,
    encoded: &[u8],
    require_gss_padding: bool,
) -> Result<Vec<u8>> {
    ensure!(key.len() == 16, "invalid RC4 session key length");
    let token = body(encoded)?;
    ensure!(
        token.len() >= (if require_gss_padding { 33 } else { 32 }) && &token[..8] == HEADER,
        "invalid or unencrypted RC4 wrap token"
    );
    let seq_key = hmac(hmac(key, &[0; 4]).as_ref(), &token[16..24]);
    let mut sequence = token[8..16].to_vec();
    apply(&seq_key[..], &mut sequence)?;
    ensure!(
        sequence[4..] == [0xff; 4],
        "RC4 token has the wrong sender direction"
    );
    let number = u32::from_be_bytes(sequence[..4].try_into().unwrap());
    ensure!(
        u64::from(number) == expected_sequence,
        "unexpected RC4 message sequence"
    );
    let encryption = crypt_key(key, &sequence[..4]);
    let mut plain = token[24..].to_vec();
    apply(&encryption[..], &mut plain)?;
    let signature = checksum(key, &token[..8], &plain);
    ensure!(
        bool::from(signature[..8].ct_eq(&token[16..24])),
        "RC4 message checksum mismatch"
    );
    // WinRM's SSPI response can omit the GSS padding buffer entirely. SOAP
    // ends in '>', while a padded GSS token ends in 0x01. Only make this
    // distinction after verifying the complete plaintext's checksum.
    if !require_gss_padding && plain.last() != Some(&1) {
        return Ok(plain[8..].to_vec());
    }
    let padding = usize::from(*plain.last().unwrap());
    ensure!(
        padding > 0
            && padding <= plain.len() - 8
            && plain[plain.len() - padding..]
                .iter()
                .all(|b| usize::from(*b) == padding),
        "invalid RC4 message padding"
    );
    Ok(plain[8..plain.len() - padding].to_vec())
}
