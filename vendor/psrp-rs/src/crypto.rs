//! Session-key cryptography for MS-PSRP `SecureString` transport.
//!
//! PSRP §3.1.2: to transmit a `SecureString` between the client and
//! server, the two sides negotiate a symmetric session key protected by
//! RSA-OAEP(SHA-1).
//!
//! 1. The client generates a 2048-bit RSA keypair.
//! 2. The client sends its public key to the server in a `PublicKey`
//!    message (CLIXML body: a single `<S>` containing the key
//!    serialized as the Windows `BLOBHEADER` + modulus + exponent).
//! 3. The server generates a 256-bit AES session key, encrypts it with
//!    the client's public key (RSA-OAEP/SHA-1), and sends the ciphertext
//!    back in an `EncryptedSessionKey` message.
//! 4. Both sides use that AES key in CBC mode with PKCS#7 padding to
//!    wrap every `<SS>` (SecureString) element. The IV is a fresh
//!    random 16-byte value prefixed to the ciphertext.
//!
//! This module implements the **pure-Rust** crypto (no OpenSSL) needed
//! for that exchange plus a [`SessionKey`] helper that encrypts and
//! decrypts individual `SecureString` values.
//!
//! The exchange itself is driven by the runspace pool — see
//! [`crate::runspace::RunspacePool::request_session_key`].

use aes::Aes256;
use aes::cipher::Array;
use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use rand::RngCore;
use rsa::traits::PublicKeyParts;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{PsrpError, Result};

/// Client-side RSA key used for PSRP session-key negotiation.
pub struct ClientSessionKey {
    private: RsaPrivateKey,
}

impl std::fmt::Debug for ClientSessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientSessionKey")
            .field("private", &"<redacted>")
            .finish()
    }
}

impl ClientSessionKey {
    /// Generate a fresh 2048-bit RSA keypair.
    pub fn generate() -> Result<Self> {
        let mut rng = rand::thread_rng();
        let private = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| PsrpError::protocol(format!("RSA keygen: {e}")))?;
        Ok(Self { private })
    }

    /// Return the Windows `PUBLICKEYBLOB` representation of the public
    /// key that PSRP expects to transport via the `PublicKey` message.
    ///
    /// Layout — 276 bytes total, hex-encoded to 552 characters:
    /// ```text
    /// BLOBHEADER (8 bytes):
    ///   bType    = 0x06    (PUBLICKEYBLOB)   1 byte
    ///   bVersion = 0x02                      1 byte
    ///   reserved = 0x0000                    2 bytes
    ///   aiKeyAlg = 0xa400  (CALG_RSA_KEYX)   4 bytes, little-endian
    /// RSAPUBKEY (12 bytes):
    ///   magic    = "RSA1"                    4 bytes
    ///   bitlen   = 2048                      4 bytes, little-endian
    ///   pubexp   = public exponent           4 bytes, little-endian
    /// modulus (256 bytes, little-endian)
    /// ```
    #[must_use]
    pub fn public_blob_hex(&self) -> String {
        let public = RsaPublicKey::from(&self.private);
        let mut blob = Vec::with_capacity(8 + 12 + 256);
        // BLOBHEADER
        blob.push(0x06);
        blob.push(0x02);
        blob.push(0x00);
        blob.push(0x00);
        blob.extend_from_slice(&0xa400u32.to_le_bytes());
        // RSAPUBKEY
        blob.extend_from_slice(b"RSA1");
        blob.extend_from_slice(&2048u32.to_le_bytes());
        let e_bytes = public.e().to_bytes_le();
        let mut exp = [0u8; 4];
        for (i, b) in e_bytes.iter().take(4).enumerate() {
            exp[i] = *b;
        }
        blob.extend_from_slice(&exp);
        // Force modulus to exactly 256 bytes (little-endian).
        let mut modulus = public.n().to_bytes_le();
        if modulus.len() > 256 {
            modulus.truncate(256);
        } else {
            modulus.resize(256, 0);
        }
        blob.extend_from_slice(&modulus);

        let mut hex = String::with_capacity(blob.len() * 2);
        for b in &blob {
            hex.push_str(&format!("{b:02X}"));
        }
        hex
    }

    /// Decrypt an RSA-OAEP/SHA-1 wrapped session key and return the raw
    /// 32-byte AES key.
    pub fn decrypt_session_key(&self, ciphertext: &[u8]) -> Result<[u8; 32]> {
        let padding = Oaep::new::<Sha1>();
        let mut decrypted = self
            .private
            .decrypt(padding, ciphertext)
            .map_err(|e| PsrpError::protocol(format!("session key unwrap: {e}")))?;
        if decrypted.len() != 32 {
            decrypted.zeroize();
            return Err(PsrpError::protocol(format!(
                "session key: expected 32 bytes, got {}",
                decrypted.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&decrypted);
        decrypted.zeroize();
        Ok(out)
    }
}

/// A negotiated AES-256-CBC session key ready for `SecureString`
/// encryption / decryption.
///
/// Key bytes are zeroized when the value is dropped.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SessionKey {
    key: [u8; 32],
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKey")
            .field("key", &"<redacted>")
            .finish()
    }
}

impl SessionKey {
    /// Wrap a raw 256-bit key.
    #[must_use]
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Generate a fresh random 256-bit key (server-side test helper).
    #[must_use]
    pub fn random() -> Self {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Self { key }
    }

    /// Encrypt a plaintext string and return `IV || ciphertext`.
    ///
    /// PSRP transports `SecureString` values by UTF-16LE-encoding the
    /// plaintext, AES-CBC encrypting with PKCS#7 padding, and prefixing
    /// the 16-byte IV.
    pub fn encrypt_secure_string(&self, plaintext: &str) -> Vec<u8> {
        // UTF-16LE encode + PKCS#7 pad to 16 bytes.
        let mut padded: Vec<u8> = plaintext
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let pad = 16 - (padded.len() % 16);
        padded.extend(std::iter::repeat_n(pad as u8, pad));

        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);
        let cipher = Aes256::new(&Array::from(self.key));

        // CBC: for each block, XOR with previous ciphertext (or IV for
        // the first block) then encrypt.
        let mut out = Vec::with_capacity(16 + padded.len());
        out.extend_from_slice(&iv);
        let mut prev: [u8; 16] = iv;
        for chunk in padded.as_chunks::<16>().0 {
            let mut block = [0u8; 16];
            for i in 0..16 {
                block[i] = chunk[i] ^ prev[i];
            }
            let mut ga = Array::from(block);
            cipher.encrypt_block(&mut ga);
            prev.copy_from_slice(ga.as_ref());
            out.extend_from_slice(&prev);
        }
        out
    }

    /// Decrypt `IV || ciphertext` back into the plaintext string.
    pub fn decrypt_secure_string(&self, payload: &[u8]) -> Result<String> {
        if payload.len() < 32 || (payload.len() - 16) % 16 != 0 {
            return Err(PsrpError::protocol("secure string payload malformed"));
        }
        let (iv, ct) = payload.split_at(16);
        let cipher = Aes256::new(&Array::from(self.key));

        let mut prev: [u8; 16] = iv.try_into().unwrap();
        let mut pt = Vec::with_capacity(ct.len());
        for chunk in ct.as_chunks::<16>().0 {
            let mut ga = Array::from(*chunk);
            cipher.decrypt_block(&mut ga);
            let mut block = [0u8; 16];
            for i in 0..16 {
                block[i] = ga[i] ^ prev[i];
            }
            pt.extend_from_slice(&block);
            prev.copy_from_slice(chunk);
        }

        // Strip PKCS#7 padding.
        let pad = *pt
            .last()
            .ok_or_else(|| PsrpError::protocol("empty plaintext"))? as usize;
        if pad == 0 || pad > 16 || pad > pt.len() {
            return Err(PsrpError::protocol("invalid PKCS#7 padding"));
        }
        for &b in &pt[pt.len() - pad..] {
            if b as usize != pad {
                return Err(PsrpError::protocol("invalid PKCS#7 padding"));
            }
        }
        pt.truncate(pt.len() - pad);

        if pt.len() % 2 != 0 {
            return Err(PsrpError::protocol(
                "secure string plaintext not UTF-16 aligned",
            ));
        }
        let units: Vec<u16> = pt
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        String::from_utf16(&units)
            .map_err(|e| PsrpError::protocol(format!("secure string UTF-16: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_key_roundtrip_ascii() {
        let key = SessionKey::random();
        let ct = key.encrypt_secure_string("hello world");
        assert!(ct.len() > 16);
        let pt = key.decrypt_secure_string(&ct).unwrap();
        assert_eq!(pt, "hello world");
    }

    #[test]
    fn session_key_roundtrip_unicode() {
        let key = SessionKey::random();
        let ct = key.encrypt_secure_string("héllo 🌍");
        let pt = key.decrypt_secure_string(&ct).unwrap();
        assert_eq!(pt, "héllo 🌍");
    }

    #[test]
    fn session_key_empty_string() {
        let key = SessionKey::random();
        let ct = key.encrypt_secure_string("");
        let pt = key.decrypt_secure_string(&ct).unwrap();
        assert_eq!(pt, "");
    }

    #[test]
    fn decrypt_too_short() {
        let key = SessionKey::random();
        assert!(key.decrypt_secure_string(&[0u8; 4]).is_err());
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let k1 = SessionKey::random();
        let k2 = SessionKey::random();
        let ct = k1.encrypt_secure_string("x");
        assert!(k2.decrypt_secure_string(&ct).is_err());
    }

    #[test]
    fn session_key_from_bytes() {
        let key = SessionKey::from_bytes([0u8; 32]);
        let ct = key.encrypt_secure_string("abc");
        let pt = SessionKey::from_bytes([0u8; 32])
            .decrypt_secure_string(&ct)
            .unwrap();
        assert_eq!(pt, "abc");
    }

    #[test]
    fn client_session_key_generates_blob() {
        // RSA keygen is slow (~500 ms on modest hardware). Keep to one test.
        let k = ClientSessionKey::generate().unwrap();
        let blob = k.public_blob_hex();
        // Header is always 24 bytes (48 hex chars), modulus is 256 bytes.
        assert!(blob.len() >= 48);
        assert!(blob.starts_with("06020000"));
    }

    #[test]
    fn decrypt_misaligned_payload() {
        let key = SessionKey::random();
        // 16 (IV) + 17 (not a multiple of 16)
        let bad = vec![0u8; 33];
        assert!(key.decrypt_secure_string(&bad).is_err());
    }

    #[test]
    fn decrypt_bad_pkcs7_padding() {
        let key = SessionKey::random();
        // Encrypt something valid, then tamper with the last byte (padding)
        let ct = key.encrypt_secure_string("x");
        let mut tampered = ct.clone();
        let len = tampered.len();
        tampered[len - 1] ^= 0xFF; // flip last byte
        assert!(key.decrypt_secure_string(&tampered).is_err());
    }

    #[test]
    fn full_rsa_aes_roundtrip() {
        // Local simulation: client generates key, "server" uses its
        // public key to RSA-OAEP encrypt a random AES key, client
        // decrypts, both encrypt/decrypt a SecureString.
        let client = ClientSessionKey::generate().unwrap();
        let aes = {
            let mut k = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut k);
            k
        };
        // Encrypt with the client's public key.
        let public = RsaPublicKey::from(&client.private);
        let padding = Oaep::new::<Sha1>();
        let wrapped = public
            .encrypt(&mut rand::thread_rng(), padding, &aes)
            .unwrap();
        // Client decrypts.
        let unwrapped = client.decrypt_session_key(&wrapped).unwrap();
        assert_eq!(unwrapped, aes);
        let sk = SessionKey::from_bytes(unwrapped);
        let ct = sk.encrypt_secure_string("s3cret");
        let pt = sk.decrypt_secure_string(&ct).unwrap();
        assert_eq!(pt, "s3cret");
    }

    #[test]
    fn client_session_key_debug_redacts_private() {
        let key = ClientSessionKey::generate().unwrap();
        let dbg = format!("{key:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("BEGIN"));
    }
}
