//! Length-prefixed metadata and CLIXML input frames keep uploads bounded over local HTTP.
use anyhow::{Context, Result, bail};
use bytes::{Buf, Bytes, BytesMut};
use http_body_util::BodyExt;
pub(super) fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + 4);
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}
pub(super) struct Frames {
    body: axum::body::Body,
    pending: BytesMut,
}
impl Frames {
    pub fn new(body: axum::body::Body) -> Self {
        Self {
            body,
            pending: BytesMut::new(),
        }
    }
    async fn data(&mut self) -> Result<Option<Bytes>> {
        while let Some(frame) = self.body.frame().await {
            if let Ok(data) = frame?.into_data() {
                return Ok(Some(data));
            }
        }
        Ok(None)
    }
    pub async fn next(&mut self, max: usize) -> Result<Option<Vec<u8>>> {
        while self.pending.len() < 4 {
            match self.data().await? {
                Some(bytes) => self.pending.extend_from_slice(&bytes),
                None if self.pending.is_empty() => return Ok(None),
                None => bail!("truncated frame header"),
            }
        }
        let len = u32::from_be_bytes(self.pending[..4].try_into().unwrap()) as usize;
        if len > max {
            bail!("local input frame exceeds {max} bytes");
        }
        while self.pending.len() < 4 + len {
            let bytes = self.data().await?.context("truncated input frame")?;
            self.pending.extend_from_slice(&bytes);
        }
        self.pending.advance(4);
        Ok(Some(self.pending.split_to(len).to_vec()))
    }
}
