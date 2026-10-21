//! PSRP fragment layer (MS-PSRP §2.2.4).
//!
//! A PSRP message is sliced into one or more fragments. Each fragment has a
//! 21-byte big-endian header followed by a blob:
//!
//! ```text
//!  0                               8                              16
//! +-------------------------------+-------------------------------+---+-----+
//! |          ObjectId  (u64 BE)   |        FragmentId (u64 BE)    | F | Len |
//! +-------------------------------+-------------------------------+---+-----+
//!                                                                  ^17 ^21 + payload
//! ```
//!
//! `F` flags: `0x01` = Start of object, `0x02` = End of object.
//!
//! The fragmenter splits a message payload at [`MAX_FRAGMENT_PAYLOAD`]; the
//! reassembler is stateful and tolerates fragments being split at arbitrary
//! byte boundaries across successive `feed` calls.

use std::collections::HashMap;

use crate::error::{PsrpError, Result};

/// Maximum payload bytes per fragment. Matches `pypsrp`'s default and is well
/// under `winrm-rs`' default `max_envelope_size` of 153 600 bytes (base64
/// overhead included).
pub const MAX_FRAGMENT_PAYLOAD: usize = 32 * 1024;

/// Size of the fragment header in bytes.
pub const FRAGMENT_HEADER_LEN: usize = 21;

const FLAG_START: u8 = 0x01;
const FLAG_END: u8 = 0x02;

/// A single PSRP fragment (header + blob).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    /// Object identifier shared by all fragments of the same message.
    pub object_id: u64,
    /// 0-based index of this fragment within the message.
    pub fragment_id: u64,
    /// True for the first fragment of an object.
    pub start: bool,
    /// True for the last fragment of an object.
    pub end: bool,
    /// Payload bytes for this fragment.
    pub blob: Vec<u8>,
}

impl Fragment {
    fn flags(&self) -> u8 {
        let mut f = 0;
        if self.start {
            f |= FLAG_START;
        }
        if self.end {
            f |= FLAG_END;
        }
        f
    }

    /// Serialize this fragment to its wire representation.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FRAGMENT_HEADER_LEN + self.blob.len());
        out.extend_from_slice(&self.object_id.to_be_bytes());
        out.extend_from_slice(&self.fragment_id.to_be_bytes());
        out.push(self.flags());
        out.extend_from_slice(
            &u32::try_from(self.blob.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        out.extend_from_slice(&self.blob);
        out
    }
}

/// Split a complete PSRP message payload into fragments for the given
/// `object_id`. At least one fragment is always returned (an empty message
/// yields a single `start+end` fragment with an empty blob).
#[must_use]
pub fn split_message(object_id: u64, payload: &[u8]) -> Vec<Fragment> {
    if payload.is_empty() {
        return vec![Fragment {
            object_id,
            fragment_id: 0,
            start: true,
            end: true,
            blob: Vec::new(),
        }];
    }

    let mut out = Vec::new();
    let chunks: Vec<&[u8]> = payload.chunks(MAX_FRAGMENT_PAYLOAD).collect();
    let last = chunks.len() - 1;
    for (i, chunk) in chunks.into_iter().enumerate() {
        out.push(Fragment {
            object_id,
            fragment_id: i as u64,
            start: i == 0,
            end: i == last,
            blob: chunk.to_vec(),
        });
    }
    out
}

/// Encode every fragment produced by [`split_message`] into a single
/// concatenated byte buffer ready to be sent via `Shell::send_input`.
#[must_use]
pub fn encode_message(object_id: u64, payload: &[u8]) -> Vec<u8> {
    let frags = split_message(object_id, payload);
    let total: usize = frags
        .iter()
        .map(|f| FRAGMENT_HEADER_LEN + f.blob.len())
        .sum();
    let mut out = Vec::with_capacity(total);
    for f in frags {
        out.extend_from_slice(&f.encode());
    }
    out
}

/// Track partial messages so they can be emitted whole once the final
/// fragment arrives.
#[derive(Debug, Default)]
struct InFlight {
    buf: Vec<u8>,
    next_fragment_id: u64,
    started: bool,
}

/// Stateful reassembler for incoming PSRP fragments.
///
/// Bytes from `Shell::receive_next` can be fed in arbitrary chunks. Whenever
/// a complete message is reconstructed (from the `start` fragment through the
/// `end` fragment), its payload is returned in order from [`Reassembler::feed`].
#[derive(Debug, Default)]
pub struct Reassembler {
    buffer: Vec<u8>,
    in_flight: HashMap<u64, InFlight>,
    completed_order: Vec<u64>,
}

impl Reassembler {
    /// Create a fresh reassembler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed raw bytes received from the transport and return every message
    /// payload that becomes complete as a result.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
        self.buffer.extend_from_slice(bytes);
        let mut completed = Vec::new();

        loop {
            if self.buffer.len() < FRAGMENT_HEADER_LEN {
                break;
            }
            let header = &self.buffer[..FRAGMENT_HEADER_LEN];
            let object_id = u64::from_be_bytes(header[0..8].try_into().unwrap());
            let fragment_id = u64::from_be_bytes(header[8..16].try_into().unwrap());
            let flags = header[16];
            let blob_len = u32::from_be_bytes(header[17..21].try_into().unwrap()) as usize;

            if self.buffer.len() < FRAGMENT_HEADER_LEN + blob_len {
                break; // need more bytes
            }

            let start = flags & FLAG_START != 0;
            let end = flags & FLAG_END != 0;

            let blob_start = FRAGMENT_HEADER_LEN;
            let blob_end = blob_start + blob_len;
            // Use drain to keep allocation patterns simple.
            let blob: Vec<u8> = self.buffer[blob_start..blob_end].to_vec();
            self.buffer.drain(..blob_end);

            let entry = self.in_flight.entry(object_id).or_default();

            if start {
                if entry.started {
                    return Err(PsrpError::fragment(format!(
                        "duplicate start fragment for object {object_id}"
                    )));
                }
                if fragment_id != 0 {
                    return Err(PsrpError::fragment(format!(
                        "start fragment for object {object_id} has non-zero fragment id {fragment_id}"
                    )));
                }
                entry.started = true;
                entry.next_fragment_id = 0;
            } else if !entry.started {
                return Err(PsrpError::fragment(format!(
                    "continuation fragment before start for object {object_id}"
                )));
            }

            if fragment_id != entry.next_fragment_id {
                return Err(PsrpError::fragment(format!(
                    "out-of-order fragment for object {object_id}: expected {}, got {fragment_id}",
                    entry.next_fragment_id
                )));
            }
            entry.next_fragment_id += 1;
            entry.buf.extend_from_slice(&blob);

            if end {
                let done = self.in_flight.remove(&object_id).unwrap().buf;
                completed.push(done);
                self.completed_order.push(object_id);
            }
        }

        Ok(completed)
    }

    /// True if there are no partially-accumulated messages and no leftover
    /// buffered bytes.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.buffer.is_empty() && self.in_flight.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_roundtrip_single_fragment() {
        let payload = b"hello world".to_vec();
        let bytes = encode_message(42, &payload);
        let mut r = Reassembler::new();
        let out = r.feed(&bytes).unwrap();
        assert_eq!(out, vec![payload]);
        assert!(r.is_idle());
    }

    #[test]
    fn empty_message_roundtrip() {
        let bytes = encode_message(7, b"");
        let mut r = Reassembler::new();
        let out = r.feed(&bytes).unwrap();
        assert_eq!(out, vec![Vec::<u8>::new()]);
    }

    #[test]
    fn splits_at_max_fragment_payload() {
        let payload = vec![0xABu8; MAX_FRAGMENT_PAYLOAD * 2 + 10];
        let frags = split_message(1, &payload);
        assert_eq!(frags.len(), 3);
        assert!(frags[0].start && !frags[0].end);
        assert!(!frags[1].start && !frags[1].end);
        assert!(!frags[2].start && frags[2].end);
        assert_eq!(frags[0].blob.len(), MAX_FRAGMENT_PAYLOAD);
        assert_eq!(frags[1].blob.len(), MAX_FRAGMENT_PAYLOAD);
        assert_eq!(frags[2].blob.len(), 10);

        let bytes = encode_message(1, &payload);
        let mut r = Reassembler::new();
        let out = r.feed(&bytes).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], payload);
    }

    #[test]
    fn feed_byte_by_byte() {
        let payload = b"PSRP fragments love being cruelly sliced".to_vec();
        let bytes = encode_message(9, &payload);
        let mut r = Reassembler::new();
        let mut got = Vec::new();
        for b in &bytes {
            got.extend(r.feed(&[*b]).unwrap());
        }
        assert_eq!(got, vec![payload]);
    }

    #[test]
    fn feed_header_split() {
        // split exactly in the middle of the header
        let payload = b"halfway header".to_vec();
        let bytes = encode_message(2, &payload);
        let (a, b) = bytes.split_at(10);
        let mut r = Reassembler::new();
        assert!(r.feed(a).unwrap().is_empty());
        let out = r.feed(b).unwrap();
        assert_eq!(out, vec![payload]);
    }

    #[test]
    fn interleaved_object_ids() {
        // Message A: 2 fragments; Message B: 1 fragment. We send them
        // interleaved: A0 B0 A1. Wire order MUST preserve per-object fragment
        // ordering, which it does here.
        let a_payload = vec![0xAA; MAX_FRAGMENT_PAYLOAD + 5];
        let b_payload = b"beta".to_vec();

        let a_frags = split_message(100, &a_payload);
        let b_frags = split_message(200, &b_payload);

        let mut wire = Vec::new();
        wire.extend_from_slice(&a_frags[0].encode());
        wire.extend_from_slice(&b_frags[0].encode());
        wire.extend_from_slice(&a_frags[1].encode());

        let mut r = Reassembler::new();
        let out = r.feed(&wire).unwrap();
        // B completes first, then A.
        assert_eq!(out, vec![b_payload, a_payload]);
        assert!(r.is_idle());
    }

    #[test]
    fn rejects_continuation_before_start() {
        // Fabricate a fragment with flags=0 and fragment_id=0 without a
        // preceding start fragment.
        let f = Fragment {
            object_id: 5,
            fragment_id: 0,
            start: false,
            end: true,
            blob: b"oops".to_vec(),
        };
        let mut r = Reassembler::new();
        let err = r.feed(&f.encode()).unwrap_err();
        assert!(matches!(err, PsrpError::Fragment(_)));
    }

    #[test]
    fn rejects_duplicate_start() {
        let f1 = Fragment {
            object_id: 5,
            fragment_id: 0,
            start: true,
            end: false,
            blob: b"a".to_vec(),
        };
        let f2 = Fragment {
            object_id: 5,
            fragment_id: 0,
            start: true,
            end: false,
            blob: b"b".to_vec(),
        };
        let mut r = Reassembler::new();
        r.feed(&f1.encode()).unwrap();
        let err = r.feed(&f2.encode()).unwrap_err();
        assert!(matches!(err, PsrpError::Fragment(_)));
    }

    #[test]
    fn rejects_out_of_order_fragment_id() {
        let f0 = Fragment {
            object_id: 5,
            fragment_id: 0,
            start: true,
            end: false,
            blob: b"a".to_vec(),
        };
        let f2 = Fragment {
            object_id: 5,
            fragment_id: 2,
            start: false,
            end: true,
            blob: b"c".to_vec(),
        };
        let mut r = Reassembler::new();
        r.feed(&f0.encode()).unwrap();
        let err = r.feed(&f2.encode()).unwrap_err();
        assert!(matches!(err, PsrpError::Fragment(_)));
    }

    #[test]
    fn rejects_start_with_nonzero_fragment_id() {
        let f = Fragment {
            object_id: 5,
            fragment_id: 3,
            start: true,
            end: true,
            blob: b"a".to_vec(),
        };
        let mut r = Reassembler::new();
        let err = r.feed(&f.encode()).unwrap_err();
        assert!(matches!(err, PsrpError::Fragment(_)));
    }

    #[test]
    fn fragment_encode_flags_start_only() {
        let f = Fragment {
            object_id: 1,
            fragment_id: 0,
            start: true,
            end: false,
            blob: b"x".to_vec(),
        };
        let bytes = f.encode();
        assert_eq!(bytes[16], 0x01);
    }

    #[test]
    fn fragment_encode_flags_end_only() {
        let f = Fragment {
            object_id: 1,
            fragment_id: 1,
            start: false,
            end: true,
            blob: b"x".to_vec(),
        };
        let bytes = f.encode();
        assert_eq!(bytes[16], 0x02);
    }

    #[test]
    fn fragment_encode_flags_both() {
        let f = Fragment {
            object_id: 1,
            fragment_id: 0,
            start: true,
            end: true,
            blob: b"x".to_vec(),
        };
        let bytes = f.encode();
        assert_eq!(bytes[16], 0x03);
    }

    #[test]
    fn max_fragment_payload_value() {
        assert_eq!(MAX_FRAGMENT_PAYLOAD, 32_768);
    }

    #[test]
    fn fragment_encode_flags_none() {
        let f = Fragment {
            object_id: 1,
            fragment_id: 1,
            start: false,
            end: false,
            blob: b"x".to_vec(),
        };
        let bytes = f.encode();
        assert_eq!(bytes[16], 0x00);
    }

    #[test]
    fn is_idle_tracks_partial_state() {
        let payload = b"xxxxxxxxxx".to_vec();
        let bytes = encode_message(1, &payload);
        let mut r = Reassembler::new();
        assert!(r.is_idle());
        r.feed(&bytes[..15]).unwrap();
        assert!(!r.is_idle());
        r.feed(&bytes[15..]).unwrap();
        assert!(r.is_idle());
    }
}
