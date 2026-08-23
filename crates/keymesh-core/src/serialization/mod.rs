//! Deterministic binary serialization for protocol messages.
//!
//! Why hand-rolled instead of serde: the encoding is part of the protocol
//! surface — it must be stable, canonical (no ambiguous encodings), and
//! identical across TypeScript, Rust, and future chain runtimes. Canonical
//! encoding is a security property: signature payloads must serialize to
//! exactly one byte string or signatures become malleable.
//!
//! Format rules:
//! - All integers are big-endian.
//! - Lengths are `u32` byte counts.
//! - Enumerants are `u8` discriminants from a fixed registry.
//!
//! ## Maturity: PROTOTYPE
//! The wire format may still change; versioned domain strings in the signing
//! module protect against cross-version replay until v1 freezes it.

use crate::errors::KeymeshError;

/// Encoder with explicit capacity management.
#[derive(Debug, Default)]
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn write_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        self.buf.extend_from_slice(bytes);
    }
}

/// Decoder over a borrowed byte slice.
#[derive(Debug)]
pub struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Fails unless the buffer is fully consumed; partial reads are protocol
    /// errors, never silently truncated.
    pub fn finish(self) -> Result<(), KeymeshError> {
        if self.remaining() != 0 {
            return Err(KeymeshError::InvalidInput(format!(
                "trailing bytes: {} unconsumed",
                self.remaining()
            )));
        }
        Ok(())
    }

    pub fn read_u8(&mut self) -> Result<u8, KeymeshError> {
        if self.remaining() < 1 {
            return Err(KeymeshError::InvalidInput("unexpected end of buffer".into()));
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn read_u64(&mut self) -> Result<u64, KeymeshError> {
        if self.remaining() < 8 {
            return Err(KeymeshError::InvalidInput(
                "unexpected end of buffer reading u64".into(),
            ));
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_be_bytes(arr))
    }

    pub fn read_u32(&mut self) -> Result<u32, KeymeshError> {
        if self.remaining() < 4 {
            return Err(KeymeshError::InvalidInput(
                "unexpected end of buffer reading u32".into(),
            ));
        }
        let mut arr = [0u8; 4];
        arr.copy_from_slice(&self.buf[self.pos..self.pos + 4]);
        self.pos += 4;
        Ok(u32::from_be_bytes(arr))
    }

    pub fn read_bytes(&mut self) -> Result<Vec<u8>, KeymeshError> {
        let len = self.read_u32()? as usize;
        if len > self.remaining() {
            return Err(KeymeshError::InvalidInput(
                "declared length exceeds remaining buffer".into(),
            ));
        }
        let out = self.buf[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(out)
    }
}

/// Discriminants for recovery states on the wire. Frozen per PROTOCOL_VERSION.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireRecoveryState {
    Pending = 0x01,
    TimelockActive = 0x02,
    Completed = 0x03,
    Cancelled = 0x04,
    Expired = 0x05,
}

impl TryFrom<u8> for WireRecoveryState {
    type Error = KeymeshError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(WireRecoveryState::Pending),
            0x02 => Ok(WireRecoveryState::TimelockActive),
            0x03 => Ok(WireRecoveryState::Completed),
            0x04 => Ok(WireRecoveryState::Cancelled),
            0x05 => Ok(WireRecoveryState::Expired),
            other => Err(KeymeshError::InvalidInput(format!(
                "unknown recovery state discriminant: {other:#04x}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_scalar_types() {
        let mut enc = Encoder::new();
        enc.write_u8(0x07);
        enc.write_u64(1_700_000_000_000);
        enc.write_bytes(b"keymesh");
        let bytes = enc.into_bytes();

        let mut dec = Decoder::new(&bytes);
        assert_eq!(dec.read_u8().unwrap(), 0x07);
        assert_eq!(dec.read_u64().unwrap(), 1_700_000_000_000);
        assert_eq!(dec.read_bytes().unwrap(), b"keymesh");
        dec.finish().unwrap();
    }

    #[test]
    fn trailing_bytes_are_errors() {
        let mut enc = Encoder::new();
        enc.write_u64(1);
        enc.write_u64(2);
        let bytes = enc.into_bytes();

        let mut dec = Decoder::new(&bytes);
        assert_eq!(dec.read_u64().unwrap(), 1);
        let err = dec.finish().unwrap_err();
        assert!(matches!(err, KeymeshError::InvalidInput(_)));
    }

    #[test]
    fn oversized_length_is_rejected_not_panic() {
        // Hand-crafted hostile buffer: a u32::MAX length prefix followed by
        // far fewer bytes than declared.
        let mut hostile = Vec::new();
        hostile.extend_from_slice(&u32::MAX.to_be_bytes());
        hostile.extend_from_slice(b"tiny");

        let mut dec = Decoder::new(&hostile);
        let err = dec.read_bytes().unwrap_err();
        assert!(matches!(err, KeymeshError::InvalidInput(_)));
    }

    #[test]
    fn truncated_buffers_are_errors() {
        let mut enc = Encoder::new();
        enc.write_bytes(b"keymesh");
        let full = enc.into_bytes();

        // Cut off mid-payload; must error instead of panicking or truncating.
        let mut dec = Decoder::new(&full[..full.len() - 2]);
        assert!(dec.read_bytes().is_err());
    }

    #[test]
    fn state_discriminants_roundtrip_and_reject_unknown() {
        let mut enc = Encoder::new();
        enc.write_u8(WireRecoveryState::TimelockActive as u8);
        let bytes = enc.into_bytes();

        let mut dec = Decoder::new(&bytes);
        let state = WireRecoveryState::try_from(dec.read_u8().unwrap()).unwrap();
        assert_eq!(state, WireRecoveryState::TimelockActive);

        assert!(matches!(
            WireRecoveryState::try_from(0xFF),
            Err(KeymeshError::InvalidInput(_))
        ));
    }

    #[test]
    fn empty_payload_roundtrip() {
        let mut enc = Encoder::new();
        enc.write_bytes(b"");
        let bytes = enc.into_bytes();

        let mut dec = Decoder::new(&bytes);
        assert_eq!(dec.read_bytes().unwrap(), Vec::<u8>::new());
        dec.finish().unwrap();
    }
}
