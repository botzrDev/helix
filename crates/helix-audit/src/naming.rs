//! Log file naming: `helix-<start-ulid>.log` and caps side-file paths.

use crate::frame::HASH_LEN;

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Encode 16 raw ULID bytes as a 26-character Crockford base32 string.
#[must_use]
pub fn encode_ulid_bytes(bytes: &[u8; 16]) -> String {
    let mut value = 0u128;
    for b in bytes {
        value = (value << 8) | u128::from(*b);
    }
    let mut buf = [0u8; 26];
    for slot in buf.iter_mut().rev() {
        *slot = CROCKFORD[(value & 0x1f) as usize];
        value >>= 5;
    }
    // SAFETY: alphabet is ASCII.
    String::from_utf8(buf.to_vec()).expect("alphabet is ASCII")
}

/// Decode a 26-character Crockford base32 ULID into 16 bytes.
pub fn decode_ulid_str(s: &str) -> Result<[u8; 16], NamingError> {
    if s.len() != 26 {
        return Err(NamingError::BadUlidLen(s.len()));
    }
    let mut value: u128 = 0;
    for b in s.bytes() {
        let u = b.to_ascii_uppercase();
        let idx = match u {
            b'0'..=b'9' => u - b'0',
            b'A'..=b'H' => u - b'A' + 10,
            b'J' => 18,
            b'K' => 19,
            b'M' => 20,
            b'N' => 21,
            b'P' => 22,
            b'Q' => 23,
            b'R' => 24,
            b'S' => 25,
            b'T' => 26,
            b'V' => 27,
            b'W' => 28,
            b'X' => 29,
            b'Y' => 30,
            b'Z' => 31,
            _ => return Err(NamingError::BadUlidChar),
        };
        value = value.checked_shl(5).ok_or(NamingError::BadUlidChar)? | u128::from(idx);
    }
    let mut out = [0u8; 16];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = ((value >> (8 * (15 - i))) & 0xff) as u8;
    }
    Ok(out)
}

/// Hex-encode bytes (lowercase).
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

/// Hex-decode into a fixed array.
pub fn hex_decode_32(s: &str) -> Result<[u8; HASH_LEN], NamingError> {
    if s.len() != HASH_LEN * 2 {
        return Err(NamingError::BadHexLen(s.len()));
    }
    let mut out = [0u8; HASH_LEN];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, NamingError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(NamingError::BadHexChar),
    }
}

/// `helix-<ulid>.log` filename for a file ULID.
#[must_use]
pub fn log_file_name(file_ulid: &[u8; 16]) -> String {
    format!("helix-{}.log", encode_ulid_bytes(file_ulid))
}

/// Relative caps side-file path: `caps/<hex>.cbor`.
#[must_use]
pub fn caps_rel_path(caps_hash: &[u8; HASH_LEN]) -> String {
    format!("caps/{}.cbor", hex_encode(caps_hash))
}

/// Parse `helix-<ulid>.log` → ULID bytes. Returns `None` if not a log name.
#[must_use]
pub fn parse_log_file_name(name: &str) -> Option<[u8; 16]> {
    let rest = name.strip_prefix("helix-")?.strip_suffix(".log")?;
    decode_ulid_str(rest).ok()
}

#[derive(Debug, thiserror::Error)]
pub enum NamingError {
    #[error("ULID string length {0}, expected 26")]
    BadUlidLen(usize),
    #[error("malformed Crockford base32 ULID")]
    BadUlidChar,
    #[error("hex length {0}, expected 64")]
    BadHexLen(usize),
    #[error("malformed hex")]
    BadHexChar,
}
