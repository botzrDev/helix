//! Serde helper: encodes `RequestId` as a Crockford base32 ULID string (ADR-008 A.5).

use serde::{Deserialize, Deserializer, Serializer};

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Encode a `u128` as a 26-character Crockford base32 ULID.
#[must_use]
pub fn encode(mut value: u128) -> String {
    let mut buf = [0u8; 26];
    for slot in buf.iter_mut().rev() {
        *slot = ALPHABET[(value & 0x1f) as usize];
        value >>= 5;
    }
    String::from_utf8(buf.to_vec()).expect("alphabet is ASCII")
}

/// Decode a 26-character Crockford base32 ULID into a `u128`.
pub fn decode(s: &str) -> Result<u128, &'static str> {
    if s.len() != 26 {
        return Err("ULID must be exactly 26 characters");
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
            _ => return Err("malformed Crockford base32 ULID"),
        };
        value = value
            .checked_shl(5)
            .ok_or("malformed Crockford base32 ULID")?
            | u128::from(idx);
    }
    Ok(value)
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde `with` module signature
pub fn serialize<S>(value: &u128, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&encode(*value))
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<u128, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    decode(&s).map_err(serde::de::Error::custom)
}
