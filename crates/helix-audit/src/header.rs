//! Audit log file header (ADR-009 D.1).

use crate::tags::{header_key, HEADER_VERSION};
use minicbor::{Decoder, Encoder};
use thiserror::Error;

/// Log file header. Integer keys are provisional (see `tags::header_key`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileHeader {
    pub version: u8,
    pub file_ulid: [u8; 16],
    pub gateway_id: String,
    pub prev_hash: [u8; 32],
}

impl FileHeader {
    #[must_use]
    pub fn new(file_ulid: [u8; 16], gateway_id: impl Into<String>, prev_hash: [u8; 32]) -> Self {
        Self {
            version: HEADER_VERSION,
            file_ulid,
            gateway_id: gateway_id.into(),
            prev_hash,
        }
    }

    pub fn encode_cbor(&self) -> Result<Vec<u8>, HeaderError> {
        let mut e = Encoder::new(Vec::with_capacity(64));
        e.map(4).map_err(|e| enc(&e))?;
        e.u8(header_key::VERSION)
            .map_err(|e| enc(&e))?
            .u8(self.version)
            .map_err(|e| enc(&e))?;
        e.u8(header_key::FILE_ULID)
            .map_err(|e| enc(&e))?
            .bytes(&self.file_ulid)
            .map_err(|e| enc(&e))?;
        e.u8(header_key::GATEWAY_ID)
            .map_err(|e| enc(&e))?
            .str(&self.gateway_id)
            .map_err(|e| enc(&e))?;
        e.u8(header_key::PREV_HASH)
            .map_err(|e| enc(&e))?
            .bytes(&self.prev_hash)
            .map_err(|e| enc(&e))?;
        Ok(e.into_writer())
    }

    pub fn decode_cbor(bytes: &[u8]) -> Result<(Self, usize), HeaderError> {
        let mut d = Decoder::new(bytes);
        let len = d.map()?.ok_or(HeaderError::IndefiniteMap)?;
        let mut version: Option<u8> = None;
        let mut file_ulid: Option<[u8; 16]> = None;
        let mut gateway_id: Option<String> = None;
        let mut prev_hash: Option<[u8; 32]> = None;

        for _ in 0..len {
            let key = d.u8()?;
            match key {
                header_key::VERSION => version = Some(d.u8()?),
                header_key::FILE_ULID => {
                    let b = d.bytes()?;
                    if b.len() != 16 {
                        return Err(HeaderError::BadBytesLen {
                            expected: 16,
                            got: b.len(),
                        });
                    }
                    let mut a = [0u8; 16];
                    a.copy_from_slice(b);
                    file_ulid = Some(a);
                }
                header_key::GATEWAY_ID => gateway_id = Some(d.str()?.to_owned()),
                header_key::PREV_HASH => {
                    let b = d.bytes()?;
                    if b.len() != 32 {
                        return Err(HeaderError::BadBytesLen {
                            expected: 32,
                            got: b.len(),
                        });
                    }
                    let mut a = [0u8; 32];
                    a.copy_from_slice(b);
                    prev_hash = Some(a);
                }
                _ => d.skip()?,
            }
        }

        let version = version.ok_or(HeaderError::MissingField("version"))?;
        if version > HEADER_VERSION {
            return Err(HeaderError::UnsupportedVersion(version));
        }
        let header = Self {
            version,
            file_ulid: file_ulid.ok_or(HeaderError::MissingField("file_ulid"))?,
            gateway_id: gateway_id.ok_or(HeaderError::MissingField("gateway_id"))?,
            prev_hash: prev_hash.ok_or(HeaderError::MissingField("prev_hash"))?,
        };
        Ok((header, d.position()))
    }
}

fn enc(e: &minicbor::encode::Error<core::convert::Infallible>) -> HeaderError {
    HeaderError::Encode(e.to_string())
}

#[derive(Debug, Error)]
pub enum HeaderError {
    #[error("cbor decode: {0}")]
    Decode(String),
    #[error("cbor encode: {0}")]
    Encode(String),
    #[error("missing field {0}")]
    MissingField(&'static str),
    #[error("unsupported header version {0}")]
    UnsupportedVersion(u8),
    #[error("indefinite-length map rejected")]
    IndefiniteMap,
    #[error("bytes length {got}, expected {expected}")]
    BadBytesLen { expected: usize, got: usize },
}

impl From<minicbor::decode::Error> for HeaderError {
    fn from(e: minicbor::decode::Error) -> Self {
        Self::Decode(e.to_string())
    }
}
