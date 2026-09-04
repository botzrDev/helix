//! Output-bounded writer on the result channel (S4 / RT-7 / A7).

/// Writes guest result bytes up to `limit`; exceeding the limit yields
/// [`BoundedWriterError::Exceeded`] and **no** partial bytes for the caller.
#[derive(Debug)]
pub struct BoundedWriter {
    limit: usize,
    buf: Vec<u8>,
    exceeded: bool,
}

/// Error from [`BoundedWriter::write`] / [`BoundedWriter::finish`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundedWriterError {
    /// `output_bytes` ceiling would be exceeded; caller must discard output.
    Exceeded,
}

impl BoundedWriter {
    /// Create a writer that accepts at most `limit` bytes total.
    #[must_use]
    pub fn new(limit: u32) -> Self {
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        Self {
            limit,
            buf: Vec::new(),
            exceeded: false,
        }
    }

    /// Append `data`. On overflow sets the exceeded flag and returns [`BoundedWriterError::Exceeded`].
    ///
    /// # Errors
    ///
    /// [`BoundedWriterError::Exceeded`] when `written + data.len() > limit`.
    pub fn write(&mut self, data: &[u8]) -> Result<(), BoundedWriterError> {
        if self.exceeded {
            return Err(BoundedWriterError::Exceeded);
        }
        let new_len = self.buf.len().saturating_add(data.len());
        if new_len > self.limit {
            self.exceeded = true;
            self.buf.clear();
            return Err(BoundedWriterError::Exceeded);
        }
        self.buf.extend_from_slice(data);
        Ok(())
    }

    /// Bytes accepted so far (zero after an exceed).
    #[must_use]
    pub fn written(&self) -> usize {
        self.buf.len()
    }

    /// Whether the ceiling was hit.
    #[must_use]
    pub fn exceeded(&self) -> bool {
        self.exceeded
    }

    /// Finish: `Ok(bytes)` within limit, or `Err` with **no** partial output (S4).
    ///
    /// # Errors
    ///
    /// [`BoundedWriterError::Exceeded`] when the ceiling was crossed earlier.
    pub fn finish(self) -> Result<Vec<u8>, BoundedWriterError> {
        if self.exceeded {
            Err(BoundedWriterError::Exceeded)
        } else {
            Ok(self.buf)
        }
    }

    /// Bound an already-materialized guest result in one shot (typical `invoke` path).
    ///
    /// # Errors
    ///
    /// [`BoundedWriterError::Exceeded`] when `bytes.len() > limit`.
    pub fn bound(bytes: Vec<u8>, limit: u32) -> Result<Vec<u8>, BoundedWriterError> {
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        if bytes.len() > limit {
            Err(BoundedWriterError::Exceeded)
        } else {
            Ok(bytes)
        }
    }
}
