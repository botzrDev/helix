//! Memory / table ceilings via wasmtime [`ResourceLimiter`] (B5 / RT-6).

use wasmtime::ResourceLimiter;

/// Default table-element ceiling when the budget does not name one.
///
/// Large enough for normal components; small enough that a table bomb cannot
/// exhaust host memory before the limiter refuses growth.
pub const DEFAULT_TABLE_ELEMENTS: usize = 10_000;

/// Per-store limiter driven by `budget.memory_bytes`.
///
/// Returning `Err` from [`ResourceLimiter::memory_growing`] raises a guest trap
/// so the invoke path can map it to `Killed(Memory)` (`-32012`).
#[derive(Debug)]
pub struct HelixLimiter {
    memory_bytes: usize,
    table_elements: usize,
    peak_memory_bytes: usize,
    /// Set when growth past the memory ceiling was refused with a trap.
    memory_kill: bool,
}

impl HelixLimiter {
    /// Construct from the invocation memory ceiling (bytes).
    #[must_use]
    pub fn new(memory_bytes: u64) -> Self {
        let memory_bytes = usize::try_from(memory_bytes).unwrap_or(usize::MAX);
        Self {
            memory_bytes,
            table_elements: DEFAULT_TABLE_ELEMENTS,
            peak_memory_bytes: 0,
            memory_kill: false,
        }
    }

    /// Override the table-element ceiling (tests / future budget field).
    #[must_use]
    pub fn with_table_elements(mut self, table_elements: usize) -> Self {
        self.table_elements = table_elements;
        self
    }

    /// Peak linear-memory size observed (bytes).
    #[must_use]
    pub fn peak_memory_bytes(&self) -> usize {
        self.peak_memory_bytes
    }

    /// True after a memory-ceiling trap was requested.
    #[must_use]
    pub fn memory_kill(&self) -> bool {
        self.memory_kill
    }

    fn note_size(&mut self, size: usize) {
        self.peak_memory_bytes = self.peak_memory_bytes.max(size);
    }
}

impl ResourceLimiter for HelixLimiter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        self.note_size(current);
        if desired > self.memory_bytes {
            self.memory_kill = true;
            self.note_size(self.memory_bytes);
            return Err(anyhow::anyhow!(
                "helix memory ceiling exceeded: desired {desired} > budget {}",
                self.memory_bytes
            ));
        }
        self.note_size(desired);
        Ok(true)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        if desired > self.table_elements {
            return Err(anyhow::anyhow!(
                "helix table ceiling exceeded: desired {desired} > {}",
                self.table_elements
            ));
        }
        Ok(true)
    }
}
