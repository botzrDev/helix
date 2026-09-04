//! Fail-closed audit paths (ADR-008 D.3 / HLX-23).
//!
//! Writer IO failures surface as typed [`crate::AuditError`]. After
//! `audit.max_consecutive_errors` (default 3) consecutive failures the writer
//! signals fatal via [`FatalHook`] and stops. Health is `ok | degraded | failed`
//! for `helix.health` (`gateway.health_detail = full`).
//!
//! Gateway JSON-RPC `-32030` wiring is **M5-05 / HLX-36**; this crate exposes
//! [`crate::AuditError::GATEWAY_CODE`] (`-32030`) for that map.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

/// Health string for `helix.health` `audit` field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditHealth {
    Ok,
    Degraded,
    Failed,
}

impl AuditHealth {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Degraded => "degraded",
            Self::Failed => "failed",
        }
    }

    pub(crate) fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Degraded,
            2 => Self::Failed,
            _ => Self::Ok,
        }
    }

    pub(crate) const fn to_u8(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::Degraded => 1,
            Self::Failed => 2,
        }
    }
}

impl std::fmt::Display for AuditHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Called when consecutive writer failures reach `max_consecutive_errors`.
///
/// Production installs [`ProcessExitFatal`]. Tests install [`RecordingFatal`] so
/// the harness is not killed (`std::process::exit` would tear down the test
/// process).
pub trait FatalHook: Send + Sync + 'static {
    fn on_fatal(&self, err: &crate::AuditError);
}

/// Default production fatal hook: `std::process::exit(78)`.
///
/// Exit code 78 ("configuration error" / `EX_CONFIG` style) marks audit fatality;
/// the process must not keep serving without a durable audit log.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcessExitFatal;

impl FatalHook for ProcessExitFatal {
    fn on_fatal(&self, _err: &crate::AuditError) {
        // A gateway that cannot record is not a gateway (ADR-008 D.3).
        std::process::exit(78);
    }
}

/// Test double: records that fatal was signaled without exiting.
#[derive(Debug, Default)]
pub struct RecordingFatal {
    fired: AtomicBool,
}

impl RecordingFatal {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    #[must_use]
    pub fn fired(&self) -> bool {
        self.fired.load(Ordering::SeqCst)
    }
}

impl FatalHook for RecordingFatal {
    fn on_fatal(&self, _err: &crate::AuditError) {
        self.fired.store(true, Ordering::SeqCst);
    }
}

impl FatalHook for Arc<RecordingFatal> {
    fn on_fatal(&self, err: &crate::AuditError) {
        (**self).on_fatal(err);
    }
}

/// Injectable IO fault points for AUD-6 / AUD-7 (full-disk / unwritable rotate).
pub trait IoFault: Send + Sync + 'static {
    /// Checked immediately before `write_all` of a framed batch.
    fn before_write(&self) -> Result<(), io::Error> {
        Ok(())
    }

    /// Checked immediately before `sync_data` / fdatasync.
    fn before_sync(&self) -> Result<(), io::Error> {
        Ok(())
    }

    /// Checked immediately before opening the next rotated log file.
    fn before_rotate_open(&self) -> Result<(), io::Error> {
        Ok(())
    }
}

/// No-op fault injector (production default).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopIoFault;

impl IoFault for NoopIoFault {}

/// Which IO site an [`InjectedIoFault`] trips.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultSite {
    Write,
    Sync,
    RotateOpen,
}

/// Test double: returns a cloned `io::Error` at a chosen site, optionally for a
/// limited number of hits (`None` = always).
#[derive(Debug)]
pub struct InjectedIoFault {
    site: FaultSite,
    /// Remaining failures; `u32::MAX` means unlimited.
    remaining: AtomicU32,
    /// Raw OS error to synthesize (e.g. 28 = ENOSPC on Linux).
    raw_os: i32,
}

impl InjectedIoFault {
    /// Always fail at `site` with `raw_os` (e.g. `28` ENOSPC, `5` EIO, `13` EACCES).
    #[must_use]
    pub fn always(site: FaultSite, raw_os: i32) -> Arc<Self> {
        Arc::new(Self {
            site,
            remaining: AtomicU32::new(u32::MAX),
            raw_os,
        })
    }

    /// Fail the next `count` attempts at `site`, then succeed.
    #[must_use]
    pub fn times(site: FaultSite, raw_os: i32, count: u32) -> Arc<Self> {
        Arc::new(Self {
            site,
            remaining: AtomicU32::new(count),
            raw_os,
        })
    }

    fn trip(&self) -> Result<(), io::Error> {
        let prev = self.remaining.load(Ordering::SeqCst);
        if prev == 0 {
            return Ok(());
        }
        if prev != u32::MAX {
            self.remaining.fetch_sub(1, Ordering::SeqCst);
        }
        Err(io::Error::from_raw_os_error(self.raw_os))
    }
}

impl IoFault for InjectedIoFault {
    fn before_write(&self) -> Result<(), io::Error> {
        if self.site == FaultSite::Write {
            self.trip()
        } else {
            Ok(())
        }
    }

    fn before_sync(&self) -> Result<(), io::Error> {
        if self.site == FaultSite::Sync {
            self.trip()
        } else {
            Ok(())
        }
    }

    fn before_rotate_open(&self) -> Result<(), io::Error> {
        if self.site == FaultSite::RotateOpen {
            self.trip()
        } else {
            Ok(())
        }
    }
}

impl IoFault for Arc<InjectedIoFault> {
    fn before_write(&self) -> Result<(), io::Error> {
        (**self).before_write()
    }

    fn before_sync(&self) -> Result<(), io::Error> {
        (**self).before_sync()
    }

    fn before_rotate_open(&self) -> Result<(), io::Error> {
        (**self).before_rotate_open()
    }
}

/// Fail-closed knobs for the writer task (`audit.max_consecutive_errors`, hooks).
#[derive(Clone)]
pub struct FailClosedConfig {
    /// After this many consecutive writer failures, invoke [`FatalHook`] (default 3).
    pub max_consecutive_errors: u32,
    pub fatal: Arc<dyn FatalHook>,
    pub fault: Arc<dyn IoFault>,
}

impl std::fmt::Debug for FailClosedConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FailClosedConfig")
            .field("max_consecutive_errors", &self.max_consecutive_errors)
            .finish_non_exhaustive()
    }
}

impl Default for FailClosedConfig {
    fn default() -> Self {
        Self {
            max_consecutive_errors: 3,
            fatal: Arc::new(ProcessExitFatal),
            fault: Arc::new(NoopIoFault),
        }
    }
}

impl FailClosedConfig {
    /// Test-friendly config: recording fatal hook (no process exit) + custom fault.
    #[must_use]
    pub fn for_test(fault: Arc<dyn IoFault>, fatal: Arc<RecordingFatal>) -> Self {
        Self {
            max_consecutive_errors: 3,
            fatal,
            fault,
        }
    }

    #[must_use]
    pub fn with_max_consecutive_errors(mut self, n: u32) -> Self {
        self.max_consecutive_errors = n.max(1);
        self
    }
}
