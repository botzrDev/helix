//! Optional tool component + signature registry for the gateway pipeline.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use helix_caps::ToolDigest;
use helix_runtime::signature::ToolSignatureRecord;
use helix_runtime::{
    build_engine, digest_of_bytes, RuntimeConfig, RuntimeError, ToolSignatureInfo, EPOCH_TICK_MS,
};
use std::sync::atomic::AtomicBool;
use std::thread::JoinHandle;
use std::time::Duration;
use tokio::sync::Notify;
use wasmtime::component::{Component, Linker};
use wasmtime::{Engine, Store};

/// Loaded tool ready for invoke / describe.
#[derive(Clone)]
pub struct LoadedTool {
    /// Content digest.
    pub digest: ToolDigest,
    /// Parsed component.
    pub component: Component,
    /// Cached `signature` export.
    pub signature: ToolSignatureInfo,
}

/// Keeps the 1 ms epoch ticker alive for the lifetime of [`ToolRuntime`].
///
/// [`EpochTicker`]'s `JoinHandle` is `Send` but not `Sync`; wrap join in a mutex
/// so `ToolRuntime` can live behind `Arc` (gateway state).
struct EpochTickerGuard {
    stop: Arc<AtomicBool>,
    join: std::sync::Mutex<Option<JoinHandle<()>>>,
}

impl EpochTickerGuard {
    fn start(engine: Engine) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let join = std::thread::Builder::new()
            .name("helix-epoch-ticker".into())
            .spawn(move || {
                while !flag.load(Ordering::Relaxed) {
                    engine.increment_epoch();
                    std::thread::sleep(Duration::from_millis(EPOCH_TICK_MS));
                }
            })
            .expect("spawn helix-epoch-ticker");
        Self {
            stop,
            join: std::sync::Mutex::new(Some(join)),
        }
    }
}

impl Drop for EpochTickerGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Ok(mut g) = self.join.lock() {
            if let Some(j) = g.take() {
                let _ = j.join();
            }
        }
    }
}

/// Runtime handle held by the gateway: engine + tools + optional test latch.
pub struct ToolRuntime {
    engine: Engine,
    /// Advances wasmtime epoch every 1 ms (ADR-009 E.1) for preempt kills.
    _epoch_ticker: EpochTickerGuard,
    tools: RwLock<HashMap<ToolDigest, LoadedTool>>,
    /// When set, invoke waits after Granted until `notify_waiters` (GW-15).
    pub hold: Option<Arc<Notify>>,
    /// Count of successful instantiate entries (AUD-6/7).
    pub instantiate_count: AtomicU64,
}

impl ToolRuntime {
    /// Build a test/production engine under `artifact_dir`.
    ///
    /// # Errors
    ///
    /// Engine configuration failures.
    pub fn new(artifact_dir: impl Into<PathBuf>) -> Result<Self, RuntimeError> {
        let dir = artifact_dir.into();
        let cfg = RuntimeConfig::for_test(&dir);
        let engine = build_engine(&cfg)?;
        let ticker = EpochTickerGuard::start(engine.clone());
        Ok(Self {
            engine,
            _epoch_ticker: ticker,
            tools: RwLock::new(HashMap::new()),
            hold: None,
            instantiate_count: AtomicU64::new(0),
        })
    }

    /// Engine borrow.
    #[must_use]
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Register a wasm component from bytes.
    ///
    /// # Errors
    ///
    /// Parse or signature-read failures.
    pub fn register_bytes(&self, bytes: &[u8]) -> Result<ToolDigest, RuntimeError> {
        let digest = digest_of_bytes(bytes);
        let component = Component::new(&self.engine, bytes).map_err(RuntimeError::from)?;
        let signature = signature_from_component(&self.engine, &component)?;
        self.tools
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                digest,
                LoadedTool {
                    digest,
                    component,
                    signature,
                },
            );
        Ok(digest)
    }

    /// Register from filesystem path.
    ///
    /// # Errors
    ///
    /// I/O or register failures.
    pub fn register_path(&self, path: &Path) -> Result<ToolDigest, RuntimeError> {
        let bytes = std::fs::read(path).map_err(|source| RuntimeError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        self.register_bytes(&bytes)
    }

    /// Lookup by digest.
    #[must_use]
    pub fn get(&self, digest: &ToolDigest) -> Option<LoadedTool> {
        self.tools
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(digest)
            .cloned()
    }

    /// Signature only (describe).
    #[must_use]
    pub fn signature(&self, digest: &ToolDigest) -> Option<ToolSignatureInfo> {
        self.tools
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(digest)
            .map(|t| t.signature.clone())
    }

    /// Set a hold latch for concurrency tests.
    pub fn set_hold(&mut self, hold: Option<Arc<Notify>>) {
        self.hold = hold;
    }

    /// Instantiate counter (AUD-6).
    #[must_use]
    pub fn instantiate_count(&self) -> u64 {
        self.instantiate_count.load(Ordering::SeqCst)
    }

    /// Mark one instantiate (after Granted sync succeeded).
    pub fn note_instantiate(&self) {
        self.instantiate_count.fetch_add(1, Ordering::SeqCst);
    }
}

fn signature_from_component(
    engine: &Engine,
    component: &Component,
) -> Result<ToolSignatureInfo, RuntimeError> {
    let mut linker = Linker::new(engine);
    linker
        .define_unknown_imports_as_traps(component)
        .map_err(RuntimeError::from)?;
    let pre = linker
        .instantiate_pre(component)
        .map_err(RuntimeError::from)?;
    let mut store = Store::new(engine, ());
    store.set_epoch_deadline(u64::from(u32::MAX));
    let instance = pre.instantiate(&mut store).map_err(RuntimeError::from)?;
    let typed = instance
        .get_typed_func::<(), (ToolSignatureRecord,)>(&mut store, "signature")
        .map_err(RuntimeError::from)?;
    let (record,) = typed.call(&mut store, ()).map_err(RuntimeError::from)?;
    typed.post_return(&mut store).map_err(RuntimeError::from)?;
    Ok(record.into())
}
