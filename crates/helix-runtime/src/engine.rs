//! Wasmtime `Engine` construction (component model, epochs, pooling).

use wasmtime::{Config, Engine, InstanceAllocationStrategy, PoolingAllocationConfig};

use crate::config::RuntimeConfig;
use crate::error::RuntimeError;

/// Build an [`Engine`] with component model, epoch interruption, and pooling.
///
/// Pooling knobs:
/// - `total_component_instances` = `runtime.max_concurrent_instances`
/// - `max_memory_size` = `runtime.pool_max_memory_bytes`
///
/// `memory_reservation` is capped to `pool_max_memory_bytes` so test hosts do
/// not reserve multi-GiB slots per instance. Guard pages are disabled for the
/// same reason (production may widen later).
///
/// # Errors
///
/// Returns [`RuntimeError::Wasmtime`] when the config is rejected by wasmtime.
pub fn build_engine(cfg: &RuntimeConfig) -> Result<Engine, RuntimeError> {
    let mut config = Config::new();
    config.wasm_component_model(true);
    config.epoch_interruption(true);

    let instances = cfg.max_concurrent_instances.max(1);
    let mem = cfg.pool_max_memory_bytes.max(64 * 1024);

    let mut pool = PoolingAllocationConfig::new();
    pool.total_component_instances(instances);
    pool.max_memory_size(mem);
    // Keep related pool dimensions in sync with the component instance budget.
    pool.total_memories(instances);
    pool.total_tables(instances);
    pool.total_core_instances(instances);
    pool.total_stacks(instances);

    config.allocation_strategy(InstanceAllocationStrategy::Pooling(pool));
    config.memory_reservation(u64::try_from(mem).unwrap_or(u64::MAX));
    config.memory_guard_size(0);

    Engine::new(&config).map_err(RuntimeError::from)
}
