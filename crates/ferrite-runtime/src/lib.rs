//! ferrite-runtime — sandboxed execution of pack payloads + the verified-behavior check.
//!
//! v0.1 engine: `wasi-cmd`. The entry is a wasm32-wasip1 command module run under
//! wasmtime with a deny-by-default WASI context: stdin/stdout are in-memory
//! pipes, there are **no preopens, no net, no args, no env**, and — unless the
//! manifest grants them — the clock is frozen and the RNG is a fixed seed.
//! That makes the sandbox itself deterministic, which is what turns the eval
//! vectors from a smoke test into a *behavioral signature*: same pack, same
//! input, same bytes out — on any device, any fabric.

use ferrite_pack::{EvalVector, Manifest, Requires, sha256_hex};
pub use wasmtime::Engine;
use wasmtime::{Config, Linker, Module, Store};

#[cfg(feature = "ferric")]
pub mod ferric_engine;
pub mod native;
use wasmtime_wasi::p1::WasiP1Ctx;
use wasmtime_wasi::p2::pipe::{MemoryInputPipe, MemoryOutputPipe};
use wasmtime_wasi::{WasiCtxBuilder, clocks::{HostMonotonicClock, HostWallClock}};

/// Fuel budget for one eval-vector run. Generous for policies (billions of
/// instructions) while still bounding a runaway loop.
pub const EVAL_FUEL: u64 = 5_000_000_000;
/// Cap on captured stdout/stderr per run.
const MAX_OUT: usize = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("wasm: {0}")]
    Wasm(String),
    #[error("payload exited with code {0}")]
    Exit(i32),
    #[error("unsupported eval engine {0:?}")]
    Engine(String),
    #[error("host engine: {0}")]
    Host(String),
    #[error("bad vector input hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("bridge: {0}")]
    Bridge(String),
}

pub struct Output {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub fuel_used: u64,
}

/// A frozen wall/monotonic clock — time exists but never advances.
struct FrozenClock;
impl HostMonotonicClock for FrozenClock {
    fn resolution(&self) -> u64 {
        1
    }
    fn now(&self) -> u64 {
        0
    }
}
impl HostWallClock for FrozenClock {
    fn resolution(&self) -> std::time::Duration {
        std::time::Duration::from_nanos(1)
    }
    fn now(&self) -> std::time::Duration {
        std::time::Duration::ZERO
    }
}

/// Build the engine used for pack execution. `Engine` is cheaply cloneable
/// (Arc): keep a clone and call [`interrupt`] to stop a run from outside.
pub fn make_engine() -> Result<Engine, RuntimeError> {
    let mut config = Config::new();
    config.consume_fuel(true);
    config.epoch_interruption(true);
    Engine::new(&config).map_err(wasm_err)
}

/// Trap any execution currently running on this engine (its stores sit at
/// epoch deadline 1; bumping the epoch fires the trap).
pub fn interrupt(engine: &Engine) {
    engine.increment_epoch();
}

/// Run `wasm` as a WASI command with `input` on stdin, honoring the pack's
/// capability grants. Everything not granted does not exist.
pub fn run_wasi_cmd(
    wasm: &[u8],
    input: &[u8],
    grants: &Requires,
    fuel: u64,
) -> Result<Output, RuntimeError> {
    let engine = make_engine()?;
    run_wasi_cmd_on(&engine, wasm, input, grants, fuel)
}

/// [`run_wasi_cmd`] on a caller-owned engine, so the caller can [`interrupt`].
pub fn run_wasi_cmd_on(
    engine: &Engine,
    wasm: &[u8],
    input: &[u8],
    grants: &Requires,
    fuel: u64,
) -> Result<Output, RuntimeError> {
    let module = Module::new(engine, wasm).map_err(wasm_err)?;

    let stdout = MemoryOutputPipe::new(MAX_OUT);
    let stderr = MemoryOutputPipe::new(MAX_OUT);
    let mut builder = WasiCtxBuilder::new();
    builder
        .stdin(MemoryInputPipe::new(input.to_vec()))
        .stdout(stdout.clone())
        .stderr(stderr.clone());
    let has = |k: &str| grants.wasi.iter().any(|g| g == k);
    if !has("clock") {
        builder.monotonic_clock(FrozenClock).wall_clock(FrozenClock);
    }
    if !has("random") {
        // Deterministic RNG: random_get still works (Rust HashMaps boot fine)
        // but produces the same stream on every device.
        builder.insecure_random_seed(0xF3441723_00000001);
        builder.allow_blocking_current_thread(true);
    }
    if has("net") {
        builder.inherit_network().allow_ip_name_lookup(true);
    }
    for g in &grants.wasi {
        if let Some(dir) = g.strip_prefix("fs:") {
            builder
                .preopened_dir(
                    dir,
                    dir,
                    wasmtime_wasi::DirPerms::all(),
                    wasmtime_wasi::FilePerms::all(),
                )
                .map_err(wasm_err)?;
        }
    }
    let wasi: WasiP1Ctx = builder.build_p1();

    let mut linker: Linker<WasiP1Ctx> = Linker::new(engine);
    wasmtime_wasi::p1::add_to_linker_sync(&mut linker, |t| t).map_err(wasm_err)?;
    let mut store = Store::new(engine, wasi);
    store.set_fuel(fuel).map_err(wasm_err)?;
    // Sit at epoch deadline 1: a single increment_epoch() from outside traps us.
    store.set_epoch_deadline(1);

    let instance = linker.instantiate(&mut store, &module).map_err(wasm_err)?;
    let start = instance
        .get_typed_func::<(), ()>(&mut store, "_start")
        .map_err(wasm_err)?;
    match start.call(&mut store, ()) {
        Ok(()) => {}
        Err(trap) => match trap.downcast_ref::<wasmtime_wasi::I32Exit>() {
            Some(exit) if exit.0 == 0 => {}
            Some(exit) => return Err(RuntimeError::Exit(exit.0)),
            None => return Err(RuntimeError::Wasm(format!("{trap:#}"))),
        },
    }
    let fuel_used = fuel.saturating_sub(store.get_fuel().unwrap_or(0));
    Ok(Output {
        stdout: stdout.contents().to_vec(),
        stderr: stderr.contents().to_vec(),
        fuel_used,
    })
}

/// Per-vector verdict from a verified-behavior check.
pub struct VectorResult {
    pub pass: bool,
    pub expected_sha256: String,
    pub actual_sha256: String,
    pub fuel_used: u64,
}

/// One engine invocation: `entry` + vector input → output bytes (+ fuel where
/// the engine meters it). Both `record_eval` and `check_eval` go through here,
/// so the author's recording and the device's re-check can never diverge.
pub fn engine_output(
    engine: &str,
    entry: &[u8],
    input: &[u8],
    grants: &Requires,
) -> Result<(Vec<u8>, u64), RuntimeError> {
    match engine {
        "wasi-cmd" => {
            let out = run_wasi_cmd(entry, input, grants, EVAL_FUEL)?;
            Ok((out.stdout, out.fuel_used))
        }
        #[cfg(feature = "ferric")]
        "ferric" => Ok((ferric_engine::run(entry, input)?, 0)),
        "native" => {
            let out = native::run_native(entry, input, grants, native::DEFAULT_CPU_SECS)?;
            Ok((out.stdout, out.fuel_used))
        }
        other => Err(RuntimeError::Engine(other.to_string())),
    }
}

/// Apply a manifest's sim-to-real bridge stage: the payload's stdout is a JSON
/// array of normalized actuator targets (each 0..1); encode it into the named
/// bridge target's wire bytes. Those bytes ARE the pack's behavior — what the
/// eval vectors digest, what the author signs, and what the bus will carry.
pub fn bridge_encode(spec: &ferrite_pack::BridgeSpec, stdout: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    let targets: Vec<f64> = serde_json::from_slice(stdout)
        .map_err(|e| RuntimeError::Bridge(format!("payload stdout is not a JSON number array: {e}")))?;
    if targets.iter().any(|t| !t.is_finite()) {
        return Err(RuntimeError::Bridge("non-finite target".into()));
    }
    // A target id ("feetech") resolves through the registry to its codec; a bare
    // codec id ("feetech-scs") is accepted directly.
    let codec_id = match ferrite_bridge::target(&spec.target) {
        Some(t) => t.codec,
        None => &spec.target,
    };
    let codec = ferrite_bridge::codec(codec_id)
        .ok_or_else(|| RuntimeError::Bridge(format!("unknown bridge target/codec {:?}", spec.target)))?;
    let mut cmd = ferrite_bridge::Cmd::new(targets);
    cmd.ids = spec.ids.clone();
    cmd.names = spec.names.clone();
    cmd.topic = spec.topic.clone();
    Ok((codec.encode)(&cmd))
}

/// Engine output with the manifest's optional bridge stage applied — the
/// "behavior bytes" a vector digests.
fn behavior_output(
    engine: &str,
    entry: &[u8],
    input: &[u8],
    grants: &Requires,
    bridge: Option<&ferrite_pack::BridgeSpec>,
) -> Result<(Vec<u8>, u64), RuntimeError> {
    let (out, fuel) = engine_output(engine, entry, input, grants)?;
    match bridge {
        Some(spec) => Ok((bridge_encode(spec, &out)?, fuel)),
        None => Ok((out, fuel)),
    }
}

/// Run every eval vector in `manifest` against `entry` and byte-compare
/// output digests. This is the device-side post-apply self-check *and* the
/// author-side pre-ship check — the same code, which is the point.
pub fn check_eval(manifest: &Manifest, entry: &[u8]) -> Result<Vec<VectorResult>, RuntimeError> {
    let Some(eval) = &manifest.eval else {
        return Ok(Vec::new());
    };
    let mut results = Vec::with_capacity(eval.vectors.len());
    for v in &eval.vectors {
        let input = hex::decode(&v.input_hex)?;
        let (out, fuel_used) =
            behavior_output(&eval.engine, entry, &input, &manifest.requires, manifest.bridge.as_ref())?;
        let actual = sha256_hex(&out);
        results.push(VectorResult {
            pass: actual == v.output_sha256,
            expected_sha256: v.output_sha256.clone(),
            actual_sha256: actual,
            fuel_used,
        });
    }
    Ok(results)
}

/// Author-side: run `entry` on each input and *record* the output digests
/// as eval vectors to be signed into the manifest. `bridge` must match what
/// the manifest will declare, so recorded digests cover the wire bytes.
pub fn record_eval(
    engine: &str,
    entry: &[u8],
    inputs: &[Vec<u8>],
    grants: &Requires,
    bridge: Option<&ferrite_pack::BridgeSpec>,
) -> Result<Vec<EvalVector>, RuntimeError> {
    let mut vectors = Vec::with_capacity(inputs.len());
    for input in inputs {
        let (out, _) = behavior_output(engine, entry, input, grants, bridge)?;
        vectors.push(EvalVector {
            input_hex: hex::encode(input),
            output_sha256: sha256_hex(&out),
        });
    }
    Ok(vectors)
}

fn wasm_err(e: wasmtime::Error) -> RuntimeError {
    RuntimeError::Wasm(format!("{e:#}"))
}
