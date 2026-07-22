//! engine "ferric" — model payloads verified on the device's *GPU fabric*.
//!
//! The entry is not wasm: it's a JSON spec describing a Ferric compute program.
//! Eval runs on whatever fabric the device binds (Metal on a Mac, Vulkan on a
//! Jetson/PC, WebGPU in a browser) — so a passing check certifies that this
//! device's GPU reproduces the author's GPU **bit-exactly**. That is the claim
//! no other fleet platform can make, and it rests on Ferric's cross-fabric
//! deterministic kernel path.
//!
//! Ops:
//! - `matmul-chain` — input is an f32-LE `m×dims[0]` matrix; it flows through
//!   `dims.len()-1` fixed pseudo-random weight matmuls on the GPU. Weights come
//!   from an integer xorshift + bitcast (NO libm anywhere), so the program is
//!   bit-identical by construction everywhere; the matmul kernel is Ferric's
//!   proven bit-identical cross-fabric path. Output: final matrix, f32-LE.
//! - `demo-lm` — input is u32-LE token ids for Ferric's deterministic 3-layer
//!   Llama-style demo LM; output is the full logits (f32-LE) ++ `steps` greedy
//!   tokens (u32-LE). RoPE/sigmoid use GPU `sin`/`exp`, whose precision is
//!   implementation-defined across fabrics — this op *probes* how far
//!   bit-identity extends rather than assuming it.

use crate::RuntimeError;
use ferric_pack_serde::Spec;
use ferric_core::{Context, demo};

/// The parsed entry file (payload/model.json).
mod ferric_pack_serde {
    #[derive(serde::Deserialize)]
    pub struct Spec {
        pub op: String,
        /// matmul-chain: rows of the input matrix.
        #[serde(default)]
        pub m: usize,
        /// matmul-chain: layer widths, e.g. [64, 64, 64, 32].
        #[serde(default)]
        pub dims: Vec<usize>,
        /// matmul-chain: weight seed.
        #[serde(default)]
        pub seed: u64,
        /// demo-lm: greedy generation steps after the logits pass.
        #[serde(default)]
        pub steps: usize,
    }
}

pub fn run(spec_bytes: &[u8], input: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    let spec: Spec =
        serde_json::from_slice(spec_bytes).map_err(|e| RuntimeError::Host(format!("spec: {e}")))?;
    let ctx = pollster::block_on(Context::new()).map_err(RuntimeError::Host)?;
    match spec.op.as_str() {
        "matmul-chain" => matmul_chain(&ctx, &spec, input),
        "demo-lm" => demo_lm(&ctx, &spec, input),
        other => Err(RuntimeError::Host(format!("unknown ferric op {other:?}"))),
    }
}

/// Which fabric this device would run packs on — for reports/telemetry.
pub fn fabric() -> String {
    match pollster::block_on(Context::new()) {
        Ok(ctx) => format!("{:?} ({})", ctx.backend, ctx.adapter_name),
        Err(e) => format!("unavailable: {e}"),
    }
}

/// Deterministic pseudo-random weights with NO floating-point math in the
/// generator: xorshift64* → top 23 bits into an f32 mantissa in [1,2) → −1.5
/// ⇒ exact same bit patterns in [−0.5, 0.5) on every platform, every libm.
fn det_weights(n: usize, seed: u64) -> Vec<f32> {
    let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..n)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            f32::from_bits(0x3F80_0000 | (s >> 41) as u32) - 1.5
        })
        .collect()
}

fn matmul_chain(ctx: &Context, spec: &Spec, input: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    if spec.dims.len() < 2 || spec.m == 0 {
        return Err(RuntimeError::Host("matmul-chain needs m and ≥2 dims".into()));
    }
    let want = spec.m * spec.dims[0] * 4;
    if input.len() != want {
        return Err(RuntimeError::Host(format!(
            "input must be {want} bytes (m×dims[0] f32-LE), got {}",
            input.len()
        )));
    }
    let mut x: Vec<f32> = input
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes(c.try_into().unwrap()))
        .collect();
    for (i, pair) in spec.dims.windows(2).enumerate() {
        let (k, n) = (pair[0], pair[1]);
        let w = det_weights(k * n, spec.seed.wrapping_add(i as u64 + 1));
        x = pollster::block_on(ctx.matmul(&x, &w, spec.m as u32, k as u32, n as u32))
            .map_err(RuntimeError::Host)?;
    }
    Ok(x.iter().flat_map(|v| v.to_le_bytes()).collect())
}

fn demo_lm(ctx: &Context, spec: &Spec, input: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    if input.is_empty() || input.len() % 4 != 0 {
        return Err(RuntimeError::Host("input must be u32-LE token ids".into()));
    }
    let ids: Vec<u32> = input
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()) % demo::VOCAB as u32)
        .collect();
    let logits = pollster::block_on(demo::logits(ctx, &ids)).map_err(RuntimeError::Host)?;
    let toks = pollster::block_on(demo::generate(ctx, &ids, spec.steps)).map_err(RuntimeError::Host)?;
    let mut out: Vec<u8> = logits.iter().flat_map(|v| v.to_le_bytes()).collect();
    out.extend(toks.iter().flat_map(|t| t.to_le_bytes()));
    Ok(out)
}
