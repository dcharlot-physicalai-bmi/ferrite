use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const FPACK_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PayloadKind {
    /// A WebAssembly module/component run under the agent's wasmtime host.
    Wasm,
    /// A native executable (sandboxed with landlock/seccomp — v0.2).
    Native,
    /// Model weights consumed by a host engine (Ferric) — not directly runnable.
    Model,
    /// Pure configuration.
    Config,
}

/// Capability grants requested by the pack. Deny-by-default: anything not
/// listed here does not exist as far as the payload is concerned. This is what
/// makes the eval self-check *sound*: a pack that requests no clock, random,
/// or net has no source of nondeterminism inside the sandbox.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Requires {
    /// WASI grants: "clock", "random", "net", "fs:<dir>" (preopen).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wasi: Vec<String>,
    /// Typed host worlds: "ipai:nn", "robot:motor-bus", …
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caps: Vec<String>,
}

/// One verified-behavior vector: run the eval engine on `input_hex` bytes; the
/// sha256 of the produced output must equal `output_sha256`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalVector {
    pub input_hex: String,
    pub output_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalSpec {
    /// Eval engine id. v1: "wasi-cmd" — run `entry` as a WASI command with the
    /// vector input on stdin; the output is the raw stdout bytes.
    pub engine: String,
    pub vectors: Vec<EvalVector>,
}

/// Optional sim-to-real output stage. When present, the payload's stdout is a
/// JSON array of normalized actuator targets (each 0..1) and the host encodes
/// it with the named ferrite-bridge target's wire codec — so the *behavior*
/// the eval vectors digest (and the author signs) is the **exact bytes that
/// reach the motor bus**, not just the policy's text output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeSpec {
    /// ferrite-bridge target id ("feetech", "dynamixel", "arduino", …) or a
    /// bare codec id ("feetech-scs", "pwm-text", …).
    pub target: String,
    /// Bus servo IDs (feetech / dynamixel). Default: 1..=N.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<u8>>,
    /// Joint names (rosbridge). Default: "joint0".."joint{N-1}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
    /// MQTT publish topic. Default: "forge/joints".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Format version — always [`FPACK_VERSION`] for packs built by this crate.
    pub fpack: u32,
    pub name: String,
    pub version: String,
    pub kind: PayloadKind,
    /// Pack-relative path of the runnable payload, e.g. "payload/policy.wasm".
    pub entry: String,
    #[serde(default)]
    pub requires: Requires,
    /// sha256 (lowercase hex) of every payload file, keyed by pack-relative
    /// path. BTreeMap ⇒ stable serialization order ⇒ reproducible manifests.
    pub files: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eval: Option<EvalSpec>,
    /// Sim-to-real output stage — see [`BridgeSpec`]. Absent for plain packs
    /// (field is skipped, so pre-bridge manifests' canonical bytes are unchanged).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge: Option<BridgeSpec>,
}

impl Manifest {
    /// The exact bytes that get stored in the pack and signed. Stored-bytes ==
    /// signed-bytes, so verification never depends on re-serialization.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut v = serde_json::to_vec_pretty(self)?;
        v.push(b'\n');
        Ok(v)
    }
}
