//! ferrite-pack — the signed, verified-behavior artifact format.
//!
//! A `.fpack` is a deterministic tar containing:
//!   manifest.json   — name/version/kind/entry, capability grants, sha256 of
//!                     every payload file, and (optionally) signed eval vectors
//!   signature.json  — ed25519 signature over the exact stored manifest bytes
//!   payload/…       — the artifact itself (wasm | native | model | config)
//!
//! Trust chain: the signature covers the manifest; the manifest carries the
//! digest of every payload file — so the whole pack is transitively signed.
//! Eval vectors carried in the manifest let a device verify *behavior* after
//! apply, not just bytes: run the payload on each vector input and byte-compare
//! the output digest. Deny-by-default capability grants make that check sound —
//! a pack that requests no clock/random/net cannot act nondeterministically.

pub mod archive;
pub mod manifest;
pub mod sign;

pub use archive::{LoadedPack, build, extract, load, verify};
pub use manifest::{BridgeSpec, EvalSpec, EvalVector, FPACK_VERSION, Manifest, PayloadKind, Requires};
pub use sign::{KeyPair, SignatureBlock};

use sha2::{Digest, Sha256};

/// Lowercase hex sha256 of `bytes` — the digest used everywhere in the format.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Debug, thiserror::Error)]
pub enum PackError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("rng failure: {0}")]
    Rng(String),
    #[error("bad key or signature: {0}")]
    Crypto(String),
    #[error("digest mismatch for {path}: manifest says {expected}, file is {actual}")]
    Digest {
        path: String,
        expected: String,
        actual: String,
    },
    #[error("malformed pack: {0}")]
    Malformed(String),
}
