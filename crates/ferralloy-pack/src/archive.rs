use crate::manifest::Manifest;
use crate::sign::{KeyPair, SignatureBlock};
use crate::{PackError, sha256_hex};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

const MANIFEST_NAME: &str = "manifest.json";
const SIGNATURE_NAME: &str = "signature.json";
const PAYLOAD_PREFIX: &str = "payload/";

/// A `.fpack` read fully into memory (v0.1 packs are policy/model-sized — MBs).
pub struct LoadedPack {
    pub manifest: Manifest,
    /// The exact stored manifest bytes — what the signature covers.
    pub manifest_bytes: Vec<u8>,
    pub signature: SignatureBlock,
    /// Payload files keyed by pack-relative path ("payload/…").
    pub files: BTreeMap<String, Vec<u8>>,
}

/// Assemble and sign a `.fpack`.
///
/// Walks `payload_root` recursively; every file lands in the pack under
/// `payload/<relative-path>` and its sha256 is recorded in the manifest.
/// The manifest is then serialized once, signed over those exact bytes, and
/// both are written into a *deterministic* tar (sorted entries, zeroed
/// mtime/uid/gid, fixed modes) — same input ⇒ bit-identical `.fpack`.
pub fn build(
    payload_root: &Path,
    mut manifest: Manifest,
    key: &KeyPair,
    out: &Path,
) -> Result<(), PackError> {
    let mut rel_paths = Vec::new();
    walk(payload_root, PathBuf::new(), &mut rel_paths)?;
    rel_paths.sort();
    if rel_paths.is_empty() {
        return Err(PackError::Malformed("payload directory is empty".into()));
    }

    manifest.files.clear();
    let mut contents: Vec<(String, Vec<u8>)> = Vec::with_capacity(rel_paths.len());
    for rel in &rel_paths {
        let bytes = fs::read(payload_root.join(rel))?;
        let pack_path = format!("{PAYLOAD_PREFIX}{}", rel.to_string_lossy().replace('\\', "/"));
        manifest.files.insert(pack_path.clone(), sha256_hex(&bytes));
        contents.push((pack_path, bytes));
    }
    if !manifest.files.contains_key(&manifest.entry) {
        return Err(PackError::Malformed(format!(
            "entry {:?} is not among the payload files",
            manifest.entry
        )));
    }

    let manifest_bytes = manifest.to_canonical_bytes()?;
    let sig = key.sign(&manifest_bytes);
    let sig_bytes = {
        let mut v = serde_json::to_vec_pretty(&sig)?;
        v.push(b'\n');
        v
    };

    let file = fs::File::create(out)?;
    let mut tar = tar::Builder::new(file);
    append(&mut tar, MANIFEST_NAME, &manifest_bytes)?;
    append(&mut tar, SIGNATURE_NAME, &sig_bytes)?;
    for (path, bytes) in &contents {
        append(&mut tar, path, bytes)?;
    }
    tar.into_inner()?.sync_all()?;
    Ok(())
}

/// Read a `.fpack` into memory. Rejects path traversal (zip-slip), absolute
/// paths, and anything outside the fixed layout — this runs on devices.
pub fn load(path: &Path) -> Result<LoadedPack, PackError> {
    let file = fs::File::open(path)?;
    let mut ar = tar::Archive::new(file);
    let mut manifest_bytes = None;
    let mut sig_bytes = None;
    let mut files = BTreeMap::new();

    for entry in ar.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let name = entry
            .path()
            .map_err(|e| PackError::Malformed(e.to_string()))?
            .to_string_lossy()
            .into_owned();
        if name.split('/').any(|c| c == ".." || c.is_empty()) || name.starts_with('/') {
            return Err(PackError::Malformed(format!("illegal path {name:?}")));
        }
        let mut bytes = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut bytes)?;
        match name.as_str() {
            MANIFEST_NAME => manifest_bytes = Some(bytes),
            SIGNATURE_NAME => sig_bytes = Some(bytes),
            _ if name.starts_with(PAYLOAD_PREFIX) => {
                files.insert(name, bytes);
            }
            _ => return Err(PackError::Malformed(format!("unexpected member {name:?}"))),
        }
    }

    let manifest_bytes = manifest_bytes.ok_or_else(|| PackError::Malformed("no manifest.json".into()))?;
    let sig_bytes = sig_bytes.ok_or_else(|| PackError::Malformed("no signature.json".into()))?;
    Ok(LoadedPack {
        manifest: serde_json::from_slice(&manifest_bytes)?,
        manifest_bytes,
        signature: serde_json::from_slice(&sig_bytes)?,
        files,
    })
}

/// Full static verification: signature over stored manifest bytes, then every
/// payload digest, then exact file-set equality (no extras, no missing).
/// Returns the signer's public key hex — the identity for allowlisting.
/// (Behavioral verification — the eval vectors — is the runtime's job.)
pub fn verify(pack: &LoadedPack) -> Result<String, PackError> {
    let signer = pack.signature.verify(&pack.manifest_bytes)?;

    for (path, expected) in &pack.manifest.files {
        let bytes = pack
            .files
            .get(path)
            .ok_or_else(|| PackError::Malformed(format!("manifest lists missing file {path:?}")))?;
        let actual = sha256_hex(bytes);
        if &actual != expected {
            return Err(PackError::Digest {
                path: path.clone(),
                expected: expected.clone(),
                actual,
            });
        }
    }
    for path in pack.files.keys() {
        if !pack.manifest.files.contains_key(path) {
            return Err(PackError::Malformed(format!("unsigned extra file {path:?}")));
        }
    }
    if !pack.manifest.files.contains_key(&pack.manifest.entry) {
        return Err(PackError::Malformed(format!(
            "entry {:?} not in pack",
            pack.manifest.entry
        )));
    }
    Ok(signer)
}

/// Write a verified pack's payload into `dest` (the agent's staging dir).
/// Call [`verify`] first — extract trusts the in-memory pack.
pub fn extract(pack: &LoadedPack, dest: &Path) -> Result<(), PackError> {
    fs::create_dir_all(dest)?;
    fs::write(dest.join(MANIFEST_NAME), &pack.manifest_bytes)?;
    for (path, bytes) in &pack.files {
        let rel = Path::new(path);
        // Belt-and-braces: re-check even though `load` already rejected these.
        if rel.components().any(|c| !matches!(c, Component::Normal(_))) {
            return Err(PackError::Malformed(format!("illegal path {path:?}")));
        }
        let target = dest.join(rel);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(target, bytes)?;
    }
    Ok(())
}

fn walk(root: &Path, rel: PathBuf, out: &mut Vec<PathBuf>) -> Result<(), PackError> {
    for entry in fs::read_dir(root.join(&rel))? {
        let entry = entry?;
        let child = rel.join(entry.file_name());
        let ty = entry.file_type()?;
        if ty.is_dir() {
            walk(root, child, out)?;
        } else if ty.is_file() {
            out.push(child);
        }
        // Symlinks are deliberately skipped: a pack is data, not a filesystem.
    }
    Ok(())
}

fn append<W: std::io::Write>(
    tar: &mut tar::Builder<W>,
    path: &str,
    bytes: &[u8],
) -> Result<(), PackError> {
    let mut header = tar::Header::new_ustar();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_uid(0);
    header.set_gid(0);
    header.set_cksum();
    tar.append_data(&mut header, path, bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{EvalSpec, EvalVector, FPACK_VERSION, PayloadKind, Requires};

    fn demo_manifest() -> Manifest {
        Manifest {
            fpack: FPACK_VERSION,
            name: "demo-policy".into(),
            version: "0.1.0".into(),
            kind: PayloadKind::Wasm,
            entry: "payload/policy.wasm".into(),
            requires: Requires::default(),
            files: BTreeMap::new(),
            eval: Some(EvalSpec {
                engine: "wasi-cmd".into(),
                vectors: vec![EvalVector {
                    input_hex: hex::encode(b"obs:1,2,3"),
                    output_sha256: sha256_hex(b"act:0.5"),
                }],
            }),
            bridge: None,
        }
    }

    fn build_demo(dir: &Path) -> (PathBuf, KeyPair) {
        let payload = dir.join("payload-src");
        fs::create_dir_all(payload.join("cfg")).unwrap();
        fs::write(payload.join("policy.wasm"), b"\0asm-fake-module").unwrap();
        fs::write(payload.join("cfg").join("gains.json"), b"{\"kp\":1.5}").unwrap();
        let key = KeyPair::generate().unwrap();
        let out = dir.join("demo.fpack");
        build(&payload, demo_manifest(), &key, &out).unwrap();
        (out, key)
    }

    #[test]
    fn round_trip_verifies_and_extracts() {
        let dir = tempfile::tempdir().unwrap();
        let (out, key) = build_demo(dir.path());

        let pack = load(&out).unwrap();
        let signer = verify(&pack).unwrap();
        assert_eq!(signer, key.public_hex());
        assert_eq!(pack.manifest.files.len(), 2);
        assert!(pack.manifest.files.contains_key("payload/cfg/gains.json"));

        let staged = dir.path().join("staged");
        extract(&pack, &staged).unwrap();
        assert_eq!(fs::read(staged.join("payload/policy.wasm")).unwrap(), b"\0asm-fake-module");
        assert!(staged.join("manifest.json").exists());
    }

    #[test]
    fn deterministic_build_bit_identical() {
        let dir = tempfile::tempdir().unwrap();
        let payload = dir.path().join("p");
        fs::create_dir_all(&payload).unwrap();
        fs::write(payload.join("policy.wasm"), b"same-bytes").unwrap();
        let key = KeyPair::from_seed_hex(&"11".repeat(32)).unwrap();
        let m = Manifest { entry: "payload/policy.wasm".into(), ..demo_manifest() };
        let a = dir.path().join("a.fpack");
        let b = dir.path().join("b.fpack");
        build(&payload, m.clone(), &key, &a).unwrap();
        build(&payload, m, &key, &b).unwrap();
        assert_eq!(fs::read(&a).unwrap(), fs::read(&b).unwrap(), "same input must give bit-identical packs");
    }

    #[test]
    fn tampered_payload_fails_digest() {
        let dir = tempfile::tempdir().unwrap();
        let (out, _) = build_demo(dir.path());
        let mut pack = load(&out).unwrap();
        pack.files.get_mut("payload/policy.wasm").unwrap()[3] ^= 0xFF;
        match verify(&pack) {
            Err(PackError::Digest { path, .. }) => assert_eq!(path, "payload/policy.wasm"),
            other => panic!("expected digest failure, got {other:?}"),
        }
    }

    #[test]
    fn tampered_manifest_fails_signature() {
        let dir = tempfile::tempdir().unwrap();
        let (out, _) = build_demo(dir.path());
        let mut pack = load(&out).unwrap();
        // Flip a byte inside the stored manifest — e.g. corrupt a digest char.
        let pos = pack.manifest_bytes.len() / 2;
        pack.manifest_bytes[pos] ^= 0x01;
        assert!(matches!(verify(&pack), Err(PackError::Crypto(_))));
    }

    #[test]
    fn extra_unsigned_file_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (out, _) = build_demo(dir.path());
        let mut pack = load(&out).unwrap();
        pack.files.insert("payload/smuggled.bin".into(), b"evil".to_vec());
        assert!(matches!(verify(&pack), Err(PackError::Malformed(_))));
    }

    #[test]
    fn wrong_key_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (out, _) = build_demo(dir.path());
        let mut pack = load(&out).unwrap();
        let other = KeyPair::from_seed_hex(&"22".repeat(32)).unwrap();
        pack.signature = other.sign(b"not the manifest");
        assert!(matches!(verify(&pack), Err(PackError::Crypto(_))));
    }
}
