//! The sim-to-real bridge stage, end to end: a policy payload's stdout (JSON
//! normalized targets) is encoded to actuator wire bytes, and THOSE bytes are
//! the behavior the signed eval vectors pin. Golden wire bytes were captured
//! from the original JS hwbridge implementation — the vectors are
//! cross-language: the Rust device must produce byte-for-byte what the
//! browser-side sim produced.

use ferrite_pack::{BridgeSpec, EvalSpec, EvalVector, FPACK_VERSION, Manifest, PayloadKind, Requires, sha256_hex};
use ferrite_runtime::{bridge_encode, check_eval, record_eval};
use std::collections::BTreeMap;

/// Pure echo: stdout = stdin, unchanged. The "policy" whose output is the
/// JSON target array itself.
const ECHO: &str = r#"
(module
  (import "wasi_snapshot_preview1" "fd_read"
    (func $fd_read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    (i32.store (i32.const 0) (i32.const 100))
    (i32.store (i32.const 4) (i32.const 4096))
    (drop (call $fd_read (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 8)))
    (i32.store (i32.const 4) (i32.load (i32.const 8)))
    (drop (call $fd_write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))))
"#;

/// JS-captured golden: feetech-scs SYNC WRITE for targets [0, 0.5, 1], ids [1,2,3].
const FEETECH_GOLDEN: &str = "fffffe0d832a0201000002000803ff0f29";
/// JS-captured golden: pwm-text for the same targets.
const PWM_GOLDEN: &[u8] = b"#500,1500,2500\n";

fn feetech_spec(ids: Vec<u8>) -> BridgeSpec {
    BridgeSpec { target: "feetech".into(), ids: Some(ids), names: None, topic: None }
}

fn manifest_with(vectors: Vec<EvalVector>, bridge: Option<BridgeSpec>) -> Manifest {
    Manifest {
        fpack: FPACK_VERSION,
        name: "echo-policy".into(),
        version: "0.1.0".into(),
        kind: PayloadKind::Wasm,
        entry: "payload/echo.wasm".into(),
        requires: Requires::default(),
        files: BTreeMap::new(),
        eval: Some(EvalSpec { engine: "wasi-cmd".into(), vectors }),
        bridge,
    }
}

#[test]
fn bridge_encode_matches_js_goldens() {
    // The cross-language contract: identical wire bytes to the browser-side JS.
    let out = bridge_encode(&feetech_spec(vec![1, 2, 3]), b"[0,0.5,1]").unwrap();
    assert_eq!(hex::encode(&out), FEETECH_GOLDEN);

    let spec = BridgeSpec { target: "arduino".into(), ids: None, names: None, topic: None };
    assert_eq!(bridge_encode(&spec, b"[0,0.5,1]").unwrap(), PWM_GOLDEN);

    // A bare codec id works too.
    let spec = BridgeSpec { target: "pwm-text".into(), ids: None, names: None, topic: None };
    assert_eq!(bridge_encode(&spec, b"[0,0.5,1]").unwrap(), PWM_GOLDEN);
}

#[test]
fn vectors_pin_the_wire_bytes() {
    // Record vectors THROUGH the bridge: the digests are of the bus bytes.
    let inputs = vec![b"[0,0.5,1]".to_vec()];
    let vectors = record_eval("wasi-cmd", ECHO.as_bytes(), &inputs, &Requires::default(),
        Some(&feetech_spec(vec![1, 2, 3]))).unwrap();
    assert_eq!(vectors[0].output_sha256, sha256_hex(&hex::decode(FEETECH_GOLDEN).unwrap()),
        "the signed digest must be of the WIRE bytes, not the policy's text output");

    // Device-side self-check with the same bridge spec: passes.
    let m = manifest_with(vectors, Some(feetech_spec(vec![1, 2, 3])));
    let results = check_eval(&m, ECHO.as_bytes()).unwrap();
    assert!(results.iter().all(|r| r.pass));
}

#[test]
fn changed_bus_wiring_is_behavioral_drift() {
    // Same policy, same vectors — but the manifest routes to different servo
    // IDs. Different bytes reach the bus, so the check MUST fail: bus wiring
    // is part of the signed behavior.
    let inputs = vec![b"[0,0.5,1]".to_vec()];
    let vectors = record_eval("wasi-cmd", ECHO.as_bytes(), &inputs, &Requires::default(),
        Some(&feetech_spec(vec![1, 2, 3]))).unwrap();
    let m = manifest_with(vectors, Some(feetech_spec(vec![1, 2, 4])));
    let results = check_eval(&m, ECHO.as_bytes()).unwrap();
    assert!(results.iter().any(|r| !r.pass), "different servo ids ⇒ different wire bytes ⇒ drift");
}

#[test]
fn non_numeric_stdout_is_rejected() {
    let err = bridge_encode(&feetech_spec(vec![1]), b"not json");
    assert!(err.is_err());
    let err = bridge_encode(&feetech_spec(vec![1]), b"[1e999]"); // parses to inf
    assert!(err.is_err(), "non-finite targets must be rejected");
}
