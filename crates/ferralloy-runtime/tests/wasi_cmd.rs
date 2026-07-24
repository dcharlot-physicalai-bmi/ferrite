//! Runtime tests against a handwritten WAT WASI command — no external
//! toolchain needed. The module reads stdin, adds 1 to every byte, writes the
//! result to stdout: a deterministic transform with observable behavior.

use ferralloy_pack::{EvalSpec, EvalVector, FPACK_VERSION, Manifest, PayloadKind, Requires, sha256_hex};
use ferralloy_runtime::{EVAL_FUEL, check_eval, record_eval, run_wasi_cmd};
use std::collections::BTreeMap;

const ECHO_PLUS_ONE: &str = r#"
(module
  (import "wasi_snapshot_preview1" "fd_read"
    (func $fd_read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    (local $n i32) (local $i i32)
    ;; iovec at 0 -> { buf: 100, len: 4096 }, nread/nwritten cell at 8
    (i32.store (i32.const 0) (i32.const 100))
    (i32.store (i32.const 4) (i32.const 4096))
    (drop (call $fd_read (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 8)))
    (local.set $n (i32.load (i32.const 8)))
    (block $done
      (loop $l
        (br_if $done (i32.ge_u (local.get $i) (local.get $n)))
        (i32.store8 (i32.add (i32.const 100) (local.get $i))
          (i32.add (i32.load8_u (i32.add (i32.const 100) (local.get $i))) (i32.const 1)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $l)))
    (i32.store (i32.const 4) (local.get $n))
    (drop (call $fd_write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))))
"#;

const INFINITE_LOOP: &str = r#"
(module (func (export "_start") (loop $l (br $l))))
"#;

fn manifest_with(vectors: Vec<EvalVector>) -> Manifest {
    Manifest {
        fpack: FPACK_VERSION,
        name: "echo-plus-one".into(),
        version: "0.1.0".into(),
        kind: PayloadKind::Wasm,
        entry: "payload/echo.wasm".into(),
        requires: Requires::default(),
        files: BTreeMap::new(),
        eval: Some(EvalSpec { engine: "wasi-cmd".into(), vectors }),
        bridge: None,
    }
}

#[test]
fn transforms_stdin_to_stdout() {
    let out = run_wasi_cmd(ECHO_PLUS_ONE.as_bytes(), b"abc", &Requires::default(), EVAL_FUEL).unwrap();
    assert_eq!(out.stdout, b"bcd");
    assert!(out.fuel_used > 0);
}

#[test]
fn runs_are_deterministic() {
    let a = run_wasi_cmd(ECHO_PLUS_ONE.as_bytes(), b"obs:1,2,3", &Requires::default(), EVAL_FUEL).unwrap();
    let b = run_wasi_cmd(ECHO_PLUS_ONE.as_bytes(), b"obs:1,2,3", &Requires::default(), EVAL_FUEL).unwrap();
    assert_eq!(a.stdout, b.stdout);
    assert_eq!(a.fuel_used, b.fuel_used, "even the instruction count must match");
}

#[test]
fn record_then_check_round_trips() {
    let inputs = vec![b"hello".to_vec(), b"".to_vec(), vec![0u8, 255, 7]];
    let vectors = record_eval("wasi-cmd", ECHO_PLUS_ONE.as_bytes(), &inputs, &Requires::default(), None).unwrap();
    assert_eq!(vectors.len(), 3);
    assert_eq!(vectors[0].output_sha256, sha256_hex(b"ifmmp"));

    let manifest = manifest_with(vectors);
    let results = check_eval(&manifest, ECHO_PLUS_ONE.as_bytes()).unwrap();
    assert!(results.iter().all(|r| r.pass), "recorded vectors must verify");
}

#[test]
fn behavioral_drift_is_caught() {
    // Vectors recorded from echo+1, "verified" against echo+2 — a policy whose
    // behavior changed must fail even though it runs fine.
    let vectors = record_eval("wasi-cmd", ECHO_PLUS_ONE.as_bytes(), &[b"abc".to_vec()], &Requires::default(), None).unwrap();
    let manifest = manifest_with(vectors);
    let echo_plus_two = ECHO_PLUS_ONE.replace("(i32.const 1)))\n", "(i32.const 2)))\n");
    assert_ne!(echo_plus_two, ECHO_PLUS_ONE);
    let results = check_eval(&manifest, echo_plus_two.as_bytes()).unwrap();
    assert!(results.iter().any(|r| !r.pass), "changed behavior must fail the check");
}

#[test]
fn runaway_loop_is_fuel_bounded() {
    let err = run_wasi_cmd(INFINITE_LOOP.as_bytes(), b"", &Requires::default(), 1_000_000);
    assert!(err.is_err(), "infinite loop must be stopped by fuel metering");
}
