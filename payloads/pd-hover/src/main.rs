//! pd-hover — demo Ferralloy pack payload: a PD hover controller for a 1-D
//! thrust-controlled point mass. Reads "y0,v0,target" from stdin, closes the
//! loop for 200 steps at dt=0.02 s, prints the command trajectory and the
//! final state. Pure f64 math: WebAssembly floats are deterministic by spec,
//! so this policy's behavior IS its signature.

use std::io::Read;

const DT: f64 = 0.02;
const STEPS: usize = 200;
const MASS: f64 = 0.5; // kg
const G: f64 = 9.81;
const KP: f64 = 18.0;
const KD: f64 = 7.5;
const THRUST_MAX: f64 = 12.0; // N

fn main() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).expect("stdin");
    let mut it = input.trim().split(',').map(|s| s.trim().parse::<f64>().expect("obs float"));
    let (mut y, mut v, target) = (
        it.next().expect("y0"),
        it.next().expect("v0"),
        it.next().expect("target"),
    );

    println!("pd-hover v{} target={target:.3}", env!("CARGO_PKG_VERSION"));
    for step in 0..STEPS {
        // PD law + gravity feed-forward, clamped to the actuator envelope.
        let u = (MASS * G + KP * (target - y) + KD * (0.0 - v)).clamp(0.0, THRUST_MAX);
        let a = u / MASS - G;
        v += a * DT;
        y += v * DT;
        if step % 20 == 0 {
            println!("t={:.2} y={y:.4} v={v:.4} u={u:.4}", step as f64 * DT);
        }
    }
    let settled = (y - target).abs() < 1e-3 && v.abs() < 1e-2;
    println!("final y={y:.6} v={v:.6} settled={settled}");
}
