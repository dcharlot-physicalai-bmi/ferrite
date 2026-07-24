# Ferralloy

**Signed, verified-behavior packs for physical-AI fleets.** Pure Rust.

Every fleet platform ships *bytes* and calls it an update. Ferralloy ships
*behavior*: a pack carries its author's signed eval vectors, and a device
accepts the pack only after re-running them in the same deny-by-default sandbox
and byte-comparing the outputs. Not "did it install" — "does it still do
exactly what the author proved it does."

```
ferralloy keygen
ferralloy build ./policy --name pd-hover --entry pd-hover.wasm \
    --vec-str "0.0,0.0,1.0" --vec-str "2.5,-0.4,1.2" -o pd-hover.fpack
ferralloy discover                       # mDNS: find agents on the LAN/tailnet
ferralloy deploy pd-hover.fpack --to jetson-hub:7266
ferralloy start pd-hover --to jetson-hub:7266 --input "0.0,0.0,1.0"
ferralloy logs  pd-hover --to jetson-hub:7266
```

Proven 2026-07-22 (v0.1, first day): a pack built + vectored on an aarch64 Mac
deployed to an x86_64 Linux box; the device independently verified all vectors
**bit-exact across architectures**.


## Install from crates.io

The whole stack is published — no clone needed:

```
cargo install ferralloy         # the CLI (keygen, build, sign, deploy, verify, run, release)
cargo install ferralloy-agent   # ferralloyd — the device agent
cargo install ferralloy-fleet   # the open fleet server
```

Library crates:

```
cargo add ferralloy-pack        # the signed, verified-behavior pack format
cargo add ferralloy-bridge      # 12 wire codecs x 17 hardware targets, zero-dep
cargo add ferralloy-runtime     # sandboxed execution + verified-behavior eval
```

The GPU cross-fabric `ferric` engine builds against the published `ferric-core`
on **stock wgpu** — no toolchain forks. Cross-fabric bit-identity comes from the
WGSL kernels themselves (proven Metal = Vulkan = browser on unpatched wgpu), so
`cargo install ferralloy` is deterministic out of the box.


## How

- **`ferralloy-pack`** — the `.fpack` format: deterministic tar (bit-identical
  rebuilds), manifest with sha256 of every payload file, ed25519 signature over
  the stored manifest bytes (transitively signs the whole pack), capability
  grants, and eval vectors (input → expected output sha256).
- **`ferralloy-runtime`** — wasmtime host for `wasi-cmd` payloads
  (wasm32-wasip1): in-memory stdin/stdout, **no preopens, no net, no args, no
  env; clock frozen and RNG seeded unless the manifest grants them**. Fuel
  metering bounds runaways; epoch interrupts implement `stop`. Determinism is
  structural: what isn't granted doesn't exist, so behavior can't drift.
- **`ferralloy`** — the CLI: keygen / build (records vectors by running your
  payload) / inspect / verify / discover / deploy / start / stop / logs.
- **`ferralloy-agent`** (`ferralloyd`) — the device daemon: mDNS advertisement,
  HTTP API, and the four-step accept gate — signature → digests → stage →
  **re-run the signed vectors from the staged bytes** — then an atomic swap to
  live. Signer allowlist (`~/.ferralloy/agent/allowed_signers`) or
  trust-on-first-use with the signer reported.

Behavioral drift is a first-class failure: a payload whose bytes verify but
whose *behavior* changed is rejected with the differing digests in the report.
Fuel counts are reported as telemetry (repeatable within a platform, not part
of the acceptance contract — output digests are).

## Status

v0.1 — the verified loop, working end-to-end (11 unit/integration tests + live
cross-arch deploy). Roadmap (see `../ferric/docs/FERRALLOY-INGEST-PLAN.md`):
ferralloy-bridge (typed actuator codecs), Rugix OS A/B integration, USB-C
CDC-NCM dev link, TUF root of trust, sim-gated promotion, joules-per-task
telemetry, browser ops surface, `ferralloy-lite` (MCU), `ferralloy-fleet` (open
cohorts — no paid gate, ever).

Part of the IPAI @ BMI open ecosystem, alongside
[Ferric](https://ferric.physicalai-bmi.org) (AI framework) and Ferromotion
(kinematics/dynamics). MIT OR Apache-2.0.
