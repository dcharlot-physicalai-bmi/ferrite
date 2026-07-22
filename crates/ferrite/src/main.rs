//! ferrite — build, sign, verify, and deploy verified-behavior packs.
//!
//! The inner loop this CLI exists for:
//!   ferrite keygen
//!   ferrite build ./my-policy --name reach --version 0.1.0 --entry policy.wasm \
//!       --vec-str "obs:0.1,0.2" --vec-str "obs:0.9,0.4" -o reach.fpack
//!   ferrite discover
//!   ferrite deploy reach.fpack --to pi4.local:7266
//! The device re-runs the signed eval vectors after apply and refuses the pack
//! if its *behavior* doesn't match what the author signed — not just its bytes.

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use ferrite_pack::{
    EvalSpec, FPACK_VERSION, KeyPair, Manifest, PayloadKind, Requires,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

const SERVICE_TYPE: &str = "_ferrite._tcp.local.";
pub const DEFAULT_PORT: u16 = 7266; // "F-A-N-N" on a phone pad? no — FE(rrite) on 0x1C62. It's just ours.

#[derive(Parser)]
#[command(name = "ferrite", version, about = "Signed, verified-behavior packs for physical-AI fleets")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate the author keypair (~/.ferrite/key.hex)
    Keygen {
        #[arg(long)]
        force: bool,
    },
    /// Build + sign a .fpack from a payload directory, recording eval vectors
    Build {
        /// Directory whose contents become payload/…
        payload_dir: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "0.1.0")]
        version: String,
        /// Entry file, relative to the payload dir (e.g. policy.wasm)
        #[arg(long)]
        entry: String,
        /// Eval engine: "wasi-cmd" (wasm payload) or "ferric" (GPU-fabric model spec)
        #[arg(long, default_value = "wasi-cmd")]
        engine: String,
        /// WASI grants: clock, random, net, fs:<dir> (repeatable, comma-ok)
        #[arg(long, value_delimiter = ',')]
        wasi: Vec<String>,
        /// Typed host worlds, e.g. ipai:nn (repeatable, comma-ok)
        #[arg(long, value_delimiter = ',')]
        cap: Vec<String>,
        /// Eval-vector input as a UTF-8 string (repeatable)
        #[arg(long = "vec-str")]
        vec_str: Vec<String>,
        /// Eval-vector input as hex bytes (repeatable)
        #[arg(long = "vec-hex")]
        vec_hex: Vec<String>,
        /// Sim-to-real bridge target ("feetech", "dynamixel", "arduino", … or a
        /// bare codec id): the payload's stdout (JSON targets 0..1) is encoded
        /// to that bus's wire bytes, and the signed vectors digest THOSE bytes.
        #[arg(long)]
        bridge: Option<String>,
        /// Bus servo IDs for the bridge target (comma-separated, e.g. 1,2,3)
        #[arg(long = "bridge-ids", value_delimiter = ',')]
        bridge_ids: Vec<u8>,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Print a pack's manifest and signer without executing anything
    Inspect { fpack: PathBuf },
    /// Statically verify a pack, then re-run its eval vectors locally
    Verify { fpack: PathBuf },
    /// Browse the LAN/tailnet for ferrited agents (mDNS)
    Discover {
        #[arg(long, default_value_t = 3)]
        secs: u64,
    },
    /// Push a pack to an agent; prints the device's verification report
    Deploy {
        fpack: PathBuf,
        #[arg(long)]
        to: String,
    },
    /// Agent info
    Info {
        #[arg(long)]
        to: String,
    },
    /// Start a deployed pack on an agent
    Start {
        name: String,
        #[arg(long)]
        to: String,
        /// stdin for the run, as a UTF-8 string
        #[arg(long, default_value = "")]
        input: String,
    },
    /// Stop a running pack
    Stop {
        name: String,
        #[arg(long)]
        to: String,
    },
    /// Fetch recent logs for a pack
    Logs {
        name: String,
        #[arg(long)]
        to: String,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Keygen { force } => keygen(force),
        Cmd::Build { payload_dir, name, version, entry, engine, wasi, cap, vec_str, vec_hex, bridge, bridge_ids, out } => {
            build(payload_dir, name, version, entry, engine, wasi, cap, vec_str, vec_hex, bridge, bridge_ids, out)
        }
        Cmd::Inspect { fpack } => inspect(&fpack),
        Cmd::Verify { fpack } => verify(&fpack),
        Cmd::Discover { secs } => discover(secs),
        Cmd::Deploy { fpack, to } => deploy(&fpack, &to),
        Cmd::Info { to } => http_get(&to, "/v1/info"),
        Cmd::Start { name, to, input } => http_post(&to, &format!("/v1/packs/{name}/start"), input.as_bytes()),
        Cmd::Stop { name, to } => http_post(&to, &format!("/v1/packs/{name}/stop"), &[]),
        Cmd::Logs { name, to } => http_get(&to, &format!("/v1/packs/{name}/logs")),
    }
}

fn key_path() -> Result<PathBuf> {
    let home = std::env::home_dir().context("no home directory")?;
    Ok(home.join(".ferrite").join("key.hex"))
}

fn load_key() -> Result<KeyPair> {
    let path = key_path()?;
    let seed = fs::read_to_string(&path)
        .with_context(|| format!("no author key at {} — run `ferrite keygen`", path.display()))?;
    Ok(KeyPair::from_seed_hex(&seed)?)
}

fn keygen(force: bool) -> Result<()> {
    let path = key_path()?;
    if path.exists() && !force {
        let key = load_key()?;
        println!("key exists: {}", path.display());
        println!("public: {}", key.public_hex());
        return Ok(());
    }
    let key = KeyPair::generate()?;
    fs::create_dir_all(path.parent().unwrap())?;
    fs::write(&path, key.seed_hex())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    println!("wrote {}", path.display());
    println!("public: {}", key.public_hex());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build(
    payload_dir: PathBuf,
    name: String,
    version: String,
    entry: String,
    engine: String,
    wasi: Vec<String>,
    cap: Vec<String>,
    vec_str: Vec<String>,
    vec_hex: Vec<String>,
    bridge: Option<String>,
    bridge_ids: Vec<u8>,
    out: Option<PathBuf>,
) -> Result<()> {
    let key = load_key()?;
    let requires = Requires { wasi, caps: cap };
    let bridge = bridge.map(|target| ferrite_pack::BridgeSpec {
        target,
        ids: if bridge_ids.is_empty() { None } else { Some(bridge_ids) },
        names: None,
        topic: None,
    });
    let entry_rel = entry.trim_start_matches("payload/").to_string();
    let entry_pack = format!("payload/{entry_rel}");
    let entry_bytes = fs::read(payload_dir.join(&entry_rel))
        .with_context(|| format!("entry {entry_rel:?} not found in {}", payload_dir.display()))?;

    // Record verified-behavior vectors by running the payload NOW, under the
    // same deny-by-default sandbox the device will use.
    let mut inputs: Vec<Vec<u8>> = vec_str.into_iter().map(|s| s.into_bytes()).collect();
    for h in vec_hex {
        inputs.push(hex::decode(h.trim()).context("bad --vec-hex")?);
    }
    let eval = if inputs.is_empty() {
        eprintln!("warning: no --vec-str/--vec-hex given — pack ships WITHOUT behavior vectors");
        None
    } else {
        let vectors = ferrite_runtime::record_eval(&engine, &entry_bytes, &inputs, &requires, bridge.as_ref())?;
        for (i, v) in vectors.iter().enumerate() {
            println!("vector {i}: in {}B → out sha256 {}…", inputs[i].len(), &v.output_sha256[..16]);
        }
        Some(EvalSpec { engine: engine.clone(), vectors })
    };

    let manifest = Manifest {
        fpack: FPACK_VERSION,
        name: name.clone(),
        version: version.clone(),
        kind: if engine == "ferric" { PayloadKind::Model } else { PayloadKind::Wasm },
        entry: entry_pack,
        requires,
        files: BTreeMap::new(),
        eval,
        bridge,
    };
    let out = out.unwrap_or_else(|| PathBuf::from(format!("{name}-{version}.fpack")));
    ferrite_pack::build(&payload_dir, manifest, &key, &out)?;
    let bytes = fs::read(&out)?;
    println!("built {} ({} bytes)", out.display(), bytes.len());
    println!("pack sha256: {}", ferrite_pack::sha256_hex(&bytes));
    println!("signer: {}", key.public_hex());
    Ok(())
}

fn inspect(fpack: &PathBuf) -> Result<()> {
    let pack = ferrite_pack::load(fpack)?;
    let signer = ferrite_pack::verify(&pack)?;
    println!("{}", String::from_utf8_lossy(&pack.manifest_bytes));
    println!("signature: VALID, signer {signer}");
    Ok(())
}

fn verify(fpack: &PathBuf) -> Result<()> {
    let pack = ferrite_pack::load(fpack)?;
    let signer = ferrite_pack::verify(&pack)?;
    println!("static: signature + {} file digest(s) OK (signer {}…)", pack.manifest.files.len(), &signer[..16]);
    let entry = &pack.files[&pack.manifest.entry];
    let results = ferrite_runtime::check_eval(&pack.manifest, entry)?;
    if results.is_empty() {
        println!("behavior: pack carries no eval vectors");
        return Ok(());
    }
    let mut ok = true;
    for (i, r) in results.iter().enumerate() {
        println!(
            "vector {i}: {} (fuel {}){}",
            if r.pass { "PASS" } else { "FAIL" },
            r.fuel_used,
            if r.pass { String::new() } else { format!(" expected {}… got {}…", &r.expected_sha256[..16], &r.actual_sha256[..16]) },
        );
        ok &= r.pass;
    }
    if !ok {
        bail!("behavioral verification FAILED");
    }
    println!("behavior: all {} vector(s) match the signed outputs", results.len());
    Ok(())
}

fn discover(secs: u64) -> Result<()> {
    let mdns = mdns_sd::ServiceDaemon::new()?;
    let rx = mdns.browse(SERVICE_TYPE)?;
    let deadline = std::time::Instant::now() + Duration::from_secs(secs);
    let mut seen = std::collections::BTreeSet::new();
    println!("browsing {SERVICE_TYPE} for {secs}s…");
    while let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) {
        match rx.recv_timeout(left.min(Duration::from_millis(250))) {
            Ok(mdns_sd::ServiceEvent::ServiceResolved(info)) => {
                let addrs: Vec<String> = info.get_addresses().iter().map(|a| a.to_string()).collect();
                let name = info.get_fullname().to_string();
                if seen.insert(name.clone()) {
                    println!(
                        "  {} → {}:{}  platform={}",
                        name.trim_end_matches(&format!(".{SERVICE_TYPE}")),
                        addrs.first().cloned().unwrap_or_default(),
                        info.get_port(),
                        info.get_property_val_str("platform").unwrap_or("?"),
                    );
                }
            }
            Ok(_) => {}
            Err(_) => {}
        }
    }
    if seen.is_empty() {
        println!("  (no agents found)");
    }
    Ok(())
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(120)))
        .build()
        .into()
}

fn deploy(fpack: &PathBuf, to: &str) -> Result<()> {
    // Refuse to ship a pack that doesn't verify locally — fail here, not on-device.
    let pack = ferrite_pack::load(fpack)?;
    ferrite_pack::verify(&pack)?;
    let bytes = fs::read(fpack)?;
    println!("deploying {} ({} bytes) → {to}", fpack.display(), bytes.len());
    let mut resp = agent()
        .post(format!("http://{to}/v1/packs"))
        .content_type("application/vnd.ferrite.fpack")
        .send(&bytes[..])?;
    let status = resp.status();
    let body = resp.body_mut().read_to_string()?;
    print_report(&body);
    if !status.is_success() {
        bail!("device REJECTED the pack (HTTP {status})");
    }
    Ok(())
}

fn print_report(body: &str) {
    match serde_json::from_str::<serde_json::Value>(body) {
        Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap_or_else(|_| body.into())),
        Err(_) => println!("{body}"),
    }
}

fn http_get(to: &str, path: &str) -> Result<()> {
    let mut resp = agent().get(format!("http://{to}{path}")).call()?;
    let status = resp.status();
    let body = resp.body_mut().read_to_string()?;
    print_report(&body);
    if !status.is_success() {
        bail!("HTTP {status}");
    }
    Ok(())
}

fn http_post(to: &str, path: &str, body: &[u8]) -> Result<()> {
    let mut resp = agent().post(format!("http://{to}{path}")).send(body)?;
    let status = resp.status();
    let text = resp.body_mut().read_to_string()?;
    print_report(&text);
    if !status.is_success() {
        bail!("HTTP {status}");
    }
    Ok(())
}
