//! ferrited — the Ferrite device agent.
//!
//! What makes this agent different from every fleet agent in the field: a pack
//! is accepted only if its **behavior** verifies, not just its bytes. On
//! deploy the agent (1) checks the ed25519 signature against its signer policy,
//! (2) checks every payload digest, (3) stages the pack, then (4) re-runs the
//! author's signed eval vectors *from the staged files* in the same
//! deny-by-default sandbox the pack will run in, byte-comparing output digests.
//! Only then does the pack go live — atomically.
//!
//! Signer policy: if ~/.ferrite/agent/allowed_signers exists (one pubkey hex
//! per line) it is enforced; otherwise the agent runs trust-on-first-use and
//! reports the signer so the operator can pin it.

use axum::extract::{Path as AxPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use ferrite_pack::{LoadedPack, Manifest};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

const SERVICE_TYPE: &str = "_ferrite._tcp.local.";
const DEFAULT_PORT: u16 = 7266;
const RUN_FUEL: u64 = u64::MAX / 2; // effectively unbounded for `start`; eval runs use EVAL_FUEL

#[derive(Clone)]
struct App {
    inner: Arc<Mutex<AgentState>>,
    root: Arc<PathBuf>,
}

struct AgentState {
    packs: BTreeMap<String, PackState>,
}

struct PackState {
    manifest: Manifest,
    signer: String,
    dir: PathBuf,
    run: RunState,
    logs: Vec<String>,
    engine: Option<ferrite_runtime::Engine>,
}

#[derive(Clone, Serialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum RunState {
    Stopped,
    Running,
    Exited,
    Failed,
}

#[derive(Serialize)]
struct VectorReport {
    pass: bool,
    fuel: u64,
    expected: String,
    actual: String,
}

#[derive(Serialize)]
struct DeployReport {
    name: String,
    version: String,
    signer: String,
    signer_policy: String,
    #[serde(rename = "static")]
    static_check: String,
    behavior: String,
    vectors: Vec<VectorReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn agent_root() -> PathBuf {
    std::env::home_dir()
        .expect("no home directory")
        .join(".ferrite")
        .join("agent")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let port: u16 = std::env::var("FERRITE_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    let root = agent_root();
    fs::create_dir_all(root.join("packs"))?;

    let app = App {
        inner: Arc::new(Mutex::new(AgentState { packs: BTreeMap::new() })),
        root: Arc::new(root),
    };
    reload_packs(&app);

    // mDNS advertisement — `ferrite discover` finds us with zero config.
    let host = gethostname::gethostname().to_string_lossy().into_owned();
    let mdns = mdns_sd::ServiceDaemon::new()?;
    let props = [("platform", format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH))];
    let service = mdns_sd::ServiceInfo::new(
        SERVICE_TYPE,
        &host,
        &format!("{host}.local."),
        "",
        port,
        &props[..],
    )?
    .enable_addr_auto();
    mdns.register(service)?;

    // Optional fleet subscription: poll a fleet server for this channel's
    // target release, pull + run the accept gate + report. The device pulls;
    // the fleet server never pushes — a device behind NAT still updates, and a
    // pack still only goes live if its behavior verifies on THIS device.
    if let Ok(fleet) = std::env::var("FERRITE_FLEET_URL") {
        let channel = std::env::var("FERRITE_CHANNEL").unwrap_or_else(|_| "stable".into());
        let device_id = std::env::var("FERRITE_DEVICE_ID").unwrap_or_else(|_| host.clone());
        println!("fleet: subscribing to {fleet} channel={channel} as {device_id}");
        let app_fleet = app.clone();
        std::thread::spawn(move || fleet_poll_loop(app_fleet, fleet, channel, device_id));
    }

    let router = axum::Router::new()
        .route("/", get(ops_page))
        .route("/v1/info", get(info))
        .route("/v1/packs", post(deploy))
        .route("/v1/packs/{name}/start", post(start))
        .route("/v1/packs/{name}/stop", post(stop))
        .route("/v1/packs/{name}/logs", get(logs))
        .with_state(app)
        // Packs are model-sized; 512 MB ceiling.
        .layer(axum::extract::DefaultBodyLimit::max(512 * 1024 * 1024));

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    println!("ferrited listening on 0.0.0.0:{port} ({host})");
    axum::serve(listener, router).await?;
    Ok(())
}

/// Re-hydrate pack state from disk on boot (live packs survive agent restarts).
fn reload_packs(app: &App) {
    let packs_dir = app.root.join("packs");
    let Ok(entries) = fs::read_dir(&packs_dir) else { return };
    let mut st = app.inner.lock().unwrap();
    for e in entries.flatten() {
        let dir = e.path();
        let Ok(bytes) = fs::read(dir.join("manifest.json")) else { continue };
        let Ok(manifest) = serde_json::from_slice::<Manifest>(&bytes) else { continue };
        let signer = fs::read_to_string(dir.join("signer")).unwrap_or_default();
        st.packs.insert(
            manifest.name.clone(),
            PackState { manifest, signer, dir, run: RunState::Stopped, logs: Vec::new(), engine: None },
        );
    }
}

/// The GPU fabric this device verifies model packs on — resolved once.
fn fabric() -> &'static str {
    static FABRIC: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    FABRIC.get_or_init(ferrite_runtime::ferric_engine::fabric)
}

async fn info(State(app): State<App>) -> Json<serde_json::Value> {
    let st = app.inner.lock().unwrap();
    let packs: Vec<_> = st
        .packs
        .values()
        .map(|p| {
            serde_json::json!({
                "name": p.manifest.name,
                "version": p.manifest.version,
                "kind": p.manifest.kind,
                "signer": p.signer,
                "state": p.run,
                "vectors": p.manifest.eval.as_ref().map(|e| e.vectors.len()).unwrap_or(0),
                "bridge": p.manifest.bridge.as_ref().map(|b| &b.target),
            })
        })
        .collect();
    Json(serde_json::json!({
        "agent": "ferrited",
        "version": env!("CARGO_PKG_VERSION"),
        "host": gethostname::gethostname().to_string_lossy(),
        "platform": format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
        "fabric": fabric(),
        "packs": packs,
    }))
}

async fn deploy(State(app): State<App>, body: axum::body::Bytes) -> Response {
    // Verification runs wasm — do the whole thing off the async runtime.
    let res = tokio::task::spawn_blocking(move || deploy_blocking(app, body)).await;
    match res {
        Ok(resp) => resp,
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")).into_response(),
    }
}

fn deploy_blocking(app: App, body: axum::body::Bytes) -> Response {
    let report = accept_pack(&app, &body);
    let code = if report.error.is_none() {
        StatusCode::OK
    } else {
        StatusCode::BAD_REQUEST
    };
    (code, Json(report)).into_response()
}

/// The accept gate — the heart of Ferrite, shared by the HTTP deploy endpoint
/// and the fleet-subscription poller. Runs signature → digests → signer policy
/// → staged behavioral verification, and on full success swaps the pack live
/// atomically. Returns a report; `error` is `Some` on any rejection and the
/// pack never goes live in that case.
fn accept_pack(app: &App, body: &[u8]) -> DeployReport {
    let mut report = DeployReport {
        name: String::new(),
        version: String::new(),
        signer: String::new(),
        signer_policy: String::new(),
        static_check: "FAILED".into(),
        behavior: "not-run".into(),
        vectors: Vec::new(),
        error: None,
    };
    let reject = |mut r: DeployReport, msg: String| {
        r.error = Some(msg);
        r
    };

    // 1) Parse + static verification (signature, digests, file-set equality).
    let tmp = app.root.join("incoming.fpack");
    if let Err(e) = fs::write(&tmp, body) {
        return reject(report, format!("io: {e}"));
    }
    let pack: LoadedPack = match ferrite_pack::load(&tmp) {
        Ok(p) => p,
        Err(e) => return reject(report, format!("load: {e}")),
    };
    report.name = pack.manifest.name.clone();
    report.version = pack.manifest.version.clone();
    let signer = match ferrite_pack::verify(&pack) {
        Ok(s) => s,
        Err(e) => return reject(report, format!("static verification failed: {e}")),
    };
    report.static_check = "ok".into();
    report.signer = signer.clone();

    // 2) Signer policy: enforced allowlist if present, TOFU otherwise.
    let allowlist = app.root.join("allowed_signers");
    if allowlist.exists() {
        let allowed = fs::read_to_string(&allowlist).unwrap_or_default();
        if !allowed.lines().any(|l| l.trim() == signer) {
            report.signer_policy = "DENIED".into();
            return reject(report, format!("signer {signer} not in allowed_signers"));
        }
        report.signer_policy = "allowlisted".into();
    } else {
        report.signer_policy = "tofu".into();
    }

    // 3) Stage, then verify BEHAVIOR from the staged bytes — run what you
    //    stored, not what you parsed.
    let staged = app.root.join("staging").join(&report.name);
    let _ = fs::remove_dir_all(&staged);
    if let Err(e) = ferrite_pack::extract(&pack, &staged) {
        return reject(report, format!("stage: {e}"));
    }
    let entry_path = staged.join(&pack.manifest.entry);
    let entry = match fs::read(&entry_path) {
        Ok(b) => b,
        Err(e) => return reject(report, format!("staged entry: {e}")),
    };
    match ferrite_runtime::check_eval(&pack.manifest, &entry) {
        Ok(results) if results.is_empty() => {
            report.behavior = "no-vectors".into();
        }
        Ok(results) => {
            let all = results.iter().all(|r| r.pass);
            report.vectors = results
                .into_iter()
                .map(|r| VectorReport {
                    pass: r.pass,
                    fuel: r.fuel_used,
                    expected: r.expected_sha256,
                    actual: r.actual_sha256,
                })
                .collect();
            if !all {
                report.behavior = "FAILED".into();
                return reject(report, "behavioral verification failed: device output does not match the signed vectors".into());
            }
            report.behavior = format!("verified ({} vectors, bit-exact)", report.vectors.len());
        }
        Err(e) => return reject(report, format!("eval: {e}")),
    }

    // 4) Go live atomically: staged dir swaps into packs/<name>.
    let live = app.root.join("packs").join(&report.name);
    let old = app.root.join("staging").join(format!("{}.old", report.name));
    let _ = fs::remove_dir_all(&old);
    if live.exists() {
        if let Err(e) = fs::rename(&live, &old) {
            return reject(report, format!("swap out: {e}"));
        }
    }
    if let Err(e) = fs::rename(&staged, &live) {
        let _ = fs::rename(&old, &live); // roll back
        return reject(report, format!("swap in: {e}"));
    }
    let _ = fs::remove_dir_all(&old);
    let _ = fs::write(live.join("signer"), &signer);
    let _ = fs::remove_file(&tmp);

    let mut st = app.inner.lock().unwrap();
    st.packs.insert(
        report.name.clone(),
        PackState {
            manifest: pack.manifest,
            signer,
            dir: live,
            run: RunState::Stopped,
            logs: Vec::new(),
            engine: None,
        },
    );
    report
}

async fn start(
    State(app): State<App>,
    AxPath(name): AxPath<String>,
    body: axum::body::Bytes,
) -> Response {
    let (manifest, entry, engine) = {
        let mut st = app.inner.lock().unwrap();
        let Some(p) = st.packs.get_mut(&name) else {
            return (StatusCode::NOT_FOUND, "no such pack").into_response();
        };
        if p.run == RunState::Running {
            return (StatusCode::CONFLICT, "already running").into_response();
        }
        let entry = match fs::read(p.dir.join(&p.manifest.entry)) {
            Ok(b) => b,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("entry: {e}")).into_response(),
        };
        let engine = match ferrite_runtime::make_engine() {
            Ok(e) => e,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("engine: {e}")).into_response(),
        };
        p.run = RunState::Running;
        p.logs.clear();
        p.engine = Some(engine.clone());
        (p.manifest.clone(), entry, engine)
    };

    let app2 = app.clone();
    let name2 = name.clone();
    tokio::task::spawn_blocking(move || {
        let kind = manifest.kind;
        let outcome: Result<Vec<String>, String> = if kind == ferrite_pack::PayloadKind::Model {
            // Model pack: run the ferric engine once on this device's fabric.
            ferrite_runtime::engine_output("ferric", &entry, &body, &manifest.requires)
                .map(|(out, _)| {
                    vec![
                        format!("out| ferric fabric: {}", fabric()),
                        format!("out| output: {} bytes, sha256 {}", out.len(), ferrite_pack::sha256_hex(&out)),
                    ]
                })
                .map_err(|e| e.to_string())
        } else if kind == ferrite_pack::PayloadKind::Native {
            // Native pack: run the ELF under the OS sandbox (landlock + rlimits).
            ferrite_runtime::native::run_native(&entry, &body, &manifest.requires, ferrite_runtime::native::DEFAULT_CPU_SECS)
                .map_err(|e| e.to_string())
                .map(|out| {
                    let mut lines: Vec<String> = vec!["out| native (landlock-confined)".into()];
                    lines.extend(String::from_utf8_lossy(&out.stdout).lines().map(|l| format!("out| {l}")));
                    lines.extend(String::from_utf8_lossy(&out.stderr).lines().map(|l| format!("err| {l}")));
                    lines.push("-- exited ok".into());
                    lines
                })
        } else {
            ferrite_runtime::run_wasi_cmd_on(&engine, &entry, &body, &manifest.requires, RUN_FUEL)
                .map_err(|e| e.to_string())
                .and_then(|out| {
                    let mut lines: Vec<String> = String::from_utf8_lossy(&out.stdout)
                        .lines()
                        .map(|l| format!("out| {l}"))
                        .collect();
                    lines.extend(String::from_utf8_lossy(&out.stderr).lines().map(|l| format!("err| {l}")));
                    // Sim-to-real: a bridge pack's stdout is normalized targets; encode
                    // to the bus wire bytes and emit them — the same encode path the
                    // signed eval vectors verified.
                    if let Some(spec) = &manifest.bridge {
                        let wire = ferrite_runtime::bridge_encode(spec, &out.stdout)
                            .map_err(|e| format!("bridge: {e}"))?;
                        let sink = emit_bridge_bytes(&name2, spec, &wire).map_err(|e| format!("bridge sink: {e}"))?;
                        let preview: String = wire.iter().take(24).map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
                        lines.push(format!("bridge| {} → {} bytes → {sink}", spec.target, wire.len()));
                        lines.push(format!("bridge| {preview}{}", if wire.len() > 24 { " …" } else { "" }));
                    }
                    lines.push(format!("-- exited ok, fuel {}", out.fuel_used));
                    Ok(lines)
                })
        };
        let mut st = app2.inner.lock().unwrap();
        if let Some(p) = st.packs.get_mut(&name2) {
            match outcome {
                Ok(lines) => {
                    for line in lines {
                        push_log(&mut p.logs, line);
                    }
                    p.run = RunState::Exited;
                }
                Err(e) => {
                    push_log(&mut p.logs, format!("-- failed: {e}"));
                    p.run = RunState::Failed;
                }
            }
            p.engine = None;
        }
    });
    (StatusCode::OK, Json(serde_json::json!({"name": name, "state": "running"}))).into_response()
}

/// The browser ops surface: one dependency-free page served by the agent
/// itself — packs, verification state, start/stop, live logs (with the bridge
/// wire bytes). Talks to the same /v1 API every other client uses.
async fn ops_page() -> axum::response::Html<&'static str> {
    axum::response::Html(OPS_HTML)
}

const OPS_HTML: &str = r#"<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ferrited — ops</title>
<style>
  :root { color-scheme: dark; }
  body { font: 14px/1.45 ui-monospace, SFMono-Regular, Menlo, monospace; background: #0b0e14; color: #cdd6e4; max-width: 72rem; margin: 1.5rem auto; padding: 0 1rem; }
  h1 { font-size: 1.1rem; color: #e8eefc; } h1 small { color: #7d8aa0; font-weight: 400; }
  .card { background: #121826; border: 1px solid #1f2a3d; border-radius: 8px; padding: .9rem 1rem; margin: .8rem 0; }
  .row { display: flex; gap: .6rem; align-items: baseline; flex-wrap: wrap; }
  .name { color: #e8eefc; font-weight: 600; }
  .tag { font-size: .78rem; border: 1px solid #2a3950; border-radius: 999px; padding: .05rem .55rem; color: #9fb0c8; }
  .st-running { color: #ffd479; border-color: #6b5518; } .st-exited { color: #7ee787; border-color: #1f5c33; }
  .st-failed { color: #ff8080; border-color: #6b2222; } .st-stopped { color: #9fb0c8; }
  .signer { color: #7d8aa0; font-size: .78rem; }
  textarea { width: 100%; box-sizing: border-box; background: #0b0e14; color: #cdd6e4; border: 1px solid #1f2a3d; border-radius: 6px; padding: .45rem .6rem; font: inherit; resize: vertical; min-height: 2.2rem; }
  button { background: #1c2a44; color: #dbe6f7; border: 1px solid #2c4166; border-radius: 6px; padding: .3rem .9rem; font: inherit; cursor: pointer; }
  button:hover { background: #24365a; }
  pre.logs { background: #0b0e14; border: 1px solid #1f2a3d; border-radius: 6px; padding: .6rem .7rem; max-height: 16rem; overflow: auto; white-space: pre-wrap; margin: .5rem 0 0; }
  pre.logs .bridge { color: #8fd3ff; } pre.logs .err { color: #ff9f9f; }
  .empty { color: #7d8aa0; padding: 2rem 0; }
</style>
<h1>ferrited <small id="meta">…</small></h1>
<div id="packs"><div class="empty">loading…</div></div>
<script>
const $ = (s, r=document) => r.querySelector(s);
const esc = (s) => String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
let inputs = {};   // preserve per-pack input across re-renders
async function refresh() {
  const info = await (await fetch('/v1/info')).json();
  $('#meta').textContent = `${info.host || ''} · ${info.platform} · fabric ${info.fabric} · v${info.version}`;
  const root = $('#packs');
  if (!info.packs.length) { root.innerHTML = '<div class="empty">no packs deployed — <code>ferrite deploy &lt;pack.fpack&gt; --to this-host:7266</code></div>'; return; }
  for (const p of info.packs) {
    let card = $('#pack-' + CSS.escape(p.name));
    if (!card) {
      card = document.createElement('div');
      card.className = 'card'; card.id = 'pack-' + p.name;
      card.innerHTML = `
        <div class="row">
          <span class="name"></span><span class="ver tag"></span><span class="kind tag"></span>
          <span class="state tag"></span><span class="vectors tag"></span><span class="bridge-t tag" hidden></span>
        </div>
        <div class="signer"></div>
        <div class="row" style="margin-top:.6rem">
          <textarea class="input" rows="1" spellcheck="false" placeholder="stdin for start — e.g. [0,0.5,1]"></textarea>
        </div>
        <div class="row" style="margin-top:.5rem">
          <button class="start">start</button><button class="stop">stop</button>
        </div>
        <pre class="logs" hidden></pre>`;
      root.querySelector('.empty')?.remove();
      root.appendChild(card);
      const name = p.name;
      $('.input', card).addEventListener('input', e => inputs[name] = e.target.value);
      $('.start', card).addEventListener('click', async () => {
        await fetch(`/v1/packs/${encodeURIComponent(name)}/start`, { method: 'POST', body: inputs[name] ?? $('.input', card).value });
        refresh();
      });
      $('.stop', card).addEventListener('click', async () => {
        await fetch(`/v1/packs/${encodeURIComponent(name)}/stop`, { method: 'POST' });
        refresh();
      });
    }
    $('.name', card).textContent = p.name;
    $('.ver', card).textContent = 'v' + p.version;
    $('.kind', card).textContent = p.kind;
    const st = $('.state', card); st.textContent = p.state; st.className = 'state tag st-' + p.state;
    $('.vectors', card).textContent = p.vectors + ' vector' + (p.vectors === 1 ? '' : 's');
    const bt = $('.bridge-t', card);
    if (p.bridge) { bt.hidden = false; bt.textContent = '⇄ ' + p.bridge; } else bt.hidden = true;
    $('.signer', card).textContent = 'signer ' + p.signer;
    const logs = await (await fetch(`/v1/packs/${encodeURIComponent(p.name)}/logs`)).json();
    const pre = $('.logs', card);
    if (logs.logs && logs.logs.length) {
      pre.hidden = false;
      pre.innerHTML = logs.logs.map(l => {
        const cls = l.startsWith('bridge|') ? 'bridge' : (l.startsWith('err|') || l.startsWith('-- failed') ? 'err' : '');
        return cls ? `<span class="${cls}">${esc(l)}</span>` : esc(l);
      }).join('\n');
    }
  }
}
refresh(); setInterval(refresh, 1500);
</script>
"#;

/// Route bridge wire bytes to the device sink: a real serial port when the
/// agent was built with `--features serial` AND `FERRITE_BRIDGE_DEV` names a
/// device (baud from the target registry), else an append-only byte-exact
/// capture file under the agent root — the same bytes either way, so the
/// capture path doubles as the hardware-free verification of this stage.
fn emit_bridge_bytes(pack: &str, spec: &ferrite_pack::BridgeSpec, wire: &[u8]) -> anyhow::Result<String> {
    use std::io::Write;
    #[cfg(feature = "serial")]
    if let Ok(dev) = std::env::var("FERRITE_BRIDGE_DEV") {
        let baud = ferrite_bridge::target(&spec.target)
            .and_then(|t| t.baud)
            .or_else(|| ferrite_bridge::codec(&spec.target).and_then(|c| c.baud))
            .unwrap_or(115_200);
        let mut port = serialport::new(&dev, baud)
            .timeout(std::time::Duration::from_millis(200))
            .open()?;
        port.write_all(wire)?;
        return Ok(format!("serial:{dev}@{baud}"));
    }
    #[cfg(not(feature = "serial"))]
    let _ = spec; // baud lookup only needed for the serial sink
    let dir = agent_root().join("bridge-out");
    fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{pack}.bin"));
    let mut f = fs::OpenOptions::new().create(true).append(true).open(&path)?;
    f.write_all(wire)?;
    Ok(format!("capture:{}", path.display()))
}

fn push_log(logs: &mut Vec<String>, line: String) {
    if logs.len() >= 1000 {
        logs.remove(0);
    }
    logs.push(line);
}

async fn stop(State(app): State<App>, AxPath(name): AxPath<String>) -> Response {
    let st = app.inner.lock().unwrap();
    let Some(p) = st.packs.get(&name) else {
        return (StatusCode::NOT_FOUND, "no such pack").into_response();
    };
    match &p.engine {
        Some(engine) => {
            ferrite_runtime::interrupt(engine);
            (StatusCode::OK, Json(serde_json::json!({"name": name, "state": "interrupted"}))).into_response()
        }
        None => (StatusCode::OK, Json(serde_json::json!({"name": name, "state": p.run.clone()}))).into_response(),
    }
}

async fn logs(State(app): State<App>, AxPath(name): AxPath<String>) -> Response {
    let st = app.inner.lock().unwrap();
    let Some(p) = st.packs.get(&name) else {
        return (StatusCode::NOT_FOUND, "no such pack").into_response();
    };
    Json(serde_json::json!({"name": name, "state": p.run, "logs": p.logs})).into_response()
}

// ─────────────────────────── fleet subscription ───────────────────────────

fn fleet_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(std::time::Duration::from_secs(120)))
        .build()
        .into()
}

/// Poll the fleet server forever: fetch the channel's target, and if it's new,
/// pull the pack and run it through the same accept gate as a manual deploy.
/// Only a behaviorally-verified pack goes live; the result is reported back.
fn fleet_poll_loop(app: App, fleet: String, channel: String, device_id: String) {
    let agent = fleet_agent();
    let mut applied_sha = String::new();
    loop {
        if let Err(e) = fleet_tick(&app, &agent, &fleet, &channel, &device_id, &mut applied_sha) {
            eprintln!("fleet tick: {e}");
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}

fn fleet_tick(
    app: &App,
    agent: &ureq::Agent,
    fleet: &str,
    channel: &str,
    device_id: &str,
    applied_sha: &mut String,
) -> Result<(), String> {
    // 1) what should this channel be running?
    let mut resp = agent
        .get(format!("{fleet}/v1/channels/{channel}"))
        .call()
        .map_err(|e| e.to_string())?;
    if resp.status() == 404 {
        report_state(agent, fleet, device_id, channel, "", "idle", "no target", true);
        return Ok(());
    }
    let body = resp.body_mut().read_to_string().map_err(|e| e.to_string())?;
    let target: serde_json::Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
    let want_sha = target["sha256"].as_str().unwrap_or_default().to_string();
    let want_ver = target["version"].as_str().unwrap_or_default().to_string();

    // 2) already on it? just heartbeat.
    if want_sha == *applied_sha && !want_sha.is_empty() {
        report_state(agent, fleet, device_id, channel, &want_sha, &want_ver, "up-to-date", true);
        return Ok(());
    }

    // 3) pull the pack, integrity-check the transfer, run the accept gate.
    let pack_bytes = agent
        .get(format!("{fleet}/v1/channels/{channel}/pack"))
        .call()
        .map_err(|e| e.to_string())?
        .body_mut()
        .read_to_vec()
        .map_err(|e| e.to_string())?;
    if !want_sha.is_empty() && ferrite_pack::sha256_hex(&pack_bytes) != want_sha {
        return Err("pulled pack sha256 != channel target".into());
    }
    let report = accept_pack(app, &pack_bytes);
    let ok = report.error.is_none();
    if ok {
        *applied_sha = want_sha.clone();
    }
    let behavior = report.error.clone().unwrap_or_else(|| report.behavior.clone());
    println!("fleet: channel={channel} → {} {} · {}", report.name, report.version, behavior);
    report_state(agent, fleet, device_id, channel, &want_sha, &report.version, &behavior, ok);
    Ok(())
}

fn report_state(
    agent: &ureq::Agent,
    fleet: &str,
    device_id: &str,
    channel: &str,
    target_sha: &str,
    version: &str,
    behavior: &str,
    ok: bool,
) {
    let body = serde_json::json!({
        "device": device_id,
        "channel": channel,
        "target_sha": target_sha,
        "version": version,
        "behavior": behavior,
        "ok": ok,
        "platform": format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
    });
    let _ = agent
        .post(format!("{fleet}/v1/devices/{device_id}/report"))
        .send_json(&body);
}
