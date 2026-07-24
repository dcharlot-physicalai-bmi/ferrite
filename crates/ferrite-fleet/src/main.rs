//! ferrite-fleet — the open, self-hostable fleet plane.
//!
//! Every serious edge platform ships an open device agent and gates the fleet
//! server behind a paid cloud. Ferrite's fleet plane is open too, with no
//! feature gate — that is the whole point. It is deliberately small:
//!
//!   • **channels** (stable, beta, …) each hold one current **release** — a
//!     signed `.fpack`, validated on upload (signature + digests) so a broken
//!     or unsigned artifact can never become a channel target.
//!   • **devices** poll their channel, pull the pack, and run it through their
//!     OWN accept gate (behavioral verification on-device) before it goes live,
//!     then **report** the outcome here. The server never pushes; a device
//!     behind NAT still updates, and "rolled out" means "behavior verified on
//!     the device," not "bytes delivered."
//!
//! State is a directory: `channels/<name>.fpack` + a small `channels.json` and
//! `devices.json`. No database, no cloud — copy the directory to move the
//! fleet. This is the reference server; a production one would add cohorts,
//! staged canaries, and TUF-rooted keys (all planned, all open).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Json, Response};
use axum::routing::{get, put};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Clone, Serialize, Deserialize)]
struct Release {
    name: String,
    version: String,
    sha256: String,
    signer: String,
    /// seconds since epoch, stamped by the server on upload
    published: u64,
}

// `device` and `seen` are stamped by the server, so a device's POST omits
// them; `#[serde(default)]` on every field also makes the report robust to a
// client that sends a subset.
#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(default)]
struct DeviceReport {
    device: String,
    channel: String,
    target_sha: String,
    version: String,
    behavior: String,
    ok: bool,
    platform: String,
    /// seconds since epoch of the last report
    seen: u64,
}

#[derive(Default, Serialize, Deserialize)]
struct FleetState {
    channels: BTreeMap<String, Release>,
    devices: BTreeMap<String, DeviceReport>,
}

#[derive(Clone)]
struct App {
    inner: Arc<Mutex<FleetState>>,
    root: Arc<PathBuf>,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let port: u16 = std::env::var("FERRITE_FLEET_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(7280);
    let root = std::env::var("FERRITE_FLEET_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::home_dir()
                .expect("no home")
                .join(".ferrite")
                .join("fleet")
        });
    fs::create_dir_all(root.join("channels"))?;

    let mut state = FleetState::default();
    if let Ok(bytes) = fs::read(root.join("channels.json")) {
        state.channels = serde_json::from_slice(&bytes).unwrap_or_default();
    }
    if let Ok(bytes) = fs::read(root.join("devices.json")) {
        state.devices = serde_json::from_slice(&bytes).unwrap_or_default();
    }

    let app = App {
        inner: Arc::new(Mutex::new(state)),
        root: Arc::new(root),
    };

    let router = axum::Router::new()
        .route("/", get(dashboard))
        .route("/v1/fleet", get(fleet_json))
        .route("/v1/channels/{ch}", put(set_channel).get(get_channel))
        .route("/v1/channels/{ch}/pack", get(get_pack))
        .route("/v1/devices/{id}/report", axum::routing::post(post_report))
        .with_state(app)
        .layer(axum::extract::DefaultBodyLimit::max(512 * 1024 * 1024));

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    println!("ferrite-fleet listening on 0.0.0.0:{port}");
    axum::serve(listener, router).await?;
    Ok(())
}

fn persist(app: &App, st: &FleetState) {
    let _ = fs::write(
        app.root.join("channels.json"),
        serde_json::to_vec_pretty(&st.channels).unwrap_or_default(),
    );
    let _ = fs::write(
        app.root.join("devices.json"),
        serde_json::to_vec_pretty(&st.devices).unwrap_or_default(),
    );
}

/// PUT a `.fpack` as a channel's release. The pack is statically verified
/// (signature + digests) before it can become a target — the fleet plane never
/// serves an artifact it hasn't validated.
async fn set_channel(State(app): State<App>, Path(ch): Path<String>, body: axum::body::Bytes) -> Response {
    if ch.contains(['/', '.']) {
        return (StatusCode::BAD_REQUEST, "bad channel name").into_response();
    }
    let tmp = app.root.join("channels").join(format!("{ch}.incoming"));
    if let Err(e) = fs::write(&tmp, &body) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("io: {e}")).into_response();
    }
    let pack = match ferrite_pack::load(&tmp) {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("load: {e}")).into_response(),
    };
    let signer = match ferrite_pack::verify(&pack) {
        Ok(s) => s,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("verification failed: {e}")).into_response(),
    };
    let rel = Release {
        name: pack.manifest.name.clone(),
        version: pack.manifest.version.clone(),
        sha256: ferrite_pack::sha256_hex(&body),
        signer,
        published: now(),
    };
    let final_path = app.root.join("channels").join(format!("{ch}.fpack"));
    if let Err(e) = fs::rename(&tmp, &final_path) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("store: {e}")).into_response();
    }
    let mut st = app.inner.lock().unwrap();
    st.channels.insert(ch.clone(), rel.clone());
    persist(&app, &st);
    (StatusCode::OK, Json(serde_json::json!({ "channel": ch, "released": rel }))).into_response()
}

async fn get_channel(State(app): State<App>, Path(ch): Path<String>) -> Response {
    let st = app.inner.lock().unwrap();
    match st.channels.get(&ch) {
        Some(r) => Json(r).into_response(),
        None => (StatusCode::NOT_FOUND, "no release on this channel").into_response(),
    }
}

async fn get_pack(State(app): State<App>, Path(ch): Path<String>) -> Response {
    if ch.contains(['/', '.']) {
        return (StatusCode::BAD_REQUEST, "bad channel name").into_response();
    }
    let path = app.root.join("channels").join(format!("{ch}.fpack"));
    match fs::read(&path) {
        Ok(bytes) => (
            [(axum::http::header::CONTENT_TYPE, "application/vnd.ferrite.fpack")],
            bytes,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "no pack").into_response(),
    }
}

async fn post_report(State(app): State<App>, Path(id): Path<String>, Json(mut rep): Json<DeviceReport>) -> Response {
    rep.device = id.clone();
    rep.seen = now();
    let mut st = app.inner.lock().unwrap();
    st.devices.insert(id, rep);
    persist(&app, &st);
    (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
}

async fn fleet_json(State(app): State<App>) -> Json<serde_json::Value> {
    let st = app.inner.lock().unwrap();
    Json(serde_json::json!({ "channels": st.channels, "devices": st.devices }))
}

async fn dashboard(State(app): State<App>) -> Html<String> {
    let st = app.inner.lock().unwrap();
    let t = now();
    let mut chan_rows = String::new();
    for (name, r) in &st.channels {
        chan_rows.push_str(&format!(
            "<tr><td><b>{name}</b></td><td>{}</td><td>{}</td><td class=m>{}…</td><td class=m>{}…</td></tr>",
            r.name, r.version, &r.sha256[..r.sha256.len().min(12)], &r.signer[..r.signer.len().min(12)]
        ));
    }
    if chan_rows.is_empty() {
        chan_rows = "<tr><td colspan=5 class=dim>no channels yet — <span class=m>ferrite release &lt;pack&gt; --channel stable --fleet …</span></td></tr>".into();
    }
    let mut dev_rows = String::new();
    for (id, d) in &st.devices {
        let age = t.saturating_sub(d.seen);
        let dot = if d.ok { "ok" } else { "bad" };
        dev_rows.push_str(&format!(
            "<tr><td><b>{id}</b></td><td class=m>{}</td><td>{}</td><td>{}</td><td class={dot}>{}</td><td class=dim>{age}s ago</td></tr>",
            d.platform, d.channel, d.version, d.behavior
        ));
    }
    if dev_rows.is_empty() {
        dev_rows = "<tr><td colspan=6 class=dim>no devices reporting — start ferrited with FERRITE_FLEET_URL set</td></tr>".into();
    }
    Html(format!(
        r#"<!doctype html><meta charset=utf-8><title>Ferrite Fleet</title>
<style>
 body{{font:14px ui-monospace,Menlo,monospace;background:#0b1024;color:#eef1f8;margin:0;padding:28px 34px}}
 h1{{font-size:17px;letter-spacing:.02em;margin:0 0 2px}} h1 b{{color:#cfaa5b}}
 .sub{{color:#8aa0bd;font-size:12px;margin:0 0 22px}}
 h2{{font-size:12px;letter-spacing:.16em;text-transform:uppercase;color:#cfaa5b;margin:26px 0 8px}}
 table{{width:100%;border-collapse:collapse}} td,th{{text-align:left;padding:8px 12px;border-bottom:1px solid #243157;font-size:12.5px}}
 th{{color:#8aa0bd;font-size:10px;letter-spacing:.1em;text-transform:uppercase}}
 .m{{color:#9fb2cc}} .dim{{color:#61708a}} .ok{{color:#46c6b0}} .bad{{color:#ff6a6a}}
</style>
<h1><b>Φ</b> Ferrite Fleet</h1>
<p class=sub>Open fleet plane · a device shows here only after it VERIFIES a release's behavior on-device. Rolled out = verified, not delivered.</p>
<h2>Channels</h2>
<table><tr><th>channel</th><th>pack</th><th>version</th><th>sha256</th><th>signer</th></tr>{chan_rows}</table>
<h2>Devices</h2>
<table><tr><th>device</th><th>platform</th><th>channel</th><th>version</th><th>behavior</th><th>last seen</th></tr>{dev_rows}</table>
"#
    ))
}
