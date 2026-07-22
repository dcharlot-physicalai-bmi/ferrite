//! ferrite-bridge — wire-protocol codecs for the sim-to-real hardware bridge.
//!
//! A byte-faithful Rust port of the codec + target layers of the Forge
//! hwbridge (`v2/public/assets/islands/lib/hwbridge.js`). A TARGET picks a
//! TRANSPORT (how bytes leave the host — WebSerial/BLE/WebSocket, browser-side,
//! deliberately NOT ported) × a CODEC (the wire protocol below), so new boards
//! and ecosystems drop in without touching the rest.
//!
//! Every codec is a PURE function: normalized targets t[] ∈ [0,1] (+ per-codec
//! params in [`Cmd`]) → wire bytes. That makes the whole layer unit-testable
//! byte-for-byte against golden vectors captured from the JS implementation —
//! no hardware in the loop. What CANNOT be verified here is a physical
//! actuator moving; that needs the board in hand.
//!
//! Fidelity notes (quirks preserved on purpose, so wire bytes match the JS):
//!   • rounding is JS `Math.round` (half toward +∞), not Rust's half-away-0
//!   • JSON payload numbers use JS shortest-round-trip formatting ("0.5", "1")
//!   • the MQTT CONNECT client id is the fixed "forge-1000001" the JS emits

/// One tick of actuator commands, faithful to the JS `encode(t, opts)` shape:
/// normalized per-channel targets plus the per-codec options.
#[derive(Debug, Clone, PartialEq)]
pub struct Cmd {
    /// Normalized targets, one per channel/servo/axis, each in 0..1.
    pub targets: Vec<f64>,
    /// Bus servo IDs (feetech-scs, dynamixel2). Default: 1..=N.
    pub ids: Option<Vec<u8>>,
    /// Joint names (rosbridge). Default: "joint0".."joint{N-1}".
    pub names: Option<Vec<String>>,
    /// MQTT publish topic. Default: "forge/joints".
    pub topic: Option<String>,
}

impl Cmd {
    /// A command with default options — the common case.
    pub fn new(targets: Vec<f64>) -> Self {
        Self { targets, ids: None, names: None, topic: None }
    }

    /// Same command with explicit bus servo IDs.
    pub fn with_ids(mut self, ids: Vec<u8>) -> Self {
        self.ids = Some(ids);
        self
    }

    fn ids_or_default(&self) -> Vec<u8> {
        self.ids
            .clone()
            .unwrap_or_else(|| (1..=self.targets.len() as u8).collect())
    }
}

/// Config for codec `init` frames (rosbridge advertise · Firmata pin modes ·
/// MQTT CONNECT). Only Firmata reads `channels` (default 8).
#[derive(Debug, Clone, Copy, Default)]
pub struct InitCfg {
    pub channels: Option<usize>,
}

// ── shared helpers ──

/// JS `Math.round`: round half toward +∞ (Math.round(-89.5) === -89).
fn js_round(x: f64) -> i64 {
    (x + 0.5).floor() as i64
}

fn clamp01(v: f64) -> f64 {
    v.clamp(0.0, 1.0)
}

/// JS shortest-round-trip number formatting, as JSON.stringify prints it:
/// 0 → "0", 0.5 → "0.5", 1 → "1". Rust's f64 Display is also shortest
/// round-trip, so the digits agree; we only normalize -0 → "0".
fn js_num(x: f64) -> String {
    if x == 0.0 { "0".into() } else { format!("{x}") }
}

/// Minimal JSON string escape matching JSON.stringify for the wire payloads.
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// MQTT length-prefixed UTF-8 string (2-byte big-endian length + bytes).
fn mqtt_str(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = vec![(b.len() >> 8) as u8, (b.len() & 0xFF) as u8];
    out.extend_from_slice(b);
    out
}

/// MQTT remaining-length varint (7 bits per byte, MSB = continuation).
fn mqtt_varint(mut n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut d = (n & 0x7F) as u8;
        n >>= 7;
        if n != 0 {
            d |= 0x80;
        }
        out.push(d);
        if n == 0 {
            break;
        }
    }
    out
}

/// OSC string: null-terminated, zero-padded to a 4-byte boundary.
fn osc_str(s: &str) -> Vec<u8> {
    let mut b = s.as_bytes().to_vec();
    b.push(0);
    while b.len() % 4 != 0 {
        b.push(0);
    }
    b
}

/// LEGO Wireless Protocol 3 GATT service + characteristic (SPIKE/Technic hubs).
pub const LEGO_SVC: &str = "00001623-1212-efde-1623-785feabcd123";
pub const LEGO_CHAR: &str = "00001624-1212-efde-1623-785feabcd123";

/// Normalize raw actuator commands to 0..1 within each actuator's ctrl range.
/// A missing range defaults to [-1, 1]; a zero-width range divides by 1.
pub fn normalize(ctrl: &[f64], ranges: Option<&[[f64; 2]]>) -> Vec<f64> {
    ctrl.iter()
        .enumerate()
        .map(|(i, &c)| {
            let [lo, hi] = ranges.and_then(|r| r.get(i)).copied().unwrap_or([-1.0, 1.0]);
            let sp = if hi - lo == 0.0 { 1.0 } else { hi - lo };
            clamp01((c - lo) / sp)
        })
        .collect()
}

/// CRC-16/BUYPASS (poly 0x8005, init 0, no reflection) — exactly what ROBOTIS
/// Dynamixel Protocol 2.0 uses.
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x8005 } else { crc << 1 };
        }
    }
    crc
}

// ── CODECS: normalized targets t[] ∈ [0,1] (+ Cmd params) → wire bytes ──

/// Generic PWM over an MCU running the forge-bridge firmware. us = 500..2500,
/// framed `#u0,u1,...\n`. (Arduino / ESP32 / Pico / Teensy / micro:bit.)
pub fn encode_pwm_text(cmd: &Cmd) -> Vec<u8> {
    let us: Vec<String> = cmd
        .targets
        .iter()
        .map(|&v| js_round(500.0 + v * 2000.0).to_string())
        .collect();
    format!("#{}\n", us.join(",")).into_bytes()
}

/// Lynxmotion SSC-32(U) servo controller: `#<ch> P<us>` groups, <CR> terminated.
pub fn encode_ssc32(cmd: &Cmd) -> Vec<u8> {
    let groups: Vec<String> = cmd
        .targets
        .iter()
        .enumerate()
        .map(|(i, &v)| format!("#{} P{}", i, js_round(500.0 + v * 2000.0)))
        .collect();
    format!("{}\r", groups.join(" ")).into_bytes()
}

/// Pololu Maestro compact protocol, Set Target 0x84: target in quarter-µs,
/// 7-bit split low/high.
pub fn encode_maestro(cmd: &Cmd) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(cmd.targets.len() * 4);
    for (ch, &v) in cmd.targets.iter().enumerate() {
        let q = js_round((500.0 + v * 2000.0) * 4.0);
        bytes.extend_from_slice(&[0x84, (ch & 0x7F) as u8, (q & 0x7F) as u8, ((q >> 7) & 0x7F) as u8]);
    }
    bytes
}

/// Feetech STS/SMS (Protocol 0) SYNC WRITE goal position (addr 42), 2 bytes
/// little-endian, 0..4095 — the LeRobot SO-100/SO-101 + Waveshare ST3215 bus.
pub fn encode_feetech_scs(cmd: &Cmd) -> Vec<u8> {
    let ids = cmd.ids_or_default();
    let n = cmd.targets.len();
    const ADDR: u8 = 42;
    const L: usize = 2;
    let len = ((L + 1) * n + 4) as u8;
    let mut pkt = vec![0xFF, 0xFF, 0xFE, len, 0x83, ADDR, L as u8];
    for (i, &v) in cmd.targets.iter().enumerate() {
        let p = js_round(v * 4095.0);
        pkt.extend_from_slice(&[ids[i], (p & 0xFF) as u8, ((p >> 8) & 0xFF) as u8]);
    }
    let sum: u32 = pkt[2..].iter().map(|&b| b as u32).sum();
    pkt.push(!(sum as u8));
    pkt
}

/// ROBOTIS Dynamixel Protocol 2.0 SYNC WRITE goal position (addr 116, 4 bytes
/// LE, X-series 0..4095), CRC-16/BUYPASS trailer.
pub fn encode_dynamixel2(cmd: &Cmd) -> Vec<u8> {
    let ids = cmd.ids_or_default();
    const ADDR: u16 = 116;
    const L: u16 = 4;
    let mut params = vec![
        (ADDR & 0xFF) as u8,
        (ADDR >> 8) as u8,
        (L & 0xFF) as u8,
        (L >> 8) as u8,
    ];
    for (i, &v) in cmd.targets.iter().enumerate() {
        let p = js_round(v * 4095.0);
        params.extend_from_slice(&[
            ids[i],
            (p & 0xFF) as u8,
            ((p >> 8) & 0xFF) as u8,
            ((p >> 16) & 0xFF) as u8,
            ((p >> 24) & 0xFF) as u8,
        ]);
    }
    let length = params.len() + 3; // instr + params + 2 CRC
    let mut head = vec![
        0xFF,
        0xFF,
        0xFD,
        0x00,
        0xFE,
        (length & 0xFF) as u8,
        ((length >> 8) & 0xFF) as u8,
        0x83,
    ];
    head.extend_from_slice(&params);
    let c = crc16(&head);
    head.push((c & 0xFF) as u8);
    head.push((c >> 8) as u8);
    head
}

/// Firmata init: set each pin to SERVO mode (0xF4 pin 0x04) — stock
/// StandardFirmata on any Arduino, no custom firmware. Default 8 channels.
pub fn init_firmata(cfg: &InitCfg) -> Vec<u8> {
    let n = cfg.channels.unwrap_or(8);
    let mut b = Vec::with_capacity(n * 3);
    for i in 0..n {
        b.extend_from_slice(&[0xF4, i as u8, 0x04]);
    }
    b
}

/// Firmata tick: one Extended Analog sysex (0xF0 0x6F …) per pin, angle 0..180
/// in two 7-bit bytes (pins >15 OK).
pub fn encode_firmata(cmd: &Cmd) -> Vec<u8> {
    let mut b = Vec::with_capacity(cmd.targets.len() * 6);
    for (pin, &v) in cmd.targets.iter().enumerate() {
        let val = js_round(v * 180.0);
        b.extend_from_slice(&[
            0xF0,
            0x6F,
            (pin & 0x7F) as u8,
            (val & 0x7F) as u8,
            ((val >> 7) & 0x7F) as u8,
            0xF7,
        ]);
    }
    b
}

/// ODrive BLDC motor controllers (real legged-robot motors), ASCII protocol:
/// `w axisN.controller.input_pos <turns>`, one line per axis.
pub fn encode_odrive(cmd: &Cmd) -> Vec<u8> {
    let mut s = String::new();
    for (i, &v) in cmd.targets.iter().enumerate() {
        s.push_str(&format!("w axis{}.controller.input_pos {:.3}\n", i, v - 0.5));
    }
    s.into_bytes()
}

/// LEGO SPIKE/Technic/MINDSTORMS hub over LWP3: one Port Output Command (0x81)
/// per port, GotoAbsolutePosition (0x0D), position int32 LE degrees, speed 40,
/// maxpower 100, endstate hold. Each command is a DISCRETE BLE write.
pub fn lego_frames(cmd: &Cmd) -> Vec<Vec<u8>> {
    cmd.targets
        .iter()
        .enumerate()
        .map(|(port, &v)| {
            let deg = js_round((v - 0.5) * 180.0) as i32;
            let p = deg as u32; // JS `deg >>> 0` — two's-complement reinterpret
            vec![
                0x0E,
                0x00,
                0x81,
                (port & 0xFF) as u8,
                0x11,
                0x0D,
                (p & 0xFF) as u8,
                ((p >> 8) & 0xFF) as u8,
                ((p >> 16) & 0xFF) as u8,
                ((p >> 24) & 0xFF) as u8,
                40,
                100,
                126,
                0,
            ]
        })
        .collect()
}

/// LEGO frames concatenated — the registry-level `encode`. Real BLE transports
/// must send each 14-byte frame from [`lego_frames`] as its own write.
pub fn encode_lego(cmd: &Cmd) -> Vec<u8> {
    lego_frames(cmd).concat()
}

/// MQTT 3.1.1 CONNECT (Home Assistant / ESPHome / IoT over WebSocket):
/// protocol "MQTT" level 4, clean session, keepalive 60, fixed client id.
pub fn init_mqtt(_cfg: &InitCfg) -> Vec<u8> {
    let mut body = mqtt_str("MQTT");
    body.extend_from_slice(&[0x04, 0x02, 0x00, 0x3C]);
    body.extend_from_slice(&mqtt_str("forge-1000001")); // fixed-ish; no RNG in shared code
    let mut pkt = vec![0x10];
    pkt.extend_from_slice(&mqtt_varint(body.len()));
    pkt.extend_from_slice(&body);
    pkt
}

/// MQTT PUBLISH (QoS 0, no packet id): a JSON joint array (3-decimal rounded)
/// to `cmd.topic` (default "forge/joints") each tick.
pub fn encode_mqtt(cmd: &Cmd) -> Vec<u8> {
    let topic = cmd.topic.as_deref().unwrap_or("forge/joints");
    let nums: Vec<String> = cmd
        .targets
        .iter()
        .map(|&v| js_num(js_round(v * 1000.0) as f64 / 1000.0))
        .collect();
    let payload = format!("[{}]", nums.join(","));
    let mut body = mqtt_str(topic);
    body.extend_from_slice(payload.as_bytes());
    let mut pkt = vec![0x30];
    pkt.extend_from_slice(&mqtt_varint(body.len()));
    pkt.extend_from_slice(&body);
    pkt
}

/// OSC (TouchDesigner / Max / SuperCollider / creative robotics): one message
/// `/forge/joints` with N float32 args, big-endian per the OSC spec.
pub fn encode_osc(cmd: &Cmd) -> Vec<u8> {
    let mut out = osc_str("/forge/joints");
    let tags: String = std::iter::once(',')
        .chain(std::iter::repeat('f').take(cmd.targets.len()))
        .collect();
    out.extend_from_slice(&osc_str(&tags));
    for &v in &cmd.targets {
        out.extend_from_slice(&(v as f32).to_be_bytes());
    }
    out
}

/// CAN bus via an SLCAN (Lawicel) USB-CAN adapter, framed for ODrive-CAN
/// Set_Input_Pos (cmd 0x0C): `t<id3><dlc><data>` per channel, arbitration
/// (axis<<5)|0x0C, payload float32 input_pos LE + ff bytes, CR-terminated.
pub fn encode_slcan(cmd: &Cmd) -> Vec<u8> {
    let mut s = String::new();
    for (i, &v) in cmd.targets.iter().enumerate() {
        let id = ((i << 5) | 0x0C) & 0x7FF;
        let mut bytes = ((v - 0.5) as f32).to_le_bytes().to_vec();
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        let hd: String = bytes.iter().map(|b| format!("{b:02X}")).collect();
        s.push_str(&format!("t{id:03X}8{hd}\r"));
    }
    s.into_bytes()
}

/// rosbridge advertise: declare /joint_states as sensor_msgs/JointState.
pub fn init_rosbridge(_cfg: &InitCfg) -> Vec<u8> {
    br#"{"op":"advertise","topic":"/joint_states","type":"sensor_msgs/JointState"}"#.to_vec()
}

/// ROS 2 via rosbridge: publish sensor_msgs/JointState on /joint_states,
/// 0..1 → -π..π. Names default to "joint0".."joint{N-1}".
pub fn encode_rosbridge(cmd: &Cmd) -> Vec<u8> {
    let names: Vec<String> = match &cmd.names {
        Some(n) => n.clone(),
        None => (0..cmd.targets.len()).map(|i| format!("joint{i}")).collect(),
    };
    let name_json: Vec<String> = names.iter().map(|n| json_str(n)).collect();
    let pos_json: Vec<String> = cmd
        .targets
        .iter()
        .map(|&v| js_num(-std::f64::consts::PI + v * 2.0 * std::f64::consts::PI))
        .collect();
    format!(
        r#"{{"op":"publish","topic":"/joint_states","msg":{{"name":[{}],"position":[{}]}}}}"#,
        name_json.join(","),
        pos_json.join(",")
    )
    .into_bytes()
}

/// Back-compat pure encoder (the original PWM path): raw ctrl + ranges →
/// normalized → `#us0,us1,...\n` frame bytes.
pub fn encode_frame(ctrl: &[f64], ranges: Option<&[[f64; 2]]>) -> Vec<u8> {
    encode_pwm_text(&Cmd::new(normalize(ctrl, ranges)))
}

// ── CODEC REGISTRY ──

/// One wire-protocol codec: id/label/metadata + its pure encode function.
pub struct CodecInfo {
    pub id: &'static str,
    pub label: &'static str,
    /// True when the wire format is binary (monitor shows hex, not text).
    pub binary: bool,
    /// Codec-preferred baud rate, where the JS declares one.
    pub baud: Option<u32>,
    pub encode: fn(&Cmd) -> Vec<u8>,
    /// One-shot setup frame sent on connect (rosbridge advertise · Firmata
    /// pin modes · MQTT CONNECT), where the JS has `init`.
    pub init: Option<fn(&InitCfg) -> Vec<u8>>,
    /// Discrete-message codecs (LEGO BLE): the per-write frames. `encode`
    /// returns their concatenation.
    pub frames: Option<fn(&Cmd) -> Vec<Vec<u8>>>,
}

static CODECS: &[CodecInfo] = &[
    CodecInfo { id: "pwm-text", label: "PWM text", binary: false, baud: None, encode: encode_pwm_text, init: None, frames: None },
    CodecInfo { id: "ssc32", label: "Lynxmotion SSC-32", binary: false, baud: None, encode: encode_ssc32, init: None, frames: None },
    CodecInfo { id: "maestro", label: "Pololu Maestro", binary: true, baud: None, encode: encode_maestro, init: None, frames: None },
    CodecInfo { id: "feetech-scs", label: "Feetech STS/SMS (LeRobot) [beta]", binary: true, baud: Some(1_000_000), encode: encode_feetech_scs, init: None, frames: None },
    CodecInfo { id: "dynamixel2", label: "ROBOTIS Dynamixel X (2.0) [beta]", binary: true, baud: Some(1_000_000), encode: encode_dynamixel2, init: None, frames: None },
    CodecInfo { id: "firmata", label: "Firmata (any Arduino · no custom firmware)", binary: true, baud: Some(57_600), encode: encode_firmata, init: Some(init_firmata), frames: None },
    CodecInfo { id: "odrive", label: "ODrive (BLDC motor controllers)", binary: false, baud: Some(115_200), encode: encode_odrive, init: None, frames: None },
    CodecInfo { id: "lego", label: "LEGO SPIKE / Technic hub (BLE)", binary: true, baud: None, encode: encode_lego, init: None, frames: Some(lego_frames) },
    CodecInfo { id: "mqtt", label: "MQTT (Home Assistant / ESPHome / IoT)", binary: true, baud: None, encode: encode_mqtt, init: Some(init_mqtt), frames: None },
    CodecInfo { id: "osc", label: "OSC (TouchDesigner / Max / SuperCollider)", binary: true, baud: None, encode: encode_osc, init: None, frames: None },
    CodecInfo { id: "slcan", label: "CAN bus · ODrive (SLCAN adapter)", binary: false, baud: None, encode: encode_slcan, init: None, frames: None },
    CodecInfo { id: "rosbridge", label: "ROS 2 (rosbridge JointState)", binary: false, baud: None, encode: encode_rosbridge, init: Some(init_rosbridge), frames: None },
];

/// The codec registry, in the JS declaration order.
pub fn codecs() -> &'static [CodecInfo] {
    CODECS
}

/// Look up a codec by its id.
pub fn codec(id: &str) -> Option<&'static CodecInfo> {
    CODECS.iter().find(|c| c.id == id)
}

// ── TARGET REGISTRY: the boards / ecosystems the bridge can drive ──

/// BLE service/characteristic override for non-NUS targets (LEGO hubs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BleCfg {
    pub service: &'static str,
    pub characteristic: &'static str,
    pub with_response: bool,
}

/// One named hardware target: transport × codec + connection metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetInfo {
    pub group: &'static str,
    pub id: &'static str,
    pub label: &'static str,
    /// Transport id: "serial" | "ble" | "ws" (transports live browser-side).
    pub transport: &'static str,
    /// Codec id — resolves in [`codecs`].
    pub codec: &'static str,
    pub baud: Option<u32>,
    /// Firmware flavor the target expects, where the JS declares one.
    pub firmware: Option<&'static str>,
    /// WebSocket URL default (ws targets).
    pub url: Option<&'static str>,
    /// WebSocket subprotocol (MQTT).
    pub protocol: Option<&'static str>,
    pub ble: Option<BleCfg>,
    pub setup: &'static str,
}

static TARGETS: &[TargetInfo] = &[
    TargetInfo { group: "Microcontroller (Arduino-class)", id: "arduino", label: "Arduino (Uno/Mega/Nano/Leonardo/Due)", transport: "serial", codec: "pwm-text", baud: Some(115_200), firmware: Some("pwm"), url: None, protocol: None, ble: None, setup: "Flash forge-bridge.ino, wire servo channel i → PINS[i], connect over USB." },
    TargetInfo { group: "Microcontroller (Arduino-class)", id: "esp32", label: "ESP32 / ESP8266 (USB)", transport: "serial", codec: "pwm-text", baud: Some(115_200), firmware: Some("pwm"), url: None, protocol: None, ble: None, setup: "Flash forge-bridge.ino (Arduino-ESP32 core). For >8 servos use a PCA9685." },
    TargetInfo { group: "Microcontroller (Arduino-class)", id: "esp32-ble", label: "ESP32 (wireless · Bluetooth LE)", transport: "ble", codec: "pwm-text", baud: None, firmware: Some("pwm-ble"), url: None, protocol: None, ble: None, setup: "Flash a BLE-UART (Nordic NUS) firmware; the browser streams frames wirelessly." },
    TargetInfo { group: "Microcontroller (Arduino-class)", id: "pico", label: "Raspberry Pi Pico / RP2040", transport: "serial", codec: "pwm-text", baud: Some(115_200), firmware: Some("pwm"), url: None, protocol: None, ble: None, setup: "Flash forge-bridge.ino via the Arduino-Pico core (or a MicroPython equivalent)." },
    TargetInfo { group: "Microcontroller (Arduino-class)", id: "teensy", label: "Teensy 3.x / 4.x", transport: "serial", codec: "pwm-text", baud: Some(115_200), firmware: Some("pwm"), url: None, protocol: None, ble: None, setup: "Flash forge-bridge.ino (Teensyduino). Great for many servos + fast serial." },
    TargetInfo { group: "Microcontroller (Arduino-class)", id: "microbit", label: "BBC micro:bit v2 (Bluetooth LE)", transport: "ble", codec: "pwm-text", baud: None, firmware: Some("pwm-ble"), url: None, protocol: None, ble: None, setup: "Run a MakeCode/MicroPython BLE-UART receiver that parses \"#us,…\" to servo writes." },
    TargetInfo { group: "Microcontroller (Arduino-class)", id: "firmata", label: "Firmata (any Arduino · no custom firmware)", transport: "serial", codec: "firmata", baud: Some(57_600), firmware: None, url: None, protocol: None, ble: None, setup: "Flash the stock StandardFirmata (Arduino IDE → Examples → Firmata → StandardFirmata). No custom code — channel i → pin i as a servo." },
    TargetInfo { group: "Servo / motor controller (native protocol)", id: "maestro", label: "Pololu Maestro (6–24 ch)", transport: "serial", codec: "maestro", baud: Some(115_200), firmware: None, url: None, protocol: None, ble: None, setup: "Set the Maestro serial mode to \"USB Dual Port\"; no firmware needed." },
    TargetInfo { group: "Servo / motor controller (native protocol)", id: "ssc32", label: "Lynxmotion SSC-32U", transport: "serial", codec: "ssc32", baud: Some(115_200), firmware: None, url: None, protocol: None, ble: None, setup: "Connect over USB; no firmware needed." },
    TargetInfo { group: "Servo / motor controller (native protocol)", id: "odrive", label: "ODrive (BLDC motor controllers)", transport: "serial", codec: "odrive", baud: Some(115_200), firmware: None, url: None, protocol: None, ble: None, setup: "Connect the ODrive over USB, axes in closed-loop position control. Channel i → axis i (input_pos in turns). Great for real BLDC legged robots." },
    TargetInfo { group: "Smart-servo bus (position + feedback)", id: "feetech", label: "Feetech STS/SMS · LeRobot SO-100/101, Waveshare ST3215", transport: "serial", codec: "feetech-scs", baud: Some(1_000_000), firmware: None, url: None, protocol: None, ble: None, setup: "Connect the bus USB-TTL adapter (FE-URT / Waveshare). Set servo IDs 1..N. Write-only (open loop). BETA — verify against your servo docs." },
    TargetInfo { group: "Smart-servo bus (position + feedback)", id: "dynamixel", label: "ROBOTIS Dynamixel X (Protocol 2.0)", transport: "serial", codec: "dynamixel2", baud: Some(1_000_000), firmware: None, url: None, protocol: None, ble: None, setup: "Connect a U2D2 / USB2Dynamixel. Set IDs 1..N, goal position addressing (X-series). BETA — verify against your model." },
    TargetInfo { group: "Robot kit (Bluetooth LE)", id: "lego", label: "LEGO SPIKE / Technic / MINDSTORMS hub", transport: "ble", codec: "lego", baud: None, firmware: None, url: None, protocol: None, ble: Some(BleCfg { service: LEGO_SVC, characteristic: LEGO_CHAR, with_response: true }), setup: "Power on a SPIKE Prime / Technic / Robot Inventor hub and pick it in the Bluetooth prompt. Channel i → port (A,B,C,D…); motors go to an absolute angle." },
    TargetInfo { group: "Servo / motor controller (native protocol)", id: "slcan", label: "CAN bus · ODrive (SLCAN adapter)", transport: "serial", codec: "slcan", baud: Some(115_200), firmware: None, url: None, protocol: None, ble: None, setup: "Use a CANable / SLCAN USB-CAN adapter (open the channel first, e.g. `S8` 1 Mbit + `O`). Frames ODrive Set_Input_Pos on arbitration (axis<<5)|0x0C." },
    TargetInfo { group: "Ecosystem", id: "osc", label: "OSC (TouchDesigner / Max / SuperCollider)", transport: "ws", codec: "osc", baud: None, firmware: None, url: Some("ws://localhost:8080"), protocol: None, ble: None, setup: "Run an OSC-over-WebSocket bridge (e.g. an osc-js relay). Sends /forge/joints with a float per joint." },
    TargetInfo { group: "Ecosystem", id: "ros2", label: "ROS 2 (rosbridge · JointState)", transport: "ws", codec: "rosbridge", baud: None, firmware: None, url: Some("ws://localhost:9090"), protocol: None, ble: None, setup: "Run rosbridge_server (ros2 launch rosbridge_server rosbridge_websocket_launch.xml). Streams sensor_msgs/JointState on /joint_states." },
    TargetInfo { group: "Ecosystem", id: "mqtt", label: "MQTT (Home Assistant / ESPHome / IoT)", transport: "ws", codec: "mqtt", baud: None, firmware: None, url: Some("ws://localhost:9001"), protocol: Some("mqtt"), ble: None, setup: "Point at your broker’s WebSocket listener (e.g. Mosquitto: listener 9001 + protocol websockets). Publishes a joint array to forge/joints." },
];

/// The target registry, in the JS declaration order.
pub fn targets() -> &'static [TargetInfo] {
    TARGETS
}

/// Look up a target by its id.
pub fn target(id: &str) -> Option<&'static TargetInfo> {
    TARGETS.iter().find(|t| t.id == id)
}

// ── tests: every golden vector captured from the JS implementation, plus the
//    structural invariants its hwbridge.test.mjs checks ──
#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical input from the JS test suite: min / mid / max.
    fn t3() -> Cmd {
        Cmd::new(vec![0.0, 0.5, 1.0])
    }

    // ── normalize() — ported from hwbridge.test.mjs ──

    #[test]
    fn normalize_maps_to_unit_range() {
        let n = normalize(
            &[-1.0, 0.0, 1.0, 5.0],
            Some(&[[-1.0, 1.0], [-1.0, 1.0], [-1.0, 1.0], [0.0, 10.0]]),
        );
        assert_eq!(n, vec![0.0, 0.5, 1.0, 0.5]);
    }

    #[test]
    fn normalize_clamps_out_of_range() {
        let c = normalize(&[-9.0, 9.0], Some(&[[-1.0, 1.0], [-1.0, 1.0]]));
        assert_eq!(c, vec![0.0, 1.0]);
    }

    #[test]
    fn normalize_defaults_missing_ranges() {
        // JS golden: normalize([0.5], null) === [0.75] (default range [-1,1]).
        assert_eq!(normalize(&[0.5], None), vec![0.75]);
    }

    // ── crc16 — CRC-16/BUYPASS check values (computed by the JS crc16) ──

    #[test]
    fn crc16_check_values() {
        assert_eq!(crc16(b"123456789"), 0xFEE8); // the standard BUYPASS check value
        assert_eq!(crc16(&[]), 0);
        assert_eq!(crc16(&[0xFF, 0xFF, 0xFD, 0x00]), 0x0E28); // JS golden
    }

    // ── determinism: every codec is pure (ported from hwbridge.test.mjs) ──

    #[test]
    fn every_codec_is_deterministic() {
        let cmd = t3().with_ids(vec![1, 2, 3]);
        for c in codecs() {
            assert_eq!((c.encode)(&cmd), (c.encode)(&cmd), "codec {}", c.id);
        }
    }

    // ── text protocols: exact golden strings from hwbridge.test.mjs ──

    #[test]
    fn pwm_text_golden() {
        assert_eq!(encode_pwm_text(&t3()), b"#500,1500,2500\n");
    }

    #[test]
    fn ssc32_golden() {
        assert_eq!(encode_ssc32(&t3()), b"#0 P500 #1 P1500 #2 P2500\r");
    }

    #[test]
    fn odrive_golden() {
        assert_eq!(
            encode_odrive(&t3()),
            b"w axis0.controller.input_pos -0.500\nw axis1.controller.input_pos 0.000\nw axis2.controller.input_pos 0.500\n"
        );
    }

    #[test]
    fn encode_frame_back_compat() {
        // raw ctrl in [-1,1] → normalized → the PWM frame.
        assert_eq!(encode_frame(&[-1.0, 0.0, 1.0], None), b"#500,1500,2500\n");
    }

    // ── maestro: exact JS bytes + Set Target structure ──

    #[test]
    fn maestro_golden_bytes() {
        let u = encode_maestro(&t3());
        assert_eq!(
            u,
            vec![0x84, 0x00, 0x50, 0x0F, 0x84, 0x01, 0x70, 0x2E, 0x84, 0x02, 0x10, 0x4E]
        );
        // structural: cmd byte + quarter-µs 7-bit split round-trip
        for ch in 0..3usize {
            let o = ch * 4;
            assert_eq!(u[o], 0x84);
            assert_eq!(u[o + 1] as usize, ch);
            let q = (u[o + 2] as u32) | ((u[o + 3] as u32) << 7);
            let want = ((500.0 + [0.0, 0.5, 1.0][ch] * 2000.0) * 4.0) as u32;
            assert_eq!(q, want);
        }
    }

    // ── feetech-scs: exact JS bytes + Protocol-0 SYNC WRITE structure ──

    #[test]
    fn feetech_golden_bytes() {
        let u = encode_feetech_scs(&t3().with_ids(vec![1, 2, 3]));
        assert_eq!(
            u,
            vec![
                0xFF, 0xFF, 0xFE, 0x0D, 0x83, 0x2A, 0x02, 0x01, 0x00, 0x00, 0x02, 0x00, 0x08,
                0x03, 0xFF, 0x0F, 0x29
            ]
        );
    }

    #[test]
    fn feetech_default_ids_match_explicit() {
        assert_eq!(
            encode_feetech_scs(&t3()),
            encode_feetech_scs(&t3().with_ids(vec![1, 2, 3]))
        );
    }

    #[test]
    fn feetech_second_vector() {
        // JS golden for targets [0.25, 0.75], ids [5, 7].
        let u = encode_feetech_scs(&Cmd::new(vec![0.25, 0.75]).with_ids(vec![5, 7]));
        assert_eq!(
            u,
            vec![0xFF, 0xFF, 0xFE, 0x0A, 0x83, 0x2A, 0x02, 0x05, 0x00, 0x04, 0x07, 0xFF, 0x0B, 0x2E]
        );
    }

    #[test]
    fn feetech_structure_checksum_and_positions() {
        let u = encode_feetech_scs(&t3().with_ids(vec![1, 2, 3]));
        assert!(u[0] == 0xFF && u[1] == 0xFF && u[2] == 0xFE && u[4] == 0x83);
        assert_eq!(u[3] as usize, (2 + 1) * 3 + 4); // length field
        let sum: u32 = u[2..u.len() - 1].iter().map(|&b| b as u32).sum();
        assert_eq!(*u.last().unwrap(), !(sum as u8)); // ~sum checksum
        // body: [addr=42, L=2, then per servo: id, lo, hi]
        for i in 0..3usize {
            let o = 7 + i * 3;
            assert_eq!(u[o] as usize, i + 1);
            let p = (u[o + 1] as u32) | ((u[o + 2] as u32) << 8);
            assert_eq!(p as i64, js_round([0.0, 0.5, 1.0][i] * 4095.0));
        }
    }

    // ── dynamixel2: several exact CRC-bearing frames + Protocol-2.0 structure ──

    #[test]
    fn dynamixel_golden_bytes_three_servos() {
        let u = encode_dynamixel2(&t3().with_ids(vec![1, 2, 3]));
        assert_eq!(
            u,
            vec![
                0xFF, 0xFF, 0xFD, 0x00, 0xFE, 0x16, 0x00, 0x83, 0x74, 0x00, 0x04, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x03, 0xFF, 0x0F, 0x00,
                0x00, 0x36, 0xBB
            ]
        );
    }

    #[test]
    fn dynamixel_golden_bytes_two_servos() {
        // JS golden for targets [0.25, 0.75], ids [5, 7] — a distinct CRC.
        let u = encode_dynamixel2(&Cmd::new(vec![0.25, 0.75]).with_ids(vec![5, 7]));
        assert_eq!(
            u,
            vec![
                0xFF, 0xFF, 0xFD, 0x00, 0xFE, 0x11, 0x00, 0x83, 0x74, 0x00, 0x04, 0x00, 0x05,
                0x00, 0x04, 0x00, 0x00, 0x07, 0xFF, 0x0B, 0x00, 0x00, 0x9A, 0x01
            ]
        );
    }

    #[test]
    fn dynamixel_golden_bytes_single_servo() {
        // JS golden for targets [1.0], id [3] — a third distinct CRC.
        let u = encode_dynamixel2(&Cmd::new(vec![1.0]).with_ids(vec![3]));
        assert_eq!(
            u,
            vec![
                0xFF, 0xFF, 0xFD, 0x00, 0xFE, 0x0C, 0x00, 0x83, 0x74, 0x00, 0x04, 0x00, 0x03,
                0xFF, 0x0F, 0x00, 0x00, 0xCB, 0x2F
            ]
        );
    }

    #[test]
    fn dynamixel_default_ids_match_explicit() {
        assert_eq!(
            encode_dynamixel2(&t3()),
            encode_dynamixel2(&t3().with_ids(vec![1, 2, 3]))
        );
    }

    #[test]
    fn dynamixel_structure_length_and_positions() {
        let u = encode_dynamixel2(&t3().with_ids(vec![1, 2, 3]));
        assert_eq!(&u[..5], &[0xFF, 0xFF, 0xFD, 0x00, 0xFE]);
        assert_eq!(u[7], 0x83); // SYNC WRITE
        let length = (u[5] as usize) | ((u[6] as usize) << 8);
        assert_eq!(length, u.len() - 7);
        // params start at 8: addr(2) L(2), then per servo id + 4-byte pos
        let base = 8 + 4;
        for i in 0..3usize {
            let o = base + i * 5;
            assert_eq!(u[o] as usize, i + 1);
            let p = (u[o + 1] as u32)
                | ((u[o + 2] as u32) << 8)
                | ((u[o + 3] as u32) << 16)
                | ((u[o + 4] as u32) << 24);
            assert_eq!(p as i64, js_round([0.0, 0.5, 1.0][i] * 4095.0));
        }
        // trailer is the BUYPASS CRC over everything before it
        let c = crc16(&u[..u.len() - 2]);
        assert_eq!(&u[u.len() - 2..], &[(c & 0xFF) as u8, (c >> 8) as u8]);
    }

    // ── firmata: exact init + sysex frames ──

    #[test]
    fn firmata_init_golden() {
        assert_eq!(
            init_firmata(&InitCfg { channels: Some(3) }),
            vec![0xF4, 0x00, 0x04, 0xF4, 0x01, 0x04, 0xF4, 0x02, 0x04]
        );
        // default = 8 channels (JS golden)
        assert_eq!(
            init_firmata(&InitCfg::default()),
            vec![
                0xF4, 0x00, 0x04, 0xF4, 0x01, 0x04, 0xF4, 0x02, 0x04, 0xF4, 0x03, 0x04, 0xF4,
                0x04, 0x04, 0xF4, 0x05, 0x04, 0xF4, 0x06, 0x04, 0xF4, 0x07, 0x04
            ]
        );
    }

    #[test]
    fn firmata_encode_golden() {
        let u = encode_firmata(&t3());
        assert_eq!(
            u,
            vec![
                0xF0, 0x6F, 0x00, 0x00, 0x00, 0xF7, 0xF0, 0x6F, 0x01, 0x5A, 0x00, 0xF7, 0xF0,
                0x6F, 0x02, 0x34, 0x01, 0xF7
            ]
        );
        // structural: sysex framing + angle round-trip
        assert_eq!(u.len(), 18); // 6 bytes/pin × 3
        for i in 0..3usize {
            let o = i * 6;
            assert!(u[o] == 0xF0 && u[o + 1] == 0x6F && u[o + 5] == 0xF7);
            let val = (u[o + 3] as i64) | ((u[o + 4] as i64) << 7);
            assert_eq!(val, js_round([0.0, 0.5, 1.0][i] * 180.0));
        }
    }

    // ── lego: exact discrete frames (incl. negative-degree two's complement) ──

    #[test]
    fn lego_frames_golden() {
        let f = lego_frames(&t3());
        assert_eq!(f.len(), 3); // discrete BLE writes
        assert_eq!(
            f[0],
            vec![0x0E, 0x00, 0x81, 0x00, 0x11, 0x0D, 0xA6, 0xFF, 0xFF, 0xFF, 0x28, 0x64, 0x7E, 0x00]
        ); // -90° as int32 LE
        assert_eq!(
            f[1],
            vec![0x0E, 0x00, 0x81, 0x01, 0x11, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x28, 0x64, 0x7E, 0x00]
        );
        assert_eq!(
            f[2],
            vec![0x0E, 0x00, 0x81, 0x02, 0x11, 0x0D, 0x5A, 0x00, 0x00, 0x00, 0x28, 0x64, 0x7E, 0x00]
        ); // +90°
        // shape invariants from the JS test
        for (port, c) in f.iter().enumerate() {
            assert!(c.len() == 14 && c[2] == 0x81 && c[3] as usize == port && c[5] == 0x0D);
        }
        assert_eq!(encode_lego(&t3()), f.concat());
    }

    // ── mqtt: exact CONNECT + PUBLISH packets ──

    #[test]
    fn mqtt_init_golden() {
        assert_eq!(
            init_mqtt(&InitCfg::default()),
            vec![
                0x10, 0x19, 0x00, 0x04, 0x4D, 0x51, 0x54, 0x54, 0x04, 0x02, 0x00, 0x3C, 0x00,
                0x0D, 0x66, 0x6F, 0x72, 0x67, 0x65, 0x2D, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30,
                0x31
            ]
        );
    }

    #[test]
    fn mqtt_publish_golden_default_topic() {
        let u = encode_mqtt(&t3());
        assert_eq!(u[0], 0x30); // PUBLISH, QoS 0
        assert_eq!(
            u,
            vec![
                0x30, 0x17, 0x00, 0x0C, 0x66, 0x6F, 0x72, 0x67, 0x65, 0x2F, 0x6A, 0x6F, 0x69,
                0x6E, 0x74, 0x73, 0x5B, 0x30, 0x2C, 0x30, 0x2E, 0x35, 0x2C, 0x31, 0x5D
            ]
        ); // topic "forge/joints", payload "[0,0.5,1]"
    }

    #[test]
    fn mqtt_publish_golden_custom_topic() {
        let mut cmd = Cmd::new(vec![0.123, 0.5]);
        cmd.topic = Some("robot/a".into());
        assert_eq!(
            encode_mqtt(&cmd),
            vec![
                0x30, 0x14, 0x00, 0x07, 0x72, 0x6F, 0x62, 0x6F, 0x74, 0x2F, 0x61, 0x5B, 0x30,
                0x2E, 0x31, 0x32, 0x33, 0x2C, 0x30, 0x2E, 0x35, 0x5D
            ]
        ); // payload "[0.123,0.5]"
    }

    // ── osc: exact packets, address + 4-byte alignment ──

    #[test]
    fn osc_golden_three_channels() {
        let u = encode_osc(&t3());
        assert_eq!(
            u,
            vec![
                0x2F, 0x66, 0x6F, 0x72, 0x67, 0x65, 0x2F, 0x6A, 0x6F, 0x69, 0x6E, 0x74, 0x73,
                0x00, 0x00, 0x00, 0x2C, 0x66, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x3F, 0x80, 0x00, 0x00
            ]
        );
        assert_eq!(&u[..13], b"/forge/joints");
        assert_eq!(u.len() % 4, 0);
    }

    #[test]
    fn osc_golden_two_channels() {
        assert_eq!(
            encode_osc(&Cmd::new(vec![0.25, 0.75])),
            vec![
                0x2F, 0x66, 0x6F, 0x72, 0x67, 0x65, 0x2F, 0x6A, 0x6F, 0x69, 0x6E, 0x74, 0x73,
                0x00, 0x00, 0x00, 0x2C, 0x66, 0x66, 0x00, 0x3E, 0x80, 0x00, 0x00, 0x3F, 0x40,
                0x00, 0x00
            ]
        ); // float32 big-endian 0.25 / 0.75
    }

    // ── slcan: exact SLCAN lines (float32 LE hex + arbitration ids) ──

    #[test]
    fn slcan_golden() {
        let s = encode_slcan(&t3());
        assert_eq!(
            s,
            b"t00C8000000BF00000000\rt02C80000000000000000\rt04C80000003F00000000\r"
        );
        // one CR-terminated frame per axis, each starting 't'
        let txt = String::from_utf8(s).unwrap();
        let frames: Vec<&str> = txt.trim_end_matches('\r').split('\r').collect();
        assert_eq!(frames.len(), 3);
        assert!(frames.iter().all(|f| f.starts_with('t')));
    }

    // ── rosbridge: exact JSON strings ──

    #[test]
    fn rosbridge_init_golden() {
        assert_eq!(
            init_rosbridge(&InitCfg::default()),
            br#"{"op":"advertise","topic":"/joint_states","type":"sensor_msgs/JointState"}"#
        );
    }

    #[test]
    fn rosbridge_publish_golden_default_names() {
        assert_eq!(
            String::from_utf8(encode_rosbridge(&t3())).unwrap(),
            r#"{"op":"publish","topic":"/joint_states","msg":{"name":["joint0","joint1","joint2"],"position":[-3.141592653589793,0,3.141592653589793]}}"#
        );
    }

    #[test]
    fn rosbridge_publish_golden_custom_names() {
        let mut cmd = Cmd::new(vec![0.25]);
        cmd.names = Some(vec!["elbow".into()]);
        assert_eq!(
            String::from_utf8(encode_rosbridge(&cmd)).unwrap(),
            r#"{"op":"publish","topic":"/joint_states","msg":{"name":["elbow"],"position":[-1.5707963267948966]}}"#
        );
    }

    // ── registries: same shape + integrity as the JS ──

    #[test]
    fn registry_counts_match_js() {
        assert_eq!(codecs().len(), 12);
        assert_eq!(targets().len(), 17);
    }

    #[test]
    fn every_target_codec_and_transport_exists() {
        for t in targets() {
            assert!(codec(t.codec).is_some(), "target {} → missing codec {}", t.id, t.codec);
            assert!(
                matches!(t.transport, "serial" | "ble" | "ws"),
                "target {} → unknown transport {}",
                t.id,
                t.transport
            );
        }
    }

    #[test]
    fn registry_metadata_spot_checks() {
        let f = codec("feetech-scs").unwrap();
        assert_eq!(f.label, "Feetech STS/SMS (LeRobot) [beta]");
        assert!(f.binary);
        assert_eq!(f.baud, Some(1_000_000));

        let fir = codec("firmata").unwrap();
        assert_eq!(fir.baud, Some(57_600));
        assert!(fir.init.is_some());

        let lego = target("lego").unwrap();
        let ble = lego.ble.unwrap();
        assert_eq!(ble.service, LEGO_SVC);
        assert_eq!(ble.characteristic, LEGO_CHAR);
        assert!(ble.with_response);

        let mqtt = target("mqtt").unwrap();
        assert_eq!(mqtt.transport, "ws");
        assert_eq!(mqtt.url, Some("ws://localhost:9001"));
        assert_eq!(mqtt.protocol, Some("mqtt"));

        assert_eq!(target("arduino").unwrap().firmware, Some("pwm"));
        assert_eq!(target("ros2").unwrap().url, Some("ws://localhost:9090"));
    }

    #[test]
    fn registry_dispatch_matches_direct_calls() {
        let cmd = t3().with_ids(vec![1, 2, 3]);
        assert_eq!((codec("pwm-text").unwrap().encode)(&cmd), encode_pwm_text(&cmd));
        assert_eq!((codec("dynamixel2").unwrap().encode)(&cmd), encode_dynamixel2(&cmd));
        let frames = codec("lego").unwrap().frames.unwrap();
        assert_eq!(frames(&cmd), lego_frames(&cmd));
    }
}
