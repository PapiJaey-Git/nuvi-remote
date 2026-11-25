use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const DEFAULT_SERVER_URL: &str = match option_env!("NUVI_DEFAULT_SERVER_URL") {
    Some(url) => url,
    None => "ws://127.0.0.1:8765/ws",
};
pub const HAS_BAKED_SERVER_URL: bool = option_env!("NUVI_DEFAULT_SERVER_URL").is_some();

pub fn is_legacy_local_url(url: &str) -> bool {
    let trimmed = url.trim();
    trimmed.is_empty()
        || trimmed == "ws://127.0.0.1:8080/ws"
        || trimmed == "ws://127.0.0.1:8765/ws"
}

/// Normalizes a domain, IP, `nuvi://` setup code, or `http(s)://`/`ws(s)://` URL into a
/// canonical WebSocket relay URL ending in `/ws`.
pub fn normalize_server_url(raw: &str) -> String {
    let mut s = raw.trim();
    if let Some(rest) = s.strip_prefix("nuvi://").or_else(|| s.strip_prefix("NUVI://")) {
        s = rest.trim();
    }
    if s.is_empty() {
        return DEFAULT_SERVER_URL.to_string();
    }

    let (scheme, rest) = if let Some(r) = s.strip_prefix("wss://") {
        ("wss", r)
    } else if let Some(r) = s.strip_prefix("ws://") {
        ("ws", r)
    } else if let Some(r) = s.strip_prefix("https://") {
        ("wss", r)
    } else if let Some(r) = s.strip_prefix("http://") {
        ("ws", r)
    } else {
        let bare = s.trim_end_matches('/').trim_end_matches("/ws").trim_end_matches('/');
        let host_only = bare.split(':').next().unwrap_or(bare);
        let is_ip_or_local = host_only.eq_ignore_ascii_case("localhost")
            || host_only.parse::<std::net::Ipv4Addr>().is_ok();
        if is_ip_or_local {
            if bare.contains(':') {
                return format!("ws://{bare}/ws");
            }
            return format!("ws://{bare}:8765/ws");
        }
        return format!("wss://{bare}/ws");
    };

    let trimmed_rest = rest.trim_end_matches('/');
    if trimmed_rest.ends_with("/ws") {
        format!("{scheme}://{trimmed_rest}")
    } else if trimmed_rest.contains('/') {
        format!("{scheme}://{trimmed_rest}")
    } else {
        format!("{scheme}://{trimmed_rest}/ws")
    }
}

/// Formats a canonical `ws://` or `wss://` relay URL as a shareable `nuvi://` setup code.
pub fn format_setup_code(ws_url: &str) -> String {
    let norm = normalize_server_url(ws_url);
    let stripped = norm
        .strip_prefix("wss://")
        .or_else(|| norm.strip_prefix("ws://"))
        .unwrap_or(&norm);
    let stripped = stripped.strip_suffix("/ws").unwrap_or(stripped);
    format!("nuvi://{stripped}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientRunMode {
    Portable,
    Service,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectMode {
    Attended,
    Unattended,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatHistoryEntry {
    pub sender: String,
    pub text: String,
    pub sent_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QualityPreset {
    Auto,
    Sharp,
    Smooth,
}

impl QualityPreset {
    pub fn jpeg_quality(self) -> u8 {
        match self {
            QualityPreset::Auto => 72,
            QualityPreset::Sharp => 88,
            QualityPreset::Smooth => 52,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            QualityPreset::Auto => "Auto",
            QualityPreset::Sharp => "Sharp",
            QualityPreset::Smooth => "Smooth",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionPermissions {
    pub allow_control: bool,
    pub allow_clipboard: bool,
}

impl Default for SessionPermissions {
    fn default() -> Self {
        Self {
            allow_control: true,
            allow_clipboard: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorInfo {
    pub index: u8,
    pub name: String,
    pub left: i32,
    pub top: i32,
    pub width: u32,
    pub height: u32,
    pub primary: bool,
}

/// Control messages exchanged in JSON over WebSocket Text frames with `nuvi-server`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerEnvelope {
    ServerChallenge {
        nonce_b64: String,
    },
    ClientRegister {
        device_id: String,
        public_key_b64: String,
        hostname: String,
        os_version: String,
        mode: ClientRunMode,
        unattended_enabled: bool,
        #[serde(default)]
        signature_b64: String,
    },
    ClientRegistered {
        ok: bool,
        device_id: String,
        message: String,
    },
    ClientStatusUpdate {
        unattended_enabled: bool,
    },
    HostAuth {
        tech_key: String,
        tech_name: String,
        host_public_key_b64: String,
    },
    HostAuthed {
        ok: bool,
        tech_id: String,
        message: String,
    },
    HostConnectRequest {
        target_device_id: String,
    },
    SessionPairing {
        session_id: Uuid,
        peer_device_id: String,
        peer_public_key_b64: String,
        peer_name: String,
    },
    SessionHandshake {
        session_id: Uuid,
        ephemeral_x25519_pub_b64: String,
        identity_ed25519_pub_b64: String,
        signature_b64: String,
    },
    SessionError {
        code: String,
        message: String,
    },
    SessionClosed {
        session_id: Uuid,
        reason: String,
    },
    Ping,
    Pong,
}

/// Binary WebSocket frame framing: `[16 bytes UUID][ciphertext]`.
pub fn encode_relay_frame(session_id: Uuid, ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + ciphertext.len());
    out.extend_from_slice(session_id.as_bytes());
    out.extend_from_slice(ciphertext);
    out
}

pub fn decode_relay_frame(bytes: &[u8]) -> Option<(Uuid, &[u8])> {
    if bytes.len() < 16 {
        return None;
    }
    let id_bytes: [u8; 16] = bytes[..16].try_into().ok()?;
    Some((Uuid::from_bytes(id_bytes), &bytes[16..]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
    X1,
    X2,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum MouseEventKind {
    Move { nx: f32, ny: f32 },
    Button { button: MouseButton, pressed: bool },
    Wheel { dx: i16, dy: i16 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VideoTile {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
    pub jpeg_data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VideoFrame {
    pub monitor_index: u8,
    pub width: u16,
    pub height: u16,
    pub full_frame: bool,
    pub tiles: Vec<VideoTile>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct KeyInput {
    pub scancode: u16,
    pub extended: bool,
    pub pressed: bool,
    pub unicode: Option<char>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemoteCursorShape {
    Default,
    Text,
    Hand,
    Wait,
    Crosshair,
    ResizeNS,
    ResizeEW,
    ResizeNWSE,
    ResizeNESW,
    Move,
    NotAllowed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemoteQuickAction {
    OpenTaskManager,
    LockWorkstation,
    RequestElevation,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum AnnotationKind {
    Laser { nx: f32, ny: f32 },
    Stroke { x1: f32, y1: f32, x2: f32, y2: f32 },
    Clear,
}

pub const MAX_PEER_MESSAGE_BYTES: u64 = 16 * 1024 * 1024;

pub fn decode_peer_message(bytes: &[u8]) -> anyhow::Result<PeerMessage> {
    use bincode::Options;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(MAX_PEER_MESSAGE_BYTES)
        .deserialize(bytes)
        .map_err(|e| anyhow::anyhow!("peer message decode failed: {e}"))
}

pub fn sanitize_filename(raw: &str) -> String {
    let base = raw
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("file.bin")
        .trim();
    let mut cleaned: String = base
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') {
                '_'
            } else {
                c
            }
        })
        .collect();
    cleaned = cleaned.trim_end_matches(['.', ' ']).to_string();
    if cleaned.chars().count() > 180 {
        cleaned = cleaned.chars().take(180).collect();
        cleaned = cleaned.trim_end_matches(['.', ' ']).to_string();
    }
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        return "received_file.bin".to_string();
    }
    let stem = cleaned.split('.').next().unwrap_or("").to_ascii_uppercase();
    let is_reserved = matches!(
        stem.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    );
    if is_reserved {
        format!("_{cleaned}")
    } else {
        cleaned
    }
}

/// End-to-end encrypted peer messages (`bincode` inside `ChaCha20-Poly1305`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PeerMessage {
    ConnectIntent {
        mode: ConnectMode,
        tech_name: String,
        reason: String,
        unattended_key: Option<String>,
        requested_permissions: SessionPermissions,
    },
    ConnectDecision {
        accepted: bool,
        permissions: SessionPermissions,
        reject_reason: Option<String>,
        monitors: Vec<MonitorInfo>,
        client_mode: ClientRunMode,
    },
    VideoFrame {
        monitor_index: u8,
        width: u16,
        height: u16,
        full_frame: bool,
        tiles: Vec<VideoTile>,
    },
    MouseInput {
        monitor_index: u8,
        kind: MouseEventKind,
    },
    KeyInput {
        scancode: u16,
        extended: bool,
        pressed: bool,
        unicode: Option<char>,
    },
    ReleaseAllKeys,
    SelectMonitor {
        monitor_index: u8,
    },
    SetQuality {
        preset: QualityPreset,
    },
    UpdatePermissions {
        permissions: SessionPermissions,
    },
    SendCtrlAltDel,
    RebootClient,
    SystemNotice {
        message: String,
    },
    SessionPing {
        sent_ms: u64,
    },
    SessionPong {
        sent_ms: u64,
    },
    Disconnect {
        reason: String,
    },
    ClipboardText {
        text: String,
    },
    FileOffer {
        transfer_id: Uuid,
        filename: String,
        total_bytes: u64,
    },
    FileChunk {
        transfer_id: Uuid,
        offset: u64,
        data: Vec<u8>,
    },
    FileComplete {
        transfer_id: Uuid,
        sha256_hex: String,
    },
    FileAck {
        transfer_id: Uuid,
        ok: bool,
        message: String,
    },
    ChatMessage {
        sender: String,
        text: String,
        sent_at: String,
    },
    CursorShape {
        shape: RemoteCursorShape,
    },
    QuickAction {
        action: RemoteQuickAction,
    },
    Annotation {
        monitor_index: u8,
        kind: AnnotationKind,
    },
    AuthChallenge {
        requires_unattended_key: bool,
        message: String,
    },
    AuthResponse {
        unattended_key: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnlineDeviceSummary {
    pub device_id: String,
    pub hostname: String,
    pub os_version: String,
    pub mode: ClientRunMode,
    pub unattended_enabled: bool,
    pub connected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub event: String,
    pub session_id: Option<Uuid>,
    pub tech_id: Option<String>,
    pub tech_name: Option<String>,
    pub target_device_id: Option<String>,
    pub detail: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_control_peer_messages_roundtrip_json() {
        for msg in [
            PeerMessage::SendCtrlAltDel,
            PeerMessage::RebootClient,
            PeerMessage::SystemNotice {
                message: "Rebooting".to_string(),
            },
        ] {
            let s = serde_json::to_string(&msg).unwrap();
            let d: PeerMessage = serde_json::from_str(&s).unwrap();
            match (msg, d) {
                (PeerMessage::SendCtrlAltDel, PeerMessage::SendCtrlAltDel) => {}
                (PeerMessage::RebootClient, PeerMessage::RebootClient) => {}
                (
                    PeerMessage::SystemNotice { message: a },
                    PeerMessage::SystemNotice { message: b },
                ) => assert_eq!(a, b),
                _ => panic!("mismatch"),
            }
        }
    }

    #[test]
    fn session_feature_peer_messages_and_sanitize_filename() {
        assert_eq!(sanitize_filename(r"C:\evil\..\..\test<1>.exe"), "test_1_.exe");
        assert_eq!(sanitize_filename(".."), "received_file.bin");

        let tid = Uuid::new_v4();
        for msg in [
            PeerMessage::ClipboardText {
                text: "hello".into(),
            },
            PeerMessage::FileOffer {
                transfer_id: tid,
                filename: "setup.exe".into(),
                total_bytes: 1024,
            },
            PeerMessage::FileChunk {
                transfer_id: tid,
                offset: 0,
                data: vec![1, 2, 3],
            },
            PeerMessage::FileComplete {
                transfer_id: tid,
                sha256_hex: "abcd".into(),
            },
            PeerMessage::FileAck {
                transfer_id: tid,
                ok: true,
                message: "Saved".into(),
            },
            PeerMessage::ChatMessage {
                sender: "TechUser".into(),
                text: "Hi".into(),
                sent_at: "17:00".into(),
            },
            PeerMessage::CursorShape {
                shape: RemoteCursorShape::Hand,
            },
            PeerMessage::QuickAction {
                action: RemoteQuickAction::OpenTaskManager,
            },
            PeerMessage::Annotation {
                monitor_index: 0,
                kind: AnnotationKind::Laser { nx: 0.5, ny: 0.25 },
            },
        ] {
            let s = serde_json::to_string(&msg).unwrap();
            let d: PeerMessage = serde_json::from_str(&s).unwrap();
            let s2 = serde_json::to_string(&d).unwrap();
            assert_eq!(s, s2);
        }
    }

    #[test]
    fn chat_history_entry_roundtrip() {
        let entry = ChatHistoryEntry {
            sender: "TechUser".into(),
            text: "Connected session chat".into(),
            sent_at: "17:30".into(),
        };
        let s = serde_json::to_string(&entry).unwrap();
        let d: ChatHistoryEntry = serde_json::from_str(&s).unwrap();
        assert_eq!(d.sender, "TechUser");
        assert_eq!(d.text, "Connected session chat");
        assert_eq!(d.sent_at, "17:30");
    }

    #[test]
    fn auth_challenge_roundtrip() {
        for msg in [
            PeerMessage::AuthChallenge {
                requires_unattended_key: true,
                message: "Enter unattended key".into(),
            },
            PeerMessage::AuthResponse {
                unattended_key: "NUVI-1234-5678-ABCD".into(),
            },
        ] {
            let s = serde_json::to_string(&msg).unwrap();
            let d: PeerMessage = serde_json::from_str(&s).unwrap();
            let s2 = serde_json::to_string(&d).unwrap();
            assert_eq!(s, s2);
        }
    }

    #[test]
    fn normalize_and_setup_code_roundtrip() {
        assert_eq!(
            normalize_server_url("remote.example.com"),
            "wss://remote.example.com/ws"
        );
        assert_eq!(
            normalize_server_url("nuvi://remote.example.com"),
            "wss://remote.example.com/ws"
        );
        assert_eq!(
            normalize_server_url("192.168.1.50"),
            "ws://192.168.1.50:8765/ws"
        );
        assert_eq!(
            normalize_server_url("100.64.0.10:9000"),
            "ws://100.64.0.10:9000/ws"
        );
        assert_eq!(
            normalize_server_url("nuvi://192.168.1.50:8765"),
            "ws://192.168.1.50:8765/ws"
        );
        assert_eq!(
            normalize_server_url("https://relay.example.com/"),
            "wss://relay.example.com/ws"
        );
        assert_eq!(
            format_setup_code("wss://remote.example.com/ws"),
            "nuvi://remote.example.com"
        );
        assert_eq!(
            format_setup_code("ws://192.168.1.50:8765/ws"),
            "nuvi://192.168.1.50:8765"
        );
    }

    #[test]
    fn sanitize_filename_blocks_reserved_and_trailing_dots() {
        assert_eq!(sanitize_filename("CON.txt"), "_CON.txt");
        assert_eq!(sanitize_filename("nul"), "_nul");
        assert_eq!(sanitize_filename("COM1.log"), "_COM1.log");
        assert_eq!(sanitize_filename("report.pdf..  "), "report.pdf");
    }

    #[test]
    fn decode_peer_message_enforces_size_bound() {
        let msg = PeerMessage::SystemNotice {
            message: "ok".to_string(),
        };
        let encoded = bincode::serialize(&msg).unwrap();
        let decoded = decode_peer_message(&encoded).unwrap();
        assert!(matches!(decoded, PeerMessage::SystemNotice { ref message } if message == "ok"));

        // Crafted PeerMessage::ClipboardText (variant 15 in little-endian u32) with huge string length
        let mut evil = Vec::new();
        evil.extend_from_slice(&15u32.to_le_bytes());
        evil.extend_from_slice(&(u64::MAX / 2).to_le_bytes());
        assert!(decode_peer_message(&evil).is_err());
    }
}
