use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use chrono::{DateTime, Local, Utc};
use futures_util::{SinkExt, StreamExt};
use nuvi_proto::{
    crypto::{
        decode_verifying_key, sign_registration_challenge, verify_unattended_key, HandshakeState,
        IdentityKeypair, Role, SessionCipher, VerifyingKey,
    },
    protocol::{
        decode_peer_message, decode_relay_frame, encode_relay_frame, sanitize_filename,
        ChatHistoryEntry, ClientRunMode, ConnectMode, MonitorInfo, PeerMessage, QualityPreset,
        RemoteCursorShape, RemoteQuickAction, ServerEnvelope, SessionPermissions, VideoFrame,
    },
    rotation::{is_locked_out, is_rotation_due, record_failed_attempt, reset_failures},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    capture::{enumerate_monitors, query_cursor_shape, ScreenCapturer},
    input::InputInjector,
    ipc::HelperCmd,
    overlay::OverlayHandle,
    service::{send_ctrl_alt_del, trigger_system_reboot, HelperBridge},
    storage::{append_chat_history, rotate_unattended_key, save_config, ClientConfig, StorageScope},
};

#[derive(Debug, Clone)]
pub struct PendingConsent {
    pub session_id: Uuid,
    pub tech_name: String,
    pub reason: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveSessionInfo {
    pub session_id: Uuid,
    pub tech_name: String,
    pub mode: ConnectMode,
    pub control_paused: bool,
}

#[derive(Debug)]
pub enum UiToNet {
    Reconnect,
    UpdateUnattendedStatus(bool),
    ConsentDecision {
        session_id: Uuid,
        accepted: bool,
        permissions: SessionPermissions,
    },
    TogglePauseControl(bool),
    DisconnectSession,
    SendChat(String),
}

#[derive(Debug, Clone)]
pub enum NetToUi {
    ConnectionState { online: bool, status: String },
    ConsentRequested(PendingConsent),
    ConsentCleared,
    SessionStarted(ActiveSessionInfo),
    SessionEnded { reason: String },
    KeyAutoRotated { new_key: String },
    DeviceIdSynced(String),
    Notice(String),
    ChatMessage {
        sender: String,
        text: String,
        sent_at: String,
    },
    ChatHistoryLoaded(Vec<ChatHistoryEntry>),
    FileProgress {
        filename: String,
        received: u64,
        total: u64,
        done: bool,
    },
}

struct IncomingFile {
    filename: String,
    path: PathBuf,
    file: File,
    hasher: Sha256,
    received: u64,
    total: u64,
}

const MAX_CONCURRENT_INCOMING_FILES: usize = 4;
const MAX_INCOMING_FILE_BYTES: u64 = 512 * 1024 * 1024;

fn downloads_dir() -> PathBuf {
    let base = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("Downloads").join("NUVI Remote")
}

fn create_unique_download_file(dir: &Path, clean_name: &str) -> std::io::Result<(PathBuf, String, File)> {
    let candidate = dir.join(clean_name);
    match OpenOptions::new().write(true).create_new(true).open(&candidate) {
        Ok(f) => return Ok((candidate, clean_name.to_string(), f)),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }

    let path_obj = Path::new(clean_name);
    let stem = path_obj
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("file");
    let ext = path_obj
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| format!(".{s}"))
        .unwrap_or_default();

    for i in 1..=999 {
        let numbered = format!("{stem} ({i}){ext}");
        let dest = dir.join(&numbered);
        match OpenOptions::new().write(true).create_new(true).open(&dest) {
            Ok(f) => return Ok((dest, numbered, f)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "Too many filename collisions",
    ))
}

pub fn spawn_network_worker(
    scope: StorageScope,
    run_mode: ClientRunMode,
    config: Arc<Mutex<ClientConfig>>,
    ui_rx: mpsc::UnboundedReceiver<UiToNet>,
    ui_tx: mpsc::UnboundedSender<NetToUi>,
    egui_ctx: egui::Context,
) {
    tokio::spawn(run_client_worker(
        scope,
        run_mode,
        config,
        ui_rx,
        ui_tx,
        Some(egui_ctx),
        None,
    ));
}

pub async fn run_client_worker(
    scope: StorageScope,
    run_mode: ClientRunMode,
    config: Arc<Mutex<ClientConfig>>,
    mut ui_rx: mpsc::UnboundedReceiver<UiToNet>,
    ui_tx: mpsc::UnboundedSender<NetToUi>,
    egui_ctx: Option<egui::Context>,
    mut service_helper: Option<(
        HelperBridge,
        mpsc::Receiver<VideoFrame>,
        mpsc::Receiver<RemoteCursorShape>,
    )>,
) {
    let mut backoff_secs = 1u64;

    loop {
        let (server_url, kp, hostname, unattended_enabled) = {
            let cfg = config.lock().unwrap();
            let kp = IdentityKeypair::from_bytes(&cfg.identity_secret);
            let host = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Windows-PC".into());
            (
                cfg.server_url.clone(),
                kp,
                host,
                cfg.unattended.enabled,
            )
        };
        let device_id = kp.device_id();

        let _ = ui_tx.send(NetToUi::ConnectionState {
            online: false,
            status: "Connecting...".to_string(),
        });
        if let Some(ctx) = &egui_ctx {
            ctx.request_repaint();
        }

        match connect_async(&server_url).await {
            Ok((ws, _)) => {
                backoff_secs = 1;
                let reconnect = run_connection(
                    scope,
                    run_mode,
                    ws,
                    &kp,
                    &device_id,
                    &hostname,
                    unattended_enabled,
                    &config,
                    &mut ui_rx,
                    &ui_tx,
                    egui_ctx.as_ref(),
                    service_helper.as_mut(),
                )
                .await;
                let _ = ui_tx.send(NetToUi::ConnectionState {
                    online: false,
                    status: "Disconnected".to_string(),
                });
                if let Some(ctx) = &egui_ctx {
                    ctx.request_repaint();
                }
                if reconnect {
                    continue;
                }
            }
            Err(e) => {
                warn!("Connect failed to {server_url}: {e}");
                let _ = ui_tx.send(NetToUi::ConnectionState {
                    online: false,
                    status: format!("Offline ({e})"),
                });
                if let Some(ctx) = &egui_ctx {
                    ctx.request_repaint();
                }
            }
        }

        let sleep = tokio::time::sleep(Duration::from_secs(backoff_secs));
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                _ = &mut sleep => {
                    backoff_secs = (backoff_secs * 2).min(20);
                    break;
                }
                cmd = ui_rx.recv() => {
                    match cmd {
                        Some(UiToNet::Reconnect) => {
                            backoff_secs = 1;
                            break;
                        }
                        None => return,
                        _ => {}
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_connection(
    scope: StorageScope,
    run_mode: ClientRunMode,
    ws: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    kp: &IdentityKeypair,
    device_id: &str,
    hostname: &str,
    unattended_enabled: bool,
    config: &Arc<Mutex<ClientConfig>>,
    ui_rx: &mut mpsc::UnboundedReceiver<UiToNet>,
    ui_tx: &mpsc::UnboundedSender<NetToUi>,
    egui_ctx: Option<&egui::Context>,
    service_helper: Option<&mut (
        HelperBridge,
        mpsc::Receiver<VideoFrame>,
        mpsc::Receiver<RemoteCursorShape>,
    )>,
) -> bool {
    let (mut ws_tx, mut ws_rx) = ws.split();
    let (out_tx, mut out_rx) = mpsc::channel::<Message>(256);

    let writer = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            if ws_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    let challenge_nonce = match tokio::time::timeout(Duration::from_secs(10), ws_rx.next()).await {
        Ok(Some(Ok(Message::Text(txt)))) => match serde_json::from_str::<ServerEnvelope>(&txt) {
            Ok(ServerEnvelope::ServerChallenge { nonce_b64 }) => nonce_b64,
            _ => {
                drop(out_tx);
                let _ = writer.await;
                return false;
            }
        },
        _ => {
            drop(out_tx);
            let _ = writer.await;
            return false;
        }
    };

    let Ok(signature_b64) = sign_registration_challenge(kp, device_id, &challenge_nonce) else {
        drop(out_tx);
        let _ = writer.await;
        return false;
    };

    let reg = ServerEnvelope::ClientRegister {
        device_id: device_id.to_string(),
        public_key_b64: kp.public_key_b64(),
        hostname: hostname.to_string(),
        os_version: "Windows".to_string(),
        mode: run_mode,
        unattended_enabled,
        signature_b64,
    };
    let _ = out_tx
        .send(Message::Text(serde_json::to_string(&reg).unwrap().into()))
        .await;

    struct ActiveState {
        session_id: Uuid,
        mode: ConnectMode,
        cipher: SessionCipher,
        monitors: Vec<MonitorInfo>,
        active_monitor: u8,
        quality: QualityPreset,
        permissions: SessionPermissions,
        control_paused: bool,
        injector: InputInjector,
        last_clip: String,
        incoming_files: HashMap<Uuid, IncomingFile>,
    }

    struct PendingAttended {
        session_id: Uuid,
        tech_name: String,
        cipher: SessionCipher,
        deadline: tokio::time::Instant,
    }

    struct PendingUnattended {
        session_id: Uuid,
        tech_name: String,
        cipher: SessionCipher,
        requested_permissions: SessionPermissions,
        deadline: tokio::time::Instant,
    }

    let mut handshake: Option<(Uuid, VerifyingKey, String, HandshakeState)> = None;
    let mut pre_intent_cipher: Option<(Uuid, String, SessionCipher)> = None;
    let mut active: Option<ActiveState> = None;
    let mut pending_attended: Option<PendingAttended> = None;
    let mut pending_unattended: Option<PendingUnattended> = None;

    let (svc_bridge, mut svc_frame_rx, mut svc_cursor_rx) = match service_helper {
        Some((b, frx, crx)) => (Some(b.clone()), Some(frx), Some(crx)),
        None => (None, None, None),
    };
    let is_service_helper = svc_bridge.is_some();

    let (local_frame_tx, mut local_frame_rx) = mpsc::channel::<VideoFrame>(4);
    let (local_cursor_tx, mut local_cursor_rx) = mpsc::channel::<RemoteCursorShape>(8);
    let (cap_stop_tx, _cap_stop_rx) = watch::channel(true);
    let (cap_cfg_tx, cap_cfg_rx) =
        watch::channel((0u8, QualityPreset::Auto, Vec::<MonitorInfo>::new()));

    let local_overlay = if !is_service_helper {
        Some(OverlayHandle::spawn())
    } else {
        None
    };

    if !is_service_helper {
        let mut stop_rx = cap_stop_tx.subscribe();
        let cfg_rx = cap_cfg_rx.clone();
        let f_tx = local_frame_tx.clone();
        let c_tx = local_cursor_tx.clone();
        tokio::spawn(async move {
            let mut capturer = ScreenCapturer::new();
            let mut last_cursor = RemoteCursorShape::Default;
            let mut cursor_every = 0u8;
            loop {
                if *stop_rx.borrow() {
                    if stop_rx.changed().await.is_err() {
                        break;
                    }
                    capturer.reset();
                    continue;
                }
                let (mon_idx, quality, monitors) = cfg_rx.borrow().clone();
                if let Some(mon) = monitors
                    .iter()
                    .find(|m| m.index == mon_idx)
                    .or_else(|| monitors.first())
                {
                    let mon_clone = mon.clone();
                    let cap_res =
                        tokio::task::block_in_place(|| capturer.capture_frame(&mon_clone, quality));
                    if let Ok(Some(vf)) = cap_res {
                        let _ = f_tx.try_send(vf);
                    }
                }
                cursor_every = cursor_every.wrapping_add(1);
                if cursor_every.is_multiple_of(3) {
                    let shape = query_cursor_shape();
                    if shape != last_cursor {
                        last_cursor = shape;
                        let _ = c_tx.try_send(shape);
                    }
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                    _ = stop_rx.changed() => {}
                }
            }
        });
    }

    let mut rotation_tick = tokio::time::interval(Duration::from_secs(30));
    let mut ping_tick = tokio::time::interval(Duration::from_secs(20));
    let mut clip_tick = tokio::time::interval(Duration::from_millis(550));
    let mut force_reconnect = false;

    let repaint = || {
        if let Some(ctx) = egui_ctx {
            ctx.request_repaint();
        }
    };

    loop {
        tokio::select! {
            _ = rotation_tick.tick() => {
                let rotated_key = {
                    let mut cfg = config.lock().unwrap();
                    if is_rotation_due(&cfg.unattended, Utc::now()) {
                        rotate_unattended_key(scope, &mut cfg).ok()
                    } else {
                        None
                    }
                };
                if let Some(new_key) = rotated_key {
                    let _ = ui_tx.send(NetToUi::KeyAutoRotated { new_key });
                    repaint();
                }
            }
            _ = ping_tick.tick() => {
                let _ = out_tx.send(Message::Text(serde_json::to_string(&ServerEnvelope::Ping).unwrap().into())).await;
            }
            _ = async {
                if let Some(p) = &pending_attended {
                    tokio::time::sleep_until(p.deadline).await;
                }
            }, if pending_attended.is_some() => {
                if let Some(mut pend) = pending_attended.take() {
                    let _ = ui_tx.send(NetToUi::ConsentCleared);
                    repaint();
                    let resp = PeerMessage::ConnectDecision {
                        accepted: false,
                        permissions: SessionPermissions::default(),
                        reject_reason: Some("Client request timed out".to_string()),
                        monitors: Vec::new(),
                        client_mode: run_mode,
                    };
                    if let Ok(ct) = pend.cipher.encrypt(&bincode::serialize(&resp).unwrap()) {
                        let _ = out_tx.send(Message::Binary(encode_relay_frame(pend.session_id, &ct).into())).await;
                    }
                }
            }
            _ = async {
                if let Some(p) = &pending_unattended {
                    tokio::time::sleep_until(p.deadline).await;
                }
            }, if pending_unattended.is_some() => {
                if let Some(mut pend) = pending_unattended.take() {
                    let resp = PeerMessage::ConnectDecision {
                        accepted: false,
                        permissions: SessionPermissions::default(),
                        reject_reason: Some("Unattended key prompt timed out".to_string()),
                        monitors: Vec::new(),
                        client_mode: run_mode,
                    };
                    if let Ok(ct) = pend.cipher.encrypt(&bincode::serialize(&resp).unwrap()) {
                        let _ = out_tx.send(Message::Binary(encode_relay_frame(pend.session_id, &ct).into())).await;
                    }
                }
            }
            _ = clip_tick.tick(), if active.is_some() => {
                if let Some(act) = active.as_mut() {
                    if act.permissions.allow_clipboard {
                        if let Ok(mut cb) = arboard::Clipboard::new() {
                            if let Ok(text) = cb.get_text() {
                                if !text.is_empty() && text != act.last_clip && text.len() <= 512 * 1024 {
                                    act.last_clip = text.clone();
                                    if let Ok(raw) = bincode::serialize(&PeerMessage::ClipboardText { text }) {
                                        if let Ok(ct) = act.cipher.encrypt(&raw) {
                                            let _ = out_tx.send(Message::Binary(encode_relay_frame(act.session_id, &ct).into())).await;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Some(vf) = async {
                if let Some(rx) = svc_frame_rx.as_mut() {
                    rx.recv().await
                } else {
                    local_frame_rx.recv().await
                }
            } => {
                if let Some(act) = active.as_mut() {
                    if let Ok(raw) = bincode::serialize(&PeerMessage::VideoFrame {
                        monitor_index: vf.monitor_index,
                        width: vf.width,
                        height: vf.height,
                        full_frame: vf.full_frame,
                        tiles: vf.tiles,
                    }) {
                        if let Ok(ct) = act.cipher.encrypt(&raw) {
                            let _ = out_tx.send(Message::Binary(encode_relay_frame(act.session_id, &ct).into())).await;
                        }
                    }
                }
            }
            Some(shape) = async {
                if let Some(crx) = svc_cursor_rx.as_mut() {
                    crx.recv().await
                } else {
                    local_cursor_rx.recv().await
                }
            } => {
                if let Some(act) = active.as_mut() {
                    if let Ok(raw) = bincode::serialize(&PeerMessage::CursorShape { shape }) {
                        if let Ok(ct) = act.cipher.encrypt(&raw) {
                            let _ = out_tx.send(Message::Binary(encode_relay_frame(act.session_id, &ct).into())).await;
                        }
                    }
                }
            }
            cmd = ui_rx.recv() => {
                match cmd {
                    Some(UiToNet::Reconnect) => {
                        force_reconnect = true;
                        break;
                    }
                    Some(UiToNet::UpdateUnattendedStatus(enabled)) => {
                        let env = ServerEnvelope::ClientStatusUpdate { unattended_enabled: enabled };
                        let _ = out_tx.send(Message::Text(serde_json::to_string(&env).unwrap().into())).await;
                    }
                    Some(UiToNet::ConsentDecision { session_id, accepted, permissions }) => {
                        if pending_attended.as_ref().map(|p| p.session_id == session_id).unwrap_or(false) {
                            let mut pend = pending_attended.take().unwrap();
                            let _ = ui_tx.send(NetToUi::ConsentCleared);
                            repaint();

                            if accepted {
                                let monitors = if let Some(bridge) = svc_bridge.as_ref() {
                                    bridge.get_monitors().await
                                } else {
                                    enumerate_monitors()
                                };
                                let resp = PeerMessage::ConnectDecision {
                                    accepted: true,
                                    permissions,
                                    reject_reason: None,
                                    monitors: monitors.clone(),
                                    client_mode: run_mode,
                                };
                                if let Ok(ct) = pend.cipher.encrypt(&bincode::serialize(&resp).unwrap()) {
                                    let _ = out_tx.send(Message::Binary(encode_relay_frame(session_id, &ct).into())).await;
                                }
                                if let Some(bridge) = svc_bridge.as_ref() {
                                    bridge.send_cmd(HelperCmd::Configure { monitor_index: 0, quality: QualityPreset::Auto }).await;
                                    bridge.send_cmd(HelperCmd::StartCapture).await;
                                } else {
                                    let _ = cap_cfg_tx.send((0, QualityPreset::Auto, monitors.clone()));
                                    let _ = cap_stop_tx.send(false);
                                }
                                active = Some(ActiveState {
                                    session_id,
                                    mode: ConnectMode::Attended,
                                    cipher: pend.cipher,
                                    monitors,
                                    active_monitor: 0,
                                    quality: QualityPreset::Auto,
                                    permissions,
                                    control_paused: false,
                                    injector: InputInjector::default(),
                                    last_clip: String::new(),
                                    incoming_files: HashMap::new(),
                                });
                                let _ = ui_tx.send(NetToUi::SessionStarted(ActiveSessionInfo {
                                    session_id,
                                    tech_name: pend.tech_name,
                                    mode: ConnectMode::Attended,
                                    control_paused: false,
                                }));
                                repaint();
                            } else {
                                let resp = PeerMessage::ConnectDecision {
                                    accepted: false,
                                    permissions: SessionPermissions::default(),
                                    reject_reason: Some("Client declined".to_string()),
                                    monitors: Vec::new(),
                                    client_mode: run_mode,
                                };
                                if let Ok(ct) = pend.cipher.encrypt(&bincode::serialize(&resp).unwrap()) {
                                    let _ = out_tx.send(Message::Binary(encode_relay_frame(session_id, &ct).into())).await;
                                }
                            }
                        }
                    }
                    Some(UiToNet::TogglePauseControl(paused)) => {
                        if let Some(act) = active.as_mut() {
                            act.control_paused = paused;
                            if paused {
                                if let Some(bridge) = svc_bridge.as_ref() {
                                    bridge.send_cmd(HelperCmd::ReleaseAllKeys).await;
                                } else {
                                    act.injector.release_all_keys();
                                }
                            }
                        }
                    }
                    Some(UiToNet::SendChat(text)) => {
                        if let Some(act) = active.as_mut() {
                            let sent_at = Local::now().format("%H:%M").to_string();
                            let msg = PeerMessage::ChatMessage {
                                sender: hostname.to_string(),
                                text: text.clone(),
                                sent_at: sent_at.clone(),
                            };
                            if let Ok(raw) = bincode::serialize(&msg) {
                                if let Ok(ct) = act.cipher.encrypt(&raw) {
                                    let _ = out_tx.send(Message::Binary(encode_relay_frame(act.session_id, &ct).into())).await;
                                }
                            }
                            append_chat_history(
                                scope,
                                ChatHistoryEntry {
                                    sender: "You".to_string(),
                                    text: text.clone(),
                                    sent_at: sent_at.clone(),
                                },
                            );
                            let _ = ui_tx.send(NetToUi::ChatMessage {
                                sender: "You".to_string(),
                                text,
                                sent_at,
                            });
                            repaint();
                        }
                    }
                    Some(UiToNet::DisconnectSession) => {
                        if let Some(mut act) = active.take() {
                            if let Some(bridge) = svc_bridge.as_ref() {
                                bridge.send_cmd(HelperCmd::StopCapture).await;
                            } else {
                                let _ = cap_stop_tx.send(true);
                                act.injector.release_all_keys();
                                if let Some(ov) = &local_overlay {
                                    ov.clear();
                                }
                            }
                            if let Ok(raw) = bincode::serialize(&PeerMessage::Disconnect { reason: "Client disconnected".to_string() }) {
                                if let Ok(ct) = act.cipher.encrypt(&raw) {
                                    let _ = out_tx.send(Message::Binary(encode_relay_frame(act.session_id, &ct).into())).await;
                                }
                            }
                            let closed = ServerEnvelope::SessionClosed { session_id: act.session_id, reason: "Client disconnected".to_string() };
                            let _ = out_tx.send(Message::Text(serde_json::to_string(&closed).unwrap().into())).await;
                            maybe_rotate_after_session(scope, config, act.mode, ui_tx);
                            let _ = ui_tx.send(NetToUi::SessionEnded { reason: "Disconnected by you".to_string() });
                            repaint();
                        }
                    }
                    None => break,
                }
            }
            ws_item = ws_rx.next() => {
                let Some(Ok(msg)) = ws_item else {
                    break;
                };
                match msg {
                    Message::Text(txt) => {
                        if let Ok(env) = serde_json::from_str::<ServerEnvelope>(&txt) {
                            match env {
                                ServerEnvelope::ClientRegistered { ok, message, .. } => {
                                    let _ = ui_tx.send(NetToUi::ConnectionState {
                                        online: ok,
                                        status: if ok { "ONLINE".to_string() } else { message },
                                    });
                                    repaint();
                                }
                                ServerEnvelope::SessionPairing { session_id, peer_public_key_b64, peer_name, .. } => {
                                    if active.is_some()
                                        || pending_attended.is_some()
                                        || pending_unattended.is_some()
                                        || handshake.is_some()
                                        || pre_intent_cipher.is_some()
                                    {
                                        let closed = ServerEnvelope::SessionClosed {
                                            session_id,
                                            reason: "Client is busy".to_string(),
                                        };
                                        let _ = out_tx.send(Message::Text(serde_json::to_string(&closed).unwrap().into())).await;
                                        continue;
                                    }
                                    if let Ok(expected_vk) = decode_verifying_key(&peer_public_key_b64) {
                                        let hs = HandshakeState::new(session_id, Role::Client);
                                        let reply = ServerEnvelope::SessionHandshake {
                                            session_id,
                                            ephemeral_x25519_pub_b64: hs.ephemeral_pub_b64(),
                                            identity_ed25519_pub_b64: kp.public_key_b64(),
                                            signature_b64: hs.sign_ephemeral(kp),
                                        };
                                        let _ = out_tx.send(Message::Text(serde_json::to_string(&reply).unwrap().into())).await;
                                        handshake = Some((session_id, expected_vk, peer_name, hs));
                                    }
                                }
                                ServerEnvelope::SessionHandshake { session_id, ephemeral_x25519_pub_b64, identity_ed25519_pub_b64, signature_b64 } => {
                                    if let Some((hs_sid, expected_vk, peer_name, hs)) = handshake.take() {
                                        if hs_sid == session_id {
                                            match hs.complete(&expected_vk, &ephemeral_x25519_pub_b64, &identity_ed25519_pub_b64, &signature_b64) {
                                                Ok(cipher) => {
                                                    pre_intent_cipher = Some((session_id, peer_name, cipher));
                                                }
                                                Err(e) => warn!("Handshake verify failed: {e}"),
                                            }
                                        }
                                    }
                                }
                                ServerEnvelope::SessionClosed { session_id, reason } => {
                                    if active.as_ref().map(|a| a.session_id == session_id).unwrap_or(false) {
                                        let mut act = active.take().unwrap();
                                        if let Some(bridge) = svc_bridge.as_ref() {
                                            bridge.send_cmd(HelperCmd::StopCapture).await;
                                        } else {
                                            let _ = cap_stop_tx.send(true);
                                            act.injector.release_all_keys();
                                            if let Some(ov) = &local_overlay {
                                                ov.clear();
                                            }
                                        }
                                        maybe_rotate_after_session(scope, config, act.mode, ui_tx);
                                        let _ = ui_tx.send(NetToUi::SessionEnded { reason });
                                        repaint();
                                    }
                                    if pending_attended.as_ref().map(|p| p.session_id == session_id).unwrap_or(false) {
                                        pending_attended = None;
                                        let _ = ui_tx.send(NetToUi::ConsentCleared);
                                        repaint();
                                    }
                                    if pending_unattended.as_ref().map(|p| p.session_id == session_id).unwrap_or(false) {
                                        pending_unattended = None;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Message::Binary(bin) => {
                        let Some((sid, payload)) = decode_relay_frame(&bin) else {
                            continue;
                        };
                        if let Some((pre_sid, peer_name, mut cipher)) = pre_intent_cipher.take() {
                            if pre_sid == sid {
                                if let Ok(pt) = cipher.decrypt(payload) {
                                    if let Ok(PeerMessage::ConnectIntent { mode: _, tech_name, reason, unattended_key, requested_permissions }) = decode_peer_message(&pt) {
                                        let display_tech = if tech_name.is_empty() { peer_name } else { tech_name };
                                        let unattended_on = config.lock().unwrap().unattended.enabled;
                                        if unattended_on {
                                            let has_key = unattended_key
                                                .as_deref()
                                                .map(|k| !k.trim().is_empty())
                                                .unwrap_or(false);
                                            if has_key {
                                                match verify_unattended_attempt(scope, config, unattended_key.as_deref()) {
                                                    Ok(()) => {
                                                        let monitors = if let Some(bridge) = svc_bridge.as_ref() {
                                                            bridge.get_monitors().await
                                                        } else {
                                                            enumerate_monitors()
                                                        };
                                                        let resp = PeerMessage::ConnectDecision {
                                                            accepted: true,
                                                            permissions: requested_permissions,
                                                            reject_reason: None,
                                                            monitors: monitors.clone(),
                                                            client_mode: run_mode,
                                                        };
                                                        if let Ok(ct) = cipher.encrypt(&bincode::serialize(&resp).unwrap()) {
                                                            let _ = out_tx.send(Message::Binary(encode_relay_frame(sid, &ct).into())).await;
                                                        }
                                                        if let Some(bridge) = svc_bridge.as_ref() {
                                                            bridge.send_cmd(HelperCmd::Configure { monitor_index: 0, quality: QualityPreset::Auto }).await;
                                                            bridge.send_cmd(HelperCmd::StartCapture).await;
                                                        } else {
                                                            let _ = cap_cfg_tx.send((0, QualityPreset::Auto, monitors.clone()));
                                                            let _ = cap_stop_tx.send(false);
                                                        }
                                                        active = Some(ActiveState {
                                                            session_id: sid,
                                                            mode: ConnectMode::Unattended,
                                                            cipher,
                                                            monitors,
                                                            active_monitor: 0,
                                                            quality: QualityPreset::Auto,
                                                            permissions: requested_permissions,
                                                            control_paused: false,
                                                            injector: InputInjector::default(),
                                                            last_clip: String::new(),
                                                            incoming_files: HashMap::new(),
                                                        });
                                                        let _ = ui_tx.send(NetToUi::SessionStarted(ActiveSessionInfo {
                                                            session_id: sid,
                                                            tech_name: display_tech,
                                                            mode: ConnectMode::Unattended,
                                                            control_paused: false,
                                                        }));
                                                        repaint();
                                                    }
                                                    Err(rej) => {
                                                        if rej.contains("Locked out") {
                                                            let resp = PeerMessage::ConnectDecision {
                                                                accepted: false,
                                                                permissions: SessionPermissions::default(),
                                                                reject_reason: Some(rej.clone()),
                                                                monitors: Vec::new(),
                                                                client_mode: run_mode,
                                                            };
                                                            if let Ok(ct) = cipher.encrypt(&bincode::serialize(&resp).unwrap()) {
                                                                let _ = out_tx.send(Message::Binary(encode_relay_frame(sid, &ct).into())).await;
                                                            }
                                                            let _ = ui_tx.send(NetToUi::Notice(format!("Blocked unattended login: {rej}")));
                                                            repaint();
                                                        } else {
                                                            let challenge = PeerMessage::AuthChallenge {
                                                                requires_unattended_key: true,
                                                                message: rej,
                                                            };
                                                            if let Ok(ct) = cipher.encrypt(&bincode::serialize(&challenge).unwrap()) {
                                                                let _ = out_tx.send(Message::Binary(encode_relay_frame(sid, &ct).into())).await;
                                                            }
                                                            pending_unattended = Some(PendingUnattended {
                                                                session_id: sid,
                                                                tech_name: display_tech,
                                                                cipher,
                                                                requested_permissions,
                                                                deadline: tokio::time::Instant::now() + Duration::from_secs(120),
                                                            });
                                                        }
                                                    }
                                                }
                                            } else {
                                                let challenge = PeerMessage::AuthChallenge {
                                                    requires_unattended_key: true,
                                                    message: "Unattended Access is enabled on this client. Enter its rotating key to connect.".to_string(),
                                                };
                                                if let Ok(ct) = cipher.encrypt(&bincode::serialize(&challenge).unwrap()) {
                                                    let _ = out_tx.send(Message::Binary(encode_relay_frame(sid, &ct).into())).await;
                                                }
                                                pending_unattended = Some(PendingUnattended {
                                                    session_id: sid,
                                                    tech_name: display_tech,
                                                    cipher,
                                                    requested_permissions,
                                                    deadline: tokio::time::Instant::now() + Duration::from_secs(120),
                                                });
                                            }
                                        } else {
                                            pending_attended = Some(PendingAttended {
                                                session_id: sid,
                                                tech_name: display_tech.clone(),
                                                cipher,
                                                deadline: tokio::time::Instant::now() + Duration::from_secs(60),
                                            });
                                            let _ = ui_tx.send(NetToUi::ConsentRequested(PendingConsent {
                                                session_id: sid,
                                                tech_name: display_tech,
                                                reason,
                                                expires_at: Utc::now() + chrono::Duration::seconds(60),
                                            }));
                                            repaint();
                                        }
                                    }
                                    continue;
                                }
                            }
                            pre_intent_cipher = Some((pre_sid, peer_name, cipher));
                        }

                        if let Some(mut pend) = pending_unattended.take() {
                            if pend.session_id == sid {
                                if let Ok(pt) = pend.cipher.decrypt(payload) {
                                    if let Ok(PeerMessage::AuthResponse { unattended_key }) = decode_peer_message(&pt) {
                                        match verify_unattended_attempt(scope, config, Some(&unattended_key)) {
                                            Ok(()) => {
                                                let monitors = if let Some(bridge) = svc_bridge.as_ref() {
                                                    bridge.get_monitors().await
                                                } else {
                                                    enumerate_monitors()
                                                };
                                                let resp = PeerMessage::ConnectDecision {
                                                    accepted: true,
                                                    permissions: pend.requested_permissions,
                                                    reject_reason: None,
                                                    monitors: monitors.clone(),
                                                    client_mode: run_mode,
                                                };
                                                if let Ok(ct) = pend.cipher.encrypt(&bincode::serialize(&resp).unwrap()) {
                                                    let _ = out_tx.send(Message::Binary(encode_relay_frame(sid, &ct).into())).await;
                                                }
                                                if let Some(bridge) = svc_bridge.as_ref() {
                                                    bridge.send_cmd(HelperCmd::Configure { monitor_index: 0, quality: QualityPreset::Auto }).await;
                                                    bridge.send_cmd(HelperCmd::StartCapture).await;
                                                } else {
                                                    let _ = cap_cfg_tx.send((0, QualityPreset::Auto, monitors.clone()));
                                                    let _ = cap_stop_tx.send(false);
                                                }
                                                active = Some(ActiveState {
                                                    session_id: sid,
                                                    mode: ConnectMode::Unattended,
                                                    cipher: pend.cipher,
                                                    monitors,
                                                    active_monitor: 0,
                                                    quality: QualityPreset::Auto,
                                                    permissions: pend.requested_permissions,
                                                    control_paused: false,
                                                    injector: InputInjector::default(),
                                                    last_clip: String::new(),
                                                    incoming_files: HashMap::new(),
                                                });
                                                let _ = ui_tx.send(NetToUi::SessionStarted(ActiveSessionInfo {
                                                    session_id: sid,
                                                    tech_name: pend.tech_name,
                                                    mode: ConnectMode::Unattended,
                                                    control_paused: false,
                                                }));
                                                repaint();
                                            }
                                            Err(rej) => {
                                                if rej.contains("Locked out") {
                                                    let resp = PeerMessage::ConnectDecision {
                                                        accepted: false,
                                                        permissions: SessionPermissions::default(),
                                                        reject_reason: Some(rej.clone()),
                                                        monitors: Vec::new(),
                                                        client_mode: run_mode,
                                                    };
                                                    if let Ok(ct) = pend.cipher.encrypt(&bincode::serialize(&resp).unwrap()) {
                                                        let _ = out_tx.send(Message::Binary(encode_relay_frame(sid, &ct).into())).await;
                                                    }
                                                    let _ = ui_tx.send(NetToUi::Notice(format!("Blocked unattended login: {rej}")));
                                                    repaint();
                                                } else {
                                                    let challenge = PeerMessage::AuthChallenge {
                                                        requires_unattended_key: true,
                                                        message: rej,
                                                    };
                                                    if let Ok(ct) = pend.cipher.encrypt(&bincode::serialize(&challenge).unwrap()) {
                                                        let _ = out_tx.send(Message::Binary(encode_relay_frame(sid, &ct).into())).await;
                                                    }
                                                    pend.deadline = tokio::time::Instant::now() + Duration::from_secs(120);
                                                    pending_unattended = Some(pend);
                                                }
                                            }
                                        }
                                        continue;
                                    }
                                }
                            }
                            pending_unattended = Some(pend);
                        }

                        if let Some(act) = active.as_mut() {
                            if act.session_id == sid {
                                if let Ok(pt) = act.cipher.decrypt(payload) {
                                    if let Ok(pmsg) = decode_peer_message(&pt) {
                                        match pmsg {
                                            PeerMessage::MouseInput { monitor_index, kind } => {
                                                if act.permissions.allow_control && !act.control_paused {
                                                    if let Some(bridge) = svc_bridge.as_ref() {
                                                        bridge.send_cmd(HelperCmd::Mouse { monitor_index, kind }).await;
                                                    } else if let Some(mon) = act.monitors.iter().find(|m| m.index == monitor_index).or_else(|| act.monitors.first()) {
                                                        act.injector.apply_mouse(mon, kind);
                                                    }
                                                }
                                            }
                                            PeerMessage::KeyInput { scancode, extended, pressed, unicode } => {
                                                if act.permissions.allow_control && !act.control_paused {
                                                    let key = nuvi_proto::protocol::KeyInput { scancode, extended, pressed, unicode };
                                                    if let Some(bridge) = svc_bridge.as_ref() {
                                                        bridge.send_cmd(HelperCmd::Key(key)).await;
                                                    } else {
                                                        act.injector.apply_key(key);
                                                    }
                                                }
                                            }
                                            PeerMessage::ReleaseAllKeys => {
                                                if let Some(bridge) = svc_bridge.as_ref() {
                                                    bridge.send_cmd(HelperCmd::ReleaseAllKeys).await;
                                                } else {
                                                    act.injector.release_all_keys();
                                                }
                                            }
                                            PeerMessage::SelectMonitor { monitor_index } => {
                                                act.active_monitor = monitor_index;
                                                if let Some(bridge) = svc_bridge.as_ref() {
                                                    bridge.send_cmd(HelperCmd::Configure { monitor_index: act.active_monitor, quality: act.quality }).await;
                                                } else {
                                                    let _ = cap_cfg_tx.send((act.active_monitor, act.quality, act.monitors.clone()));
                                                }
                                            }
                                            PeerMessage::SetQuality { preset } => {
                                                act.quality = preset;
                                                if let Some(bridge) = svc_bridge.as_ref() {
                                                    bridge.send_cmd(HelperCmd::Configure { monitor_index: act.active_monitor, quality: act.quality }).await;
                                                } else {
                                                    let _ = cap_cfg_tx.send((act.active_monitor, act.quality, act.monitors.clone()));
                                                }
                                            }
                                            PeerMessage::SendCtrlAltDel => {
                                                if act.permissions.allow_control && !act.control_paused {
                                                    let msg = if run_mode == ClientRunMode::Service {
                                                        match send_ctrl_alt_del() {
                                                            Ok(()) => "Sent Ctrl+Alt+Del (SAS)".to_string(),
                                                            Err(e) => format!("Ctrl+Alt+Del failed: {e}"),
                                                        }
                                                    } else {
                                                        "Ctrl+Alt+Del requires 'Install for Unattended Service' on the client.".to_string()
                                                    };
                                                    if let Ok(raw) = bincode::serialize(&PeerMessage::SystemNotice { message: msg }) {
                                                        if let Ok(ct) = act.cipher.encrypt(&raw) {
                                                            let _ = out_tx.send(Message::Binary(encode_relay_frame(act.session_id, &ct).into())).await;
                                                        }
                                                    }
                                                }
                                            }
                                            PeerMessage::RebootClient => {
                                                if act.permissions.allow_control && !act.control_paused {
                                                    if run_mode == ClientRunMode::Service {
                                                        if let Ok(raw) = bincode::serialize(&PeerMessage::SystemNotice { message: "Client PC is rebooting...".to_string() }) {
                                                            if let Ok(ct) = act.cipher.encrypt(&raw) {
                                                                let _ = out_tx.send(Message::Binary(encode_relay_frame(act.session_id, &ct).into())).await;
                                                            }
                                                        }
                                                        if let Some(bridge) = svc_bridge.as_ref() {
                                                            bridge.send_cmd(HelperCmd::ReleaseAllKeys).await;
                                                        }
                                                        let _ = trigger_system_reboot();
                                                    } else if let Ok(raw) = bincode::serialize(&PeerMessage::SystemNotice { message: "Remote Reboot requires 'Install for Unattended Service' on the client.".to_string() }) {
                                                        if let Ok(ct) = act.cipher.encrypt(&raw) {
                                                            let _ = out_tx.send(Message::Binary(encode_relay_frame(act.session_id, &ct).into())).await;
                                                        }
                                                    }
                                                }
                                            }
                                            PeerMessage::ClipboardText { text } => {
                                                if act.permissions.allow_clipboard && text != act.last_clip {
                                                    act.last_clip = text.clone();
                                                    if let Ok(mut cb) = arboard::Clipboard::new() {
                                                        let _ = cb.set_text(text);
                                                    }
                                                }
                                            }
                                            PeerMessage::FileOffer { transfer_id, filename, total_bytes } => {
                                                if !act.permissions.allow_control || act.control_paused {
                                                    let ack = PeerMessage::FileAck {
                                                        transfer_id,
                                                        ok: false,
                                                        message: "File transfer disabled in View-Only / paused mode".to_string(),
                                                    };
                                                    if let Ok(raw) = bincode::serialize(&ack) {
                                                        if let Ok(ct) = act.cipher.encrypt(&raw) {
                                                            let _ = out_tx.send(Message::Binary(encode_relay_frame(act.session_id, &ct).into())).await;
                                                        }
                                                    }
                                                } else if total_bytes > MAX_INCOMING_FILE_BYTES || act.incoming_files.len() >= MAX_CONCURRENT_INCOMING_FILES {
                                                    let ack = PeerMessage::FileAck {
                                                        transfer_id,
                                                        ok: false,
                                                        message: "File transfer rejected (size or concurrency limit exceeded)".to_string(),
                                                    };
                                                    if let Ok(raw) = bincode::serialize(&ack) {
                                                        if let Ok(ct) = act.cipher.encrypt(&raw) {
                                                            let _ = out_tx.send(Message::Binary(encode_relay_frame(act.session_id, &ct).into())).await;
                                                        }
                                                    }
                                                } else {
                                                    let clean = sanitize_filename(&filename);
                                                    let dir = downloads_dir();
                                                    let _ = std::fs::create_dir_all(&dir);
                                                    if let Ok((dest, unique_name, f)) = create_unique_download_file(&dir, &clean) {
                                                        act.incoming_files.insert(
                                                            transfer_id,
                                                            IncomingFile {
                                                                filename: unique_name.clone(),
                                                                path: dest,
                                                                file: f,
                                                                hasher: Sha256::new(),
                                                                received: 0,
                                                                total: total_bytes,
                                                            },
                                                        );
                                                        let _ = ui_tx.send(NetToUi::FileProgress {
                                                            filename: unique_name,
                                                            received: 0,
                                                            total: total_bytes,
                                                            done: false,
                                                        });
                                                        repaint();
                                                    }
                                                }
                                            }
                                            PeerMessage::FileChunk { transfer_id, offset: _, data } => {
                                                if !act.permissions.allow_control || act.control_paused {
                                                    if let Some(inc) = act.incoming_files.remove(&transfer_id) {
                                                        let _ = std::fs::remove_file(&inc.path);
                                                    }
                                                    continue;
                                                }
                                                let mut exceeded = false;
                                                if let Some(inc) = act.incoming_files.get_mut(&transfer_id) {
                                                    let next_received = inc.received.saturating_add(data.len() as u64);
                                                    if next_received > inc.total || next_received > MAX_INCOMING_FILE_BYTES {
                                                        exceeded = true;
                                                    } else if inc.file.write_all(&data).is_ok() {
                                                        inc.hasher.update(&data);
                                                        inc.received = next_received;
                                                        let _ = ui_tx.send(NetToUi::FileProgress {
                                                            filename: inc.filename.clone(),
                                                            received: inc.received,
                                                            total: inc.total,
                                                            done: false,
                                                        });
                                                    }
                                                }
                                                if exceeded {
                                                    if let Some(inc) = act.incoming_files.remove(&transfer_id) {
                                                        drop(inc.file);
                                                        let _ = std::fs::remove_file(&inc.path);
                                                    }
                                                    let ack = PeerMessage::FileAck {
                                                        transfer_id,
                                                        ok: false,
                                                        message: "File exceeded declared size limit".to_string(),
                                                    };
                                                    if let Ok(raw) = bincode::serialize(&ack) {
                                                        if let Ok(ct) = act.cipher.encrypt(&raw) {
                                                            let _ = out_tx.send(Message::Binary(encode_relay_frame(act.session_id, &ct).into())).await;
                                                        }
                                                    }
                                                }
                                            }
                                            PeerMessage::FileComplete { transfer_id, sha256_hex } => {
                                                if let Some(mut inc) = act.incoming_files.remove(&transfer_id) {
                                                    let _ = inc.file.flush();
                                                    let digest = hex::encode(inc.hasher.finalize());
                                                    let ok = digest.eq_ignore_ascii_case(&sha256_hex);
                                                    let msg = if ok {
                                                        format!("Saved to {}", inc.path.display())
                                                    } else {
                                                        let _ = std::fs::remove_file(&inc.path);
                                                        "Checksum mismatch; file discarded".to_string()
                                                    };
                                                    let ack = PeerMessage::FileAck { transfer_id, ok, message: msg.clone() };
                                                    if let Ok(raw) = bincode::serialize(&ack) {
                                                        if let Ok(ct) = act.cipher.encrypt(&raw) {
                                                            let _ = out_tx.send(Message::Binary(encode_relay_frame(act.session_id, &ct).into())).await;
                                                        }
                                                    }
                                                    let _ = ui_tx.send(NetToUi::FileProgress {
                                                        filename: inc.filename,
                                                        received: inc.received,
                                                        total: inc.total,
                                                        done: true,
                                                    });
                                                    let _ = ui_tx.send(NetToUi::Notice(msg));
                                                    repaint();
                                                }
                                            }
                                            PeerMessage::ChatMessage { sender, text, sent_at } => {
                                                append_chat_history(
                                                    scope,
                                                    ChatHistoryEntry {
                                                        sender: sender.clone(),
                                                        text: text.clone(),
                                                        sent_at: sent_at.clone(),
                                                    },
                                                );
                                                let _ = ui_tx.send(NetToUi::ChatMessage { sender, text, sent_at });
                                                repaint();
                                            }
                                            PeerMessage::QuickAction { action } => {
                                                if act.permissions.allow_control && !act.control_paused {
                                                    let note = execute_quick_action(action, run_mode);
                                                    if let Ok(raw) = bincode::serialize(&PeerMessage::SystemNotice { message: note }) {
                                                        if let Ok(ct) = act.cipher.encrypt(&raw) {
                                                            let _ = out_tx.send(Message::Binary(encode_relay_frame(act.session_id, &ct).into())).await;
                                                        }
                                                    }
                                                }
                                            }
                                            PeerMessage::Annotation { monitor_index, kind } => {
                                                if let Some(bridge) = svc_bridge.as_ref() {
                                                    bridge.send_cmd(HelperCmd::Annotation { monitor_index, kind }).await;
                                                } else if let Some(ov) = &local_overlay {
                                                    if let Some(mon) = act.monitors.iter().find(|m| m.index == monitor_index).or_else(|| act.monitors.first()).cloned() {
                                                        ov.apply(mon, kind);
                                                    }
                                                }
                                            }
                                            PeerMessage::SessionPing { sent_ms } => {
                                                if let Ok(raw) = bincode::serialize(&PeerMessage::SessionPong { sent_ms }) {
                                                    if let Ok(ct) = act.cipher.encrypt(&raw) {
                                                        let _ = out_tx.send(Message::Binary(encode_relay_frame(act.session_id, &ct).into())).await;
                                                    }
                                                }
                                            }
                                            PeerMessage::Disconnect { reason } => {
                                                let mut ended = active.take().unwrap();
                                                if let Some(bridge) = svc_bridge.as_ref() {
                                                    bridge.send_cmd(HelperCmd::StopCapture).await;
                                                } else {
                                                    let _ = cap_stop_tx.send(true);
                                                    ended.injector.release_all_keys();
                                                    if let Some(ov) = &local_overlay {
                                                        ov.clear();
                                                    }
                                                }
                                                maybe_rotate_after_session(scope, config, ended.mode, ui_tx);
                                                let _ = ui_tx.send(NetToUi::SessionEnded { reason });
                                                repaint();
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        }
    }

    if let Some(bridge) = svc_bridge.as_ref() {
        bridge.send_cmd(HelperCmd::StopCapture).await;
    } else {
        let _ = cap_stop_tx.send(true);
        if let Some(ov) = &local_overlay {
            ov.clear();
        }
    }
    if let Some(mut act) = active.take() {
        act.injector.release_all_keys();
        let _ = ui_tx.send(NetToUi::SessionEnded {
            reason: "Connection lost".to_string(),
        });
    }
    drop(out_tx);
    let _ = writer.await;
    info!("Client WS loop ended");
    force_reconnect
}

fn execute_quick_action(action: RemoteQuickAction, run_mode: ClientRunMode) -> String {
    match action {
        RemoteQuickAction::OpenTaskManager => {
            if run_mode == ClientRunMode::Service {
                "Task Manager cannot be launched from Session 0 Service; use Ctrl+Alt+Del instead."
                    .to_string()
            } else {
                let _ = std::process::Command::new(crate::service::system32_exe("taskmgr.exe"))
                    .spawn();
                "Opened Task Manager".to_string()
            }
        }
        RemoteQuickAction::LockWorkstation => {
            #[cfg(windows)]
            unsafe {
                let _ = windows::Win32::System::Shutdown::LockWorkStation();
            }
            "Locked workstation".to_string()
        }
        RemoteQuickAction::RequestElevation => {
            if run_mode == ClientRunMode::Service {
                "Already running elevated as SYSTEM Service.".to_string()
            } else {
                #[cfg(windows)]
                {
                    if let Ok(exe) = std::env::current_exe() {
                        use windows::{
                            core::PCWSTR,
                            Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOW},
                        };
                        let exe_w: Vec<u16> =
                            exe.to_string_lossy().encode_utf16().chain(Some(0)).collect();
                        let verb_w: Vec<u16> = "runas".encode_utf16().chain(Some(0)).collect();
                        unsafe {
                            let _ = ShellExecuteW(
                                None,
                                PCWSTR(verb_w.as_ptr()),
                                PCWSTR(exe_w.as_ptr()),
                                None,
                                None,
                                SW_SHOW,
                            );
                        }
                    }
                }
                "Requested elevation prompt on client PC".to_string()
            }
        }
    }
}

fn verify_unattended_attempt(
    scope: StorageScope,
    config: &Arc<Mutex<ClientConfig>>,
    candidate: Option<&str>,
) -> Result<(), String> {
    let mut cfg = config.lock().unwrap();
    let now = Utc::now();

    if !cfg.unattended.enabled {
        return Err("Unattended access is disabled on this client".to_string());
    }
    if let Some(secs) = is_locked_out(&cfg.unattended, now) {
        return Err(format!("Locked out for {secs}s after repeated failed attempts"));
    }
    if is_rotation_due(&cfg.unattended, now) {
        let _ = rotate_unattended_key(scope, &mut cfg);
        return Err("Unattended key rotated due to schedule; ask client for new key".to_string());
    }
    let Some(stored_hash) = cfg.unattended.key_hash.clone() else {
        return Err("No unattended key configured".to_string());
    };
    let Some(cand) = candidate else {
        record_failed_attempt(&mut cfg.unattended, now);
        let _ = save_config(scope, &cfg);
        return Err("Missing unattended key".to_string());
    };

    if verify_unattended_key(cand, &stored_hash) {
        reset_failures(&mut cfg.unattended);
        let _ = save_config(scope, &cfg);
        Ok(())
    } else {
        record_failed_attempt(&mut cfg.unattended, now);
        let _ = save_config(scope, &cfg);
        Err("Invalid unattended key".to_string())
    }
}

fn maybe_rotate_after_session(
    scope: StorageScope,
    config: &Arc<Mutex<ClientConfig>>,
    mode: ConnectMode,
    ui_tx: &mpsc::UnboundedSender<NetToUi>,
) {
    if mode != ConnectMode::Unattended {
        return;
    }
    let rotated = {
        let mut cfg = config.lock().unwrap();
        if cfg.unattended.enabled && cfg.unattended.rotate_after_session {
            rotate_unattended_key(scope, &mut cfg).ok()
        } else {
            None
        }
    };
    if let Some(new_key) = rotated {
        let _ = ui_tx.send(NetToUi::KeyAutoRotated { new_key });
    }
}
