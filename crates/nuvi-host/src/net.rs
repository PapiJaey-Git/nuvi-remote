use std::{
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Result};
use futures_util::{SinkExt, StreamExt};
use nuvi_proto::{
    crypto::{decode_verifying_key, device_id_from_pubkey, HandshakeState, IdentityKeypair, Role},
    protocol::{
        decode_peer_message, decode_relay_frame, encode_relay_frame, ClientRunMode, ConnectMode,
        MonitorInfo, OnlineDeviceSummary, PeerMessage, RemoteCursorShape, ServerEnvelope,
        SessionPermissions, VideoFrame,
    },
};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ConnectParams {
    pub server_url: String,
    pub tech_key: String,
    pub tech_name: String,
    pub identity_secret: [u8; 32],
    pub target_device_id: String,
    pub reason: String,
    pub unattended_key: Option<String>,
    pub pinned_peer_key_b64: Option<String>,
}

#[derive(Debug)]
pub enum HostUiCmd {
    SubmitUnattendedKey(String),
    SendPeer(PeerMessage),
    SendFile(PathBuf),
    SendClipboard(String),
    Disconnect,
}

#[derive(Debug)]
pub enum HostNetEvent {
    Status {
        tab_id: Uuid,
        message: String,
    },
    UnattendedKeyRequired {
        tab_id: Uuid,
        message: String,
    },
    PeerKeyVerified {
        device_id: String,
        public_key_b64: String,
    },
    SessionEstablished {
        tab_id: Uuid,
        device_id: String,
        mode: ConnectMode,
        client_mode: ClientRunMode,
        monitors: Vec<MonitorInfo>,
        permissions: SessionPermissions,
    },
    VideoFrame {
        tab_id: Uuid,
        frame: VideoFrame,
    },
    RttMs {
        tab_id: Uuid,
        rtt: u64,
    },
    SystemNotice {
        tab_id: Uuid,
        message: String,
    },
    ClipboardReceived {
        tab_id: Uuid,
        text: String,
    },
    ChatMessage {
        tab_id: Uuid,
        sender: String,
        text: String,
        sent_at: String,
    },
    FileProgress {
        tab_id: Uuid,
        filename: String,
        sent: u64,
        total: u64,
        done: bool,
    },
    FileAck {
        tab_id: Uuid,
        ok: bool,
        message: String,
    },
    CursorShape {
        tab_id: Uuid,
        shape: RemoteCursorShape,
    },
    SessionEnded {
        tab_id: Uuid,
        reason: String,
    },
    ServerHealth(Result<String, String>),
    OnlineDevices(Result<Vec<OnlineDeviceSummary>, String>),
}

pub fn ws_to_http_base(ws_url: &str) -> String {
    let trimmed = ws_url.trim().trim_end_matches('/');
    let without_ws = trimmed.strip_suffix("/ws").unwrap_or(trimmed);
    if let Some(rest) = without_ws.strip_prefix("wss://") {
        format!("https://{rest}")
    } else if let Some(rest) = without_ws.strip_prefix("ws://") {
        format!("http://{rest}")
    } else {
        without_ws.to_string()
    }
}

pub fn spawn_probe_server(
    server_ws_url: String,
    tx: mpsc::UnboundedSender<HostNetEvent>,
    ctx: egui::Context,
) {
    tokio::spawn(async move {
        let base = ws_to_http_base(&server_ws_url);
        let url = format!("{base}/health");
        let client = reqwest::Client::new();
        let res = client.get(&url).timeout(Duration::from_secs(6)).send().await;
        let out = match res {
            Ok(resp) if resp.status().is_success() => match resp.json::<serde_json::Value>().await {
                Ok(v) => Ok(v
                    .get("auth_mode")
                    .and_then(|m| m.as_str())
                    .unwrap_or("private")
                    .to_string()),
                Err(e) => Err(format!("Invalid /health JSON: {e}")),
            },
            Ok(resp) => Err(format!("Server returned {}", resp.status())),
            Err(e) => Err(format!("Request failed: {e}")),
        };
        let _ = tx.send(HostNetEvent::ServerHealth(out));
        ctx.request_repaint();
    });
}

pub fn spawn_fetch_devices(
    server_ws_url: String,
    tech_key: String,
    tx: mpsc::UnboundedSender<HostNetEvent>,
    ctx: egui::Context,
) {
    tokio::spawn(async move {
        let base = ws_to_http_base(&server_ws_url);
        let url = format!("{base}/api/devices");
        let client = reqwest::Client::new();
        let res = client
            .get(&url)
            .bearer_auth(tech_key.trim())
            .timeout(Duration::from_secs(6))
            .send()
            .await;

        let out = match res {
            Ok(resp) if resp.status().is_success() => resp
                .json::<Vec<OnlineDeviceSummary>>()
                .await
                .map_err(|e| format!("Invalid response: {e}")),
            Ok(resp) => Err(format!("Server returned {}", resp.status())),
            Err(e) => Err(format!("Request failed: {e}")),
        };
        let _ = tx.send(HostNetEvent::OnlineDevices(out));
        ctx.request_repaint();
    });
}

pub fn spawn_host_session(
    tab_id: Uuid,
    params: ConnectParams,
    mut cmd_rx: mpsc::UnboundedReceiver<HostUiCmd>,
    ev_tx: mpsc::UnboundedSender<HostNetEvent>,
    ctx: egui::Context,
) {
    tokio::spawn(async move {
        let mut attempts = 0u32;
        loop {
            match run_session(tab_id, params.clone(), &mut cmd_rx, &ev_tx, &ctx).await {
                Ok(true) => {
                    attempts += 1;
                    if attempts > 36 {
                        let _ = ev_tx.send(HostNetEvent::SessionEnded {
                            tab_id,
                            reason: "Reboot reconnect timed out".to_string(),
                        });
                        ctx.request_repaint();
                        break;
                    }
                    let _ = ev_tx.send(HostNetEvent::Status {
                        tab_id,
                        message: format!(
                            "Client rebooting — reconnecting (attempt {attempts})..."
                        ),
                    });
                    ctx.request_repaint();

                    let sleep = tokio::time::sleep(Duration::from_secs(5));
                    tokio::pin!(sleep);
                    let mut cancelled = false;
                    loop {
                        tokio::select! {
                            _ = &mut sleep => break,
                            c = cmd_rx.recv() => {
                                if matches!(c, Some(HostUiCmd::Disconnect) | None) {
                                    cancelled = true;
                                    break;
                                }
                            }
                        }
                    }
                    if cancelled {
                        let _ = ev_tx.send(HostNetEvent::SessionEnded {
                            tab_id,
                            reason: "Cancelled".to_string(),
                        });
                        ctx.request_repaint();
                        break;
                    }
                }
                Ok(false) => break,
                Err(e) => {
                    if attempts > 0 && attempts <= 36 {
                        attempts += 1;
                        let _ = ev_tx.send(HostNetEvent::Status {
                            tab_id,
                            message: format!(
                                "Waiting for client to finish rebooting (attempt {attempts})..."
                            ),
                        });
                        ctx.request_repaint();
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                    let _ = ev_tx.send(HostNetEvent::SessionEnded {
                        tab_id,
                        reason: format!("{e}"),
                    });
                    ctx.request_repaint();
                    break;
                }
            }
        }
    });
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

async fn run_session(
    tab_id: Uuid,
    params: ConnectParams,
    cmd_rx: &mut mpsc::UnboundedReceiver<HostUiCmd>,
    ev_tx: &mpsc::UnboundedSender<HostNetEvent>,
    ctx: &egui::Context,
) -> Result<bool> {
    let _ = ev_tx.send(HostNetEvent::Status {
        tab_id,
        message: "Connecting to server...".to_string(),
    });
    ctx.request_repaint();

    let (ws, _) = connect_async(&params.server_url)
        .await
        .map_err(|e| anyhow!("WebSocket connect failed: {e}"))?;
    let (mut ws_tx, mut ws_rx) = ws.split();
    let (out_tx, mut out_rx) = mpsc::channel::<Message>(256);

    let writer = tokio::spawn(async move {
        while let Some(m) = out_rx.recv().await {
            if ws_tx.send(m).await.is_err() {
                break;
            }
        }
    });

    let kp = IdentityKeypair::from_bytes(&params.identity_secret);
    let auth = ServerEnvelope::HostAuth {
        tech_key: params.tech_key.clone(),
        tech_name: params.tech_name.clone(),
        host_public_key_b64: kp.public_key_b64(),
    };
    out_tx
        .send(Message::Text(serde_json::to_string(&auth)?.into()))
        .await?;

    loop {
        let Some(Ok(msg)) = ws_rx.next().await else {
            return Err(anyhow!("Server closed before auth"));
        };
        if let Message::Text(txt) = msg {
            if let Ok(ServerEnvelope::HostAuthed { ok, message, .. }) =
                serde_json::from_str::<ServerEnvelope>(&txt)
            {
                if !ok {
                    return Err(anyhow!("Auth failed: {message}"));
                }
                break;
            }
        }
    }

    let _ = ev_tx.send(HostNetEvent::Status {
        tab_id,
        message: "Requesting client pairing...".to_string(),
    });
    ctx.request_repaint();

    out_tx
        .send(Message::Text(
            serde_json::to_string(&ServerEnvelope::HostConnectRequest {
                target_device_id: params.target_device_id.clone(),
            })?
            .into(),
        ))
        .await?;

    let (session_id, peer_vk, peer_pub_b64) = loop {
        let Some(Ok(msg)) = ws_rx.next().await else {
            return Err(anyhow!("Disconnected while pairing"));
        };
        if let Message::Text(txt) = msg {
            if let Ok(env) = serde_json::from_str::<ServerEnvelope>(&txt) {
                match env {
                    ServerEnvelope::SessionPairing {
                        session_id,
                        peer_public_key_b64,
                        ..
                    } => {
                        let vk = decode_verifying_key(&peer_public_key_b64)?;
                        let derived_id = device_id_from_pubkey(&vk);
                        if derived_id != params.target_device_id {
                            return Err(anyhow!(
                                "Relay returned public key for {derived_id}, expected {}",
                                params.target_device_id
                            ));
                        }
                        if let Some(pinned) = &params.pinned_peer_key_b64 {
                            if pinned != &peer_public_key_b64 {
                                return Err(anyhow!(
                                    "SECURITY WARNING: Peer identity key changed for {}! Possible MitM or reinstalled client.",
                                    params.target_device_id
                                ));
                            }
                        }
                        break (session_id, vk, peer_public_key_b64);
                    }
                    ServerEnvelope::SessionError { message, .. } => {
                        return Err(anyhow!(message));
                    }
                    _ => {}
                }
            }
        }
    };

    let hs = HandshakeState::new(session_id, Role::Host);
    let hs_msg = ServerEnvelope::SessionHandshake {
        session_id,
        ephemeral_x25519_pub_b64: hs.ephemeral_pub_b64(),
        identity_ed25519_pub_b64: kp.public_key_b64(),
        signature_b64: hs.sign_ephemeral(&kp),
    };
    out_tx
        .send(Message::Text(serde_json::to_string(&hs_msg)?.into()))
        .await?;

    let mut cipher = loop {
        let Some(Ok(msg)) = ws_rx.next().await else {
            return Err(anyhow!("Disconnected during handshake"));
        };
        if let Message::Text(txt) = msg {
            if let Ok(ServerEnvelope::SessionHandshake {
                session_id: sid,
                ephemeral_x25519_pub_b64,
                identity_ed25519_pub_b64,
                signature_b64,
            }) = serde_json::from_str::<ServerEnvelope>(&txt)
            {
                if sid == session_id {
                    break hs.complete(
                        &peer_vk,
                        &ephemeral_x25519_pub_b64,
                        &identity_ed25519_pub_b64,
                        &signature_b64,
                    )?;
                }
            }
        }
    };

    let _ = ev_tx.send(HostNetEvent::PeerKeyVerified {
        device_id: params.target_device_id.clone(),
        public_key_b64: peer_pub_b64,
    });

    let mut effective_mode = if params
        .unattended_key
        .as_deref()
        .map(|k| !k.trim().is_empty())
        .unwrap_or(false)
    {
        ConnectMode::Unattended
    } else {
        ConnectMode::Attended
    };
    let intent = PeerMessage::ConnectIntent {
        mode: effective_mode,
        tech_name: params.tech_name.clone(),
        reason: params.reason.clone(),
        unattended_key: params.unattended_key.clone(),
        requested_permissions: SessionPermissions::default(),
    };
    let ct = cipher.encrypt(&bincode::serialize(&intent)?)?;
    out_tx
        .send(Message::Binary(encode_relay_frame(session_id, &ct).into()))
        .await?;

    let wait_label = if effective_mode == ConnectMode::Unattended {
        "Verifying unattended key..."
    } else {
        "Connecting to client..."
    };
    let _ = ev_tx.send(HostNetEvent::Status {
        tab_id,
        message: wait_label.to_string(),
    });
    ctx.request_repaint();

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(HostUiCmd::SubmitUnattendedKey(key)) => {
                        effective_mode = ConnectMode::Unattended;
                        let resp = PeerMessage::AuthResponse { unattended_key: key };
                        if let Ok(ct) = cipher.encrypt(&bincode::serialize(&resp)?) {
                            let _ = out_tx.send(Message::Binary(encode_relay_frame(session_id, &ct).into())).await;
                        }
                        let _ = ev_tx.send(HostNetEvent::Status {
                            tab_id,
                            message: "Verifying unattended key...".to_string(),
                        });
                        ctx.request_repaint();
                    }
                    Some(HostUiCmd::Disconnect) | None => {
                        let _ = out_tx.send(Message::Text(serde_json::to_string(&ServerEnvelope::SessionClosed {
                            session_id,
                            reason: "Host cancelled".to_string(),
                        })?.into())).await;
                        drop(out_tx);
                        let _ = writer.await;
                        return Err(anyhow!("Cancelled"));
                    }
                    _ => {}
                }
            }
            item = ws_rx.next() => {
                let Some(Ok(msg)) = item else {
                    return Err(anyhow!("Connection closed while waiting for client"));
                };
                match msg {
                    Message::Binary(bin) => {
                        if let Some((sid, payload)) = decode_relay_frame(&bin) {
                            if sid == session_id {
                                let pt = cipher.decrypt(payload)?;
                                match decode_peer_message(&pt)? {
                                    PeerMessage::AuthChallenge { requires_unattended_key: true, message } => {
                                        effective_mode = ConnectMode::Unattended;
                                        let _ = ev_tx.send(HostNetEvent::UnattendedKeyRequired {
                                            tab_id,
                                            message,
                                        });
                                        ctx.request_repaint();
                                    }
                                    PeerMessage::ConnectDecision { accepted, permissions, reject_reason, monitors, client_mode } => {
                                        if !accepted {
                                            return Err(anyhow!(reject_reason.unwrap_or_else(|| "Connection rejected".to_string())));
                                        }
                                        let _ = ev_tx.send(HostNetEvent::SessionEstablished {
                                            tab_id,
                                            device_id: params.target_device_id.clone(),
                                            mode: effective_mode,
                                            client_mode,
                                            monitors,
                                            permissions,
                                        });
                                        ctx.request_repaint();
                                        break;
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    Message::Text(txt) => {
                        if let Ok(ServerEnvelope::SessionClosed { reason, .. }) = serde_json::from_str::<ServerEnvelope>(&txt) {
                            return Err(anyhow!(reason));
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    let mut ping_tick = tokio::time::interval(Duration::from_secs(3));
    let end_reason;
    let mut expect_reboot = false;

    loop {
        tokio::select! {
            _ = ping_tick.tick() => {
                let ping = PeerMessage::SessionPing { sent_ms: now_ms() };
                if let Ok(ct) = cipher.encrypt(&bincode::serialize(&ping).unwrap_or_default()) {
                    let _ = out_tx.send(Message::Binary(encode_relay_frame(session_id, &ct).into())).await;
                }
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(HostUiCmd::SendPeer(pmsg)) => {
                        if matches!(pmsg, PeerMessage::RebootClient) {
                            expect_reboot = true;
                        }
                        if let Ok(raw) = bincode::serialize(&pmsg) {
                            if let Ok(ct) = cipher.encrypt(&raw) {
                                let _ = out_tx.send(Message::Binary(encode_relay_frame(session_id, &ct).into())).await;
                            }
                        }
                    }
                    Some(HostUiCmd::SendClipboard(text)) => {
                        if let Ok(raw) = bincode::serialize(&PeerMessage::ClipboardText { text }) {
                            if let Ok(ct) = cipher.encrypt(&raw) {
                                let _ = out_tx.send(Message::Binary(encode_relay_frame(session_id, &ct).into())).await;
                            }
                        }
                    }
                    Some(HostUiCmd::SendFile(path)) => {
                        if let Ok(bytes) = tokio::fs::read(&path).await {
                            let filename = path
                                .file_name()
                                .map(|n| n.to_string_lossy().to_string())
                                .unwrap_or_else(|| "file.bin".to_string());
                            let total = bytes.len() as u64;
                            let tid = Uuid::new_v4();
                            let offer = PeerMessage::FileOffer {
                                transfer_id: tid,
                                filename: filename.clone(),
                                total_bytes: total,
                            };
                            if let Ok(ct) = cipher.encrypt(&bincode::serialize(&offer).unwrap_or_default()) {
                                let _ = out_tx.send(Message::Binary(encode_relay_frame(session_id, &ct).into())).await;
                            }
                            let mut hasher = Sha256::new();
                            let mut sent = 0u64;
                            for chunk in bytes.chunks(128 * 1024) {
                                hasher.update(chunk);
                                let msg = PeerMessage::FileChunk {
                                    transfer_id: tid,
                                    offset: sent,
                                    data: chunk.to_vec(),
                                };
                                if let Ok(ct) = cipher.encrypt(&bincode::serialize(&msg).unwrap_or_default()) {
                                    let _ = out_tx.send(Message::Binary(encode_relay_frame(session_id, &ct).into())).await;
                                }
                                sent += chunk.len() as u64;
                                let _ = ev_tx.send(HostNetEvent::FileProgress {
                                    tab_id,
                                    filename: filename.clone(),
                                    sent,
                                    total,
                                    done: false,
                                });
                                ctx.request_repaint();
                            }
                            let sha256_hex = hex::encode(hasher.finalize());
                            let done_msg = PeerMessage::FileComplete {
                                transfer_id: tid,
                                sha256_hex,
                            };
                            if let Ok(ct) = cipher.encrypt(&bincode::serialize(&done_msg).unwrap_or_default()) {
                                let _ = out_tx.send(Message::Binary(encode_relay_frame(session_id, &ct).into())).await;
                            }
                            let _ = ev_tx.send(HostNetEvent::FileProgress {
                                tab_id,
                                filename,
                                sent,
                                total,
                                done: true,
                            });
                            ctx.request_repaint();
                        } else {
                            let _ = ev_tx.send(HostNetEvent::SystemNotice {
                                tab_id,
                                message: format!("Failed to read file {}", path.display()),
                            });
                            ctx.request_repaint();
                        }
                    }
                    Some(HostUiCmd::SubmitUnattendedKey(_)) => {}
                    Some(HostUiCmd::Disconnect) | None => {
                        expect_reboot = false;
                        if let Ok(raw) = bincode::serialize(&PeerMessage::Disconnect { reason: "Tech disconnected".to_string() }) {
                            if let Ok(ct) = cipher.encrypt(&raw) {
                                let _ = out_tx.send(Message::Binary(encode_relay_frame(session_id, &ct).into())).await;
                            }
                        }
                        let _ = out_tx.send(Message::Text(serde_json::to_string(&ServerEnvelope::SessionClosed {
                            session_id,
                            reason: "Tech disconnected".to_string(),
                        })?.into())).await;
                        end_reason = "Disconnected".to_string();
                        break;
                    }
                }
            }
            item = ws_rx.next() => {
                let Some(Ok(msg)) = item else {
                    end_reason = "Relay connection lost".to_string();
                    break;
                };
                match msg {
                    Message::Binary(bin) => {
                        if let Some((sid, payload)) = decode_relay_frame(&bin) {
                            if sid == session_id {
                                if let Ok(pt) = cipher.decrypt(payload) {
                                    if let Ok(pmsg) = decode_peer_message(&pt) {
                                        match pmsg {
                                            PeerMessage::VideoFrame { monitor_index, width, height, full_frame, tiles } => {
                                                let _ = ev_tx.send(HostNetEvent::VideoFrame {
                                                    tab_id,
                                                    frame: VideoFrame { monitor_index, width, height, full_frame, tiles },
                                                });
                                                ctx.request_repaint();
                                            }
                                            PeerMessage::SessionPong { sent_ms } => {
                                                let rtt = now_ms().saturating_sub(sent_ms);
                                                let _ = ev_tx.send(HostNetEvent::RttMs { tab_id, rtt });
                                            }
                                            PeerMessage::SystemNotice { message } => {
                                                if message.contains("rebooting") {
                                                    expect_reboot = true;
                                                }
                                                let _ = ev_tx.send(HostNetEvent::SystemNotice { tab_id, message });
                                                ctx.request_repaint();
                                            }
                                            PeerMessage::ClipboardText { text } => {
                                                let _ = ev_tx.send(HostNetEvent::ClipboardReceived { tab_id, text });
                                            }
                                            PeerMessage::ChatMessage { sender, text, sent_at } => {
                                                let _ = ev_tx.send(HostNetEvent::ChatMessage { tab_id, sender, text, sent_at });
                                                ctx.request_repaint();
                                            }
                                            PeerMessage::FileAck { ok, message, .. } => {
                                                let _ = ev_tx.send(HostNetEvent::FileAck { tab_id, ok, message });
                                                ctx.request_repaint();
                                            }
                                            PeerMessage::CursorShape { shape } => {
                                                let _ = ev_tx.send(HostNetEvent::CursorShape { tab_id, shape });
                                                ctx.request_repaint();
                                            }
                                            PeerMessage::Disconnect { reason } => {
                                                end_reason = reason;
                                                break;
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Message::Text(txt) => {
                        if let Ok(ServerEnvelope::SessionClosed { reason, .. }) = serde_json::from_str::<ServerEnvelope>(&txt) {
                            end_reason = reason;
                            break;
                        }
                    }
                    Message::Close(_) => {
                        end_reason = "Server closed connection".to_string();
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    drop(out_tx);
    let _ = writer.await;
    if !expect_reboot {
        let _ = ev_tx.send(HostNetEvent::SessionEnded {
            tab_id,
            reason: end_reason,
        });
        ctx.request_repaint();
    }
    Ok(expect_reboot)
}
