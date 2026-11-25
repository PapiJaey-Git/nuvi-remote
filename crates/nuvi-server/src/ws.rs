use std::sync::Arc;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::Response,
};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use nuvi_proto::{
    crypto::{
        decode_verifying_key, device_id_from_pubkey, generate_challenge_nonce_b64,
        verify_registration_challenge,
    },
    protocol::{decode_relay_frame, ServerEnvelope},
};
use tokio::sync::mpsc;
use tracing::{info, warn};
use uuid::Uuid;

use crate::state::{cleanup_connection_sessions, make_audit, ClientHandle, ServerState, SessionPair};

const MAX_WS_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_CLIENTS: usize = 10_000;
const MAX_SESSIONS: usize = 10_000;
const MAX_META_LEN: usize = 128;

fn clamp_meta(s: String) -> String {
    s.trim().chars().take(MAX_META_LEN).collect()
}

pub async fn ws_handler(ws: WebSocketUpgrade, State(state): State<Arc<ServerState>>) -> Response {
    ws.max_message_size(MAX_WS_MESSAGE_BYTES)
        .on_upgrade(move |socket| handle_socket(socket, state))
}

async fn send_json(tx: &mpsc::Sender<Message>, env: &ServerEnvelope) {
    if let Ok(txt) = serde_json::to_string(env) {
        let _ = tx.send(Message::Text(txt.into())).await;
    }
}

async fn handle_socket(socket: WebSocket, state: Arc<ServerState>) {
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (tx, mut rx) = mpsc::channel::<Message>(256);

    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    let conn_id = Uuid::new_v4();
    let challenge_nonce = generate_challenge_nonce_b64();
    send_json(
        &tx,
        &ServerEnvelope::ServerChallenge {
            nonce_b64: challenge_nonce.clone(),
        },
    )
    .await;

    // First message must identify as ClientRegister or HostAuth.
    let first = match ws_rx.next().await {
        Some(Ok(Message::Text(txt))) => serde_json::from_str::<ServerEnvelope>(&txt).ok(),
        _ => None,
    };

    match first {
        Some(ServerEnvelope::ClientRegister {
            device_id,
            public_key_b64,
            hostname,
            os_version,
            mode,
            unattended_enabled,
            signature_b64,
        }) => {
            let vk = match decode_verifying_key(&public_key_b64) {
                Ok(vk) if device_id_from_pubkey(&vk) == device_id => vk,
                _ => {
                    send_json(
                        &tx,
                        &ServerEnvelope::ClientRegistered {
                            ok: false,
                            device_id,
                            message: "Device ID does not match public key".to_string(),
                        },
                    )
                    .await;
                    drop(tx);
                    let _ = writer.await;
                    return;
                }
            };

            if verify_registration_challenge(&vk, &device_id, &challenge_nonce, &signature_b64)
                .is_err()
            {
                send_json(
                    &tx,
                    &ServerEnvelope::ClientRegistered {
                        ok: false,
                        device_id,
                        message: "Invalid registration signature".to_string(),
                    },
                )
                .await;
                drop(tx);
                let _ = writer.await;
                return;
            }

            let hostname = clamp_meta(hostname);
            let os_version = clamp_meta(os_version);

            {
                let mut clients = state.clients.write().await;
                if !clients.contains_key(&device_id) && clients.len() >= MAX_CLIENTS {
                    send_json(
                        &tx,
                        &ServerEnvelope::ClientRegistered {
                            ok: false,
                            device_id,
                            message: "Server client capacity reached".to_string(),
                        },
                    )
                    .await;
                    drop(tx);
                    let _ = writer.await;
                    return;
                }
                if let Some(existing) = clients.get(&device_id) {
                    if existing.public_key_b64 != public_key_b64 && !existing.tx.is_closed() {
                        send_json(
                            &tx,
                            &ServerEnvelope::ClientRegistered {
                                ok: false,
                                device_id,
                                message: "Device ID already active with another identity key"
                                    .to_string(),
                            },
                        )
                        .await;
                        drop(tx);
                        let _ = writer.await;
                        return;
                    }
                }
                clients.insert(
                    device_id.clone(),
                    ClientHandle {
                        conn_id,
                        device_id: device_id.clone(),
                        public_key_b64,
                        hostname: hostname.clone(),
                        os_version,
                        mode,
                        unattended_enabled,
                        connected_at: Utc::now(),
                        tx: tx.clone(),
                    },
                );
            }

            send_json(
                &tx,
                &ServerEnvelope::ClientRegistered {
                    ok: true,
                    device_id: device_id.clone(),
                    message: "Registered".to_string(),
                },
            )
            .await;
            info!("Client online: {device_id} ({hostname})");

            while let Some(Ok(msg)) = ws_rx.next().await {
                match msg {
                    Message::Text(txt) => {
                        if let Ok(env) = serde_json::from_str::<ServerEnvelope>(&txt) {
                            match env {
                                ServerEnvelope::ClientStatusUpdate { unattended_enabled } => {
                                    let mut clients = state.clients.write().await;
                                    if let Some(c) = clients.get_mut(&device_id) {
                                        if c.conn_id == conn_id {
                                            c.unattended_enabled = unattended_enabled;
                                        }
                                    }
                                }
                                ServerEnvelope::SessionHandshake { session_id, .. } => {
                                    let peer_tx = {
                                        let sessions = state.sessions.read().await;
                                        sessions
                                            .get(&session_id)
                                            .filter(|s| s.client_conn_id == conn_id)
                                            .map(|s| s.host_tx.clone())
                                    };
                                    if let Some(ptx) = peer_tx {
                                        let _ = ptx.send(Message::Text(txt)).await;
                                    }
                                }
                                ServerEnvelope::SessionClosed { session_id, reason } => {
                                    let removed = {
                                        let mut sessions = state.sessions.write().await;
                                        if sessions
                                            .get(&session_id)
                                            .map(|s| s.client_conn_id == conn_id)
                                            .unwrap_or(false)
                                        {
                                            sessions.remove(&session_id)
                                        } else {
                                            None
                                        }
                                    };
                                    if let Some(pair) = removed {
                                        send_json(
                                            &pair.host_tx,
                                            &ServerEnvelope::SessionClosed { session_id, reason },
                                        )
                                        .await;
                                    }
                                }
                                ServerEnvelope::Ping => {
                                    send_json(&tx, &ServerEnvelope::Pong).await;
                                }
                                _ => {}
                            }
                        }
                    }
                    Message::Binary(bin) => {
                        if let Some((session_id, _)) = decode_relay_frame(&bin) {
                            let peer_tx = {
                                let sessions = state.sessions.read().await;
                                sessions
                                    .get(&session_id)
                                    .filter(|s| s.client_conn_id == conn_id)
                                    .map(|s| s.host_tx.clone())
                            };
                            if let Some(ptx) = peer_tx {
                                let _ = ptx.send(Message::Binary(bin)).await;
                            }
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }

            {
                let mut clients = state.clients.write().await;
                if clients.get(&device_id).map(|c| c.conn_id == conn_id).unwrap_or(false) {
                    clients.remove(&device_id);
                }
            }
            cleanup_connection_sessions(&state, conn_id, "Client disconnected").await;
            info!("Client offline: {device_id}");
        }
        Some(ServerEnvelope::HostAuth {
            tech_key,
            tech_name,
            host_public_key_b64,
        }) => {
            let tech_name = clamp_meta(tech_name);
            let Ok(host_vk) = decode_verifying_key(&host_public_key_b64) else {
                send_json(
                    &tx,
                    &ServerEnvelope::HostAuthed {
                        ok: false,
                        tech_id: String::new(),
                        message: "Invalid host public key".to_string(),
                    },
                )
                .await;
                drop(tx);
                let _ = writer.await;
                return;
            };
            if !state.verify_tech_key(&tech_key) {
                warn!("Host auth failed for tech '{tech_name}'");
                send_json(
                    &tx,
                    &ServerEnvelope::HostAuthed {
                        ok: false,
                        tech_id: String::new(),
                        message: "Invalid NUVI technician key".to_string(),
                    },
                )
                .await;
                state
                    .append_audit(make_audit(
                        "host_auth_failed",
                        None,
                        None,
                        Some(&tech_name),
                        None,
                        "Invalid tech key",
                    ))
                    .await;
                drop(tx);
                let _ = writer.await;
                return;
            }

            let tech_id = device_id_from_pubkey(&host_vk);

            send_json(
                &tx,
                &ServerEnvelope::HostAuthed {
                    ok: true,
                    tech_id: tech_id.clone(),
                    message: "Authenticated".to_string(),
                },
            )
            .await;

            while let Some(Ok(msg)) = ws_rx.next().await {
                match msg {
                    Message::Text(txt) => {
                        if let Ok(env) = serde_json::from_str::<ServerEnvelope>(&txt) {
                            match env {
                                ServerEnvelope::HostConnectRequest { target_device_id } => {
                                    let target = {
                                        let clients = state.clients.read().await;
                                        clients.get(&target_device_id).cloned()
                                    };
                                    let Some(client) = target else {
                                        send_json(
                                            &tx,
                                            &ServerEnvelope::SessionError {
                                                code: "not_online".to_string(),
                                                message: format!(
                                                    "Client {target_device_id} is not online"
                                                ),
                                            },
                                        )
                                        .await;
                                        continue;
                                    };

                                    {
                                        let sessions = state.sessions.read().await;
                                        if sessions.len() >= MAX_SESSIONS {
                                            send_json(
                                                &tx,
                                                &ServerEnvelope::SessionError {
                                                    code: "server_busy".to_string(),
                                                    message: "Server session limit reached"
                                                        .to_string(),
                                                },
                                            )
                                            .await;
                                            continue;
                                        }
                                        if sessions
                                            .values()
                                            .any(|s| s.client_conn_id == client.conn_id)
                                        {
                                            send_json(
                                                &tx,
                                                &ServerEnvelope::SessionError {
                                                    code: "client_busy".to_string(),
                                                    message: "Client is already in a session or handling a connection request".to_string(),
                                                },
                                            )
                                            .await;
                                            continue;
                                        }
                                    }

                                    let session_id = Uuid::new_v4();
                                    let pair = SessionPair {
                                        session_id,
                                        host_conn_id: conn_id,
                                        client_conn_id: client.conn_id,
                                        target_device_id: target_device_id.clone(),
                                        tech_id: tech_id.clone(),
                                        tech_name: tech_name.clone(),
                                        started_at: Utc::now(),
                                        host_tx: tx.clone(),
                                        client_tx: client.tx.clone(),
                                    };
                                    state.sessions.write().await.insert(session_id, pair);
                                    state
                                        .append_audit(make_audit(
                                            "session_paired",
                                            Some(session_id),
                                            Some(&tech_id),
                                            Some(&tech_name),
                                            Some(&target_device_id),
                                            "Host requested connection",
                                        ))
                                        .await;

                                    send_json(
                                        &tx,
                                        &ServerEnvelope::SessionPairing {
                                            session_id,
                                            peer_device_id: client.device_id.clone(),
                                            peer_public_key_b64: client.public_key_b64.clone(),
                                            peer_name: client.hostname.clone(),
                                        },
                                    )
                                    .await;

                                    send_json(
                                        &client.tx,
                                        &ServerEnvelope::SessionPairing {
                                            session_id,
                                            peer_device_id: tech_id.clone(),
                                            peer_public_key_b64: host_public_key_b64.clone(),
                                            peer_name: tech_name.clone(),
                                        },
                                    )
                                    .await;
                                }
                                ServerEnvelope::SessionHandshake { session_id, .. } => {
                                    let peer_tx = {
                                        let sessions = state.sessions.read().await;
                                        sessions
                                            .get(&session_id)
                                            .filter(|s| s.host_conn_id == conn_id)
                                            .map(|s| s.client_tx.clone())
                                    };
                                    if let Some(ptx) = peer_tx {
                                        let _ = ptx.send(Message::Text(txt)).await;
                                    }
                                }
                                ServerEnvelope::SessionClosed { session_id, reason } => {
                                    let removed = {
                                        let mut sessions = state.sessions.write().await;
                                        if sessions
                                            .get(&session_id)
                                            .map(|s| s.host_conn_id == conn_id)
                                            .unwrap_or(false)
                                        {
                                            sessions.remove(&session_id)
                                        } else {
                                            None
                                        }
                                    };
                                    if let Some(pair) = removed {
                                        send_json(
                                            &pair.client_tx,
                                            &ServerEnvelope::SessionClosed { session_id, reason },
                                        )
                                        .await;
                                    }
                                }
                                ServerEnvelope::Ping => {
                                    send_json(&tx, &ServerEnvelope::Pong).await;
                                }
                                _ => {}
                            }
                        }
                    }
                    Message::Binary(bin) => {
                        if let Some((session_id, _)) = decode_relay_frame(&bin) {
                            let peer_tx = {
                                let sessions = state.sessions.read().await;
                                sessions
                                    .get(&session_id)
                                    .filter(|s| s.host_conn_id == conn_id)
                                    .map(|s| s.client_tx.clone())
                            };
                            if let Some(ptx) = peer_tx {
                                let _ = ptx.send(Message::Binary(bin)).await;
                            }
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }

            cleanup_connection_sessions(&state, conn_id, "Host disconnected").await;
        }
        _ => {
            send_json(
                &tx,
                &ServerEnvelope::SessionError {
                    code: "bad_hello".to_string(),
                    message: "Expected ClientRegister or HostAuth".to_string(),
                },
            )
            .await;
        }
    }

    drop(tx);
    let _ = writer.await;
}
