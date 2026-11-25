use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use nuvi_proto::{
    crypto::{
        decode_verifying_key, generate_unattended_key, hash_unattended_key,
        sign_registration_challenge, verify_unattended_key, HandshakeState, IdentityKeypair, Role,
    },
    protocol::{
        decode_relay_frame, encode_relay_frame, AnnotationKind, ClientRunMode, ConnectMode,
        MonitorInfo, MouseEventKind, PeerMessage, RemoteCursorShape, RemoteQuickAction,
        ServerEnvelope, SessionPermissions, VideoTile,
    },
};
use tokio::net::TcpListener;
use tokio_tungstenite::{connect_async, tungstenite::Message};

async fn read_challenge<S>(ws: &mut S) -> String
where
    S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let msg = ws.next().await.unwrap().unwrap();
    let Message::Text(txt) = msg else {
        panic!("expected challenge text frame");
    };
    match serde_json::from_str::<ServerEnvelope>(&txt).unwrap() {
        ServerEnvelope::ServerChallenge { nonce_b64 } => nonce_b64,
        other => panic!("expected ServerChallenge, got {other:?}"),
    }
}

async fn spawn_test_server() -> (String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(
        nuvi_server::state::ServerState::new("secret-tech-key".to_string(), dir.path().to_path_buf())
            .await
            .unwrap(),
    );
    let app = nuvi_server::build_router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), dir)
}

#[tokio::test]
async fn reject_invalid_tech_key() {
    let (base, _dir) = spawn_test_server().await;
    let ws_url = base.replace("http://", "ws://") + "/ws";
    let (mut ws, _) = connect_async(&ws_url).await.unwrap();
    let _nonce = read_challenge(&mut ws).await;

    let host_kp = IdentityKeypair::generate();
    let auth = ServerEnvelope::HostAuth {
        tech_key: "wrong-key".to_string(),
        tech_name: "Intruder".to_string(),
        host_public_key_b64: host_kp.public_key_b64(),
    };
    ws.send(Message::Text(serde_json::to_string(&auth).unwrap().into()))
        .await
        .unwrap();

    let resp = ws.next().await.unwrap().unwrap();
    let Message::Text(txt) = resp else {
        panic!("expected text");
    };
    let env: ServerEnvelope = serde_json::from_str(&txt).unwrap();
    match env {
        ServerEnvelope::HostAuthed { ok, .. } => assert!(!ok),
        other => panic!("unexpected: {other:?}"),
    }
}

#[tokio::test]
async fn full_e2ee_attended_relay_and_unattended_key_check() {
    let (base, _dir) = spawn_test_server().await;
    let ws_url = base.replace("http://", "ws://") + "/ws";

    // Connect Client
    let client_kp = IdentityKeypair::generate();
    let client_id = client_kp.device_id();
    let unattended_secret = generate_unattended_key();
    let unattended_hash = hash_unattended_key(&unattended_secret).unwrap();

    let (mut client_ws, _) = connect_async(&ws_url).await.unwrap();
    let c_nonce = read_challenge(&mut client_ws).await;
    let reg = ServerEnvelope::ClientRegister {
        device_id: client_id.clone(),
        public_key_b64: client_kp.public_key_b64(),
        hostname: "CLIENT-PC".to_string(),
        os_version: "Windows 11".to_string(),
        mode: ClientRunMode::Portable,
        unattended_enabled: true,
        signature_b64: sign_registration_challenge(&client_kp, &client_id, &c_nonce).unwrap(),
    };
    client_ws
        .send(Message::Text(serde_json::to_string(&reg).unwrap().into()))
        .await
        .unwrap();
    let _ = client_ws.next().await.unwrap().unwrap(); // ClientRegistered

    // Connect Host
    let host_kp = IdentityKeypair::generate();
    let (mut host_ws, _) = connect_async(&ws_url).await.unwrap();
    let _h_nonce = read_challenge(&mut host_ws).await;
    let auth = ServerEnvelope::HostAuth {
        tech_key: "secret-tech-key".to_string(),
        tech_name: "TechUser".to_string(),
        host_public_key_b64: host_kp.public_key_b64(),
    };
    host_ws
        .send(Message::Text(serde_json::to_string(&auth).unwrap().into()))
        .await
        .unwrap();
    let _ = host_ws.next().await.unwrap().unwrap(); // HostAuthed

    // Request connection
    host_ws
        .send(Message::Text(
            serde_json::to_string(&ServerEnvelope::HostConnectRequest {
                target_device_id: client_id.clone(),
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();

    let h_pair_msg = host_ws.next().await.unwrap().unwrap();
    let c_pair_msg = client_ws.next().await.unwrap().unwrap();

    let ServerEnvelope::SessionPairing {
        session_id,
        peer_public_key_b64: h_peer_pub,
        ..
    } = serde_json::from_str(h_pair_msg.to_text().unwrap()).unwrap()
    else {
        panic!("expected host pairing");
    };
    let ServerEnvelope::SessionPairing {
        session_id: c_sid,
        peer_public_key_b64: c_peer_pub,
        ..
    } = serde_json::from_str(c_pair_msg.to_text().unwrap()).unwrap()
    else {
        panic!("expected client pairing");
    };
    assert_eq!(session_id, c_sid);

    let h_hs = HandshakeState::new(session_id, Role::Host);
    let c_hs = HandshakeState::new(session_id, Role::Client);

    host_ws
        .send(Message::Text(
            serde_json::to_string(&ServerEnvelope::SessionHandshake {
                session_id,
                ephemeral_x25519_pub_b64: h_hs.ephemeral_pub_b64(),
                identity_ed25519_pub_b64: host_kp.public_key_b64(),
                signature_b64: h_hs.sign_ephemeral(&host_kp),
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();

    client_ws
        .send(Message::Text(
            serde_json::to_string(&ServerEnvelope::SessionHandshake {
                session_id,
                ephemeral_x25519_pub_b64: c_hs.ephemeral_pub_b64(),
                identity_ed25519_pub_b64: client_kp.public_key_b64(),
                signature_b64: c_hs.sign_ephemeral(&client_kp),
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();

    let h_hs_rx = host_ws.next().await.unwrap().unwrap();
    let c_hs_rx = client_ws.next().await.unwrap().unwrap();

    let ServerEnvelope::SessionHandshake {
        ephemeral_x25519_pub_b64: ce,
        identity_ed25519_pub_b64: ci,
        signature_b64: cs,
        ..
    } = serde_json::from_str(h_hs_rx.to_text().unwrap()).unwrap()
    else {
        panic!("expected client hs");
    };
    let ServerEnvelope::SessionHandshake {
        ephemeral_x25519_pub_b64: he,
        identity_ed25519_pub_b64: hi,
        signature_b64: hs_sig,
        ..
    } = serde_json::from_str(c_hs_rx.to_text().unwrap()).unwrap()
    else {
        panic!("expected host hs");
    };

    let mut host_cipher = h_hs
        .complete(&decode_verifying_key(&h_peer_pub).unwrap(), &ce, &ci, &cs)
        .unwrap();
    let mut client_cipher = c_hs
        .complete(&decode_verifying_key(&c_peer_pub).unwrap(), &he, &hi, &hs_sig)
        .unwrap();

    // Host sends E2EE ConnectIntent (Unattended)
    let intent = PeerMessage::ConnectIntent {
        mode: ConnectMode::Unattended,
        tech_name: "TechUser".to_string(),
        reason: "".to_string(),
        unattended_key: Some(unattended_secret.clone()),
        requested_permissions: SessionPermissions::default(),
    };
    let ct = host_cipher.encrypt(&bincode::serialize(&intent).unwrap()).unwrap();
    host_ws
        .send(Message::Binary(encode_relay_frame(session_id, &ct).into()))
        .await
        .unwrap();

    let bin = client_ws.next().await.unwrap().unwrap();
    let bin_data = bin.into_data();
    let (sid, payload) = decode_relay_frame(&bin_data).unwrap();
    assert_eq!(sid, session_id);
    let rx_intent: PeerMessage =
        bincode::deserialize(&client_cipher.decrypt(payload).unwrap()).unwrap();
    match rx_intent {
        PeerMessage::ConnectIntent {
            unattended_key: Some(k),
            ..
        } => {
            assert!(verify_unattended_key(&k, &unattended_hash));
            assert!(!verify_unattended_key("NUVI-BAD0-BAD0-BAD0", &unattended_hash));
        }
        other => panic!("unexpected: {other:?}"),
    }

    // Client sends ConnectDecision + VideoFrame
    let decision = PeerMessage::ConnectDecision {
        accepted: true,
        permissions: SessionPermissions::default(),
        reject_reason: None,
        monitors: vec![MonitorInfo {
            index: 0,
            name: "Primary".to_string(),
            left: 0,
            top: 0,
            width: 1920,
            height: 1080,
            primary: true,
        }],
        client_mode: ClientRunMode::Service,
    };
    let d_ct = client_cipher
        .encrypt(&bincode::serialize(&decision).unwrap())
        .unwrap();
    client_ws
        .send(Message::Binary(encode_relay_frame(session_id, &d_ct).into()))
        .await
        .unwrap();

    let d_bin = host_ws.next().await.unwrap().unwrap();
    let d_data = d_bin.into_data();
    let (_, d_payload) = decode_relay_frame(&d_data).unwrap();
    let rx_dec: PeerMessage =
        bincode::deserialize(&host_cipher.decrypt(d_payload).unwrap()).unwrap();
    assert!(matches!(
        rx_dec,
        PeerMessage::ConnectDecision { accepted: true, .. }
    ));

    // Host sends MouseInput -> Client receives
    let mouse = PeerMessage::MouseInput {
        monitor_index: 0,
        kind: MouseEventKind::Move { nx: 0.5, ny: 0.5 },
    };
    let m_ct = host_cipher.encrypt(&bincode::serialize(&mouse).unwrap()).unwrap();
    host_ws
        .send(Message::Binary(encode_relay_frame(session_id, &m_ct).into()))
        .await
        .unwrap();
    let m_bin = client_ws.next().await.unwrap().unwrap();
    let m_data = m_bin.into_data();
    let (_, m_payload) = decode_relay_frame(&m_data).unwrap();
    let rx_mouse: PeerMessage =
        bincode::deserialize(&client_cipher.decrypt(m_payload).unwrap()).unwrap();
    assert!(matches!(rx_mouse, PeerMessage::MouseInput { .. }));

    // Client sends VideoFrame -> Host receives
    let vf = PeerMessage::VideoFrame {
        monitor_index: 0,
        width: 64,
        height: 64,
        full_frame: true,
        tiles: vec![VideoTile {
            x: 0,
            y: 0,
            w: 64,
            h: 64,
            jpeg_data: vec![0xFF, 0xD8, 0xFF, 0xD9],
        }],
    };
    let v_ct = client_cipher.encrypt(&bincode::serialize(&vf).unwrap()).unwrap();
    client_ws
        .send(Message::Binary(encode_relay_frame(session_id, &v_ct).into()))
        .await
        .unwrap();
    let v_bin = host_ws.next().await.unwrap().unwrap();
    let v_data = v_bin.into_data();
    let (_, v_payload) = decode_relay_frame(&v_data).unwrap();
    let rx_vf: PeerMessage =
        bincode::deserialize(&host_cipher.decrypt(v_payload).unwrap()).unwrap();
    assert!(matches!(rx_vf, PeerMessage::VideoFrame { .. }));

    // Host sends SendCtrlAltDel -> Client receives
    let cad_ct = host_cipher
        .encrypt(&bincode::serialize(&PeerMessage::SendCtrlAltDel).unwrap())
        .unwrap();
    host_ws
        .send(Message::Binary(encode_relay_frame(session_id, &cad_ct).into()))
        .await
        .unwrap();
    let cad_bin = client_ws.next().await.unwrap().unwrap();
    let cad_data = cad_bin.into_data();
    let (_, cad_payload) = decode_relay_frame(&cad_data).unwrap();
    let rx_cad: PeerMessage =
        bincode::deserialize(&client_cipher.decrypt(cad_payload).unwrap()).unwrap();
    assert!(matches!(rx_cad, PeerMessage::SendCtrlAltDel));

    // Client sends SystemNotice -> Host receives
    let note_ct = client_cipher
        .encrypt(
            &bincode::serialize(&PeerMessage::SystemNotice {
                message: "SAS sent".to_string(),
            })
            .unwrap(),
        )
        .unwrap();
    client_ws
        .send(Message::Binary(encode_relay_frame(session_id, &note_ct).into()))
        .await
        .unwrap();
    let note_bin = host_ws.next().await.unwrap().unwrap();
    let note_data = note_bin.into_data();
    let (_, note_payload) = decode_relay_frame(&note_data).unwrap();
    let rx_note: PeerMessage =
        bincode::deserialize(&host_cipher.decrypt(note_payload).unwrap()).unwrap();
    assert!(matches!(rx_note, PeerMessage::SystemNotice { .. }));

    // E2EE roundtrip (Clipboard, Chat, FileOffer/Chunk/Complete/Ack, Cursor, QuickAction, Annotation)
    let tid = uuid::Uuid::new_v4();
    let p3_msgs = vec![
        PeerMessage::ClipboardText {
            text: "nuvi-clipboard".into(),
        },
        PeerMessage::ChatMessage {
            sender: "TechUser".into(),
            text: "Testing chat".into(),
            sent_at: "17:00".into(),
        },
        PeerMessage::FileOffer {
            transfer_id: tid,
            filename: "note.txt".into(),
            total_bytes: 4,
        },
        PeerMessage::FileChunk {
            transfer_id: tid,
            offset: 0,
            data: b"test".to_vec(),
        },
        PeerMessage::FileComplete {
            transfer_id: tid,
            sha256_hex: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".into(),
        },
        PeerMessage::CursorShape {
            shape: RemoteCursorShape::Text,
        },
        PeerMessage::QuickAction {
            action: RemoteQuickAction::OpenTaskManager,
        },
        PeerMessage::Annotation {
            monitor_index: 0,
            kind: AnnotationKind::Laser { nx: 0.4, ny: 0.6 },
        },
    ];
    for m in p3_msgs {
        let ct = host_cipher.encrypt(&bincode::serialize(&m).unwrap()).unwrap();
        host_ws
            .send(Message::Binary(encode_relay_frame(session_id, &ct).into()))
            .await
            .unwrap();
        let bin = client_ws.next().await.unwrap().unwrap();
        let data = bin.into_data();
        let (_, pl) = decode_relay_frame(&data).unwrap();
        let dec: PeerMessage = bincode::deserialize(&client_cipher.decrypt(pl).unwrap()).unwrap();
        assert_eq!(std::mem::discriminant(&m), std::mem::discriminant(&dec));
    }
}

#[tokio::test]
async fn e2ee_in_session_chat_roundtrip() {
    let (base, _dir) = spawn_test_server().await;
    let ws_url = base.replace("http://", "ws://") + "/ws";

    let client_kp = IdentityKeypair::generate();
    let client_id = client_kp.device_id();
    let (mut client_ws, _) = connect_async(&ws_url).await.unwrap();
    let c_nonce = read_challenge(&mut client_ws).await;
    let reg = ServerEnvelope::ClientRegister {
        device_id: client_id.clone(),
        public_key_b64: client_kp.public_key_b64(),
        hostname: "CHAT-CLIENT".to_string(),
        os_version: "Windows 11".to_string(),
        mode: ClientRunMode::Portable,
        unattended_enabled: false,
        signature_b64: sign_registration_challenge(&client_kp, &client_id, &c_nonce).unwrap(),
    };
    client_ws
        .send(Message::Text(serde_json::to_string(&reg).unwrap().into()))
        .await
        .unwrap();
    let _ = client_ws.next().await.unwrap().unwrap();

    let host_kp = IdentityKeypair::generate();
    let (mut host_ws, _) = connect_async(&ws_url).await.unwrap();
    let _h_nonce = read_challenge(&mut host_ws).await;
    let auth = ServerEnvelope::HostAuth {
        tech_key: "secret-tech-key".to_string(),
        tech_name: "TechUser".to_string(),
        host_public_key_b64: host_kp.public_key_b64(),
    };
    host_ws
        .send(Message::Text(serde_json::to_string(&auth).unwrap().into()))
        .await
        .unwrap();
    let _ = host_ws.next().await.unwrap().unwrap();

    host_ws
        .send(Message::Text(
            serde_json::to_string(&ServerEnvelope::HostConnectRequest {
                target_device_id: client_id.clone(),
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();

    let h_pair_msg = host_ws.next().await.unwrap().unwrap();
    let c_pair_msg = client_ws.next().await.unwrap().unwrap();
    let ServerEnvelope::SessionPairing {
        session_id,
        peer_public_key_b64: h_peer_pub,
        ..
    } = serde_json::from_str(h_pair_msg.to_text().unwrap()).unwrap()
    else {
        panic!("expected host pairing");
    };
    let ServerEnvelope::SessionPairing {
        peer_public_key_b64: c_peer_pub,
        ..
    } = serde_json::from_str(c_pair_msg.to_text().unwrap()).unwrap()
    else {
        panic!("expected client pairing");
    };

    let h_hs = HandshakeState::new(session_id, Role::Host);
    let c_hs = HandshakeState::new(session_id, Role::Client);
    host_ws
        .send(Message::Text(
            serde_json::to_string(&ServerEnvelope::SessionHandshake {
                session_id,
                ephemeral_x25519_pub_b64: h_hs.ephemeral_pub_b64(),
                identity_ed25519_pub_b64: host_kp.public_key_b64(),
                signature_b64: h_hs.sign_ephemeral(&host_kp),
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    client_ws
        .send(Message::Text(
            serde_json::to_string(&ServerEnvelope::SessionHandshake {
                session_id,
                ephemeral_x25519_pub_b64: c_hs.ephemeral_pub_b64(),
                identity_ed25519_pub_b64: client_kp.public_key_b64(),
                signature_b64: c_hs.sign_ephemeral(&client_kp),
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();

    let h_hs_rx = host_ws.next().await.unwrap().unwrap();
    let c_hs_rx = client_ws.next().await.unwrap().unwrap();
    let ServerEnvelope::SessionHandshake {
        ephemeral_x25519_pub_b64: ce,
        identity_ed25519_pub_b64: ci,
        signature_b64: cs,
        ..
    } = serde_json::from_str(h_hs_rx.to_text().unwrap()).unwrap()
    else {
        panic!("expected client hs");
    };
    let ServerEnvelope::SessionHandshake {
        ephemeral_x25519_pub_b64: he,
        identity_ed25519_pub_b64: hi,
        signature_b64: hs_sig,
        ..
    } = serde_json::from_str(c_hs_rx.to_text().unwrap()).unwrap()
    else {
        panic!("expected host hs");
    };

    let mut host_cipher = h_hs
        .complete(&decode_verifying_key(&h_peer_pub).unwrap(), &ce, &ci, &cs)
        .unwrap();
    let mut client_cipher = c_hs
        .complete(&decode_verifying_key(&c_peer_pub).unwrap(), &he, &hi, &hs_sig)
        .unwrap();

    // Host sends Attended intent
    let intent = PeerMessage::ConnectIntent {
        mode: ConnectMode::Attended,
        tech_name: "TechUser".to_string(),
        reason: "Support".to_string(),
        unattended_key: None,
        requested_permissions: SessionPermissions::default(),
    };
    let ct = host_cipher.encrypt(&bincode::serialize(&intent).unwrap()).unwrap();
    host_ws
        .send(Message::Binary(encode_relay_frame(session_id, &ct).into()))
        .await
        .unwrap();

    let bin = client_ws.next().await.unwrap().unwrap();
    let bin_data = bin.into_data();
    let (_, payload) = decode_relay_frame(&bin_data).unwrap();
    let rx_intent: PeerMessage =
        bincode::deserialize(&client_cipher.decrypt(payload).unwrap()).unwrap();
    assert!(matches!(
        rx_intent,
        PeerMessage::ConnectIntent {
            mode: ConnectMode::Attended,
            ..
        }
    ));

    // Client accepts session
    let decision = PeerMessage::ConnectDecision {
        accepted: true,
        permissions: SessionPermissions::default(),
        reject_reason: None,
        monitors: Vec::new(),
        client_mode: ClientRunMode::Portable,
    };
    let d_ct = client_cipher
        .encrypt(&bincode::serialize(&decision).unwrap())
        .unwrap();
    client_ws
        .send(Message::Binary(encode_relay_frame(session_id, &d_ct).into()))
        .await
        .unwrap();

    let d_bin = host_ws.next().await.unwrap().unwrap();
    let d_data = d_bin.into_data();
    let (_, d_payload) = decode_relay_frame(&d_data).unwrap();
    let rx_dec: PeerMessage =
        bincode::deserialize(&host_cipher.decrypt(d_payload).unwrap()).unwrap();
    assert!(matches!(
        rx_dec,
        PeerMessage::ConnectDecision { accepted: true, .. }
    ));

    // Bidirectional in-session ChatMessage roundtrip
    let h_msg = PeerMessage::ChatMessage {
        sender: "TechUser".into(),
        text: "Hello in connected session!".into(),
        sent_at: "17:35".into(),
    };
    let h_ct = host_cipher.encrypt(&bincode::serialize(&h_msg).unwrap()).unwrap();
    host_ws
        .send(Message::Binary(encode_relay_frame(session_id, &h_ct).into()))
        .await
        .unwrap();

    let c_rx = client_ws.next().await.unwrap().unwrap();
    let c_data = c_rx.into_data();
    let (_, c_pl) = decode_relay_frame(&c_data).unwrap();
    let c_dec: PeerMessage =
        bincode::deserialize(&client_cipher.decrypt(c_pl).unwrap()).unwrap();
    assert!(matches!(
        c_dec,
        PeerMessage::ChatMessage { ref text, .. } if text == "Hello in connected session!"
    ));

    let c_msg = PeerMessage::ChatMessage {
        sender: "CHAT-CLIENT".into(),
        text: "Got it, thanks!".into(),
        sent_at: "17:36".into(),
    };
    let c_ct = client_cipher.encrypt(&bincode::serialize(&c_msg).unwrap()).unwrap();
    client_ws
        .send(Message::Binary(encode_relay_frame(session_id, &c_ct).into()))
        .await
        .unwrap();

    let h_rx = host_ws.next().await.unwrap().unwrap();
    let h_data = h_rx.into_data();
    let (_, h_pl) = decode_relay_frame(&h_data).unwrap();
    let h_dec: PeerMessage =
        bincode::deserialize(&host_cipher.decrypt(h_pl).unwrap()).unwrap();
    assert!(matches!(
        h_dec,
        PeerMessage::ChatMessage { ref text, .. } if text == "Got it, thanks!"
    ));
}

#[tokio::test]
async fn e2ee_auto_unattended_challenge_roundtrip() {
    let (base, _dir) = spawn_test_server().await;
    let ws_url = base.replace("http://", "ws://") + "/ws";

    let client_kp = IdentityKeypair::generate();
    let client_id = client_kp.device_id();
    let unattended_secret = generate_unattended_key();
    let unattended_hash = hash_unattended_key(&unattended_secret).unwrap();

    let (mut client_ws, _) = connect_async(&ws_url).await.unwrap();
    let c_nonce = read_challenge(&mut client_ws).await;
    let reg = ServerEnvelope::ClientRegister {
        device_id: client_id.clone(),
        public_key_b64: client_kp.public_key_b64(),
        hostname: "AUTO-CLIENT".to_string(),
        os_version: "Windows 11".to_string(),
        mode: ClientRunMode::Portable,
        unattended_enabled: true,
        signature_b64: sign_registration_challenge(&client_kp, &client_id, &c_nonce).unwrap(),
    };
    client_ws
        .send(Message::Text(serde_json::to_string(&reg).unwrap().into()))
        .await
        .unwrap();
    let _ = client_ws.next().await.unwrap().unwrap();

    let host_kp = IdentityKeypair::generate();
    let (mut host_ws, _) = connect_async(&ws_url).await.unwrap();
    let _h_nonce = read_challenge(&mut host_ws).await;
    let auth = ServerEnvelope::HostAuth {
        tech_key: "secret-tech-key".to_string(),
        tech_name: "TechUser".to_string(),
        host_public_key_b64: host_kp.public_key_b64(),
    };
    host_ws
        .send(Message::Text(serde_json::to_string(&auth).unwrap().into()))
        .await
        .unwrap();
    let _ = host_ws.next().await.unwrap().unwrap();

    host_ws
        .send(Message::Text(
            serde_json::to_string(&ServerEnvelope::HostConnectRequest {
                target_device_id: client_id.clone(),
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();

    let h_pair_msg = host_ws.next().await.unwrap().unwrap();
    let c_pair_msg = client_ws.next().await.unwrap().unwrap();
    let ServerEnvelope::SessionPairing {
        session_id,
        peer_public_key_b64: h_peer_pub,
        ..
    } = serde_json::from_str(h_pair_msg.to_text().unwrap()).unwrap()
    else {
        panic!("expected host pairing");
    };
    let ServerEnvelope::SessionPairing {
        peer_public_key_b64: c_peer_pub,
        ..
    } = serde_json::from_str(c_pair_msg.to_text().unwrap()).unwrap()
    else {
        panic!("expected client pairing");
    };

    let h_hs = HandshakeState::new(session_id, Role::Host);
    let c_hs = HandshakeState::new(session_id, Role::Client);
    host_ws
        .send(Message::Text(
            serde_json::to_string(&ServerEnvelope::SessionHandshake {
                session_id,
                ephemeral_x25519_pub_b64: h_hs.ephemeral_pub_b64(),
                identity_ed25519_pub_b64: host_kp.public_key_b64(),
                signature_b64: h_hs.sign_ephemeral(&host_kp),
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    client_ws
        .send(Message::Text(
            serde_json::to_string(&ServerEnvelope::SessionHandshake {
                session_id,
                ephemeral_x25519_pub_b64: c_hs.ephemeral_pub_b64(),
                identity_ed25519_pub_b64: client_kp.public_key_b64(),
                signature_b64: c_hs.sign_ephemeral(&client_kp),
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();

    let h_hs_rx = host_ws.next().await.unwrap().unwrap();
    let c_hs_rx = client_ws.next().await.unwrap().unwrap();
    let ServerEnvelope::SessionHandshake {
        ephemeral_x25519_pub_b64: ce,
        identity_ed25519_pub_b64: ci,
        signature_b64: cs,
        ..
    } = serde_json::from_str(h_hs_rx.to_text().unwrap()).unwrap()
    else {
        panic!("expected client hs");
    };
    let ServerEnvelope::SessionHandshake {
        ephemeral_x25519_pub_b64: he,
        identity_ed25519_pub_b64: hi,
        signature_b64: hs_sig,
        ..
    } = serde_json::from_str(c_hs_rx.to_text().unwrap()).unwrap()
    else {
        panic!("expected host hs");
    };

    let mut host_cipher = h_hs
        .complete(&decode_verifying_key(&h_peer_pub).unwrap(), &ce, &ci, &cs)
        .unwrap();
    let mut client_cipher = c_hs
        .complete(&decode_verifying_key(&c_peer_pub).unwrap(), &he, &hi, &hs_sig)
        .unwrap();

    // 1. Host connects without knowing key upfront
    let intent = PeerMessage::ConnectIntent {
        mode: ConnectMode::Attended,
        tech_name: "TechUser".into(),
        reason: "".into(),
        unattended_key: None,
        requested_permissions: SessionPermissions::default(),
    };
    let ct = host_cipher.encrypt(&bincode::serialize(&intent).unwrap()).unwrap();
    host_ws
        .send(Message::Binary(encode_relay_frame(session_id, &ct).into()))
        .await
        .unwrap();
    let _ = client_ws.next().await.unwrap().unwrap();

    // 2. Client responds with AuthChallenge
    let ch = PeerMessage::AuthChallenge {
        requires_unattended_key: true,
        message: "Unattended Access is enabled".into(),
    };
    let ch_ct = client_cipher.encrypt(&bincode::serialize(&ch).unwrap()).unwrap();
    client_ws
        .send(Message::Binary(encode_relay_frame(session_id, &ch_ct).into()))
        .await
        .unwrap();

    let h_ch_rx = host_ws.next().await.unwrap().unwrap();
    let h_ch_data = h_ch_rx.into_data();
    let (_, h_ch_pl) = decode_relay_frame(&h_ch_data).unwrap();
    let h_ch_dec: PeerMessage =
        bincode::deserialize(&host_cipher.decrypt(h_ch_pl).unwrap()).unwrap();
    assert!(matches!(
        h_ch_dec,
        PeerMessage::AuthChallenge {
            requires_unattended_key: true,
            ..
        }
    ));

    // 3. Host submits AuthResponse -> Client verifies and accepts
    let resp = PeerMessage::AuthResponse {
        unattended_key: unattended_secret,
    };
    let r_ct = host_cipher.encrypt(&bincode::serialize(&resp).unwrap()).unwrap();
    host_ws
        .send(Message::Binary(encode_relay_frame(session_id, &r_ct).into()))
        .await
        .unwrap();

    let c_r_rx = client_ws.next().await.unwrap().unwrap();
    let c_r_data = c_r_rx.into_data();
    let (_, c_r_pl) = decode_relay_frame(&c_r_data).unwrap();
    let c_r_dec: PeerMessage =
        bincode::deserialize(&client_cipher.decrypt(c_r_pl).unwrap()).unwrap();
    match c_r_dec {
        PeerMessage::AuthResponse { unattended_key } => {
            assert!(verify_unattended_key(&unattended_key, &unattended_hash));
        }
        other => panic!("unexpected: {other:?}"),
    }

    let dec = PeerMessage::ConnectDecision {
        accepted: true,
        permissions: SessionPermissions::default(),
        reject_reason: None,
        monitors: Vec::new(),
        client_mode: ClientRunMode::Portable,
    };
    let d_ct = client_cipher.encrypt(&bincode::serialize(&dec).unwrap()).unwrap();
    client_ws
        .send(Message::Binary(encode_relay_frame(session_id, &d_ct).into()))
        .await
        .unwrap();

    let h_d_rx = host_ws.next().await.unwrap().unwrap();
    let h_d_data = h_d_rx.into_data();
    let (_, h_d_pl) = decode_relay_frame(&h_d_data).unwrap();
    let h_d_dec: PeerMessage =
        bincode::deserialize(&host_cipher.decrypt(h_d_pl).unwrap()).unwrap();
    assert!(matches!(
        h_d_dec,
        PeerMessage::ConnectDecision { accepted: true, .. }
    ));
}

#[tokio::test]
async fn open_mode_allows_host_without_tech_key_and_blocks_device_list() {
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(
        nuvi_server::state::ServerState::new_with_mode(
            nuvi_server::state::AuthMode::Open,
            String::new(),
            dir.path().to_path_buf(),
        )
        .await
        .unwrap(),
    );
    let app = nuvi_server::build_router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let base = format!("http://{addr}");

    let http = reqwest::Client::new();
    let health: serde_json::Value = http
        .get(format!("{base}/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["auth_mode"], "open");

    let dev_status = http
        .get(format!("{base}/api/devices"))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(dev_status, reqwest::StatusCode::FORBIDDEN);

    let ws_url = format!("ws://{addr}/ws");
    let (mut ws, _) = connect_async(&ws_url).await.unwrap();
    let _nonce = read_challenge(&mut ws).await;
    let host_kp = IdentityKeypair::generate();
    let auth = ServerEnvelope::HostAuth {
        tech_key: String::new(),
        tech_name: "OpenUser".to_string(),
        host_public_key_b64: host_kp.public_key_b64(),
    };
    ws.send(Message::Text(serde_json::to_string(&auth).unwrap().into()))
        .await
        .unwrap();

    let resp = ws.next().await.unwrap().unwrap();
    let Message::Text(txt) = resp else {
        panic!("expected text");
    };
    let env: ServerEnvelope = serde_json::from_str(&txt).unwrap();
    match env {
        ServerEnvelope::HostAuthed { ok, .. } => assert!(ok),
        other => panic!("unexpected: {other:?}"),
    }
}

#[tokio::test]
async fn reject_forged_or_unsigned_client_register() {
    let (base, _dir) = spawn_test_server().await;
    let ws_url = base.replace("http://", "ws://") + "/ws";

    let client_kp = IdentityKeypair::generate();
    let client_id = client_kp.device_id();

    let (mut leg_ws, _) = connect_async(&ws_url).await.unwrap();
    let leg_nonce = read_challenge(&mut leg_ws).await;
    let reg = ServerEnvelope::ClientRegister {
        device_id: client_id.clone(),
        public_key_b64: client_kp.public_key_b64(),
        hostname: "LEGIT-PC".to_string(),
        os_version: "Windows 11".to_string(),
        mode: ClientRunMode::Portable,
        unattended_enabled: false,
        signature_b64: sign_registration_challenge(&client_kp, &client_id, &leg_nonce).unwrap(),
    };
    leg_ws
        .send(Message::Text(serde_json::to_string(&reg).unwrap().into()))
        .await
        .unwrap();
    let leg_resp = leg_ws.next().await.unwrap().unwrap();
    assert!(matches!(
        serde_json::from_str::<ServerEnvelope>(leg_resp.to_text().unwrap()).unwrap(),
        ServerEnvelope::ClientRegistered { ok: true, .. }
    ));

    // Attacker tries to register with victim's public key without a valid signature
    let (mut att_ws, _) = connect_async(&ws_url).await.unwrap();
    let _att_nonce = read_challenge(&mut att_ws).await;
    let forged = ServerEnvelope::ClientRegister {
        device_id: client_id.clone(),
        public_key_b64: client_kp.public_key_b64(),
        hostname: "ATTACKER".to_string(),
        os_version: "Windows 11".to_string(),
        mode: ClientRunMode::Portable,
        unattended_enabled: false,
        signature_b64: String::new(),
    };
    att_ws
        .send(Message::Text(serde_json::to_string(&forged).unwrap().into()))
        .await
        .unwrap();
    let att_resp = att_ws.next().await.unwrap().unwrap();
    assert!(matches!(
        serde_json::from_str::<ServerEnvelope>(att_resp.to_text().unwrap()).unwrap(),
        ServerEnvelope::ClientRegistered { ok: false, .. }
    ));
}

#[tokio::test]
async fn reject_second_host_when_client_busy() {
    let (base, _dir) = spawn_test_server().await;
    let ws_url = base.replace("http://", "ws://") + "/ws";

    let client_kp = IdentityKeypair::generate();
    let client_id = client_kp.device_id();
    let (mut client_ws, _) = connect_async(&ws_url).await.unwrap();
    let c_nonce = read_challenge(&mut client_ws).await;
    let reg = ServerEnvelope::ClientRegister {
        device_id: client_id.clone(),
        public_key_b64: client_kp.public_key_b64(),
        hostname: "BUSY-CLIENT".to_string(),
        os_version: "Windows 11".to_string(),
        mode: ClientRunMode::Portable,
        unattended_enabled: false,
        signature_b64: sign_registration_challenge(&client_kp, &client_id, &c_nonce).unwrap(),
    };
    client_ws
        .send(Message::Text(serde_json::to_string(&reg).unwrap().into()))
        .await
        .unwrap();
    let _ = client_ws.next().await.unwrap().unwrap();

    // First host connects and pairs
    let h1_kp = IdentityKeypair::generate();
    let (mut h1_ws, _) = connect_async(&ws_url).await.unwrap();
    let _ = read_challenge(&mut h1_ws).await;
    h1_ws
        .send(Message::Text(
            serde_json::to_string(&ServerEnvelope::HostAuth {
                tech_key: "secret-tech-key".to_string(),
                tech_name: "Tech1".to_string(),
                host_public_key_b64: h1_kp.public_key_b64(),
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    let _ = h1_ws.next().await.unwrap().unwrap();
    h1_ws
        .send(Message::Text(
            serde_json::to_string(&ServerEnvelope::HostConnectRequest {
                target_device_id: client_id.clone(),
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    let _ = h1_ws.next().await.unwrap().unwrap(); // SessionPairing

    // Second host tries to connect to the same busy client
    let h2_kp = IdentityKeypair::generate();
    let (mut h2_ws, _) = connect_async(&ws_url).await.unwrap();
    let _ = read_challenge(&mut h2_ws).await;
    h2_ws
        .send(Message::Text(
            serde_json::to_string(&ServerEnvelope::HostAuth {
                tech_key: "secret-tech-key".to_string(),
                tech_name: "Tech2".to_string(),
                host_public_key_b64: h2_kp.public_key_b64(),
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    let _ = h2_ws.next().await.unwrap().unwrap();
    h2_ws
        .send(Message::Text(
            serde_json::to_string(&ServerEnvelope::HostConnectRequest {
                target_device_id: client_id,
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    let h2_resp = h2_ws.next().await.unwrap().unwrap();
    assert!(matches!(
        serde_json::from_str::<ServerEnvelope>(h2_resp.to_text().unwrap()).unwrap(),
        ServerEnvelope::SessionError { ref code, .. } if code == "client_busy"
    ));
}
