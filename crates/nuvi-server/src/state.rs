use std::{
    collections::{HashMap, VecDeque},
    path::PathBuf,
    sync::Arc,
};

use axum::extract::ws::Message;
use chrono::{DateTime, Utc};
use nuvi_proto::protocol::{AuditEntry, ClientRunMode, OnlineDeviceSummary};
use subtle::ConstantTimeEq;
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

pub type WsSender = mpsc::Sender<Message>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    Private,
    Open,
}

impl AuthMode {
    pub fn as_str(self) -> &'static str {
        match self {
            AuthMode::Private => "private",
            AuthMode::Open => "open",
        }
    }
}

#[derive(Clone)]
pub struct ClientHandle {
    pub conn_id: Uuid,
    pub device_id: String,
    pub public_key_b64: String,
    pub hostname: String,
    pub os_version: String,
    pub mode: ClientRunMode,
    pub unattended_enabled: bool,
    pub connected_at: DateTime<Utc>,
    pub tx: WsSender,
}

#[derive(Clone)]
pub struct SessionPair {
    pub session_id: Uuid,
    pub host_conn_id: Uuid,
    pub client_conn_id: Uuid,
    pub target_device_id: String,
    pub tech_id: String,
    pub tech_name: String,
    pub started_at: DateTime<Utc>,
    pub host_tx: WsSender,
    pub client_tx: WsSender,
}

pub struct ServerState {
    auth_mode: AuthMode,
    tech_key: String,
    audit_path: PathBuf,
    pub clients: RwLock<HashMap<String, ClientHandle>>,
    pub sessions: RwLock<HashMap<Uuid, SessionPair>>,
    audit_recent: RwLock<VecDeque<AuditEntry>>,
    audit_write_lock: tokio::sync::Mutex<()>,
}

impl ServerState {
    pub async fn new(tech_key: String, data_dir: PathBuf) -> anyhow::Result<Self> {
        Self::new_with_mode(AuthMode::Private, tech_key, data_dir).await
    }

    pub async fn new_with_mode(
        auth_mode: AuthMode,
        tech_key: String,
        data_dir: PathBuf,
    ) -> anyhow::Result<Self> {
        tokio::fs::create_dir_all(&data_dir).await?;
        let audit_path = data_dir.join("audit.jsonl");

        let mut recent = VecDeque::with_capacity(200);
        if let Ok(contents) = tokio::fs::read_to_string(&audit_path).await {
            for line in contents.lines().rev().take(200).collect::<Vec<_>>().into_iter().rev() {
                if let Ok(entry) = serde_json::from_str::<AuditEntry>(line) {
                    recent.push_back(entry);
                }
            }
        }

        Ok(Self {
            auth_mode,
            tech_key,
            audit_path,
            clients: RwLock::new(HashMap::new()),
            sessions: RwLock::new(HashMap::new()),
            audit_recent: RwLock::new(recent),
            audit_write_lock: tokio::sync::Mutex::new(()),
        })
    }

    pub fn auth_mode(&self) -> AuthMode {
        self.auth_mode
    }

    pub fn verify_tech_key(&self, candidate: &str) -> bool {
        if self.auth_mode == AuthMode::Open {
            return true;
        }
        let expected = self.tech_key.as_bytes();
        let provided = candidate.trim().as_bytes();
        !expected.is_empty()
            && expected.len() == provided.len()
            && bool::from(expected.ct_eq(provided))
    }

    pub async fn online_devices(&self) -> Vec<OnlineDeviceSummary> {
        let guard = self.clients.read().await;
        let mut out: Vec<_> = guard
            .values()
            .map(|c| OnlineDeviceSummary {
                device_id: c.device_id.clone(),
                hostname: c.hostname.clone(),
                os_version: c.os_version.clone(),
                mode: c.mode,
                unattended_enabled: c.unattended_enabled,
                connected_at: c.connected_at.to_rfc3339(),
            })
            .collect();
        out.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        out
    }

    pub async fn recent_audit(&self) -> Vec<AuditEntry> {
        let guard = self.audit_recent.read().await;
        guard.iter().cloned().collect()
    }

    pub async fn append_audit(&self, entry: AuditEntry) {
        {
            let mut recent = self.audit_recent.write().await;
            if recent.len() >= 200 {
                recent.pop_front();
            }
            recent.push_back(entry.clone());
        }
        if let Ok(mut line) = serde_json::to_string(&entry) {
            line.push('\n');
            let _guard = self.audit_write_lock.lock().await;
            use tokio::io::AsyncWriteExt;
            if let Ok(mut f) = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.audit_path)
                .await
            {
                let _ = f.write_all(line.as_bytes()).await;
            }
        }
    }
}

pub fn make_audit(
    event: &str,
    session_id: Option<Uuid>,
    tech_id: Option<&str>,
    tech_name: Option<&str>,
    target_device_id: Option<&str>,
    detail: impl Into<String>,
) -> AuditEntry {
    AuditEntry {
        timestamp: Utc::now().to_rfc3339(),
        event: event.to_string(),
        session_id,
        tech_id: tech_id.map(|s| s.to_string()),
        tech_name: tech_name.map(|s| s.to_string()),
        target_device_id: target_device_id.map(|s| s.to_string()),
        detail: detail.into(),
    }
}

pub async fn cleanup_connection_sessions(state: &Arc<ServerState>, conn_id: Uuid, reason: &str) {
    let removed: Vec<SessionPair> = {
        let mut sessions = state.sessions.write().await;
        let ids: Vec<Uuid> = sessions
            .iter()
            .filter(|(_, s)| s.host_conn_id == conn_id || s.client_conn_id == conn_id)
            .map(|(id, _)| *id)
            .collect();
        ids.into_iter().filter_map(|id| sessions.remove(&id)).collect()
    };

    for pair in removed {
        let duration_secs = (Utc::now() - pair.started_at).num_seconds().max(0);
        let closed = nuvi_proto::protocol::ServerEnvelope::SessionClosed {
            session_id: pair.session_id,
            reason: reason.to_string(),
        };
        if let Ok(txt) = serde_json::to_string(&closed) {
            let msg = Message::Text(txt.into());
            if pair.host_conn_id != conn_id {
                let _ = pair.host_tx.send(msg.clone()).await;
            }
            if pair.client_conn_id != conn_id {
                let _ = pair.client_tx.send(msg).await;
            }
        }
        state
            .append_audit(make_audit(
                "session_ended",
                Some(pair.session_id),
                Some(&pair.tech_id),
                Some(&pair.tech_name),
                Some(&pair.target_device_id),
                format!("{reason} (duration {duration_secs}s)"),
            ))
            .await;
    }
}
