use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use nuvi_proto::protocol::{AuditEntry, OnlineDeviceSummary};
use serde_json::{json, Value};

use crate::state::{AuthMode, ServerState};

fn is_authorized(state: &ServerState, headers: &HeaderMap) -> bool {
    let Some(auth) = headers.get(axum::http::header::AUTHORIZATION) else {
        return false;
    };
    let Ok(auth_str) = auth.to_str() else {
        return false;
    };
    let token = auth_str
        .strip_prefix("Bearer ")
        .or_else(|| auth_str.strip_prefix("bearer "))
        .unwrap_or("");
    state.verify_tech_key(token)
}

pub async fn health(State(state): State<Arc<ServerState>>) -> Json<Value> {
    Json(json!({
        "ok": true,
        "service": "nuvi-server",
        "auth_mode": state.auth_mode().as_str(),
    }))
}

pub async fn list_devices(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<OnlineDeviceSummary>>, StatusCode> {
    if state.auth_mode() == AuthMode::Open {
        return Err(StatusCode::FORBIDDEN);
    }
    if !is_authorized(&state, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(Json(state.online_devices().await))
}

pub async fn list_audit(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<AuditEntry>>, StatusCode> {
    if state.auth_mode() == AuthMode::Open {
        return Err(StatusCode::FORBIDDEN);
    }
    if !is_authorized(&state, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(Json(state.recent_audit().await))
}
