pub mod api;
pub mod state;
pub mod ws;

use std::sync::Arc;

use axum::{routing::get, Router};
use state::ServerState;

pub fn build_router(state: Arc<ServerState>) -> Router {
    Router::new()
        .route("/health", get(api::health))
        .route("/api/devices", get(api::list_devices))
        .route("/api/audit", get(api::list_audit))
        .route("/ws", get(ws::ws_handler))
        .with_state(state)
}
