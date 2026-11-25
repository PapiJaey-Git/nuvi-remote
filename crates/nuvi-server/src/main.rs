use std::{path::PathBuf, sync::Arc};

use nuvi_server::{
    build_router,
    state::{AuthMode, ServerState},
};
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use tracing::info;
use tracing_subscriber::EnvFilter;

fn generate_random_tech_key() -> String {
    OsRng
        .sample_iter(&Alphanumeric)
        .take(48)
        .map(char::from)
        .collect()
}

fn load_or_generate_tech_key(data_dir: &std::path::Path) -> anyhow::Result<String> {
    if let Ok(v) = std::env::var("NUVI_TECH_KEY") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }

    let key_path = data_dir.join("tech.key");
    if let Ok(existing) = std::fs::read_to_string(&key_path) {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            info!("Loaded persisted NUVI_TECH_KEY from {}", key_path.display());
            return Ok(trimmed.to_string());
        }
    }

    std::fs::create_dir_all(data_dir)?;
    let generated = generate_random_tech_key();
    std::fs::write(&key_path, format!("{generated}\n"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
    }

    info!("=================================================================");
    info!("Generated new NUVI_TECH_KEY (saved to {}):", key_path.display());
    info!("  {generated}");
    info!("Paste this key once into nuvi-host Settings -> NUVI Tech Key.");
    info!("=================================================================");
    Ok(generated)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("nuvi_server=info,info")),
        )
        .init();

    let bind_addr =
        std::env::var("NUVI_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8765".to_string());
    let auth_mode = match std::env::var("NUVI_AUTH_MODE") {
        Ok(v) if v.trim().eq_ignore_ascii_case("open") => AuthMode::Open,
        _ => AuthMode::Private,
    };
    let data_dir = std::env::var("NUVI_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./data"));

    let tech_key = match auth_mode {
        AuthMode::Private => load_or_generate_tech_key(&data_dir)?,
        AuthMode::Open => {
            info!("NUVI Remote server running in OPEN mode (no tech key required; /api/devices disabled)");
            String::new()
        }
    };

    let state = Arc::new(ServerState::new_with_mode(auth_mode, tech_key, data_dir).await?);
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!(
        "nuvi-server listening on {bind_addr} (auth_mode={})",
        auth_mode.as_str()
    );
    axum::serve(listener, app).await?;
    Ok(())
}
