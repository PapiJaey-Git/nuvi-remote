use std::path::PathBuf;

use anyhow::Result;
use chrono::Utc;
use nuvi_proto::{
    crypto::IdentityKeypair,
    protocol::{normalize_server_url, ChatHistoryEntry, ConnectMode, DEFAULT_SERVER_URL},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressBookEntry {
    pub label: String,
    pub device_id: String,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentSessionEntry {
    pub device_id: String,
    pub label: String,
    pub last_connected_at: String,
    pub mode: ConnectMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostConfig {
    pub identity_secret: [u8; 32],
    pub server_url: String,
    pub tech_key: String,
    pub tech_name: String,
    pub address_book: Vec<AddressBookEntry>,
    #[serde(default)]
    pub recent_sessions: Vec<RecentSessionEntry>,
    #[serde(default)]
    pub pinned_keys: std::collections::HashMap<String, String>,
}

impl Default for HostConfig {
    fn default() -> Self {
        let kp = IdentityKeypair::generate();
        Self {
            identity_secret: kp.to_bytes(),
            server_url: DEFAULT_SERVER_URL.to_string(),
            tech_key: String::new(),
            tech_name: "NUVI Tech".to_string(),
            address_book: Vec::new(),
            recent_sessions: Vec::new(),
            pinned_keys: std::collections::HashMap::new(),
        }
    }
}

pub fn data_dir() -> PathBuf {
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("NUVI Remote").join("host")
}

pub fn config_path() -> PathBuf {
    data_dir().join("config.json")
}

pub fn load_or_create_config() -> HostConfig {
    let path = config_path();
    let mut cfg = if let Ok(raw) = std::fs::read_to_string(&path) {
        if let Ok(mut parsed) = serde_json::from_str::<HostConfig>(&raw) {
            if parsed.server_url.trim().is_empty() {
                parsed.server_url = DEFAULT_SERVER_URL.to_string();
                let _ = save_config(&parsed);
            }
            parsed
        } else {
            let fresh = HostConfig::default();
            let _ = save_config(&fresh);
            fresh
        }
    } else {
        let fresh = HostConfig::default();
        let _ = save_config(&fresh);
        fresh
    };
    if let Ok(env_url) = std::env::var("NUVI_SERVER_URL") {
        let trimmed = env_url.trim();
        if !trimmed.is_empty() {
            cfg.server_url = normalize_server_url(trimmed);
        }
    }
    cfg
}

pub fn save_config(cfg: &HostConfig) -> Result<()> {
    std::fs::create_dir_all(data_dir())?;
    std::fs::write(config_path(), serde_json::to_string_pretty(cfg)?)?;
    Ok(())
}

pub fn pin_device_key(cfg: &mut HostConfig, device_id: &str, pubkey_b64: &str) {
    let norm_id = device_id.trim().to_ascii_uppercase();
    if cfg.pinned_keys.get(&norm_id).map(|k| k.as_str()) != Some(pubkey_b64) {
        cfg.pinned_keys.insert(norm_id, pubkey_b64.to_string());
        let _ = save_config(cfg);
    }
}

pub fn record_recent_session(
    cfg: &mut HostConfig,
    device_id: &str,
    label: &str,
    mode: ConnectMode,
) {
    let norm_id = device_id.trim().to_ascii_uppercase();
    cfg.recent_sessions.retain(|r| r.device_id != norm_id);
    cfg.recent_sessions.insert(
        0,
        RecentSessionEntry {
            device_id: norm_id,
            label: label.to_string(),
            last_connected_at: Utc::now().format("%b %d %H:%M").to_string(),
            mode,
        },
    );
    cfg.recent_sessions.truncate(12);
    let _ = save_config(cfg);
}

pub fn thumbs_dir() -> PathBuf {
    data_dir().join("thumbs")
}

pub fn chats_dir() -> PathBuf {
    data_dir().join("chats")
}

fn sanitize_device_id(device_id: &str) -> String {
    device_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect()
}

pub fn load_chat_history(device_id: &str) -> Vec<ChatHistoryEntry> {
    let safe = sanitize_device_id(device_id);
    if safe.is_empty() {
        return Vec::new();
    }
    let path = chats_dir().join(format!("{safe}.json"));
    let Ok(raw) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    serde_json::from_str::<Vec<ChatHistoryEntry>>(&raw).unwrap_or_default()
}

pub fn append_chat_history(device_id: &str, entry: ChatHistoryEntry) {
    let safe = sanitize_device_id(device_id);
    if safe.is_empty() {
        return;
    }
    let dir = chats_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let mut list = load_chat_history(device_id);
    list.push(entry);
    if list.len() > 200 {
        let drop_n = list.len() - 200;
        list.drain(0..drop_n);
    }
    if let Ok(raw) = serde_json::to_string_pretty(&list) {
        let _ = std::fs::write(dir.join(format!("{safe}.json")), raw);
    }
}

pub fn save_desk_thumbnail(device_id: &str, fb: &egui::ColorImage) {
    let sw = fb.size[0];
    let sh = fb.size[1];
    if sw < 2 || sh < 2 || fb.pixels.is_empty() {
        return;
    }
    let tw = 240usize;
    let th = 135usize;
    let mut rgb = Vec::with_capacity(tw * th * 3);
    for y in 0..th {
        let sy = (y * sh) / th;
        for x in 0..tw {
            let sx = (x * sw) / tw;
            let px = fb.pixels[sy * sw + sx];
            rgb.push(px.r());
            rgb.push(px.g());
            rgb.push(px.b());
        }
    }

    let dir = thumbs_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let mut jpg = Vec::new();
    let enc = jpeg_encoder::Encoder::new(&mut jpg, 78);
    if enc
        .encode(&rgb, tw as u16, th as u16, jpeg_encoder::ColorType::Rgb)
        .is_ok()
    {
        let safe_id: String = device_id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect();
        if !safe_id.is_empty() {
            let _ = std::fs::write(dir.join(format!("{safe_id}.jpg")), jpg);
        }
    }
}

pub fn load_desk_thumbnail(device_id: &str) -> Option<egui::ColorImage> {
    let safe_id: String = device_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    if safe_id.is_empty() {
        return None;
    }
    let bytes = std::fs::read(thumbs_dir().join(format!("{safe_id}.jpg"))).ok()?;
    let mut dec = zune_jpeg::JpegDecoder::new(&bytes);
    let rgb = dec.decode().ok()?;
    let info = dec.info()?;
    let w = info.width as usize;
    let h = info.height as usize;
    if rgb.len() < w * h * 3 {
        return None;
    }
    let pixels: Vec<egui::Color32> = rgb
        .chunks_exact(3)
        .take(w * h)
        .map(|c| egui::Color32::from_rgb(c[0], c[1], c[2]))
        .collect();
    Some(egui::ColorImage {
        size: [w, h],
        pixels,
    })
}

pub fn save_screenshot_png(device_id: &str, fb: &egui::ColorImage) -> Result<PathBuf> {
    let w = fb.size[0] as u32;
    let h = fb.size[1] as u32;
    if w == 0 || h == 0 || fb.pixels.is_empty() {
        anyhow::bail!("No frame available to save");
    }
    let base = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let dir = base.join("Pictures").join("NUVI Remote");
    std::fs::create_dir_all(&dir)?;

    let safe_id: String = device_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    let ts = Utc::now().format("%Y%m%d_%H%M%S");
    let path = dir.join(format!("{safe_id}_{ts}.png"));

    let mut rgba = Vec::with_capacity((w * h * 4) as usize);
    for px in &fb.pixels {
        rgba.push(px.r());
        rgba.push(px.g());
        rgba.push(px.b());
        rgba.push(255);
    }
    let img = image::RgbaImage::from_raw(w, h, rgba)
        .ok_or_else(|| anyhow::anyhow!("Invalid image buffer"))?;
    img.save(&path)?;
    Ok(path)
}
