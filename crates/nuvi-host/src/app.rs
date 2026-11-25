use std::{
    collections::{HashMap, HashSet},
    time::Instant,
};

use chrono::Local;
use egui::{
    Color32, ColorImage, CursorIcon, Margin, Modifiers, PointerButton, Pos2, Rect, RichText,
    Sense, Stroke, Vec2,
};
use nuvi_proto::{
    brand,
    crypto::IdentityKeypair,
    protocol::{
        format_setup_code, normalize_server_url, AnnotationKind, ChatHistoryEntry, ClientRunMode,
        ConnectMode, MonitorInfo, MouseButton, MouseEventKind, OnlineDeviceSummary, PeerMessage,
        QualityPreset, RemoteCursorShape, RemoteQuickAction, SessionPermissions, VideoFrame,
        HAS_BAKED_SERVER_URL,
    },
};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::{
    keymap::{egui_key_to_scancode, ModifierTracker},
    net::{
        spawn_fetch_devices, spawn_host_session, spawn_probe_server, ConnectParams, HostNetEvent,
        HostUiCmd,
    },
    storage::{
        append_chat_history, load_chat_history, load_desk_thumbnail, pin_device_key,
        record_recent_session, save_config, save_desk_thumbnail, save_screenshot_png,
        AddressBookEntry, HostConfig,
    },
    theme::{
        c, danger_pill_button, draw_nuvi_logo_mark, nuvi_card, nuvi_feature_tile, nuvi_flat_tab,
        nuvi_ribbon_banner, nuvi_session_tile, primary_pill_button, secondary_pill_button,
        segmented_tab_button, status_pill,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveTab {
    Home,
    Session(Uuid),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeskFilter {
    Overview,
    Online,
    Favorites,
    Recent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ViewMode {
    Grid,
    List,
}

struct DeskTileItem {
    device_id: String,
    title: String,
    subtitle: String,
    online: bool,
    is_service: bool,
    is_unattended: bool,
    is_saved: bool,
    saved_idx: Option<usize>,
}

struct SessionTab {
    tab_id: Uuid,
    device_id: String,
    mode: ConnectMode,
    cmd_tx: mpsc::UnboundedSender<HostUiCmd>,
    established: bool,
    client_mode: ClientRunMode,
    monitors: Vec<MonitorInfo>,
    active_monitor: u8,
    quality: QualityPreset,
    permissions: SessionPermissions,
    view_only: bool,
    rtt_ms: u64,
    notice: Option<String>,
    confirm_reboot: bool,
    show_actions: bool,

    fb_width: usize,
    fb_height: usize,
    framebuffer: ColorImage,
    texture: Option<egui::TextureHandle>,
    connected_at: Instant,
    thumb_saved: bool,

    remote_cursor: RemoteCursorShape,
    annotate_mode: bool,
    local_strokes: Vec<(f32, f32, f32, f32)>,
    last_stroke_pt: Option<(f32, f32)>,
    last_laser_sent: Instant,

    chat_open: bool,
    unread_chat: usize,
    chat_messages: Vec<ChatHistoryEntry>,
    chat_draft: String,
    auth_challenge: Option<String>,
    auth_key_draft: String,
    file_progress: Option<(String, u64, u64, bool)>,

    last_clip: String,
    last_clip_check: Instant,
    mod_tracker: ModifierTracker,

    frame_count: u32,
    fps_window_start: Instant,
    fps_display: f32,
    last_move_sent: Instant,
    had_focus: bool,
}

impl SessionTab {
    fn new(
        tab_id: Uuid,
        device_id: String,
        mode: ConnectMode,
        cmd_tx: mpsc::UnboundedSender<HostUiCmd>,
    ) -> Self {
        let chat_messages = load_chat_history(&device_id);
        Self {
            tab_id,
            device_id,
            mode,
            cmd_tx,
            established: false,
            client_mode: ClientRunMode::Portable,
            monitors: Vec::new(),
            active_monitor: 0,
            quality: QualityPreset::Auto,
            permissions: SessionPermissions::default(),
            view_only: false,
            rtt_ms: 0,
            notice: Some("Connecting...".to_string()),
            confirm_reboot: false,
            show_actions: false,
            fb_width: 0,
            fb_height: 0,
            framebuffer: ColorImage::new([1, 1], Color32::BLACK),
            texture: None,
            connected_at: Instant::now(),
            thumb_saved: false,
            remote_cursor: RemoteCursorShape::Default,
            annotate_mode: false,
            local_strokes: Vec::new(),
            last_stroke_pt: None,
            last_laser_sent: Instant::now(),
            chat_open: false,
            unread_chat: 0,
            chat_messages,
            chat_draft: String::new(),
            auth_challenge: None,
            auth_key_draft: String::new(),
            file_progress: None,
            last_clip: String::new(),
            last_clip_check: Instant::now(),
            mod_tracker: ModifierTracker::default(),
            frame_count: 0,
            fps_window_start: Instant::now(),
            fps_display: 0.0,
            last_move_sent: Instant::now(),
            had_focus: false,
        }
    }

    fn apply_frame(&mut self, ctx: &egui::Context, vf: VideoFrame) {
        let w = vf.width as usize;
        let h = vf.height as usize;
        if w == 0 || h == 0 {
            return;
        }
        if self.fb_width != w
            || self.fb_height != h
            || (vf.full_frame && self.framebuffer.size != [w, h])
        {
            self.fb_width = w;
            self.fb_height = h;
            self.framebuffer = ColorImage::new([w, h], Color32::BLACK);
        }

        for tile in vf.tiles {
            let mut decoder = zune_jpeg::JpegDecoder::new(&tile.jpeg_data);
            if let Ok(rgb) = decoder.decode() {
                let tw = tile.w as usize;
                let th = tile.h as usize;
                let tx = tile.x as usize;
                let ty = tile.y as usize;
                if rgb.len() >= tw * th * 3 {
                    for row in 0..th {
                        let dy = ty + row;
                        if dy >= h {
                            break;
                        }
                        for col in 0..tw {
                            let dx = tx + col;
                            if dx >= w {
                                break;
                            }
                            let si = (row * tw + col) * 3;
                            let di = dy * w + dx;
                            self.framebuffer.pixels[di] =
                                Color32::from_rgb(rgb[si], rgb[si + 1], rgb[si + 2]);
                        }
                    }
                }
            }
        }

        if let Some(tex) = &mut self.texture {
            tex.set(self.framebuffer.clone(), egui::TextureOptions::LINEAR);
        } else {
            self.texture = Some(ctx.load_texture(
                format!("remote_screen_{}", self.tab_id),
                self.framebuffer.clone(),
                egui::TextureOptions::LINEAR,
            ));
        }

        if !self.thumb_saved && self.connected_at.elapsed().as_secs() >= 2 {
            save_desk_thumbnail(&self.device_id, &self.framebuffer);
            self.thumb_saved = true;
        }

        self.frame_count += 1;
        let elapsed = self.fps_window_start.elapsed().as_secs_f32();
        if elapsed >= 1.0 {
            self.fps_display = self.frame_count as f32 / elapsed;
            self.frame_count = 0;
            self.fps_window_start = Instant::now();
        }
    }
}

pub struct NuviHostApp {
    config: HostConfig,
    host_device_id: String,
    ev_tx: mpsc::UnboundedSender<HostNetEvent>,
    ev_rx: mpsc::UnboundedReceiver<HostNetEvent>,

    active_tab: ActiveTab,
    desk_filter: DeskFilter,
    view_mode: ViewMode,
    search_query: String,

    target_id: String,
    reason: String,
    unattended_key: String,

    status_msg: Option<String>,
    server_auth_mode: Option<String>,
    server_url_draft: String,
    online_devices: Vec<OnlineDeviceSummary>,
    did_initial_fetch: bool,

    show_settings: bool,
    reveal_tech_key: bool,
    show_save_bar: bool,
    new_label: String,
    new_notes: String,

    thumb_cache: HashMap<String, Option<egui::TextureHandle>>,
    sessions: Vec<SessionTab>,
}

impl NuviHostApp {
    pub fn new(
        config: HostConfig,
        ev_tx: mpsc::UnboundedSender<HostNetEvent>,
        ev_rx: mpsc::UnboundedReceiver<HostNetEvent>,
    ) -> Self {
        let host_device_id = IdentityKeypair::from_bytes(&config.identity_secret).device_id();
        let show_settings =
            (!HAS_BAKED_SERVER_URL && config.server_url == "ws://127.0.0.1:8765/ws")
                || config.tech_key.trim().is_empty();
        let server_url_draft = config.server_url.clone();
        Self {
            config,
            host_device_id,
            ev_tx,
            ev_rx,
            active_tab: ActiveTab::Home,
            desk_filter: DeskFilter::Overview,
            view_mode: ViewMode::Grid,
            search_query: String::new(),
            target_id: String::new(),
            reason: "NUVI Remote Support".to_string(),
            unattended_key: String::new(),
            status_msg: None,
            server_auth_mode: None,
            server_url_draft,
            online_devices: Vec::new(),
            did_initial_fetch: false,
            show_settings,
            reveal_tech_key: false,
            show_save_bar: false,
            new_label: String::new(),
            new_notes: String::new(),
            thumb_cache: HashMap::new(),
            sessions: Vec::new(),
        }
    }

    fn get_or_load_thumb(
        &mut self,
        ctx: &egui::Context,
        device_id: &str,
    ) -> Option<&egui::TextureHandle> {
        if !self.thumb_cache.contains_key(device_id) {
            let tex = load_desk_thumbnail(device_id).map(|img| {
                ctx.load_texture(
                    format!("thumb_{device_id}"),
                    img,
                    egui::TextureOptions::LINEAR,
                )
            });
            self.thumb_cache.insert(device_id.to_string(), tex);
        }
        self.thumb_cache.get(device_id).and_then(|o| o.as_ref())
    }

    fn start_connect(&mut self, ctx: &egui::Context, id_override: Option<String>) {
        if let Some(id) = id_override {
            self.target_id = id;
        }
        let target = self.target_id.trim().to_ascii_uppercase();
        if target.is_empty() {
            return;
        }
        if self.server_auth_mode.as_deref() != Some("open") && self.config.tech_key.trim().is_empty()
        {
            self.show_settings = true;
            self.status_msg = Some("Paste your NUVI Tech Key in Settings first.".to_string());
            return;
        }
        self.target_id = target.clone();

        // If already open in a tab, switch to it
        if let Some(existing) = self.sessions.iter().find(|s| s.device_id == target) {
            self.active_tab = ActiveTab::Session(existing.tab_id);
            return;
        }

        let detected_unattended = self
            .online_devices
            .iter()
            .find(|d| d.device_id == target)
            .map(|d| d.unattended_enabled)
            .unwrap_or(false);
        let auto_mode = if detected_unattended || !self.unattended_key.trim().is_empty() {
            ConnectMode::Unattended
        } else {
            ConnectMode::Attended
        };
        let key_opt = if self.unattended_key.trim().is_empty() {
            None
        } else {
            Some(self.unattended_key.trim().to_string())
        };

        let tab_id = Uuid::new_v4();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let params = ConnectParams {
            server_url: self.config.server_url.trim().to_string(),
            tech_key: self.config.tech_key.trim().to_string(),
            tech_name: self.config.tech_name.trim().to_string(),
            identity_secret: self.config.identity_secret,
            target_device_id: target.clone(),
            reason: self.reason.clone(),
            unattended_key: key_opt,
            pinned_peer_key_b64: self.config.pinned_keys.get(&target).cloned(),
        };

        spawn_host_session(tab_id, params, cmd_rx, self.ev_tx.clone(), ctx.clone());
        self.sessions
            .push(SessionTab::new(tab_id, target, auto_mode, cmd_tx));
        self.active_tab = ActiveTab::Session(tab_id);
    }

    fn drain_events(&mut self, ctx: &egui::Context) {
        while let Ok(ev) = self.ev_rx.try_recv() {
            match ev {
                HostNetEvent::Status { tab_id, message } => {
                    if let Some(s) = self.sessions.iter_mut().find(|s| s.tab_id == tab_id) {
                        s.notice = Some(message.clone());
                    }
                    self.status_msg = Some(message);
                }
                HostNetEvent::UnattendedKeyRequired { tab_id, message } => {
                    if let Some(s) = self.sessions.iter_mut().find(|s| s.tab_id == tab_id) {
                        s.mode = ConnectMode::Unattended;
                        s.auth_challenge = Some(message);
                        s.auth_key_draft.clear();
                        s.notice = None;
                    }
                    self.active_tab = ActiveTab::Session(tab_id);
                }
                HostNetEvent::PeerKeyVerified {
                    device_id,
                    public_key_b64,
                } => {
                    pin_device_key(&mut self.config, &device_id, &public_key_b64);
                }
                HostNetEvent::SessionEstablished {
                    tab_id,
                    device_id,
                    mode,
                    client_mode,
                    monitors,
                    permissions,
                } => {
                    self.status_msg = None;
                    let label = self
                        .online_devices
                        .iter()
                        .find(|d| d.device_id == device_id)
                        .map(|d| d.hostname.clone())
                        .or_else(|| {
                            self.config
                                .address_book
                                .iter()
                                .find(|a| a.device_id == device_id)
                                .map(|a| a.label.clone())
                        })
                        .unwrap_or_else(|| device_id.clone());
                    record_recent_session(&mut self.config, &device_id, &label, mode);
                    if let Some(s) = self.sessions.iter_mut().find(|s| s.tab_id == tab_id) {
                        s.established = true;
                        s.mode = mode;
                        s.auth_challenge = None;
                        s.auth_key_draft.clear();
                        s.client_mode = client_mode;
                        s.monitors = monitors;
                        s.permissions = permissions;
                        s.view_only = !permissions.allow_control;
                        s.notice = None;
                        s.connected_at = Instant::now();
                    }
                    self.active_tab = ActiveTab::Session(tab_id);
                }
                HostNetEvent::VideoFrame { tab_id, frame } => {
                    if let Some(s) = self.sessions.iter_mut().find(|s| s.tab_id == tab_id) {
                        s.apply_frame(ctx, frame);
                    }
                }
                HostNetEvent::RttMs { tab_id, rtt } => {
                    if let Some(s) = self.sessions.iter_mut().find(|s| s.tab_id == tab_id) {
                        s.rtt_ms = rtt;
                    }
                }
                HostNetEvent::SystemNotice { tab_id, message } => {
                    if let Some(s) = self.sessions.iter_mut().find(|s| s.tab_id == tab_id) {
                        s.notice = Some(message);
                    }
                }
                HostNetEvent::ClipboardReceived { tab_id, text } => {
                    if let Some(s) = self.sessions.iter_mut().find(|s| s.tab_id == tab_id) {
                        if s.permissions.allow_clipboard && text != s.last_clip {
                            s.last_clip = text.clone();
                            if let Ok(mut cb) = arboard::Clipboard::new() {
                                let _ = cb.set_text(text);
                            }
                        }
                    }
                }
                HostNetEvent::ChatMessage {
                    tab_id,
                    sender,
                    text,
                    sent_at,
                } => {
                    if let Some(s) = self.sessions.iter_mut().find(|s| s.tab_id == tab_id) {
                        if !s.chat_open {
                            s.unread_chat += 1;
                        }
                        let entry = ChatHistoryEntry {
                            sender,
                            text,
                            sent_at,
                        };
                        append_chat_history(&s.device_id, entry.clone());
                        s.chat_messages.push(entry);
                    }
                }
                HostNetEvent::FileProgress {
                    tab_id,
                    filename,
                    sent,
                    total,
                    done,
                } => {
                    if let Some(s) = self.sessions.iter_mut().find(|s| s.tab_id == tab_id) {
                        s.file_progress = Some((filename, sent, total, done));
                    }
                }
                HostNetEvent::FileAck {
                    tab_id,
                    ok,
                    message,
                } => {
                    if let Some(s) = self.sessions.iter_mut().find(|s| s.tab_id == tab_id) {
                        s.notice = Some(if ok {
                            message
                        } else {
                            format!("Transfer failed: {message}")
                        });
                    }
                }
                HostNetEvent::CursorShape { tab_id, shape } => {
                    if let Some(s) = self.sessions.iter_mut().find(|s| s.tab_id == tab_id) {
                        s.remote_cursor = shape;
                    }
                }
                HostNetEvent::SessionEnded { tab_id, reason } => {
                    if let Some(pos) = self.sessions.iter().position(|s| s.tab_id == tab_id) {
                        let s = self.sessions.remove(pos);
                        if s.fb_width > 1 && s.fb_height > 1 {
                            save_desk_thumbnail(&s.device_id, &s.framebuffer);
                            self.thumb_cache.remove(&s.device_id);
                        }
                    }
                    if self.active_tab == ActiveTab::Session(tab_id) {
                        self.active_tab = self
                            .sessions
                            .last()
                            .map(|s| ActiveTab::Session(s.tab_id))
                            .unwrap_or(ActiveTab::Home);
                    }
                    self.status_msg = Some(reason);
                }
                HostNetEvent::ServerHealth(res) => match res {
                    Ok(mode) => {
                        self.server_auth_mode = Some(mode.clone());
                        if mode == "open" {
                            self.online_devices.clear();
                            if self.config.tech_key.trim().is_empty()
                                && self.config.server_url != "ws://127.0.0.1:8765/ws"
                            {
                                self.show_settings = false;
                            }
                        } else if !self.config.tech_key.trim().is_empty() {
                            spawn_fetch_devices(
                                self.config.server_url.clone(),
                                self.config.tech_key.clone(),
                                self.ev_tx.clone(),
                                ctx.clone(),
                            );
                        }
                    }
                    Err(e) => {
                        self.status_msg = Some(format!("Server check failed: {e}"));
                    }
                },
                HostNetEvent::OnlineDevices(res) => match res {
                    Ok(list) => {
                        self.online_devices = list;
                        self.status_msg = None;
                    }
                    Err(e) => {
                        self.status_msg = Some(format!("Device refresh failed: {e}"));
                    }
                },
            }
        }
    }

    fn collect_desk_tiles(&self) -> Vec<DeskTileItem> {
        let mut items = Vec::new();
        let mut seen = HashSet::new();

        let online_map: HashMap<&str, &OnlineDeviceSummary> = self
            .online_devices
            .iter()
            .map(|d| (d.device_id.as_str(), d))
            .collect();

        let saved_map: HashMap<&str, (usize, &AddressBookEntry)> = self
            .config
            .address_book
            .iter()
            .enumerate()
            .map(|(i, a)| (a.device_id.as_str(), (i, a)))
            .collect();

        let add_entry = |id: &str,
                         fallback_title: &str,
                         fallback_sub: &str,
                         items: &mut Vec<DeskTileItem>,
                         seen: &mut HashSet<String>| {
            if !seen.insert(id.to_string()) {
                return;
            }
            let online_dev = online_map.get(id).copied();
            let saved_dev = saved_map.get(id).copied();

            let title = saved_dev
                .map(|(_, s)| s.label.clone())
                .or_else(|| online_dev.map(|d| d.hostname.clone()))
                .unwrap_or_else(|| fallback_title.to_string());

            let subtitle = if let Some((_, s)) = saved_dev {
                if !s.notes.is_empty() {
                    s.notes.clone()
                } else if online_dev.is_some() {
                    "Online now".to_string()
                } else {
                    "Favorite".to_string()
                }
            } else {
                fallback_sub.to_string()
            };

            items.push(DeskTileItem {
                device_id: id.to_string(),
                title,
                subtitle,
                online: online_dev.is_some(),
                is_service: online_dev
                    .map(|d| d.mode == ClientRunMode::Service)
                    .unwrap_or(false),
                is_unattended: online_dev.map(|d| d.unattended_enabled).unwrap_or(false),
                is_saved: saved_dev.is_some(),
                saved_idx: saved_dev.map(|(idx, _)| idx),
            });
        };

        match self.desk_filter {
            DeskFilter::Overview => {
                for r in &self.config.recent_sessions {
                    add_entry(
                        &r.device_id,
                        &r.label,
                        &format!("Last: {}", r.last_connected_at),
                        &mut items,
                        &mut seen,
                    );
                }
                for d in &self.online_devices {
                    add_entry(&d.device_id, &d.hostname, "Online now", &mut items, &mut seen);
                }
                for s in &self.config.address_book {
                    add_entry(&s.device_id, &s.label, "Favorite", &mut items, &mut seen);
                }
            }
            DeskFilter::Online => {
                for d in &self.online_devices {
                    add_entry(&d.device_id, &d.hostname, "Online now", &mut items, &mut seen);
                }
            }
            DeskFilter::Favorites => {
                for s in &self.config.address_book {
                    add_entry(&s.device_id, &s.label, "Favorite", &mut items, &mut seen);
                }
            }
            DeskFilter::Recent => {
                for r in &self.config.recent_sessions {
                    add_entry(
                        &r.device_id,
                        &r.label,
                        &format!("Last: {}", r.last_connected_at),
                        &mut items,
                        &mut seen,
                    );
                }
            }
        }

        let q = self.search_query.trim().to_ascii_lowercase();
        if !q.is_empty() {
            items.retain(|it| {
                it.title.to_ascii_lowercase().contains(&q)
                    || it.device_id.to_ascii_lowercase().contains(&q)
                    || it.subtitle.to_ascii_lowercase().contains(&q)
            });
        }
        items
    }
}

impl eframe::App for NuviHostApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.did_initial_fetch {
            self.did_initial_fetch = true;
            spawn_probe_server(
                self.config.server_url.clone(),
                self.ev_tx.clone(),
                ctx.clone(),
            );
        }

        self.drain_events(ctx);

        // Row 1: Ultra-Slim Top Multi-Session Tab Strip
        egui::TopBottomPanel::top("nuvi_tab_bar")
            .frame(
                egui::Frame::new()
                    .fill(Color32::from_rgb(11, 13, 23))
                    .stroke(Stroke::new(1.0_f32, c(brand::BORDER_SUBTLE)))
                    .inner_margin(Margin::symmetric(10, 4)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    draw_nuvi_logo_mark(ui, 18.0);
                    ui.label(
                        RichText::new("NUVI Remote")
                            .size(12.5)
                            .strong()
                            .color(c(brand::TEXT_PRIMARY)),
                    );
                    ui.add_space(6.0);

                    if segmented_tab_button(
                        ui,
                        self.active_tab == ActiveTab::Home,
                        "New Session",
                    )
                    .clicked()
                    {
                        self.active_tab = ActiveTab::Home;
                    }

                    let mut close_tab_id: Option<Uuid> = None;
                    for s in &self.sessions {
                        let unread = if s.unread_chat > 0 {
                            format!(" ({})", s.unread_chat)
                        } else {
                            String::new()
                        };
                        let dot = if s.established { "●" } else { "○" };
                        let lbl = format!("{dot} {}{}", s.device_id, unread);
                        if segmented_tab_button(
                            ui,
                            self.active_tab == ActiveTab::Session(s.tab_id),
                            &lbl,
                        )
                        .clicked()
                        {
                            self.active_tab = ActiveTab::Session(s.tab_id);
                        }
                        if secondary_pill_button(ui, "×").clicked() {
                            close_tab_id = Some(s.tab_id);
                        }
                    }
                    if let Some(tid) = close_tab_id {
                        if let Some(s) = self.sessions.iter().find(|s| s.tab_id == tid) {
                            let _ = s.cmd_tx.send(HostUiCmd::Disconnect);
                        }
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let settings_lbl = if self.show_settings {
                            "Close Settings"
                        } else {
                            "Settings"
                        };
                        if secondary_pill_button(ui, settings_lbl).clicked() {
                            self.show_settings = !self.show_settings;
                        }
                        if secondary_pill_button(ui, "Refresh").clicked() {
                            spawn_probe_server(
                                self.config.server_url.clone(),
                                self.ev_tx.clone(),
                                ctx.clone(),
                            );
                        }
                    });
                });
            });

        match self.active_tab {
            ActiveTab::Session(tid) => {
                if self.sessions.iter().any(|s| s.tab_id == tid) {
                    self.render_viewer(ctx, tid);
                } else {
                    self.active_tab = ActiveTab::Home;
                    self.render_console(ctx);
                }
            }
            ActiveTab::Home => self.render_console(ctx),
        }
    }
}

impl NuviHostApp {
    fn render_console(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("nuvi_address_bar")
            .frame(
                egui::Frame::new()
                    .fill(c(brand::BG_CANVAS))
                    .stroke(Stroke::new(1.0_f32, c(brand::BORDER_SUBTLE)))
                    .inner_margin(Margin::symmetric(10, 6)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let is_ready = self.server_auth_mode.as_deref() == Some("open")
                        || !self.config.tech_key.trim().is_empty();
                    let dot_col = if is_ready {
                        c(brand::STATUS_ONLINE)
                    } else {
                        c(brand::TEXT_MUTED)
                    };
                    let (drect, _) = ui.allocate_exact_size(Vec2::splat(10.0), Sense::hover());
                    ui.painter().circle_filled(drect.center(), 4.5, dot_col);

                    let norm_target = self.target_id.trim().to_ascii_uppercase();
                    let detected_unattended = self
                        .online_devices
                        .iter()
                        .find(|d| d.device_id == norm_target)
                        .map(|d| d.unattended_enabled);

                    let id_resp = ui.add(
                        egui::TextEdit::singleline(&mut self.target_id)
                            .hint_text("Enter Remote Address (NUVI-XXX-XXX-XXX)")
                            .desired_width((ui.available_width() - 400.0).max(200.0)),
                    );
                    if id_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        self.start_connect(ctx, None);
                    }

                    match detected_unattended {
                        Some(true) => {
                            ui.label(
                                RichText::new("AUTO: UNATTENDED")
                                    .size(11.0)
                                    .strong()
                                    .color(c(brand::ACCENT_HIGHLIGHT)),
                            );
                            let key_resp = ui.add(
                                egui::TextEdit::singleline(&mut self.unattended_key)
                                    .password(true)
                                    .hint_text("Unattended Key (or enter after)")
                                    .desired_width(185.0),
                            );
                            if key_resp.lost_focus()
                                && ui.input(|i| i.key_pressed(egui::Key::Enter))
                            {
                                self.start_connect(ctx, None);
                            }
                        }
                        Some(false) => {
                            ui.label(
                                RichText::new("AUTO: ATTENDED")
                                    .size(11.0)
                                    .strong()
                                    .color(c(brand::TEXT_MUTED)),
                            );
                            ui.add(
                                egui::TextEdit::singleline(&mut self.reason)
                                    .hint_text("Support note")
                                    .desired_width(175.0),
                            );
                        }
                        None => {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.reason)
                                    .hint_text("Support note (mode auto-detected)")
                                    .desired_width(210.0),
                            );
                        }
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if primary_pill_button(ui, "->").clicked() {
                            self.start_connect(ctx, None);
                        }
                    });
                });
            });

        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(c(brand::BG_CANVAS)).inner_margin(Margin::ZERO))
            .show(ctx, |ui| {
                let endpoint = self
                    .config
                    .server_url
                    .trim_start_matches("wss://")
                    .trim_start_matches("ws://")
                    .trim_end_matches("/ws")
                    .to_string();
                let ribbon_text = if let Some(msg) = &self.status_msg {
                    format!("NUVI Remote  ·  {msg}")
                } else {
                    format!("NUVI Remote  ·  Private Relay: {endpoint}  ·  End-to-End Encrypted")
                };
                nuvi_ribbon_banner(ui, &ribbon_text);

                egui::Frame::new()
                    .inner_margin(Margin::symmetric(20, 14))
                    .show(ui, |ui| {
                        ui.vertical_centered(|ui| {
                            ui.horizontal(|ui| {
                                let spaced_id = self.host_device_id.replace('-', " ");
                                let total_w = 460.0_f32.min(ui.available_width());
                                ui.add_space(((ui.available_width() - total_w) * 0.5).max(0.0));
                                ui.label(
                                    RichText::new("Tech Desk")
                                        .size(14.0)
                                        .color(c(brand::TEXT_MUTED)),
                                );
                                ui.add_space(6.0);
                                ui.label(
                                    RichText::new(spaced_id)
                                        .size(28.0)
                                        .strong()
                                        .color(c(brand::ACCENT_PRIMARY)),
                                );
                                ui.add_space(6.0);
                                if secondary_pill_button(ui, "Copy").clicked() {
                                    ctx.copy_text(self.host_device_id.clone());
                                    self.status_msg = Some("Tech Desk ID copied.".to_string());
                                }
                                if secondary_pill_button(ui, "Auth Key").clicked() {
                                    self.show_settings = !self.show_settings;
                                }
                            });
                        });

                        ui.add_space(8.0);

                        if self.show_settings {
                            nuvi_card(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(
                                        RichText::new("Relay Server & Authentication")
                                            .size(13.5)
                                            .strong()
                                            .color(c(brand::TEXT_PRIMARY)),
                                    );
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if secondary_pill_button(ui, "Copy Client Setup")
                                                .clicked()
                                            {
                                                let code =
                                                    format_setup_code(&self.config.server_url);
                                                ctx.copy_text(code.clone());
                                                self.status_msg = Some(format!(
                                                    "Copied client setup code: {code}"
                                                ));
                                            }
                                        },
                                    );
                                });
                                ui.add_space(6.0);
                                ui.horizontal(|ui| {
                                    ui.label(
                                        RichText::new("Server Address")
                                            .size(12.0)
                                            .color(c(brand::TEXT_MUTED)),
                                    );
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.server_url_draft)
                                            .hint_text("remote.yourdomain.com, 192.168.1.50, or ws://...")
                                            .desired_width(340.0),
                                    );
                                    if primary_pill_button(ui, "Save & Test").clicked() {
                                        let normalized =
                                            normalize_server_url(&self.server_url_draft);
                                        self.server_url_draft = normalized.clone();
                                        self.config.server_url = normalized.clone();
                                        let _ = save_config(&self.config);
                                        self.server_auth_mode = None;
                                        self.status_msg =
                                            Some(format!("Probing {normalized}..."));
                                        spawn_probe_server(
                                            normalized,
                                            self.ev_tx.clone(),
                                            ctx.clone(),
                                        );
                                    }
                                });
                                ui.add_space(6.0);
                                if self.server_auth_mode.as_deref() == Some("open") {
                                    ui.horizontal(|ui| {
                                        ui.label(
                                            RichText::new("Server is in OPEN mode — no Tech Key needed (online directory disabled).")
                                                .size(12.0)
                                                .color(c(brand::STATUS_ONLINE)),
                                        );
                                        ui.add_space(8.0);
                                        ui.label(
                                            RichText::new("Tech Name")
                                                .size(12.0)
                                                .color(c(brand::TEXT_MUTED)),
                                        );
                                        if ui
                                            .add(
                                                egui::TextEdit::singleline(
                                                    &mut self.config.tech_name,
                                                )
                                                .desired_width(150.0),
                                            )
                                            .changed()
                                        {
                                            let _ = save_config(&self.config);
                                        }
                                    });
                                } else {
                                    ui.horizontal(|ui| {
                                        ui.label(
                                            RichText::new("NUVI Tech Key")
                                                .size(12.0)
                                                .color(c(brand::TEXT_MUTED)),
                                        );
                                        if ui
                                            .add(
                                                egui::TextEdit::singleline(
                                                    &mut self.config.tech_key,
                                                )
                                                .password(!self.reveal_tech_key)
                                                .hint_text("Paste 48-char NUVI_TECH_KEY")
                                                .desired_width(300.0),
                                            )
                                            .changed()
                                        {
                                            let _ = save_config(&self.config);
                                        }
                                        let eye = if self.reveal_tech_key {
                                            "Hide"
                                        } else {
                                            "Show"
                                        };
                                        if secondary_pill_button(ui, eye).clicked() {
                                            self.reveal_tech_key = !self.reveal_tech_key;
                                        }
                                        ui.add_space(8.0);
                                        ui.label(
                                            RichText::new("Tech Name")
                                                .size(12.0)
                                                .color(c(brand::TEXT_MUTED)),
                                        );
                                        if ui
                                            .add(
                                                egui::TextEdit::singleline(
                                                    &mut self.config.tech_name,
                                                )
                                                .desired_width(150.0),
                                            )
                                            .changed()
                                        {
                                            let _ = save_config(&self.config);
                                        }
                                    });
                                }
                            });
                            ui.add_space(8.0);
                        }

                        ui.horizontal(|ui| {
                            let on_lbl = format!("Online ({})", self.online_devices.len());
                            let fv_lbl = format!("Favorites ({})", self.config.address_book.len());
                            let rc_lbl =
                                format!("Recent Sessions ({})", self.config.recent_sessions.len());

                            if nuvi_flat_tab(
                                ui,
                                self.desk_filter == DeskFilter::Overview,
                                "Overview",
                            )
                            .clicked()
                            {
                                self.desk_filter = DeskFilter::Overview;
                            }
                            if nuvi_flat_tab(
                                ui,
                                self.desk_filter == DeskFilter::Online,
                                &on_lbl,
                            )
                            .clicked()
                            {
                                self.desk_filter = DeskFilter::Online;
                            }
                            if nuvi_flat_tab(
                                ui,
                                self.desk_filter == DeskFilter::Favorites,
                                &fv_lbl,
                            )
                            .clicked()
                            {
                                self.desk_filter = DeskFilter::Favorites;
                            }
                            if nuvi_flat_tab(
                                ui,
                                self.desk_filter == DeskFilter::Recent,
                                &rc_lbl,
                            )
                            .clicked()
                            {
                                self.desk_filter = DeskFilter::Recent;
                            }

                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if segmented_tab_button(
                                        ui,
                                        self.view_mode == ViewMode::List,
                                        "List",
                                    )
                                    .clicked()
                                    {
                                        self.view_mode = ViewMode::List;
                                    }
                                    if segmented_tab_button(
                                        ui,
                                        self.view_mode == ViewMode::Grid,
                                        "Grid",
                                    )
                                    .clicked()
                                    {
                                        self.view_mode = ViewMode::Grid;
                                    }
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.search_query)
                                            .hint_text("Filter...")
                                            .desired_width(150.0),
                                    );
                                },
                            );
                        });
                        ui.separator();

                        egui::ScrollArea::vertical().show(ui, |ui| {
                            if self.desk_filter == DeskFilter::Overview {
                                ui.add_space(6.0);
                                let avail = ui.available_width();
                                let tile_w = ((avail - 4.0 * 10.0) / 5.0).clamp(135.0, 200.0);
                                let tile_size = Vec2::new(tile_w, 104.0);

                                ui.horizontal_wrapped(|ui| {
                                    ui.spacing_mut().item_spacing = Vec2::new(10.0, 10.0);

                                    if nuvi_feature_tile(
                                        ui,
                                        tile_size,
                                        c(brand::SURFACE_CARD),
                                        "NUVI Remote",
                                        &format!("Relay:\n{endpoint}"),
                                        "Refresh ->",
                                    )
                                    .clicked()
                                    {
                                        spawn_fetch_devices(
                                            self.config.server_url.clone(),
                                            self.config.tech_key.clone(),
                                            self.ev_tx.clone(),
                                            ctx.clone(),
                                        );
                                    }

                                    let auth_sub = if self.config.tech_key.trim().is_empty() {
                                        "No key set\nClick to paste"
                                    } else {
                                        "Tech key ready\nClick to edit"
                                    };
                                    if nuvi_feature_tile(
                                        ui,
                                        tile_size,
                                        c(brand::ACCENT_TINT),
                                        "Tech Auth",
                                        auth_sub,
                                        "Configure ->",
                                    )
                                    .clicked()
                                    {
                                        self.show_settings = !self.show_settings;
                                    }

                                    if nuvi_feature_tile(
                                        ui,
                                        tile_size,
                                        Color32::from_rgb(75, 34, 27),
                                        "Auto-Detect",
                                        "Client controls\nAttended / Key",
                                        "Refresh ->",
                                    )
                                    .clicked()
                                    {
                                        spawn_fetch_devices(
                                            self.config.server_url.clone(),
                                            self.config.tech_key.clone(),
                                            self.ev_tx.clone(),
                                            ctx.clone(),
                                        );
                                    }

                                    let on_sub = format!(
                                        "{} client(s)\nonline now",
                                        self.online_devices.len()
                                    );
                                    if nuvi_feature_tile(
                                        ui,
                                        tile_size,
                                        Color32::from_rgb(21, 34, 56),
                                        "Online Desks",
                                        &on_sub,
                                        "View Online ->",
                                    )
                                    .clicked()
                                    {
                                        self.desk_filter = DeskFilter::Online;
                                    }

                                    if nuvi_feature_tile(
                                        ui,
                                        tile_size,
                                        c(brand::SURFACE_ELEVATED),
                                        "Save Desk",
                                        "Bookmark ID\nto Favorites",
                                        "+ Save ->",
                                    )
                                    .clicked()
                                    {
                                        self.show_save_bar = !self.show_save_bar;
                                    }
                                });

                                if self.show_save_bar {
                                    ui.add_space(8.0);
                                    nuvi_card(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(
                                                RichText::new("Bookmark:")
                                                    .strong()
                                                    .color(c(brand::TEXT_PRIMARY)),
                                            );
                                            ui.add(
                                                egui::TextEdit::singleline(&mut self.target_id)
                                                    .hint_text("NUVI-XXX-XXX-XXX")
                                                    .desired_width(150.0),
                                            );
                                            ui.add(
                                                egui::TextEdit::singleline(&mut self.new_label)
                                                    .hint_text("Client / PC Name")
                                                    .desired_width(160.0),
                                            );
                                            ui.add(
                                                egui::TextEdit::singleline(&mut self.new_notes)
                                                    .hint_text("Notes")
                                                    .desired_width(160.0),
                                            );
                                            if primary_pill_button(ui, "Save").clicked()
                                                && !self.target_id.trim().is_empty()
                                            {
                                                let id =
                                                    self.target_id.trim().to_ascii_uppercase();
                                                self.config.address_book.push(AddressBookEntry {
                                                    label: if self.new_label.trim().is_empty() {
                                                        id.clone()
                                                    } else {
                                                        self.new_label.trim().to_string()
                                                    },
                                                    device_id: id,
                                                    notes: self.new_notes.trim().to_string(),
                                                });
                                                self.new_label.clear();
                                                self.new_notes.clear();
                                                self.show_save_bar = false;
                                                let _ = save_config(&self.config);
                                            }
                                        });
                                    });
                                }

                                ui.add_space(10.0);
                                ui.separator();
                            }

                            ui.add_space(6.0);
                            let section_title = match self.desk_filter {
                                DeskFilter::Overview => "Recent Sessions",
                                DeskFilter::Online => "Online Desks",
                                DeskFilter::Favorites => "Favorites",
                                DeskFilter::Recent => "Recent Sessions",
                            };
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(section_title)
                                        .size(13.0)
                                        .strong()
                                        .color(c(brand::TEXT_PRIMARY)),
                                );
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if self.desk_filter != DeskFilter::Recent
                                            && ui
                                                .link(
                                                    RichText::new("Show all")
                                                        .size(11.5)
                                                        .color(c(brand::TEXT_MUTED)),
                                                )
                                                .clicked()
                                        {
                                            self.desk_filter = DeskFilter::Recent;
                                        }
                                    },
                                );
                            });
                            ui.add_space(6.0);

                            let tiles = self.collect_desk_tiles();
                            if tiles.is_empty() {
                                nuvi_card(ui, |ui| {
                                    ui.vertical_centered(|ui| {
                                        ui.add_space(18.0);
                                        ui.label(
                                            RichText::new("No desks yet — click Refresh or enter an ID above.")
                                                .size(12.5)
                                                .color(c(brand::TEXT_MUTED)),
                                        );
                                        ui.add_space(18.0);
                                    });
                                });
                            } else if self.view_mode == ViewMode::List {
                                let mut connect_to: Option<String> = None;
                                let mut toggle_fav: Option<(String, String, Option<usize>)> = None;
                                for item in &tiles {
                                    nuvi_card(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            status_pill(
                                                ui,
                                                if item.online { "ONLINE" } else { "OFFLINE" },
                                                item.online,
                                            );
                                            ui.label(
                                                RichText::new(&item.title)
                                                    .strong()
                                                    .color(c(brand::TEXT_PRIMARY)),
                                            );
                                            ui.label(
                                                RichText::new(&item.device_id)
                                                    .monospace()
                                                    .color(c(brand::ACCENT_HIGHLIGHT)),
                                            );
                                            ui.label(
                                                RichText::new(&item.subtitle)
                                                    .size(11.5)
                                                    .color(c(brand::TEXT_MUTED)),
                                            );
                                            ui.with_layout(
                                                egui::Layout::right_to_left(egui::Align::Center),
                                                |ui| {
                                                    if primary_pill_button(ui, "Connect").clicked()
                                                    {
                                                        connect_to = Some(item.device_id.clone());
                                                    }
                                                    let star =
                                                        if item.is_saved { "★" } else { "☆" };
                                                    if secondary_pill_button(ui, star).clicked() {
                                                        toggle_fav = Some((
                                                            item.device_id.clone(),
                                                            item.title.clone(),
                                                            item.saved_idx,
                                                        ));
                                                    }
                                                },
                                            );
                                        });
                                    });
                                    ui.add_space(6.0);
                                }
                                if let Some((id, title, saved_idx)) = toggle_fav {
                                    if let Some(idx) = saved_idx {
                                        self.config.address_book.remove(idx);
                                    } else {
                                        self.config.address_book.push(AddressBookEntry {
                                            label: title,
                                            device_id: id,
                                            notes: String::new(),
                                        });
                                    }
                                    let _ = save_config(&self.config);
                                }
                                if let Some(id) = connect_to {
                                    self.start_connect(ctx, Some(id));
                                }
                            } else {
                                for item in &tiles {
                                    let _ = self.get_or_load_thumb(ctx, &item.device_id);
                                }

                                let avail_w = ui.available_width();
                                let cols = ((avail_w / 195.0).floor() as usize).clamp(2, 6);
                                let tile_w = ((avail_w - (cols as f32 - 1.0) * 10.0) / cols as f32)
                                    .max(150.0);
                                let tile_h = (tile_w * 0.62).clamp(92.0, 125.0);

                                let mut connect_to: Option<String> = None;
                                let mut select_id: Option<String> = None;
                                let mut toggle_fav: Option<(String, String, Option<usize>)> = None;

                                for chunk in tiles.chunks(cols) {
                                    ui.horizontal(|ui| {
                                        ui.spacing_mut().item_spacing.x = 10.0;
                                        for item in chunk {
                                            let tex = self
                                                .thumb_cache
                                                .get(&item.device_id)
                                                .and_then(|o| o.as_ref());
                                            let selected = self
                                                .target_id
                                                .trim()
                                                .eq_ignore_ascii_case(&item.device_id);
                                            let (resp, star_clicked) = nuvi_session_tile(
                                                ui,
                                                Vec2::new(tile_w, tile_h),
                                                tex,
                                                &item.device_id,
                                                &item.title,
                                                item.online,
                                                item.is_service,
                                                item.is_unattended,
                                                item.is_saved,
                                                selected,
                                            );
                                            if star_clicked {
                                                toggle_fav = Some((
                                                    item.device_id.clone(),
                                                    item.title.clone(),
                                                    item.saved_idx,
                                                ));
                                            } else if resp.double_clicked() {
                                                connect_to = Some(item.device_id.clone());
                                            } else if resp.clicked() {
                                                select_id = Some(item.device_id.clone());
                                            }
                                        }
                                    });
                                    ui.add_space(10.0);
                                }

                                if let Some(id) = select_id {
                                    self.target_id = id;
                                }
                                if let Some((id, title, saved_idx)) = toggle_fav {
                                    if let Some(idx) = saved_idx {
                                        self.config.address_book.remove(idx);
                                    } else {
                                        self.config.address_book.push(AddressBookEntry {
                                            label: title,
                                            device_id: id,
                                            notes: String::new(),
                                        });
                                    }
                                    let _ = save_config(&self.config);
                                }
                                if let Some(id) = connect_to {
                                    self.start_connect(ctx, Some(id));
                                }
                            }
                        });
                    });
            });
    }

    fn render_viewer(&mut self, ctx: &egui::Context, tid: Uuid) {
        let Some(v) = self.sessions.iter_mut().find(|s| s.tab_id == tid) else {
            return;
        };

        // Bidirectional clipboard sync (~550ms) when active & allowed
        if v.established && v.permissions.allow_clipboard && v.last_clip_check.elapsed().as_millis() >= 550 {
            v.last_clip_check = Instant::now();
            if let Ok(mut cb) = arboard::Clipboard::new() {
                if let Ok(txt) = cb.get_text() {
                    if !txt.is_empty() && txt != v.last_clip && txt.len() <= 512 * 1024 {
                        v.last_clip = txt.clone();
                        let _ = v.cmd_tx.send(HostUiCmd::SendClipboard(txt));
                    }
                }
            }
        }

        // Drag-and-drop file transfer onto the viewer
        let dropped: Vec<std::path::PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .filter_map(|f| f.path.clone())
                .collect()
        });
        for p in dropped {
            let _ = v.cmd_tx.send(HostUiCmd::SendFile(p));
        }

        egui::TopBottomPanel::top("viewer_toolbar")
            .frame(
                egui::Frame::new()
                    .fill(c(brand::SURFACE_CARD))
                    .stroke(Stroke::new(1.0_f32, c(brand::BORDER_SUBTLE)))
                    .inner_margin(Margin::symmetric(12, 7)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let mode_txt = match v.mode {
                        ConnectMode::Attended => "Attended",
                        ConnectMode::Unattended => "Unattended",
                    };
                    let run_txt = match v.client_mode {
                        ClientRunMode::Service => "SERVICE",
                        ClientRunMode::Portable => "PORTABLE",
                    };
                    ui.label(
                        RichText::new(format!("{mode_txt} · {run_txt}"))
                            .size(12.0)
                            .strong()
                            .color(c(brand::ACCENT_HIGHLIGHT)),
                    );

                    for m in &v.monitors {
                        if segmented_tab_button(ui, v.active_monitor == m.index, &m.name).clicked()
                        {
                            v.active_monitor = m.index;
                            let _ = v.cmd_tx.send(HostUiCmd::SendPeer(
                                PeerMessage::SelectMonitor {
                                    monitor_index: m.index,
                                },
                            ));
                        }
                    }

                    for q in [QualityPreset::Auto, QualityPreset::Sharp, QualityPreset::Smooth] {
                        if segmented_tab_button(ui, v.quality == q, q.label()).clicked() {
                            v.quality = q;
                            let _ = v
                                .cmd_tx
                                .send(HostUiCmd::SendPeer(PeerMessage::SetQuality { preset: q }));
                        }
                    }

                    if ui.checkbox(&mut v.view_only, "View-Only").changed() && v.view_only {
                        let _ = v
                            .cmd_tx
                            .send(HostUiCmd::SendPeer(PeerMessage::ReleaseAllKeys));
                        v.mod_tracker.reset();
                    }

                    if segmented_tab_button(ui, v.annotate_mode, "Annotate").clicked() {
                        v.annotate_mode = !v.annotate_mode;
                        v.last_stroke_pt = None;
                    }
                    if v.annotate_mode && secondary_pill_button(ui, "Clear").clicked() {
                        v.local_strokes.clear();
                        let _ = v.cmd_tx.send(HostUiCmd::SendPeer(PeerMessage::Annotation {
                            monitor_index: v.active_monitor,
                            kind: AnnotationKind::Clear,
                        }));
                    }

                    if secondary_pill_button(ui, "Send File").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            let _ = v.cmd_tx.send(HostUiCmd::SendFile(path));
                        }
                    }

                    if secondary_pill_button(ui, "Screenshot").clicked() {
                        match save_screenshot_png(&v.device_id, &v.framebuffer) {
                            Ok(p) => {
                                v.notice = Some(format!("Screenshot saved: {}", p.display()));
                            }
                            Err(e) => {
                                v.notice = Some(format!("Screenshot failed: {e}"));
                            }
                        }
                    }

                    if v.established {
                        let chat_lbl = if v.unread_chat > 0 {
                            format!("Chat ({})", v.unread_chat)
                        } else {
                            "Chat".to_string()
                        };
                        if segmented_tab_button(ui, v.chat_open, &chat_lbl).clicked() {
                            v.chat_open = !v.chat_open;
                            if v.chat_open {
                                v.unread_chat = 0;
                            }
                        }
                    }

                    if segmented_tab_button(ui, v.show_actions, "Actions").clicked() {
                        v.show_actions = !v.show_actions;
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if danger_pill_button(ui, "End Session").clicked() {
                            let _ = v.cmd_tx.send(HostUiCmd::Disconnect);
                        }
                        ui.label(
                            RichText::new(format!("{:.0} FPS | {} ms", v.fps_display, v.rtt_ms))
                                .size(12.0)
                                .monospace()
                                .color(c(brand::TEXT_MUTED)),
                        );
                    });
                });

                if v.show_actions {
                    ui.horizontal(|ui| {
                        if secondary_pill_button(ui, "Ctrl+Alt+Del").clicked() {
                            let _ = v
                                .cmd_tx
                                .send(HostUiCmd::SendPeer(PeerMessage::SendCtrlAltDel));
                        }
                        if secondary_pill_button(ui, "Task Mgr").clicked() {
                            let _ = v.cmd_tx.send(HostUiCmd::SendPeer(PeerMessage::QuickAction {
                                action: RemoteQuickAction::OpenTaskManager,
                            }));
                        }
                        if secondary_pill_button(ui, "Lock PC").clicked() {
                            let _ = v.cmd_tx.send(HostUiCmd::SendPeer(PeerMessage::QuickAction {
                                action: RemoteQuickAction::LockWorkstation,
                            }));
                        }
                        if secondary_pill_button(ui, "Elevate").clicked() {
                            let _ = v.cmd_tx.send(HostUiCmd::SendPeer(PeerMessage::QuickAction {
                                action: RemoteQuickAction::RequestElevation,
                            }));
                        }
                        if !v.confirm_reboot {
                            if secondary_pill_button(ui, "Reboot").clicked() {
                                v.confirm_reboot = true;
                            }
                        } else if danger_pill_button(ui, "Confirm Reboot?").clicked() {
                            v.confirm_reboot = false;
                            let _ = v
                                .cmd_tx
                                .send(HostUiCmd::SendPeer(PeerMessage::RebootClient));
                        }
                    });
                }

                if let Some((fname, sent, total, done)) = &v.file_progress {
                    let lbl = if *done {
                        format!("Sent {fname} ({total} B)")
                    } else {
                        format!("Sending {fname}: {sent}/{total} B")
                    };
                    ui.label(RichText::new(lbl).size(11.5).color(c(brand::STATUS_ONLINE)));
                }

                if let Some(note) = v.notice.clone() {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(note).size(11.5).color(c(brand::ACCENT_HIGHLIGHT)));
                        if secondary_pill_button(ui, "OK").clicked() {
                            v.notice = None;
                        }
                    });
                }
            });

        // In-Session Chat Drawer (only when session is connected; fixed 300px side panel)
        if v.established && v.chat_open {
            egui::SidePanel::right("session_chat_panel")
                .exact_width(300.0)
                .resizable(false)
                .frame(
                    egui::Frame::new()
                        .fill(c(brand::SURFACE_CARD))
                        .stroke(Stroke::new(1.0_f32, c(brand::BORDER_SUBTLE)))
                        .inner_margin(Margin::same(10)),
                )
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("In-Session Chat")
                                .size(14.0)
                                .strong()
                                .color(c(brand::TEXT_PRIMARY)),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if secondary_pill_button(ui, "×").clicked() {
                                v.chat_open = false;
                            }
                        });
                    });
                    ui.separator();
                    let avail_h = (ui.available_height() - 44.0).max(100.0);
                    egui::ScrollArea::vertical()
                        .max_height(avail_h)
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            for m in &v.chat_messages {
                                let is_you = m.sender == "You";
                                let layout = if is_you {
                                    egui::Layout::right_to_left(egui::Align::TOP)
                                } else {
                                    egui::Layout::left_to_right(egui::Align::TOP)
                                };
                                ui.with_layout(layout, |ui| {
                                    let (fill, stroke) = if is_you {
                                        (c(brand::ACCENT_TINT), c(brand::ACCENT_GLOW_BORDER))
                                    } else {
                                        (c(brand::SURFACE_ELEVATED), c(brand::BORDER_SUBTLE))
                                    };
                                    egui::Frame::new()
                                        .fill(fill)
                                        .stroke(Stroke::new(1.0_f32, stroke))
                                        .corner_radius(egui::CornerRadius::same(10))
                                        .inner_margin(Margin::symmetric(10, 6))
                                        .show(ui, |ui| {
                                            ui.set_max_width(220.0);
                                            ui.vertical(|ui| {
                                                ui.label(
                                                    RichText::new(format!(
                                                        "{} · {}",
                                                        m.sender, m.sent_at
                                                    ))
                                                    .size(10.0)
                                                    .color(c(brand::ACCENT_HIGHLIGHT)),
                                                );
                                                ui.label(
                                                    RichText::new(&m.text)
                                                        .size(12.0)
                                                        .color(c(brand::TEXT_PRIMARY)),
                                                );
                                            });
                                        });
                                });
                                ui.add_space(4.0);
                            }
                        });
                    ui.horizontal(|ui| {
                        let resp = ui.add(
                            egui::TextEdit::singleline(&mut v.chat_draft)
                                .hint_text("Type message...")
                                .desired_width((ui.available_width() - 68.0).max(120.0)),
                        );
                        let clicked = primary_pill_button(ui, "Send").clicked();
                        let enter =
                            resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        if (clicked || enter) && !v.chat_draft.trim().is_empty() {
                            let text = v.chat_draft.trim().to_string();
                            v.chat_draft.clear();
                            let sent_at = Local::now().format("%H:%M").to_string();
                            let tech_name = self.config.tech_name.clone();
                            let entry = ChatHistoryEntry {
                                sender: "You".to_string(),
                                text: text.clone(),
                                sent_at: sent_at.clone(),
                            };
                            append_chat_history(&v.device_id, entry.clone());
                            v.chat_messages.push(entry);
                            let _ = v.cmd_tx.send(HostUiCmd::SendPeer(PeerMessage::ChatMessage {
                                sender: tech_name,
                                text,
                                sent_at,
                            }));
                        }
                    });
                });
        }

        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(c(brand::BG_CANVAS)))
            .show(ctx, |ui| {
                let avail = ui.available_size();
                let (rect, response) = ui.allocate_exact_size(avail, Sense::click_and_drag());

                if let Some(tex) = &v.texture {
                    let tex_size = tex.size_vec2();
                    let scale = (rect.width() / tex_size.x).min(rect.height() / tex_size.y);
                    let draw_size = tex_size * scale;
                    let top_left = rect.center() - draw_size * 0.5;
                    let draw_rect = Rect::from_min_size(top_left, draw_size);

                    ui.painter().image(
                        tex.id(),
                        draw_rect,
                        Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0)),
                        Color32::WHITE,
                    );

                    // Draw local coral annotation strokes on Host canvas
                    for &(x1, y1, x2, y2) in &v.local_strokes {
                        let p1 = Pos2::new(
                            draw_rect.left() + x1 * draw_rect.width(),
                            draw_rect.top() + y1 * draw_rect.height(),
                        );
                        let p2 = Pos2::new(
                            draw_rect.left() + x2 * draw_rect.width(),
                            draw_rect.top() + y2 * draw_rect.height(),
                        );
                        ui.painter()
                            .line_segment([p1, p2], Stroke::new(3.0_f32, c(brand::ACCENT_PRIMARY)));
                    }

                    if v.annotate_mode {
                        if let Some(pos) = response.hover_pos() {
                            if draw_rect.contains(pos) {
                                ctx.set_cursor_icon(CursorIcon::Crosshair);
                                let nx =
                                    ((pos.x - draw_rect.left()) / draw_rect.width()).clamp(0.0, 1.0);
                                let ny =
                                    ((pos.y - draw_rect.top()) / draw_rect.height()).clamp(0.0, 1.0);
                                if response.dragged_by(PointerButton::Primary) {
                                    if let Some((px, py)) = v.last_stroke_pt {
                                        v.local_strokes.push((px, py, nx, ny));
                                        let _ = v.cmd_tx.send(HostUiCmd::SendPeer(
                                            PeerMessage::Annotation {
                                                monitor_index: v.active_monitor,
                                                kind: AnnotationKind::Stroke {
                                                    x1: px,
                                                    y1: py,
                                                    x2: nx,
                                                    y2: ny,
                                                },
                                            },
                                        ));
                                    }
                                    v.last_stroke_pt = Some((nx, ny));
                                } else {
                                    v.last_stroke_pt = None;
                                    if v.last_laser_sent.elapsed().as_millis() >= 30 {
                                        v.last_laser_sent = Instant::now();
                                        let _ = v.cmd_tx.send(HostUiCmd::SendPeer(
                                            PeerMessage::Annotation {
                                                monitor_index: v.active_monitor,
                                                kind: AnnotationKind::Laser { nx, ny },
                                            },
                                        ));
                                    }
                                }
                            }
                        }
                    } else if !v.view_only && v.permissions.allow_control {
                        if let Some(pos) = response.hover_pos() {
                            if draw_rect.contains(pos) {
                                ctx.set_cursor_icon(map_cursor_icon(v.remote_cursor));
                            }
                        }

                        let focused = ctx.input(|i| i.focused);
                        if v.had_focus && !focused {
                            let _ = v
                                .cmd_tx
                                .send(HostUiCmd::SendPeer(PeerMessage::ReleaseAllKeys));
                            v.mod_tracker.reset();
                        }
                        v.had_focus = focused;

                        if let Some(pos) = response.hover_pos() {
                            if draw_rect.contains(pos)
                                && v.last_move_sent.elapsed().as_millis() >= 16
                            {
                                v.last_move_sent = Instant::now();
                                let nx =
                                    ((pos.x - draw_rect.left()) / draw_rect.width()).clamp(0.0, 1.0);
                                let ny =
                                    ((pos.y - draw_rect.top()) / draw_rect.height()).clamp(0.0, 1.0);
                                let _ = v.cmd_tx.send(HostUiCmd::SendPeer(
                                    PeerMessage::MouseInput {
                                        monitor_index: v.active_monitor,
                                        kind: MouseEventKind::Move { nx, ny },
                                    },
                                ));
                            }
                        }

                        ctx.input(|i| {
                            if i.focused && !v.chat_open {
                                for mkey in v.mod_tracker.sync(i.modifiers) {
                                    let _ = v.cmd_tx.send(HostUiCmd::SendPeer(PeerMessage::KeyInput {
                                        scancode: mkey.scancode,
                                        extended: mkey.extended,
                                        pressed: mkey.pressed,
                                        unicode: None,
                                    }));
                                }
                            }

                            for ev in &i.events {
                                match ev {
                                    egui::Event::PointerButton {
                                        pos,
                                        button,
                                        pressed,
                                        ..
                                    } => {
                                        if draw_rect.contains(*pos) {
                                            let nx = ((*pos).x - draw_rect.left()) / draw_rect.width();
                                            let ny = ((*pos).y - draw_rect.top()) / draw_rect.height();
                                            let _ = v.cmd_tx.send(HostUiCmd::SendPeer(
                                                PeerMessage::MouseInput {
                                                    monitor_index: v.active_monitor,
                                                    kind: MouseEventKind::Move {
                                                        nx: nx.clamp(0.0, 1.0),
                                                        ny: ny.clamp(0.0, 1.0),
                                                    },
                                                },
                                            ));
                                            let mb = match button {
                                                PointerButton::Primary => MouseButton::Left,
                                                PointerButton::Secondary => MouseButton::Right,
                                                PointerButton::Middle => MouseButton::Middle,
                                                PointerButton::Extra1 => MouseButton::X1,
                                                PointerButton::Extra2 => MouseButton::X2,
                                            };
                                            let _ = v.cmd_tx.send(HostUiCmd::SendPeer(
                                                PeerMessage::MouseInput {
                                                    monitor_index: v.active_monitor,
                                                    kind: MouseEventKind::Button {
                                                        button: mb,
                                                        pressed: *pressed,
                                                    },
                                                },
                                            ));
                                        }
                                    }
                                    egui::Event::MouseWheel { delta, .. } => {
                                        let dx = (delta.x * 40.0) as i16;
                                        let dy = (delta.y * 40.0) as i16;
                                        if dx != 0 || dy != 0 {
                                            let _ = v.cmd_tx.send(HostUiCmd::SendPeer(
                                                PeerMessage::MouseInput {
                                                    monitor_index: v.active_monitor,
                                                    kind: MouseEventKind::Wheel { dx, dy },
                                                },
                                            ));
                                        }
                                    }
                                    egui::Event::Key { key, pressed, .. } if !v.chat_open => {
                                        if let Some((scancode, extended)) = egui_key_to_scancode(*key)
                                        {
                                            let _ = v.cmd_tx.send(HostUiCmd::SendPeer(
                                                PeerMessage::KeyInput {
                                                    scancode,
                                                    extended,
                                                    pressed: *pressed,
                                                    unicode: None,
                                                },
                                            ));
                                        }
                                    }
                                    egui::Event::Text(txt) if !v.chat_open => {
                                        for ch in txt.chars() {
                                            if !ch.is_control() && i.modifiers == Modifiers::NONE {
                                                let _ = v.cmd_tx.send(HostUiCmd::SendPeer(
                                                    PeerMessage::KeyInput {
                                                        scancode: 0,
                                                        extended: false,
                                                        pressed: true,
                                                        unicode: Some(ch),
                                                    },
                                                ));
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        });
                    }
                } else if !v.established {
                    if let Some(msg) = v.auth_challenge.clone() {
                        let card_w = 400.0_f32.min((rect.width() - 32.0).max(240.0));
                        let card_rect = Rect::from_center_size(rect.center(), Vec2::new(card_w, 220.0));
                        ui.scope_builder(egui::UiBuilder::new().max_rect(card_rect), |ui| {
                            nuvi_card(ui, |ui| {
                                ui.horizontal(|ui| {
                                    draw_nuvi_logo_mark(ui, 36.0);
                                    ui.add_space(6.0);
                                    ui.vertical(|ui| {
                                        ui.label(
                                            RichText::new("Unattended Key Required")
                                                .size(15.5)
                                                .strong()
                                                .color(c(brand::TEXT_PRIMARY)),
                                        );
                                        ui.label(
                                            RichText::new(&v.device_id)
                                                .monospace()
                                                .size(12.0)
                                                .color(c(brand::ACCENT_PRIMARY)),
                                        );
                                    });
                                });
                                ui.add_space(8.0);
                                ui.label(
                                    RichText::new(msg)
                                        .size(12.0)
                                        .color(c(brand::ACCENT_HIGHLIGHT)),
                                );
                                ui.add_space(8.0);
                                let resp = ui.add(
                                    egui::TextEdit::singleline(&mut v.auth_key_draft)
                                        .password(true)
                                        .hint_text("NUVI-XXXX-XXXX-XXXX")
                                        .desired_width(ui.available_width()),
                                );
                                let enter = resp.lost_focus()
                                    && ui.input(|i| i.key_pressed(egui::Key::Enter));
                                ui.add_space(10.0);
                                ui.horizontal(|ui| {
                                    let submit = primary_pill_button(ui, "Unlock & Connect").clicked();
                                    if (submit || enter) && !v.auth_key_draft.trim().is_empty() {
                                        let key = v.auth_key_draft.trim().to_string();
                                        v.auth_challenge = None;
                                        let _ = v
                                            .cmd_tx
                                            .send(HostUiCmd::SubmitUnattendedKey(key));
                                    }
                                    if danger_pill_button(ui, "Cancel").clicked() {
                                        let _ = v.cmd_tx.send(HostUiCmd::Disconnect);
                                    }
                                });
                            });
                        });
                    } else {
                        ui.painter().text(
                            rect.center(),
                            egui::Align2::CENTER_CENTER,
                            "Waiting for client...",
                            egui::FontId::proportional(16.0),
                            c(brand::TEXT_MUTED),
                        );
                    }
                } else {
                    ui.painter().text(
                        rect.center(),
                        egui::Align2::CENTER_CENTER,
                        "Waiting for first frame...",
                        egui::FontId::proportional(16.0),
                        c(brand::TEXT_MUTED),
                    );
                }
            });
    }
}

fn map_cursor_icon(shape: RemoteCursorShape) -> CursorIcon {
    match shape {
        RemoteCursorShape::Default => CursorIcon::Default,
        RemoteCursorShape::Text => CursorIcon::Text,
        RemoteCursorShape::Hand => CursorIcon::PointingHand,
        RemoteCursorShape::Wait => CursorIcon::Wait,
        RemoteCursorShape::Crosshair => CursorIcon::Crosshair,
        RemoteCursorShape::ResizeNS => CursorIcon::ResizeVertical,
        RemoteCursorShape::ResizeEW => CursorIcon::ResizeHorizontal,
        RemoteCursorShape::ResizeNWSE => CursorIcon::ResizeNwSe,
        RemoteCursorShape::ResizeNESW => CursorIcon::ResizeNeSw,
        RemoteCursorShape::Move => CursorIcon::Move,
        RemoteCursorShape::NotAllowed => CursorIcon::NotAllowed,
    }
}
