use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

use chrono::Utc;
use egui::{Color32, Margin, RichText, Vec2};
use nuvi_proto::{
    brand,
    crypto::IdentityKeypair,
    protocol::{normalize_server_url, ChatHistoryEntry, SessionPermissions},
    rotation::{compute_next_rotation_utc, human_countdown, RotationSchedule},
};
use tokio::sync::mpsc;

use crate::{
    ipc::{GuiToService, ServiceToGui},
    net::{ActiveSessionInfo, NetToUi, PendingConsent, UiToNet},
    service::{
        query_service_status, trigger_elevated_install, trigger_elevated_uninstall,
        ServiceStatusSummary,
    },
    storage::{
        load_chat_history, load_dpapi_key, rotate_unattended_key, save_config, ClientConfig,
        StorageScope,
    },
    theme::{
        badge_pill, c, danger_pill_button, draw_progress_bar, nuvi_card, nuvi_feature_tile,
        nuvi_flat_tab, nuvi_header, nuvi_ribbon_banner, primary_pill_button,
        secondary_pill_button, segmented_tab_button, status_pill,
    },
    tray::{TrayEvent, TrayHandle},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientTab {
    Overview,
    Chat,
    Unattended,
    Service,
    Server,
}

#[cfg(windows)]
pub fn spawn_gui_pipe_bridge(
    config: Arc<Mutex<ClientConfig>>,
    mut cmd_rx: mpsc::UnboundedReceiver<GuiToService>,
    net_tx: mpsc::UnboundedSender<NetToUi>,
    ctx: egui::Context,
) {
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        net::windows::named_pipe::ClientOptions,
    };

    tokio::spawn(async move {
        loop {
            let pipe = match ClientOptions::new().open(crate::ipc::GUI_PIPE_NAME) {
                Ok(p) => p,
                Err(_) => {
                    let _ = net_tx.send(NetToUi::ConnectionState {
                        online: false,
                        status: "Waiting for Service...".to_string(),
                    });
                    ctx.request_repaint();
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
            };

            let (r_half, mut w_half) = tokio::io::split(pipe);
            if let Ok(mut raw) = serde_json::to_string(&GuiToService::GetStatus) {
                raw.push('\n');
                if w_half.write_all(raw.as_bytes()).await.is_err() {
                    continue;
                }
            }
            let mut reader = BufReader::new(r_half);
            let mut line = String::new();

            loop {
                line.clear();
                tokio::select! {
                    n = reader.read_line(&mut line) => {
                        match n {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {
                                if let Ok(ev) = serde_json::from_str::<ServiceToGui>(line.trim()) {
                                    match ev {
                                        ServiceToGui::Snapshot(snap) => {
                                            {
                                                let mut g = config.lock().unwrap();
                                                g.server_url = snap.server_url;
                                                g.unattended = snap.unattended;
                                            }
                                            let _ = net_tx.send(NetToUi::DeviceIdSynced(snap.device_id));
                                            if let Some(k) = snap.unattended_key_plain {
                                                let _ = net_tx.send(NetToUi::KeyAutoRotated { new_key: k });
                                            }
                                            let _ = net_tx.send(NetToUi::ConnectionState {
                                                online: snap.online,
                                                status: snap.status,
                                            });
                                            if let Some(pc) = snap.pending_consent {
                                                let _ = net_tx.send(NetToUi::ConsentRequested(pc.into()));
                                            }
                                            if let Some(act) = snap.active_session {
                                                let _ = net_tx.send(NetToUi::SessionStarted(act));
                                            }
                                            if !snap.recent_chat.is_empty() {
                                                let _ = net_tx.send(NetToUi::ChatHistoryLoaded(
                                                    snap.recent_chat,
                                                ));
                                            }
                                        }
                                        ServiceToGui::ConnectionState { online, status } => {
                                            let _ = net_tx.send(NetToUi::ConnectionState { online, status });
                                        }
                                        ServiceToGui::ConsentRequested(pc) => {
                                            let _ = net_tx.send(NetToUi::ConsentRequested(pc.into()));
                                        }
                                        ServiceToGui::ConsentCleared => {
                                            let _ = net_tx.send(NetToUi::ConsentCleared);
                                        }
                                        ServiceToGui::SessionStarted(act) => {
                                            let _ = net_tx.send(NetToUi::SessionStarted(act));
                                        }
                                        ServiceToGui::SessionEnded { reason } => {
                                            let _ = net_tx.send(NetToUi::SessionEnded { reason });
                                        }
                                        ServiceToGui::KeyAutoRotated { new_key } => {
                                            let _ = net_tx.send(NetToUi::KeyAutoRotated { new_key });
                                        }
                                        ServiceToGui::Notice(n) => {
                                            let _ = net_tx.send(NetToUi::Notice(n));
                                        }
                                        ServiceToGui::ChatMessage { sender, text, sent_at } => {
                                            let _ = net_tx.send(NetToUi::ChatMessage { sender, text, sent_at });
                                        }
                                        ServiceToGui::FileProgress { filename, received, total, done } => {
                                            let _ = net_tx.send(NetToUi::FileProgress { filename, received, total, done });
                                        }
                                    }
                                    ctx.request_repaint();
                                }
                            }
                        }
                    }
                    Some(cmd) = cmd_rx.recv() => {
                        if let Ok(mut raw) = serde_json::to_string(&cmd) {
                            raw.push('\n');
                            if w_half.write_all(raw.as_bytes()).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        }
    });
}

#[cfg(not(windows))]
pub fn spawn_gui_pipe_bridge(
    _config: Arc<Mutex<ClientConfig>>,
    _cmd_rx: mpsc::UnboundedReceiver<GuiToService>,
    _net_tx: mpsc::UnboundedSender<NetToUi>,
    _ctx: egui::Context,
) {
}

pub struct NuviClientApp {
    scope: StorageScope,
    svc_status: ServiceStatusSummary,
    config: Arc<Mutex<ClientConfig>>,
    device_id: String,
    ui_tx: mpsc::UnboundedSender<UiToNet>,
    gui_ipc_tx: mpsc::UnboundedSender<GuiToService>,
    net_rx: mpsc::UnboundedReceiver<NetToUi>,
    tray: TrayHandle,
    tray_rx: mpsc::UnboundedReceiver<TrayEvent>,
    allow_exit: bool,

    active_tab: ClientTab,
    online: bool,
    status_text: String,

    unattended_key_plain: Option<String>,
    reveal_key: bool,
    custom_days_str: String,
    server_url_draft: String,

    pending_consent: Option<PendingConsent>,
    consent_allow_control: bool,
    consent_allow_clipboard: bool,

    active_session: Option<ActiveSessionInfo>,
    session_started_at: Option<Instant>,
    chat_messages: Vec<ChatHistoryEntry>,
    unread_chat: usize,
    chat_draft: String,
    file_progress: Option<(String, u64, u64, bool)>,
    notice: Option<String>,
}

impl NuviClientApp {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: StorageScope,
        svc_status: ServiceStatusSummary,
        config: Arc<Mutex<ClientConfig>>,
        ui_tx: mpsc::UnboundedSender<UiToNet>,
        gui_ipc_tx: mpsc::UnboundedSender<GuiToService>,
        net_rx: mpsc::UnboundedReceiver<NetToUi>,
        tray: TrayHandle,
        tray_rx: mpsc::UnboundedReceiver<TrayEvent>,
    ) -> Self {
        let (device_id, custom_days, server_url) = {
            let cfg = config.lock().unwrap();
            let kp = IdentityKeypair::from_bytes(&cfg.identity_secret);
            let days = match cfg.unattended.schedule {
                RotationSchedule::EveryNDays { days } => days.to_string(),
                _ => "7".to_string(),
            };
            (kp.device_id(), days, cfg.server_url.clone())
        };
        let unattended_key_plain = load_dpapi_key(scope);

        Self {
            scope,
            svc_status,
            config,
            device_id,
            ui_tx,
            gui_ipc_tx,
            net_rx,
            tray,
            tray_rx,
            allow_exit: false,
            active_tab: ClientTab::Overview,
            online: false,
            status_text: "CONNECTING".to_string(),
            unattended_key_plain,
            reveal_key: false,
            custom_days_str: custom_days,
            server_url_draft: server_url,
            pending_consent: None,
            consent_allow_control: true,
            consent_allow_clipboard: true,
            active_session: None,
            session_started_at: None,
            chat_messages: load_chat_history(scope),
            unread_chat: 0,
            chat_draft: String::new(),
            file_progress: None,
            notice: None,
        }
    }

    fn drain_net_events(&mut self, ctx: &egui::Context) {
        while let Ok(tev) = self.tray_rx.try_recv() {
            match tev {
                TrayEvent::ShowWindow => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                TrayEvent::Quit => {
                    self.allow_exit = true;
                    self.tray.shutdown();
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }

        while let Ok(ev) = self.net_rx.try_recv() {
            match ev {
                NetToUi::ConnectionState { online, status } => {
                    self.online = online;
                    if online {
                        self.status_text = "ONLINE".to_string();
                    } else if status.eq_ignore_ascii_case("Connecting...") {
                        self.status_text = "CONNECTING".to_string();
                    } else {
                        self.status_text = "OFFLINE".to_string();
                        if !status.eq_ignore_ascii_case("Disconnected") {
                            self.notice = Some(status);
                        }
                    }
                }
                NetToUi::ConsentRequested(req) => {
                    self.consent_allow_control = true;
                    self.consent_allow_clipboard = true;
                    self.tray.notify(
                        "NUVI Remote — Connection Request",
                        &format!("{} wants to connect to your desk.", req.tech_name),
                    );
                    self.pending_consent = Some(req);
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                    ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(
                        egui::WindowLevel::AlwaysOnTop,
                    ));
                }
                NetToUi::ConsentCleared => {
                    self.pending_consent = None;
                    ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(
                        egui::WindowLevel::Normal,
                    ));
                }
                NetToUi::SessionStarted(info) => {
                    self.tray.notify(
                        "NUVI Remote — Session Active",
                        &format!("Connected with {}", info.tech_name),
                    );
                    self.active_session = Some(info);
                    self.session_started_at = Some(Instant::now());
                    self.file_progress = None;
                    self.pending_consent = None;
                    ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(
                        egui::WindowLevel::Normal,
                    ));
                }
                NetToUi::SessionEnded { reason } => {
                    self.active_session = None;
                    self.session_started_at = None;
                    if self.active_tab == ClientTab::Chat {
                        self.active_tab = ClientTab::Overview;
                    }
                    self.unread_chat = 0;
                    self.notice = Some(format!("Session ended: {reason}"));
                }
                NetToUi::KeyAutoRotated { new_key } => {
                    let changed = self.unattended_key_plain.as_deref() != Some(&new_key);
                    self.unattended_key_plain = Some(new_key);
                    if !self.svc_status.running {
                        self.device_id = {
                            let cfg = self.config.lock().unwrap();
                            IdentityKeypair::from_bytes(&cfg.identity_secret).device_id()
                        };
                    }
                    if changed {
                        self.tray.notify(
                            "NUVI Remote — Key Rotated",
                            "Your unattended access key has rotated automatically.",
                        );
                    }
                }
                NetToUi::DeviceIdSynced(id) => {
                    self.device_id = id;
                    self.server_url_draft = self.config.lock().unwrap().server_url.clone();
                }
                NetToUi::Notice(msg) => {
                    self.notice = Some(msg);
                }
                NetToUi::ChatMessage {
                    sender,
                    text,
                    sent_at,
                } => {
                    if sender != "You" {
                        self.tray.notify(&format!("Chat from {sender}"), &text);
                        if self.active_tab != ClientTab::Chat {
                            self.unread_chat += 1;
                        }
                    }
                    self.chat_messages.push(ChatHistoryEntry {
                        sender,
                        text,
                        sent_at,
                    });
                }
                NetToUi::ChatHistoryLoaded(hist) => {
                    if self.chat_messages.is_empty() {
                        self.chat_messages = hist;
                    }
                }
                NetToUi::FileProgress {
                    filename,
                    received,
                    total,
                    done,
                } => {
                    self.file_progress = Some((filename, received, total, done));
                }
            }
        }
    }
}

impl eframe::App for NuviClientApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if ctx.input(|i| i.viewport().close_requested()) && !self.allow_exit {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            self.tray.notify(
                "NUVI Remote is still running",
                "Minimized to the system tray. Double-click the tray icon to reopen.",
            );
        }

        self.drain_net_events(ctx);

        if self.pending_consent.is_some() || self.active_session.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(250));
        }

        egui::TopBottomPanel::top("client_header")
            .frame(
                egui::Frame::new()
                    .fill(Color32::from_rgb(11, 13, 23))
                    .stroke(egui::Stroke::new(1.0_f32, c(brand::BORDER_SUBTLE)))
                    .inner_margin(Margin::symmetric(12, 8)),
            )
            .show(ctx, |ui| {
                let header_label = if self.active_session.is_some() {
                    "SESSION LIVE"
                } else if self.online {
                    "ONLINE"
                } else {
                    &self.status_text
                };
                nuvi_header(ui, header_label, self.online || self.active_session.is_some());
            });

        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(c(brand::BG_CANVAS)).inner_margin(Margin::ZERO))
            .show(ctx, |ui| {
                let ribbon = if let Some(msg) = &self.notice {
                    format!("NUVI Remote  ·  {msg}")
                } else {
                    "NUVI Private Support  ·  Protected by End-to-End Encryption".to_string()
                };
                nuvi_ribbon_banner(ui, &ribbon);

                egui::Frame::new()
                    .inner_margin(Margin::symmetric(16, 12))
                    .show(ui, |ui| {
                        ui.vertical_centered(|ui| {
                            let spaced_id = self.device_id.replace('-', " ");
                            ui.horizontal(|ui| {
                                let est_w = 370.0_f32.min(ui.available_width());
                                ui.add_space(((ui.available_width() - est_w) * 0.5).max(0.0));
                                ui.label(
                                    RichText::new("Your Address")
                                        .size(13.0)
                                        .color(c(brand::TEXT_MUTED)),
                                );
                                ui.add_space(4.0);
                                ui.label(
                                    RichText::new(spaced_id)
                                        .size(26.0)
                                        .strong()
                                        .color(c(brand::ACCENT_PRIMARY)),
                                );
                                ui.add_space(6.0);
                                if secondary_pill_button(ui, "Copy").clicked() {
                                    ctx.copy_text(self.device_id.clone());
                                    self.notice = Some("Device ID copied to clipboard.".to_string());
                                }
                            });
                        });

                        ui.add_space(8.0);

                        // Active Session Banner + File Transfer Progress
                        if let Some(sess) = self.active_session.clone() {
                            nuvi_card(ui, true, |ui| {
                                let secs = self
                                    .session_started_at
                                    .map(|t| t.elapsed().as_secs())
                                    .unwrap_or(0);
                                let timer = format!("{:02}:{:02}", secs / 60, secs % 60);
                                ui.horizontal(|ui| {
                                    status_pill(ui, "LIVE", true);
                                    ui.label(
                                        RichText::new(format!("NUVI Support — {}", sess.tech_name))
                                            .strong()
                                            .color(c(brand::TEXT_PRIMARY)),
                                    );
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            ui.label(
                                                RichText::new(timer)
                                                    .monospace()
                                                    .size(12.0)
                                                    .color(c(brand::TEXT_MUTED)),
                                            );
                                        },
                                    );
                                });
                                ui.add_space(6.0);
                                ui.horizontal(|ui| {
                                    let pause_lbl = if sess.control_paused {
                                        "Resume Control"
                                    } else {
                                        "Pause Control"
                                    };
                                    if secondary_pill_button(ui, pause_lbl).clicked() {
                                        let new_paused = !sess.control_paused;
                                        if let Some(s) = self.active_session.as_mut() {
                                            s.control_paused = new_paused;
                                        }
                                        if self.svc_status.running {
                                            let _ = self.gui_ipc_tx.send(
                                                GuiToService::TogglePauseControl(new_paused),
                                            );
                                        } else {
                                            let _ = self.ui_tx.send(
                                                UiToNet::TogglePauseControl(new_paused),
                                            );
                                        }
                                    }
                                    let chat_btn_lbl = if self.unread_chat > 0 {
                                        format!("Chat ({})", self.unread_chat)
                                    } else {
                                        "Chat".to_string()
                                    };
                                    if segmented_tab_button(
                                        ui,
                                        self.active_tab == ClientTab::Chat,
                                        &chat_btn_lbl,
                                    )
                                    .clicked()
                                    {
                                        self.active_tab = ClientTab::Chat;
                                        self.unread_chat = 0;
                                    }
                                    if danger_pill_button(ui, "Disconnect").clicked() {
                                        if self.svc_status.running {
                                            let _ = self
                                                .gui_ipc_tx
                                                .send(GuiToService::DisconnectSession);
                                        } else {
                                            let _ =
                                                self.ui_tx.send(UiToNet::DisconnectSession);
                                        }
                                    }
                                });

                                if let Some((fname, rec, tot, done)) = &self.file_progress {
                                    ui.add_space(6.0);
                                    let frac = if *tot == 0 {
                                        1.0
                                    } else {
                                        (*rec as f32 / *tot as f32).clamp(0.0, 1.0)
                                    };
                                    let lbl = if *done {
                                        format!("Received: {fname}")
                                    } else {
                                        format!("Receiving {fname} ({rec}/{tot} B)")
                                    };
                                    ui.label(
                                        RichText::new(lbl)
                                            .size(11.5)
                                            .color(c(brand::ACCENT_HIGHLIGHT)),
                                    );
                                    draw_progress_bar(ui, frac, c(brand::STATUS_ONLINE));
                                }
                            });
                            ui.add_space(8.0);
                        }

                        // Dramatic Always-On-Top Consent Modal
                        if let Some(req) = self.pending_consent.clone() {
                            let secs_left = (req.expires_at - Utc::now()).num_seconds().max(0);
                            nuvi_card(ui, true, |ui| {
                                ui.horizontal(|ui| {
                                    let initials: String = req
                                        .tech_name
                                        .split_whitespace()
                                        .filter_map(|w| w.chars().next())
                                        .take(2)
                                        .collect::<String>()
                                        .to_ascii_uppercase();
                                    let avatar_lbl = if initials.is_empty() {
                                        "NV".to_string()
                                    } else {
                                        initials
                                    };
                                    egui::Frame::new()
                                        .fill(c(brand::ACCENT_TINT))
                                        .stroke(egui::Stroke::new(
                                            1.0_f32,
                                            c(brand::ACCENT_PRIMARY),
                                        ))
                                        .corner_radius(egui::CornerRadius::same(18))
                                        .inner_margin(Margin::symmetric(10, 8))
                                        .show(ui, |ui| {
                                            ui.label(
                                                RichText::new(avatar_lbl)
                                                    .strong()
                                                    .color(c(brand::ACCENT_HIGHLIGHT)),
                                            );
                                        });
                                    ui.vertical(|ui| {
                                        badge_pill(
                                            ui,
                                            "NUVI VERIFIED TECHNICIAN",
                                            c(brand::ACCENT_TINT),
                                            c(brand::ACCENT_HIGHLIGHT),
                                        );
                                        ui.label(
                                            RichText::new(format!(
                                                "{} wants to connect",
                                                req.tech_name
                                            ))
                                            .size(16.0)
                                            .strong()
                                            .color(c(brand::TEXT_PRIMARY)),
                                        );
                                    });
                                });

                                if !req.reason.trim().is_empty() {
                                    ui.add_space(4.0);
                                    ui.label(
                                        RichText::new(format!("Ticket note: {}", req.reason))
                                            .color(c(brand::TEXT_MUTED)),
                                    );
                                }
                                ui.add_space(6.0);
                                ui.checkbox(
                                    &mut self.consent_allow_control,
                                    "Allow Mouse & Keyboard Control",
                                );
                                ui.checkbox(
                                    &mut self.consent_allow_clipboard,
                                    "Allow Clipboard Sync",
                                );
                                ui.add_space(6.0);
                                draw_progress_bar(
                                    ui,
                                    secs_left as f32 / 60.0,
                                    c(brand::ACCENT_PRIMARY),
                                );
                                ui.add_space(4.0);
                                ui.horizontal(|ui| {
                                    if primary_pill_button(ui, "Accept").clicked() {
                                        let perms = SessionPermissions {
                                            allow_control: self.consent_allow_control,
                                            allow_clipboard: self.consent_allow_clipboard,
                                        };
                                        if self.svc_status.running {
                                            let _ = self.gui_ipc_tx.send(
                                                GuiToService::ConsentDecision {
                                                    session_id: req.session_id,
                                                    accepted: true,
                                                    permissions: perms,
                                                },
                                            );
                                        } else {
                                            let _ = self.ui_tx.send(UiToNet::ConsentDecision {
                                                session_id: req.session_id,
                                                accepted: true,
                                                permissions: perms,
                                            });
                                        }
                                        self.pending_consent = None;
                                        ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(
                                            egui::WindowLevel::Normal,
                                        ));
                                    }
                                    if danger_pill_button(ui, "Decline").clicked() {
                                        if self.svc_status.running {
                                            let _ = self.gui_ipc_tx.send(
                                                GuiToService::ConsentDecision {
                                                    session_id: req.session_id,
                                                    accepted: false,
                                                    permissions: SessionPermissions::default(),
                                                },
                                            );
                                        } else {
                                            let _ = self.ui_tx.send(UiToNet::ConsentDecision {
                                                session_id: req.session_id,
                                                accepted: false,
                                                permissions: SessionPermissions::default(),
                                            });
                                        }
                                        self.pending_consent = None;
                                        ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(
                                            egui::WindowLevel::Normal,
                                        ));
                                    }
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            ui.label(
                                                RichText::new(format!(
                                                    "Auto-declines in {secs_left}s"
                                                ))
                                                .size(11.5)
                                                .color(c(brand::TEXT_MUTED)),
                                            );
                                        },
                                    );
                                });
                            });
                            ui.add_space(8.0);
                        }

                        // Flat Section Tabs
                        ui.horizontal(|ui| {
                            if nuvi_flat_tab(
                                ui,
                                self.active_tab == ClientTab::Overview,
                                "Overview",
                            )
                            .clicked()
                            {
                                self.active_tab = ClientTab::Overview;
                            }
                            if self.active_session.is_some() {
                                let chat_lbl = if self.unread_chat > 0 {
                                    format!("Chat ({})", self.unread_chat)
                                } else {
                                    "Chat".to_string()
                                };
                                if nuvi_flat_tab(
                                    ui,
                                    self.active_tab == ClientTab::Chat,
                                    &chat_lbl,
                                )
                                .clicked()
                                {
                                    self.active_tab = ClientTab::Chat;
                                    self.unread_chat = 0;
                                }
                            }
                            if nuvi_flat_tab(
                                ui,
                                self.active_tab == ClientTab::Unattended,
                                "Unattended Key",
                            )
                            .clicked()
                            {
                                self.active_tab = ClientTab::Unattended;
                            }
                            if nuvi_flat_tab(
                                ui,
                                self.active_tab == ClientTab::Service,
                                "Service",
                            )
                            .clicked()
                            {
                                self.active_tab = ClientTab::Service;
                            }
                            if nuvi_flat_tab(
                                ui,
                                self.active_tab == ClientTab::Server,
                                "Server",
                            )
                            .clicked()
                            {
                                self.active_tab = ClientTab::Server;
                            }
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if secondary_pill_button(ui, "Quit").clicked() {
                                        self.allow_exit = true;
                                        self.tray.shutdown();
                                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                                    }
                                },
                            );
                        });
                        ui.separator();
                        ui.add_space(6.0);

                        egui::ScrollArea::vertical().show(ui, |ui| match self.active_tab {
                            ClientTab::Overview => self.render_overview_tab(ctx, ui),
                            ClientTab::Chat => self.render_chat_tab(ui),
                            ClientTab::Unattended => self.render_unattended_tab(ctx, ui),
                            ClientTab::Service => self.render_service_tab(ui),
                            ClientTab::Server => self.render_server_tab(ui),
                        });
                    });
            });
    }
}

impl NuviClientApp {
    fn render_overview_tab(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        let (unattended_on, next_rot) = {
            let cfg = self.config.lock().unwrap();
            (cfg.unattended.enabled, cfg.unattended.next_rotation_at)
        };

        let avail = ui.available_width();
        let tile_w = ((avail - 10.0) * 0.5).max(160.0);
        let tile_size = Vec2::new(tile_w, 108.0);

        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 10.0;
            let key_body = if unattended_on {
                "Key active\nClick to copy"
            } else {
                "Currently OFF\nClick to enable"
            };
            if nuvi_feature_tile(
                ui,
                tile_size,
                c(brand::ACCENT_TINT),
                "Unattended Key",
                key_body,
                if unattended_on { "Copy Key ->" } else { "Enable ->" },
            )
            .clicked()
            {
                if unattended_on {
                    if let Some(k) = &self.unattended_key_plain {
                        ctx.copy_text(k.clone());
                        self.notice = Some("Unattended key copied.".to_string());
                    }
                } else {
                    self.active_tab = ClientTab::Unattended;
                }
            }

            let rot_body = if unattended_on {
                human_countdown(next_rot, Utc::now())
            } else {
                "Schedule: Every 7d\n(when enabled)".to_string()
            };
            if nuvi_feature_tile(
                ui,
                tile_size,
                Color32::from_rgb(75, 34, 27),
                "Auto-Rotation",
                &rot_body,
                "Configure ->",
            )
            .clicked()
            {
                self.active_tab = ClientTab::Unattended;
            }
        });

        ui.add_space(10.0);

        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 10.0;
            let svc_body = if self.svc_status.running {
                "Running as SYSTEM\nUAC & Lock Screen OK"
            } else if self.svc_status.installed {
                "Installed (Stopped)\nCheck Services"
            } else {
                "Portable Mode\nNo install required"
            };
            if nuvi_feature_tile(
                ui,
                tile_size,
                Color32::from_rgb(21, 34, 56),
                "Windows Service",
                svc_body,
                if self.svc_status.installed {
                    "Manage ->"
                } else {
                    "Install ->"
                },
            )
            .clicked()
            {
                self.active_tab = ClientTab::Service;
            }

            if nuvi_feature_tile(
                ui,
                tile_size,
                c(brand::SURFACE_CARD),
                "NUVI Security",
                "E2EE ChaCha20\nNUVI Techs Only",
                "Copy ID ->",
            )
            .clicked()
            {
                ctx.copy_text(self.device_id.clone());
                self.notice = Some("Device ID copied to clipboard.".to_string());
            }
        });
    }

    fn render_chat_tab(&mut self, ui: &mut egui::Ui) {
        nuvi_card(ui, false, |ui| {
            ui.horizontal(|ui| {
                badge_pill(
                    ui,
                    "E2EE SESSION CHAT",
                    c(brand::ACCENT_TINT),
                    c(brand::ACCENT_HIGHLIGHT),
                );
                ui.label(
                    RichText::new("End-to-End Encrypted · ChaCha20-Poly1305")
                        .size(11.5)
                        .color(c(brand::TEXT_MUTED)),
                );
            });

            if let Some((fname, rec, tot, done)) = &self.file_progress {
                ui.add_space(6.0);
                let frac = if *tot == 0 {
                    1.0
                } else {
                    (*rec as f32 / *tot as f32).clamp(0.0, 1.0)
                };
                let lbl = if *done {
                    format!("Received: {fname}")
                } else {
                    format!("Receiving {fname} ({rec}/{tot} B)")
                };
                ui.label(
                    RichText::new(lbl)
                        .size(11.5)
                        .color(c(brand::ACCENT_HIGHLIGHT)),
                );
                draw_progress_bar(ui, frac, c(brand::STATUS_ONLINE));
            }

            ui.add_space(8.0);
            let msg_area_h = (ui.available_height() - 62.0).max(160.0);
            egui::ScrollArea::vertical()
                .max_height(msg_area_h)
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    if self.chat_messages.is_empty() {
                        ui.add_space(28.0);
                        ui.vertical_centered(|ui| {
                            ui.label(
                                RichText::new("No messages yet.")
                                    .size(13.0)
                                    .strong()
                                    .color(c(brand::TEXT_PRIMARY)),
                            );
                            ui.label(
                                RichText::new("Messages with your NUVI technician are end-to-end encrypted.")
                                    .size(11.5)
                                    .color(c(brand::TEXT_MUTED)),
                            );
                        });
                    } else {
                        for m in &self.chat_messages {
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
                                    .stroke(egui::Stroke::new(1.0_f32, stroke))
                                    .corner_radius(egui::CornerRadius::same(10))
                                    .inner_margin(Margin::symmetric(10, 7))
                                    .show(ui, |ui| {
                                        ui.set_max_width(300.0);
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
                                                    .size(12.5)
                                                    .color(c(brand::TEXT_PRIMARY)),
                                            );
                                        });
                                    });
                            });
                            ui.add_space(5.0);
                        }
                    }
                });

            ui.add_space(8.0);
            if self.active_session.is_some() {
                ui.horizontal(|ui| {
                    let resp = ui.add(
                        egui::TextEdit::singleline(&mut self.chat_draft)
                            .hint_text("Message NUVI tech...")
                            .desired_width((ui.available_width() - 78.0).max(120.0)),
                    );
                    let send_clicked = primary_pill_button(ui, "Send").clicked();
                    let enter =
                        resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if (send_clicked || enter) && !self.chat_draft.trim().is_empty() {
                        let msg = self.chat_draft.trim().to_string();
                        self.chat_draft.clear();
                        if self.svc_status.running {
                            let _ = self.gui_ipc_tx.send(GuiToService::SendChat(msg));
                        } else {
                            let _ = self.ui_tx.send(UiToNet::SendChat(msg));
                        }
                    }
                });
            } else {
                ui.label(
                    RichText::new("Waiting for a NUVI technician to connect...")
                        .size(11.5)
                        .color(c(brand::TEXT_MUTED)),
                );
            }
        });
    }

    fn render_unattended_tab(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        nuvi_card(ui, false, |ui| {
            let (mut enabled, mut schedule, mut rot_after, created_at, next_rot) = {
                let cfg = self.config.lock().unwrap();
                (
                    cfg.unattended.enabled,
                    cfg.unattended.schedule.clone(),
                    cfg.unattended.rotate_after_session,
                    cfg.unattended.created_at,
                    cfg.unattended.next_rotation_at,
                )
            };

            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Unattended Access")
                        .size(15.0)
                        .strong()
                        .color(c(brand::TEXT_PRIMARY)),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.checkbox(&mut enabled, "Enabled").changed() {
                        if self.svc_status.running {
                            let _ = self
                                .gui_ipc_tx
                                .send(GuiToService::UpdateUnattendedStatus(enabled));
                            let _ = self.gui_ipc_tx.send(GuiToService::GetStatus);
                        } else {
                            let mut cfg = self.config.lock().unwrap();
                            cfg.unattended.enabled = enabled;
                            let need_key = enabled && cfg.unattended.key_hash.is_none();
                            let _ = save_config(self.scope, &cfg);
                            drop(cfg);
                            if need_key {
                                let mut cfg = self.config.lock().unwrap();
                                if let Ok(k) = rotate_unattended_key(self.scope, &mut cfg) {
                                    self.unattended_key_plain = Some(k);
                                }
                            }
                            let _ = self.ui_tx.send(UiToNet::UpdateUnattendedStatus(enabled));
                        }
                    }
                });
            });

            if enabled {
                ui.add_space(8.0);
                let key_display = match &self.unattended_key_plain {
                    Some(k) if self.reveal_key => k.clone(),
                    Some(_) => "NUVI-••••-••••-••••".to_string(),
                    None => "Click Rotate Now to generate".to_string(),
                };
                ui.label(
                    RichText::new(key_display)
                        .size(18.0)
                        .strong()
                        .monospace()
                        .color(c(brand::ACCENT_HIGHLIGHT)),
                );
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    let eye = if self.reveal_key { "Hide" } else { "Show" };
                    if secondary_pill_button(ui, eye).clicked() {
                        self.reveal_key = !self.reveal_key;
                    }
                    if secondary_pill_button(ui, "Copy Key").clicked() {
                        if let Some(k) = &self.unattended_key_plain {
                            ctx.copy_text(k.clone());
                            self.notice = Some("Unattended key copied.".to_string());
                        }
                    }
                    if primary_pill_button(ui, "Rotate Now").clicked() {
                        if self.svc_status.running {
                            let _ = self.gui_ipc_tx.send(GuiToService::RotateKeyNow);
                            self.notice = Some("Requested service key rotation.".to_string());
                        } else {
                            let mut cfg = self.config.lock().unwrap();
                            if let Ok(k) = rotate_unattended_key(self.scope, &mut cfg) {
                                self.unattended_key_plain = Some(k);
                                self.notice = Some("Unattended key rotated.".to_string());
                            }
                        }
                    }
                });

                ui.add_space(8.0);
                let now = Utc::now();
                let total_secs = (next_rot - created_at).num_seconds().max(1) as f32;
                let rem_secs = (next_rot - now).num_seconds().max(0) as f32;
                draw_progress_bar(
                    ui,
                    (rem_secs / total_secs).clamp(0.0, 1.0),
                    c(brand::ACCENT_PRIMARY),
                );
                ui.add_space(4.0);
                ui.label(
                    RichText::new(human_countdown(next_rot, now))
                        .size(12.0)
                        .color(c(brand::TEXT_MUTED)),
                );

                ui.add_space(10.0);
                ui.label(
                    RichText::new("Auto-Rotation Schedule")
                        .size(12.5)
                        .strong()
                        .color(c(brand::TEXT_PRIMARY)),
                );
                ui.horizontal(|ui| {
                    let is_n_days = matches!(schedule, RotationSchedule::EveryNDays { .. });
                    if segmented_tab_button(ui, is_n_days, "Every N Days").clicked() {
                        schedule = RotationSchedule::EveryNDays { days: 7 };
                        self.custom_days_str = "7".to_string();
                        self.save_schedule(schedule.clone());
                    }
                    if segmented_tab_button(ui, !is_n_days, "Specific Weekdays").clicked() {
                        schedule = RotationSchedule::Weekdays {
                            mon: true,
                            tue: false,
                            wed: false,
                            thu: false,
                            fri: false,
                            sat: false,
                            sun: false,
                        };
                        self.save_schedule(schedule.clone());
                    }
                });

                let mut schedule_changed = false;
                match &mut schedule {
                    RotationSchedule::EveryNDays { days } => {
                        ui.horizontal(|ui| {
                            for d in [1u16, 3, 7, 14, 30] {
                                if segmented_tab_button(ui, *days == d, &format!("{d}d")).clicked()
                                {
                                    *days = d;
                                    self.custom_days_str = d.to_string();
                                    schedule_changed = true;
                                }
                            }
                            ui.add(
                                egui::TextEdit::singleline(&mut self.custom_days_str)
                                    .desired_width(36.0),
                            );
                            if secondary_pill_button(ui, "Set").clicked() {
                                if let Ok(parsed) = self.custom_days_str.trim().parse::<u16>() {
                                    *days = parsed.clamp(1, 365);
                                    schedule_changed = true;
                                }
                            }
                        });
                    }
                    RotationSchedule::Weekdays {
                        mon,
                        tue,
                        wed,
                        thu,
                        fri,
                        sat,
                        sun,
                    } => {
                        ui.horizontal_wrapped(|ui| {
                            let mut changed = false;
                            changed |= ui.checkbox(mon, "Mon").changed();
                            changed |= ui.checkbox(tue, "Tue").changed();
                            changed |= ui.checkbox(wed, "Wed").changed();
                            changed |= ui.checkbox(thu, "Thu").changed();
                            changed |= ui.checkbox(fri, "Fri").changed();
                            changed |= ui.checkbox(sat, "Sat").changed();
                            changed |= ui.checkbox(sun, "Sun").changed();
                            if changed {
                                schedule_changed = true;
                            }
                        });
                    }
                }
                if schedule_changed {
                    self.save_schedule(schedule);
                }

                ui.add_space(4.0);
                if ui
                    .checkbox(&mut rot_after, "Also rotate automatically after each session")
                    .changed()
                {
                    if self.svc_status.running {
                        let _ = self
                            .gui_ipc_tx
                            .send(GuiToService::UpdateRotateAfterSession(rot_after));
                    } else {
                        let mut cfg = self.config.lock().unwrap();
                        cfg.unattended.rotate_after_session = rot_after;
                        let _ = save_config(self.scope, &cfg);
                    }
                }
            } else {
                ui.add_space(6.0);
                ui.label(
                    RichText::new("Turn on Unattended Access to generate an auto-rotating key for NUVI support.")
                        .size(12.0)
                        .color(c(brand::TEXT_MUTED)),
                );
            }
        });
    }

    fn render_service_tab(&mut self, ui: &mut egui::Ui) {
        nuvi_card(ui, false, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Windows Unattended Service")
                        .size(15.0)
                        .strong()
                        .color(c(brand::TEXT_PRIMARY)),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let badge = if self.svc_status.running {
                        "SERVICE RUNNING"
                    } else if self.svc_status.installed {
                        "INSTALLED (STOPPED)"
                    } else {
                        "PORTABLE MODE"
                    };
                    status_pill(ui, badge, self.svc_status.running);
                });
            });
            ui.add_space(8.0);

            let check_col = if self.svc_status.installed {
                c(brand::STATUS_ONLINE)
            } else {
                c(brand::TEXT_MUTED)
            };
            let prefix = if self.svc_status.installed { "[OK]" } else { "[--]" };
            for item in [
                "Auto-starts at Windows boot before user login",
                "View & click UAC prompts and Admin windows",
                "View & unlock Windows Lock Screen (Ctrl+Alt+Del)",
                "Supports remote Reboot & automatic reconnection",
            ] {
                ui.label(RichText::new(format!("{prefix}  {item}")).size(12.0).color(check_col));
            }

            ui.add_space(10.0);
            if self.svc_status.installed {
                ui.horizontal(|ui| {
                    if secondary_pill_button(ui, "Update Service").clicked() {
                        match trigger_elevated_install() {
                            Ok(()) => {
                                self.notice = Some("Updating Windows Service... Click Refresh Status after UAC completes.".to_string());
                            }
                            Err(e) => {
                                self.notice = Some(format!("Update failed: {e}"));
                            }
                        }
                    }
                    if danger_pill_button(ui, "Uninstall Service").clicked() {
                        match trigger_elevated_uninstall() {
                            Ok(()) => {
                                self.notice = Some("Uninstall started (re-open app or click Refresh after UAC).".to_string());
                            }
                            Err(e) => {
                                self.notice = Some(format!("Uninstall failed: {e}"));
                            }
                        }
                    }
                    if secondary_pill_button(ui, "Refresh Status").clicked() {
                        self.svc_status = query_service_status();
                    }
                });
            } else {
                ui.horizontal(|ui| {
                    if primary_pill_button(ui, "Install for Unattended").clicked() {
                        match trigger_elevated_install() {
                            Ok(()) => {
                                self.notice = Some("Installing Windows Service... Restart this app after UAC completes to manage the service.".to_string());
                            }
                            Err(e) => {
                                self.notice = Some(format!("Install failed: {e}"));
                            }
                        }
                    }
                    if secondary_pill_button(ui, "Refresh Status").clicked() {
                        self.svc_status = query_service_status();
                    }
                });
            }
        });
    }

    fn save_schedule(&self, schedule: RotationSchedule) {
        if self.svc_status.running {
            let _ = self.gui_ipc_tx.send(GuiToService::UpdateSchedule(schedule));
        } else {
            let mut cfg = self.config.lock().unwrap();
            let now = Utc::now();
            cfg.unattended.next_rotation_at = compute_next_rotation_utc(&schedule, now);
            cfg.unattended.schedule = schedule;
            let _ = save_config(self.scope, &cfg);
        }
    }

    fn render_server_tab(&mut self, ui: &mut egui::Ui) {
        nuvi_card(ui, false, |ui| {
            ui.label(
                RichText::new("Relay Server Configuration")
                    .size(15.0)
                    .strong()
                    .color(c(brand::TEXT_PRIMARY)),
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new("Enter your relay domain, LAN/Tailscale/VPS IP, or a nuvi:// setup code from your technician.")
                    .size(12.0)
                    .color(c(brand::TEXT_MUTED)),
            );
            ui.add_space(8.0);

            ui.add(
                egui::TextEdit::singleline(&mut self.server_url_draft)
                    .hint_text("remote.yourdomain.com, 192.168.1.50, or nuvi://...")
                    .desired_width(ui.available_width()),
            );
            let normalized = normalize_server_url(&self.server_url_draft);
            ui.add_space(4.0);
            ui.label(
                RichText::new(format!("Resolved WS URL: {normalized}"))
                    .size(11.5)
                    .monospace()
                    .color(c(brand::ACCENT_HIGHLIGHT)),
            );
            ui.add_space(8.0);

            ui.horizontal(|ui| {
                if primary_pill_button(ui, "Save & Reconnect").clicked() {
                    self.server_url_draft = normalized.clone();
                    if self.svc_status.running {
                        let _ = self
                            .gui_ipc_tx
                            .send(GuiToService::UpdateServerUrl(normalized.clone()));
                    } else {
                        {
                            let mut cfg = self.config.lock().unwrap();
                            cfg.server_url = normalized.clone();
                            let _ = save_config(self.scope, &cfg);
                        }
                        let _ = self.ui_tx.send(UiToNet::Reconnect);
                    }
                    self.notice = Some(format!("Connecting to {normalized}..."));
                }
            });

            ui.add_space(10.0);
            ui.label(
                RichText::new("Tip: Drop a 1-line `nuvi-server.txt` file next to nuvi-client.exe to pre-configure the server automatically.")
                    .size(11.5)
                    .color(c(brand::TEXT_MUTED)),
            );
        });
    }
}
