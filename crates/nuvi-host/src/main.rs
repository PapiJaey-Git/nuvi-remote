#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod keymap;
mod net;
mod storage;
mod theme;

use std::sync::Arc;

use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("nuvi_host=info")),
        )
        .init();

    #[cfg(windows)]
    unsafe {
        use windows::Win32::UI::HiDpi::{
            SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
        };
        let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    }

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let _enter = rt.enter();

    let cfg = storage::load_or_create_config();
    let (ev_tx, ev_rx) = mpsc::unbounded_channel();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1120.0, 740.0])
            .with_min_inner_size([820.0, 560.0])
            .with_icon(Arc::new(theme::nuvi_window_icon()))
            .with_title("NUVI Remote — Tech Console"),
        ..Default::default()
    };

    eframe::run_native(
        "NUVI Remote — Tech Console",
        options,
        Box::new(move |cc| {
            theme::apply_nuvi_theme(&cc.egui_ctx);
            Ok(Box::new(app::NuviHostApp::new(cfg, ev_tx, ev_rx)))
        }),
    )
}
