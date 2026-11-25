#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod capture;
mod input;
mod ipc;
mod net;
mod overlay;
mod service;
mod storage;
mod theme;
mod tray;

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use nuvi_proto::protocol::ClientRunMode;
use storage::StorageScope;
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("nuvi_client=info")),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--status") {
        let st = service::query_service_status();
        println!(
            "NuviRemoteService installed={} running={}",
            st.installed, st.running
        );
        return Ok(());
    }

    if args.iter().any(|a| a == "--install-service") {
        let migrate_from = args
            .windows(2)
            .find(|w| w[0] == "--migrate-from")
            .map(|w| PathBuf::from(&w[1]));
        if let Err(e) = service::run_install_service(migrate_from) {
            eprintln!("Service install failed: {e}");
            std::process::exit(1);
        }
        return Ok(());
    }

    if args.iter().any(|a| a == "--uninstall-service") {
        if let Err(e) = service::run_uninstall_service() {
            eprintln!("Service uninstall failed: {e}");
            std::process::exit(1);
        }
        return Ok(());
    }

    if args.iter().any(|a| a == "--service") {
        if let Err(e) = service::run_windows_service() {
            eprintln!("Service exited with error: {e}");
            std::process::exit(1);
        }
        return Ok(());
    }

    if args.iter().any(|a| a == "--session-helper") {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        if let Err(e) = rt.block_on(service::run_session_helper()) {
            eprintln!("Session helper exited: {e}");
            std::process::exit(1);
        }
        return Ok(());
    }

    #[cfg(windows)]
    unsafe {
        use windows::Win32::UI::HiDpi::{
            SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
        };
        let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    }

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let _enter = rt.enter();

    let svc_status = service::query_service_status();
    let scope = if svc_status.running {
        StorageScope::MachineService
    } else {
        StorageScope::Portable
    };

    let cfg = Arc::new(Mutex::new(if svc_status.running {
        storage::load_config_readonly_or_default(scope)
    } else {
        storage::load_or_create_config(scope)
    }));
    let (ui_tx, ui_rx) = mpsc::unbounded_channel();
    let (net_tx, net_rx) = mpsc::unbounded_channel();
    let (gui_ipc_tx, gui_ipc_rx) = mpsc::unbounded_channel::<ipc::GuiToService>();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([500.0, 640.0])
            .with_min_inner_size([440.0, 560.0])
            .with_icon(Arc::new(theme::nuvi_window_icon()))
            .with_title("NUVI Remote — Client"),
        ..Default::default()
    };

    let service_running = svc_status.running;
    eframe::run_native(
        "NUVI Remote — Client",
        options,
        Box::new(move |cc| {
            theme::apply_nuvi_theme(&cc.egui_ctx);
            let (tray_handle, tray_rx) = tray::TrayHandle::spawn(cc.egui_ctx.clone());
            if service_running {
                app::spawn_gui_pipe_bridge(
                    cfg.clone(),
                    gui_ipc_rx,
                    net_tx,
                    cc.egui_ctx.clone(),
                );
            } else {
                net::spawn_network_worker(
                    StorageScope::Portable,
                    ClientRunMode::Portable,
                    cfg.clone(),
                    ui_rx,
                    net_tx,
                    cc.egui_ctx.clone(),
                );
            }
            Ok(Box::new(app::NuviClientApp::new(
                scope,
                svc_status,
                cfg,
                ui_tx,
                gui_ipc_tx,
                net_rx,
                tray_handle,
                tray_rx,
            )))
        }),
    )
}
