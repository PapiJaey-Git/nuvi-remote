use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use anyhow::{anyhow, Result};
use nuvi_proto::protocol::{ClientRunMode, MonitorInfo, QualityPreset, RemoteCursorShape};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    sync::{broadcast, mpsc, watch, RwLock},
};
use tracing::{error, info, warn};

use crate::{
    capture::{enumerate_monitors, query_cursor_shape, ScreenCapturer},
    input::InputInjector,
    ipc::{
        read_bincode_frame, write_bincode_frame, GuiToService, HelperCmd, HelperEvent,
        PendingConsentSnapshot, ServiceSnapshot, ServiceToGui, HELPER_PIPE_NAME,
    },
    net::{run_client_worker, ActiveSessionInfo, NetToUi, UiToNet},
    overlay::OverlayHandle,
    storage::{
        data_dir, load_chat_history, load_dpapi_key, load_or_create_config,
        migrate_portable_to_service, rotate_unattended_key, save_config, ClientConfig,
        StorageScope,
    },
};

pub const SERVICE_NAME: &str = "NuviRemoteService";
pub const SERVICE_DISPLAY_NAME: &str = "NUVI Remote Unattended Service";
pub const SERVICE_DESC: &str =
    "Enables unattended remote support, UAC control, and Windows lock-screen access for NUVI Remote.";
pub const INSTALL_DIR: &str = r"C:\Program Files\NUVI Remote";
pub const INSTALL_EXE_PATH: &str = r"C:\Program Files\NUVI Remote\nuvi-client.exe";

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct ServiceStatusSummary {
    pub installed: bool,
    pub running: bool,
}

#[derive(Clone)]
pub struct HelperBridge {
    cmd_tx: Arc<RwLock<Option<mpsc::UnboundedSender<HelperCmd>>>>,
    monitors: Arc<RwLock<Vec<MonitorInfo>>>,
    frame_tx: mpsc::Sender<nuvi_proto::protocol::VideoFrame>,
    cursor_tx: mpsc::Sender<RemoteCursorShape>,
}

impl HelperBridge {
    pub fn new(
        frame_tx: mpsc::Sender<nuvi_proto::protocol::VideoFrame>,
        cursor_tx: mpsc::Sender<RemoteCursorShape>,
    ) -> Self {
        Self {
            cmd_tx: Arc::new(RwLock::new(None)),
            monitors: Arc::new(RwLock::new(Vec::new())),
            frame_tx,
            cursor_tx,
        }
    }

    pub async fn send_cmd(&self, cmd: HelperCmd) {
        let tx = self.cmd_tx.read().await.clone();
        if let Some(tx) = tx {
            let _ = tx.send(cmd);
        }
    }

    pub async fn get_monitors(&self) -> Vec<MonitorInfo> {
        let m = self.monitors.read().await.clone();
        if m.is_empty() {
            enumerate_monitors()
        } else {
            m
        }
    }
}

#[cfg(windows)]
pub fn query_service_status() -> ServiceStatusSummary {
    use windows::{
        core::PCWSTR,
        Win32::System::Services::{
            CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx,
            SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS,
            SERVICE_RUNNING, SERVICE_STATUS_PROCESS,
        },
    };

    unsafe {
        let Ok(scm) = OpenSCManagerW(None, None, SC_MANAGER_CONNECT) else {
            return ServiceStatusSummary::default();
        };
        let name_w: Vec<u16> = SERVICE_NAME.encode_utf16().chain(Some(0)).collect();
        let Ok(svc) = OpenServiceW(scm, PCWSTR(name_w.as_ptr()), SERVICE_QUERY_STATUS) else {
            let _ = CloseServiceHandle(scm);
            return ServiceStatusSummary::default();
        };

        let mut ssp = SERVICE_STATUS_PROCESS::default();
        let mut needed = 0u32;
        let slice = std::slice::from_raw_parts_mut(
            &mut ssp as *mut _ as *mut u8,
            std::mem::size_of::<SERVICE_STATUS_PROCESS>(),
        );
        let running = QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, Some(slice), &mut needed)
            .is_ok()
            && ssp.dwCurrentState == SERVICE_RUNNING;

        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
        ServiceStatusSummary {
            installed: true,
            running,
        }
    }
}

#[cfg(not(windows))]
pub fn query_service_status() -> ServiceStatusSummary {
    ServiceStatusSummary::default()
}

#[cfg(windows)]
pub fn trigger_elevated_install() -> Result<()> {
    let portable_dir = data_dir(StorageScope::Portable);
    let args = format!(
        "--install-service --migrate-from \"{}\"",
        portable_dir.display()
    );
    shell_execute_runas(&args)
}

#[cfg(not(windows))]
pub fn trigger_elevated_install() -> Result<()> {
    Err(anyhow!("Windows Service install is only supported on Windows"))
}

#[cfg(windows)]
pub fn trigger_elevated_uninstall() -> Result<()> {
    shell_execute_runas("--uninstall-service")
}

#[cfg(not(windows))]
pub fn trigger_elevated_uninstall() -> Result<()> {
    Err(anyhow!("Windows Service uninstall is only supported on Windows"))
}

#[cfg(windows)]
fn shell_execute_runas(args: &str) -> Result<()> {
    use windows::{
        core::PCWSTR,
        Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_HIDE},
    };

    let exe = std::env::current_exe()?;
    let exe_w: Vec<u16> = exe.to_string_lossy().encode_utf16().chain(Some(0)).collect();
    let verb_w: Vec<u16> = "runas".encode_utf16().chain(Some(0)).collect();
    let args_w: Vec<u16> = args.encode_utf16().chain(Some(0)).collect();

    unsafe {
        let inst = ShellExecuteW(
            None,
            PCWSTR(verb_w.as_ptr()),
            PCWSTR(exe_w.as_ptr()),
            PCWSTR(args_w.as_ptr()),
            None,
            SW_HIDE,
        );
        if (inst.0 as isize) <= 32 {
            return Err(anyhow!("Elevation declined or failed (code {:?})", inst.0));
        }
    }
    Ok(())
}

#[cfg(windows)]
pub fn run_install_service(migrate_from: Option<PathBuf>) -> Result<()> {
    use windows::{
        core::PCWSTR,
        Win32::System::Services::{
            ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, ControlService,
            CreateServiceW, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, StartServiceW,
            SC_MANAGER_ALL_ACCESS, SC_STATUS_PROCESS_INFO, SERVICE_ALL_ACCESS,
            SERVICE_AUTO_START, SERVICE_CONFIG_DESCRIPTION, SERVICE_CONTROL_STOP,
            SERVICE_DESCRIPTIONW, SERVICE_ERROR_NORMAL, SERVICE_NO_CHANGE, SERVICE_STATUS,
            SERVICE_STATUS_PROCESS, SERVICE_STOPPED, SERVICE_WIN32_OWN_PROCESS,
        },
    };

    let name_w: Vec<u16> = SERVICE_NAME.encode_utf16().chain(Some(0)).collect();

    // If the service is already installed/running, stop it first so we can overwrite the binary in-place.
    unsafe {
        if let Ok(scm) = OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS) {
            if let Ok(existing) = OpenServiceW(scm, PCWSTR(name_w.as_ptr()), SERVICE_ALL_ACCESS) {
                let mut status = SERVICE_STATUS::default();
                let _ = ControlService(existing, SERVICE_CONTROL_STOP, &mut status);
                for _ in 0..40 {
                    let mut ssp = SERVICE_STATUS_PROCESS::default();
                    let mut needed = 0u32;
                    let slice = std::slice::from_raw_parts_mut(
                        &mut ssp as *mut _ as *mut u8,
                        std::mem::size_of::<SERVICE_STATUS_PROCESS>(),
                    );
                    if QueryServiceStatusEx(existing, SC_STATUS_PROCESS_INFO, Some(slice), &mut needed)
                        .is_ok()
                        && ssp.dwCurrentState == SERVICE_STOPPED
                    {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }
                let _ = CloseServiceHandle(existing);
            }
            let _ = CloseServiceHandle(scm);
        }
    }

    std::fs::create_dir_all(INSTALL_DIR)?;
    let current = std::env::current_exe()?;
    let target = Path::new(INSTALL_EXE_PATH);
    if current != target {
        std::fs::copy(&current, target)?;
    }

    let src_dir = migrate_from.unwrap_or_else(|| data_dir(StorageScope::Portable));
    migrate_portable_to_service(&src_dir)?;
    let _ = crate::storage::harden_service_data_dir_acl(&data_dir(StorageScope::MachineService));
    enable_software_sas_policy();

    let bin_path = format!("\"{}\" --service", INSTALL_EXE_PATH);
    let bin_w: Vec<u16> = bin_path.encode_utf16().chain(Some(0)).collect();
    let disp_w: Vec<u16> = SERVICE_DISPLAY_NAME.encode_utf16().chain(Some(0)).collect();
    let mut desc_w: Vec<u16> = SERVICE_DESC.encode_utf16().chain(Some(0)).collect();

    unsafe {
        let scm = OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
            .map_err(|e| anyhow!("OpenSCManagerW failed (run as Admin): {e}"))?;

        let svc = match OpenServiceW(scm, PCWSTR(name_w.as_ptr()), SERVICE_ALL_ACCESS) {
            Ok(existing) => {
                let _ = ChangeServiceConfigW(
                    existing,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    PCWSTR(bin_w.as_ptr()),
                    None,
                    None,
                    None,
                    None,
                    None,
                    PCWSTR(disp_w.as_ptr()),
                );
                existing
            }
            Err(_) => CreateServiceW(
                scm,
                PCWSTR(name_w.as_ptr()),
                PCWSTR(disp_w.as_ptr()),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                PCWSTR(bin_w.as_ptr()),
                None,
                None,
                None,
                None,
                None,
            )
            .map_err(|e| anyhow!("CreateServiceW failed: {e}"))?,
        };

        let mut sd = SERVICE_DESCRIPTIONW {
            lpDescription: windows::core::PWSTR(desc_w.as_mut_ptr()),
        };
        let _ = ChangeServiceConfig2W(
            svc,
            SERVICE_CONFIG_DESCRIPTION,
            Some(&mut sd as *mut _ as *const _),
        );

        let _ = StartServiceW(svc, None);
        let _ = SERVICE_NO_CHANGE;
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
    }

    Ok(())
}

#[cfg(not(windows))]
pub fn run_install_service(_migrate_from: Option<PathBuf>) -> Result<()> {
    Err(anyhow!("Windows-only"))
}

#[cfg(windows)]
pub fn run_uninstall_service() -> Result<()> {
    use windows::{
        core::PCWSTR,
        Win32::System::Services::{
            CloseServiceHandle, ControlService, DeleteService, OpenSCManagerW, OpenServiceW,
            QueryServiceStatusEx, SC_MANAGER_ALL_ACCESS, SC_STATUS_PROCESS_INFO,
            SERVICE_ALL_ACCESS, SERVICE_CONTROL_STOP, SERVICE_STATUS, SERVICE_STATUS_PROCESS,
            SERVICE_STOPPED,
        },
    };

    unsafe {
        let scm = OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
            .map_err(|e| anyhow!("OpenSCManagerW failed: {e}"))?;
        let name_w: Vec<u16> = SERVICE_NAME.encode_utf16().chain(Some(0)).collect();
        if let Ok(svc) = OpenServiceW(scm, PCWSTR(name_w.as_ptr()), SERVICE_ALL_ACCESS) {
            let mut status = SERVICE_STATUS::default();
            let _ = ControlService(svc, SERVICE_CONTROL_STOP, &mut status);

            for _ in 0..20 {
                let mut ssp = SERVICE_STATUS_PROCESS::default();
                let mut needed = 0u32;
                let slice = std::slice::from_raw_parts_mut(
                    &mut ssp as *mut _ as *mut u8,
                    std::mem::size_of::<SERVICE_STATUS_PROCESS>(),
                );
                if QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, Some(slice), &mut needed)
                    .is_ok()
                    && ssp.dwCurrentState == SERVICE_STOPPED
                {
                    break;
                }
                std::thread::sleep(Duration::from_millis(250));
            }

            let _ = DeleteService(svc);
            let _ = CloseServiceHandle(svc);
        }
        let _ = CloseServiceHandle(scm);
    }

    let _ = std::fs::remove_file(INSTALL_EXE_PATH);
    let _ = std::fs::remove_dir(INSTALL_DIR);
    Ok(())
}

#[cfg(not(windows))]
pub fn run_uninstall_service() -> Result<()> {
    Err(anyhow!("Windows-only"))
}

#[cfg(windows)]
fn enable_software_sas_policy() {
    use windows::{
        core::PCWSTR,
        Win32::System::Registry::{
            RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_WRITE,
            REG_DWORD, REG_OPTION_NON_VOLATILE,
        },
    };

    let subkey: Vec<u16> = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let val_name: Vec<u16> = "SoftwareSASGeneration"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let data: u32 = 1; // Allow services only to simulate SAS

    unsafe {
        let mut hkey = HKEY::default();
        if RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            0,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        )
        .is_ok()
        {
            let _ = RegSetValueExW(
                hkey,
                PCWSTR(val_name.as_ptr()),
                0,
                REG_DWORD,
                Some(&data.to_le_bytes()),
            );
            let _ = RegCloseKey(hkey);
        }
    }
}

#[cfg(windows)]
pub fn send_ctrl_alt_del() -> Result<()> {
    use windows::{
        core::{PCSTR, PCWSTR},
        Win32::{
            Foundation::FreeLibrary,
            System::LibraryLoader::{GetProcAddress, LoadLibraryW},
        },
    };

    let dll_w: Vec<u16> = "sas.dll".encode_utf16().chain(Some(0)).collect();
    unsafe {
        let hmod = LoadLibraryW(PCWSTR(dll_w.as_ptr()))
            .map_err(|e| anyhow!("Failed to load sas.dll: {e}"))?;
        let proc = GetProcAddress(hmod, PCSTR(b"SendSAS\0".as_ptr()));
        if let Some(func) = proc {
            let send_sas: unsafe extern "system" fn(windows::Win32::Foundation::BOOL) =
                std::mem::transmute(func);
            send_sas(false.into());
            let _ = FreeLibrary(hmod);
            Ok(())
        } else {
            let _ = FreeLibrary(hmod);
            Err(anyhow!("SendSAS export not found in sas.dll"))
        }
    }
}

#[cfg(not(windows))]
pub fn send_ctrl_alt_del() -> Result<()> {
    Err(anyhow!("Windows-only"))
}

#[cfg(windows)]
pub fn system32_exe(name: &str) -> PathBuf {
    use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
    let mut buf = [0u16; 260];
    let len = unsafe { GetSystemDirectoryW(Some(&mut buf)) } as usize;
    if len > 0 && len < buf.len() {
        let dir = String::from_utf16_lossy(&buf[..len]);
        PathBuf::from(dir).join(name)
    } else {
        PathBuf::from(r"C:\Windows\System32").join(name)
    }
}

#[cfg(not(windows))]
pub fn system32_exe(name: &str) -> PathBuf {
    PathBuf::from(name)
}

pub fn trigger_system_reboot() -> Result<()> {
    #[cfg(windows)]
    {
        std::process::Command::new(system32_exe("shutdown.exe"))
            .args(["/r", "/t", "2", "/c", "NUVI Remote reboot requested"])
            .spawn()?;
        Ok(())
    }
    #[cfg(not(windows))]
    Err(anyhow!("Windows-only"))
}

// ============================================================================
// Windows Service Runtime (Session 0)
// ============================================================================

static SHUTDOWN_TX: OnceLock<watch::Sender<bool>> = OnceLock::new();

#[cfg(windows)]
pub fn run_windows_service() -> Result<()> {
    use windows::{
        core::PWSTR,
        Win32::System::Services::{
            StartServiceCtrlDispatcherW, SERVICE_TABLE_ENTRYW,
        },
    };

    let mut name_w: Vec<u16> = SERVICE_NAME.encode_utf16().chain(Some(0)).collect();
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR(name_w.as_mut_ptr()),
            lpServiceProc: Some(service_main_entry),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];

    unsafe {
        StartServiceCtrlDispatcherW(table.as_ptr())
            .map_err(|e| anyhow!("StartServiceCtrlDispatcherW failed: {e}"))?;
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn run_windows_service() -> Result<()> {
    Err(anyhow!("Windows-only"))
}

#[cfg(windows)]
unsafe extern "system" fn service_ctrl_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut std::ffi::c_void,
    _context: *mut std::ffi::c_void,
) -> u32 {
    use windows::Win32::System::Services::{SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP};
    if control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN {
        if let Some(tx) = SHUTDOWN_TX.get() {
            let _ = tx.send(true);
        }
    }
    0
}

#[cfg(windows)]
unsafe extern "system" fn service_main_entry(_argc: u32, _argv: *mut windows::core::PWSTR) {
    use windows::{
        core::PCWSTR,
        Win32::System::Services::{
            RegisterServiceCtrlHandlerExW, SetServiceStatus, SERVICE_ACCEPT_SHUTDOWN,
            SERVICE_ACCEPT_STOP, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS,
            SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_WIN32_OWN_PROCESS,
        },
    };

    let name_w: Vec<u16> = SERVICE_NAME.encode_utf16().chain(Some(0)).collect();
    let Ok(status_handle) =
        RegisterServiceCtrlHandlerExW(PCWSTR(name_w.as_ptr()), Some(service_ctrl_handler), None)
    else {
        return;
    };

    let set_status = |handle: SERVICE_STATUS_HANDLE,
                      state: windows::Win32::System::Services::SERVICE_STATUS_CURRENT_STATE,
                      accepted: u32| {
        let ss = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: accepted,
            dwWin32ExitCode: 0,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: 0,
        };
        let _ = SetServiceStatus(handle, &ss);
    };

    set_status(status_handle, SERVICE_START_PENDING, 0);

    let (sd_tx, mut sd_rx) = watch::channel(false);
    let _ = SHUTDOWN_TX.set(sd_tx);

    set_status(
        status_handle,
        SERVICE_RUNNING,
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
    );

    if let Ok(rt) = tokio::runtime::Runtime::new() {
        rt.block_on(async move {
            run_service_runtime(&mut sd_rx).await;
        });
    }

    set_status(status_handle, SERVICE_STOPPED, 0);
}

#[cfg(windows)]
async fn run_service_runtime(shutdown_rx: &mut watch::Receiver<bool>) {
    let _ = crate::storage::harden_service_data_dir_acl(&data_dir(StorageScope::MachineService));
    let config = Arc::new(Mutex::new(load_or_create_config(StorageScope::MachineService)));
    let (ui_tx, ui_rx) = mpsc::unbounded_channel::<UiToNet>();
    let (net_tx, mut net_rx) = mpsc::unbounded_channel::<NetToUi>();
    let (frame_tx, frame_rx) = mpsc::channel::<nuvi_proto::protocol::VideoFrame>(4);
    let (cursor_tx, cursor_rx) = mpsc::channel::<RemoteCursorShape>(8);

    let helper_bridge = HelperBridge::new(frame_tx, cursor_tx);

    // 1. Spawn Helper Named Pipe Server + Session Helper Supervisor
    let bridge_pipe = helper_bridge.clone();
    let mut sd_pipe = shutdown_rx.clone();
    tokio::spawn(async move {
        run_helper_pipe_server(bridge_pipe, &mut sd_pipe).await;
    });

    let mut sd_sup = shutdown_rx.clone();
    tokio::spawn(async move {
        run_session_helper_supervisor(&mut sd_sup).await;
    });

    // 2. Shared live state for GUI snapshots + broadcast channel to connected GUIs
    let live_state = Arc::new(RwLock::new(ServiceLiveState::default()));
    let (gui_bcast_tx, _) = broadcast::channel::<ServiceToGui>(64);

    let ls_clone = live_state.clone();
    let bcast_clone = gui_bcast_tx.clone();
    tokio::spawn(async move {
        while let Some(ev) = net_rx.recv().await {
            let msg = match ev {
                NetToUi::ConnectionState { online, status } => {
                    let mut ls = ls_clone.write().await;
                    ls.online = online;
                    ls.status = status.clone();
                    ServiceToGui::ConnectionState { online, status }
                }
                NetToUi::ConsentRequested(req) => {
                    let snap = PendingConsentSnapshot::from(&req);
                    ls_clone.write().await.pending_consent = Some(snap.clone());
                    ServiceToGui::ConsentRequested(snap)
                }
                NetToUi::ConsentCleared => {
                    ls_clone.write().await.pending_consent = None;
                    ServiceToGui::ConsentCleared
                }
                NetToUi::SessionStarted(info) => {
                    let mut ls = ls_clone.write().await;
                    ls.pending_consent = None;
                    ls.active_session = Some(info.clone());
                    ServiceToGui::SessionStarted(info)
                }
                NetToUi::SessionEnded { reason } => {
                    ls_clone.write().await.active_session = None;
                    ServiceToGui::SessionEnded { reason }
                }
                NetToUi::KeyAutoRotated { new_key } => ServiceToGui::KeyAutoRotated { new_key },
                NetToUi::DeviceIdSynced(_) => continue,
                NetToUi::Notice(n) => ServiceToGui::Notice(n),
                NetToUi::ChatMessage {
                    sender,
                    text,
                    sent_at,
                } => ServiceToGui::ChatMessage {
                    sender,
                    text,
                    sent_at,
                },
                NetToUi::ChatHistoryLoaded(_) => continue,
                NetToUi::FileProgress {
                    filename,
                    received,
                    total,
                    done,
                } => ServiceToGui::FileProgress {
                    filename,
                    received,
                    total,
                    done,
                },
            };
            let _ = bcast_clone.send(msg);
        }
    });

    // 3. GUI Named Pipe Server
    let cfg_gui = config.clone();
    let ui_tx_gui = ui_tx.clone();
    let ls_gui = live_state.clone();
    let bcast_gui = gui_bcast_tx.clone();
    let mut sd_gui = shutdown_rx.clone();
    tokio::spawn(async move {
        run_gui_pipe_server(cfg_gui, ui_tx_gui, ls_gui, bcast_gui, &mut sd_gui).await;
    });

    // 4. Network Worker in Service Mode
    let worker = tokio::spawn(run_client_worker(
        StorageScope::MachineService,
        ClientRunMode::Service,
        config,
        ui_rx,
        net_tx,
        None,
        Some((helper_bridge, frame_rx, cursor_rx)),
    ));

    let _ = shutdown_rx.wait_for(|&v| v).await;
    worker.abort();
}

#[derive(Default)]
struct ServiceLiveState {
    online: bool,
    status: String,
    pending_consent: Option<PendingConsentSnapshot>,
    active_session: Option<ActiveSessionInfo>,
}

#[cfg(windows)]
async fn run_gui_pipe_server(
    config: Arc<Mutex<ClientConfig>>,
    ui_tx: mpsc::UnboundedSender<UiToNet>,
    live_state: Arc<RwLock<ServiceLiveState>>,
    bcast_tx: broadcast::Sender<ServiceToGui>,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    use crate::ipc::{create_secure_named_pipe, GUI_PIPE_NAME, GUI_PIPE_SDDL};

    let mut first = true;
    loop {
        if *shutdown_rx.borrow() {
            break;
        }
        let server = match create_secure_named_pipe(GUI_PIPE_NAME, GUI_PIPE_SDDL, first) {
            Ok(s) => {
                first = false;
                s
            }
            Err(e) => {
                error!("GUI pipe create failed: {e}");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };

        tokio::select! {
            res = server.connect() => {
                if res.is_err() {
                    continue;
                }
            }
            _ = shutdown_rx.wait_for(|&v| v) => break,
        }

        let cfg_c = config.clone();
        let ui_tx_c = ui_tx.clone();
        let ls_c = live_state.clone();
        let mut rx_bcast = bcast_tx.subscribe();
        let bcast_c = bcast_tx.clone();

        tokio::spawn(async move {
            use std::os::windows::io::AsRawHandle;
            let raw_handle = server.as_raw_handle() as isize;
            let (read_half, mut write_half) = tokio::io::split(server);
            let mut reader = BufReader::new(read_half);
            let mut caller_admin: Option<bool> = None;

            let mut line = String::new();
            loop {
                line.clear();
                tokio::select! {
                    n = reader.read_line(&mut line) => {
                        match n {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {
                                let is_admin = *caller_admin.get_or_insert_with(|| {
                                    crate::ipc::is_pipe_client_admin(raw_handle)
                                });
                                if let Ok(cmd) = serde_json::from_str::<GuiToService>(line.trim()) {
                                    match cmd {
                                        GuiToService::GetStatus => {
                                            send_snapshot_to_gui(&mut write_half, &cfg_c, &ls_c, is_admin).await;
                                        }
                                        GuiToService::ConsentDecision { session_id, accepted, permissions } => {
                                            if accepted && !is_admin {
                                                send_admin_required_notice(&mut write_half).await;
                                            } else {
                                                let _ = ui_tx_c.send(UiToNet::ConsentDecision { session_id, accepted, permissions });
                                            }
                                        }
                                        GuiToService::TogglePauseControl(p) => {
                                            let _ = ui_tx_c.send(UiToNet::TogglePauseControl(p));
                                        }
                                        GuiToService::DisconnectSession => {
                                            let _ = ui_tx_c.send(UiToNet::DisconnectSession);
                                        }
                                        GuiToService::ReloadConfig => {
                                            if !is_admin {
                                                send_admin_required_notice(&mut write_half).await;
                                            } else {
                                                let fresh = load_or_create_config(StorageScope::MachineService);
                                                *cfg_c.lock().unwrap() = fresh;
                                                let _ = ui_tx_c.send(UiToNet::Reconnect);
                                            }
                                        }
                                        GuiToService::RotateKeyNow => {
                                            if !is_admin {
                                                send_admin_required_notice(&mut write_half).await;
                                            } else {
                                                let rotated = {
                                                    let mut g = cfg_c.lock().unwrap();
                                                    rotate_unattended_key(StorageScope::MachineService, &mut g).ok()
                                                };
                                                if let Some(new_key) = rotated {
                                                    let _ = bcast_c.send(ServiceToGui::KeyAutoRotated { new_key });
                                                }
                                            }
                                        }
                                        GuiToService::UpdateUnattendedStatus(enabled) => {
                                            if !is_admin {
                                                send_admin_required_notice(&mut write_half).await;
                                            } else {
                                                {
                                                    let mut g = cfg_c.lock().unwrap();
                                                    g.unattended.enabled = enabled;
                                                    let need = enabled && g.unattended.key_hash.is_none();
                                                    let _ = save_config(StorageScope::MachineService, &g);
                                                    if need {
                                                        if let Ok(k) = rotate_unattended_key(StorageScope::MachineService, &mut g) {
                                                            let _ = bcast_c.send(ServiceToGui::KeyAutoRotated { new_key: k });
                                                        }
                                                    }
                                                }
                                                let _ = ui_tx_c.send(UiToNet::UpdateUnattendedStatus(enabled));
                                            }
                                        }
                                        GuiToService::UpdateServerUrl(url) => {
                                            if !is_admin {
                                                send_admin_required_notice(&mut write_half).await;
                                            } else {
                                                {
                                                    let mut g = cfg_c.lock().unwrap();
                                                    g.server_url = url.trim().to_string();
                                                    let _ = save_config(StorageScope::MachineService, &g);
                                                }
                                                send_snapshot_to_gui(&mut write_half, &cfg_c, &ls_c, is_admin).await;
                                                let _ = ui_tx_c.send(UiToNet::Reconnect);
                                            }
                                        }
                                        GuiToService::UpdateSchedule(schedule) => {
                                            if !is_admin {
                                                send_admin_required_notice(&mut write_half).await;
                                            } else {
                                                {
                                                    let mut g = cfg_c.lock().unwrap();
                                                    let now = chrono::Utc::now();
                                                    g.unattended.next_rotation_at =
                                                        nuvi_proto::rotation::compute_next_rotation_utc(&schedule, now);
                                                    g.unattended.schedule = schedule;
                                                    let _ = save_config(StorageScope::MachineService, &g);
                                                }
                                                send_snapshot_to_gui(&mut write_half, &cfg_c, &ls_c, is_admin).await;
                                            }
                                        }
                                        GuiToService::UpdateRotateAfterSession(rot_after) => {
                                            if !is_admin {
                                                send_admin_required_notice(&mut write_half).await;
                                            } else {
                                                {
                                                    let mut g = cfg_c.lock().unwrap();
                                                    g.unattended.rotate_after_session = rot_after;
                                                    let _ = save_config(StorageScope::MachineService, &g);
                                                }
                                                send_snapshot_to_gui(&mut write_half, &cfg_c, &ls_c, is_admin).await;
                                            }
                                        }
                                        GuiToService::SendChat(text) => {
                                            let _ = ui_tx_c.send(UiToNet::SendChat(text));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    ev = rx_bcast.recv() => {
                        if let Ok(msg) = ev {
                            let is_admin = caller_admin.unwrap_or(false);
                            let out_msg = match msg {
                                ServiceToGui::KeyAutoRotated { .. } if !is_admin => {
                                    ServiceToGui::Notice(
                                        "Unattended key rotated (run as Administrator to view)."
                                            .to_string(),
                                    )
                                }
                                other => other,
                            };
                            if let Ok(mut out) = serde_json::to_string(&out_msg) {
                                out.push('\n');
                                if write_half.write_all(out.as_bytes()).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        });
    }
}

#[cfg(windows)]
async fn send_admin_required_notice(
    w: &mut tokio::io::WriteHalf<tokio::net::windows::named_pipe::NamedPipeServer>,
) {
    let notice = ServiceToGui::Notice(
        "Administrator privileges required for this Windows Service action. Right-click nuvi-client.exe and choose 'Run as administrator'."
            .to_string(),
    );
    if let Ok(mut line) = serde_json::to_string(&notice) {
        line.push('\n');
        let _ = w.write_all(line.as_bytes()).await;
    }
}

#[cfg(windows)]
async fn send_snapshot_to_gui(
    w: &mut tokio::io::WriteHalf<tokio::net::windows::named_pipe::NamedPipeServer>,
    cfg_c: &Arc<Mutex<ClientConfig>>,
    ls_c: &Arc<RwLock<ServiceLiveState>>,
    is_admin: bool,
) {
    let (device_id, server_url, unattended) = {
        let cfg_snap = cfg_c.lock().unwrap();
        let dev_id = nuvi_proto::crypto::IdentityKeypair::from_bytes(&cfg_snap.identity_secret)
            .device_id();
        (dev_id, cfg_snap.server_url.clone(), cfg_snap.unattended.clone())
    };
    let key_plain = if is_admin {
        load_dpapi_key(StorageScope::MachineService)
    } else {
        None
    };
    let ls = ls_c.read().await;
    let snap = ServiceToGui::Snapshot(ServiceSnapshot {
        online: ls.online,
        status: if ls.status.is_empty() {
            "Connecting...".into()
        } else {
            ls.status.clone()
        },
        device_id,
        server_url,
        unattended,
        is_admin,
        unattended_key_plain: key_plain,
        pending_consent: ls.pending_consent.clone(),
        active_session: ls.active_session.clone(),
        recent_chat: load_chat_history(StorageScope::MachineService),
    });
    if let Ok(mut line) = serde_json::to_string(&snap) {
        line.push('\n');
        let _ = w.write_all(line.as_bytes()).await;
    }
}

#[cfg(windows)]
async fn run_helper_pipe_server(bridge: HelperBridge, shutdown_rx: &mut watch::Receiver<bool>) {
    use crate::ipc::{create_secure_named_pipe, HELPER_PIPE_SDDL};

    let mut first = true;
    loop {
        if *shutdown_rx.borrow() {
            break;
        }
        let server = match create_secure_named_pipe(HELPER_PIPE_NAME, HELPER_PIPE_SDDL, first) {
            Ok(s) => {
                first = false;
                s
            }
            Err(e) => {
                error!("Helper pipe create failed: {e}");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };

        tokio::select! {
            res = server.connect() => {
                if res.is_err() {
                    continue;
                }
            }
            _ = shutdown_rx.wait_for(|&v| v) => break,
        }

        let (mut r_half, mut w_half) = tokio::io::split(server);
        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<HelperCmd>();
        *bridge.cmd_tx.write().await = Some(cmd_tx.clone());
        let _ = cmd_tx.send(HelperCmd::EnumerateMonitors);

        let writer_task = tokio::spawn(async move {
            while let Some(cmd) = cmd_rx.recv().await {
                if write_bincode_frame(&mut w_half, &cmd).await.is_err() {
                    break;
                }
            }
        });

        while let Ok(ev) = read_bincode_frame::<_, HelperEvent>(&mut r_half).await {
            match ev {
                HelperEvent::Monitors(m) => {
                    *bridge.monitors.write().await = m;
                }
                HelperEvent::Frame(vf) => {
                    let _ = bridge.frame_tx.try_send(vf);
                }
                HelperEvent::CursorShape(shape) => {
                    let _ = bridge.cursor_tx.try_send(shape);
                }
            }
        }

        *bridge.cmd_tx.write().await = None;
        writer_task.abort();
    }
}

#[cfg(windows)]
async fn run_session_helper_supervisor(shutdown_rx: &mut watch::Receiver<bool>) {
    use windows::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId;

    let mut last_session = u32::MAX;
    let mut child_handle: Option<isize> = None;

    loop {
        if *shutdown_rx.borrow() {
            terminate_process_raw(child_handle);
            break;
        }

        let active_session = unsafe { WTSGetActiveConsoleSessionId() };
        let alive = is_process_alive(child_handle);

        if active_session != 0xFFFFFFFF && (active_session != last_session || !alive) {
            terminate_process_raw(child_handle);
            child_handle = None;
            match spawn_helper_in_session(active_session) {
                Ok(h) => {
                    info!("Spawned session helper in console session {active_session}");
                    child_handle = Some(h);
                    last_session = active_session;
                }
                Err(e) => {
                    warn!("Failed to spawn session helper in session {active_session}: {e}");
                }
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(2)) => {}
            _ = shutdown_rx.wait_for(|&v| v) => {
                terminate_process_raw(child_handle);
                break;
            }
        }
    }
}

#[cfg(windows)]
fn is_process_alive(handle_opt: Option<isize>) -> bool {
    use windows::Win32::{
        Foundation::{CloseHandle, HANDLE, STILL_ACTIVE},
        System::Threading::GetExitCodeProcess,
    };
    let Some(raw) = handle_opt else {
        return false;
    };
    let h = HANDLE(raw as *mut _);
    let mut code = 0u32;
    unsafe {
        if GetExitCodeProcess(h, &mut code).is_ok() && code == STILL_ACTIVE.0 as u32 {
            return true;
        }
        let _ = CloseHandle(h);
    }
    false
}

#[cfg(windows)]
fn terminate_process_raw(handle_opt: Option<isize>) {
    use windows::Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::Threading::TerminateProcess,
    };
    if let Some(raw) = handle_opt {
        let h = HANDLE(raw as *mut _);
        unsafe {
            let _ = TerminateProcess(h, 0);
            let _ = CloseHandle(h);
        }
    }
}

#[cfg(windows)]
fn spawn_helper_in_session(session_id: u32) -> Result<isize> {
    use windows::{
        core::PWSTR,
        Win32::{
            Foundation::{CloseHandle, HANDLE},
            Security::{
                DuplicateTokenEx, SecurityIdentification, SetTokenInformation, TokenPrimary,
                TokenSessionId, TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_QUERY,
            },
            System::Threading::{
                CreateProcessAsUserW, GetCurrentProcess, OpenProcessToken, PROCESS_INFORMATION,
                STARTF_USESHOWWINDOW, STARTUPINFOW,
            },
            UI::WindowsAndMessaging::SW_HIDE,
        },
    };

    let exe = std::env::current_exe()?;
    let cmd = format!("\"{}\" --session-helper", exe.display());
    let mut cmd_w: Vec<u16> = cmd.encode_utf16().chain(Some(0)).collect();
    let mut desktop_w: Vec<u16> = "winsta0\\default".encode_utf16().chain(Some(0)).collect();

    unsafe {
        let mut proc_token = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &mut proc_token,
        )
        .map_err(|e| anyhow!("OpenProcessToken failed: {e}"))?;

        let mut dup_token = HANDLE::default();
        let dup_res = DuplicateTokenEx(
            proc_token,
            TOKEN_ALL_ACCESS,
            None,
            SecurityIdentification,
            TokenPrimary,
            &mut dup_token,
        );
        let _ = CloseHandle(proc_token);
        dup_res.map_err(|e| anyhow!("DuplicateTokenEx failed: {e}"))?;

        let sid_res = SetTokenInformation(
            dup_token,
            TokenSessionId,
            &session_id as *const u32 as *const _,
            std::mem::size_of::<u32>() as u32,
        );
        if let Err(e) = sid_res {
            let _ = CloseHandle(dup_token);
            return Err(anyhow!("SetTokenInformation(TokenSessionId) failed: {e}"));
        }

        let mut si = STARTUPINFOW::default();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        si.lpDesktop = PWSTR(desktop_w.as_mut_ptr());
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE.0 as u16;

        let mut pi = PROCESS_INFORMATION::default();
        let create_res = CreateProcessAsUserW(
            dup_token,
            None,
            PWSTR(cmd_w.as_mut_ptr()),
            None,
            None,
            false,
            windows::Win32::System::Threading::CREATE_NO_WINDOW,
            None,
            None,
            &si,
            &mut pi,
        );
        let _ = CloseHandle(dup_token);
        create_res.map_err(|e| anyhow!("CreateProcessAsUserW failed: {e}"))?;
        let _ = CloseHandle(pi.hThread);
        Ok(pi.hProcess.0 as isize)
    }
}

// ============================================================================
// Session Helper Process (--session-helper)
// ============================================================================

#[cfg(windows)]
pub async fn run_session_helper() -> Result<()> {
    use tokio::net::windows::named_pipe::ClientOptions;

    let pipe = loop {
        match ClientOptions::new().open(HELPER_PIPE_NAME) {
            Ok(p) => break p,
            Err(_) => tokio::time::sleep(Duration::from_millis(300)).await,
        }
    };

    let (mut r_half, mut w_half) = tokio::io::split(pipe);
    let (ev_tx, mut ev_rx) = mpsc::channel::<HelperEvent>(8);

    let writer = tokio::spawn(async move {
        while let Some(ev) = ev_rx.recv().await {
            if write_bincode_frame(&mut w_half, &ev).await.is_err() {
                break;
            }
        }
    });

    let mut capturer = ScreenCapturer::new();
    let mut injector = InputInjector::default();
    let overlay = OverlayHandle::spawn();
    let mut monitors = enumerate_monitors();
    let mut capturing = false;
    let mut active_monitor: u8 = 0;
    let mut quality = QualityPreset::Auto;
    let mut last_cursor = RemoteCursorShape::Default;

    let mut tick = tokio::time::interval(Duration::from_millis(50));
    let mut cursor_tick = tokio::time::interval(Duration::from_millis(150));

    loop {
        tokio::select! {
            _ = tick.tick(), if capturing => {
                if let Some(mon) = monitors.iter().find(|m| m.index == active_monitor).or_else(|| monitors.first()).cloned() {
                    if let Ok(Some(vf)) = tokio::task::block_in_place(|| capturer.capture_frame(&mon, quality)) {
                        let _ = ev_tx.try_send(HelperEvent::Frame(vf));
                    }
                }
            }
            _ = cursor_tick.tick(), if capturing => {
                let shape = query_cursor_shape();
                if shape != last_cursor {
                    last_cursor = shape;
                    let _ = ev_tx.try_send(HelperEvent::CursorShape(shape));
                }
            }
            cmd_res = read_bincode_frame::<_, HelperCmd>(&mut r_half) => {
                let Ok(cmd) = cmd_res else {
                    break;
                };
                match cmd {
                    HelperCmd::EnumerateMonitors => {
                        monitors = enumerate_monitors();
                        let _ = ev_tx.send(HelperEvent::Monitors(monitors.clone())).await;
                    }
                    HelperCmd::Configure { monitor_index, quality: q } => {
                        active_monitor = monitor_index;
                        quality = q;
                    }
                    HelperCmd::StartCapture => {
                        capturer.reset();
                        monitors = enumerate_monitors();
                        let _ = ev_tx.send(HelperEvent::Monitors(monitors.clone())).await;
                        capturing = true;
                    }
                    HelperCmd::StopCapture => {
                        capturing = false;
                        injector.release_all_keys();
                        overlay.clear();
                    }
                    HelperCmd::Mouse { monitor_index, kind } => {
                        if let Some(mon) = monitors.iter().find(|m| m.index == monitor_index).or_else(|| monitors.first()) {
                            injector.apply_mouse(mon, kind);
                        }
                    }
                    HelperCmd::Key(k) => {
                        injector.apply_key(k);
                    }
                    HelperCmd::ReleaseAllKeys => {
                        injector.release_all_keys();
                    }
                    HelperCmd::Annotation { monitor_index, kind } => {
                        if let Some(mon) = monitors.iter().find(|m| m.index == monitor_index).or_else(|| monitors.first()).cloned() {
                            overlay.apply(mon, kind);
                        }
                    }
                    HelperCmd::ClearOverlay => {
                        overlay.clear();
                    }
                    HelperCmd::Shutdown => break,
                }
            }
        }
    }

    overlay.clear();

    injector.release_all_keys();
    drop(ev_tx);
    let _ = writer.await;
    Ok(())
}

#[cfg(not(windows))]
pub async fn run_session_helper() -> Result<()> {
    Err(anyhow!("Windows-only"))
}
