use tokio::sync::mpsc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayEvent {
    ShowWindow,
    Quit,
}

#[derive(Clone)]
pub struct TrayHandle {
    #[cfg(windows)]
    hwnd_raw: isize,
}

impl TrayHandle {
    pub fn spawn(
        egui_ctx: egui::Context,
    ) -> (Self, mpsc::UnboundedReceiver<TrayEvent>) {
        #[cfg(windows)]
        {
            windows_impl::spawn_tray(egui_ctx)
        }
        #[cfg(not(windows))]
        {
            let _ = egui_ctx;
            let (_tx, rx) = mpsc::unbounded_channel();
            (Self {}, rx)
        }
    }

    pub fn notify(&self, title: &str, body: &str) {
        #[cfg(windows)]
        windows_impl::show_balloon(self.hwnd_raw, title, body);
        #[cfg(not(windows))]
        let _ = (title, body);
    }

    pub fn shutdown(&self) {
        #[cfg(windows)]
        windows_impl::destroy_tray(self.hwnd_raw);
    }
}

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use std::sync::OnceLock;
    use windows::{
        core::PCWSTR,
        Win32::{
            Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM},
            System::LibraryLoader::GetModuleHandleW,
            UI::{
                Shell::{
                    Shell_NotifyIconW, NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_INFO,
                    NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW,
                },
                WindowsAndMessaging::{
                    AppendMenuW, CreateIcon, CreatePopupMenu, CreateWindowExW, DefWindowProcW,
                    DestroyIcon, DestroyMenu, DispatchMessageW, GetCursorPos, GetMessageW,
                    PostMessageW, PostQuitMessage, RegisterClassW, SetForegroundWindow,
                    TrackPopupMenu, TranslateMessage, HICON, MF_STRING, MSG, TPM_BOTTOMALIGN,
                    TPM_LEFTALIGN, WINDOW_EX_STYLE, WM_APP, WM_CLOSE, WM_COMMAND, WM_DESTROY,
                    WM_LBUTTONDBLCLK, WM_RBUTTONUP, WNDCLASSW, WS_OVERLAPPEDWINDOW,
                },
            },
        },
    };

    const WM_TRAY: u32 = WM_APP + 1;
    const CMD_OPEN: usize = 1001;
    const CMD_QUIT: usize = 1002;
    const TRAY_UID: u32 = 1;

    static TRAY_SENDER: OnceLock<(mpsc::UnboundedSender<TrayEvent>, egui::Context)> =
        OnceLock::new();

    fn to_wide_fixed<const N: usize>(s: &str) -> [u16; N] {
        let mut buf = [0u16; N];
        for (i, u) in s.encode_utf16().take(N.saturating_sub(1)).enumerate() {
            buf[i] = u;
        }
        buf
    }

    unsafe fn create_nuvi_hicon() -> HICON {
        let w = 32i32;
        let h = 32i32;
        let and_mask = vec![0u8; (w * h / 8) as usize];
        let mut xor_mask = vec![0u8; (w * h * 4) as usize];

        if let Ok(img) = image::load_from_memory(crate::theme::NUVI_LOGO_PNG) {
            let rgba = img
                .resize_exact(w as u32, h as u32, image::imageops::FilterType::Lanczos3)
                .to_rgba8();
            for (i, px) in rgba.pixels().enumerate() {
                let idx = i * 4;
                // BGRA format for CreateIcon XOR bitmap
                xor_mask[idx] = px[2];
                xor_mask[idx + 1] = px[1];
                xor_mask[idx + 2] = px[0];
                xor_mask[idx + 3] = px[3];
            }
        }

        CreateIcon(None, w, h, 1, 32, and_mask.as_ptr(), xor_mask.as_ptr()).unwrap_or_default()
    }

    unsafe extern "system" fn wnd_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match msg {
            WM_TRAY => {
                let ev = lparam.0 as u32;
                if ev == WM_LBUTTONDBLCLK {
                    if let Some((tx, ctx)) = TRAY_SENDER.get() {
                        let _ = tx.send(TrayEvent::ShowWindow);
                        ctx.request_repaint();
                    }
                } else if ev == WM_RBUTTONUP {
                    let mut pt = POINT::default();
                    let _ = GetCursorPos(&mut pt);
                    if let Ok(menu) = CreatePopupMenu() {
                        let open_w: Vec<u16> =
                            "Open NUVI Remote".encode_utf16().chain(Some(0)).collect();
                        let quit_w: Vec<u16> = "Quit".encode_utf16().chain(Some(0)).collect();
                        let _ = AppendMenuW(menu, MF_STRING, CMD_OPEN, PCWSTR(open_w.as_ptr()));
                        let _ = AppendMenuW(menu, MF_STRING, CMD_QUIT, PCWSTR(quit_w.as_ptr()));
                        let _ = SetForegroundWindow(hwnd);
                        let _ = TrackPopupMenu(
                            menu,
                            TPM_LEFTALIGN | TPM_BOTTOMALIGN,
                            pt.x,
                            pt.y,
                            0,
                            hwnd,
                            None,
                        );
                        let _ = DestroyMenu(menu);
                    }
                }
                LRESULT(0)
            }
            WM_COMMAND => {
                let id = wparam.0 & 0xFFFF;
                if let Some((tx, ctx)) = TRAY_SENDER.get() {
                    if id == CMD_OPEN {
                        let _ = tx.send(TrayEvent::ShowWindow);
                        ctx.request_repaint();
                    } else if id == CMD_QUIT {
                        let _ = tx.send(TrayEvent::Quit);
                        ctx.request_repaint();
                    }
                }
                LRESULT(0)
            }
            WM_CLOSE | WM_DESTROY => {
                PostQuitMessage(0);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }

    pub fn spawn_tray(egui_ctx: egui::Context) -> (TrayHandle, mpsc::UnboundedReceiver<TrayEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let _ = TRAY_SENDER.set((tx, egui_ctx));

        let (hwnd_tx, hwnd_rx) = std::sync::mpsc::channel::<isize>();

        std::thread::spawn(move || unsafe {
            let hinst = GetModuleHandleW(None).unwrap_or_default();
            let cls_w: Vec<u16> = "NuviRemoteTrayWnd".encode_utf16().chain(Some(0)).collect();
            let wc = WNDCLASSW {
                lpfnWndProc: Some(wnd_proc),
                hInstance: hinst.into(),
                lpszClassName: PCWSTR(cls_w.as_ptr()),
                ..Default::default()
            };
            let _ = RegisterClassW(&wc);

            let hwnd = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                PCWSTR(cls_w.as_ptr()),
                PCWSTR(cls_w.as_ptr()),
                WS_OVERLAPPEDWINDOW,
                0,
                0,
                0,
                0,
                None,
                None,
                hinst,
                None,
            )
            .unwrap_or_default();

            let icon = create_nuvi_hicon();
            let mut nid = NOTIFYICONDATAW {
                cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
                hWnd: hwnd,
                uID: TRAY_UID,
                uFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP,
                uCallbackMessage: WM_TRAY,
                hIcon: icon,
                szTip: to_wide_fixed::<128>("NUVI Remote — Client"),
                ..Default::default()
            };
            let _ = Shell_NotifyIconW(NIM_ADD, &nid);
            let _ = hwnd_tx.send(hwnd.0 as isize);

            let mut msg = MSG::default();
            while GetMessageW(&mut msg, None, 0, 0).as_bool() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }

            nid.uFlags = windows::Win32::UI::Shell::NOTIFY_ICON_DATA_FLAGS(0);
            let _ = Shell_NotifyIconW(NIM_DELETE, &nid);
            if !icon.0.is_null() {
                let _ = DestroyIcon(icon);
            }
        });

        let hwnd_raw = hwnd_rx.recv().unwrap_or(0);
        (TrayHandle { hwnd_raw }, rx)
    }

    pub fn show_balloon(hwnd_raw: isize, title: &str, body: &str) {
        if hwnd_raw == 0 {
            return;
        }
        unsafe {
            let nid = NOTIFYICONDATAW {
                cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
                hWnd: HWND(hwnd_raw as *mut _),
                uID: TRAY_UID,
                uFlags: NIF_INFO,
                szInfoTitle: to_wide_fixed::<64>(title),
                szInfo: to_wide_fixed::<256>(body),
                dwInfoFlags: NIIF_INFO,
                ..Default::default()
            };
            let _ = Shell_NotifyIconW(NIM_MODIFY, &nid);
        }
    }

    pub fn destroy_tray(hwnd_raw: isize) {
        if hwnd_raw != 0 {
            unsafe {
                let _ = PostMessageW(HWND(hwnd_raw as *mut _), WM_CLOSE, WPARAM(0), LPARAM(0));
            }
        }
    }
}
