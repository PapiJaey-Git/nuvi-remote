use nuvi_proto::protocol::{AnnotationKind, MonitorInfo};

#[derive(Clone)]
pub struct OverlayHandle {
    #[cfg(windows)]
    tx: std::sync::mpsc::Sender<OverlayMsg>,
}

#[cfg(windows)]
enum OverlayMsg {
    Update {
        monitor: MonitorInfo,
        kind: AnnotationKind,
    },
    Clear,
}

impl OverlayHandle {
    pub fn spawn() -> Self {
        #[cfg(windows)]
        {
            windows_impl::spawn_overlay()
        }
        #[cfg(not(windows))]
        {
            Self {}
        }
    }

    pub fn apply(&self, monitor: MonitorInfo, kind: AnnotationKind) {
        #[cfg(windows)]
        let _ = self.tx.send(OverlayMsg::Update { monitor, kind });
        #[cfg(not(windows))]
        let _ = (monitor, kind);
    }

    pub fn clear(&self) {
        #[cfg(windows)]
        let _ = self.tx.send(OverlayMsg::Clear);
    }
}

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use std::{
        sync::{Arc, Mutex},
        time::Instant,
    };
    use windows::{
        core::PCWSTR,
        Win32::{
            Foundation::{COLORREF, HWND, LPARAM, LRESULT, RECT, WPARAM},
            Graphics::Gdi::{
                BeginPaint, CreatePen, CreateSolidBrush, DeleteObject, Ellipse, EndPaint, FillRect,
                InvalidateRect, LineTo, MoveToEx, SelectObject, PAINTSTRUCT, PS_SOLID,
            },
            System::LibraryLoader::GetModuleHandleW,
            UI::WindowsAndMessaging::{
                CreateWindowExW, DefWindowProcW, DispatchMessageW, PeekMessageW, RegisterClassW,
                SetLayeredWindowAttributes, SetWindowPos, ShowWindow, HWND_TOPMOST, LWA_COLORKEY,
                MSG, PM_REMOVE, SWP_NOACTIVATE, SW_HIDE, SW_SHOWNOACTIVATE, WNDCLASSW,
                WS_EX_LAYERED, WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_EX_TRANSPARENT, WS_POPUP,
            },
        },
    };

    const KEY_COLOR: u32 = 0x00030201; // BGR transparent key

    #[derive(Default)]
    struct OverlayState {
        monitor: Option<MonitorInfo>,
        strokes: Vec<(f32, f32, f32, f32)>,
        laser: Option<(f32, f32, Instant)>,
    }

    static OVERLAY_STATE: std::sync::OnceLock<Arc<Mutex<OverlayState>>> = std::sync::OnceLock::new();

    unsafe extern "system" fn wnd_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match msg {
            windows::Win32::UI::WindowsAndMessaging::WM_PAINT => {
                let mut ps = PAINTSTRUCT::default();
                let hdc = BeginPaint(hwnd, &mut ps);

                let bg_brush = CreateSolidBrush(COLORREF(KEY_COLOR));
                FillRect(hdc, &ps.rcPaint, bg_brush);
                let _ = DeleteObject(bg_brush);

                if let Some(st_arc) = OVERLAY_STATE.get() {
                    let st = st_arc.lock().unwrap();
                    let w = (ps.rcPaint.right - ps.rcPaint.left).max(1) as f32;
                    let h = (ps.rcPaint.bottom - ps.rcPaint.top).max(1) as f32;

                    // Coral #FF6B3D in COLORREF (0x00BBGGRR) = 0x003D6BFF
                    let pen = CreatePen(PS_SOLID, 4, COLORREF(0x003D6BFF));
                    let old_pen = SelectObject(hdc, pen);

                    for &(x1, y1, x2, y2) in &st.strokes {
                        let _ = MoveToEx(hdc, (x1 * w) as i32, (y1 * h) as i32, None);
                        let _ = LineTo(hdc, (x2 * w) as i32, (y2 * h) as i32);
                    }

                    if let Some((lx, ly, at)) = st.laser {
                        if at.elapsed().as_millis() < 1500 {
                            let brush = CreateSolidBrush(COLORREF(0x003D6BFF));
                            let old_brush = SelectObject(hdc, brush);
                            let cx = (lx * w) as i32;
                            let cy = (ly * h) as i32;
                            let _ = Ellipse(hdc, cx - 10, cy - 10, cx + 10, cy + 10);
                            SelectObject(hdc, old_brush);
                            let _ = DeleteObject(brush);
                        }
                    }

                    SelectObject(hdc, old_pen);
                    let _ = DeleteObject(pen);
                }

                let _ = EndPaint(hwnd, &ps);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }

    pub fn spawn_overlay() -> OverlayHandle {
        let (tx, rx) = std::sync::mpsc::channel::<OverlayMsg>();
        let state = OVERLAY_STATE
            .get_or_init(|| Arc::new(Mutex::new(OverlayState::default())))
            .clone();

        std::thread::spawn(move || unsafe {
            let hinst = GetModuleHandleW(None).unwrap_or_default();
            let cls_w: Vec<u16> = "NuviRemoteOverlayWnd".encode_utf16().chain(Some(0)).collect();
            let wc = WNDCLASSW {
                lpfnWndProc: Some(wnd_proc),
                hInstance: hinst.into(),
                lpszClassName: PCWSTR(cls_w.as_ptr()),
                ..Default::default()
            };
            let _ = RegisterClassW(&wc);

            let hwnd = CreateWindowExW(
                WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
                PCWSTR(cls_w.as_ptr()),
                PCWSTR(cls_w.as_ptr()),
                WS_POPUP,
                0,
                0,
                1,
                1,
                None,
                None,
                hinst,
                None,
            )
            .unwrap_or_default();

            let _ = SetLayeredWindowAttributes(hwnd, COLORREF(KEY_COLOR), 0, LWA_COLORKEY);
            let mut visible = false;

            loop {
                let mut msg = MSG::default();
                while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                    let _ = DispatchMessageW(&msg);
                }

                while let Ok(m) = rx.try_recv() {
                    let mut st = state.lock().unwrap();
                    match m {
                        OverlayMsg::Update { monitor, kind } => {
                            let mon_changed = st
                                .monitor
                                .as_ref()
                                .map(|c| c.index != monitor.index)
                                .unwrap_or(true);
                            if mon_changed || !visible {
                                let _ = SetWindowPos(
                                    hwnd,
                                    HWND_TOPMOST,
                                    monitor.left,
                                    monitor.top,
                                    monitor.width as i32,
                                    monitor.height as i32,
                                    SWP_NOACTIVATE,
                                );
                                let _ = ShowWindow(hwnd, SW_SHOWNOACTIVATE);
                                visible = true;
                            }
                            st.monitor = Some(monitor);
                            match kind {
                                AnnotationKind::Laser { nx, ny } => {
                                    st.laser = Some((nx, ny, Instant::now()));
                                }
                                AnnotationKind::Stroke { x1, y1, x2, y2 } => {
                                    st.strokes.push((x1, y1, x2, y2));
                                    if st.strokes.len() > 2000 {
                                        st.strokes.drain(0..500);
                                    }
                                }
                                AnnotationKind::Clear => {
                                    st.strokes.clear();
                                    st.laser = None;
                                }
                            }
                            let _ = InvalidateRect(hwnd, None::<*const RECT>, false);
                        }
                        OverlayMsg::Clear => {
                            st.strokes.clear();
                            st.laser = None;
                            if visible {
                                let _ = ShowWindow(hwnd, SW_HIDE);
                                visible = false;
                            }
                        }
                    }
                }

                if visible {
                    let expired = {
                        let mut st = state.lock().unwrap();
                        if let Some((_, _, at)) = st.laser {
                            if at.elapsed().as_millis() >= 1500 {
                                st.laser = None;
                                true
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    };
                    if expired {
                        let _ = InvalidateRect(hwnd, None::<*const RECT>, false);
                    }
                }

                std::thread::sleep(std::time::Duration::from_millis(25));
            }
        });

        OverlayHandle { tx }
    }
}
