use std::collections::HashSet;

use nuvi_proto::protocol::{KeyInput, MonitorInfo, MouseButton, MouseEventKind};

#[derive(Default)]
pub struct InputInjector {
    held_keys: HashSet<(u16, bool)>,
}

impl InputInjector {
    pub fn apply_mouse(&self, monitor: &MonitorInfo, kind: MouseEventKind) {
        #[cfg(windows)]
        {
            crate::capture::switch_to_input_desktop();
            windows_impl::send_mouse(monitor, kind);
        }
        #[cfg(not(windows))]
        let _ = (monitor, kind);
    }

    pub fn apply_key(&mut self, input: KeyInput) {
        if input.scancode != 0 {
            if input.pressed {
                self.held_keys.insert((input.scancode, input.extended));
            } else {
                self.held_keys.remove(&(input.scancode, input.extended));
            }
        }
        #[cfg(windows)]
        {
            crate::capture::switch_to_input_desktop();
            windows_impl::send_key(input);
        }
    }

    pub fn release_all_keys(&mut self) {
        #[cfg(windows)]
        crate::capture::switch_to_input_desktop();
        let keys: Vec<(u16, bool)> = self.held_keys.drain().collect();
        for (scancode, extended) in keys {
            #[cfg(windows)]
            windows_impl::send_key(KeyInput {
                scancode,
                extended,
                pressed: false,
                unicode: None,
            });
            #[cfg(not(windows))]
            let _ = (scancode, extended);
        }
    }
}

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use windows::Win32::UI::{
        Input::KeyboardAndMouse::{
            SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYBD_EVENT_FLAGS,
            KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, KEYEVENTF_UNICODE,
            MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP,
            MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE,
            MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_VIRTUALDESK,
            MOUSEEVENTF_WHEEL, MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, MOUSEINPUT,
        },
        WindowsAndMessaging::{
            GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN,
            SM_YVIRTUALSCREEN,
        },
    };

    const XBUTTON1_DATA: u32 = 0x0001;
    const XBUTTON2_DATA: u32 = 0x0002;

    pub fn send_mouse(monitor: &MonitorInfo, kind: MouseEventKind) {
        unsafe {
            let mut mi = MOUSEINPUT::default();
            match kind {
                MouseEventKind::Move { nx, ny } => {
                    let vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
                    let vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
                    let vw = GetSystemMetrics(SM_CXVIRTUALSCREEN).max(1);
                    let vh = GetSystemMetrics(SM_CYVIRTUALSCREEN).max(1);

                    let px = monitor.left as f64 + nx.clamp(0.0, 1.0) as f64 * monitor.width as f64;
                    let py = monitor.top as f64 + ny.clamp(0.0, 1.0) as f64 * monitor.height as f64;

                    let abs_x = (((px - vx as f64) * 65535.0) / (vw as f64 - 1.0).max(1.0))
                        .round()
                        .clamp(0.0, 65535.0) as i32;
                    let abs_y = (((py - vy as f64) * 65535.0) / (vh as f64 - 1.0).max(1.0))
                        .round()
                        .clamp(0.0, 65535.0) as i32;

                    mi.dx = abs_x;
                    mi.dy = abs_y;
                    mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;
                }
                MouseEventKind::Button { button, pressed } => {
                    let (flag, data) = match (button, pressed) {
                        (MouseButton::Left, true) => (MOUSEEVENTF_LEFTDOWN, 0),
                        (MouseButton::Left, false) => (MOUSEEVENTF_LEFTUP, 0),
                        (MouseButton::Right, true) => (MOUSEEVENTF_RIGHTDOWN, 0),
                        (MouseButton::Right, false) => (MOUSEEVENTF_RIGHTUP, 0),
                        (MouseButton::Middle, true) => (MOUSEEVENTF_MIDDLEDOWN, 0),
                        (MouseButton::Middle, false) => (MOUSEEVENTF_MIDDLEUP, 0),
                        (MouseButton::X1, true) => (MOUSEEVENTF_XDOWN, XBUTTON1_DATA),
                        (MouseButton::X1, false) => (MOUSEEVENTF_XUP, XBUTTON1_DATA),
                        (MouseButton::X2, true) => (MOUSEEVENTF_XDOWN, XBUTTON2_DATA),
                        (MouseButton::X2, false) => (MOUSEEVENTF_XUP, XBUTTON2_DATA),
                    };
                    mi.dwFlags = flag;
                    mi.mouseData = data;
                }
                MouseEventKind::Wheel { dx, dy } => {
                    if dy != 0 {
                        mi.dwFlags = MOUSEEVENTF_WHEEL;
                        mi.mouseData = dy as i32 as u32;
                    } else if dx != 0 {
                        mi.dwFlags = MOUSEEVENTF_HWHEEL;
                        mi.mouseData = dx as i32 as u32;
                    } else {
                        return;
                    }
                }
            }

            let input = INPUT {
                r#type: INPUT_MOUSE,
                Anonymous: INPUT_0 { mi },
            };
            let _ = SendInput(&[input], std::mem::size_of::<INPUT>() as i32);
        }
    }

    pub fn send_key(k: KeyInput) {
        unsafe {
            if k.scancode != 0 {
                let mut flags = KEYEVENTF_SCANCODE;
                if k.extended {
                    flags |= KEYEVENTF_EXTENDEDKEY;
                }
                if !k.pressed {
                    flags |= KEYEVENTF_KEYUP;
                }
                let ki = KEYBDINPUT {
                    wScan: k.scancode,
                    dwFlags: flags,
                    ..Default::default()
                };
                let input = INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 { ki },
                };
                let _ = SendInput(&[input], std::mem::size_of::<INPUT>() as i32);
            } else if let Some(ch) = k.unicode {
                let mut buf = [0u16; 2];
                for unit in ch.encode_utf16(&mut buf) {
                    let down = INPUT {
                        r#type: INPUT_KEYBOARD,
                        Anonymous: INPUT_0 {
                            ki: KEYBDINPUT {
                                wScan: *unit,
                                dwFlags: KEYBD_EVENT_FLAGS(KEYEVENTF_UNICODE.0),
                                ..Default::default()
                            },
                        },
                    };
                    let up = INPUT {
                        r#type: INPUT_KEYBOARD,
                        Anonymous: INPUT_0 {
                            ki: KEYBDINPUT {
                                wScan: *unit,
                                dwFlags: KEYEVENTF_UNICODE | KEYEVENTF_KEYUP,
                                ..Default::default()
                            },
                        },
                    };
                    let _ = SendInput(&[down, up], std::mem::size_of::<INPUT>() as i32);
                }
            }
        }
    }
}
