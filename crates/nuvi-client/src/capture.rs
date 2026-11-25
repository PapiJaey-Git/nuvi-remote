use anyhow::Result;
use nuvi_proto::protocol::{
    MonitorInfo, QualityPreset, RemoteCursorShape, VideoFrame, VideoTile,
};

const TILE_SIZE: usize = 64;

pub struct ScreenCapturer {
    prev_rgb: Vec<u8>,
    prev_w: u16,
    prev_h: u16,
    prev_monitor: u8,
    bgra_scratch: Vec<u8>,
    rgb_scratch: Vec<u8>,
    tile_scratch: Vec<u8>,
    #[cfg(windows)]
    dxgi: Option<DxgiOutputCapturer>,
}

impl ScreenCapturer {
    pub fn new() -> Self {
        Self {
            prev_rgb: Vec::new(),
            prev_w: 0,
            prev_h: 0,
            prev_monitor: u8::MAX,
            bgra_scratch: Vec::new(),
            rgb_scratch: Vec::new(),
            tile_scratch: Vec::with_capacity(TILE_SIZE * TILE_SIZE * 3),
            #[cfg(windows)]
            dxgi: None,
        }
    }

    pub fn reset(&mut self) {
        self.prev_rgb.clear();
        self.prev_w = 0;
        self.prev_h = 0;
        #[cfg(windows)]
        {
            self.dxgi = None;
        }
    }

    pub fn capture_frame(
        &mut self,
        monitor: &MonitorInfo,
        quality: QualityPreset,
    ) -> Result<Option<VideoFrame>> {
        let w = monitor.width as usize;
        let h = monitor.height as usize;
        if w == 0 || h == 0 {
            return Ok(None);
        }

        #[cfg(windows)]
        {
            let mut got_dxgi = false;
            if self.dxgi.as_ref().map(|d| d.monitor_index) != Some(monitor.index) {
                self.dxgi = DxgiOutputCapturer::new(monitor.index, w as u32, h as u32).ok();
            }
            if let Some(dxgi) = self.dxgi.as_mut() {
                match dxgi.capture_bgra(&mut self.bgra_scratch) {
                    Ok(true) => got_dxgi = true,
                    Ok(false) => return Ok(None), // No desktop change
                    Err(_) => {
                        self.dxgi = None; // Fall back to GDI BitBlt cleanly
                    }
                }
            }
            if !got_dxgi {
                capture_monitor_bgra(monitor, &mut self.bgra_scratch)?;
            }
        }
        #[cfg(not(windows))]
        capture_monitor_bgra(monitor, &mut self.bgra_scratch)?;

        let expected_rgb = w * h * 3;
        if self.rgb_scratch.len() != expected_rgb {
            self.rgb_scratch.resize(expected_rgb, 0);
        }
        for (i, px) in self.bgra_scratch.chunks_exact(4).enumerate() {
            let off = i * 3;
            self.rgb_scratch[off] = px[2]; // R
            self.rgb_scratch[off + 1] = px[1]; // G
            self.rgb_scratch[off + 2] = px[0]; // B
        }

        let w16 = w as u16;
        let h16 = h as u16;
        let full_frame = self.prev_w != w16
            || self.prev_h != h16
            || self.prev_monitor != monitor.index
            || self.prev_rgb.len() != expected_rgb;

        let mut tiles = Vec::new();
        let jpeg_q = quality.jpeg_quality();

        let mut ty = 0usize;
        while ty < h {
            let th = TILE_SIZE.min(h - ty);
            let mut tx = 0usize;
            while tx < w {
                let tw = TILE_SIZE.min(w - tx);

                let dirty = if full_frame {
                    true
                } else {
                    tile_changed(&self.rgb_scratch, &self.prev_rgb, w, tx, ty, tw, th)
                };

                if dirty {
                    self.tile_scratch.clear();
                    for row in 0..th {
                        let start = ((ty + row) * w + tx) * 3;
                        let end = start + tw * 3;
                        self.tile_scratch
                            .extend_from_slice(&self.rgb_scratch[start..end]);
                    }

                    let mut jpeg_data = Vec::new();
                    let encoder = jpeg_encoder::Encoder::new(&mut jpeg_data, jpeg_q);
                    encoder.encode(
                        &self.tile_scratch,
                        tw as u16,
                        th as u16,
                        jpeg_encoder::ColorType::Rgb,
                    )?;

                    tiles.push(VideoTile {
                        x: tx as u16,
                        y: ty as u16,
                        w: tw as u16,
                        h: th as u16,
                        jpeg_data,
                    });
                }

                tx += TILE_SIZE;
            }
            ty += TILE_SIZE;
        }

        self.prev_w = w16;
        self.prev_h = h16;
        self.prev_monitor = monitor.index;
        if self.prev_rgb.len() != expected_rgb {
            self.prev_rgb.resize(expected_rgb, 0);
        }
        self.prev_rgb.copy_from_slice(&self.rgb_scratch);

        if tiles.is_empty() {
            return Ok(None);
        }

        Ok(Some(VideoFrame {
            monitor_index: monitor.index,
            width: w16,
            height: h16,
            full_frame,
            tiles,
        }))
    }
}

fn tile_changed(
    curr: &[u8],
    prev: &[u8],
    stride_w: usize,
    tx: usize,
    ty: usize,
    tw: usize,
    th: usize,
) -> bool {
    for row in 0..th {
        let start = ((ty + row) * stride_w + tx) * 3;
        let end = start + tw * 3;
        if curr[start..end] != prev[start..end] {
            return true;
        }
    }
    false
}

#[cfg(windows)]
pub fn enumerate_monitors() -> Vec<MonitorInfo> {
    use windows::Win32::{
        Foundation::{BOOL, LPARAM, RECT},
        Graphics::Gdi::{
            EnumDisplayMonitors, GetMonitorInfoW, HDC, HMONITOR, MONITORINFOEXW,
        },
    };

    unsafe extern "system" fn enum_cb(
        hmon: HMONITOR,
        _hdc: HDC,
        _rect: *mut RECT,
        data: LPARAM,
    ) -> BOOL {
        let list = &mut *(data.0 as *mut Vec<MonitorInfo>);
        let mut info = MONITORINFOEXW::default();
        info.monitorInfo.cbSize = std::mem::size_of::<MONITORINFOEXW>() as u32;
        if GetMonitorInfoW(hmon, &mut info.monitorInfo as *mut _ as *mut _).as_bool() {
            let rc = info.monitorInfo.rcMonitor;
            let primary = (info.monitorInfo.dwFlags & 1) != 0; // MONITORINFOF_PRIMARY
            let idx = list.len() as u8;
            list.push(MonitorInfo {
                index: idx,
                name: format!("Display {}", idx + 1),
                left: rc.left,
                top: rc.top,
                width: (rc.right - rc.left).max(1) as u32,
                height: (rc.bottom - rc.top).max(1) as u32,
                primary,
            });
        }
        BOOL(1)
    }

    let mut monitors: Vec<MonitorInfo> = Vec::new();
    unsafe {
        let _ = EnumDisplayMonitors(
            None,
            None,
            Some(enum_cb),
            LPARAM(&mut monitors as *mut _ as isize),
        );
    }
    if monitors.is_empty() {
        monitors.push(MonitorInfo {
            index: 0,
            name: "Display 1".to_string(),
            left: 0,
            top: 0,
            width: 1920,
            height: 1080,
            primary: true,
        });
    }
    monitors
}

#[cfg(not(windows))]
pub fn enumerate_monitors() -> Vec<MonitorInfo> {
    vec![MonitorInfo {
        index: 0,
        name: "Display 1".to_string(),
        left: 0,
        top: 0,
        width: 1280,
        height: 720,
        primary: true,
    }]
}

/// Best-effort switch of the current thread to the active input desktop
/// (allows capturing UAC Secure Desktop and `Winlogon` lock screen when running as SYSTEM).
#[cfg(windows)]
pub fn switch_to_input_desktop() {
    use windows::Win32::System::StationsAndDesktops::{
        CloseDesktop, OpenInputDesktop, SetThreadDesktop, DESKTOP_ACCESS_FLAGS,
        DESKTOP_CONTROL_FLAGS,
    };

    unsafe {
        if let Ok(hdesk) = OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_ACCESS_FLAGS(0x01FF)) {
            let _ = SetThreadDesktop(hdesk);
            let _ = CloseDesktop(hdesk);
        }
    }
}

#[cfg(not(windows))]
pub fn switch_to_input_desktop() {}

#[cfg(windows)]
fn capture_monitor_bgra(monitor: &MonitorInfo, out: &mut Vec<u8>) -> Result<()> {
    switch_to_input_desktop();
    use anyhow::anyhow;
    use windows::Win32::Graphics::Gdi::{
        BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, GetDC,
        GetDIBits, ReleaseDC, SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS,
        SRCCOPY,
    };

    let w = monitor.width as i32;
    let h = monitor.height as i32;
    let needed = (w as usize) * (h as usize) * 4;
    if out.len() != needed {
        out.resize(needed, 0);
    }

    unsafe {
        let hdc_screen = GetDC(None);
        if hdc_screen.is_invalid() {
            return Err(anyhow!("GetDC failed"));
        }
        let hdc_mem = CreateCompatibleDC(hdc_screen);
        if hdc_mem.is_invalid() {
            let _ = ReleaseDC(None, hdc_screen);
            return Err(anyhow!("CreateCompatibleDC failed"));
        }
        let hbm = CreateCompatibleBitmap(hdc_screen, w, h);
        if hbm.is_invalid() {
            let _ = DeleteDC(hdc_mem);
            let _ = ReleaseDC(None, hdc_screen);
            return Err(anyhow!("CreateCompatibleBitmap failed"));
        }

        let old = SelectObject(hdc_mem, hbm);
        let blt_res = BitBlt(
            hdc_mem,
            0,
            0,
            w,
            h,
            hdc_screen,
            monitor.left,
            monitor.top,
            SRCCOPY,
        );

        let mut bmi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: w,
                biHeight: -h, // top-down
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                ..Default::default()
            },
            ..Default::default()
        };

        let lines = GetDIBits(
            hdc_mem,
            hbm,
            0,
            h as u32,
            Some(out.as_mut_ptr() as *mut _),
            &mut bmi,
            DIB_RGB_COLORS,
        );

        SelectObject(hdc_mem, old);
        let _ = DeleteObject(hbm);
        let _ = DeleteDC(hdc_mem);
        let _ = ReleaseDC(None, hdc_screen);

        blt_res?;
        if lines == 0 {
            return Err(anyhow!("GetDIBits returned 0 lines"));
        }
    }

    Ok(())
}

#[cfg(not(windows))]
fn capture_monitor_bgra(monitor: &MonitorInfo, out: &mut Vec<u8>) -> Result<()> {
    let needed = (monitor.width as usize) * (monitor.height as usize) * 4;
    out.resize(needed, 20);
    Ok(())
}

#[cfg(windows)]
pub fn query_cursor_shape() -> RemoteCursorShape {
    use windows::Win32::UI::WindowsAndMessaging::{
        GetCursorInfo, LoadCursorW, CURSORINFO, CURSOR_SHOWING, IDC_ARROW, IDC_CROSS, IDC_HAND,
        IDC_IBEAM, IDC_NO, IDC_SIZEALL, IDC_SIZENESW, IDC_SIZENS, IDC_SIZENWSE, IDC_SIZEWE,
        IDC_WAIT,
    };

    unsafe {
        let mut ci = CURSORINFO {
            cbSize: std::mem::size_of::<CURSORINFO>() as u32,
            ..Default::default()
        };
        if GetCursorInfo(&mut ci).is_err() || (ci.flags.0 & CURSOR_SHOWING.0) == 0 {
            return RemoteCursorShape::Default;
        }
        let h = ci.hCursor;
        let checks = [
            (IDC_IBEAM, RemoteCursorShape::Text),
            (IDC_HAND, RemoteCursorShape::Hand),
            (IDC_WAIT, RemoteCursorShape::Wait),
            (IDC_CROSS, RemoteCursorShape::Crosshair),
            (IDC_SIZENS, RemoteCursorShape::ResizeNS),
            (IDC_SIZEWE, RemoteCursorShape::ResizeEW),
            (IDC_SIZENWSE, RemoteCursorShape::ResizeNWSE),
            (IDC_SIZENESW, RemoteCursorShape::ResizeNESW),
            (IDC_SIZEALL, RemoteCursorShape::Move),
            (IDC_NO, RemoteCursorShape::NotAllowed),
            (IDC_ARROW, RemoteCursorShape::Default),
        ];
        for (id, shape) in checks {
            if let Ok(sys_h) = LoadCursorW(None, windows::core::PCWSTR(id.0 as _)) {
                if sys_h == h {
                    return shape;
                }
            }
        }
        RemoteCursorShape::Default
    }
}

#[cfg(not(windows))]
pub fn query_cursor_shape() -> RemoteCursorShape {
    RemoteCursorShape::Default
}

#[cfg(windows)]
struct DxgiOutputCapturer {
    monitor_index: u8,
    width: u32,
    height: u32,
    context: windows::Win32::Graphics::Direct3D11::ID3D11DeviceContext,
    duplication: windows::Win32::Graphics::Dxgi::IDXGIOutputDuplication,
    staging: windows::Win32::Graphics::Direct3D11::ID3D11Texture2D,
}

#[cfg(windows)]
impl DxgiOutputCapturer {
    fn new(monitor_index: u8, width: u32, height: u32) -> Result<Self> {
        use anyhow::anyhow;
        use windows::{
            core::Interface,
            Win32::Graphics::{
                Direct3D::D3D_DRIVER_TYPE_HARDWARE,
                Direct3D11::{
                    D3D11CreateDevice, ID3D11Texture2D, D3D11_CPU_ACCESS_READ,
                    D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC,
                    D3D11_USAGE_STAGING,
                },
                Dxgi::{
                    Common::{DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC},
                    IDXGIDevice, IDXGIOutput1,
                },
            },
        };

        switch_to_input_desktop();

        unsafe {
            let mut device = None;
            let mut context = None;
            D3D11CreateDevice(
                None,
                D3D_DRIVER_TYPE_HARDWARE,
                None,
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                None,
                D3D11_SDK_VERSION,
                Some(&mut device),
                None,
                Some(&mut context),
            )?;
            let device = device.ok_or_else(|| anyhow!("No D3D11 device"))?;
            let context = context.ok_or_else(|| anyhow!("No D3D11 context"))?;

            let dxgi_device: IDXGIDevice = device.cast()?;
            let adapter = dxgi_device.GetAdapter()?;
            let output = adapter.EnumOutputs(monitor_index as u32)?;
            let output1: IDXGIOutput1 = output.cast()?;
            let duplication = output1.DuplicateOutput(&device)?;

            let desc = D3D11_TEXTURE2D_DESC {
                Width: width,
                Height: height,
                MipLevels: 1,
                ArraySize: 1,
                Format: DXGI_FORMAT_B8G8R8A8_UNORM,
                SampleDesc: DXGI_SAMPLE_DESC {
                    Count: 1,
                    Quality: 0,
                },
                Usage: D3D11_USAGE_STAGING,
                BindFlags: 0,
                CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
                MiscFlags: 0,
            };
            let mut staging: Option<ID3D11Texture2D> = None;
            device.CreateTexture2D(&desc, None, Some(&mut staging))?;
            let staging = staging.ok_or_else(|| anyhow!("Failed to create staging texture"))?;

            Ok(Self {
                monitor_index,
                width,
                height,
                context,
                duplication,
                staging,
            })
        }
    }

    fn capture_bgra(&mut self, out: &mut Vec<u8>) -> Result<bool> {
        use anyhow::anyhow;
        use windows::{
            core::Interface,
            Win32::Graphics::{
                Direct3D11::{ID3D11Texture2D, D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_READ},
                Dxgi::{DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO},
            },
        };

        unsafe {
            let mut frame_info = DXGI_OUTDUPL_FRAME_INFO::default();
            let mut resource = None;
            match self.duplication.AcquireNextFrame(16, &mut frame_info, &mut resource) {
                Ok(()) => {}
                Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => return Ok(false),
                Err(e) => return Err(anyhow!("AcquireNextFrame failed: {e}")),
            }

            let res = (|| -> Result<bool> {
                let res = resource.ok_or_else(|| anyhow!("Empty DXGI resource"))?;
                let tex: ID3D11Texture2D = res.cast()?;
                self.context.CopyResource(&self.staging, &tex);

                let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
                self.context
                    .Map(&self.staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))?;

                let w = self.width as usize;
                let h = self.height as usize;
                let needed = w * h * 4;
                if out.len() != needed {
                    out.resize(needed, 0);
                }
                let src_base = mapped.pData as *const u8;
                let row_bytes = w * 4;
                let pitch = mapped.RowPitch as usize;
                for y in 0..h {
                    let src_row = std::slice::from_raw_parts(src_base.add(y * pitch), row_bytes);
                    let dst_row = &mut out[y * row_bytes..(y + 1) * row_bytes];
                    dst_row.copy_from_slice(src_row);
                }

                self.context.Unmap(&self.staging, 0);
                Ok(true)
            })();

            let _ = self.duplication.ReleaseFrame();
            res
        }
    }
}
