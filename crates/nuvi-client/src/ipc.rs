use anyhow::{anyhow, Result};
use nuvi_proto::protocol::{
    AnnotationKind, ChatHistoryEntry, KeyInput, MonitorInfo, MouseEventKind, QualityPreset,
    RemoteCursorShape, SessionPermissions, VideoFrame,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

use crate::net::{ActiveSessionInfo, PendingConsent};

pub const GUI_PIPE_NAME: &str = r"\\.\pipe\NuviRemoteService";
pub const HELPER_PIPE_NAME: &str = r"\\.\pipe\NuviRemoteHelper";

/// SDDL allowing SYSTEM, Builtin Administrators, and Interactive Users read/write access.
/// Privileged commands and secrets are gated by `is_pipe_client_admin()` on the server.
pub const GUI_PIPE_SDDL: &str = "D:(A;;GRGW;;;SY)(A;;GRGW;;;BA)(A;;GRGW;;;IU)";
/// SDDL allowing SYSTEM only.
pub const HELPER_PIPE_SDDL: &str = "D:(A;;GRGW;;;SY)";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSnapshot {
    pub online: bool,
    pub status: String,
    pub device_id: String,
    pub server_url: String,
    pub unattended: nuvi_proto::rotation::UnattendedKeyState,
    #[serde(default)]
    pub is_admin: bool,
    pub unattended_key_plain: Option<String>,
    pub pending_consent: Option<PendingConsentSnapshot>,
    pub active_session: Option<ActiveSessionInfo>,
    #[serde(default)]
    pub recent_chat: Vec<ChatHistoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingConsentSnapshot {
    pub session_id: Uuid,
    pub tech_name: String,
    pub reason: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

impl From<&PendingConsent> for PendingConsentSnapshot {
    fn from(p: &PendingConsent) -> Self {
        Self {
            session_id: p.session_id,
            tech_name: p.tech_name.clone(),
            reason: p.reason.clone(),
            expires_at: p.expires_at,
        }
    }
}

impl From<PendingConsentSnapshot> for PendingConsent {
    fn from(p: PendingConsentSnapshot) -> Self {
        Self {
            session_id: p.session_id,
            tech_name: p.tech_name,
            reason: p.reason,
            expires_at: p.expires_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GuiToService {
    GetStatus,
    ConsentDecision {
        session_id: Uuid,
        accepted: bool,
        permissions: SessionPermissions,
    },
    TogglePauseControl(bool),
    DisconnectSession,
    ReloadConfig,
    RotateKeyNow,
    UpdateUnattendedStatus(bool),
    UpdateServerUrl(String),
    UpdateSchedule(nuvi_proto::rotation::RotationSchedule),
    UpdateRotateAfterSession(bool),
    SendChat(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceToGui {
    Snapshot(ServiceSnapshot),
    ConnectionState { online: bool, status: String },
    ConsentRequested(PendingConsentSnapshot),
    ConsentCleared,
    SessionStarted(ActiveSessionInfo),
    SessionEnded { reason: String },
    KeyAutoRotated { new_key: String },
    Notice(String),
    ChatMessage {
        sender: String,
        text: String,
        sent_at: String,
    },
    FileProgress {
        filename: String,
        received: u64,
        total: u64,
        done: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HelperCmd {
    Configure {
        monitor_index: u8,
        quality: QualityPreset,
    },
    StartCapture,
    StopCapture,
    Mouse {
        monitor_index: u8,
        kind: MouseEventKind,
    },
    Key(KeyInput),
    ReleaseAllKeys,
    EnumerateMonitors,
    Annotation {
        monitor_index: u8,
        kind: AnnotationKind,
    },
    ClearOverlay,
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HelperEvent {
    Monitors(Vec<MonitorInfo>),
    Frame(VideoFrame),
    CursorShape(RemoteCursorShape),
}

pub async fn write_bincode_frame<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    msg: &T,
) -> Result<()> {
    let payload = bincode::serialize(msg)?;
    let len = payload.len() as u32;
    writer.write_all(&len.to_le_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_bincode_frame<R: AsyncRead + Unpin, T: for<'de> Deserialize<'de>>(
    reader: &mut R,
) -> Result<T> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 64 * 1024 * 1024 {
        return Err(anyhow!("IPC frame too large: {len} bytes"));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    use bincode::Options;
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(64 * 1024 * 1024)
        .deserialize(&buf)?)
}

/// Checks whether the connected named-pipe client belongs to Builtin Administrators or LocalSystem.
/// Must only be called after at least one byte has been read from the pipe.
#[cfg(windows)]
pub fn is_pipe_client_admin(pipe_handle: isize) -> bool {
    use std::ffi::c_void;
    use windows::Win32::{
        Foundation::{BOOL, HANDLE},
        Security::{
            AllocateAndInitializeSid, CheckTokenMembership, FreeSid, RevertToSelf, PSID,
            SECURITY_NT_AUTHORITY,
        },
        System::Pipes::ImpersonateNamedPipeClient,
    };

    const SECURITY_BUILTIN_DOMAIN_RID: u32 = 0x0000_0020;
    const DOMAIN_ALIAS_RID_ADMINS: u32 = 0x0000_0220;
    const SECURITY_LOCAL_SYSTEM_RID: u32 = 0x0000_0012;

    unsafe {
        if ImpersonateNamedPipeClient(HANDLE(pipe_handle as *mut c_void)).is_err() {
            return false;
        }
        let mut is_admin = BOOL(0);
        let mut admin_sid = PSID::default();
        if AllocateAndInitializeSid(
            &SECURITY_NT_AUTHORITY,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0,
            0,
            0,
            0,
            0,
            0,
            &mut admin_sid,
        )
        .is_ok()
        {
            let _ = CheckTokenMembership(None, admin_sid, &mut is_admin);
            let _ = FreeSid(admin_sid);
        }

        let mut is_system = BOOL(0);
        if !is_admin.as_bool() {
            let mut sys_sid = PSID::default();
            if AllocateAndInitializeSid(
                &SECURITY_NT_AUTHORITY,
                1,
                SECURITY_LOCAL_SYSTEM_RID,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                &mut sys_sid,
            )
            .is_ok()
            {
                let _ = CheckTokenMembership(None, sys_sid, &mut is_system);
                let _ = FreeSid(sys_sid);
            }
        }
        let _ = RevertToSelf();
        is_admin.as_bool() || is_system.as_bool()
    }
}

#[cfg(windows)]
pub fn create_secure_named_pipe(
    pipe_name: &str,
    sddl: &str,
    first_instance: bool,
) -> Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use std::ffi::c_void;
    use tokio::net::windows::named_pipe::ServerOptions;
    use windows::{
        core::PCWSTR,
        Win32::{
            Foundation::{LocalFree, HLOCAL},
            Security::{
                Authorization::{
                    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
                },
                PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
            },
        },
    };

    let mut sddl_wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sd = PSECURITY_DESCRIPTOR::default();

    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_wide.as_mut_ptr()),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
        .map_err(|e| anyhow!("SDDL conversion failed: {e}"))?;

        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: false.into(),
        };

        let mut opts = ServerOptions::new();
        opts.first_pipe_instance(first_instance);
        let res = opts.create_with_security_attributes_raw(
            pipe_name,
            &mut sa as *mut SECURITY_ATTRIBUTES as *mut c_void,
        );
        let _ = LocalFree(HLOCAL(sd.0));
        res.map_err(|e| anyhow!("Named pipe creation failed for {pipe_name}: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bincode_frame_roundtrip_helper_cmd() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let cmd = HelperCmd::Configure {
            monitor_index: 1,
            quality: QualityPreset::Sharp,
        };
        write_bincode_frame(&mut a, &cmd).await.unwrap();
        let decoded: HelperCmd = read_bincode_frame(&mut b).await.unwrap();
        match decoded {
            HelperCmd::Configure {
                monitor_index,
                quality,
            } => {
                assert_eq!(monitor_index, 1);
                assert_eq!(quality, QualityPreset::Sharp);
            }
            _ => panic!("unexpected variant"),
        }
    }
}
