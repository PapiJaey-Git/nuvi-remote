use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use nuvi_proto::{
    crypto::{generate_unattended_key, hash_unattended_key, IdentityKeypair},
    protocol::{normalize_server_url, ChatHistoryEntry, DEFAULT_SERVER_URL},
    rotation::{compute_next_rotation_utc, UnattendedKeyState},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageScope {
    Portable,
    MachineService,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub identity_secret: [u8; 32],
    pub server_url: String,
    pub unattended: UnattendedKeyState,
}

impl Default for ClientConfig {
    fn default() -> Self {
        let kp = IdentityKeypair::generate();
        Self {
            identity_secret: kp.to_bytes(),
            server_url: DEFAULT_SERVER_URL.to_string(),
            unattended: UnattendedKeyState::default(),
        }
    }
}

pub fn data_dir(scope: StorageScope) -> PathBuf {
    match scope {
        StorageScope::Portable => {
            let base = std::env::var_os("APPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
            base.join("NUVI Remote").join("client")
        }
        StorageScope::MachineService => {
            let base = std::env::var_os("ProgramData")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
            base.join("NUVI Remote").join("client")
        }
    }
}

pub fn config_path(scope: StorageScope) -> PathBuf {
    data_dir(scope).join("config.json")
}

pub fn dpapi_path(scope: StorageScope) -> PathBuf {
    data_dir(scope).join("unattended.dpapi")
}

pub fn chat_history_path(scope: StorageScope) -> PathBuf {
    data_dir(scope).join("chat_history.json")
}

pub fn load_chat_history(scope: StorageScope) -> Vec<ChatHistoryEntry> {
    let path = chat_history_path(scope);
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    serde_json::from_str::<Vec<ChatHistoryEntry>>(&raw).unwrap_or_default()
}

pub fn append_chat_history(scope: StorageScope, entry: ChatHistoryEntry) {
    let dir = data_dir(scope);
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let mut list = load_chat_history(scope);
    list.push(entry);
    if list.len() > 200 {
        let drop_n = list.len() - 200;
        list.drain(0..drop_n);
    }
    if let Ok(raw) = serde_json::to_string_pretty(&list) {
        let _ = std::fs::write(chat_history_path(scope), raw);
    }
}

pub fn load_or_create_config(scope: StorageScope) -> ClientConfig {
    let path = config_path(scope);
    let mut cfg = if let Ok(raw) = std::fs::read_to_string(&path) {
        if let Ok(mut parsed) = serde_json::from_str::<ClientConfig>(&raw) {
            if parsed.server_url.trim().is_empty() {
                parsed.server_url = DEFAULT_SERVER_URL.to_string();
                let _ = save_config(scope, &parsed);
            }
            parsed
        } else {
            let fresh = ClientConfig::default();
            let _ = save_config(scope, &fresh);
            fresh
        }
    } else {
        let fresh = ClientConfig::default();
        let _ = save_config(scope, &fresh);
        fresh
    };
    if let Some(sidecar_txt) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("nuvi-server.txt")))
        .and_then(|p| std::fs::read_to_string(p).ok())
    {
        let trimmed = sidecar_txt.trim();
        if !trimmed.is_empty() {
            cfg.server_url = normalize_server_url(trimmed);
        }
    }
    if let Ok(env_url) = std::env::var("NUVI_SERVER_URL") {
        let trimmed = env_url.trim();
        if !trimmed.is_empty() {
            cfg.server_url = normalize_server_url(trimmed);
        }
    }
    cfg
}

pub fn load_config_readonly_or_default(scope: StorageScope) -> ClientConfig {
    let path = config_path(scope);
    if let Ok(raw) = std::fs::read_to_string(&path) {
        if let Ok(mut parsed) = serde_json::from_str::<ClientConfig>(&raw) {
            if parsed.server_url.trim().is_empty() {
                parsed.server_url = DEFAULT_SERVER_URL.to_string();
            }
            return parsed;
        }
    }
    ClientConfig::default()
}

pub fn save_config(scope: StorageScope, cfg: &ClientConfig) -> Result<()> {
    let dir = data_dir(scope);
    std::fs::create_dir_all(&dir)?;
    let raw = serde_json::to_string_pretty(cfg)?;
    std::fs::write(config_path(scope), raw)?;
    Ok(())
}

/// Rotates the local unattended key, saves Argon2id hash to config, and encrypts the
/// viewable plaintext key via Windows DPAPI.
pub fn rotate_unattended_key(scope: StorageScope, cfg: &mut ClientConfig) -> Result<String> {
    let new_key = generate_unattended_key();
    let hash = hash_unattended_key(&new_key)?;
    let now = chrono::Utc::now();
    cfg.unattended.key_hash = Some(hash);
    cfg.unattended.created_at = now;
    cfg.unattended.next_rotation_at = compute_next_rotation_utc(&cfg.unattended.schedule, now);
    cfg.unattended.failed_attempts = 0;
    cfg.unattended.locked_until = None;
    save_config(scope, cfg)?;
    save_dpapi_key(scope, &new_key)?;
    Ok(new_key)
}

pub fn save_dpapi_key(scope: StorageScope, key: &str) -> Result<()> {
    let dir = data_dir(scope);
    std::fs::create_dir_all(&dir)?;
    let local_machine = scope == StorageScope::MachineService;
    let protected = dpapi_protect(key.as_bytes(), local_machine)?;
    std::fs::write(dpapi_path(scope), protected)?;
    Ok(())
}

pub fn load_dpapi_key(scope: StorageScope) -> Option<String> {
    let bytes = std::fs::read(dpapi_path(scope)).ok()?;
    let plain = dpapi_unprotect(&bytes).ok()?;
    String::from_utf8(plain).ok()
}

/// Migrates portable config (preserving Device ID, server URL, and schedule) into
/// `C:\ProgramData\NUVI Remote\client\` during service installation.
pub fn migrate_portable_to_service(portable_dir: &Path) -> Result<()> {
    let svc_dir = data_dir(StorageScope::MachineService);
    std::fs::create_dir_all(&svc_dir)?;

    let src_cfg = portable_dir.join("config.json");
    let dst_cfg = config_path(StorageScope::MachineService);

    let mut cfg = if let Ok(raw) = std::fs::read_to_string(&src_cfg) {
        serde_json::from_str::<ClientConfig>(&raw).unwrap_or_default()
    } else if let Ok(raw) = std::fs::read_to_string(&dst_cfg) {
        serde_json::from_str::<ClientConfig>(&raw).unwrap_or_default()
    } else {
        ClientConfig::default()
    };

    // If a DPAPI key was saved under CurrentUser, try reading it only if readable; otherwise
    // if unattended is enabled with no machine-readable DPAPI key, rotate cleanly under LocalMachine.
    let src_dpapi = portable_dir.join("unattended.dpapi");
    let mut migrated_plain: Option<String> = None;
    if let Ok(bytes) = std::fs::read(&src_dpapi) {
        if let Ok(plain) = dpapi_unprotect(&bytes) {
            if let Ok(s) = String::from_utf8(plain) {
                migrated_plain = Some(s);
            }
        }
    }

    if let Some(plain) = migrated_plain {
        save_config(StorageScope::MachineService, &cfg)?;
        save_dpapi_key(StorageScope::MachineService, &plain)?;
    } else {
        if cfg.unattended.enabled || cfg.unattended.key_hash.is_none() {
            cfg.unattended.enabled = true;
            let _ = rotate_unattended_key(StorageScope::MachineService, &mut cfg)?;
        } else {
            save_config(StorageScope::MachineService, &cfg)?;
        }
    }

    let _ = harden_service_data_dir_acl(&svc_dir);
    Ok(())
}

/// Restricts the `ProgramData\NUVI Remote\client` directory to `SYSTEM` and `Administrators` only.
#[cfg(windows)]
pub fn harden_service_data_dir_acl(dir: &Path) -> Result<()> {
    use windows::{
        core::{PCWSTR, PWSTR},
        Win32::{
            Foundation::{BOOL, LocalFree, HLOCAL},
            Security::{
                Authorization::{
                    ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
                    SDDL_REVISION_1, SE_FILE_OBJECT,
                },
                GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION,
                PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            },
        },
    };

    std::fs::create_dir_all(dir)?;
    let sddl: Vec<u16> = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut path_w: Vec<u16> = dir
        .to_string_lossy()
        .encode_utf16()
        .chain(Some(0))
        .collect();

    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
        .map_err(|e| anyhow!("SDDL parse failed: {e}"))?;

        let mut dacl_present = BOOL(0);
        let mut dacl_defaulted = BOOL(0);
        let mut p_dacl: *mut ACL = std::ptr::null_mut();
        let res = GetSecurityDescriptorDacl(
            sd,
            &mut dacl_present,
            &mut p_dacl,
            &mut dacl_defaulted,
        )
        .map_err(|e| anyhow!("GetSecurityDescriptorDacl failed: {e}"));

        if res.is_ok() && dacl_present.as_bool() && !p_dacl.is_null() {
            let err = SetNamedSecurityInfoW(
                PWSTR(path_w.as_mut_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(p_dacl),
                None,
            );
            let _ = LocalFree(HLOCAL(sd.0));
            if err.0 != 0 {
                return Err(anyhow!("SetNamedSecurityInfoW failed with WIN32_ERROR({})", err.0));
            }
            Ok(())
        } else {
            let _ = LocalFree(HLOCAL(sd.0));
            Err(anyhow!("Missing DACL from SDDL"))
        }
    }
}

#[cfg(not(windows))]
pub fn harden_service_data_dir_acl(_dir: &Path) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
fn dpapi_protect(data: &[u8], local_machine: bool) -> Result<Vec<u8>> {
    use windows::Win32::{
        Foundation::{LocalFree, HLOCAL},
        Security::Cryptography::{
            CryptProtectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
            CRYPT_INTEGER_BLOB,
        },
    };

    let flags = if local_machine {
        CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE
    } else {
        CRYPTPROTECT_UI_FORBIDDEN
    };

    unsafe {
        let mut in_blob = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB::default();
        CryptProtectData(
            &mut in_blob,
            None,
            None,
            None,
            None,
            flags,
            &mut out_blob,
        )
        .map_err(|e| anyhow!("CryptProtectData failed: {e}"))?;

        let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
        let vec = slice.to_vec();
        let _ = LocalFree(HLOCAL(out_blob.pbData as _));
        Ok(vec)
    }
}

#[cfg(windows)]
fn dpapi_unprotect(data: &[u8]) -> Result<Vec<u8>> {
    use windows::Win32::{
        Foundation::{LocalFree, HLOCAL},
        Security::Cryptography::{
            CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        },
    };

    unsafe {
        let mut in_blob = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB::default();
        CryptUnprotectData(
            &mut in_blob,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
        .map_err(|e| anyhow!("CryptUnprotectData failed: {e}"))?;

        let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
        let vec = slice.to_vec();
        let _ = LocalFree(HLOCAL(out_blob.pbData as _));
        Ok(vec)
    }
}

#[cfg(not(windows))]
fn dpapi_protect(data: &[u8], _local_machine: bool) -> Result<Vec<u8>> {
    Ok(data.to_vec())
}

#[cfg(not(windows))]
fn dpapi_unprotect(data: &[u8]) -> Result<Vec<u8>> {
    Ok(data.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpapi_current_user_and_local_machine_roundtrip() {
        let secret = b"NUVI-7K9P-M4XQ-28TR";
        let ct_user = dpapi_protect(secret, false).expect("user protect");
        let pt_user = dpapi_unprotect(&ct_user).expect("user unprotect");
        assert_eq!(pt_user, secret);

        let ct_mach = dpapi_protect(secret, true).expect("machine protect");
        let pt_mach = dpapi_unprotect(&ct_mach).expect("machine unprotect");
        assert_eq!(pt_mach, secret);
    }
}
