use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

fn find_rc_exe() -> Option<PathBuf> {
    if let Ok(status) = Command::new("rc.exe").arg("/?").output() {
        if status.status.success() || !status.stdout.is_empty() || !status.stderr.is_empty() {
            return Some(PathBuf::from("rc.exe"));
        }
    }
    let kits_root = Path::new(r"C:\Program Files (x86)\Windows Kits\10\bin");
    if let Ok(entries) = fs::read_dir(kits_root) {
        let mut candidates: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path().join("x64").join("rc.exe"))
            .filter(|p| p.is_file())
            .collect();
        candidates.sort();
        return candidates.pop();
    }
    None
}

fn strip_verbatim_prefix(p: &Path) -> String {
    let s = p.to_string_lossy();
    s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
}

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ico_raw = manifest_dir.join("..").join("..").join("assets").join("nuvi-logo.ico");
    let ico_canon = fs::canonicalize(&ico_raw)
        .unwrap_or_else(|e| panic!("Failed to locate {}: {e}", ico_raw.display()));
    let ico_clean = strip_verbatim_prefix(&ico_canon).replace('\\', "/");

    println!("cargo:rerun-if-changed={}", strip_verbatim_prefix(&ico_canon));

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let rc_path = out_dir.join("nuvi_icon.rc");
    let res_path = out_dir.join("nuvi_icon.res");

    fs::write(&rc_path, format!("1 ICON \"{ico_clean}\"\n"))
        .unwrap_or_else(|e| panic!("Failed to write {}: {e}", rc_path.display()));

    let rc_exe = find_rc_exe().expect("Windows SDK rc.exe not found");
    let output = Command::new(&rc_exe)
        .arg("/nologo")
        .arg("/fo")
        .arg(&res_path)
        .arg(&rc_path)
        .output()
        .unwrap_or_else(|e| panic!("Failed to invoke {}: {e}", rc_exe.display()));

    if !output.status.success() {
        panic!(
            "rc.exe failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    println!("cargo:rustc-link-arg-bin=nuvi-host={}", res_path.display());
}
