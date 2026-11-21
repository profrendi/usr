//! Update otomatis lewat GitHub Releases. Hanya pakai std + curl.exe/certutil.exe bawaan Windows 10+
//! (tanpa crate HTTP/TLS tambahan -> exe kecil, RAM kecil).

use std::path::PathBuf;
use std::process::Command;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const LATEST_URL: &str = "https://github.com/profrendi/usr/releases/latest/download/latest.json";
const ALLOWED_PREFIX: &str = "https://github.com/profrendi/usr/releases/download/";

pub enum Outcome {
    UpToDate,
    Installed(String),
    Failed(String),
}

fn sys32(exe: &str) -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    PathBuf::from(root).join("System32").join(exe)
}

fn run(cmd: &mut Command) -> Option<std::process::Output> {
    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    cmd.output().ok()
}

fn json_str(s: &str, key: &str) -> Option<String> {
    let pat = format!("\"{}\"", key);
    let i = s.find(&pat)? + pat.len();
    let rest = s[i..].trim_start().strip_prefix(':')?.trim_start().strip_prefix('"')?;
    Some(rest[..rest.find('"')?].to_string())
}

fn ver_tuple(v: &str) -> Vec<u32> {
    v.trim_start_matches('v').split('.').map(|p| p.parse().unwrap_or(0)).collect()
}

fn newer(remote: &str, local: &str) -> bool {
    ver_tuple(remote) > ver_tuple(local)
}

fn sha256(path: &PathBuf) -> Option<String> {
    let out = run(Command::new(sys32("certutil.exe")).args(["-hashfile"]).arg(path).arg("SHA256"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().nth(1)?;
    Some(line.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_lowercase())
}

/// Bersihkan sisa update sebelumnya (dipanggil saat start).
pub fn cleanup() {
    if let Ok(exe) = std::env::current_exe() {
        let _ = std::fs::remove_file(exe.with_extension("old"));
        let _ = std::fs::remove_file(exe.with_extension("new"));
    }
}

pub fn check_and_install() -> Outcome {
    let curl = sys32("curl.exe");
    let Some(out) = run(Command::new(&curl).args(["-fsSL", "--max-time", "20", LATEST_URL])) else {
        return Outcome::Failed("curl.exe tidak tersedia".into());
    };
    if !out.status.success() {
        return Outcome::Failed("tidak bisa menghubungi GitHub".into());
    }
    let body = String::from_utf8_lossy(&out.stdout).trim_start_matches('\u{feff}').to_string();
    let (Some(ver), Some(url), Some(hash)) = (json_str(&body, "version"), json_str(&body, "url"), json_str(&body, "sha256"))
    else {
        return Outcome::Failed("latest.json tidak valid".into());
    };
    if !newer(&ver, VERSION) {
        return Outcome::UpToDate;
    }
    if !url.starts_with(ALLOWED_PREFIX) {
        return Outcome::Failed("alamat unduhan tidak dipercaya".into());
    }
    let Ok(exe) = std::env::current_exe() else {
        return Outcome::Failed("lokasi aplikasi tidak diketahui".into());
    };
    let new = exe.with_extension("new");
    let old = exe.with_extension("old");
    let _ = std::fs::remove_file(&new);

    let ok = run(Command::new(&curl).args(["-fsSL", "--max-time", "180", "-o"]).arg(&new).arg(&url))
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !ok {
        let _ = std::fs::remove_file(&new);
        return Outcome::Failed("unduhan update gagal".into());
    }
    if sha256(&new).as_deref() != Some(hash.to_lowercase().as_str()) {
        let _ = std::fs::remove_file(&new);
        return Outcome::Failed("checksum update tidak cocok, dibatalkan".into());
    }
    let _ = std::fs::remove_file(&old);
    if std::fs::rename(&exe, &old).is_err() {
        let _ = std::fs::remove_file(&new);
        return Outcome::Failed("tidak bisa mengganti aplikasi (folder dikunci?)".into());
    }
    if std::fs::rename(&new, &exe).is_err() {
        let _ = std::fs::rename(&old, &exe); // kembalikan
        return Outcome::Failed("gagal memasang update".into());
    }
    Outcome::Installed(ver)
}

/// Jalankan ulang aplikasi dari exe yang baru.
pub fn relaunch() {
    if let Ok(exe) = std::env::current_exe() {
        let _ = Command::new(exe).spawn();
    }
}
