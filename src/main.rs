#![windows_subsystem = "windows"]
//! PwAkun - pengatur akun lokal Windows: password, aktif/nonaktif, hapus akun,
//! dan pulihkan akun Administrator bawaan. Native Win32 murni: tanpa framework
//! UI, tanpa thread tambahan selain cek update -> start instan, RAM kecil.

mod update;

use std::cell::RefCell;
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicIsize, Ordering::Relaxed};
use std::sync::Mutex;

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::NetworkManagement::NetManagement::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Registry::*;
use windows_sys::Win32::System::WindowsProgramming::GetUserNameW;
use windows_sys::Win32::UI::Controls::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

// ---------- ID kontrol ----------
const ID_DEL: isize = 101; // hapus password
const ID_PASS: isize = 102; // password tanpa expired
const ID_ACCT: isize = 103; // akun tanpa expired
const ID_ALL: isize = 104; // semuanya (password+expired)
const ID_CHECKPW: isize = 105; // cek apakah akun punya password
const ID_ENABLE: isize = 106; // aktifkan akun
const ID_DISABLE: isize = 107; // nonaktifkan akun
const ID_DELACC: isize = 108; // hapus akun
const ID_RESTORE: isize = 109; // pulihkan Administrator bawaan
const ID_REF: isize = 110; // refresh
const BTN_IDS: [isize; 9] = [ID_DEL, ID_PASS, ID_ACCT, ID_ALL, ID_CHECKPW, ID_ENABLE, ID_DISABLE, ID_DELACC, ID_RESTORE];

const WM_UPDATE_DONE: u32 = WM_APP + 1;
const TIMER_UPDATE: usize = 1;
const UPDATE_EVERY_MS: u32 = 6 * 60 * 60 * 1000;

const ERR_PASSWORD_TOO_SHORT: u32 = 2245;
const TIMEQ_FOREVER: u32 = u32::MAX;
const SS_LEFT_: u32 = 0;
const SS_ENDELLIPSIS_: u32 = 0x4000;
const UF_ACCOUNTDISABLE_: u32 = 0x0002;
const UF_DONT_EXPIRE_PASSWD_: u32 = 0x10000;

// SID bawaan lokal S-1-5-32-544 (grup Administrators), dibuat manual byte-per-byte
// supaya tidak tergantung bahasa tampilan Windows.
const ADMINS_SID: [u8; 16] = [1, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x20, 2, 0, 0];

static H_LIST: AtomicIsize = AtomicIsize::new(0);
static H_STATUS: AtomicIsize = AtomicIsize::new(0);
static H_FONT: AtomicIsize = AtomicIsize::new(0);
static H_BTN: [AtomicIsize; 9] = [
    AtomicIsize::new(0),
    AtomicIsize::new(0),
    AtomicIsize::new(0),
    AtomicIsize::new(0),
    AtomicIsize::new(0),
    AtomicIsize::new(0),
    AtomicIsize::new(0),
    AtomicIsize::new(0),
    AtomicIsize::new(0),
];
static DPI: AtomicI32 = AtomicI32::new(96);
static CHECKING: AtomicBool = AtomicBool::new(false);
static UPDATE_MSG: Mutex<String> = Mutex::new(String::new());

struct Acc {
    name: String,
    rid: Option<u32>,
    is_admin: bool,
    disabled: bool,
    pw_status: String,
}

thread_local! {
    static ACCS: RefCell<Vec<Acc>> = const { RefCell::new(Vec::new()) };
}

fn sc(v: i32) -> i32 {
    v * DPI.load(Relaxed) / 96
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn from_wide(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0;
    while *p.add(n) != 0 {
        n += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
}

fn hwnd(a: &AtomicIsize) -> HWND {
    a.load(Relaxed) as HWND
}

unsafe fn set_status(text: &str) {
    SetWindowTextW(hwnd(&H_STATUS), wide(text).as_ptr());
}

fn err_text(code: u32) -> String {
    match code {
        0 => "ok".into(),
        5 => "akses ditolak".into(),
        2221 => "akun tidak ditemukan".into(),
        2224 => "akun sudah ada".into(),
        ERR_PASSWORD_TOO_SHORT => "kebijakan panjang password minimum".into(),
        2243 => "password tidak bisa diubah".into(),
        2244 | 2246 => "ditolak kebijakan password".into(),
        1314 => "butuh privilese khusus".into(),
        1326 => "login ditolak".into(),
        1327 => "dibatasi jam/komputer login".into(),
        1331 => "akun nonaktif".into(),
        1378 => "sudah anggota grup".into(),
        c => format!("kode {}", c),
    }
}

// ---------- tanggal (detik sejak 1970 -> yyyy-mm-dd) ----------
fn ymd(secs: u32) -> String {
    let z = (secs / 86400) as i64 + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 {
        y += 1;
    }
    format!("{:04}-{:02}-{:02}", y, m, d)
}

// ---------- SID / nama ----------

/// RID (sub-authority terakhir) dari sebuah akun, lewat LookupAccountNameW.
/// RID 500 = Administrator bawaan, 501 = Guest bawaan, 503 = DefaultAccount, 504 = WDAGUtilityAccount.
unsafe fn account_rid(name: &[u16]) -> Option<u32> {
    let (mut cb_sid, mut cch_dom, mut use_): (u32, u32, SID_NAME_USE) = (0, 0, 0);
    LookupAccountNameW(null(), name.as_ptr(), null_mut(), &mut cb_sid, null_mut(), &mut cch_dom, &mut use_);
    if cb_sid == 0 {
        return None;
    }
    let mut sid = vec![0u8; cb_sid as usize];
    let mut dom = vec![0u16; cch_dom as usize];
    let ok = LookupAccountNameW(null(), name.as_ptr(), sid.as_mut_ptr() as PSID, &mut cb_sid, dom.as_mut_ptr(), &mut cch_dom, &mut use_);
    if ok == 0 || sid.len() < 8 {
        return None;
    }
    let count = sid[1] as usize;
    let off = 8 + (count.checked_sub(1)?) * 4;
    if sid.len() < off + 4 {
        return None;
    }
    Some(u32::from_le_bytes([sid[off], sid[off + 1], sid[off + 2], sid[off + 3]]))
}

/// Nama tampilan grup lokal dari SID well-known-nya (mis. Administrators), supaya
/// tidak tergantung bahasa Windows (nama grup berbeda di Windows non-Inggris).
unsafe fn group_name_from_sid(sid_bytes: &[u8]) -> Option<Vec<u16>> {
    let mut sid = sid_bytes.to_vec();
    let (mut cch_name, mut cch_dom, mut use_): (u32, u32, SID_NAME_USE) = (0, 0, 0);
    LookupAccountSidW(null(), sid.as_mut_ptr() as PSID, null_mut(), &mut cch_name, null_mut(), &mut cch_dom, &mut use_);
    if cch_name == 0 {
        return None;
    }
    let mut name = vec![0u16; cch_name as usize];
    let mut dom = vec![0u16; cch_dom as usize];
    let ok = LookupAccountSidW(null(), sid.as_mut_ptr() as PSID, name.as_mut_ptr(), &mut cch_name, dom.as_mut_ptr(), &mut cch_dom, &mut use_);
    if ok == 0 {
        return None;
    }
    name.push(0);
    Some(name)
}

unsafe fn current_username() -> String {
    let mut size: u32 = 0;
    GetUserNameW(null_mut(), &mut size);
    if size == 0 {
        return String::new();
    }
    let mut buf = vec![0u16; size as usize];
    if GetUserNameW(buf.as_mut_ptr(), &mut size) == 0 {
        return String::new();
    }
    from_wide(buf.as_ptr())
}

// ---------- daftar akun ----------
unsafe fn lv_set(list: HWND, row: i32, col: i32, text: &str, insert: bool) {
    let mut t = wide(text);
    let mut item: LVITEMW = zeroed();
    item.mask = LVIF_TEXT;
    item.iItem = row;
    item.iSubItem = col;
    item.pszText = t.as_mut_ptr();
    let msg = if insert { LVM_INSERTITEMW } else { LVM_SETITEMTEXTW };
    SendMessageW(list, msg, row as WPARAM, &item as *const _ as LPARAM);
}

const PW_BELUM: &str = "(klik Cek Password)";

unsafe fn refresh() {
    let list = hwnd(&H_LIST);
    SendMessageW(list, WM_SETREDRAW, 0, 0);
    SendMessageW(list, LVM_DELETEALLITEMS, 0, 0);
    ACCS.with(|a| a.borrow_mut().clear());

    let mut buf: *mut u8 = null_mut();
    let (mut read, mut total, mut resume) = (0u32, 0u32, 0u32);
    let rc = NetUserEnum(
        null(),
        2,
        FILTER_NORMAL_ACCOUNT,
        &mut buf,
        MAX_PREFERRED_LENGTH,
        &mut read,
        &mut total,
        &mut resume,
    );
    if (rc == 0 || rc == ERROR_MORE_DATA) && !buf.is_null() {
        let users = std::slice::from_raw_parts(buf as *const USER_INFO_2, read as usize);
        for (i, u) in users.iter().enumerate() {
            let name = from_wide(u.usri2_name);
            let row = i as i32;
            let disabled = u.usri2_flags & UF_ACCOUNTDISABLE_ != 0;
            lv_set(list, row, 0, &name, true);
            lv_set(list, row, 1, if disabled { "Nonaktif" } else { "Aktif" }, false);
            lv_set(list, row, 2, PW_BELUM, false);
            lv_set(
                list,
                row,
                3,
                if u.usri2_flags & UF_DONT_EXPIRE_PASSWD_ != 0 { "Tidak pernah" } else { "Bisa expired" },
                false,
            );
            let acct = if u.usri2_acct_expires == TIMEQ_FOREVER { "Tidak pernah".to_string() } else { ymd(u.usri2_acct_expires) };
            lv_set(list, row, 4, &acct, false);
            let rid = account_rid(&wide(&name));
            ACCS.with(|a| {
                a.borrow_mut().push(Acc {
                    name,
                    rid,
                    is_admin: u.usri2_priv == USER_PRIV_ADMIN,
                    disabled,
                    pw_status: PW_BELUM.to_string(),
                })
            });
        }
        set_status(&format!("{} akun dimuat. Pilih akun (boleh lebih dari satu), lalu klik tombol.", read));
    } else {
        set_status(&format!("Gagal membaca daftar akun (kode {}).", rc));
    }
    if !buf.is_null() {
        NetApiBufferFree(buf as *const c_void);
    }
    SendMessageW(list, WM_SETREDRAW, 1, 0);
    InvalidateRect(list, null(), 1);
}

unsafe fn selected_idx() -> Vec<usize> {
    let list = hwnd(&H_LIST);
    let mut out = Vec::new();
    let mut idx: isize = -1;
    loop {
        idx = SendMessageW(list, LVM_GETNEXTITEM, idx as WPARAM, LVNI_SELECTED as LPARAM);
        if idx < 0 {
            break;
        }
        out.push(idx as usize);
    }
    out
}

unsafe fn selected_names() -> Vec<String> {
    let idxs = selected_idx();
    ACCS.with(|a| {
        let accs = a.borrow();
        idxs.iter().filter_map(|&i| accs.get(i)).map(|acc| acc.name.clone()).collect()
    })
}

// ---------- operasi password / expired (seperti sebelumnya) ----------
unsafe fn set_empty_password(name: &[u16]) -> u32 {
    let mut empty = [0u16; 1];
    let info = USER_INFO_1003 { usri1003_password: empty.as_mut_ptr() };
    NetUserSetInfo(null(), name.as_ptr(), 1003, &info as *const _ as *const u8, null_mut())
}

unsafe fn get_flags(name: &[u16]) -> Option<(u32, *mut u8)> {
    let mut buf: *mut u8 = null_mut();
    if NetUserGetInfo(null(), name.as_ptr(), 1, &mut buf) != 0 || buf.is_null() {
        return None;
    }
    let flags = (*(buf as *const USER_INFO_1)).usri1_flags;
    Some((flags, buf))
}

unsafe fn set_flags(name: &[u16], flags: u32) -> u32 {
    let info = USER_INFO_1008 { usri1008_flags: flags };
    NetUserSetInfo(null(), name.as_ptr(), 1008, &info as *const _ as *const u8, null_mut())
}

unsafe fn set_password_never_expires(name: &[u16]) -> u32 {
    match get_flags(name) {
        Some((flags, buf)) => {
            NetApiBufferFree(buf as *const c_void);
            set_flags(name, flags | UF_DONT_EXPIRE_PASSWD_)
        }
        None => 2221,
    }
}

unsafe fn set_account_never_expires(name: &[u16]) -> u32 {
    let info = USER_INFO_1017 { usri1017_acct_expires: TIMEQ_FOREVER };
    NetUserSetInfo(null(), name.as_ptr(), 1017, &info as *const _ as *const u8, null_mut())
}

unsafe fn set_disabled(name: &[u16], disable: bool) -> u32 {
    match get_flags(name) {
        Some((flags, buf)) => {
            NetApiBufferFree(buf as *const c_void);
            let new_flags = if disable { flags | UF_ACCOUNTDISABLE_ } else { flags & !UF_ACCOUNTDISABLE_ };
            set_flags(name, new_flags)
        }
        None => 2221,
    }
}

unsafe fn allow_blank_passwords() -> u32 {
    let info = USER_MODALS_INFO_1001 { usrmod1001_min_passwd_len: 0 };
    NetUserModalsSet(null(), 1001, &info as *const _ as *const u8, null_mut())
}

unsafe fn run(hwnd_main: HWND, id: isize) {
    let names = selected_names();
    if names.is_empty() {
        set_status("Pilih minimal satu akun dulu.");
        return;
    }
    let do_pw = id == ID_DEL || id == ID_ALL;
    let do_pass = id == ID_PASS || id == ID_ALL;
    let do_acct = id == ID_ACCT || id == ID_ALL;

    if do_pw {
        let msg = format!(
            "Hapus password {} akun terpilih?\n\nAkun tanpa password bisa dipakai login lokal tanpa kata sandi.\nTindakan ini tidak bisa dibatalkan.",
            names.len()
        );
        if MessageBoxW(hwnd_main, wide(&msg).as_ptr(), wide("Konfirmasi").as_ptr(), MB_YESNO | MB_ICONWARNING) != IDYES {
            return;
        }
    }

    let (mut ok, mut fail) = (0, Vec::<String>::new());
    let mut asked_policy = false;
    for name in &names {
        let w = wide(name);
        let mut errs: Vec<String> = Vec::new();
        if do_pw {
            let mut rc = set_empty_password(&w);
            if rc == ERR_PASSWORD_TOO_SHORT && !asked_policy {
                asked_policy = true;
                let q = "Kebijakan Windows mewajibkan panjang password minimum.\n\nSet panjang minimum menjadi 0 agar password kosong diizinkan, lalu coba lagi?";
                if MessageBoxW(hwnd_main, wide(q).as_ptr(), wide("Kebijakan password").as_ptr(), MB_YESNO | MB_ICONQUESTION) == IDYES
                    && allow_blank_passwords() == 0
                {
                    rc = set_empty_password(&w);
                }
            } else if rc == ERR_PASSWORD_TOO_SHORT {
                rc = set_empty_password(&w);
            }
            if rc != 0 {
                errs.push(format!("hapus password: {}", err_text(rc)));
            }
        }
        if do_pass {
            let rc = set_password_never_expires(&w);
            if rc != 0 {
                errs.push(format!("pass expired: {}", err_text(rc)));
            }
        }
        if do_acct {
            let rc = set_account_never_expires(&w);
            if rc != 0 {
                errs.push(format!("akun expired: {}", err_text(rc)));
            }
        }
        if errs.is_empty() {
            ok += 1;
        } else {
            fail.push(format!("{} ({})", name, errs.join(", ")));
        }
    }

    refresh();
    if fail.is_empty() {
        set_status(&format!("Selesai: {} akun berhasil diubah.", ok));
    } else {
        set_status(&format!("Berhasil {}, gagal {}: {}", ok, fail.len(), fail.join("; ")));
    }
}

// ---------- aktifkan / nonaktifkan ----------
unsafe fn toggle_enabled(h: HWND, enable: bool) {
    let names = selected_names();
    if names.is_empty() {
        set_status("Pilih minimal satu akun dulu.");
        return;
    }
    let (mut ok, mut fail) = (0, Vec::<String>::new());
    for name in &names {
        let rc = set_disabled(&wide(name), !enable);
        if rc == 0 {
            ok += 1;
        } else {
            fail.push(format!("{} ({})", name, err_text(rc)));
        }
    }
    refresh();
    let kata = if enable { "diaktifkan" } else { "dinonaktifkan" };
    if fail.is_empty() {
        set_status(&format!("{} akun {}.", ok, kata));
    } else {
        set_status(&format!("{} {}, gagal {}: {}", ok, kata, fail.len(), fail.join("; ")));
    }
    let _ = h;
}

// ---------- cek password kosong/ada ----------
/// Mengecek apakah password akun kosong, lewat percobaan login lokal dengan
/// password kosong (LogonUserW). Ini TIDAK bisa membaca atau menampilkan isi
/// password yang sebenarnya -- Windows tidak pernah menyimpan password dalam
/// bentuk yang bisa dibaca ulang, hanya hash satu arah. Hasilnya hanya "kosong"
/// atau "ada", bukan isi passwordnya.
unsafe fn check_blank_password(name: &[u16]) -> Result<bool, u32> {
    let domain = wide(".");
    let empty = [0u16; 1];
    let mut token: HANDLE = null_mut();
    let ok = LogonUserW(name.as_ptr(), domain.as_ptr(), empty.as_ptr(), LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &mut token);
    if ok != 0 {
        CloseHandle(token);
        return Ok(true);
    }
    let err = GetLastError();
    if err == ERROR_LOGON_FAILURE {
        Ok(false)
    } else {
        Err(err)
    }
}

unsafe fn check_passwords(h: HWND) {
    let idxs = selected_idx();
    if idxs.is_empty() {
        set_status("Pilih minimal satu akun dulu.");
        return;
    }
    let warn = "Memeriksa password kosong mencoba LOGIN dengan password kosong ke tiap akun terpilih.\n\nIni hanya memberi tahu KOSONG atau ADA, bukan isi passwordnya (Windows tidak pernah menyimpan password dalam bentuk yang bisa dibaca ulang).\n\nJika PC menerapkan kebijakan penguncian akun (account lockout) setelah beberapa kali login gagal, ini terhitung sebagai satu kali kegagalan untuk akun yang memang punya password.\n\nLanjutkan?";
    if MessageBoxW(h, wide(warn).as_ptr(), wide("Cek Password").as_ptr(), MB_YESNO | MB_ICONWARNING) != IDYES {
        return;
    }
    let list = hwnd(&H_LIST);
    for &i in &idxs {
        let name = ACCS.with(|a| a.borrow().get(i).map(|acc| acc.name.clone()));
        let Some(name) = name else { continue };
        let status = match check_blank_password(&wide(&name)) {
            Ok(true) => "Kosong (tanpa password)".to_string(),
            Ok(false) => "Ada password".to_string(),
            Err(code) => format!("Tidak bisa dicek ({})", err_text(code)),
        };
        ACCS.with(|a| {
            if let Some(acc) = a.borrow_mut().get_mut(i) {
                acc.pw_status = status.clone();
            }
        });
        lv_set(list, i as i32, 2, &status, false);
    }
    set_status("Pemeriksaan password selesai.");
}

// ---------- hapus akun ----------
fn protect_reason(acc: &Acc, current_user: &str) -> Option<&'static str> {
    if acc.name.eq_ignore_ascii_case(current_user) {
        return Some("akun yang sedang dipakai sesi ini");
    }
    match acc.rid {
        Some(500) => return Some("Administrator bawaan (RID 500)"),
        Some(501) => return Some("Guest bawaan (RID 501)"),
        Some(503) => return Some("DefaultAccount (RID 503)"),
        Some(504) => return Some("WDAGUtilityAccount (RID 504)"),
        _ => {}
    }
    // Jaga-jaga kalau SID gagal dibaca: tetap lindungi lewat nama bawaan Windows.
    if acc.name.eq_ignore_ascii_case("Administrator") {
        Some("nama akun Administrator bawaan")
    } else if acc.name.eq_ignore_ascii_case("Guest") {
        Some("nama akun Guest bawaan")
    } else {
        None
    }
}

unsafe fn delete_accounts(h: HWND) {
    let idxs = selected_idx();
    if idxs.is_empty() {
        set_status("Pilih minimal satu akun dulu.");
        return;
    }
    let cur = current_username();
    let (mut candidates, mut blocked) = (Vec::<String>::new(), Vec::<String>::new());
    ACCS.with(|a| {
        let accs = a.borrow();
        for &i in &idxs {
            if let Some(acc) = accs.get(i) {
                match protect_reason(acc, &cur) {
                    Some(r) => blocked.push(format!("{} ({})", acc.name, r)),
                    None => candidates.push(acc.name.clone()),
                }
            }
        }
    });

    if !candidates.is_empty() {
        let remaining_admin = ACCS.with(|a| {
            a.borrow()
                .iter()
                .filter(|acc| acc.is_admin && !acc.disabled && !candidates.iter().any(|c| c.eq_ignore_ascii_case(&acc.name)))
                .count()
        });
        if remaining_admin == 0 {
            MessageBoxW(
                h,
                wide("Tidak bisa menghapus: tidak akan ada akun Administrator aktif yang tersisa setelah ini.").as_ptr(),
                wide("Ditolak").as_ptr(),
                MB_OK | MB_ICONERROR,
            );
            candidates.clear();
        }
    }

    if candidates.is_empty() {
        if blocked.is_empty() {
            set_status("Tidak ada akun yang dihapus.");
        } else {
            set_status(&format!("Tidak ada yang dihapus. Dilindungi: {}", blocked.join(", ")));
        }
        return;
    }

    let mut msg = format!(
        "Hapus {} akun berikut? Tindakan ini tidak bisa dibatalkan.\n\n{}",
        candidates.len(),
        candidates.join(", ")
    );
    if !blocked.is_empty() {
        msg.push_str(&format!("\n\nDilewati (dilindungi, tidak akan dihapus): {}", blocked.join(", ")));
    }
    if MessageBoxW(h, wide(&msg).as_ptr(), wide("Konfirmasi hapus akun").as_ptr(), MB_YESNO | MB_ICONWARNING) != IDYES {
        return;
    }

    let (mut ok, mut fail) = (0, Vec::<String>::new());
    for name in &candidates {
        let rc = NetUserDel(null(), wide(name).as_ptr());
        if rc == 0 {
            ok += 1;
        } else {
            fail.push(format!("{} ({})", name, err_text(rc)));
        }
    }
    refresh();
    if fail.is_empty() {
        set_status(&format!("{} akun dihapus.", ok));
    } else {
        set_status(&format!("{} akun dihapus, gagal {}: {}", ok, fail.len(), fail.join("; ")));
    }
}

// ---------- pulihkan Administrator bawaan ----------
unsafe fn rename_user(old: &[u16], new_name: &str) -> u32 {
    let mut new_w = wide(new_name);
    let info = USER_INFO_0 { usri0_name: new_w.as_mut_ptr() };
    NetUserSetInfo(null(), old.as_ptr(), 0, &info as *const _ as *const u8, null_mut())
}

unsafe fn add_to_administrators(name: &[u16]) -> Result<(), String> {
    let Some(group) = group_name_from_sid(&ADMINS_SID) else {
        return Err("tidak bisa menentukan nama grup Administrators".into());
    };
    let mut uname = name.to_vec();
    let info = LOCALGROUP_MEMBERS_INFO_3 { lgrmi3_domainandname: uname.as_mut_ptr() };
    let rc = NetLocalGroupAddMembers(null(), group.as_ptr(), 3, &info as *const _ as *const u8, 1);
    if rc == 0 || rc == ERROR_MEMBER_IN_ALIAS {
        Ok(())
    } else {
        Err(err_text(rc))
    }
}

unsafe fn unhide_from_login(name: &str) -> String {
    let path = wide("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList");
    let mut hkey: HKEY = null_mut();
    let rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_SET_VALUE, &mut hkey);
    if rc == ERROR_FILE_NOT_FOUND {
        return "tidak pernah disembunyikan dari layar login".into();
    }
    if rc != ERROR_SUCCESS {
        return format!("tidak bisa membuka registry login ({})", err_text(rc));
    }
    let valrc = RegDeleteValueW(hkey, wide(name).as_ptr());
    RegCloseKey(hkey);
    match valrc {
        ERROR_SUCCESS => "ditampilkan kembali di layar login".into(),
        ERROR_FILE_NOT_FOUND => "tidak pernah disembunyikan dari layar login".into(),
        c => format!("tidak bisa menampilkan di layar login ({})", err_text(c)),
    }
}

unsafe fn restore_builtin_admin(h: HWND) {
    let target = ACCS.with(|a| a.borrow().iter().find(|acc| acc.rid == Some(500)).map(|acc| acc.name.clone()));
    let Some(mut name) = target else {
        set_status("Akun Administrator bawaan (SID berakhiran -500) tidak ditemukan.");
        return;
    };

    let confirm = format!(
        "Pulihkan akun Administrator bawaan ({})?\n\n- Nama dikembalikan ke \"Administrator\" bila pernah diubah\n- Akun diaktifkan dan dibuat tidak pernah kedaluwarsa\n- Dimasukkan ke grup Administrators\n- Ditampilkan kembali di layar login bila disembunyikan",
        name
    );
    if MessageBoxW(h, wide(&confirm).as_ptr(), wide("Pulihkan Admin Bawaan").as_ptr(), MB_YESNO | MB_ICONQUESTION) != IDYES {
        return;
    }

    let mut report = Vec::<String>::new();

    if name != "Administrator" {
        let rc = rename_user(&wide(&name), "Administrator");
        if rc == 0 {
            report.push(format!("nama diubah dari \"{}\" menjadi \"Administrator\"", name));
            name = "Administrator".to_string();
        } else {
            report.push(format!("gagal mengubah nama ({})", err_text(rc)));
        }
    }

    let w = wide(&name);
    let rc = set_disabled(&w, false);
    report.push(if rc == 0 { "diaktifkan".into() } else { format!("gagal mengaktifkan ({})", err_text(rc)) });

    let rc = set_account_never_expires(&w);
    report.push(if rc == 0 { "akun tanpa expired".into() } else { format!("gagal set tanpa-expired ({})", err_text(rc)) });

    match add_to_administrators(&w) {
        Ok(()) => report.push("masuk grup Administrators".into()),
        Err(e) => report.push(format!("gagal masuk grup Administrators ({})", e)),
    }

    report.push(unhide_from_login(&name));

    refresh();
    set_status(&format!("Administrator bawaan: {}.", report.join("; ")));
}

// ---------- UI ----------
unsafe fn child(class: &str, text: &str, style: u32, ex: u32, parent: HWND, id: isize) -> HWND {
    CreateWindowExW(
        ex,
        wide(class).as_ptr(),
        wide(text).as_ptr(),
        WS_CHILD | WS_VISIBLE | style,
        0,
        0,
        10,
        10,
        parent,
        id as HMENU,
        GetModuleHandleW(null()),
        null(),
    )
}

unsafe fn create_controls(parent: HWND) {
    // Font sistem (Segoe UI) mengikuti pengaturan Windows
    let mut ncm: NONCLIENTMETRICSW = zeroed();
    ncm.cbSize = size_of::<NONCLIENTMETRICSW>() as u32;
    SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, ncm.cbSize, &mut ncm as *mut _ as *mut c_void, 0);
    let font = CreateFontIndirectW(&ncm.lfMessageFont);
    H_FONT.store(font as isize, Relaxed);

    let list = child(
        "SysListView32",
        "",
        WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS,
        WS_EX_CLIENTEDGE,
        parent,
        1,
    );
    SendMessageW(
        list,
        LVM_SETEXTENDEDLISTVIEWSTYLE,
        0,
        (LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP) as LPARAM,
    );
    let cols = [("Nama akun", 170), ("Status", 80), ("Password", 170), ("Pass expired", 110), ("Akun expired", 110)];
    for (i, (title, width)) in cols.iter().enumerate() {
        let mut t = wide(title);
        let mut col: LVCOLUMNW = zeroed();
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        col.cx = sc(*width);
        col.pszText = t.as_mut_ptr();
        col.iSubItem = i as i32;
        SendMessageW(list, LVM_INSERTCOLUMNW, i as WPARAM, &col as *const _ as LPARAM);
    }
    H_LIST.store(list as isize, Relaxed);

    let labels = [
        (ID_DEL, "Hapus password"),
        (ID_PASS, "Pass tanpa expired"),
        (ID_ACCT, "Akun tanpa expired"),
        (ID_ALL, "Lakukan semua"),
        (ID_CHECKPW, "Cek password"),
        (ID_ENABLE, "Aktifkan"),
        (ID_DISABLE, "Nonaktifkan"),
        (ID_DELACC, "Hapus akun"),
        (ID_RESTORE, "Pulihkan admin bawaan"),
    ];
    for (i, (id, text)) in labels.iter().enumerate() {
        let b = child("BUTTON", text, WS_TABSTOP | BS_PUSHBUTTON as u32, 0, parent, *id);
        SendMessageW(b, WM_SETFONT, font as WPARAM, 1);
        H_BTN[i].store(b as isize, Relaxed);
    }
    let refresh_btn = child("BUTTON", "Refresh", WS_TABSTOP | BS_PUSHBUTTON as u32, 0, parent, ID_REF);
    SendMessageW(refresh_btn, WM_SETFONT, font as WPARAM, 1);
    REFRESH_BTN.store(refresh_btn as isize, Relaxed);

    let st = child("STATIC", "", SS_LEFT_ | SS_ENDELLIPSIS_, 0, parent, 2);
    SendMessageW(st, WM_SETFONT, font as WPARAM, 1);
    SendMessageW(list, WM_SETFONT, font as WPARAM, 1);
    H_STATUS.store(st as isize, Relaxed);

    refresh();
}

static REFRESH_BTN: AtomicIsize = AtomicIsize::new(0);

fn start_update_check(h: HWND) {
    if CHECKING.swap(true, Relaxed) {
        return;
    }
    let hv = h as isize;
    std::thread::spawn(move || {
        let (kind, msg) = match update::check_and_install() {
            update::Outcome::UpToDate => (0, String::new()),
            update::Outcome::Installed(v) => (1, v),
            update::Outcome::Failed(e) => (2, e),
        };
        *UPDATE_MSG.lock().unwrap() = msg;
        CHECKING.store(false, Relaxed);
        unsafe { PostMessageW(hv as HWND, WM_UPDATE_DONE, kind, 0) };
    });
}

unsafe fn layout(parent: HWND) {
    if H_LIST.load(Relaxed) == 0 {
        return;
    }
    let mut rc: RECT = zeroed();
    GetClientRect(parent, &mut rc);
    let (w, h) = (rc.right, rc.bottom);
    let (m, bh, sh, gap) = (sc(10), sc(32), sc(40), sc(6));
    let row2_y_offset = bh + gap;
    let list_h = (h - m - 2 * bh - gap - m - sh - m).max(sc(60));
    MoveWindow(hwnd(&H_LIST), m, m, w - 2 * m, list_h, 1);

    let row1_y = m + list_h + m;
    let row2_y = row1_y + row2_y_offset;

    // Baris 1: 5 tombol (password/expired/cek password)
    let row1 = [ID_DEL, ID_PASS, ID_ACCT, ID_ALL, ID_CHECKPW];
    let bw1 = (w - 2 * m - (row1.len() as i32 - 1) * gap) / row1.len() as i32;
    for (i, id) in row1.iter().enumerate() {
        if let Some(pos) = BTN_IDS.iter().position(|x| x == id) {
            MoveWindow(hwnd(&H_BTN[pos]), m + i as i32 * (bw1 + gap), row1_y, bw1, bh, 1);
        }
    }
    // Baris 2: 4 tombol (aktif/nonaktif/hapus/restore) + Refresh
    let row2 = [ID_ENABLE, ID_DISABLE, ID_DELACC, ID_RESTORE];
    let bw2 = (w - 2 * m - row2.len() as i32 * gap) / (row2.len() as i32 + 1);
    for (i, id) in row2.iter().enumerate() {
        if let Some(pos) = BTN_IDS.iter().position(|x| x == id) {
            MoveWindow(hwnd(&H_BTN[pos]), m + i as i32 * (bw2 + gap), row2_y, bw2, bh, 1);
        }
    }
    MoveWindow(hwnd(&REFRESH_BTN), m + row2.len() as i32 * (bw2 + gap), row2_y, bw2, bh, 1);

    MoveWindow(hwnd(&H_STATUS), m, row2_y + bh + m / 2, w - 2 * m, sh, 1);
}

unsafe extern "system" fn wndproc(h: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    match msg {
        WM_CREATE => {
            create_controls(h);
            layout(h);
            SetTimer(h, TIMER_UPDATE, UPDATE_EVERY_MS, None);
            start_update_check(h);
            0
        }
        WM_TIMER => {
            if wp == TIMER_UPDATE {
                start_update_check(h);
            }
            0
        }
        WM_UPDATE_DONE => {
            let msg = UPDATE_MSG.lock().unwrap().clone();
            match wp {
                1 => {
                    let q = format!("Update PwAkun v{} sudah terpasang.\n\nMulai ulang sekarang?", msg);
                    if MessageBoxW(h, wide(&q).as_ptr(), wide("Update").as_ptr(), MB_YESNO | MB_ICONINFORMATION) == IDYES {
                        update::relaunch();
                        DestroyWindow(h);
                    } else {
                        set_status(&format!("Update v{} terpasang, aktif setelah aplikasi dibuka ulang.", msg));
                    }
                }
                2 => set_status(&format!("Cek update gagal: {}.", msg)),
                _ => {}
            }
            0
        }
        WM_SIZE => {
            layout(h);
            0
        }
        WM_GETMINMAXINFO => {
            let mm = &mut *(lp as *mut MINMAXINFO);
            mm.ptMinTrackSize.x = sc(760);
            mm.ptMinTrackSize.y = sc(400);
            0
        }
        WM_COMMAND => {
            let id = (wp & 0xFFFF) as isize;
            match id {
                ID_REF => refresh(),
                ID_DEL | ID_PASS | ID_ACCT | ID_ALL => run(h, id),
                ID_CHECKPW => check_passwords(h),
                ID_ENABLE => toggle_enabled(h, true),
                ID_DISABLE => toggle_enabled(h, false),
                ID_DELACC => delete_accounts(h),
                ID_RESTORE => restore_builtin_admin(h),
                _ => {}
            }
            0
        }
        WM_DESTROY => {
            KillTimer(h, TIMER_UPDATE);
            DeleteObject(H_FONT.load(Relaxed) as HGDIOBJ);
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(h, msg, wp, lp),
    }
}

fn main() {
    update::cleanup();
    unsafe {
        let dc = GetDC(null_mut());
        DPI.store(GetDeviceCaps(dc, LOGPIXELSX as i32), Relaxed);
        ReleaseDC(null_mut(), dc);

        let icc = INITCOMMONCONTROLSEX {
            dwSize: size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_LISTVIEW_CLASSES,
        };
        InitCommonControlsEx(&icc);

        let hinst = GetModuleHandleW(null());
        let class = wide("PwAkunWindow");
        let wc = WNDCLASSEXW {
            cbSize: size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wndproc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinst,
            hIcon: null_mut(),
            hCursor: LoadCursorW(null_mut(), IDC_ARROW),
            hbrBackground: (COLOR_BTNFACE + 1) as usize as HBRUSH,
            lpszMenuName: null(),
            lpszClassName: class.as_ptr(),
            hIconSm: null_mut(),
        };
        RegisterClassExW(&wc);

        let main = CreateWindowExW(
            0,
            class.as_ptr(),
            wide(&format!("PwAkun v{} - Pengatur Akun Windows", update::VERSION)).as_ptr(),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            sc(900),
            sc(560),
            null_mut(),
            null_mut(),
            hinst,
            null(),
        );
        if main.is_null() {
            return;
        }

        let mut msg: MSG = zeroed();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}
