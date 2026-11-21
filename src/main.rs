#![windows_subsystem = "windows"]
//! PwAkun - pengatur akun lokal Windows (hapus password, tanpa expired).
//! Native Win32 murni: tanpa framework UI, tanpa thread tambahan -> start instan, RAM kecil.

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
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Controls::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

const ID_DEL: isize = 101; // hapus password
const ID_PASS: isize = 102; // password tanpa expired
const ID_ACCT: isize = 103; // akun tanpa expired
const ID_ALL: isize = 104; // semuanya
const ID_REF: isize = 105; // refresh
const WM_UPDATE_DONE: u32 = WM_APP + 1;
const TIMER_UPDATE: usize = 1;
const UPDATE_EVERY_MS: u32 = 6 * 60 * 60 * 1000;

const ERR_PASSWORD_TOO_SHORT: u32 = 2245;
const TIMEQ_FOREVER: u32 = u32::MAX;
const SS_LEFT_: u32 = 0;
const SS_ENDELLIPSIS_: u32 = 0x4000;
const UF_ACCOUNTDISABLE_: u32 = 0x0002;
const UF_DONT_EXPIRE_PASSWD_: u32 = 0x10000;

static H_LIST: AtomicIsize = AtomicIsize::new(0);
static H_STATUS: AtomicIsize = AtomicIsize::new(0);
static H_FONT: AtomicIsize = AtomicIsize::new(0);
static H_BTN: [AtomicIsize; 5] = [
    AtomicIsize::new(0),
    AtomicIsize::new(0),
    AtomicIsize::new(0),
    AtomicIsize::new(0),
    AtomicIsize::new(0),
];
static DPI: AtomicI32 = AtomicI32::new(96);
static CHECKING: AtomicBool = AtomicBool::new(false);
static UPDATE_MSG: Mutex<String> = Mutex::new(String::new());

thread_local! {
    static NAMES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
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

unsafe fn refresh() {
    let list = hwnd(&H_LIST);
    SendMessageW(list, WM_SETREDRAW, 0, 0);
    SendMessageW(list, LVM_DELETEALLITEMS, 0, 0);
    NAMES.with(|n| n.borrow_mut().clear());

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
            lv_set(list, row, 0, &name, true);
            lv_set(list, row, 1, if u.usri2_flags & UF_ACCOUNTDISABLE_ != 0 { "Nonaktif" } else { "Aktif" }, false);
            lv_set(
                list,
                row,
                2,
                if u.usri2_flags & UF_DONT_EXPIRE_PASSWD_ != 0 { "Tidak pernah" } else { "Bisa expired" },
                false,
            );
            let acct = if u.usri2_acct_expires == TIMEQ_FOREVER {
                "Tidak pernah".to_string()
            } else {
                ymd(u.usri2_acct_expires)
            };
            lv_set(list, row, 3, &acct, false);
            NAMES.with(|n| n.borrow_mut().push(name));
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

unsafe fn selected() -> Vec<String> {
    let list = hwnd(&H_LIST);
    let mut out = Vec::new();
    let mut idx: isize = -1;
    loop {
        idx = SendMessageW(list, LVM_GETNEXTITEM, idx as WPARAM, LVNI_SELECTED as LPARAM);
        if idx < 0 {
            break;
        }
        NAMES.with(|n| {
            if let Some(s) = n.borrow().get(idx as usize) {
                out.push(s.clone());
            }
        });
    }
    out
}

// ---------- operasi akun ----------
unsafe fn set_empty_password(name: &[u16]) -> u32 {
    let mut empty = [0u16; 1];
    let info = USER_INFO_1003 { usri1003_password: empty.as_mut_ptr() };
    NetUserSetInfo(null(), name.as_ptr(), 1003, &info as *const _ as *const u8, null_mut())
}

unsafe fn set_password_never_expires(name: &[u16]) -> u32 {
    let mut buf: *mut u8 = null_mut();
    let rc = NetUserGetInfo(null(), name.as_ptr(), 1, &mut buf);
    if rc != 0 {
        return rc;
    }
    let flags = (*(buf as *const USER_INFO_1)).usri1_flags;
    NetApiBufferFree(buf as *const c_void);
    let info = USER_INFO_1008 { usri1008_flags: flags | UF_DONT_EXPIRE_PASSWD_ };
    NetUserSetInfo(null(), name.as_ptr(), 1008, &info as *const _ as *const u8, null_mut())
}

unsafe fn set_account_never_expires(name: &[u16]) -> u32 {
    let info = USER_INFO_1017 { usri1017_acct_expires: TIMEQ_FOREVER };
    NetUserSetInfo(null(), name.as_ptr(), 1017, &info as *const _ as *const u8, null_mut())
}

unsafe fn allow_blank_passwords() -> u32 {
    let info = USER_MODALS_INFO_1001 { usrmod1001_min_passwd_len: 0 };
    NetUserModalsSet(null(), 1001, &info as *const _ as *const u8, null_mut())
}

fn err_text(code: u32) -> String {
    match code {
        5 => "akses ditolak".into(),
        2221 => "akun tidak ditemukan".into(),
        ERR_PASSWORD_TOO_SHORT => "kebijakan panjang password minimum".into(),
        2243 => "password tidak bisa diubah".into(),
        2244 | 2246 => "ditolak kebijakan password".into(),
        c => format!("kode {}", c),
    }
}

unsafe fn run(hwnd_main: HWND, id: isize) {
    let names = selected();
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
    let cols = [("Nama akun", 200), ("Status", 90), ("Password expired", 150), ("Akun expired", 130)];
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
        (ID_REF, "Refresh"),
    ];
    for (i, (id, text)) in labels.iter().enumerate() {
        let b = child("BUTTON", text, WS_TABSTOP | BS_PUSHBUTTON as u32, 0, parent, *id);
        SendMessageW(b, WM_SETFONT, font as WPARAM, 1);
        H_BTN[i].store(b as isize, Relaxed);
    }
    let st = child("STATIC", "", SS_LEFT_ | SS_ENDELLIPSIS_, 0, parent, 2);
    SendMessageW(st, WM_SETFONT, font as WPARAM, 1);
    SendMessageW(list, WM_SETFONT, font as WPARAM, 1);
    H_STATUS.store(st as isize, Relaxed);

    refresh();
}

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
    let list_h = (h - m - bh - m - sh - m).max(sc(60));
    MoveWindow(hwnd(&H_LIST), m, m, w - 2 * m, list_h, 1);
    let by = m + list_h + m;
    let bw = (w - 2 * m - 4 * gap) / 5;
    for i in 0..5 {
        MoveWindow(hwnd(&H_BTN[i]), m + i as i32 * (bw + gap), by, bw, bh, 1);
    }
    MoveWindow(hwnd(&H_STATUS), m, by + bh + m / 2, w - 2 * m, sh, 1);
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
            mm.ptMinTrackSize.x = sc(700);
            mm.ptMinTrackSize.y = sc(320);
            0
        }
        WM_COMMAND => {
            let id = (wp & 0xFFFF) as isize;
            if id == ID_REF {
                refresh();
            } else if (ID_DEL..ID_REF).contains(&id) {
                run(h, id);
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
            wide(&format!("PwAkun v{} - Hapus Password & Tanpa Expired", update::VERSION)).as_ptr(),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            sc(820),
            sc(480),
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
