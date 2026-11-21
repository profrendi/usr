# PwAkun

Aplikasi kecil (Rust, Win32 murni) untuk akun lokal Windows 10/11: **hapus password**, **password tanpa expired**, dan **akun tanpa expired** untuk satu atau beberapa akun sekaligus.

- Unduh `PwAkun.exe` dari [Releases](https://github.com/profrendi/usr/releases/latest), jalankan (Windows meminta izin Administrator).
- Tidak perlu instalasi dan tidak butuh VC++ Redistributable (runtime ikut di dalam exe).
- Update otomatis: saat dibuka dan tiap 6 jam, aplikasi mengecek `latest.json` di rilis terbaru, memverifikasi SHA-256, lalu mengganti dirinya sendiri.

## Rilis
Push ke `main` dengan versi baru di `Cargo.toml` -> GitHub Actions membangun dan menerbitkan rilis (exe + `latest.json`) otomatis.
Kalau versi tidak dinaikkan, build tetap berjalan tetapi rilis dilewati.

## Catatan
- Password kosong tidak bisa dipakai login lewat jaringan/Remote Desktop (aturan bawaan Windows).
- Akun Microsoft (login dengan email) dikelola dari akun online-nya.
- Group Policy di PC kantor dapat mengembalikan perubahan.
