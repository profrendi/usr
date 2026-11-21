# PwAkun

Aplikasi kecil (Rust, Win32 murni) untuk mengatur akun lokal Windows 10/11.

- Unduh `PwAkun.exe` dari [Releases](https://github.com/profrendi/usr/releases/latest), jalankan (Windows meminta izin Administrator).
- Tidak perlu instalasi dan tidak butuh VC++ Redistributable (runtime ikut di dalam exe).
- Update otomatis: saat dibuka dan tiap 6 jam, aplikasi mengecek `latest.json` di rilis terbaru, memverifikasi SHA-256, lalu mengganti dirinya sendiri.

## Fitur

**Daftar akun** menampilkan kolom Nama, Status (Aktif/Nonaktif), Password, Pass expired, dan Akun expired.

- **Hapus password** - mengosongkan password satu/lebih akun terpilih.
- **Pass tanpa expired** / **Akun tanpa expired** / **Lakukan semua** - seperti sebelumnya.
- **Cek password** - mengecek apakah password akun kosong atau tidak, dengan mencoba login lokal menggunakan password kosong (`LogonUserW`). Hasilnya hanya **"Kosong"** atau **"Ada"**, **bukan isi password sebenarnya** - Windows tidak pernah menyimpan password dalam bentuk yang bisa dibaca ulang (hanya hash satu arah), jadi tidak ada cara sah untuk menampilkan isi password yang sudah ada. Fitur ini meminta konfirmasi dulu karena terhitung sebagai percobaan login gagal untuk akun yang memang berpassword (relevan bila ada kebijakan *account lockout*).
- **Aktifkan** / **Nonaktifkan** - mengubah status aktif akun terpilih.
- **Hapus akun** - menghapus akun terpilih, dengan konfirmasi. Akun berikut selalu dilindungi dan tidak akan terhapus: akun yang sedang dipakai sesi berjalan, akun bawaan Windows (Administrator/RID 500, Guest/RID 501, DefaultAccount/RID 503, WDAGUtilityAccount/RID 504), dan akun admin aktif terakhir yang tersisa.
- **Pulihkan admin bawaan** - mencari akun Administrator bawaan lewat SID yang berakhiran `-500` (jadi tetap ketemu walau namanya sudah diganti), lalu: mengembalikan namanya ke "Administrator", mengaktifkan akun dan membuatnya tidak pernah kedaluwarsa, memasukkannya ke grup Administrators (dicari lewat SID S-1-5-32-544 agar tidak tergantung bahasa Windows), dan menampilkannya kembali di layar login bila sempat disembunyikan lewat registry.

## Rilis
Push ke `main` dengan versi baru di `Cargo.toml` -> GitHub Actions membangun dan menerbitkan rilis (exe + `latest.json`) otomatis.
Kalau versi tidak dinaikkan, build tetap berjalan tetapi rilis dilewati.

## Catatan & batasan
- Password kosong tidak bisa dipakai login lewat jaringan/Remote Desktop (aturan bawaan Windows).
- Akun Microsoft (login dengan email) dikelola dari akun online-nya; sebagian aksi di sini tidak berlaku untuknya.
- Fitur "Cek password" bisa gagal dengan "tidak bisa dicek" di PC yang bergabung ke domain dan menerapkan kebijakan "Deny access to this computer from the network" untuk akun lokal/admin - itu normal, bukan bug.
- Group Policy di PC kantor dapat mengembalikan perubahan.
