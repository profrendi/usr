@echo off
REM Butuh Rust (https://rustup.rs) dan Visual Studio Build Tools (C++).
cargo build --release
if %errorlevel% neq 0 (echo Build gagal & pause & exit /b 1)
copy /y target\release\pwakun.exe "%~dp0PwAkun.exe" >nul
echo Selesai: PwAkun.exe
pause
