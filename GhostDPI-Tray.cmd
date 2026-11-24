@echo off
rem GhostDPI system tray launcher: shows a small status icon next to the clock.
rem Copyright (c) 2026 Artapa.
start "" /b "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0app\tray.ps1"
