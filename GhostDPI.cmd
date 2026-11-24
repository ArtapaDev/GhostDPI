@echo off
rem GhostDPI launcher: opens the control panel (asks for administrator rights).
rem Copyright (c) 2026 Artapa.
start "" "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0app\panel.ps1"
