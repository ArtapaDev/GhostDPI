@echo off
rem GhostDPI manual launcher: runs the engine in a console window without installing a service.
rem Closing the window stops GhostDPI immediately. Copyright (c) 2026 Artapa.
start "" "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0app\panel.ps1" -Manual
