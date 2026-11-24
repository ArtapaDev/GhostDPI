# GhostDPI

GhostDPI opens websites blocked by your internet provider's DPI (Deep Packet Inspection) or DNS
filters. It is not a VPN: your traffic still goes straight to the destination server, so speed
and ping stay unchanged. It uses about 9–10 MB of memory and almost no CPU.

© 2026 Artapa (MIT License, see `LICENSE`). GhostDPI uses its own C engine on top of the
[WinDivert](https://github.com/basil00/WinDivert) packet driver (LGPL-3.0, see `licenses/`).

## Requirements
- Windows 10 or 11, 64-bit, with an administrator account.
- Kaspersky blocks the WinDivert packet driver; uninstall it before using GhostDPI.

## Quick start (what to click)

After extracting GhostDPI, you only ever need these three launchers in the main folder:

| File | Purpose |
|---|---|
| `GhostDPI.cmd` | Opens the control panel to install, repair, diagnose, or configure GhostDPI. |
| `GhostDPI-Manual.cmd` | Runs GhostDPI in a standalone console window without installing a service (close the window to stop). |
| `GhostDPI-Tray.cmd` | Opens an optional status icon next to the Windows clock (Start/Stop, Manual, Panel, Diagnostics). |

### Option A — Background service (automatic with Windows)
1. Double-click `GhostDPI.cmd` and accept the administrator prompt.
2. Press **1** (**Install**).
3. When the final check reports access works cleanly, restart any app that was already open.

### Option B — Manual window (no install)
Double-click `GhostDPI-Manual.cmd` (or press **2** in the panel) and accept the administrator
prompt. GhostDPI stays active only while that console window is open; closing the window (or
pressing `Ctrl+C`) stops DPI bypass immediately and leaves no service behind.

## Language
The control panel, manual runner and system tray default to **English**, automatically switch to
**Turkish** when Windows is set to Turkish, and can be switched manually anytime under
**Advanced → Language** (or via `app\panel.ps1 -Lang en` / `-Lang tr`).

## Control panel

| Key | Item | What it does |
|---|---|---|
| 1 | Install / Repair | Measures which preset works (including automatic TTL tuning if needed) and installs the Windows service. |
| 2 | Manual run | Opens a separate console window without installing; closing that window stops GhostDPI. |
| 3 | Diagnostics | Checks ping, packet loss, IPv6, DNS, HTTPS, blocked sites, clock, proxy, VPN, other DPI tools and GhostDPI; copies an anonymized report to the clipboard. |
| 4 | Site test | Tests whether a domain opens and diagnoses DNS blocks, DPI blocks, certificate interception, or IP blocks. |
| 5 | Stop / Start | Temporarily stops or starts the installed Windows service. |
| 6 | Advanced | DNS protection, DNS profile (Standard, Ad-blocking via AdGuard, Cloudflare, Google, Quad9), QUIC filter, preset selection, site exclude/include lists, language, system tray, shortcuts and service log. |
| 7 | Check updates | Checks GitHub for a newer GhostDPI release. |
| 8 | Uninstall | Removes the Windows service, Program Files copy and shortcuts completely. |

All probes open a verified TLS handshake and close immediately without requesting a page or
launching any application.

## How it works
- **DPI blocks:** the engine splits the first packet of each TLS/HTTP connection after
  randomized decoy packets that the destination server discards, preventing inline filters from
  reading the target hostname. Subsequent packets never leave the kernel. You can exclude
  specific domains (banking, anti-cheat) or limit DPI bypass to a selected domain list.
- **DNS blocks:** public lookups are answered over encrypted DNS-over-HTTPS by IP (`standard`:
  Cloudflare/Google/Quad9; `adblock`: AdGuard DNS; or single providers). Local/LAN names and
  Tailscale MagicDNS stay on the local resolver, and unreachable DoH falls back cleanly.
- **QUIC:** only QUIC Initial packets (UDP 443, RFC 9000 Long Header ≥ 1200 B) are dropped
  inside the kernel driver so browsers fall back to TCP without affecting other UDP 443 apps.
- **Safety:** installs to `C:\Program Files\GhostDPI` (administrators only) and verifies SHA-256
  fingerprints before every install, service start and manual launch. Rolls back to the previous
  service if setup fails.
- **Reliability:** automatic service recovery on crash plus a capped 32 KB event/error log
  (`engine-error.log`).

## Folder layout

```
GhostDPI/
├── GhostDPI.cmd           # Control panel launcher
├── GhostDPI-Manual.cmd    # No-install manual window launcher
├── GhostDPI-Tray.cmd      # Optional system tray launcher
├── app/                   # Control panel, tray script and language dictionary
├── bin/                   # Compiled engine and signed WinDivert packet driver
├── licenses/              # Third-party license (WinDivert LGPL-3.0)
├── engine/                # C engine source code (developers)
├── scripts/               # Build and release packaging scripts (developers)
└── vendor/                # WinDivert SDK headers (developers)
```

## Building and packaging
Install Visual Studio C++ Build Tools (x64), then run:
- `scripts\build.ps1` — compiles `bin\ghostdpi-engine.exe` (`/W4 /sdl /guard:cf`), runs its
  24-check self-test and updates the SHA-256 fingerprints in `app\panel.ps1`.
- `scripts\package.ps1` — verifies all hashes and encoding, then creates a clean, shareable
  `dist\GhostDPI-<version>-win64.zip` archive and `.sha256` file.
