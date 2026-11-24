#Requires -Version 5.1
<#
    GhostDPI - optional system tray status icon.
    Copyright (c) 2026 Artapa. MIT License (LICENSE).

    Starts only when opened by the user; shows service/manual status next to the clock
    and offers quick Start/Stop, manual window, panel and diagnostics shortcuts.
    UI language defaults to English, switches to Turkish on Turkish Windows, and follows
    the language setting in state.json / portable-state.json.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'SilentlyContinue'

$mutexCreated = $false
$mutex = New-Object System.Threading.Mutex($true, 'Local\GhostDPI_Tray_Artapa', [ref]$mutexCreated)
if (-not $mutexCreated) { return }

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class GhostTrayNative {
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool DestroyIcon(IntPtr hIcon);
}
'@

[System.Windows.Forms.Application]::EnableVisualStyles()

$ServiceName = 'GhostDPI'
$AppVersion  = '1.2.0'
$ScriptDir   = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$RootDir     = if ((Split-Path -Leaf $ScriptDir) -eq 'app') { Split-Path -Parent $ScriptDir } else { $ScriptDir }
$InstallDir  = Join-Path $env:ProgramFiles 'GhostDPI'
$PowerShell  = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$PanelScript = if (Test-Path -LiteralPath (Join-Path $ScriptDir 'panel.ps1')) {
    Join-Path $ScriptDir 'panel.ps1'
} else {
    Join-Path $InstallDir 'app\panel.ps1'
}

$LangFile = @(
    (Join-Path $ScriptDir 'lang.json'),
    (Join-Path $InstallDir 'app\lang.json')
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
$LangDict = if ($LangFile) { [IO.File]::ReadAllText($LangFile, [Text.Encoding]::UTF8) | ConvertFrom-Json } else { $null }

function Get-TrayLang {
    $pref = 'auto'
    foreach ($sf in (Join-Path $InstallDir 'state.json'), (Join-Path $RootDir 'portable-state.json')) {
        if (Test-Path -LiteralPath $sf) {
            try {
                $s = [IO.File]::ReadAllText($sf, [Text.Encoding]::UTF8) | ConvertFrom-Json
                if ($s.PSObject.Properties['lang'] -and $s.lang -in @('en', 'tr', 'auto')) { $pref = $s.lang }
                break
            } catch { }
        }
    }
    if ($pref -in @('en', 'tr')) { return $pref }
    try {
        if ([Globalization.CultureInfo]::CurrentUICulture.TwoLetterISOLanguageName -eq 'tr') { return 'tr' }
    } catch { }
    return 'en'
}

function TT([string]$LangCode, [string]$Key, [object[]]$FmtArgs = @()) {
    $val = $Key
    if ($LangDict) {
        $pack = $LangDict.$LangCode
        if ($pack -and $pack.PSObject.Properties[$Key]) { $val = [string]$pack.$Key }
        elseif ($LangDict.en.PSObject.Properties[$Key]) { $val = [string]$LangDict.en.$Key }
    }
    if ($FmtArgs -and $FmtArgs.Count -gt 0) { return ($val -f $FmtArgs) }
    return $val
}

function New-StatusIcon([System.Drawing.Color]$Color) {
    $bmp = New-Object System.Drawing.Bitmap(16, 16)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.Clear([System.Drawing.Color]::Transparent)
    $ring = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(220, 20, 24, 30), 1.5)
    $fill = New-Object System.Drawing.SolidBrush($Color)
    $g.FillEllipse($fill, 2, 2, 12, 12)
    $g.DrawEllipse($ring, 2, 2, 12, 12)
    $g.Dispose(); $fill.Dispose(); $ring.Dispose()
    $hIcon = $bmp.GetHicon()
    $icon = [System.Drawing.Icon]::FromHandle($hIcon).Clone()
    [void][GhostTrayNative]::DestroyIcon($hIcon)
    $bmp.Dispose()
    return $icon
}

$IconGreen = New-StatusIcon ([System.Drawing.Color]::FromArgb(34, 197, 94))
$IconBlue  = New-StatusIcon ([System.Drawing.Color]::FromArgb(56, 189, 248))
$IconRed   = New-StatusIcon ([System.Drawing.Color]::FromArgb(239, 68, 68))

$initLang = Get-TrayLang
$menu = New-Object System.Windows.Forms.ContextMenuStrip
$miStatus = New-Object System.Windows.Forms.ToolStripMenuItem (TT $initLang 'tray_checking')
$miStatus.Enabled = $false
$miToggle = New-Object System.Windows.Forms.ToolStripMenuItem (TT $initLang 'tray_start_svc')
$miManual = New-Object System.Windows.Forms.ToolStripMenuItem (TT $initLang 'tray_open_man')
$miPanel  = New-Object System.Windows.Forms.ToolStripMenuItem (TT $initLang 'tray_open_panel')
$miDiag   = New-Object System.Windows.Forms.ToolStripMenuItem (TT $initLang 'tray_diag')
$miExit   = New-Object System.Windows.Forms.ToolStripMenuItem (TT $initLang 'tray_exit')

[void]$menu.Items.Add($miStatus)
[void]$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))
[void]$menu.Items.Add($miToggle)
[void]$menu.Items.Add($miManual)
[void]$menu.Items.Add($miPanel)
[void]$menu.Items.Add($miDiag)
[void]$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))
[void]$menu.Items.Add($miExit)

$notify = New-Object System.Windows.Forms.NotifyIcon
$notify.Icon = $IconRed
$notify.Text = "GhostDPI $AppVersion"
$notify.ContextMenuStrip = $menu
$notify.Visible = $true

function Update-TrayState {
    $lg = Get-TrayLang
    $miManual.Text = TT $lg 'tray_open_man'
    $miPanel.Text  = TT $lg 'tray_open_panel'
    $miDiag.Text   = TT $lg 'tray_diag'
    $miExit.Text   = TT $lg 'tray_exit'

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $proc = Get-Process -Name 'ghostdpi-engine' -ErrorAction SilentlyContinue | Select-Object -First 1
    $mem = if ($proc) { ' ({0:N1} MB)' -f ($proc.WorkingSet64 / 1MB) } else { '' }

    if ($svc -and $svc.Status -eq 'Running') {
        $notify.Icon = $IconGreen
        $miStatus.Text = TT $lg 'tray_st_svc' @($mem)
        $miToggle.Text = TT $lg 'tray_stop_svc'
        $miToggle.Enabled = $true
        $tip = TT $lg 'tray_tip_run' @($AppVersion, $mem)
    } elseif ($proc) {
        $notify.Icon = $IconBlue
        $miStatus.Text = TT $lg 'tray_st_man' @($mem)
        $miToggle.Text = if ($svc) { TT $lg 'tray_start_svc' } else { TT $lg 'tray_no_svc' }
        $miToggle.Enabled = $false
        $tip = TT $lg 'tray_tip_man' @($AppVersion, $mem)
    } elseif ($svc) {
        $notify.Icon = $IconRed
        $miStatus.Text = TT $lg 'tray_st_stop'
        $miToggle.Text = TT $lg 'tray_start_svc'
        $miToggle.Enabled = $true
        $tip = TT $lg 'tray_tip_stop' @($AppVersion)
    } else {
        $notify.Icon = $IconRed
        $miStatus.Text = TT $lg 'tray_st_none'
        $miToggle.Text = TT $lg 'tray_no_svc'
        $miToggle.Enabled = $false
        $tip = TT $lg 'tray_tip_none' @($AppVersion)
    }
    if ($tip.Length -gt 63) { $tip = $tip.Substring(0, 63) }
    $notify.Text = $tip
}

$miToggle.Add_Click({
    Start-Process -FilePath $PowerShell -WindowStyle Hidden `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PanelScript`" -ToggleService"
})
$miManual.Add_Click({
    Start-Process -FilePath $PowerShell `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PanelScript`" -Manual"
})
$miPanel.Add_Click({
    Start-Process -FilePath $PowerShell `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PanelScript`""
})
$miDiag.Add_Click({
    Start-Process -FilePath $PowerShell `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PanelScript`" -Diagnostics"
})
$notify.Add_DoubleClick({
    Start-Process -FilePath $PowerShell `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PanelScript`""
})

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 3000
$timer.Add_Tick({ Update-TrayState })

$miExit.Add_Click({
    $timer.Stop()
    $notify.Visible = $false
    [System.Windows.Forms.Application]::Exit()
})

Update-TrayState
$timer.Start()

try {
    [System.Windows.Forms.Application]::Run()
} finally {
    $timer.Dispose()
    $notify.Visible = $false
    $notify.Dispose()
    $IconGreen.Dispose()
    $IconBlue.Dispose()
    $IconRed.Dispose()
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
