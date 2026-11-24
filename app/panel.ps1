#Requires -Version 5.1
<#
    GhostDPI - control panel, installer and manual runner.
    Copyright (c) 2026 Artapa. MIT License (LICENSE).

    The engine (engine/, built into bin/ghostdpi-engine.exe) is GhostDPI's own; it runs on the
    WinDivert packet driver (LGPL-3.0, licenses/). This script installs it as the "GhostDPI"
    Windows service in Program Files (writable by administrators only), runs it on demand in a
    separate console window without installing, picks a working strategy by measuring quietly,
    and runs the diagnostics.

    UI language defaults to English, automatically switches to Turkish on Turkish Windows, and
    can be overridden in Advanced -> Language or via -Lang (en / tr).

    Switches
    -Status         Print the status panel and exit (no administrator rights needed).
    -Manual         Run the engine directly in this console window (closes when window closes).
    -VerboseEngine  With -Manual: show live per-domain activity in the manual window.
    -Diagnostics    Run network diagnostics directly and wait for a key.
    -ToggleService  Start or stop the installed service safely (used by the tray helper).
    -Lang           Override UI language for this run ('en' or 'tr').
#>
[CmdletBinding()]
param(
    [switch]$Status,
    [switch]$Manual,
    [switch]$VerboseEngine,
    [switch]$Diagnostics,
    [switch]$ToggleService,
    [ValidateSet('', 'en', 'tr')][string]$Lang = ''
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- settings

$AppName     = 'GhostDPI'
$AppVersion  = '1.2.0'
$Owner       = 'Artapa'
$ServiceName = 'GhostDPI'
$EngineExe   = 'ghostdpi-engine.exe'
$ScriptDir   = if ($PSScriptRoot) { $PSScriptRoot } elseif (Test-Path -LiteralPath (Join-Path (Get-Location).Path 'app\panel.ps1')) { Join-Path (Get-Location).Path 'app' } else { (Get-Location).Path }
$RootDir     = if ((Split-Path -Leaf $ScriptDir) -eq 'app') { Split-Path -Parent $ScriptDir } else { $ScriptDir }
$InstallDir  = Join-Path $env:ProgramFiles 'GhostDPI'
$StateFile   = Join-Path $InstallDir 'state.json'
$PortableStateFile = Join-Path $RootDir 'portable-state.json'
$LogFile     = Join-Path $InstallDir 'engine-error.log'
$Curl        = Join-Path $env:SystemRoot 'System32\curl.exe'
$PowerShell  = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$StartMenuDir = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\GhostDPI'
$ProbeTimeoutMs = 4000

# GitHub repository ("owner/repo") for manual update checks.
$UpdateRepo = 'ArtapaDev/GhostDPI'

# SHA-256 of the files in bin/, written by scripts/build.ps1. A file that does not match is never run.
# BEGIN ENGINE HASHES
$EngineFiles = [ordered]@{
    'ghostdpi-engine.exe' = '84216b028ef55b4e879534919d20c2d364a1f5030555d9ef9779417a35e8e5d4'
    'WinDivert.dll'       = '6110bfa44667405179c3e15e12af1b62037e447ed59b054b19042032995e6c7e'
    'WinDivert64.sys'     = 'e69b5ba3f0cd6cfb2983e442636e7f0b342b61b15264b0328317d4559c82cf50'
}
# END ENGINE HASHES

# Strategies, most likely to work first. Display names live in lang.json (strat_0..strat_6).
$Strategies = @(
    @{ Key = 'strat_0'; Args = '--fake-badsum --fake-badseq --fake-ttl 5' },
    @{ Key = 'strat_1'; Args = '--fake-ttl 5' },
    @{ Key = 'strat_2'; Args = '--split-sni --fake-badsum --fake-badseq --fake-repeat 2' },
    @{ Key = 'strat_3'; Args = '--split-sni' },
    @{ Key = 'strat_4'; Args = '--fake-badsum --fake-badseq' },
    @{ Key = 'strat_5'; Args = '' },
    @{ Key = 'strat_6'; Args = '--split 0 --fake-ttl 3' }
)

# Extra TTL values tried automatically if none of the standard presets pass every probe site.
$AutoTtlCandidates = @(3, 4, 6, 7, 8)

$DnsProfileKeys = @('standard', 'adblock', 'cloudflare', 'google', 'quad9')

# Hosts commonly blocked by ISPs; measured quietly, never shown by name.
$DefaultProbeHosts = @(
    'discord.com', 'gateway.discord.gg', 'cdn.discordapp.com', 'www.roblox.com', 'tr.rbxcdn.com'
)
# Neutral hosts that answer everywhere; they separate "no internet" from "blocked".
$ControlHosts = @('www.cloudflare.com', 'www.google.com')

# Leftovers of earlier setups, removed on install and uninstall.
$LegacyServices = @('GoodbyeDPI')
$DriverServices = @('WinDivert', 'WinDivert14')
$LegacyTasks    = @('GhostDPI DNS')
$OtherDpiTools  = @('goodbyedpi', 'winws', 'byedpi', 'ciadpi', 'spoofdpi', 'zapret')

# ---------------------------------------------------------------- localization

$script:LangDict = $null
$script:UiLang = 'en'

function Get-SystemUiLang {
    try {
        if ([Globalization.CultureInfo]::CurrentUICulture.TwoLetterISOLanguageName -eq 'tr') { return 'tr' }
    } catch { }
    return 'en'
}

function Initialize-Language([string]$Preference = 'auto') {
    if (-not $script:LangDict) {
        $candidates = @(
            (Join-Path $ScriptDir 'lang.json'),
            (Join-Path $InstallDir 'app\lang.json')
        )
        $file = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
        if (-not $file) { throw 'Language dictionary (app\lang.json) not found.' }
        $script:LangDict = [IO.File]::ReadAllText($file, [Text.Encoding]::UTF8) | ConvertFrom-Json
    }
    if ($Lang -in @('en', 'tr')) {
        $script:UiLang = $Lang
    } elseif ($Preference -in @('en', 'tr')) {
        $script:UiLang = $Preference
    } else {
        $script:UiLang = Get-SystemUiLang
    }
}

function T([string]$Key, [object[]]$FmtArgs = @()) {
    if (-not $script:LangDict) { Initialize-Language }
    $pack = $script:LangDict.($script:UiLang)
    $val = $null
    if ($pack -and $pack.PSObject.Properties[$Key]) { $val = [string]$pack.$Key }
    elseif ($script:LangDict.en.PSObject.Properties[$Key]) { $val = [string]$script:LangDict.en.$Key }
    else { $val = $Key }
    if ($FmtArgs -and $FmtArgs.Count -gt 0) { return ($val -f $FmtArgs) }
    return $val
}

function Get-StrategyName([int]$Index) { return (T $Strategies[$Index].Key) }
function Get-DnsShort([string]$ProfileKey) { return (T "dns_${ProfileKey}_short") }
function Get-DnsDesc([string]$ProfileKey)  { return (T "dns_${ProfileKey}_desc") }

function Get-LangSettingLabel([string]$Setting) {
    switch ($Setting) {
        'en' { return (T 'lang_en') }
        'tr' { return (T 'lang_tr') }
        default {
            if ((Get-SystemUiLang) -eq 'tr') { return (T 'lang_auto_tr') }
            return (T 'lang_auto_en')
        }
    }
}

# ---------------------------------------------------------------- output

function Write-Step([string]$Text) { Write-Host "  ► $Text" -ForegroundColor Cyan }
function Write-Ok([string]$Text)   { Write-Host "    √ $Text" -ForegroundColor Green }
function Write-Warn([string]$Text) { Write-Host "    ! $Text" -ForegroundColor Yellow }
function Write-Bad([string]$Text)  { Write-Host "    × $Text" -ForegroundColor Red }
function Write-Info([string]$Text) { Write-Host "    • $Text" -ForegroundColor Gray }

function Write-Progress-Line([string]$Text) {
    $pad = [Math]::Max(0, 62 - $Text.Length)
    Write-Host ("`r    {0}{1}" -f $Text, (' ' * $pad)) -ForegroundColor DarkGray -NoNewline
}
function Clear-Progress-Line { Write-Host ("`r" + (' ' * 68) + "`r") -NoNewline }

function Read-YesNo([string]$Question) {
    $hint = T 'yes_no_hint'
    $accept = (T 'yes_keys').ToCharArray()
    Write-Host "  $Question $hint " -ForegroundColor Yellow -NoNewline
    $key = [Console]::ReadKey($true).KeyChar
    Write-Host $key
    return ($accept -contains $key)
}

# ---------------------------------------------------------------- state and files

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-ServiceInstalled {
    return [bool](Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)
}

function Get-ActiveDataDir {
    if ((Test-ServiceInstalled) -or (Test-Path -LiteralPath $StateFile)) { return $InstallDir }
    return $RootDir
}

function Get-ActiveStateFile {
    if ((Test-ServiceInstalled) -or (Test-Path -LiteralPath $StateFile)) { return $StateFile }
    return $PortableStateFile
}

function Get-State {
    $path = Get-ActiveStateFile
    $state = $null
    if (Test-Path -LiteralPath $path) {
        try { $state = [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8) | ConvertFrom-Json } catch { }
    }
    $defaults = [ordered]@{
        version    = $AppVersion
        lang       = 'auto'
        strategy   = 0
        ttl        = 0
        dns        = $true
        dnsProfile = 'standard'
        quic       = $true
        listMode   = 'all'
        exclude    = @()
        include    = @()
        sites      = @()
    }
    $result = [ordered]@{}
    foreach ($k in $defaults.Keys) {
        if ($state -and $state.PSObject.Properties[$k]) { $result[$k] = $state.$k } else { $result[$k] = $defaults[$k] }
    }

    $lg = "$($result.lang)".ToLowerInvariant()
    if ($lg -notin @('auto', 'en', 'tr')) { $lg = 'auto' }
    $result.lang = $lg

    $idx = 0
    if ([int]::TryParse("$($result.strategy)", [ref]$idx) -and $idx -ge 0 -and $idx -lt $Strategies.Count) {
        $result.strategy = $idx
    } else {
        $result.strategy = 0
    }

    $ttl = 0
    if ([int]::TryParse("$($result.ttl)", [ref]$ttl) -and $ttl -ge 0 -and $ttl -le 64) {
        $result.ttl = $ttl
    } else {
        $result.ttl = 0
    }

    $prof = "$($result.dnsProfile)".ToLowerInvariant()
    if ($prof -eq 'adguard') { $prof = 'adblock' }
    if ($prof -notin $DnsProfileKeys) { $prof = 'standard' }
    $result.dnsProfile = $prof

    $mode = "$($result.listMode)".ToLowerInvariant()
    if ($mode -notin @('all', 'exclude', 'include')) { $mode = 'all' }
    $result.listMode = $mode

    $result.exclude = @($result.exclude | Where-Object { $_ } | Select-Object -Unique)
    $result.include = @($result.include | Where-Object { $_ } | Select-Object -Unique)
    $result.sites   = @($result.sites   | Where-Object { $_ } | Select-Object -Unique)
    return [pscustomobject]$result
}

function Save-State($State, [string]$Path = $null) {
    $target = if ($Path) { $Path } else { Get-ActiveStateFile }
    $dir = Split-Path -Parent $target
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $State.version = $AppVersion
    $State | ConvertTo-Json | Set-Content -LiteralPath $target -Encoding UTF8
}

function Sync-HostlistFiles($State, [string]$DataDir) {
    $enc = New-Object Text.UTF8Encoding $false
    foreach ($pair in @(
        @{ File = 'exclude.txt'; Items = @($State.exclude) },
        @{ File = 'include.txt'; Items = @($State.include) }
    )) {
        $p = Join-Path $DataDir $pair.File
        if ($pair.Items.Count -gt 0) {
            if (-not (Test-Path -LiteralPath $DataDir)) { New-Item -ItemType Directory -Path $DataDir -Force | Out-Null }
            [IO.File]::WriteAllText($p, (($pair.Items -join "`r`n") + "`r`n"), $enc)
        } elseif (Test-Path -LiteralPath $p) {
            Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-EngineSourceDir {
    $bin = Join-Path $RootDir 'bin'
    if (Test-Path -LiteralPath (Join-Path $bin $EngineExe)) { return $bin }
    return $RootDir
}

function Test-EngineFiles([string]$Dir) {
    foreach ($file in $EngineFiles.Keys) {
        $path = Join-Path $Dir $file
        if (-not $EngineFiles[$file] -or -not (Test-Path -LiteralPath $path)) { return $false }
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $EngineFiles[$file]) { return $false }
    }
    return $true
}

function Get-StrategyLabel($State) {
    $name = Get-StrategyName ([int]$State.strategy)
    if ([int]$State.ttl -gt 0) { return "$name (TTL $($State.ttl))" }
    return $name
}

function Get-ListModeLabel($State) {
    switch ($State.listMode) {
        'exclude' { return (T 'list_exclude' @(@($State.exclude).Count)) }
        'include' { return (T 'list_include' @(@($State.include).Count)) }
        default   { return (T 'list_all') }
    }
}

function Get-EngineArgTokens(
    [int]$Strategy,
    $State,
    [int]$TtlOverride = -1,
    [string]$DataDir = $null,
    [switch]$ForService,
    [switch]$VerboseMode
) {
    $tokens = New-Object System.Collections.Generic.List[string]
    $raw = $Strategies[$Strategy].Args
    $ttl = if ($TtlOverride -ge 0) { $TtlOverride } else { [int]$State.ttl }
    $ttlReplaced = $false

    if ($raw) {
        $parts = $raw -split '\s+'
        for ($i = 0; $i -lt $parts.Count; $i++) {
            if ($parts[$i] -eq '--fake-ttl' -and ($i + 1) -lt $parts.Count) {
                $tokens.Add('--fake-ttl')
                if ($ttl -gt 0) { $tokens.Add("$ttl"); $ttlReplaced = $true }
                else            { $tokens.Add($parts[$i + 1]) }
                $i++
            } elseif ($parts[$i]) {
                $tokens.Add($parts[$i])
            }
        }
    }
    if ($ttl -gt 0 -and -not $ttlReplaced) {
        $tokens.Add('--fake-ttl')
        $tokens.Add("$ttl")
    }

    if (-not $State.dns) {
        $tokens.Add('--no-dns')
    } elseif ($State.dnsProfile -and $State.dnsProfile -ne 'standard') {
        $tokens.Add('--dns-profile')
        $tokens.Add($State.dnsProfile)
    }
    if (-not $State.quic) { $tokens.Add('--no-quic-block') }

    $dir = if ($DataDir) { $DataDir } else { Get-ActiveDataDir }
    if ($State.listMode -eq 'exclude' -and @($State.exclude).Count -gt 0) {
        $tokens.Add('--exclude-file')
        $tokens.Add((Join-Path $dir 'exclude.txt'))
    } elseif ($State.listMode -eq 'include' -and @($State.include).Count -gt 0) {
        $tokens.Add('--include-file')
        $tokens.Add((Join-Path $dir 'include.txt'))
    }

    if ($ForService) {
        $tokens.Add('--log-file')
        $tokens.Add($LogFile)
    }
    if ($VerboseMode) { $tokens.Add('--verbose') }

    return @($tokens)
}

function Format-CommandArgs([string[]]$Tokens) {
    $escaped = foreach ($t in $Tokens) {
        if ($t -match '[\s"]') { '"' + ($t -replace '"', '\"') + '"' } else { $t }
    }
    return ($escaped -join ' ').Trim()
}

function Get-EngineArgs([int]$Strategy, $State, [int]$TtlOverride = -1, [string]$DataDir = $null, [switch]$ForService) {
    $tokens = Get-EngineArgTokens -Strategy $Strategy -State $State -TtlOverride $TtlOverride -DataDir $DataDir -ForService:$ForService
    return (Format-CommandArgs $tokens)
}

function Get-ProbeHosts($State) { return @($DefaultProbeHosts + @($State.sites) | Select-Object -Unique) }

# ---------------------------------------------------------------- engine control

function Get-EngineProcess { return @(Get-Process -Name 'ghostdpi-engine' -ErrorAction SilentlyContinue) }

function Wait-Until([scriptblock]$Condition, [int]$TimeoutMs = 4000) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.ElapsedMilliseconds -lt $TimeoutMs) {
        if (& $Condition) { return $true }
        Start-Sleep -Milliseconds 100
    }
    return [bool](& $Condition)
}

function Stop-Engine {
    foreach ($name in @($ServiceName) + $LegacyServices) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne 'Stopped') { Stop-Service -Name $name -Force -ErrorAction SilentlyContinue }
    }
    @(Get-EngineProcess) + @(Get-Process -Name goodbyedpi -ErrorAction SilentlyContinue) |
        Stop-Process -Force -ErrorAction SilentlyContinue
    [void](Wait-Until { (Get-EngineProcess).Count -eq 0 })
}

function Stop-TrayProcess {
    $procs = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
               Where-Object { $_.CommandLine -match '(app\\tray|GhostDPI-Tray)\.ps1' })
    foreach ($p in $procs) {
        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
    }
}

function Remove-ServiceEntry([string]$Name) {
    if (Get-Service -Name $Name -ErrorAction SilentlyContinue) {
        & sc.exe stop $Name 2>&1 | Out-Null
        & sc.exe delete $Name 2>&1 | Out-Null
    } else {
        & sc.exe query $Name 2>&1 | Out-Null       # kernel drivers are invisible to Get-Service
        if ($LASTEXITCODE -eq 0) { & sc.exe stop $Name 2>&1 | Out-Null; & sc.exe delete $Name 2>&1 | Out-Null }
    }
}

function Remove-LegacySetup {
    foreach ($name in $LegacyServices + $DriverServices) { Remove-ServiceEntry $name }
    foreach ($task in $LegacyTasks) {
        Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
    }
}

# Files of earlier layouts; removed only once the new service runs.
function Remove-OldEngineFiles {
    foreach ($old in 'goodbyedpi.exe', 'ghostdpi.log', 'GhostDPI.ps1', 'GhostDPI-Tray.ps1', 'lang.json') {
        Remove-Item -LiteralPath (Join-Path $InstallDir $old) -Force -ErrorAction SilentlyContinue
    }
}

# After a failed install: start whatever the service pointed to before, if it still exists.
function Restore-PreviousService {
    $svc = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    if (-not $svc -or $svc.State -eq 'Running') { return }
    $exe = if ($svc.PathName -match '^"([^"]+)"') { $Matches[1] } else { ($svc.PathName -split ' ')[0] }
    if (Test-Path -LiteralPath $exe) {
        Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
        Write-Info (T 'info_prev_restored')
    }
}

function Copy-Engine {
    $source = Get-EngineSourceDir
    if (-not (Test-EngineFiles $source)) {
        throw (T 'err_hash_mismatch' @($source))
    }
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    if ((Resolve-Path $source).Path -ne (Resolve-Path $InstallDir).Path) {
        foreach ($file in $EngineFiles.Keys) {
            Copy-Item -LiteralPath (Join-Path $source $file) -Destination $InstallDir -Force
        }
        $targetApp = Join-Path $InstallDir 'app'
        New-Item -ItemType Directory -Path $targetApp -Force | Out-Null
        foreach ($appFile in 'panel.ps1', 'tray.ps1', 'lang.json') {
            $p = Join-Path $ScriptDir $appFile
            if (Test-Path -LiteralPath $p) {
                Copy-Item -LiteralPath $p -Destination (Join-Path $targetApp $appFile) -Force
            }
        }
        foreach ($extra in 'GhostDPI.cmd', 'GhostDPI-Manual.cmd', 'GhostDPI-Tray.cmd', 'LICENSE') {
            $p = Join-Path $RootDir $extra
            if (Test-Path -LiteralPath $p) {
                Copy-Item -LiteralPath $p -Destination (Join-Path $InstallDir $extra) -Force
            }
        }
        $licenses = Join-Path $RootDir 'licenses'
        if (Test-Path -LiteralPath $licenses) {
            $target = Join-Path $InstallDir 'licenses'
            if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
            Copy-Item -LiteralPath $licenses -Destination $target -Recurse -Force
        }
    }
    if (-not (Test-EngineFiles $InstallDir)) { throw (T 'err_copy_verify') }
}

function Install-EngineService([string]$EngineArgs) {
    $exe = Join-Path $InstallDir $EngineExe
    $imagePath = "`"$exe`" --service $EngineArgs".TrimEnd()
    $description = T 'svc_desc'

    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name ImagePath -Value $imagePath
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name Description -Value $description
        Set-Service -Name $ServiceName -StartupType Automatic
    } else {
        New-Service -Name $ServiceName -BinaryPathName $imagePath -DisplayName $AppName `
                    -Description $description -StartupType Automatic | Out-Null
    }
    # Restart after 5 s, 10 s, then 30 s if the engine ever stops unexpectedly.
    & sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 2>&1 | Out-Null
    Start-Service -Name $ServiceName
    if (-not (Wait-Until { (Get-Service -Name $ServiceName).Status -eq 'Running' -and (Get-EngineProcess).Count -gt 0 })) {
        throw (T 'err_service_start')
    }
}

function Update-ActiveConfig($State) {
    $dataDir = Get-ActiveDataDir
    Sync-HostlistFiles $State $dataDir
    if (Test-ServiceInstalled) {
        Stop-Engine
        Install-EngineService (Get-EngineArgs $State.strategy $State -DataDir $InstallDir -ForService)
        Save-State $State $StateFile
    } else {
        Save-State $State $PortableStateFile
    }
}

function Install-Shortcuts([switch]$WithDesktop) {
    $base = if (Test-Path -LiteralPath (Join-Path $InstallDir 'app\panel.ps1')) { $InstallDir } else { $RootDir }
    $shell = New-Object -ComObject WScript.Shell
    if (Test-Path -LiteralPath $StartMenuDir) {
        Remove-Item -LiteralPath $StartMenuDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -ItemType Directory -Path $StartMenuDir -Force | Out-Null

    $panelFile = Join-Path $base 'app\panel.ps1'
    $items = @(
        @{ Name = (T 'sc_panel_name');  Args = "-NoProfile -ExecutionPolicy Bypass -File `"$panelFile`"";        Win = 1; Desc = (T 'sc_panel_desc') },
        @{ Name = (T 'sc_manual_name'); Args = "-NoProfile -ExecutionPolicy Bypass -File `"$panelFile`" -Manual"; Win = 1; Desc = (T 'sc_manual_desc') }
    )
    $trayScript = Join-Path $base 'app\tray.ps1'
    if (Test-Path -LiteralPath $trayScript) {
        $items += @{ Name = (T 'sc_tray_name'); Args = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$trayScript`""; Win = 7; Desc = (T 'sc_tray_desc') }
    }

    foreach ($it in $items) {
        $sc = $shell.CreateShortcut((Join-Path $StartMenuDir $it.Name))
        $sc.TargetPath = $PowerShell
        $sc.Arguments = $it.Args
        $sc.WorkingDirectory = $base
        $sc.WindowStyle = $it.Win
        $sc.Description = $it.Desc
        $sc.Save()
    }
    if ($WithDesktop) {
        $desktop = [Environment]::GetFolderPath('Desktop')
        $sc = $shell.CreateShortcut((Join-Path $desktop 'GhostDPI.lnk'))
        $sc.TargetPath = $PowerShell
        $sc.Arguments = $items[0].Args
        $sc.WorkingDirectory = $base
        $sc.WindowStyle = 1
        $sc.Description = T 'sc_panel_desc'
        $sc.Save()
    }
}

function Remove-Shortcuts {
    if (Test-Path -LiteralPath $StartMenuDir) {
        Remove-Item -LiteralPath $StartMenuDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    foreach ($desktop in @([Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('CommonDesktopDirectory'))) {
        if (-not $desktop) { continue }
        foreach ($name in 'GhostDPI.lnk', 'GhostDPI Manual.lnk', 'GhostDPI Tray.lnk') {
            $p = Join-Path $desktop $name
            if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
        }
    }
}

# ---------------------------------------------------------------- measurements

$ProbeSource = @'
using System;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Threading.Tasks;

public class GhostProbeResult {
    public string Host; public string Ip; public bool Dns; public bool Tcp; public bool Tls;
    public int TcpMs; public int TlsMs; public string Error = "";
}

public static class GhostProbe {
    // Opens a TLS connection to every host at once, completes the handshake and closes it.
    // No request is sent. ips[i] (optional) skips the DNS lookup for hosts[i].
    public static GhostProbeResult[] Run(string[] hosts, string[] ips, int timeoutMs) {
        var tasks = new Task<GhostProbeResult>[hosts.Length];
        for (int i = 0; i < hosts.Length; i++) {
            string h = hosts[i];
            string ip = (ips != null && i < ips.Length) ? ips[i] : null;
            tasks[i] = Task.Run(() => One(h, ip, timeoutMs));
        }
        Task.WaitAll(tasks);
        var results = new GhostProbeResult[tasks.Length];
        for (int i = 0; i < tasks.Length; i++) results[i] = tasks[i].Result;
        return results;
    }

    static GhostProbeResult One(string host, string ipText, int timeoutMs) {
        var r = new GhostProbeResult { Host = host };
        IPAddress ip = null;
        try {
            if (!string.IsNullOrEmpty(ipText)) ip = IPAddress.Parse(ipText);
            else {
                foreach (var a in Dns.GetHostAddresses(host))
                    if (a.AddressFamily == AddressFamily.InterNetwork) { ip = a; break; }
                if (ip == null) { var all = Dns.GetHostAddresses(host); if (all.Length > 0) ip = all[0]; }
            }
        } catch { }
        if (ip == null) { r.Error = "dns"; return r; }
        r.Dns = true; r.Ip = ip.ToString();

        var sw = Stopwatch.StartNew();
        using (var client = new TcpClient(ip.AddressFamily)) {
            try {
                var connect = client.ConnectAsync(ip, 443);
                if (!connect.Wait(timeoutMs)) { r.Error = "tcp-timeout"; return r; }
            } catch { r.Error = "tcp"; return r; }
            r.Tcp = true; r.TcpMs = (int)sw.ElapsedMilliseconds; sw.Restart();
            SslPolicyErrors certErr = SslPolicyErrors.None;
            try {
                using (var ssl = new SslStream(client.GetStream(), false, (s, c, ch, e) => { certErr = e; return e == SslPolicyErrors.None; })) {
                    var hs = ssl.AuthenticateAsClientAsync(host, null, SslProtocols.None, false);
                    if (!hs.Wait(timeoutMs)) { r.Error = "tls-timeout"; return r; }
                    r.Tls = true; r.TlsMs = (int)sw.ElapsedMilliseconds;
                }
            } catch { r.Error = certErr != SslPolicyErrors.None ? "tls-cert" : "tls-reset"; }
        }
        return r;
    }
}
'@

function Initialize-Probe {
    if (-not ('GhostProbe' -as [type])) { Add-Type -TypeDefinition $ProbeSource -Language CSharp }
}

function Invoke-Probe([string[]]$Hosts, [string[]]$Ips = $null, [int]$TimeoutMs = $ProbeTimeoutMs) {
    Initialize-Probe
    return @([GhostProbe]::Run($Hosts, $Ips, $TimeoutMs))
}

function Get-Average($Values) {
    $v = @($Values | Where-Object { $null -ne $_ })
    if ($v.Count -eq 0) { return 0 }
    return [int](($v | Measure-Object -Average).Average)
}

function Resolve-Doh([string]$Name) {
    $ErrorActionPreference = 'Continue'
    foreach ($url in "https://1.1.1.1/dns-query?name=$Name&type=A", "https://8.8.8.8/resolve?name=$Name&type=A") {
        $raw = & $Curl -s -m 5 -H 'accept: application/dns-json' $url 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $raw) { continue }
        try { $json = ($raw -join '') | ConvertFrom-Json } catch { continue }
        $ips = @()
        if ($json.PSObject.Properties['Answer']) {
            $ips = @($json.Answer | Where-Object { $_.type -eq 1 } | ForEach-Object { [string]$_.data })
        }
        return [pscustomobject]@{ Ok = $true; Ips = $ips; Status = [int]$json.Status }
    }
    return [pscustomobject]@{ Ok = $false; Ips = @(); Status = -1 }
}

function Resolve-System([string]$Name) {
    try { return @([Net.Dns]::GetHostAddresses($Name) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                   ForEach-Object { $_.ToString() }) }
    catch { return @() }
}

function Measure-Ping([string]$Address, [int]$Count = 3) {
    $ping = New-Object System.Net.NetworkInformation.Ping
    $times = @()
    for ($i = 0; $i -lt $Count; $i++) {
        try { $r = $ping.Send($Address, 1000); if ($r.Status -eq 'Success') { $times += [int]$r.RoundtripTime } } catch { }
    }
    $ping.Dispose()
    return [pscustomobject]@{ Received = $times.Count; Sent = $Count; Ms = (Get-Average $times) }
}

# Sends a DNS query to an address that does not exist (TEST-NET-2) on a non-DNS port.
# Any answer means the provider (or another tool) intercepts plain DNS traffic.
function Test-DnsInterception {
    $ErrorActionPreference = 'Continue'
    $out = & nslookup.exe -port=5353 -timeout=2 -retry=1 example.com 198.51.100.7 2>$null
    return [bool](@($out) -match '^Name:')
}

function Get-ClockSkewMinutes {
    $ErrorActionPreference = 'Continue'
    $headers = & $Curl -sI -m 5 'https://1.1.1.1/' 2>$null
    $line = @($headers | Where-Object { $_ -match '^date:\s*(.+)$' }) | Select-Object -First 1
    if (-not $line) { return $null }
    $value = ($line -replace '^date:\s*', '').Trim()
    try {
        $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
        $server = [DateTime]::ParseExact($value, 'r', [Globalization.CultureInfo]::InvariantCulture, $styles)
        return [Math]::Abs(([DateTime]::UtcNow - $server).TotalMinutes)
    } catch { return $null }
}

function Test-StrategyCandidate([string]$Exe, [string]$WorkDir, [string]$EngineArgs, [string[]]$Probe) {
    $start = @{ FilePath = $Exe; WorkingDirectory = $WorkDir; WindowStyle = 'Hidden'; PassThru = $true }
    if ($EngineArgs) { $start.ArgumentList = $EngineArgs }
    $proc = Start-Process @start
    Start-Sleep -Milliseconds 400
    if ($proc.HasExited) {
        Clear-Progress-Line
        throw (T 'err_engine_start')
    }
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    $results = Invoke-Probe $Probe -TimeoutMs 2500
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    [void](Wait-Until { $proc.HasExited })
    $controlOk = @($results | Where-Object { $ControlHosts -contains $_.Host -and $_.Tls }).Count -gt 0
    $allOk = $controlOk -and @($results | Where-Object { -not $_.Tls }).Count -eq 0
    return [pscustomobject]@{ ControlOk = $controlOk; AllOk = $allOk }
}

function Find-WorkingStrategy($State) {
    $exe = Join-Path $InstallDir $EngineExe
    $probe = @(Get-ProbeHosts $State) + $ControlHosts
    $order = New-Object System.Collections.Generic.List[int]
    $order.Add([int]$State.strategy)
    for ($i = 0; $i -lt $Strategies.Count; $i++) { if (-not $order.Contains($i)) { $order.Add($i) } }
    $safe = -1
    $safeTtl = 0
    Initialize-Probe

    if (@(Invoke-Probe @('one.one.one.one', 'dns.google') @('1.1.1.1', '8.8.8.8') | Where-Object { $_.Tls }).Count -eq 0) {
        throw (T 'err_no_internet')
    }

    $probeState = [pscustomobject]@{
        strategy   = $State.strategy
        ttl        = 0
        dns        = $State.dns
        dnsProfile = $State.dnsProfile
        quic       = $State.quic
        listMode   = 'all'
        exclude    = @()
        include    = @()
    }

    $n = 0
    foreach ($i in $order) {
        $n++
        Write-Progress-Line (T 'prog_measuring' @($n, $Strategies.Count))
        $engineArgs = Get-EngineArgs $i $probeState -TtlOverride 0 -DataDir $InstallDir
        $res = Test-StrategyCandidate $exe $InstallDir $engineArgs $probe
        if ($res.ControlOk -and $safe -lt 0) { $safe = $i; $safeTtl = 0 }
        if ($res.AllOk) {
            Clear-Progress-Line
            Write-Ok (T 'ok_found_strat' @((Get-StrategyName $i)))
            return [pscustomobject]@{ Index = $i; Safe = $i; Ttl = 0; SafeTtl = 0 }
        }
    }

    $tIdx = 0
    foreach ($t in $AutoTtlCandidates) {
        $tIdx++
        Write-Progress-Line (T 'prog_ttl' @($t, $tIdx, $AutoTtlCandidates.Count))
        $engineArgs = Get-EngineArgs 0 $probeState -TtlOverride $t -DataDir $InstallDir
        $res = Test-StrategyCandidate $exe $InstallDir $engineArgs $probe
        if ($res.ControlOk -and $safe -lt 0) { $safe = 0; $safeTtl = $t }
        if ($res.AllOk) {
            Clear-Progress-Line
            Write-Ok (T 'ok_found_ttl' @((Get-StrategyName 0), $t))
            return [pscustomobject]@{ Index = 0; Safe = 0; Ttl = $t; SafeTtl = $t }
        }
    }

    Clear-Progress-Line
    return [pscustomobject]@{ Index = -1; Safe = $safe; Ttl = 0; SafeTtl = $safeTtl }
}

# ---------------------------------------------------------------- panel actions

function Invoke-Install {
    $state = Get-State
    Write-Host ''
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Write-Step (T 'inst_step1')
    Stop-Engine
    try {
        Remove-LegacySetup
        Copy-Engine
        Write-Ok (T 'inst_verified' @($InstallDir))

        Write-Step (T 'inst_step2')
        $found = Find-WorkingStrategy $state
        if ($found.Index -ge 0) {
            $chosen = $found.Index
            $chosenTtl = $found.Ttl
        } elseif ($found.Safe -ge 0) {
            $chosen = $found.Safe
            $chosenTtl = $found.SafeTtl
            Write-Warn (T 'inst_warn_partial' @((Get-StrategyName $chosen)))
            Write-Info (T 'inst_info_other_vpn')
        } else {
            throw (T 'err_breaks_net')
        }
        $state.strategy = $chosen
        $state.ttl = $chosenTtl

        Write-Step (T 'inst_step3')
        Sync-HostlistFiles $state $InstallDir
        Install-EngineService (Get-EngineArgs $chosen $state -DataDir $InstallDir -ForService)
    } catch {
        Clear-Progress-Line
        Write-Bad $_.Exception.Message
        Restore-PreviousService
        return
    }
    Save-State $state $StateFile
    Remove-OldEngineFiles
    Write-Ok (T 'inst_ok_running')

    Write-Step (T 'inst_step4')
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    Show-AccessSummary (Invoke-Probe (Get-ProbeHosts $state))

    Write-Host ''
    Write-Host ("  " + (T 'inst_done' @($sw.Elapsed.TotalSeconds))) -ForegroundColor Green
    if (-not (Test-Path -LiteralPath (Join-Path $StartMenuDir 'GhostDPI.lnk'))) {
        if (Read-YesNo (T 'inst_ask_startmenu')) {
            $desk = Read-YesNo (T 'inst_ask_desktop')
            Install-Shortcuts -WithDesktop:$desk
            Write-Ok (T 'ok_shortcuts')
        }
    }
}

function Invoke-ManualLaunchFromPanel {
    Write-Host ''
    $source = Get-EngineSourceDir
    if (-not (Test-EngineFiles $source)) {
        Write-Bad (T 'man_bad_files' @($source))
        return
    }
    Write-Step (T 'man_step')
    Write-Info (T 'man_info')
    $verb = Read-YesNo (T 'man_ask_verbose')
    $argStr = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Manual"
    if ($verb) { $argStr += ' -VerboseEngine' }
    if ($Lang) { $argStr += " -Lang $Lang" }
    Start-Process -FilePath $PowerShell -ArgumentList $argStr
    Write-Ok (T 'man_opened')
}

function Invoke-ManualWindow {
    $state = Get-State
    Initialize-Language $state.lang
    $Host.UI.RawUI.WindowTitle = T 'man_title' @($AppName, $AppVersion)
    try { $Host.UI.RawUI.BackgroundColor = 'Black'; $Host.UI.RawUI.ForegroundColor = 'Gray' } catch { }
    Clear-Host
    Show-Header

    $source = Get-EngineSourceDir
    if (-not (Test-EngineFiles $source)) {
        Write-Bad (T 'man_bad_files' @($source))
        Write-Info (T 'man_not_started')
        Write-Host ''; Write-Host ("  " + (T 'press_any_close')) -ForegroundColor DarkGray
        [void][Console]::ReadKey($true)
        return
    }

    $resumeService = $false
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        Write-Warn (T 'man_svc_running')
        if (-not (Read-YesNo (T 'man_ask_pause_svc'))) {
            Write-Info (T 'man_cancelled')
            Start-Sleep -Milliseconds 1200
            return
        }
        Stop-Engine
        $resumeService = $true
    } elseif ((Get-EngineProcess).Count -gt 0) {
        Write-Warn (T 'man_already_open')
        Write-Host ''; Write-Host ("  " + (T 'press_any_close')) -ForegroundColor DarkGray
        [void][Console]::ReadKey($true)
        return
    }

    $dataDir = Get-ActiveDataDir
    Sync-HostlistFiles $state $dataDir
    $tokens = Get-EngineArgTokens -Strategy $state.strategy -State $state -DataDir $dataDir -VerboseMode:$VerboseEngine
    $exe = Join-Path $source $EngineExe

    $dnsLabel = if ($state.dns) { Get-DnsShort $state.dnsProfile } else { T 'off' }
    Write-Row (T 'man_row_mode') (T 'man_mode_val') Cyan
    Write-Row (T 'row_preset')   ("{0}  ·  DNS: {1}  ·  QUIC: {2}" -f (Get-StrategyLabel $state), $dnsLabel, (On-Off $state.quic).ToLower())
    Write-Row (T 'row_list')     (Get-ListModeLabel $state)
    Write-Host ''
    Write-Ok (T 'man_running')
    if ($VerboseEngine) { Write-Info (T 'man_verbose_on') }
    Write-Host ''

    try {
        & $exe @tokens
    } finally {
        Write-Host ''
        Write-Info (T 'man_stopped')
        if ($resumeService) {
            try {
                Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
                Write-Ok (T 'man_svc_resumed')
            } catch { }
        }
    }
}

function Show-AccessSummary($Results) {
    $failed = @($Results | Where-Object { -not $_.Tls })
    if ($failed.Count -eq 0) {
        Write-Ok (T 'acc_ok' @((Get-Average ($Results | ForEach-Object { $_.TcpMs + $_.TlsMs }))))
    } else {
        Write-Bad (T 'acc_bad' @($failed.Count, @($Results).Count))
    }
}

function Invoke-Diagnostics {
    $state = Get-State
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $running = $svc -and $svc.Status -eq 'Running'
    $manualRunning = (-not $running) -and ((Get-EngineProcess).Count -gt 0)
    $report = New-Object System.Collections.Generic.List[string]
    $report.Add((T 'diag_rep_hdr' @($AppVersion, (Get-Date -Format 'yyyy-MM-dd HH:mm'))))
    $report.Add('------------------------------------------------------------')
    Write-Host ''

    Write-Step (T 'diag_s_conn')
    $p1 = Measure-Ping '1.1.1.1'; $p2 = Measure-Ping '8.8.8.8'
    $received = $p1.Received + $p2.Received; $sent = $p1.Sent + $p2.Sent
    if ($received -eq 0) {
        $msg = T 'diag_no_ping'
        Write-Bad $msg; $report.Add((T 'rep_conn' @($msg)))
    } else {
        $loss = [int](100 * ($sent - $received) / $sent)
        $ms = Get-Average @($(if ($p1.Received) { $p1.Ms }), $(if ($p2.Received) { $p2.Ms }))
        if ($loss -gt 0) { $msg = T 'diag_ping_loss' @($ms, $loss); Write-Warn $msg }
        else             { $msg = T 'diag_ping_ok' @($ms); Write-Ok $msg }
        $report.Add((T 'rep_conn' @($msg)))
    }
    $p6 = Measure-Ping '2606:4700:4700::1111' 2
    if ($p6.Received) { Write-Ok (T 'diag_ipv6_ok' @($p6.Ms)); $report.Add((T 'rep_ipv6_ok' @($p6.Ms))) }
    else { Write-Info (T 'diag_ipv6_no'); $report.Add((T 'rep_ipv6_no')) }

    Write-Step (T 'diag_s_dns')
    $dnsProtected = ($running -or $manualRunning) -and $state.dns -and -not (Test-OldInstall)
    if (@(Resolve-System 'www.cloudflare.com').Count -gt 0) {
        Write-Ok (T 'diag_dns_ok'); $report.Add((T 'rep_dns_ok'))
    } elseif ($dnsProtected) {
        Write-Bad (T 'diag_dns_bad'); $report.Add((T 'rep_dns_bad'))
    } else {
        $servers = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                     ForEach-Object { $_.ServerAddresses } | Select-Object -Unique)
        Write-Bad (T 'diag_dns_sys_bad' @(($servers -join ', ')))
        Write-Info (T 'diag_dns_sys_hint')
        $report.Add((T 'rep_dns_sys'))
    }
    $doh = Resolve-Doh 'www.cloudflare.com'
    if ($doh.Ok) { Write-Ok (T 'diag_doh_ok'); $report.Add((T 'rep_doh_ok')) }
    else         { Write-Bad (T 'diag_doh_bad'); $report.Add((T 'rep_doh_bad')) }
    if (Test-DnsInterception) {
        if ($dnsProtected) { Write-Ok (T 'diag_dns_int_ok'); $report.Add((T 'rep_int_ok')) }
        else { Write-Warn (T 'diag_dns_int_warn'); $report.Add((T 'rep_int_yes')) }
    } else {
        Write-Ok (T 'diag_dns_int_none'); $report.Add((T 'rep_int_no'))
    }

    Write-Step (T 'diag_s_acc')
    $hosts = Get-ProbeHosts $state
    $results = Invoke-Probe ($hosts + $ControlHosts)
    $control = @($results | Where-Object { $ControlHosts -contains $_.Host })
    $blocked = @($results | Where-Object { $ControlHosts -notcontains $_.Host })
    if (@($control | Where-Object { $_.Dns }).Count -eq 0) {
        Write-Bad (T 'diag_acc_nodns'); $report.Add((T 'rep_acc_nodns'))
    } else {
        if (@($control | Where-Object { $_.Tls }).Count -eq 0) {
            Write-Bad (T 'diag_https_bad'); $report.Add((T 'rep_https_bad'))
        } else {
            $cms = Get-Average ($control | Where-Object { $_.Tls } | ForEach-Object { $_.TcpMs + $_.TlsMs })
            Write-Ok (T 'diag_https_ok' @($cms)); $report.Add((T 'rep_https_ok' @($cms)))
        }
        Show-AccessSummary $blocked
        $okCount = @($blocked | Where-Object { $_.Tls }).Count
        $report.Add((T 'rep_probes' @($okCount, @($blocked).Count)))
        $dpiHits = @($blocked | Where-Object { $_.Tcp -and -not $_.Tls }).Count
        $dnsHits = @($blocked | Where-Object { -not $_.Dns }).Count
        $ipHits  = @($blocked | Where-Object { $_.Dns -and -not $_.Tcp }).Count
        if ($dpiHits) { Write-Info (T 'diag_dpi_hits' @($dpiHits)); $report.Add((T 'rep_dpi' @($dpiHits))) }
        if ($dnsHits) { Write-Info (T 'diag_dns_hits' @($dnsHits)); $report.Add((T 'rep_dns' @($dnsHits))) }
        if ($ipHits)  { Write-Info (T 'diag_ip_hits'  @($ipHits));  $report.Add((T 'rep_ip'  @($ipHits))) }
    }

    Write-Step (T 'diag_s_sys')
    $skew = Get-ClockSkewMinutes
    if ($null -eq $skew)   { Write-Info (T 'diag_clk_na'); $report.Add((T 'rep_clk_na')) }
    elseif ($skew -gt 5)   { Write-Bad (T 'diag_clk_skew' @($skew)); $report.Add((T 'rep_clk_skew' @($skew))) }
    else                   { Write-Ok (T 'diag_clk_ok'); $report.Add((T 'rep_clk_ok')) }

    $proxy = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    if ($proxy -and $proxy.ProxyEnable -eq 1) { Write-Warn (T 'diag_proxy_on' @($proxy.ProxyServer)); $report.Add((T 'rep_proxy_on')) }
    else { Write-Ok (T 'diag_proxy_off'); $report.Add((T 'rep_proxy_off')) }

    $vpn = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.Status -eq 'Up' -and $_.InterfaceDescription -match 'TAP-|WireGuard|Wintun|OpenVPN|VPN|Tailscale' })
    if ($vpn.Count) { Write-Info (T 'diag_vpn_up' @(($vpn | ForEach-Object { $_.Name }) -join ', ')); $report.Add((T 'rep_vpn' @($vpn.Count))) }

    $others = @(Get-Process -Name $OtherDpiTools -ErrorAction SilentlyContinue |
                Where-Object { -not (Test-OwnLegacyProcess $_) } | ForEach-Object { $_.ProcessName } | Select-Object -Unique)
    if ($others.Count) { Write-Warn (T 'diag_dpi_other' @(($others -join ', '))); $report.Add((T 'rep_other_dpi' @(($others -join ', ')))) }
    else { Write-Ok (T 'diag_dpi_none'); $report.Add((T 'rep_no_other_dpi')) }

    $av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
            Where-Object { $_.displayName -match 'Kaspersky' })
    if ($av.Count) { Write-Bad (T 'diag_kaspersky'); $report.Add((T 'rep_kaspersky')) }

    Write-Step $AppName
    $dnsDesc = if ($state.dns) { Get-DnsShort $state.dnsProfile } else { T 'off' }
    $report.Add((T 'rep_cfg' @((Get-StrategyLabel $state), $dnsDesc, (On-Off $state.quic), (Get-ListModeLabel $state))))
    if (-not $svc) {
        if ($manualRunning) {
            $res = Get-ResourceText
            Write-Ok (T 'diag_manual_run' @((Get-StrategyLabel $state), $(if ($res) { ", $res" } else { '' })))
            $report.Add((T 'rep_st_man'))
        } else {
            Write-Warn (T 'diag_not_inst'); $report.Add((T 'rep_st_notinst'))
        }
    } elseif (Test-OldInstall) {
        Write-Warn (T 'diag_old_ver'); $report.Add((T 'rep_st_old'))
    } else {
        if ($running) {
            $res = Get-ResourceText
            $detail = Get-StrategyLabel $state
            if ($res) { $detail += ", $res" }
            Write-Ok (T 'diag_svc_run' @($detail)); $report.Add((T 'rep_st_run' @($detail)))
        } elseif ($manualRunning) {
            Write-Ok (T 'diag_man_svc_off'); $report.Add((T 'rep_st_man'))
        } else {
            Write-Warn (T 'diag_svc_stop'); $report.Add((T 'rep_st_stop'))
        }
        $driver = Get-CimInstance Win32_SystemDriver -Filter "Name='WinDivert'" -ErrorAction SilentlyContinue
        if ($driver -and $driver.State -eq 'Running') { Write-Ok (T 'diag_drv_ok'); $report.Add((T 'rep_drv_ok')) }
        elseif ($running -or $manualRunning) { Write-Warn (T 'diag_drv_miss'); $report.Add((T 'rep_drv_miss')) }
        if (Test-EngineFiles $InstallDir) { Write-Ok (T 'diag_files_ok'); $report.Add((T 'rep_f_ok')) }
        elseif (Test-UpdateReady) { Write-Warn (T 'diag_upd_ready'); $report.Add((T 'rep_f_upd')) }
        else { Write-Bad (T 'diag_files_bad'); $report.Add((T 'rep_f_bad')) }
    }

    Write-Host ''
    if (Read-YesNo (T 'diag_ask_clip')) {
        $text = $report -join "`r`n"
        try { Set-Clipboard -Value $text } catch { $text | & clip.exe }
        Write-Ok (T 'diag_clip_ok')
    }
}

function Test-OldInstall {
    $path = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -ErrorAction SilentlyContinue).ImagePath
    return [bool]$path -and $path -notmatch [regex]::Escape($EngineExe)
}

function Test-UpdateReady {
    $source = Get-EngineSourceDir
    return $source -ne $InstallDir -and (Test-EngineFiles $source)
}

function Test-OwnLegacyProcess($Process) {
    try { return $Process.Path -and $Process.Path.StartsWith($InstallDir, [StringComparison]::OrdinalIgnoreCase) }
    catch { return $false }
}

function ConvertTo-HostName([string]$Text) {
    $t = $Text.Trim().ToLowerInvariant()
    $t = $t -replace '^[a-z]+://', ''
    $t = ($t -split '[/?#:]')[0]
    if ($t -notmatch '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$') { return $null }
    return $t
}

function Invoke-SiteTest {
    Write-Host ''
    Write-Host ("  " + (T 'site_prompt')) -ForegroundColor Gray -NoNewline
    [Console]::CursorVisible = $true
    $name = ConvertTo-HostName (Read-Host)
    [Console]::CursorVisible = $false
    if (-not $name) { Write-Warn (T 'site_invalid'); return }

    Write-Step (T 'site_checking' @($name))
    $sys = @(Resolve-System $name)
    $doh = Resolve-Doh $name
    if ($doh.Ok -and $doh.Status -eq 3) { Write-Bad (T 'site_nxdomain'); return }

    if ($sys.Count -gt 0) { Write-Ok (T 'site_dns_ok' @($sys[0])) }
    elseif ($doh.Ips.Count -gt 0) { Write-Bad (T 'site_dns_block') }
    else { Write-Bad (T 'site_dns_fail') }

    $r = @(Invoke-Probe @($name))[0]
    $viaDoh = $null
    if (-not $r.Tls -and $doh.Ips.Count -gt 0) { $viaDoh = @(Invoke-Probe @($name) @($doh.Ips[0]))[0] }
    $check = if ($viaDoh) { $viaDoh } else { $r }

    if ($r.Tls) {
        Write-Ok (T 'site_open_ok' @($r.TcpMs, $r.TlsMs))
    } elseif ($viaDoh -and $viaDoh.Tls) {
        Write-Warn (T 'site_doh_only')
    } elseif ($check.Dns -and -not $check.Tcp) {
        Write-Bad (T 'site_ip_block')
    } elseif ($check.Tcp -and $check.Error -eq 'tls-cert') {
        Write-Bad (T 'site_cert_err')
    } elseif ($check.Tcp) {
        Write-Bad (T 'site_dpi_block')
    }

    $state = Get-State
    if ((Test-ServiceInstalled) -and $state.sites -notcontains $name -and
        $DefaultProbeHosts -notcontains $name) {
        if (Read-YesNo (T 'site_ask_add')) {
            $state.sites = @($state.sites) + $name
            Save-State $state
            Write-Ok (T 'site_added')
        }
    }
}

function Invoke-Toggle {
    Write-Host ''
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) { Write-Warn (T 'tog_not_inst'); return }
    if ($svc.Status -eq 'Running') {
        Write-Step (T 'tog_stopping')
        Stop-Engine
        Write-Ok (T 'tog_stopped')
        return
    }
    Write-Step (T 'tog_starting')
    if (-not (Test-EngineFiles $InstallDir)) {
        Write-Bad (T 'tog_bad_files')
        return
    }
    Start-Service -Name $ServiceName
    Write-Ok (T 'tog_started')
}

function Invoke-SiteListMenu($State) {
    while ($true) {
        Clear-Host
        Show-Header
        Write-Host ("  " + (T 'sl_title')) -ForegroundColor White
        Write-Host ''
        Write-Row (T 'sl_cur_mode') (Get-ListModeLabel $State) Cyan
        $activeKey = if ($State.listMode -eq 'include') { 'include' } else { 'exclude' }
        $listTitle = if ($activeKey -eq 'include') { T 'sl_inc_lbl' } else { T 'sl_exc_lbl' }
        $items = @($State.$activeKey)
        if ($items.Count -gt 0) { Write-Row $listTitle ($items -join ', ') Gray }
        else                    { Write-Row $listTitle (T 'none_empty') DarkGray }
        if (@($State.sites).Count -gt 0) { Write-Row (T 'sl_probe_lbl') (@($State.sites) -join ', ') Gray }
        Write-Host ''
        Write-MenuItem '1' (T 'sl_m1') '' (T 'sl_m1_h')
        Write-MenuItem '2' (T 'sl_m2') '' (T 'sl_m2_h' @($listTitle))
        Write-MenuItem '3' (T 'sl_m3') '' (T 'sl_m3_h' @($listTitle))
        Write-MenuItem '4' (T 'sl_m4') '' (T 'sl_m4_h' @($listTitle))
        Write-MenuItem '5' (T 'sl_m5') '' (T 'sl_m5_h' @((Get-ProbeHosts $State).Count))
        Write-MenuItem '0' (T 'back') '' ''
        Write-Host ''
        $k = "$([Console]::ReadKey($true).KeyChar)"
        switch ($k) {
            '1' {
                $modes = @('all', 'exclude', 'include')
                $State.listMode = $modes[([Array]::IndexOf($modes, $State.listMode) + 1) % $modes.Count]
                Update-ActiveConfig $State
            }
            '2' {
                Write-Host ''
                Write-Host ("  " + (T 'sl_add_prompt')) -ForegroundColor Gray -NoNewline
                [Console]::CursorVisible = $true
                $h = ConvertTo-HostName (Read-Host)
                [Console]::CursorVisible = $false
                if ($h) {
                    if ($State.listMode -eq 'all') { $State.listMode = 'exclude'; $activeKey = 'exclude' }
                    $State.$activeKey = @($State.$activeKey + $h | Select-Object -Unique)
                    Update-ActiveConfig $State
                }
            }
            '3' {
                if ($items.Count -eq 0) { continue }
                Write-Host ''
                for ($i = 0; $i -lt $items.Count; $i++) {
                    Write-Host ("    [{0}] {1}" -f ($i + 1), $items[$i]) -ForegroundColor Gray
                }
                Write-Host ("  " + (T 'sl_rem_prompt')) -ForegroundColor Gray -NoNewline
                [Console]::CursorVisible = $true
                $raw = Read-Host
                [Console]::CursorVisible = $false
                $num = 0
                if ([int]::TryParse($raw, [ref]$num) -and $num -ge 1 -and $num -le $items.Count) {
                    $State.$activeKey = @($items | Where-Object { $_ -ne $items[$num - 1] })
                    Update-ActiveConfig $State
                }
            }
            '4' {
                $State.$activeKey = @()
                if ($State.listMode -ne 'all') { $State.listMode = 'all' }
                Update-ActiveConfig $State
            }
            '5' {
                $State.sites = @()
                Save-State $State
            }
            '0' { return }
        }
    }
}

function Invoke-ServiceLog {
    Write-Host ''
    Write-Step (T 'log_step')
    if (Test-Path -LiteralPath $LogFile) {
        $lines = @(Get-Content -LiteralPath $LogFile -Tail 15 -ErrorAction SilentlyContinue)
        if ($lines.Count -gt 0) { foreach ($l in $lines) { Write-Info $l } }
        else { Write-Info (T 'log_empty') }
    } else {
        Write-Info (T 'log_none')
    }
}

function Invoke-UpdateCheck {
    Write-Host ''
    Write-Step (T 'upd_step')
    Write-Info (T 'upd_cur' @($AppName, $AppVersion))
    if (-not $UpdateRepo) { Write-Info (T 'upd_no_repo'); return }
    Write-Info (T 'upd_checking')
    $ErrorActionPreference = 'Continue'
    $raw = & $Curl -s -m 6 -H 'User-Agent: GhostDPI' "https://api.github.com/repos/$UpdateRepo/releases/latest" 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $raw) { Write-Warn (T 'upd_err_fetch'); return }
    try {
        $rel = ($raw -join '') | ConvertFrom-Json
        $latest = ("$($rel.tag_name)").TrimStart('v', 'V')
        if (-not $latest) { Write-Warn (T 'upd_no_rel'); return }
        if ([version]$latest -gt [version]$AppVersion) { Write-Warn (T 'upd_new' @($latest, $rel.html_url)) }
        else { Write-Ok (T 'upd_latest' @($AppVersion)) }
    } catch {
        Write-Warn (T 'upd_err_parse')
    }
}

function Invoke-LaunchTray {
    $candidates = @(
        (Join-Path $ScriptDir 'tray.ps1'),
        (Join-Path $InstallDir 'app\tray.ps1')
    )
    $tray = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $tray) { Write-Warn (T 'tray_missing'); return }
    Start-Process -FilePath $PowerShell -WindowStyle Hidden `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$tray`""
    Write-Ok (T 'tray_started')
}

function Invoke-Advanced {
    while ($true) {
        $state = Get-State
        Initialize-Language $state.lang
        Clear-Host
        Show-Header
        Write-Host ("  " + (T 'adv_title')) -ForegroundColor White
        if (-not (Test-ServiceInstalled)) {
            Write-Host ("  " + (T 'adv_portable_note')) -ForegroundColor DarkGray
        }
        Write-Host ''
        Write-MenuItem '1' (T 'adv_1') (On-Off $state.dns)                  (T 'adv_1_h')
        Write-MenuItem '2' (T 'adv_2') (Get-DnsShort $state.dnsProfile)     (T 'adv_2_h')
        Write-MenuItem '3' (T 'adv_3') (On-Off $state.quic)                 (T 'adv_3_h')
        Write-MenuItem '4' (T 'adv_4') (Get-StrategyLabel $state)           (T 'adv_4_h')
        Write-MenuItem '5' (T 'adv_5') (Get-ListModeLabel $state)           (T 'adv_5_h')
        Write-MenuItem '6' (T 'adv_6') (Get-LangSettingLabel $state.lang)   (T 'adv_6_h')
        Write-MenuItem '7' (T 'adv_7') ''                                   (T 'adv_7_h')
        Write-MenuItem '8' (T 'adv_8') ''                                   (T 'adv_8_h')
        Write-MenuItem '9' (T 'adv_9') ''                                   (T 'adv_9_h')
        Write-MenuItem '0' (T 'back')  ''                                   ''
        Write-Host ''
        $key = "$([Console]::ReadKey($true).KeyChar)"
        switch ($key) {
            '1' { $state.dns = -not $state.dns; Update-ActiveConfig $state }
            '2' {
                Write-Host ''
                for ($i = 0; $i -lt $DnsProfileKeys.Count; $i++) {
                    Write-Host ("    [{0}] {1}" -f ($i + 1), (Get-DnsDesc $DnsProfileKeys[$i])) -ForegroundColor Gray
                }
                Write-Host ("  " + (T 'adv_dns_prompt')) -ForegroundColor Gray -NoNewline
                $k = "$([Console]::ReadKey($true).KeyChar)"
                $n = 0
                if ([int]::TryParse($k, [ref]$n) -and $n -ge 1 -and $n -le $DnsProfileKeys.Count) {
                    $state.dnsProfile = $DnsProfileKeys[$n - 1]
                    $state.dns = $true
                    Update-ActiveConfig $state
                }
            }
            '3' { $state.quic = -not $state.quic; Update-ActiveConfig $state }
            '4' {
                Write-Host ''
                for ($i = 0; $i -lt $Strategies.Count; $i++) {
                    Write-Host ("    [{0}] {1}" -f ($i + 1), (Get-StrategyName $i)) -ForegroundColor Gray
                }
                Write-Host ("  " + (T 'adv_strat_prompt')) -ForegroundColor Gray -NoNewline
                $k = "$([Console]::ReadKey($true).KeyChar)"
                $n = 0
                if ([int]::TryParse($k, [ref]$n) -and $n -ge 1 -and $n -le $Strategies.Count) {
                    $state.strategy = $n - 1
                    $state.ttl = 0
                    Update-ActiveConfig $state
                }
            }
            '5' { Invoke-SiteListMenu $state }
            '6' {
                Write-Host ''
                Write-Host ("    [1] " + (T 'lang_opt_auto')) -ForegroundColor Gray
                Write-Host ("    [2] " + (T 'lang_opt_en'))   -ForegroundColor Gray
                Write-Host ("    [3] " + (T 'lang_opt_tr'))   -ForegroundColor Gray
                Write-Host ("  " + (T 'lang_prompt')) -ForegroundColor Gray -NoNewline
                $k = "$([Console]::ReadKey($true).KeyChar)"
                $map = @{ '1' = 'auto'; '2' = 'en'; '3' = 'tr' }
                if ($map.ContainsKey($k)) {
                    $state.lang = $map[$k]
                    $Lang = ''
                    Save-State $state
                    Initialize-Language $state.lang
                }
            }
            '7' {
                Write-Host ''
                Invoke-LaunchTray
                Start-Sleep -Milliseconds 1200
            }
            '8' {
                Write-Host ''
                $desk = Read-YesNo (T 'inst_ask_desktop')
                Install-Shortcuts -WithDesktop:$desk
                Write-Ok (T 'ok_shortcuts')
                Start-Sleep -Milliseconds 1200
            }
            '9' {
                Invoke-ServiceLog
                Write-Host ''
                Write-Host ("  " + (T 'press_any_continue')) -ForegroundColor DarkGray
                [void][Console]::ReadKey($true)
            }
            '0' { return }
        }
    }
}

function Invoke-Uninstall {
    Write-Host ''
    if (-not (Read-YesNo (T 'uninst_ask'))) { Write-Info (T 'uninst_cancel'); return }
    Write-Step (T 'uninst_step')
    Stop-TrayProcess
    Stop-Engine
    Remove-ServiceEntry $ServiceName
    Remove-LegacySetup
    Remove-Shortcuts
    Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    Write-Ok (T 'uninst_done')
}

# ---------------------------------------------------------------- panel

function On-Off([bool]$Value) { if ($Value) { return (T 'on') } else { return (T 'off') } }

function Get-ResourceText {
    $proc = Get-EngineProcess | Select-Object -First 1
    if (-not $proc) { return '' }
    $text = T 'mem_unit' @(($proc.WorkingSet64 / 1MB))
    try {
        $uptime = ((Get-Date) - $proc.StartTime).TotalSeconds
        if ($uptime -gt 0) {
            $cpu = 100 * $proc.TotalProcessorTime.TotalSeconds / $uptime / [Environment]::ProcessorCount
            $text += T 'cpu_unit' @($cpu)
        }
    } catch { }
    return $text
}

function Write-Row([string]$Label, [string]$Value, [ConsoleColor]$Color = 'White') {
    Write-Host ('  {0,-14}' -f $Label) -ForegroundColor DarkGray -NoNewline
    Write-Host $Value -ForegroundColor $Color
}

function Write-MenuItem([string]$Key, [string]$Title, [string]$Value, [string]$Hint) {
    Write-Host '  ' -NoNewline
    Write-Host " $Key " -ForegroundColor Black -BackgroundColor DarkCyan -NoNewline
    Write-Host (' {0,-17}' -f $Title) -ForegroundColor White -NoNewline
    if ($Value) { Write-Host ('{0,-22}' -f $Value) -ForegroundColor Cyan -NoNewline }
    Write-Host $Hint -ForegroundColor DarkGray
}

function Show-Header {
    $width = 62
    $title = " $AppName"
    $version = " $AppVersion"
    $brand = "by $Owner "
    Write-Host ''
    Write-Host ("  ┌{0}┐" -f ('─' * $width)) -ForegroundColor DarkCyan
    Write-Host '  │' -ForegroundColor DarkCyan -NoNewline
    Write-Host $title -ForegroundColor White -NoNewline
    Write-Host $version -ForegroundColor DarkGray -NoNewline
    Write-Host (' ' * ($width - $title.Length - $version.Length - $brand.Length)) -NoNewline
    Write-Host $brand -ForegroundColor DarkGray -NoNewline
    Write-Host '│' -ForegroundColor DarkCyan
    Write-Host ("  └{0}┘" -f ('─' * $width)) -ForegroundColor DarkCyan
    Write-Host ''
}

function Show-Panel {
    $state = Get-State
    Initialize-Language $state.lang
    Show-Header
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $installed = [bool]$svc
    $manualRunning = (-not ($svc -and $svc.Status -eq 'Running')) -and ((Get-EngineProcess).Count -gt 0)
    $dnsText = if ($state.dns) { Get-DnsShort $state.dnsProfile } else { (T 'off').ToLower() }

    if ($manualRunning) {
        Write-Row (T 'row_status') (T 'st_manual') Cyan
    } elseif (-not $installed) {
        Write-Row (T 'row_status') (T 'st_not_inst') Yellow
        Write-Row '' (T 'st_hint_start') Gray
    } else {
        if ($svc.Status -eq 'Running') { Write-Row (T 'row_status') (T 'st_running') Green }
        else                           { Write-Row (T 'row_status') (T 'st_stopped') Red }
    }

    if ($installed -or $manualRunning) {
        Write-Row (T 'row_preset') ("{0}  ·  DNS: {1}  ·  QUIC: {2}" -f
            (Get-StrategyLabel $state), $dnsText, (On-Off $state.quic).ToLower())
        if ($state.listMode -ne 'all') { Write-Row (T 'row_list') (Get-ListModeLabel $state) }
        $res = Get-ResourceText
        if ($res) { Write-Row (T 'row_res') $res }
    }
    if ($installed) {
        if (Test-OldInstall)                  { Write-Row (T 'row_ver') (T 'st_old') Yellow }
        elseif (Test-EngineFiles $InstallDir) { Write-Row (T 'row_sec') (T 'st_verified') Green }
        elseif (Test-UpdateReady)             { Write-Row (T 'row_ver') (T 'st_upd_ready') Yellow }
        else                                  { Write-Row (T 'row_sec') (T 'st_tampered') Red }
    }
    foreach ($name in $LegacyServices) {
        if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
            Write-Row (T 'row_note') (T 'st_legacy_note' @($name)) Yellow
        }
    }

    Write-Host ''
    if ($installed) { Write-MenuItem '1' (T 'm_repair')  '' (T 'm_install_h') }
    else            { Write-MenuItem '1' (T 'm_install') '' (T 'm_install_h') }
    Write-MenuItem '2' (T 'm_manual') '' (T 'm_manual_h')
    Write-MenuItem '3' (T 'm_diag')   '' (T 'm_diag_h')
    Write-MenuItem '4' (T 'm_site')   '' (T 'm_site_h')
    if ($installed -and $svc.Status -eq 'Running') { Write-MenuItem '5' (T 'm_stop')  '' (T 'm_stop_h') }
    else                                           { Write-MenuItem '5' (T 'm_start') '' (T 'm_start_h') }
    Write-MenuItem '6' (T 'm_adv')     '' (T 'm_adv_h')
    Write-MenuItem '7' (T 'm_updates') '' (T 'm_updates_h')
    Write-MenuItem '8' (T 'm_uninst')  '' (T 'm_uninst_h')
    Write-MenuItem '0' (T 'exit')      '' ''
    Write-Host ''
}

# ---------------------------------------------------------------- entry point

Initialize-Language (Get-State).lang

if ($Status) {
    Show-Panel
    return
}

if ($Manual) {
    if (-not (Test-Admin)) {
        $argStr = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Manual"
        if ($VerboseEngine) { $argStr += ' -VerboseEngine' }
        if ($Lang) { $argStr += " -Lang $Lang" }
        Start-Process -FilePath $PowerShell -Verb RunAs -ArgumentList $argStr
        return
    }
    Invoke-ManualWindow
    return
}

if ($ToggleService) {
    if (-not (Test-Admin)) {
        $argStr = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -ToggleService"
        if ($Lang) { $argStr += " -Lang $Lang" }
        Start-Process -FilePath $PowerShell -Verb RunAs -WindowStyle Hidden -ArgumentList $argStr
        return
    }
    Invoke-Toggle
    return
}

if ($Diagnostics) {
    if (-not (Test-Admin)) {
        $argStr = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Diagnostics"
        if ($Lang) { $argStr += " -Lang $Lang" }
        Start-Process -FilePath $PowerShell -Verb RunAs -ArgumentList $argStr
        return
    }
    $Host.UI.RawUI.WindowTitle = T 'diag_title' @($AppName, $AppVersion)
    try { $Host.UI.RawUI.BackgroundColor = 'Black'; $Host.UI.RawUI.ForegroundColor = 'Gray' } catch { }
    Clear-Host
    Show-Header
    Invoke-Diagnostics
    Write-Host ''
    Write-Host ("  " + (T 'press_any_close')) -ForegroundColor DarkGray
    [void][Console]::ReadKey($true)
    return
}

if (-not (Test-Admin)) {
    $argStr = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($Lang) { $argStr += " -Lang $Lang" }
    Start-Process -FilePath $PowerShell -Verb RunAs -ArgumentList $argStr
    return
}

$Host.UI.RawUI.WindowTitle = "$AppName $AppVersion"
try { $Host.UI.RawUI.BackgroundColor = 'Black'; $Host.UI.RawUI.ForegroundColor = 'Gray' } catch { }
[Console]::CursorVisible = $false

while ($true) {
    Clear-Host
    Show-Panel
    $key = "$([Console]::ReadKey($true).KeyChar)"
    if ($key -notin @('0', '1', '2', '3', '4', '5', '6', '7', '8')) { continue }
    if ($key -eq '0') { break }

    $installed = Test-ServiceInstalled
    $pause = $true
    try {
        switch ($key) {
            '1' { Invoke-Install }
            '2' { Invoke-ManualLaunchFromPanel }
            '3' { Invoke-Diagnostics }
            '4' { Invoke-SiteTest }
            '5' { if ($installed) { Invoke-Toggle } else { Write-Host ''; Write-Warn (T 'warn_install_first') } }
            '6' { Invoke-Advanced; $pause = $false }
            '7' { Invoke-UpdateCheck }
            '8' { if ($installed) { Invoke-Uninstall } else { Write-Host ''; Write-Warn (T 'warn_not_inst') } }
        }
    } catch {
        Clear-Progress-Line
        Write-Bad (T 'error_prefix' @($_.Exception.Message))
    }
    if (-not $pause) { continue }
    Write-Host ''
    Write-Host ("  " + (T 'press_any_panel')) -ForegroundColor DarkGray
    [void][Console]::ReadKey($true)
}
[Console]::CursorVisible = $true
