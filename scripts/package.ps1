# Packages a verified, ready-to-share GhostDPI release ZIP and its SHA-256 file in dist\.
# Refuses to package if any binary in bin\ does not match the hashes recorded in app\panel.ps1.
# Copyright (c) 2026 Artapa. MIT License (LICENSE).
[CmdletBinding()]
param([switch]$Rebuild)

$ErrorActionPreference = 'Stop'
$root  = Split-Path $PSScriptRoot -Parent
$dist  = Join-Path $root 'dist'
$panel = Join-Path $root 'app\panel.ps1'

if ($Rebuild) {
    & (Join-Path $PSScriptRoot 'build.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'Engine build failed.' }
}

$panelText = [IO.File]::ReadAllText($panel)
if ($panelText -notmatch "\`$AppVersion\s*=\s*'([^']+)'") {
    throw 'Could not read $AppVersion from app\panel.ps1.'
}
$version = $Matches[1]

# Parse recorded SHA-256 hashes from app\panel.ps1 and verify bin\.
if ($panelText -notmatch '(?s)# BEGIN ENGINE HASHES(.*?)# END ENGINE HASHES') {
    throw 'Could not find ENGINE HASHES block in app\panel.ps1.'
}
$hashBlock = $Matches[1]
$expected = [ordered]@{}
foreach ($m in [regex]::Matches($hashBlock, "'([^']+)'\s*=\s*'([0-9a-fA-F]{64})'")) {
    $expected[$m.Groups[1].Value] = $m.Groups[2].Value.ToLower()
}
if ($expected.Count -lt 3) { throw 'Incomplete ENGINE HASHES block in app\panel.ps1.' }

$binDir = Join-Path $root 'bin'
foreach ($f in $expected.Keys) {
    $p = Join-Path $binDir $f
    if (-not (Test-Path -LiteralPath $p)) { throw "Missing binary: $p" }
    $actual = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $expected[$f]) {
        throw "SHA-256 mismatch for $f (expected $($expected[$f]), got $actual). Run scripts\build.ps1 first."
    }
}

# Verify UTF-8 BOM on PowerShell scripts so Windows PowerShell 5.1 renders non-ASCII letters cleanly.
foreach ($psFile in 'app\panel.ps1', 'app\tray.ps1') {
    $bytes = [IO.File]::ReadAllBytes((Join-Path $root $psFile))
    if ($bytes.Length -lt 3 -or $bytes[0] -ne 0xEF -or $bytes[1] -ne 0xBB -or $bytes[2] -ne 0xBF) {
        throw "$psFile is missing its UTF-8 BOM."
    }
}

# Verify app\lang.json parses cleanly and has both en and tr packs.
$langObj = [IO.File]::ReadAllText((Join-Path $root 'app\lang.json'), [Text.Encoding]::UTF8) | ConvertFrom-Json
if (-not $langObj.en -or -not $langObj.tr) { throw 'app\lang.json must contain both en and tr dictionaries.' }

$shipFiles = @(
    'GhostDPI.cmd',
    'GhostDPI-Manual.cmd',
    'GhostDPI-Tray.cmd',
    'README.md',
    'LICENSE',
    'app\panel.ps1',
    'app\tray.ps1',
    'app\lang.json',
    'licenses\LICENSE-windivert.txt',
    'bin\ghostdpi-engine.exe',
    'bin\WinDivert.dll',
    'bin\WinDivert64.sys'
)
foreach ($rel in $shipFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $root $rel))) {
        throw "Missing required release file: $rel"
    }
}

New-Item -ItemType Directory -Path $dist -Force | Out-Null
$zipName = "GhostDPI-$version-win64.zip"
$zipPath = Join-Path $dist $zipName
$shaPath = "$zipPath.sha256"
$stage   = Join-Path ([IO.Path]::GetTempPath()) ("ghostdpi-pkg-" + [Guid]::NewGuid().ToString('N'))

try {
    $inner = Join-Path $stage 'GhostDPI'
    foreach ($rel in $shipFiles) {
        $dst = Join-Path $inner $rel
        $dstDir = Split-Path -Parent $dst
        if (-not (Test-Path -LiteralPath $dstDir)) { New-Item -ItemType Directory -Path $dstDir -Force | Out-Null }
        Copy-Item -LiteralPath (Join-Path $root $rel) -Destination $dst -Force
    }
    if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory(
        $stage, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $false
    )
} finally {
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue }
}

$zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLower()
[IO.File]::WriteAllText($shaPath, "$zipHash  $zipName`r`n", (New-Object Text.UTF8Encoding $false))
$sizeKb = [Math]::Round((Get-Item -LiteralPath $zipPath).Length / 1KB, 1)

Write-Host "Packaged $zipPath ($sizeKb KB)"
Write-Host "SHA-256  $zipHash"
