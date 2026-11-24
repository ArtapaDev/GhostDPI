# Builds bin\ghostdpi-engine.exe with the Visual Studio C compiler, runs its self-test and
# writes the SHA-256 of every file in bin\ into app\panel.ps1 (the panel refuses files
# that do not match).
# Copyright (c) 2026 Artapa.
#
# -Define NAME -Out path.exe  builds a comparison copy elsewhere (no self-test, no hashes).
param([switch]$NoTest, [string]$Define, [string]$Out)

$ErrorActionPreference = 'Stop'
$root   = Split-Path $PSScriptRoot -Parent
$src    = Join-Path $root 'engine'
$vendor = Join-Path $root 'vendor\windivert'
$bin    = Join-Path $root 'bin'
$build  = Join-Path $root 'build'
New-Item -ItemType Directory -Force -Path $build | Out-Null

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw 'Visual Studio C++ build tools not found.' }
$vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'

$sources = 'main.c engine.c tls.c dns.c hostlist.c selftest.c' -split ' ' | ForEach-Object { "`"$src\$_`"" }
$cflags  = '/nologo /O2 /W4 /MT /GS /guard:cf /sdl /DNDEBUG /utf-8'
$lflags  = '/DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /GUARD:CF /SUBSYSTEM:CONSOLE /OPT:REF /OPT:ICF'
$libs    = "`"$build\WinDivert.lib`" winhttp.lib advapi32.lib `"$build\version.res`""
$exe     = if ($Out) { $Out } else { Join-Path $bin 'ghostdpi-engine.exe' }
if ($Define) { $cflags += " /D$Define" }

$cmd = @(
    "call `"$vcvars`" >nul",
    "lib /nologo /def:`"$vendor\WinDivert.def`" /machine:x64 /out:`"$build\WinDivert.lib`" >nul",
    "rc /nologo /fo `"$build\version.res`" `"$src\version.rc`"",
    "cl $cflags /I`"$vendor`" /Fo`"$build\\`" /Fe`"$exe`" $($sources -join ' ') /link $lflags $libs"
) -join ' && '

# vcvars64.bat looks for vswhere.exe on PATH.
$env:PATH = "$(Split-Path $vswhere -Parent);$env:PATH"
$ErrorActionPreference = 'Continue'
& cmd.exe /d /c "$cmd 2>&1"
$code = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
if ($code -ne 0) { throw "Build failed ($code)." }
Write-Host "Built $exe"
if ($Out) { return }

if (-not $NoTest) {
    & (Join-Path $bin 'ghostdpi-engine.exe') --self-test
    if ($LASTEXITCODE -ne 0) { throw 'Self-test failed.' }
}

# Record the engine hashes in the panel.
$panel = Join-Path $root 'app\panel.ps1'
if (Test-Path $panel) {
    $lines = foreach ($f in 'ghostdpi-engine.exe', 'WinDivert.dll', 'WinDivert64.sys') {
        $h = (Get-FileHash (Join-Path $bin $f) -Algorithm SHA256).Hash.ToLower()
        "    {0} = '{1}'" -f "'$f'".PadRight(21), $h
    }
    $text  = [IO.File]::ReadAllText($panel)
    $block = "# BEGIN ENGINE HASHES`r`n`$EngineFiles = [ordered]@{`r`n" + ($lines -join "`r`n") + "`r`n}`r`n# END ENGINE HASHES"
    $new   = [regex]::Replace($text, '(?s)# BEGIN ENGINE HASHES.*?# END ENGINE HASHES', { param($m) $block })
    if ($new -ne $text) {
        [IO.File]::WriteAllText($panel, $new, (New-Object Text.UTF8Encoding $true))
        Write-Host 'Engine hashes updated in app\panel.ps1'
    }
}
