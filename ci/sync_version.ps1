<#
.SYNOPSIS
    Sync the product version across the repo from the single source of truth.

.DESCRIPTION
    The only hand-edited source of the product version is the root VERSION file
    (a single semver line). This script copies it to every generated carrier:

        1. verthys-tauri/src-tauri/Cargo.toml       (package version)
        2. verthys-tauri/verthys-worker/Cargo.toml  (package version)
        3. verthys-tauri/package.json               (root version)
        4. verthys-tauri/package-lock.json          (root + packages."" entry)
        5. verthys-tauri/src/app/config.ts          (VITE_APP_VERSION fallback)

    Guard rails enforced in both modes:
        - tauri.conf.json MUST NOT carry a top-level "version" key. The Tauri
          toolchain falls back to the src-tauri crate version when it is absent,
          so removing it here keeps one source instead of two.
        - The root CMakeLists.txt MUST NOT hardcode a VERSION number; it reads
          the VERSION file at configure time. A hardcoded line cannot be fixed
          automatically and fails the script in both modes.

    Usage:
        powershell -ExecutionPolicy Bypass -File ci\sync_version.ps1
        powershell -ExecutionPolicy Bypass -File ci\sync_version.ps1 -CheckOnly

    -CheckOnly verifies consistency without writing; it is the CI gate (exit 1
    on any drift). Without -CheckOnly the script applies the VERSION value to
    all carriers. Exit code: 0 = consistent (or applied), 1 = drift / invalid.

.NOTES
    Encoding: files are read with BOM auto-detection and written back as UTF-8
    without BOM. Line endings are preserved because replacements splice inside
    the original text.
#>
param(
    [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$VersionFile = Join-Path $Root "VERSION"

if (-not (Test-Path -LiteralPath $VersionFile)) {
    Write-Host "[FAIL] missing $VersionFile"
    exit 1
}
$Version = ([System.IO.File]::ReadAllText($VersionFile)).Trim()
if ($Version -notmatch '^\d+\.\d+\.\d+$') {
    Write-Host "[FAIL] $VersionFile must hold a single semver line (MAJOR.MINOR.PATCH), got '$Version'"
    exit 1
}

function Get-ContentRaw([string]$Path) {
    return [System.IO.File]::ReadAllText($Path)
}
function Set-ContentRaw([string]$Path, [string]$Content) {
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
}

$driftCount = 0
$hardFail = $false

# ---- TOML carriers: first standalone "version = " line is the [package] field ----
$cargoTargets = @(
    (Join-Path $Root "verthys-tauri\src-tauri\Cargo.toml"),
    (Join-Path $Root "verthys-tauri\verthys-worker\Cargo.toml")
)
foreach ($path in $cargoTargets) {
    $content = Get-ContentRaw $path
    $m = [regex]::Match($content, '(?m)^version\s*=\s*"[^"]*"')
    if (-not $m.Success) {
        Write-Host "[FAIL] $path : no package version line found"
        $hardFail = $true
        continue
    }
    $current = $m.Value -replace '^.*"([^"]+)"$', '$1'
    if ($current -ne $Version) {
        Write-Host "[DIFF] $path : $current -> $Version"
        $driftCount++
        if (-not $CheckOnly) {
            $replacement = 'version = "' + $Version + '"'
            $content = $content.Substring(0, $m.Index) + $replacement + $content.Substring($m.Index + $m.Length)
            Set-ContentRaw $path $content
            Write-Host "[FIX ] $path written"
        }
    } else {
        Write-Host "[ OK ] $path : $current"
    }
}

# ---- JSON carriers ----
$jsonSingle = Join-Path $Root "verthys-tauri\package.json"
$jsonPair = Join-Path $Root "verthys-tauri\package-lock.json"

# package.json: the first standalone '"version": "..."' line is the root version.
$content = Get-ContentRaw $jsonSingle
$m = [regex]::Match($content, '(?m)^\s*"version":\s*"[^"]+"')
if (-not $m.Success) {
    Write-Host "[FAIL] $jsonSingle : no root version line found"
    $hardFail = $true
} else {
    $current = $m.Value -replace '^.*"([^"]+)"$', '$1'
    if ($current -ne $Version) {
        Write-Host "[DIFF] $jsonSingle : $current -> $Version"
        $driftCount++
        if (-not $CheckOnly) {
            $replacement = '"version": "' + $Version + '"'
            $content = $content.Substring(0, $m.Index) + $replacement + $content.Substring($m.Index + $m.Length)
            Set-ContentRaw $jsonSingle $content
            Write-Host "[FIX ] $jsonSingle written"
        }
    } else {
        Write-Host "[ OK ] $jsonSingle : $current"
    }
}

# package-lock.json: the first two standalone version lines belong to the root
# package (top-level object + the packages."" entry); dependencies follow later.
$content = Get-ContentRaw $jsonPair
$all = [regex]::Matches($content, '(?m)^\s*"version":\s*"[^"]+"')
if ($all.Count -lt 2) {
    Write-Host "[FAIL] $jsonPair : expected root version lines not found"
    $hardFail = $true
} else {
    $lockDrifted = $false
    for ($i = 1; $i -ge 0; $i--) {
        $mm = $all[$i]
        $current = $mm.Value -replace '^.*"([^"]+)"$', '$1'
        if ($current -ne $Version) {
            $lockDrifted = $true
            $driftCount++
            Write-Host "[DIFF] $jsonPair (entry $i) : $current -> $Version"
            if (-not $CheckOnly) {
                $replacement = '"version": "' + $Version + '"'
                $content = $content.Substring(0, $mm.Index) + $replacement + $content.Substring($mm.Index + $mm.Length)
            }
        }
    }
    if ($lockDrifted) {
        if (-not $CheckOnly) {
            Set-ContentRaw $jsonPair $content
            Write-Host "[FIX ] $jsonPair written"
        }
    } else {
        Write-Host "[ OK ] $jsonPair : $Version"
    }
}

# ---- TypeScript fallback in config.ts ----
$tsPath = Join-Path $Root "verthys-tauri\src\app\config.ts"
$content = Get-ContentRaw $tsPath
$m = [regex]::Match($content, '(?m)\.env\.VITE_APP_VERSION\s*\?\?\s*"([^"]+)"')
if (-not $m.Success) {
    Write-Host "[FAIL] $tsPath : VITE_APP_VERSION fallback pattern not found"
    $hardFail = $true
} else {
    $current = $m.Groups[1].Value
    if ($current -ne $Version) {
        Write-Host "[DIFF] $tsPath : $current -> $Version"
        $driftCount++
        if (-not $CheckOnly) {
            $content = $content.Substring(0, $m.Groups[1].Index) + $Version + $content.Substring($m.Groups[1].Index + $m.Groups[1].Length)
            Set-ContentRaw $tsPath $content
            Write-Host "[FIX ] $tsPath written"
        }
    } else {
        Write-Host "[ OK ] $tsPath : $current"
    }
}

# ---- Guard rail: tauri.conf.json must not carry a top-level version key ----
$tauriPath = Join-Path $Root "verthys-tauri\src-tauri\tauri.conf.json"
$content = Get-ContentRaw $tauriPath
$m = [regex]::Match($content, '(?m)^ {2}"version"\s*:')
if ($m.Success) {
    $line = $content.Substring($m.Index, [Math]::Min(60, $content.Length - $m.Index)).Split("`n")[0].Trim()
    Write-Host "[DIFF] $tauriPath : top-level version key present ($line); Tauri must fall back to the src-tauri crate version"
    $driftCount++
    if (-not $CheckOnly) {
        $content = [regex]::Replace($content, '(?m)^ {2}"version"\s*:\s*"[^"]*",?\r?\n', '')
        Set-ContentRaw $tauriPath $content
        Write-Host "[FIX ] $tauriPath : top-level version key removed"
    }
} else {
    Write-Host "[ OK ] $tauriPath : no top-level version key (falls back to crate version)"
}

# ---- Guard rail: CMakeLists.txt must not hardcode a VERSION number ----
$cmakePath = Join-Path $Root "CMakeLists.txt"
$content = Get-ContentRaw $cmakePath
if ($content -match '(?m)^\s*VERSION\s+\d+\.\d+\.\d+\s*$') {
    Write-Host "[FAIL] $cmakePath : hardcoded VERSION line found; CMake must read the root VERSION file"
    $hardFail = $true
} else {
    Write-Host "[ OK ] $cmakePath : version read from the root VERSION file"
}

Write-Host ""
if ($hardFail) {
    Write-Host "[GATE] FAIL : structural problem, cannot continue"
    exit 1
}
if ($CheckOnly) {
    if ($driftCount -gt 0) {
        Write-Host "[GATE] FAIL : $driftCount drift(s) detected. Edit the root VERSION file, run ci\sync_version.ps1, then commit the result."
        exit 1
    }
    Write-Host "[GATE] PASS : all carriers consistent with VERSION ($Version)"
    exit 0
}
if ($driftCount -gt 0) {
    Write-Host "[DONE] synchronized $driftCount carrier(s) to $Version"
} else {
    Write-Host "[DONE] already consistent at $Version"
}
exit 0