# Updater boundary gate.
#
# The updater plugin must stay a Rust-only dependency. If the webview can call
# plugin:updater|* it can install packages without the lock gate, pending marker,
# or health check. This gate fails fast when the capability set, npm manifest,
# lockfile, or frontend source re-opens that path.
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$violations = New-Object System.Collections.Generic.List[string]

$capabilityDir = Join-Path $root "verthys-tauri\src-tauri\capabilities"
if (Test-Path $capabilityDir) {
    Get-ChildItem -Path $capabilityDir -Filter *.json -File | ForEach-Object {
        $text = Get-Content -LiteralPath $_.FullName -Raw
        if ($text -match '"updater:') {
            $violations.Add("capability exposes updater plugin IPC: $($_.Name)")
        }
    }
} else {
    $violations.Add("capability directory is missing: $capabilityDir")
}

$packagePath = Join-Path $root "verthys-tauri\package.json"
if (-not (Test-Path $packagePath)) {
    $violations.Add("package manifest is missing: $packagePath")
} else {
    $package = Get-Content -LiteralPath $packagePath -Raw | ConvertFrom-Json
    foreach ($section in @("dependencies", "devDependencies")) {
        $deps = $package.$section
        if ($null -ne $deps -and $deps.PSObject.Properties.Name -contains "@tauri-apps/plugin-updater") {
            $violations.Add("package.json depends on @tauri-apps/plugin-updater ($section)")
        }
    }
}

$lockPath = Join-Path $root "verthys-tauri\package-lock.json"
if (-not (Test-Path $lockPath)) {
    $violations.Add("package lock is missing: $lockPath")
} elseif ((Get-Content -LiteralPath $lockPath -Raw) -match '@tauri-apps/plugin-updater') {
    $violations.Add("package-lock.json still contains @tauri-apps/plugin-updater")
}

$srcDir = Join-Path $root "verthys-tauri\src"
if (-not (Test-Path $srcDir)) {
    $violations.Add("frontend source directory is missing: $srcDir")
} else {
    Get-ChildItem -Path $srcDir -Recurse -File |
        Where-Object { $_.Extension -in ".ts", ".vue", ".js" } |
        ForEach-Object {
            $text = Get-Content -LiteralPath $_.FullName -Raw
            if ($text -match '@tauri-apps/plugin-updater') {
                $violations.Add("frontend imports the updater plugin API: $($_.FullName)")
            }
        }
}

if ($violations.Count -gt 0) {
    foreach ($item in $violations) {
        Write-Host "[FAIL] $item" -ForegroundColor Red
    }
    exit 1
}

Write-Host "[ OK ] updater boundary gate passed" -ForegroundColor Green
exit 0
