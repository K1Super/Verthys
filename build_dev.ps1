# Verthys Dev Launcher
# Cleans residual processes, prepares a signed production-parity dev runtime,
# then starts Tauri dev mode.
#
# Usage: .\build_dev.ps1
#
# ASCII only: Windows PowerShell 5.1 decodes BOM-less files with the ANSI code
# page, so localized comments can break parsing and make the script exit
# before printing any error.

$ErrorActionPreference = "SilentlyContinue"
$projectDir = Join-Path $PSScriptRoot "verthys-tauri"
$srcTauriDir = Join-Path $projectDir "src-tauri"
$nodeModulesDir = Join-Path $projectDir "node_modules"
$kbTypesPatchDir = Join-Path $projectDir "keyboard-types-patched"
$buildErrLog = Join-Path $projectDir "build_err.log"

# The dev runtime consumes a signed, production-parity C core built in the
# isolated build_dev directory and a signed worker built against that DLL.
# The P2 security service is a hard prerequisite: the kernel guard only accepts
# a signed host whose publisher matches the service pin, with a sibling worker.
. (Join-Path $PSScriptRoot "scripts\dev\dev_runtime.ps1")

$processNames = @("Verthys", "verthys-worker", "verthys-tauri", "dev_runner")

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Verthys Dev Launcher" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 0: Load MSVC build environment (vswhom-sys needs cl.exe in PATH).
# Without cl.exe, vswhom-sys fails to link with LNK2019:
# vswhom_find_visual_studio_and_windows_sdk is unresolved.
#
# Detection order:
#   1. An injected MSVC environment (VCToolsInstallDir + INCLUDE + LIB +
#      cl.exe on PATH) is used as-is.
#   2. Otherwise dot-source env.load.ps1 (local VS install plus the required
#      environment variables, including CC/CXX for the cc crate).
Write-Host "[0/5] Loading MSVC build environment..." -ForegroundColor Yellow
if (-not [string]::IsNullOrEmpty($env:VCToolsInstallDir) -and
    -not [string]::IsNullOrEmpty($env:INCLUDE) -and
    -not [string]::IsNullOrEmpty($env:LIB) -and
    (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    Write-Host "  Injected MSVC toolchain detected; reusing it" -ForegroundColor Green
} else {
    $envLoadScript = Join-Path $PSScriptRoot "scripts\lib\env.load.ps1"
    if (-not (Test-Path $envLoadScript)) {
        Write-Host "  !! env.load.ps1 not found: $envLoadScript" -ForegroundColor Red
        Write-Host "     vswhom-sys will fail to link (LNK2019)" -ForegroundColor Red
        exit 1
    }
    # env.load.ps1 sets EAP=Stop and StrictMode 3.0. Save and restore the
    # caller state so the rest of this launcher keeps its lenient cleanup
    # semantics (Get-Process / Get-NetTCPConnection may return nothing).
    $previousEap = $ErrorActionPreference
    . $envLoadScript
    $ErrorActionPreference = $previousEap
    Set-StrictMode -Off
}
$clCheck = Get-Command cl.exe -ErrorAction SilentlyContinue
if ($clCheck) {
    Write-Host "  cl.exe available: $($clCheck.Source)" -ForegroundColor Green
} else {
    Write-Host "  !! cl.exe still not in PATH" -ForegroundColor Red
    Write-Host "     vswhom-sys LNK2019 will recur" -ForegroundColor Red
    exit 1
}

# Step 1: Clean residual processes
Write-Host "[1/5] Checking residual processes..." -ForegroundColor Yellow

$killed = 0
foreach ($procName in $processNames) {
    $procs = Get-Process -Name $procName -ErrorAction SilentlyContinue
    if ($procs) {
        foreach ($p in $procs) {
            try {
                Write-Host "  -> Killing $($p.ProcessName) (PID: $($p.Id))" -ForegroundColor DarkYellow
                Stop-Process -Id $p.Id -Force -ErrorAction Stop
                $killed++
            } catch {
                Write-Host "  !! Cannot kill $($p.ProcessName) (PID: $($p.Id)): $_" -ForegroundColor Red
            }
        }
    }
}

if ($killed -eq 0) {
    Write-Host "  No residual processes" -ForegroundColor Green
} else {
    Write-Host "  Cleaned $killed residual processes" -ForegroundColor Green
    Start-Sleep -Milliseconds 500
}

# Step 2: Check port 1420
Write-Host ""
Write-Host "[2/5] Checking port 1420..." -ForegroundColor Yellow

$portConn = Get-NetTCPConnection -LocalPort 1420 -State Listen -ErrorAction SilentlyContinue
if ($portConn) {
    $portPid = $portConn.OwningProcess | Select-Object -First 1
    if ($portPid) {
        $portProc = Get-Process -Id $portPid -ErrorAction SilentlyContinue
        if ($portProc) {
            try {
                Write-Host "  -> Port 1420 occupied by $($portProc.ProcessName) (PID: $portPid), releasing..." -ForegroundColor DarkYellow
                Stop-Process -Id $portPid -Force -ErrorAction Stop
                Write-Host "  Port released" -ForegroundColor Green
                Start-Sleep -Milliseconds 500
            } catch {
                Write-Host "  !! Cannot release port: $_" -ForegroundColor Red
            }
        }
    }
} else {
    Write-Host "  Port 1420 is free" -ForegroundColor Green
}

# Step 3: Verify dependencies
Write-Host ""
Write-Host "[3/5] Verifying dependencies..." -ForegroundColor Yellow

# 3.1 Clean stale build error log
if (Test-Path $buildErrLog) {
    Remove-Item $buildErrLog -Force
    Write-Host "  -> Cleaned stale build_err.log" -ForegroundColor DarkYellow
}

# 3.2 Check node_modules (npm ci from package-lock.json when missing)
if (-not (Test-Path $nodeModulesDir)) {
    Write-Host "  -> node_modules missing, running npm ci..." -ForegroundColor DarkYellow
    Set-Location $projectDir
    & npm ci 2>&1 | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  !! npm ci failed" -ForegroundColor Red
        exit 1
    }
    Write-Host "  Dependencies installed" -ForegroundColor Green
} else {
    Write-Host "  node_modules OK" -ForegroundColor Green
}

# 3.3 Check keyboard-types patch
if (-not (Test-Path $kbTypesPatchDir)) {
    Write-Host "  !! keyboard-types-patched directory missing: $kbTypesPatchDir" -ForegroundColor Red
    Write-Host "     Cargo.toml [patch.crates-io] requires this directory" -ForegroundColor Red
    exit 1
}
$kbPatchCargo = Join-Path $kbTypesPatchDir "Cargo.toml"
$kbPatchModRs = Join-Path $kbTypesPatchDir "src\modifiers.rs"
if (-not (Test-Path $kbPatchCargo) -or -not (Test-Path $kbPatchModRs)) {
    Write-Host "  !! keyboard-types-patched incomplete (missing Cargo.toml or src/modifiers.rs)" -ForegroundColor Red
    exit 1
}
Write-Host "  keyboard-types patch OK" -ForegroundColor Green

# 3.4 Ensure Cargo.lock patch is applied (read-only assertion)
# [patch.crates-io] means the keyboard-types entry has no source field.
# Do not run cargo update here: it rewrites the lock file.
$kbLockPath = Join-Path $srcTauriDir "Cargo.lock"
$kbLockContent = Get-Content $kbLockPath -Raw
$kbPatchBlock = [regex]::Match($kbLockContent,
    '\[\[package\]\](?:(?!\[\[).)*?name = "keyboard-types".*?(?=(\r?\n\[\[package\]\])|$)',
    [System.Text.RegularExpressions.RegexOptions]::Singleline)
$patchConfirmed = $kbPatchBlock.Success -and $kbPatchBlock.Value -notmatch '(?m)^source\s*='
if (-not $patchConfirmed) {
    Write-Host "  !! keyboard-types patch not applied in Cargo.lock" -ForegroundColor Red
    exit 1
}
Write-Host "  Cargo.lock patch confirmed" -ForegroundColor Green

# Step 4: Sync Tauri staged resources and prepare the signed dev runtime
Write-Host ""
Write-Host "[4/5] Preparing signed dev runtime..." -ForegroundColor Yellow

# Tauri validates resource files during cargo build. Refresh the P2 service
# payload from the service build output before building the host.
$serviceResourceDir = Join-Path $srcTauriDir "service-payload"
$legacyServiceResourceDir = Join-Path $srcTauriDir "security-service"
if (Test-Path -LiteralPath $legacyServiceResourceDir) {
    Remove-Item -LiteralPath $legacyServiceResourceDir -Recurse -Force -ErrorAction SilentlyContinue
}
$serviceSourceDir = Join-Path $PSScriptRoot "build\security-service"
foreach ($name in @("VerthysSecuritySvc.exe", "VerthysRootCA.cer")) {
    $target = Join-Path $serviceResourceDir $name
    $source = Join-Path $serviceSourceDir $name
    $targetExists = Test-Path -LiteralPath $target
    if (Test-Path -LiteralPath $source) {
        $srcHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
        $needCopy = -not $targetExists
        if (-not $needCopy) {
            $dstHash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
            $needCopy = $srcHash -ne $dstHash
        }
        if ($needCopy) {
            try {
                New-Item -ItemType Directory -Path $serviceResourceDir -Force -ErrorAction Stop | Out-Null
                Copy-Item -LiteralPath $source -Destination $target -Force -ErrorAction Stop
                $copiedHash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
                if ($copiedHash -ne $srcHash) { throw "service payload hash mismatch" }
                Write-Host ("  -> Synced P2 service asset: {0}" -f $name) -ForegroundColor DarkYellow
            } catch {
                Write-Host ("  !! Failed to stage P2 service asset {0}: {1}" -f $name, $_) -ForegroundColor Red
                exit 1
            }
        }
    } elseif (-not $targetExists) {
        Write-Host ("  !! Missing P2 service payload {0}; run build_production.ps1 -Profile local -AllowLocal -SkipTauri once" -f $name) -ForegroundColor Red
        exit 1
    }
}

$previousEap = $ErrorActionPreference
$ErrorActionPreference = "Stop"
try {
    $signing = Resolve-VerthysDevSigning
    $devRuntime = Initialize-VerthysDevRuntime -Signing $signing
    $cargoRunner = Set-VerthysDevCargoRunner
    $env:VERTHYS_DEV_DLL_PATH = $devRuntime.DllPath
} catch {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  Dev runtime preparation failed" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ("  {0}" -f $_.Exception.Message) -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Required:" -ForegroundColor Yellow
    Write-Host "    - VerthysSecuritySvc installed and running" -ForegroundColor Gray
    Write-Host "    - signing certificate matching the service publisher pin" -ForegroundColor Gray
    Write-Host "    - build/security-service/security-service.artifacts.json present" -ForegroundColor Gray
    Write-Host ""
    exit 1
} finally {
    $ErrorActionPreference = $previousEap
}

Write-Host ("  Dev DLL:      {0}" -f $devRuntime.DllPath) -ForegroundColor Gray
Write-Host ("  Dev worker:   {0}" -f $devRuntime.WorkerPath) -ForegroundColor Gray
Write-Host ("  Staged host:  {0}" -f (Join-Path $devRuntime.StagedHostDir "Verthys.exe")) -ForegroundColor Gray
Write-Host ("  Publisher:    {0}..." -f $devRuntime.PublisherSha256.Substring(0, 16)) -ForegroundColor Gray
Write-Host ("  Cargo runner: {0}" -f $cargoRunner.Name) -ForegroundColor Gray
Write-Host "  Kernel guard uses the installed P2 service; no bypass is set" -ForegroundColor Green

# Step 5: Start dev mode
Write-Host ""
Write-Host "[5/5] Starting Tauri dev mode..." -ForegroundColor Yellow
Write-Host "  Dir: $projectDir" -ForegroundColor DarkGray
Write-Host ""

Set-Location $projectDir
npx tauri dev
