# Verthys Dev Launcher
# Clean residual processes, verify dependencies, then start Tauri dev mode
# Usage: .\dev.ps1

$ErrorActionPreference = "SilentlyContinue"
$projectDir = Join-Path $PSScriptRoot "verthys-tauri"
$srcTauriDir = Join-Path $projectDir "src-tauri"
$nodeModulesDir = Join-Path $projectDir "node_modules"
$kbTypesPatchDir = Join-Path $projectDir "keyboard-types-patched"
$buildErrLog = Join-Path $projectDir "build_err.log"

# Core binary paths — dev runtime consumes prod-built artifacts:
#   resolve_dll_path    -> build/core/Release/verthys.dll (always Release, never Debug)
#   resolve_worker_path -> verthys-worker/target/{release,debug}/verthys-worker.exe (release preferred)
$coreBuildDir     = Join-Path $PSScriptRoot "build"
$coreDllPath      = Join-Path $coreBuildDir "core\Release\verthys.dll"
$workerDir        = Join-Path $projectDir "verthys-worker"
$workerReleaseExe = Join-Path $workerDir "target\release\verthys-worker.exe"
$workerDebugExe   = Join-Path $workerDir "target\debug\verthys-worker.exe"
$buildProdScript  = Join-Path $PSScriptRoot "build_production.ps1"

$processNames = @("verthys-tauri", "verthys-worker")

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Verthys Dev Launcher" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 0: Load MSVC build environment (root-cause fix for vswhom LNK2019)
# 根因：build_dev.ps1 原未加载 MSVC 环境 → cl.exe 不在 PATH → cc crate 无法编译
# vswhom-sys 的 vswhom.cpp（C++ 源） → 链接时 LNK2019:
# vswhom_find_visual_studio_and_windows_sdk 未解析。build_production.ps1:144 已加载
# env.load.ps1，build_dev.ps1 必须对齐，确保 npx tauri dev → cargo run 时 cc crate
# 能找到 cl.exe（CC/CXX 均指向 cl.exe），vswhom.cpp 正确编译产出符号。
# env.load.ps1 还设置 INCLUDE/LIB/PATH，覆盖 cc crate 的 MSVC 自动探测（vswhere/
# 注册表探测在并行/沙箱环境中间歇性失败）。
Write-Host "[0/5] Loading MSVC build environment..." -ForegroundColor Yellow
$envLoadScript = Join-Path $PSScriptRoot "scripts\env.load.ps1"
if (-not (Test-Path $envLoadScript)) {
    Write-Host "  !! env.load.ps1 not found: $envLoadScript" -ForegroundColor Red
    Write-Host "     vswhom-sys 将因 cl.exe 缺失而链接失败（LNK2019）" -ForegroundColor Red
    exit 1
}
# env.load.ps1 内部设置 EAP=Stop + Set-StrictMode -Version 3.0，dot-source 会污染当前
# 作用域。保存本脚本 EAP（SilentlyContinue），加载后恢复；StrictMode 重置为 Off
# （本脚本原无严格模式，避免后续 Get-Process/Get-NetTCPConnection 等误报未定义变量）。
$prevEAP = $ErrorActionPreference
. $envLoadScript
$ErrorActionPreference = $prevEAP
Set-StrictMode -Off
# 校验 cl.exe 确实可用（env.load 已设 CC/CXX，但 PATH 优先级需确认）
$clCheck = Get-Command cl.exe -ErrorAction SilentlyContinue
if ($clCheck) {
    Write-Host "  cl.exe available: $($clCheck.Source)" -ForegroundColor Green
} else {
    Write-Host "  !! cl.exe still not in PATH after env.load" -ForegroundColor Red
    Write-Host "     vswhom-sys LNK2019 将复发" -ForegroundColor Red
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

# 3.2 Check node_modules
if (-not (Test-Path $nodeModulesDir)) {
    Write-Host "  -> node_modules missing, running npm install..." -ForegroundColor DarkYellow
    Set-Location $projectDir
    & npm install 2>&1 | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  !! npm install failed" -ForegroundColor Red
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

# 3.4 Ensure Cargo.lock patch is applied
Set-Location $srcTauriDir
& cargo update -p keyboard-types 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  !! cargo update -p keyboard-types failed" -ForegroundColor Red
    exit 1
}
Write-Host "  Cargo.lock patch confirmed" -ForegroundColor Green

# Step 4: Pre-flight core binaries (verthys.dll + verthys-worker.exe)
# Dev runtime resolves these via path_resolver.rs:
#   - verthys.dll  -> build/core/Release/verthys.dll (always Release, never Debug)
#   - verthys-worker  -> verthys-worker/target/{release,debug}/verthys-worker.exe (release preferred)
# If either is missing, delegate to build_production.ps1 -SkipTauri, which builds the
# C core + worker (release+debug), copies them into binaries/ and src-tauri/, syncs the
# Tauri target tree, and hash-verifies the copies — without running the NSIS packaging
# stage. Building core+worker together also avoids ABI drift between an old worker and
# a freshly rebuilt DLL.
Write-Host ""
Write-Host "[4/5] Pre-flight: core binaries (verthys.dll + verthys-worker.exe)..." -ForegroundColor Yellow

$dllMissing    = -not (Test-Path $coreDllPath)
$workerMissing = -not (Test-Path $workerReleaseExe) -and -not (Test-Path $workerDebugExe)

if (-not $dllMissing) {
    $info = Get-Item $coreDllPath
    Write-Host ("  verthys.dll OK ({0}, {1} KB)" -f $info.LastWriteTime, [math]::Round($info.Length / 1KB, 1)) -ForegroundColor Green
} else {
    Write-Host "  -> verthys.dll missing: $coreDllPath" -ForegroundColor DarkYellow
}

if (-not $workerMissing) {
    $wPath = if (Test-Path $workerReleaseExe) { $workerReleaseExe } else { $workerDebugExe }
    $info = Get-Item $wPath
    Write-Host ("  verthys-worker.exe OK ({0}, {1} KB)" -f $info.LastWriteTime, [math]::Round($info.Length / 1KB, 1)) -ForegroundColor Green
} else {
    Write-Host "  -> verthys-worker.exe missing (both release and debug)" -ForegroundColor DarkYellow
}

if ($dllMissing -or $workerMissing) {
    Write-Host "  -> Core binaries incomplete, invoking build_production.ps1 -SkipTauri..." -ForegroundColor DarkYellow
    if (-not (Test-Path $buildProdScript)) {
        Write-Host "  !! build_production.ps1 not found: $buildProdScript" -ForegroundColor Red
        exit 1
    }

    # Invoke as a child scope (&). Its own EAP/StrictMode are local; on failure it
    # exits with a non-zero code that we read via $LASTEXITCODE. -NoPause prevents
    # it from blocking on Read-Host in the dev-launcher context.
    & $buildProdScript -SkipTauri -NoPause
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  !! build_production.ps1 -SkipTauri failed (exit=$LASTEXITCODE)" -ForegroundColor Red
        exit 1
    }

    # Verify-after-build (persist-first principle: confirm artifacts actually landed)
    if (-not (Test-Path $coreDllPath)) {
        Write-Host "  !! verthys.dll still missing after build" -ForegroundColor Red
        exit 1
    }
    if (-not (Test-Path $workerReleaseExe) -and -not (Test-Path $workerDebugExe)) {
        Write-Host "  !! verthys-worker.exe still missing after build" -ForegroundColor Red
        exit 1
    }
    Write-Host "  Core binaries built and verified" -ForegroundColor Green
} else {
    Write-Host "  Core binaries ready (no rebuild needed)" -ForegroundColor Green
}

# Step 5: Start dev mode
Write-Host ""
Write-Host "[5/5] Starting Tauri dev mode..." -ForegroundColor Yellow
Write-Host "  Dir: $projectDir" -ForegroundColor DarkGray
Write-Host ""

Set-Location $projectDir
npx tauri dev
