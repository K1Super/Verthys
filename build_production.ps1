# build_production.ps1 - Verthys 完整生产环境一键构建脚本
#
# ★ 编码警告：本文件必须保存为 UTF-8 with BOM 编码！
#   Windows PowerShell 5.1 对无 BOM 文件按 ANSI/GBK 解码，中文注释乱码会
#   破坏字符串/大括号配对导致解析错误（ParseError），而解析错误发生在任何
#   代码执行之前，脚本内的 try/catch 与 Read-Host 暂停完全失效——表现为
#   窗口一闪而过且无任何错误显示。保存后请确认文件头 3 字节为 EF BB BF。
#
# 构建流程（严格顺序）：
#   阶段 1: 构建 C 核心安全 DLL（verthys.dll，CMake Release）
#   阶段 2: 构建 verthys-worker 子进程（Rust release）
#   阶段 3: 复制 worker 二进制到 binaries/（供 Tauri externalBin 打包）
#   阶段 4: 构建 Tauri 应用（NSIS 安装包）
#   阶段 5: 产物校验
#
# 环境隔离声明：
#   - 所有工具路径来自系统环境变量（经 scripts/env.load.ps1 注入）
#   - 脚本内零硬编码绝对路径
#   - 任一阶段失败立即终止，不继续后续阶段
#
# 用法:
#   powershell -ExecutionPolicy Bypass -File build_production.ps1 [-Clean] [-SkipCore] [-SkipWorker] [-SkipTauri] [-NoPause]
#
# 参数:
#   -Clean       构建前清理所有构建目录
#   -SkipCore    跳过 C 核心构建（DLL 已存在时使用）
#   -SkipWorker  跳过 worker 构建（二进制已存在时使用）
#   -SkipTauri   跳过 Tauri 打包（仅构建组件时使用）
#   -NoPause     失败/成功后不暂停等待 Enter（CI 场景使用；双击运行时不传此参数以便查看输出）

param(
    [switch]$Clean,
    [switch]$SkipCore,
    [switch]$SkipWorker,
    [switch]$SkipTauri,
    [switch]$NoPause
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

# ========== 路径常量 ==========
$ScriptRoot  = $PSScriptRoot
$ScriptsDir  = Join-Path $ScriptRoot "scripts"
$VerthysTauriDir = Join-Path $ScriptRoot "verthys-tauri"
$WorkerDir   = Join-Path $VerthysTauriDir "verthys-worker"
# ★ externalBin 基准目录：Tauri v2 将 tauri.conf.json 的 externalBin 路径
#   相对该文件所在目录（src-tauri/）解析。副本必须落在 src-tauri\binaries\，
#   否则 tauri-build 校验报 "resource path doesn't exist"（2026-09-18 修复：
#   原先误复制到 verthys-tauri\binaries\，历史构建成功仅因 src-tauri\binaries\
#   存在清理前的暂存副本）。
$BinariesDir = Join-Path $VerthysTauriDir "src-tauri\binaries"
$CoreBuildDir = Join-Path $ScriptRoot "build"
$CoreDllPath = Join-Path $CoreBuildDir "core\Release\verthys.dll"
$WorkerReleaseExe = Join-Path $WorkerDir "target\release\verthys-worker.exe"
$WorkerDebugExe   = Join-Path $WorkerDir "target\debug\verthys-worker.exe"
$WorkerBundledExe = Join-Path $BinariesDir "verthys-worker-x86_64-pc-windows-msvc.exe"
$SrcTauriDir  = Join-Path $VerthysTauriDir "src-tauri"
$NodeModulesDir = Join-Path $VerthysTauriDir "node_modules"
$KbTypesPatchDir = Join-Path $VerthysTauriDir "keyboard-types-patched"
$BuildErrLog = Join-Path $VerthysTauriDir "build_err.log"

# ========== 辅助函数 ==========
function Write-Stage {
    param([string]$Message)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  $Message" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Message)
    Write-Host "  [step] $Message" -ForegroundColor Gray
}

function Write-OK {
    param([string]$Message)
    Write-Host "  [OK] $Message" -ForegroundColor Green
}

function Write-Fail {
    param([string]$Message)
    Write-Host "  [FAIL] $Message" -ForegroundColor Red
}

function Assert-FileExists {
    param([string]$Path, [string]$Description)
    if (-not (Test-Path $Path)) {
        Write-Fail "$Description 不存在: $Path"
        throw "$Description 不存在: $Path"
    }
    $info = Get-Item $Path
    Write-OK ("{0}: {1} ({2} KB)" -f $Description, $info.LastWriteTime, [math]::Round($info.Length / 1KB, 1))
}

# ========== 预清理 ==========
if ($Clean) {
    Write-Stage "预清理：移除所有构建目录"
    if (Test-Path $CoreBuildDir) {
        Remove-Item -Recurse -Force $CoreBuildDir
        Write-Step "已清理: $CoreBuildDir"
    }
    $workerTarget = Join-Path $WorkerDir "target"
    if (Test-Path $workerTarget) {
        Remove-Item -Recurse -Force $workerTarget
        Write-Step "已清理: $workerTarget"
    }
    $tauriTarget = Join-Path $VerthysTauriDir "src-tauri\target"
    if (Test-Path $tauriTarget) {
        Remove-Item -Recurse -Force $tauriTarget
        Write-Step "已清理: $tauriTarget"
    }
}

# ========== 主流程（try/catch 包裹防止闪退） ==========
# 任何未捕获的错误都会进入 catch 块，显示错误信息并暂停（双击运行场景）
# -NoPause 参数可禁用暂停（CI 场景）
try {
# ========== 杀死僵尸进程 ==========
# 注意：必须用 Stop-Process -ErrorAction SilentlyContinue，不能用 taskkill。
# 原因：taskkill 是 native command，将错误写入 stderr；PowerShell 在
# $ErrorActionPreference="Stop" 下会把 stderr 包装为 ErrorRecord 并立即触发
# 终止错误（2>$null 重定向来不及生效）。当多个进程存在父子关系时，杀第一个
# 进程可能连带终止子进程，导致杀第二个时 taskkill 报 "process not found"，
# 从而触发脚本闪退。Stop-Process 是 PowerShell 原生 cmdlet，
# -ErrorAction SilentlyContinue 能正确抑制"进程不存在"错误。
Write-Stage "阶段 0: 清理僵尸进程与锁文件"

$zombies = Get-Process -Name "cargo","rustc","verthys-tauri","verthys-worker" -ErrorAction SilentlyContinue
if ($zombies) {
    Write-Step "发现僵尸进程: $($zombies.Name -join ', ') (PID: $($zombies.Id -join ', '))"
    foreach ($z in $zombies) {
        try {
            Stop-Process -Id $z.Id -Force -ErrorAction Stop
        } catch {
            # 进程可能在枚举后已自行退出（如父进程连带终止子进程），忽略此错误
            Write-Step "进程 PID $($z.Id) 已不存在，跳过"
        }
    }
    Start-Sleep -Seconds 2
    Write-OK "僵尸进程已清理"
} else {
    Write-OK "无僵尸进程"
}

$tauriTargetDir = Join-Path $VerthysTauriDir "src-tauri\target"
$lockFiles = Get-ChildItem $tauriTargetDir -Filter ".cargo-lock" -Recurse -ErrorAction SilentlyContinue
if ($lockFiles) {
    $lockFiles | ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue }
    Write-Step "已清理 cargo 锁文件"
}

# ========== 加载环境变量 ==========
Write-Stage "阶段 0.5: 加载构建环境"
. (Join-Path $ScriptsDir "env.load.ps1")
. (Join-Path $ScriptsDir "cmake.utils.ps1")
Write-OK "MSVC 环境已加载"

# ========== 依赖与补丁校验 ==========
Write-Stage "阶段 0.6: 依赖与补丁校验"

# 0.6.1 清理旧错误日志
if (Test-Path $BuildErrLog) {
    Remove-Item $BuildErrLog -Force
    Write-Step "已清理旧构建错误日志: build_err.log"
}

# 0.6.2 前端依赖校验
# 注意：npm 将进度/警告输出到 stderr，PowerShell 会将其包装为 ErrorRecord 对象。
# 直接管道 `& npm install 2>&1 | ForEach-Object` 在 ErrorActionPreference=Stop 下会触发脚本终止。
# 因此采用变量捕获模式：先捕获到 $output，再恢复 ErrorActionPreference 后逐行处理。
if (-not (Test-Path $NodeModulesDir)) {
    Write-Step "node_modules 缺失，执行 npm install..."
    Push-Location $VerthysTauriDir
    try {
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $output = & npm install 2>&1
        $npmExit = $LASTEXITCODE
        $ErrorActionPreference = $prevEAP
        $output | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
        if ($npmExit -ne 0) {
            Write-Fail "npm install 失败 (exit=$npmExit)"
            throw "前端依赖安装失败"
        }
    } finally {
        Pop-Location
    }
    Write-OK "前端依赖已安装"
} else {
    Write-OK "node_modules 已存在"
}

# 0.6.3 keyboard-types 本地补丁校验
# 修复 keyboard-types 0.7.0 的 bitflags! 宏内 derive(serde::Serialize) 路径语法不兼容问题
# Cargo.toml [patch.crates-io] 指向 ../keyboard-types-patched，必须存在
if (-not (Test-Path $KbTypesPatchDir)) {
    Write-Fail "keyboard-types-patched 目录缺失: $KbTypesPatchDir"
    Write-Host "  说明: Cargo.toml [patch.crates-io] 引用此目录修复 serde 兼容性" -ForegroundColor Yellow
    throw "补丁目录缺失，无法构建"
}
$kbPatchCargo = Join-Path $KbTypesPatchDir "Cargo.toml"
$kbPatchModRs = Join-Path $KbTypesPatchDir "src\modifiers.rs"
if (-not (Test-Path $kbPatchCargo) -or -not (Test-Path $kbPatchModRs)) {
    Write-Fail "keyboard-types-patched 内容不完整（缺少 Cargo.toml 或 src/modifiers.rs）"
    throw "补丁目录内容不完整"
}
Write-OK "keyboard-types 本地补丁就绪"

# 0.6.4 Rust 依赖锁定校验（确保补丁已写入 Cargo.lock）
Push-Location $SrcTauriDir
try {
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $output = & cargo update -p keyboard-types 2>&1
    $cargoUpdateExit = $LASTEXITCODE
    $ErrorActionPreference = $prevEAP
    if ($cargoUpdateExit -ne 0) {
        Write-Fail "cargo update -p keyboard-types 失败"
        $output | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        throw "补丁锁定更新失败"
    }
    Write-OK "Cargo.lock 补丁已确认"
} finally {
    Pop-Location
}

# ========== 阶段 1: 构建 C 核心 DLL ==========
if (-not $SkipCore) {
    Write-Stage "阶段 1/4: 构建 C 核心安全 DLL（verthys.dll）"

    # ★ 陈旧缓存自愈（根因修复 2026-09-19）：项目目录迁移/重命名后，
    # build/CMakeCache.txt 记录的绝对路径（CMAKE_HOME_DIRECTORY）失效，
    # CMake 报 "CMakeCache.txt directory ... is different than the directory
    # ... where CMakeCache.txt was created" 并拒绝配置。检测到不一致时
    # 自动清理构建目录并全量重建，保证任意路径变更后一键构建仍可用。
    Clear-StaleCMakeCache -BuildDir $CoreBuildDir -SourceDir $ScriptRoot

    Write-Step "CMake Configure (Release, x64)"
    & $VERTHYS_CMAKE_EXE -S $ScriptRoot -B $CoreBuildDir -G $VERTHYS_VS_GENERATOR -A x64
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "CMake 配置失败"
        throw "CMake 配置失败 (exit=$LASTEXITCODE)"
    }

    Write-Step "CMake Build (Release, 安全加固: /O2 /GL /GS /guard:cf)"
    & $VERTHYS_CMAKE_EXE --build $CoreBuildDir --config Release
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "CMake 构建失败"
        throw "CMake 构建失败 (exit=$LASTEXITCODE)"
    }

    Assert-FileExists $CoreDllPath "verthys.dll"
} else {
    Write-Stage "阶段 1/4: 跳过 C 核心构建（-SkipCore）"
    Assert-FileExists $CoreDllPath "verthys.dll (已有)"
}

# ========== 阶段 2: 构建 verthys-worker ==========
if (-not $SkipWorker) {
    Write-Stage "阶段 2/4: 构建 verthys-worker 子进程（Rust release）"

    # ★ 纵深防御：禁用增量编译（defense-in-depth）
    # 根因：dev profile 增量编译与 raw-dylib 导入库生成存在竞态，导致
    # LNK1181: 无法打开输入文件 "windows.0.52.0.lib"。
    # Cargo.toml [profile.dev] incremental=false 已是主修复；
    # 此处额外设置环境变量确保即使 Cargo.toml 被修改也安全。
    $env:CARGO_INCREMENTAL = "0"

    Write-Step "cargo build --release"
    Push-Location $WorkerDir
    try {
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $output = & cargo build --release 2>&1
        $cargoExit = $LASTEXITCODE
        $ErrorActionPreference = $prevEAP
        foreach ($line in $output) {
            $text = $line.ToString()
            if ($text -match "error\[|error:") {
                Write-Host "  $text" -ForegroundColor Red
            } elseif ($text -match "warning") {
                Write-Host "  $text" -ForegroundColor Yellow
            } elseif ($text -match "Finished") {
                Write-Host "  $text" -ForegroundColor Green
            }
        }
        if ($cargoExit -ne 0) {
            Write-Fail "verthys-worker 构建失败"
            throw "cargo build --release 失败 (exit=$cargoExit)"
        }
    } finally {
        Pop-Location
    }

    Assert-FileExists $WorkerReleaseExe "verthys-worker.exe (release)"

    # 同时构建 debug 版本（开发环境使用）
    Write-Step "cargo build (debug, 供开发环境)"
    Push-Location $WorkerDir
    try {
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $output = & cargo build 2>&1
        $debugExit = $LASTEXITCODE
        $ErrorActionPreference = $prevEAP
        $output | Select-Object -Last 3 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
        if ($debugExit -ne 0) {
            Write-Host "  [warn] debug 构建失败（不影响生产打包）" -ForegroundColor Yellow
        }
    } finally {
        Pop-Location
    }
} else {
    Write-Stage "阶段 2/4: 跳过 worker 构建（-SkipWorker）"
    Assert-FileExists $WorkerReleaseExe "verthys-worker.exe (已有)"
}

# ========== 阶段 3: 复制 worker 二进制与 DLL 到打包位置 ==========
Write-Stage "阶段 3/4: 部署 worker 二进制与 DLL（binaries/ + src-tauri/ + Tauri target）"

if (-not (Test-Path $BinariesDir)) {
    New-Item -ItemType Directory -Path $BinariesDir -Force | Out-Null
    Write-Step "创建 binaries/ 目录"
}

# 3.1 复制到 binaries/（供 Tauri externalBin 打包）
Copy-Item -Path $WorkerReleaseExe -Destination $WorkerBundledExe -Force
Write-OK "已复制: verthys-worker.exe -> binaries/verthys-worker-x86_64-pc-windows-msvc.exe"

Assert-FileExists $WorkerBundledExe "worker 打包二进制"

# 3.1.1 复制 DLL 到 src-tauri/（供 Tauri resources 打包）
# tauri.conf.json 中 resources: ["verthys.dll"]，Tauri 从 src-tauri/ 目录查找
# 如果不拷贝，Tauri 构建时会因找不到文件而失败
$DllTarget = Join-Path $SrcTauriDir "verthys.dll"
Copy-Item -Path $CoreDllPath -Destination $DllTarget -Force
Write-OK "已复制: verthys.dll -> src-tauri/verthys.dll"
Assert-FileExists $DllTarget "DLL 打包副本"

# 3.2 同步到 Tauri target 目录（防止开发模式 dev 落入旧版 worker 副本）
# 历史问题：src-tauri/target/{debug,release}/ 下存在旧版 verthys-worker.exe，
# 旧的 resolve_worker_path 优先匹配 Tauri 资源路径，导致使用过期二进制，
# 触发 "worker 就绪信号超时" 错误。即使新的 resolve_worker_path 已改为
# 开发环境优先查找 ../../../verthys-worker/target/，仍需同步到 target 目录
# 以保证 fallback 路径也能命中最新二进制（覆盖所有边界场景）。
$tauriTargetRoot = Join-Path $VerthysTauriDir "src-tauri\target"
$tauriDebugTarget = Join-Path $tauriTargetRoot "debug\verthys-worker.exe"
$tauriReleaseTarget = Join-Path $tauriTargetRoot "release\verthys-worker.exe"

# 同步 release 副本
if (Test-Path (Split-Path $tauriReleaseTarget -Parent)) {
    Copy-Item -Path $WorkerReleaseExe -Destination $tauriReleaseTarget -Force
    Write-OK "已同步 release worker 到 Tauri target: $tauriReleaseTarget"
}

# 同步 debug 副本（若 debug 目录存在且 debug worker 也已构建）
# 记录 debug target 实际使用的源文件，供哈希校验时比对
$debugTargetSource = $null
if (Test-Path (Split-Path $tauriDebugTarget -Parent)) {
    if (Test-Path $WorkerDebugExe) {
        Copy-Item -Path $WorkerDebugExe -Destination $tauriDebugTarget -Force
        Write-OK "已同步 debug worker 到 Tauri target: $tauriDebugTarget"
        $debugTargetSource = $WorkerDebugExe
    } else {
        # debug worker 未构建，使用 release 副本顶替（保证 dev 模式可用）
        Copy-Item -Path $WorkerReleaseExe -Destination $tauriDebugTarget -Force
        Write-OK "已用 release worker 顶替 Tauri target debug: $tauriDebugTarget"
        $debugTargetSource = $WorkerReleaseExe
    }
}

# 3.3 哈希校验：确认 binaries/ 与 Tauri target 副本一致（防止拷贝失败导致哈希漂移）
function Get-FileSha256 {
    param([string]$Path)
    $h = Get-FileHash -Algorithm SHA256 -Path $Path
    return $h.Hash.ToLower()
}

$srcHash = Get-FileSha256 $WorkerReleaseExe
foreach ($target in @($WorkerBundledExe, $tauriReleaseTarget, $tauriDebugTarget)) {
    if (Test-Path $target) {
        $tgtHash = Get-FileSha256 $target
        # debug target 可能使用 debug 或 release 源，按实际拷贝源校验
        $expectedHash = if ($target -eq $tauriDebugTarget -and $debugTargetSource) {
            Get-FileSha256 $debugTargetSource
        } else {
            $srcHash
        }
        if ($tgtHash -eq $expectedHash) {
            Write-OK ("哈希一致: {0}" -f (Split-Path $target -Leaf))
        } else {
            $leafName = Split-Path $target -Leaf
            $failMsg = "哈希漂移: $leafName (expected=$($expectedHash.Substring(0,12)), actual=$($tgtHash.Substring(0,12)))"
            Write-Fail $failMsg
            throw "worker 二进制哈希不一致: $target"
        }
    }
}

# ========== 阶段 4: 构建 Tauri 应用 ==========
if (-not $SkipTauri) {
    Write-Stage "阶段 4/4: 构建 Tauri 应用（NSIS 安装包）"

    # 4.1 前端类型检查（提前捕获 TypeScript 错误，避免 Tauri 混合输出难以定位）
    Write-Step "前端类型检查 (vue-tsc --noEmit)"
    Push-Location $VerthysTauriDir
    try {
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $output = & npx vue-tsc --noEmit 2>&1
        $tscExit = $LASTEXITCODE
        $ErrorActionPreference = $prevEAP
        if ($tscExit -ne 0) {
            Write-Fail "前端类型检查失败"
            $output | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
            throw "vue-tsc 类型检查失败 (exit=$tscExit)"
        }
    } finally {
        Pop-Location
    }
    Write-OK "前端类型检查通过"

    # 4.2 Rust 编译检查（提前捕获 Rust 错误，避免 NSIS 打包阶段才暴露）
    Write-Step "Rust 编译检查 (cargo check)"
    Push-Location $SrcTauriDir
    try {
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $output = & cargo check 2>&1
        $checkExit = $LASTEXITCODE
        $ErrorActionPreference = $prevEAP
        if ($checkExit -ne 0) {
            Write-Fail "Rust 编译检查失败"
            $output | ForEach-Object {
                $text = $_.ToString()
                if ($text -match "error\[|error:") {
                    Write-Host "  $text" -ForegroundColor Red
                }
            }
            throw "cargo check 失败 (exit=$checkExit)"
        }
    } finally {
        Pop-Location
    }
    Write-OK "Rust 编译检查通过"

    # 4.3 Tauri 打包（NSIS 安装包）
    Write-Step "npm run tauri build"
    Push-Location $VerthysTauriDir
    try {
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $output = & npm run tauri build 2>&1
        $tauriExit = $LASTEXITCODE
        $ErrorActionPreference = $prevEAP
        foreach ($line in $output) {
            $text = $line.ToString()
            if ($text -match "error|Error|ERROR|failed|Failed") {
                Write-Host "  $text" -ForegroundColor Red
            } elseif ($text -match "warn|Warn|WARNING") {
                Write-Host "  $text" -ForegroundColor Yellow
            } elseif ($text -match "Finished|completed|Built|Generating|Bundling") {
                Write-Host "  $text" -ForegroundColor Green
            } else {
                Write-Host "  $text" -ForegroundColor Gray
            }
        }
    } finally {
        Pop-Location
    }

    if ($tauriExit -ne 0) {
        Write-Fail "Tauri 构建失败 (exit=$tauriExit)"
        throw "Tauri 构建失败 (exit=$tauriExit)"
    }
} else {
    Write-Stage "阶段 4/4: 跳过 Tauri 打包（-SkipTauri）"
}

# ========== 阶段 5: 产物校验 ==========
Write-Stage "构建完成 — 产物校验"

$allOk = $true

# C 核心 DLL
if (Test-Path $CoreDllPath) {
    $info = Get-Item $CoreDllPath
    Write-OK ("verthys.dll: {0} ({1} KB)" -f $info.LastWriteTime, [math]::Round($info.Length / 1KB, 1))
} else {
    Write-Fail "verthys.dll 缺失"
    $allOk = $false
}

# Worker 二进制
if (Test-Path $WorkerBundledExe) {
    $info = Get-Item $WorkerBundledExe
    Write-OK ("verthys-worker-x86_64-pc-windows-msvc.exe: {0} ({1} KB)" -f $info.LastWriteTime, [math]::Round($info.Length / 1KB, 1))
} else {
    Write-Fail "verthys-worker 二进制缺失"
    $allOk = $false
}

# NSIS 安装包
$nsisDir = Join-Path $VerthysTauriDir "src-tauri\target\release\bundle\nsis"
if (Test-Path $nsisDir) {
    $installers = Get-ChildItem $nsisDir -Filter "*.exe" -ErrorAction SilentlyContinue
    if ($installers) {
        foreach ($inst in $installers) {
            Write-OK ("安装包: {0} ({1} MB)" -f $inst.Name, [math]::Round($inst.Length / 1MB, 2))
        }
    } else {
        Write-Fail "NSIS 安装包未生成"
        $allOk = $false
    }
} else {
    if (-not $SkipTauri) {
        Write-Fail "NSIS 输出目录不存在"
        $allOk = $false
    }
}

# 清理锁文件
Get-ChildItem $tauriTargetDir -Filter ".cargo-lock" -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

Write-Host ""
if ($allOk) {
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  全部构建成功！" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
} else {
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  构建存在缺失产物，请检查上方日志" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    throw "产物校验失败：存在缺失产物"
}

} catch {
    # 顶层错误捕获：防止任何未处理异常导致脚本直接闪退
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  构建失败：$($_.Exception.Message)" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "完整错误信息：" -ForegroundColor Yellow
    Write-Host "  $_" -ForegroundColor Yellow
    Write-Host ""
    if (-not $NoPause) {
        Write-Host "按 Enter 键退出..." -ForegroundColor Cyan
        Read-Host | Out-Null
    }
    exit 1
}

# 成功结束：双击运行场景下暂停以便查看结果，CI 场景（-NoPause）直接退出
if (-not $NoPause) {
    Write-Host ""
    Write-Host "按 Enter 键退出..." -ForegroundColor Cyan
    Read-Host | Out-Null
}
exit 0
