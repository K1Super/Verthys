# build_production.ps1 - Verthys 完整生产环境一键构建脚本
#
# 编码警告：本文件必须保存为 UTF-8 with BOM 编码！
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
#   - 所有工具路径来自系统环境变量（经 scripts/lib/env.load.ps1 注入）
#   - 脚本内零硬编码绝对路径
#   - 任一阶段失败立即终止，不继续后续阶段
#
# 用法:
#   powershell -ExecutionPolicy Bypass -File build_production.ps1 [-Clean] [-SkipCore] [-SkipWorker] [-SkipTauri] [-NoPause] [-Profile local|production]
#
# 参数:
#   -Clean       构建前清理所有构建目录
#   -SkipCore    跳过 C 核心构建（DLL 已存在时使用）
#   -SkipWorker  跳过 worker 构建（二进制已存在时使用）
#   -SkipTauri   跳过 Tauri 打包（仅构建组件时使用）
#   -NoPause     失败/成功后不暂停等待 Enter（CI 场景使用；双击运行时不传此参数以便查看输出）
#   -Profile     更新端点配置：local 仅回环验证，production 默认 HTTPS
#   -UpdaterEndpoint production 清单 URL；也可用 VERTHYS_UPDATER_ENDPOINT
#   -UpdaterArtifactRoot 物料根地址；留空时按 <端点源>/releases 派生
#   -AllowInsecureUpdater 允许 production 使用 HTTP + IP 端点（零成本自建分发）
#   -AllowLocal  允许以 local profile 打包（默认 production）
#   -ReleaseNotes 更新说明；留空时由发布脚本生成默认说明
#   -CompatAbiMin 兼容 ABI 下限；桥接发布显式传入，例如 0x000B
#   -CompatAbiMax 兼容 ABI 上限；留空时使用当前核心 ABI

param(
    [switch]$Clean,
    [switch]$SkipCore,
    [switch]$SkipWorker,
    [switch]$SkipTauri,
    [switch]$NoPause,
    [ValidateSet("local", "production")]
    [string]$Profile = "production",
    [string]$UpdaterEndpoint = $env:VERTHYS_UPDATER_ENDPOINT,
    [string]$UpdaterArtifactRoot = $env:VERTHYS_UPDATER_ARTIFACT_ROOT,
    [switch]$AllowInsecureUpdater,
    [switch]$AllowLocal,
    [string]$ReleaseNotes = "",
    [string]$CompatAbiMin = "",
    [string]$CompatAbiMax = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

# ========== 路径常量 ==========
$ScriptRoot  = $PSScriptRoot
$ScriptsDir  = Join-Path $ScriptRoot "scripts"
$ScriptsLibDir     = Join-Path $ScriptsDir "lib"
$ScriptsReleaseDir = Join-Path $ScriptsDir "release"
$ScriptsGatesDir   = Join-Path $ScriptsDir "gates"
$VerthysTauriDir = Join-Path $ScriptRoot "verthys-tauri"
$WorkerDir   = Join-Path $VerthysTauriDir "verthys-worker"
# externalBin 基准目录：Tauri v2 将 tauri.conf.json 的 externalBin 路径
#   相对该文件所在目录（src-tauri/）解析。副本必须落在 src-tauri\binaries\，
#   否则 tauri-build 校验报 "resource path doesn't exist"（2026-09-18 修复：
#   原先误复制到 verthys-tauri\binaries\，历史构建成功仅因 src-tauri\binaries\
#   存在清理前的暂存副本）。
$BinariesDir = Join-Path $VerthysTauriDir "src-tauri\binaries"
$CoreBuildDir = Join-Path $ScriptRoot "build"
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

$zombies = Get-Process -Name "cargo","rustc","Verthys","verthys-worker" -ErrorAction SilentlyContinue
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

# ========== Updater boundary gate ==========
# The updater plugin must stay a Rust-only dependency. If the webview gains its
# command permissions it can install packages without the lock gate.
Write-Stage "Stage 0.1: Updater boundary gate"
$boundaryGate = Join-Path $ScriptRoot "ci\check_updater_boundary.ps1"
if (-not (Test-Path $boundaryGate)) {
    throw "Updater boundary gate script is missing: $boundaryGate"
}
& $boundaryGate
if ($LASTEXITCODE -ne 0) {
    throw "Updater boundary gate failed"
}
Write-OK "Updater boundary gate passed"

# ========== 加载构建环境 ==========
Write-Stage "阶段 0.5: 加载构建环境"

# 探测顺序（CI 机制优先，本地一键脚本兼容）：
#   1. 外部已注入的 MSVC 工具链环境（ilammy/msvc-dev-cmd 或开发者命令
#      提示符：VCToolsInstallDir + INCLUDE + LIB + PATH 中的 cl.exe 就绪）
#      → 直接沿用，配 Ninja 单配置构建，不依赖任何自定义环境变量；
#   2. 未注入时 fallback 到 env.load.ps1（本地 VS 安装 + 4 个自定义环境
#      变量的多配置构建路径）。
$script:msvcInjected = $false
if (-not [string]::IsNullOrEmpty($env:VCToolsInstallDir) -and
    -not [string]::IsNullOrEmpty($env:INCLUDE) -and
    -not [string]::IsNullOrEmpty($env:LIB) -and
    (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    $script:msvcInjected = $true
    $cmakeCmd = Get-Command cmake.exe -ErrorAction SilentlyContinue
    if (-not $cmakeCmd) {
        throw "检测到已注入的 MSVC 环境，但 cmake.exe 不在 PATH（注入环境不完整）"
    }
    $ninjaCmd = Get-Command ninja.exe -ErrorAction SilentlyContinue
    if (-not $ninjaCmd) {
        throw "检测到已注入的 MSVC 环境，但 ninja.exe 不在 PATH（注入路径需要 Ninja 生成器）"
    }
    $script:effectiveCmake = $cmakeCmd.Source
    $script:effectiveGenerator = "Ninja"
    Write-OK "沿用已注入的 MSVC 工具链环境（Ninja 单配置）"
} else {
    . (Join-Path $ScriptsLibDir "env.load.ps1")
    $script:effectiveCmake = $VERTHYS_CMAKE_EXE
    $script:effectiveGenerator = $VERTHYS_VS_GENERATOR
    Write-OK "MSVC 环境已加载（env.load.ps1 本地路径）"
}
. (Join-Path $ScriptsLibDir "cmake.utils.ps1")

# C 核心 DLL 产物路径：由构建产物契约提供（scripts/lib/artifacts.ps1 读取
# CMake POST_BUILD 生成的 build/core/verthys.artifacts.json）——消除按
# 生成器类型猜测子目录的历史分支（Ninja/VS 布局差异曾导致哈希退化为 None）。
# 契约在构建/跳过决策之后读取：首次构建不会因契约尚未生成而失败。
# 注入器与契约写入器同样来自 scripts/lib，保证与 build_core.release.ps1
# 使用完全相同的完整性基准口径。
. (Join-Path $ScriptsLibDir "artifacts.ps1")
. (Join-Path $ScriptsLibDir "vsec.ps1")

# ========== 依赖与补丁校验 ==========
Write-Stage "阶段 0.6: 依赖与补丁校验"

# 0.6.1 清理旧错误日志
if (Test-Path $BuildErrLog) {
    Remove-Item $BuildErrLog -Force
    Write-Step "已清理旧构建错误日志: build_err.log"
}

# 0.6.2 前端依赖校验
# 缺失时用 npm ci 安装：以 package-lock.json 为唯一事实源（与 CI 同解析），
# 锁文件与 package.json 不同步时直接报错而不会静默漂移；
# npm 的进度/警告输出到 stderr，PowerShell 会包装为 ErrorRecord，故采用
# 变量捕获模式（先捕获 $output，恢复 ErrorActionPreference 后逐行处理）。
if (-not (Test-Path $NodeModulesDir)) {
    Write-Step "node_modules 缺失，执行 npm ci（以 package-lock.json 为准）..."
    Push-Location $VerthysTauriDir
    try {
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $output = & npm ci 2>&1
        $npmExit = $LASTEXITCODE
        $ErrorActionPreference = $prevEAP
        $output | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
        if ($npmExit -ne 0) {
            Write-Fail "npm ci 失败 (exit=$npmExit)"
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

# 0.6.4 Rust 依赖锁定校验（只读断言，不执行任何会改写锁文件的 cargo 命令）
# [patch.crates-io] 生效的标志：Cargo.lock 中 keyboard-types 条目不含
# source 字段（本地 path 补丁无注册表来源）。cargo update/metadata 均会
# 改写锁文件，故此处只用文本断言验证补丁已落锁，锁文件变更交由依赖
# 快照门禁与版本控制管理。
$lockFilePath = Join-Path $SrcTauriDir "Cargo.lock"
if (-not (Test-Path $lockFilePath)) {
    Write-Fail "Cargo.lock 不存在: $lockFilePath"
    throw "Cargo.lock 缺失，无法校验补丁"
}
$lockContent = Get-Content $lockFilePath -Raw
$patchBlock = [regex]::Match($lockContent,
    '\[\[package\]\](?:(?!\[\[).)*?name = "keyboard-types".*?(?=(\r?\n\[\[package\]\])|$)',
    [System.Text.RegularExpressions.RegexOptions]::Singleline)
if (-not $patchBlock.Success) {
    Write-Fail "Cargo.lock 中无 keyboard-types 条目"
    throw "补丁锁定校验失败"
}
if ($patchBlock.Value -match '(?m)^source\s*=') {
    Write-Fail "keyboard-types 条目仍指向注册表来源，[patch.crates-io] 未生效"
    throw "补丁未写入 Cargo.lock"
}
Write-OK "Cargo.lock 补丁已确认（本地 path 补丁生效）"

# ========== 阶段 1: 构建 C 核心 DLL ==========
if (-not $SkipCore) {
    Write-Stage "阶段 1/4: 构建 C 核心安全 DLL（verthys.dll）"

    # 陈旧缓存自愈（根因修复 2026-09-19）：项目目录迁移/重命名后，
    # build/CMakeCache.txt 记录的绝对路径（CMAKE_HOME_DIRECTORY）失效，
    # CMake 报 "CMakeCache.txt directory ... is different than the directory
    # ... where CMakeCache.txt was created" 并拒绝配置。检测到不一致时
    # 自动清理构建目录并全量重建，保证任意路径变更后一键构建仍可用。
    Clear-StaleCMakeCache -BuildDir $CoreBuildDir -SourceDir $ScriptRoot

    Write-Step "CMake Configure (Release, x64)"
    if ($script:msvcInjected) {
        & $script:effectiveCmake -S $ScriptRoot -B $CoreBuildDir -G Ninja -DCMAKE_BUILD_TYPE=Release
    } else {
        & $script:effectiveCmake -S $ScriptRoot -B $CoreBuildDir -G $script:effectiveGenerator -A x64
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "CMake 配置失败"
        throw "CMake 配置失败 (exit=$LASTEXITCODE)"
    }

    Write-Step "CMake Build (Release, 安全加固: /O2 /GL /GS /guard:cf)"
    if ($script:msvcInjected) {
        & $script:effectiveCmake --build $CoreBuildDir
    } else {
        & $script:effectiveCmake --build $CoreBuildDir --config Release
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "CMake 构建失败"
        throw "CMake 构建失败 (exit=$LASTEXITCODE)"
    }

    # 构建后读取产物契约（POST_BUILD 刚刷新），契约路径即权威 DLL 位置
    $script:actualCoreDll = Get-VerthysArtifactDll

    Assert-FileExists $script:actualCoreDll "verthys.dll"
} else {
    Write-Stage "阶段 1/4: 跳过 C 核心构建（-SkipCore）"
    # 跳过构建：契约必须来自既有构建；缺失即给明确指引而非继续
    $script:actualCoreDll = Get-VerthysArtifactDll
    Assert-FileExists $script:actualCoreDll "verthys.dll (已有)"
}

# ========== 阶段 1.1: .vsec 完整性基准注入 + 契约刷新 ==========
# 生产 DLL 必须在进入打包前完成 .vsec 签名：运行时 integrity_verify_startup
# 从磁盘重算 .text / .rdata / .rhat 三节 HMAC 并与 .vsec 基准逐槽比对；
# 全零 .vsec 会被视为开发构建而跳过验签，等于分发物失去完整性防线。
# -SkipCore 同样执行（幂等）：既有 DLL 可能来自旧构建或旧脚本，不能在
# “跳过重编”路径上漏掉安全基准。
Write-Stage "阶段 1.1/4: .vsec 完整性基准注入"
Update-VsecBaseline -DllPath $script:actualCoreDll
# 生成器/配置以现有契约为准：-SkipCore 时构建目录可能是另一种生成器
# （例如 CI 注入环境用 Ninja、本地显式环境用 Visual Studio）产出，
# 用当前 shell 的 effectiveGenerator 会让重生成契约的元数据失真。
$coreManifest = Get-VerthysArtifactManifest
$script:coreContract = Write-VerthysArtifactContract `
    -DllPath $script:actualCoreDll `
    -CmakeExe $script:effectiveCmake `
    -Generator $coreManifest.generator `
    -Config $coreManifest.config `
    -SourceDir $ScriptRoot `
    -OutPath (Join-Path $CoreBuildDir "core\verthys.artifacts.json")
Write-OK "完整性基准已注入，产物契约已按最终字节刷新（SHA256 / 生成器 / 配置一致）"

# ========== 阶段 2: 构建 verthys-worker ==========
if (-not $SkipWorker) {
    Write-Stage "阶段 2/4: 构建 verthys-worker 子进程（Rust release）"

    # 纵深防御：禁用增量编译（defense-in-depth）
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
Copy-Item -Path $script:actualCoreDll -Destination $DllTarget -Force
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

    # 4.3 更新签名密钥注入（createUpdaterArtifacts 必需）
    #   私钥与密码文件位于用户配置目录，不进入仓库与安装包；
    #   已显式设置环境变量时以环境变量为准（CI 场景）。
    if (-not $env:TAURI_SIGNING_PRIVATE_KEY) {
        $defaultKeyPath = Join-Path $env:USERPROFILE ".tauri\verthys-updater.key"
        if (-not (Test-Path $defaultKeyPath)) {
            Write-Fail "缺少更新私钥: $defaultKeyPath"
            throw "更新签名私钥缺失，无法生成更新产物"
        }
        # 打包器读取 TAURI_SIGNING_PRIVATE_KEY；注入私钥文本，避免依赖路径解析差异
        $env:TAURI_SIGNING_PRIVATE_KEY = ([System.IO.File]::ReadAllText($defaultKeyPath)).Trim()
    }
    if (-not $env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD) {
        $defaultPassPath = Join-Path $env:USERPROFILE ".tauri\verthys-updater.pass"
        if (-not (Test-Path $defaultPassPath)) {
            Write-Fail "缺少更新私钥密码文件: $defaultPassPath"
            throw "更新签名私钥密码缺失，无法生成更新产物"
        }
        $env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = ([System.IO.File]::ReadAllText($defaultPassPath)).Trim()
    }
    Write-OK "更新签名密钥已注入"

    # 4.4 Tauri 打包（NSIS 安装包 + 更新签名）
    $nodeCmd = Get-Command node.exe -ErrorAction SilentlyContinue
    if (-not $nodeCmd) {
        throw "未找到 node.exe，无法校验更新 profile"
    }
    $artifactRootValue = ""
    if ($Profile -eq "production") {
        if ([string]::IsNullOrWhiteSpace($UpdaterEndpoint)) {
            throw "production requires -UpdaterEndpoint or VERTHYS_UPDATER_ENDPOINT"
        }
        $endpointUri = $null
        if (-not [Uri]::TryCreate($UpdaterEndpoint, [UriKind]::Absolute, [ref]$endpointUri)) {
            throw "UpdaterEndpoint must be an absolute URL"
        }
        $insecureUpdater = [bool]$AllowInsecureUpdater
        if ($endpointUri.Scheme -ne "https" -and -not ($insecureUpdater -and $endpointUri.Scheme -eq "http")) {
            throw "UpdaterEndpoint must use https (or pass -AllowInsecureUpdater for http)"
        }
        # 物料地址必须与清单端点同源：客户端只放行端点主机，跨源会被准入校验拒绝。
        $artifactRootValue = $UpdaterArtifactRoot
        if ([string]::IsNullOrWhiteSpace($artifactRootValue)) {
            $artifactRootValue = $endpointUri.GetLeftPart([System.UriPartial]::Authority) + "/releases"
        }
        $artifactUri = $null
        if (-not [Uri]::TryCreate($artifactRootValue, [UriKind]::Absolute, [ref]$artifactUri)) {
            throw "UpdaterArtifactRoot must be an absolute URL"
        }
        if ($artifactUri.Scheme -ne $endpointUri.Scheme) {
            throw "UpdaterArtifactRoot scheme must match UpdaterEndpoint"
        }
        if ($artifactUri.Host -ne $endpointUri.Host) {
            throw "UpdaterArtifactRoot host must match UpdaterEndpoint"
        }
        $artifactRootValue = $artifactRootValue.TrimEnd([char]'/')
        $templateConfig = Join-Path $VerthysTauriDir "src-tauri\tauri.production.conf.json"
        if (-not (Test-Path $templateConfig)) {
            throw "missing production template: $templateConfig"
        }
        $generatedDir = Join-Path $ScriptRoot "build"
        New-Item -ItemType Directory -Force -Path $generatedDir | Out-Null
        $profileConfig = Join-Path $generatedDir "tauri.production.generated.conf.json"
        $config = Get-Content -LiteralPath $templateConfig -Raw | ConvertFrom-Json
        $config.plugins.updater.endpoints = @($UpdaterEndpoint)
        $config.plugins.updater.channel = "stable"
        $config.plugins.updater.dangerousInsecureTransportProtocol = $insecureUpdater
        $config.plugins.updater.allowedDownloadHosts = @($endpointUri.Host)
        $config | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $profileConfig -Encoding ASCII
        $profileGateArgs = @($profileConfig, "--profile", "production", "--endpoint", $UpdaterEndpoint, "--base", (Join-Path $SrcTauriDir "tauri.conf.json"))
        if ($insecureUpdater) {
            $profileGateArgs += "--allow-insecure"
        }
    } else {
        if (-not $AllowLocal) {
            throw "local profile requires -AllowLocal"
        }
        $profileConfig = Join-Path $VerthysTauriDir "src-tauri\tauri.local.conf.json"
        if (-not (Test-Path $profileConfig)) {
            throw "missing local overlay: $profileConfig"
        }
        $profileGateArgs = @($profileConfig, "--profile", "local")
    }
    & $nodeCmd.Source (Join-Path $ScriptsGatesDir "check_updater_profile.mjs") @profileGateArgs
    if ($LASTEXITCODE -ne 0) {
        throw "更新 profile 配置校验失败: $Profile"
    }
    Write-OK "更新 profile 配置校验通过: $Profile"

    Write-Step "npm run tauri build (profile=$Profile)"
    Push-Location $VerthysTauriDir
    try {
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $output = & npm run tauri build -- --config $profileConfig 2>&1
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

# ========== 阶段 4.5: 发布符号清理与 SBOM ==========
Write-Stage "阶段 4.5: 发布符号清理与 SBOM"

# 发布目录 PDB 不进入安装包，但残留会被离线审计视为调试符号泄露。
foreach ($pdbDir in @((Join-Path $SrcTauriDir "target\release"), (Join-Path $WorkerDir "target\release"))) {
    if (Test-Path $pdbDir) {
        Get-ChildItem -Path $pdbDir -Filter *.pdb -File -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
}
Write-OK "发布目录 PDB 已清理"

$nodeCmd = Get-Command node.exe -ErrorAction SilentlyContinue
if (-not $nodeCmd) {
    throw "未找到 node.exe，无法生成 SBOM"
}
$sbomScript = Join-Path $ScriptsReleaseDir "generate_sbom.mjs"
if (-not (Test-Path $sbomScript)) {
    throw "SBOM 生成脚本缺失: $sbomScript"
}
& $nodeCmd.Source $sbomScript $ScriptRoot
if ($LASTEXITCODE -ne 0) {
    throw "SBOM 生成失败 (exit=$LASTEXITCODE)"
}
Write-OK "SBOM 已生成: build\sbom.cdx.json"

# ========== 阶段 5: 产物校验 ==========
Write-Stage "构建完成 — 产物校验"

$allOk = $true

# C 核心 DLL
if (Test-Path $script:actualCoreDll) {
    $info = Get-Item $script:actualCoreDll
    Write-OK ("verthys.dll: {0} ({1} KB)" -f $info.LastWriteTime, [math]::Round($info.Length / 1KB, 1))
    if (Test-VsecBaseline -DllPath $script:actualCoreDll) {
        Write-OK "verthys.dll .vsec 完整性基准校验通过（text+rdata+rhat）"
    } else {
        Write-Fail "verthys.dll .vsec 完整性基准缺失或失配"
        $allOk = $false
    }
} else {
    Write-Fail "verthys.dll 缺失"
    $allOk = $false
}

# DLL 打包副本（Tauri resources 实际消费的文件）
if (Test-Path $DllTarget) {
    if (Test-VsecBaseline -DllPath $DllTarget) {
        Write-OK "src-tauri/verthys.dll .vsec 完整性基准校验通过"
    } else {
        Write-Fail "src-tauri/verthys.dll .vsec 完整性基准缺失或失配"
        $allOk = $false
    }
} else {
    Write-Fail "DLL 打包副本缺失: $DllTarget"
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

# 更新发布物料：签名清单 + 安装包副本 + 账本
if (-not $SkipTauri -and $allOk -and (Test-Path $nsisDir)) {
    # 目录会残留历史安装包；必须按根 VERSION 精确选取，否则会把旧包当作新版本发布。
    $productVersion = ([System.IO.File]::ReadAllText((Join-Path $ScriptRoot "VERSION"))).Trim()
    $installerName = "Verthys_${productVersion}_x64-setup.exe"
    $installer = Get-Item (Join-Path $nsisDir $installerName) -ErrorAction SilentlyContinue
    $signature = if ($installer) { Get-Item ("{0}.sig" -f $installer.FullName) -ErrorAction SilentlyContinue } else { $null }
    if (-not $installer -or -not $signature) {
        Write-Fail "missing installer or signature for release artifacts"
        $allOk = $false
    } else {
        # Authenticode 是可选的系统信任层；未签名只提示 SmartScreen 风险，
        # 更新完整性仍由清单签名、安装包签名、SHA256 与 PE 版本保证。
        if ($Profile -eq "production") {
            $authSignature = Get-AuthenticodeSignature -LiteralPath $installer.FullName
            if ($authSignature.Status -ne "Valid") {
                Write-Host "  [warn] installer is not Authenticode trusted: $($authSignature.Status)" -ForegroundColor Yellow
            } else {
                Write-OK "Authenticode 签名有效: $($authSignature.SignerCertificate.Subject)"
            }
        }
        $releaseEndpoint = if ($Profile -eq "production") { $UpdaterEndpoint } else { "http://127.0.0.1:8765/latest.json" }
        $releaseArgs = @(
            (Join-Path $ScriptsReleaseDir "release_update.mjs"),
            "--installer", $installer.FullName,
            "--signature", $signature.FullName,
            "--endpoint", $releaseEndpoint,
            "--channel", $(if ($Profile -eq "production") { "stable" } else { "local" }),
            "--profile", $Profile
        )
        if ($Profile -eq "production" -and -not [string]::IsNullOrWhiteSpace($artifactRootValue)) {
            $releaseArgs += @("--artifact-root", $artifactRootValue)
        }
        if (-not [string]::IsNullOrWhiteSpace($ReleaseNotes)) {
            $releaseArgs += @("--notes", $ReleaseNotes)
        }
        if (-not [string]::IsNullOrWhiteSpace($CompatAbiMin)) {
            $releaseArgs += @("--compat-abi-min", $CompatAbiMin)
        }
        if (-not [string]::IsNullOrWhiteSpace($CompatAbiMax)) {
            $releaseArgs += @("--compat-abi-max", $CompatAbiMax)
        }
        & $nodeCmd.Source @releaseArgs
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "release artifact generation failed"
            $allOk = $false
        } else {
            Write-OK "release artifacts generated"
        }
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
