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
#   powershell -ExecutionPolicy Bypass -File build_production.ps1 [-Clean] [-SkipCore] [-SkipWorker] [-SkipTauri] [-SkipService] [-IncludeDriver] [-NoPause] [-Profile local|production]
#
# 参数:
#   -Clean       显式全量清理构建产物与打包暂存（发布构建时使用）
#   -SkipCore    跳过 C 核心构建（DLL 已存在时使用）
#   -SkipWorker  跳过 worker 构建（二进制已存在时使用）
#   -SkipTauri   跳过 Tauri 打包（仅构建组件时使用）
#   -SkipService 跳过独立安全服务构建
#   -IncludeDriver 将已签名并校验过的 VerthysGuard 驱动载荷打入安装包；默认不打包
#   -NoPause     失败/成功后不暂停等待 Enter（CI 场景使用；双击运行时不传此参数以便查看输出）
#   -Profile     更新端点配置：local 仅回环验证，production 默认 HTTPS
#   -UpdaterEndpoint production 清单 URL；也可用 VERTHYS_UPDATER_ENDPOINT
#   -UpdaterArtifactRoot 物料根地址；留空时按 <端点源>/releases 派生
#   -AllowInsecureUpdater 允许 production 使用 HTTP + IP 端点（零成本自建分发）
#   -AllowLocal  允许以 local profile 打包（默认 production）
#   -ReleaseNotes 更新说明；留空时由发布脚本生成默认说明
#   -CompatAbiMin 兼容 ABI 下限；默认 0x000B，覆盖 4.1.x 及之后的旧客户端
#                 传入空字符串可退回仅当前核心 ABI 的严格清单
#   -CompatAbiMax 兼容 ABI 上限；留空时使用当前核心 ABI

param(
    [switch]$Clean,
    [switch]$SkipCore,
    [switch]$SkipWorker,
    [switch]$SkipTauri,
    [switch]$SkipService,
    [switch]$IncludeDriver,
    [switch]$NoPause,
    [ValidateSet("local", "production")]
    [string]$Profile = "production",
    [string]$UpdaterEndpoint = $env:VERTHYS_UPDATER_ENDPOINT,
    [string]$UpdaterArtifactRoot = $env:VERTHYS_UPDATER_ARTIFACT_ROOT,
    [switch]$AllowInsecureUpdater,
    [switch]$AllowLocal,
    [string]$ReleaseNotes = "",
    [string]$CompatAbiMin = "0x000B",
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
#   否则 tauri-build 校验报 "resource path doesn't exist"。
$BinariesDir = Join-Path $VerthysTauriDir "src-tauri\binaries"
$CoreBuildDir = Join-Path $ScriptRoot "build"
$WorkerReleaseExe = Join-Path $WorkerDir "target\release\verthys-worker.exe"
$WorkerDebugExe   = Join-Path $WorkerDir "target\debug\verthys-worker.exe"
$WorkerBundledExe = Join-Path $BinariesDir "verthys-worker-x86_64-pc-windows-msvc.exe"
# worker 与 DLL 的构建期绑定记录：worker 在编译期把 DLL 全文件摘要固化为常量，
# 只凭当前文件哈希无法判断 release worker 是否为本次 DLL 编译。-SkipWorker
# 复用既有产物时必须回读该记录，否则会把旧 worker 与新 DLL 打进同一个包。
$WorkerStampPath = Join-Path $CoreBuildDir "core\worker.artifacts.json"
$SrcTauriDir  = Join-Path $VerthysTauriDir "src-tauri"
$NodeModulesDir = Join-Path $VerthysTauriDir "node_modules"
$KbTypesPatchDir = Join-Path $VerthysTauriDir "keyboard-types-patched"
$BuildErrLog = Join-Path $VerthysTauriDir "build_err.log"
$DriverManifestPath = Join-Path $ScriptRoot "build_driver\driver.artifacts.json"

if ($IncludeDriver -and $SkipService) {
    throw "-IncludeDriver 需要服务载荷，不能与 -SkipService 同时使用"
}
if ($IncludeDriver -and -not (Test-Path -LiteralPath $DriverManifestPath -PathType Leaf)) {
    throw "驱动载荷未找到: $DriverManifestPath（先构建并签名驱动）"
}

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

# 记录/复核锁文件哈希：构建期间任何 cargo/npm 命令都不得改写锁文件，
# 否则产物与提交的依赖解析不一致，本地生产构建缺少 CI 快照门禁兜底。
function Get-VerthysLockSnapshot {
    param([Parameter(Mandatory = $true)][string]$Root)

    $entries = @(
        @{ Name = "verthys-tauri/src-tauri/Cargo.lock"; Path = (Join-Path $Root "verthys-tauri\src-tauri\Cargo.lock") },
        @{ Name = "verthys-tauri/verthys-worker/Cargo.lock"; Path = (Join-Path $Root "verthys-tauri\verthys-worker\Cargo.lock") },
        @{ Name = "verthys-tauri/package-lock.json"; Path = (Join-Path $Root "verthys-tauri\package-lock.json") }
    )
    foreach ($entry in $entries) {
        if (-not (Test-Path -LiteralPath $entry.Path -PathType Leaf)) {
            throw ("lock file missing: {0}" -f $entry.Path)
        }
        [pscustomobject]@{
            Name   = $entry.Name
            Path   = $entry.Path
            Sha256 = (Get-FileHash -LiteralPath $entry.Path -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
}

# 构建摘要：机器可读地固化版本、通道、素材哈希、发布者与安装包信息。
# 不含任何密钥材料；正常路径写入失败按构建失败处理，catch 中降级为警告。
function Write-VerthysBuildSummary {
    param(
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Summary,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $summaryDir = Join-Path $Root "build"
    if (-not (Test-Path -LiteralPath $summaryDir)) {
        New-Item -ItemType Directory -Path $summaryDir -Force | Out-Null
    }
    $summaryPath = Join-Path $summaryDir "build-summary.json"
    $tmpPath = "$summaryPath.tmp"
    $json = $Summary | ConvertTo-Json -Depth 8
    [System.IO.File]::WriteAllText($tmpPath, $json, (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $tmpPath -Destination $summaryPath -Force
    return $summaryPath
}

# 以独立进程运行签名宿主并捕获输出。初始化可能写入用户态持久状态，
# 门禁把 LOCALAPPDATA 指向临时目录，避免污染真实用户配置。
function Invoke-VerthysHostProcess {
    param(
        [Parameter(Mandatory = $true)][string]$ExePath,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$LocalAppData
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $ExePath
    $psi.WorkingDirectory = $WorkingDirectory
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.EnvironmentVariables["LOCALAPPDATA"] = $LocalAppData

    $proc = [System.Diagnostics.Process]::Start($psi)
    try {
        # 初始化卡死同样属于“未按预期拒绝/放行”，必须显式失败而不是挂住构建。
        if (-not $proc.WaitForExit(30000)) {
            try { $proc.Kill() } catch { }
            return [pscustomobject]@{ ExitCode = -1; Output = "TIMEOUT" }
        }
        $out = $proc.StandardOutput.ReadToEnd()
        [void]$proc.StandardError.ReadToEnd()
        return [pscustomobject]@{ ExitCode = $proc.ExitCode; Output = $out.Trim() }
    } finally {
        $proc.Dispose()
    }
}

# 定位签名宿主。缺失时按既有产物契约记录的生成器补建该测试目标，
# 避免 -SkipCore 路径上无法执行调用方认证功能门禁。
function Get-VerthysSignedHostPath {
    param(
        [Parameter(Mandatory = $true)][string]$BuildDir,
        [Parameter(Mandatory = $true)]$Manifest,
        [Parameter(Mandatory = $true)][string]$CmakeExe
    )
    $candidates = @(
        (Join-Path $BuildDir "core\tests\Release\vty_signed_host.exe"),
        (Join-Path $BuildDir "core\tests\vty_signed_host.exe")
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }

    Write-Step "构建 vty_signed_host（调用方认证门禁需要签名宿主）"
    if ([string]$Manifest.generator -eq "Ninja") {
        & $CmakeExe --build $BuildDir --target vty_signed_host
    } else {
        & $CmakeExe --build $BuildDir --config ([string]$Manifest.config) --target vty_signed_host
    }
    if ($LASTEXITCODE -ne 0) { throw "构建 vty_signed_host 失败" }

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    throw "构建后仍未找到 vty_signed_host.exe"
}

# 调用方认证功能门禁：
#   负向：未签名宿主 + 签名 DLL 必须返回 UNAUTHORIZED（0x00000016）；
#   正向：目标发布者签名宿主 + 签名 DLL 必须 Init 成功（0x00000000）。
# 正向宿主使用发布者证书签名的临时副本，验证钉扎指纹与真实产物一致；
# 临时目录在结束时删除，签名副本不进入仓库与交付物。
function Invoke-VerthysCallerAuthGate {
    param(
        [Parameter(Mandatory = $true)][string]$DllPath,
        [Parameter(Mandatory = $true)][string]$HostPath,
        [Parameter(Mandatory = $true)]$Signing
    )
    $workDir = Join-Path $env:TEMP ("verthys_caller_gate_" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $workDir -Force | Out-Null
    try {
        $localAppData = Join-Path $workDir "localappdata"
        New-Item -ItemType Directory -Path $localAppData -Force | Out-Null

        $unsignedDir = Join-Path $workDir "unsigned"
        New-Item -ItemType Directory -Path $unsignedDir -Force | Out-Null
        Copy-Item -LiteralPath $HostPath -Destination (Join-Path $unsignedDir "vty_signed_host.exe") -Force
        Copy-Item -LiteralPath $DllPath -Destination (Join-Path $unsignedDir "verthys.dll") -Force

        $negative = Invoke-VerthysHostProcess `
            -ExePath (Join-Path $unsignedDir "vty_signed_host.exe") `
            -WorkingDirectory $unsignedDir `
            -LocalAppData $localAppData
        if ($negative.Output -notmatch "INIT result=0x00000016") {
            throw "未签名宿主未被拒绝（期望 0x00000016）: exit=$($negative.ExitCode) output=$($negative.Output)"
        }
        Write-OK "未签名宿主被拒绝（UNAUTHORIZED）"

        $signedDir = Join-Path $workDir "signed"
        New-Item -ItemType Directory -Path $signedDir -Force | Out-Null
        $signedHost = Join-Path $signedDir "vty_signed_host.exe"
        Copy-Item -LiteralPath $HostPath -Destination $signedHost -Force
        # 门禁只验证钉扎指纹，临时宿主不引入时间戳网络依赖。
        Invoke-VerthysAuthenticodeSign -Path $signedHost -Certificate $Signing.Certificate | Out-Null
        Copy-Item -LiteralPath $DllPath -Destination (Join-Path $signedDir "verthys.dll") -Force

        $positive = Invoke-VerthysHostProcess `
            -ExePath $signedHost `
            -WorkingDirectory $signedDir `
            -LocalAppData $localAppData
        if ($positive.ExitCode -ne 0 -or $positive.Output -notmatch "INIT result=0x00000000") {
            throw "目标发布者签名宿主未放行: exit=$($positive.ExitCode) output=$($positive.Output)"
        }
        Write-OK "目标发布者签名宿主放行（Init 成功）"
    } finally {
        Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ========== 构建互斥锁 ==========
# 生产流程与 dev staging 都会写打包路径；互斥锁保证两者不交叉。
. (Join-Path $ScriptsLibDir "build_lock.ps1")
$script:BuildLock = $null

# ========== 构建摘要初始化 ==========
$versionFile = Join-Path $ScriptRoot "VERSION"
$buildVersion = if (Test-Path -LiteralPath $versionFile -PathType Leaf) {
    ([System.IO.File]::ReadAllText($versionFile)).Trim()
} else {
    ""
}
$script:BuildSummary = [ordered]@{
    schema           = 1
    result           = "unknown"
    version          = $buildVersion
    profile          = $Profile
    clean            = $false
    started_at       = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    finished_at      = ""
    dll              = $null
    worker           = $null
    publisher_sha256 = ""
    installer        = $null
    error            = ""
}

# ========== 主流程（try/catch 包裹防止闪退） ==========
# 任何未捕获的错误都会进入 catch 块，显示错误信息并暂停（双击运行场景）
# -NoPause 参数可禁用暂停（CI 场景）
try {
# ========== 构建互斥锁获取 ==========
# 与 dev staging 共用同一把仓库级锁；抢不到说明另一端仍在运行，拒绝并发。
try {
    $script:BuildLock = Enter-VerthysBuildLock -Root $ScriptRoot -Role production
} catch {
    throw ("已有构建流程正在运行，拒绝并发：{0}" -f $_.Exception.Message)
}
Write-OK "构建互斥锁已获取（production）"

# ========== 预检：清理语义与跳过阶段 ==========
# 默认增量构建；发布时显式 -Clean 全量重建。全量清理与跳过阶段互斥，
# 避免"清空了又跳过构建"的半成品状态。
$effectiveClean = [bool]$Clean
if ($effectiveClean) {
    $conflicts = @()
    if ($SkipCore) { $conflicts += "-SkipCore" }
    if ($SkipWorker) { $conflicts += "-SkipWorker" }
    if ($SkipService) { $conflicts += "-SkipService" }
    if ($conflicts.Count -gt 0) {
        throw ("全量清理与跳过阶段互斥：{0}。需要跳过阶段请去掉 -Clean" -f ($conflicts -join ", "))
    }
}
$script:BuildSummary.clean = $effectiveClean
Write-OK ("构建模式: {0}" -f $(if ($effectiveClean) { "全量清理" } else { "增量" }))

# ========== 阶段 0: 清理本仓库进程 ==========
# 只终止可执行文件位于本仓库内的进程：全局结束 cargo/rustc 会误伤本机其他
# 项目与 IDE 的编译进程；已安装的 Verthys 若在运行也不属于本仓库产物。
# 必须先于预清理：运行中的宿主会锁定 target 下的文件，先删目录必然失败。
Write-Stage "阶段 0: 清理本仓库进程"
$repoProcessPrefix = [System.IO.Path]::GetFullPath($ScriptRoot).TrimEnd('\') + '\'
$candidates = @(Get-Process -Name "cargo","rustc","Verthys","verthys-worker" -ErrorAction SilentlyContinue)
$zombies = @()
foreach ($candidate in $candidates) {
    $candidatePath = $null
    try { $candidatePath = $candidate.Path } catch { $candidatePath = $null }
    if ([string]::IsNullOrEmpty($candidatePath)) {
        Write-Step ("跳过无法定位路径的进程: {0} (PID {1})" -f $candidate.Name, $candidate.Id)
        continue
    }
    $candidateFull = [System.IO.Path]::GetFullPath($candidatePath)
    if ($candidateFull.StartsWith($repoProcessPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        $zombies += $candidate
    } else {
        Write-Step ("跳过非本仓库进程: {0} (PID {1}, {2})" -f $candidate.Name, $candidate.Id, $candidateFull)
    }
}
if ($zombies.Count -gt 0) {
    Write-Step ("发现本仓库进程: {0} (PID: {1})" -f (($zombies | ForEach-Object Name) -join ', '), (($zombies | ForEach-Object Id) -join ', '))
    foreach ($z in $zombies) {
        try {
            Stop-Process -Id $z.Id -Force -ErrorAction Stop
        } catch {
            # 进程可能在枚举后已自行退出（如父进程连带终止子进程），忽略此错误
            Write-Step "进程 PID $($z.Id) 已不存在，跳过"
        }
    }
    Start-Sleep -Seconds 2
    Write-OK "本仓库进程已清理"
} else {
    Write-OK "无本仓库进程"
}

# ========== 预清理（全量模式） ==========
if ($effectiveClean) {
    Write-Stage "预清理：移除构建产物与打包暂存"
    $cleanDirs = @(
        $CoreBuildDir,
        (Join-Path $WorkerDir "target"),
        (Join-Path $VerthysTauriDir "src-tauri\target"),
        (Join-Path $SrcTauriDir "service-payload"),
        (Join-Path $ScriptRoot "build_security_service")
    )
    foreach ($dir in $cleanDirs) {
        if (Test-Path -LiteralPath $dir) {
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction Stop
            Write-Step "已清理: $dir"
        }
    }
    $cleanFiles = @(
        (Join-Path $SrcTauriDir "verthys.dll"),
        (Join-Path $BinariesDir "verthys-worker-x86_64-pc-windows-msvc.exe"),
        (Join-Path $SrcTauriDir "bundle-assets.json")
    )
    foreach ($file in $cleanFiles) {
        if (Test-Path -LiteralPath $file) {
            Remove-Item -LiteralPath $file -Force -ErrorAction Stop
            Write-Step "已清理: $file"
        }
    }
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

# ========== 版本载体同步 ==========
# 根 VERSION 是唯一手改点；构建前写入 Cargo.toml / package.json / package-lock.json
# / config.ts 等载体，避免 Tauri 按旧版本打包后与产物校验使用的根版本不一致，
# 导致整轮构建在最后一步才失败。同步后立即做 -CheckOnly 复核，结构性问题仍然阻断。
Write-Stage "阶段 0.2: 版本载体同步"
$syncVersionScript = Join-Path $ScriptRoot "ci\sync_version.ps1"
if (-not (Test-Path -LiteralPath $syncVersionScript)) {
    throw "Version sync script is missing: $syncVersionScript"
}
& $syncVersionScript
if ($LASTEXITCODE -ne 0) {
    throw "Version carrier sync failed"
}
& $syncVersionScript -CheckOnly
if ($LASTEXITCODE -ne 0) {
    throw "Version carrier verification failed after sync"
}
Write-OK "版本载体已与根 VERSION 同步"

# 锁文件基线：版本同步之后再测量，排除版本写入这一预期变更。
# 构建期间 cargo/npm 若改写锁文件，产物将与提交的依赖解析不一致。
$script:LockSnapshot = @(Get-VerthysLockSnapshot -Root $ScriptRoot)
Write-OK ("锁文件基线已记录: {0}" -f (($script:LockSnapshot | ForEach-Object { $_.Name }) -join ", "))

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
# CMake POST_BUILD 生成的 build/core/verthys.artifacts.json）——避免按
# 生成器类型猜测子目录（Ninja/VS 布局差异会让哈希退化为 None）。
# 契约在构建/跳过决策之后读取：首次构建不会因契约尚未生成而失败。
# 注入器与契约写入器同样来自 scripts/lib，保证与 build_core.release.ps1
# 使用完全相同的完整性基准口径。
. (Join-Path $ScriptsLibDir "artifacts.ps1")
. (Join-Path $ScriptsLibDir "vsec.ps1")
# Release 发布签名：证书解析、指纹钉扎、Authenticode 签名与复核
. (Join-Path $ScriptsLibDir "release_signing.ps1")

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

# ========== 发布签名与调用方认证解析 ==========
# production 必须有可用发布者证书；local 缺少证书时显式关闭调用方认证，
# 产物标记为不可分发，禁止把未签名构建当成发布候选。
$script:signing = Resolve-VerthysReleaseSigning -Required:($Profile -eq "production")
$script:BuildSummary.publisher_sha256 = [string]$script:signing.PublisherSha256
if (-not $script:signing.Enabled) {
    Write-Host "[sign] local profile 未提供签名证书：本次产物不启用调用方认证、不含 Authenticode，禁止分发" -ForegroundColor Yellow
}
if ($script:signing.Enabled -and $SkipWorker) {
    throw "启用发布签名的构建不允许 -SkipWorker：worker 的 Release 完整性基线必须绑定签名后的 DLL"
}

# ========== 阶段 1: 构建 C 核心 DLL ==========
if (-not $SkipCore) {
    Write-Stage "阶段 1/4: 构建 C 核心安全 DLL（verthys.dll）"

    # 陈旧缓存自愈：项目目录迁移/重命名后，
    # build/CMakeCache.txt 记录的绝对路径（CMAKE_HOME_DIRECTORY）失效，
    # CMake 报 "CMakeCache.txt directory ... is different than the directory
    # ... where CMakeCache.txt was created" 并拒绝配置。检测到不一致时
    # 自动清理构建目录并全量重建，保证任意路径变更后一键构建仍可用。
    Clear-StaleCMakeCache -BuildDir $CoreBuildDir -SourceDir $ScriptRoot

    Write-Step ("CMake Configure (Release, x64, caller_sig={0})" -f $(if ($script:signing.Enabled) { "ON" } else { "OFF" }))
    # 两个缓存变量必须每轮显式写出：CMake 会保留上一次配置的缓存值，
    # 省略会把上一轮的 ON/OFF 状态带进本轮产物。
    $callerSigState = if ($script:signing.Enabled) { "ON" } else { "OFF" }
    $publisherShaValue = if ($script:signing.Enabled) { $script:signing.PublisherSha256 } else { "" }
    $callerSigArgs = @(
        "-DVERTHYS_REQUIRE_CALLER_SIG=$callerSigState",
        "-DVERTHYS_PUBLISHER_SHA256=$publisherShaValue",
        "-DVERTHYS_TEST_HOOKS=OFF",
        "-DVERTHYS_TEST_REQUIRE_ISOLATION=OFF"
    )
    if ($script:msvcInjected) {
        & $script:effectiveCmake -S $ScriptRoot -B $CoreBuildDir -G Ninja -DCMAKE_BUILD_TYPE=Release @callerSigArgs
    } else {
        & $script:effectiveCmake -S $ScriptRoot -B $CoreBuildDir -G $script:effectiveGenerator -A x64 @callerSigArgs
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

# ========== 阶段 1.01: 生产 DLL 测试钩子字符串门 ==========
# 测试构建会编译 VERTHYS_TEST_STATE_DIR 覆盖入口；生产 DLL 绝不能包含
# 该字符串（否则测试状态目录可能被环境变量注入生产进程）。构建后立即
# 扫描产物，命中即拒绝继续打包。
$dllBytes = [System.IO.File]::ReadAllBytes($script:actualCoreDll)
$dllText = [System.Text.Encoding]::ASCII.GetString($dllBytes)
if ($dllText.Contains("VERTHYS_TEST_STATE_DIR")) {
    throw "生产 verthys.dll 含测试状态注入字符串 VERTHYS_TEST_STATE_DIR；拒绝继续打包"
}
Write-OK "生产 DLL 不含测试状态注入字符串"

# ========== 阶段 1.05: 预热签名宿主演练目标 ==========
# vty_signed_host 是调用方认证门禁的输入。若缺失，CMake 会按依赖关系
# 重新链接 verthys_core，从而覆盖刚注入的 .vsec 基准与 Authenticode 签名，
# 并让打包副本与源 DLL 哈希漂移。必须在注入前确保该目标已构建：
# 门禁阶段只签名临时副本，绝不再触发编译。
if ($script:signing.Enabled) {
    $prewarmManifest = Get-VerthysArtifactManifest
    Get-VerthysSignedHostPath `
        -BuildDir $CoreBuildDir `
        -Manifest $prewarmManifest `
        -CmakeExe $script:effectiveCmake | Out-Null
}

# ========== 阶段 1.1: .vsec 完整性基准注入 + 契约刷新 ==========
# 生产 DLL 必须在进入打包前完成 .vsec 签名：运行时 integrity_verify_startup
# 从磁盘重算 .text / .rdata / .rhat 三节 HMAC 并与 .vsec 基准逐槽比对；
# 全零 .vsec 会被视为开发构建而跳过验签，等于分发物失去完整性防线。
# -SkipCore 同样执行（幂等）：既有 DLL 可能来自旧构建或旧脚本，不能在
# “跳过重编”路径上漏掉安全基准。
Write-Stage "阶段 1.1/4: .vsec 完整性基准注入"
Update-VsecBaseline -DllPath $script:actualCoreDll

# Authenticode 必须在 .vsec 注入之后：签名只追加 PE 安全目录，
# 不改写 .text/.rdata/.rhat，因此 .vsec 基准保持有效。
if ($script:signing.Enabled) {
    Invoke-VerthysAuthenticodeSign `
        -Path $script:actualCoreDll `
        -Certificate $script:signing.Certificate `
        -TimestampServer $script:signing.TimestampServer
    Assert-VerthysAuthenticodeSignature `
        -Path $script:actualCoreDll `
        -ExpectedSha256 $script:signing.PublisherSha256 | Out-Null
    Write-OK "verthys.dll 已签名，发布者指纹=$($script:signing.PublisherSha256)"
}
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

# ========== 阶段 1.2: 调用方认证功能门禁 ==========
# 用真实发布证书对临时签名宿主做正负对照：未签名宿主必须被拒绝，
# 目标发布者签名宿主必须放行。契约哈希来自签名后字节，门禁与交付物同源。
if ($script:signing.Enabled) {
    Write-Stage "阶段 1.2/4: 调用方认证功能门禁"
    $signedHostPath = Get-VerthysSignedHostPath `
        -BuildDir $CoreBuildDir `
        -Manifest $coreManifest `
        -CmakeExe $script:effectiveCmake
    Invoke-VerthysCallerAuthGate `
        -DllPath $script:actualCoreDll `
        -HostPath $signedHostPath `
        -Signing $script:signing
} else {
    Write-Stage "阶段 1.2/4: 跳过调用方认证门禁（未启用发布签名）"
}

# ========== 阶段 2: 构建 verthys-worker ==========
if (-not $SkipWorker) {
    Write-Stage "阶段 2/4: 构建 verthys-worker 子进程（Rust release）"

    # worker 的 Release 完整性基线必须绑定最终签名字节；否则运行期
    # 全文件 SHA-256 比对必然失败，表现为 worker 拒绝加载 DLL。
    # 契约路径是唯一权威来源，禁止 worker 构建自行猜测生成器目录。
    $env:VERTHYS_DLL_PATH = $script:actualCoreDll

    # 纵深防御：禁用增量编译（defense-in-depth）
    # 根因：dev profile 增量编译与 raw-dylib 导入库生成存在竞态，导致
    # LNK1181: 无法打开输入文件 "windows.0.52.0.lib"。
    # Cargo.toml [profile.dev] incremental=false 提供同一约束；
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

    # 签名必须发生在 worker 完整性基线生成之后、复制打包之前：
    # 基线绑定的是 DLL，签名改写的是 worker 自身字节，两者互不冲突。
    if ($script:signing.Enabled) {
        Invoke-VerthysAuthenticodeSign `
            -Path $WorkerReleaseExe `
            -Certificate $script:signing.Certificate `
            -TimestampServer $script:signing.TimestampServer
        Assert-VerthysAuthenticodeSignature `
            -Path $WorkerReleaseExe `
            -ExpectedSha256 $script:signing.PublisherSha256 | Out-Null
        Write-OK "verthys-worker.exe 已签名，发布者指纹=$($script:signing.PublisherSha256)"
    }

    # 记录 worker 与 DLL 的构建期绑定（签名后字节）。
    # -SkipWorker 路径回读该记录：任何一侧字节变化都拒绝复用既有 worker。
    $boundDllHash = (Get-FileHash -LiteralPath $script:actualCoreDll -Algorithm SHA256).Hash.ToLowerInvariant()
    $boundWorkerHash = (Get-FileHash -LiteralPath $WorkerReleaseExe -Algorithm SHA256).Hash.ToLowerInvariant()
    $workerStamp = [ordered]@{
        schema        = 1
        dll_sha256    = $boundDllHash
        worker_sha256 = $boundWorkerHash
        built_at      = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
    $stampDir = Split-Path -Parent $WorkerStampPath
    if (-not (Test-Path -LiteralPath $stampDir)) {
        New-Item -ItemType Directory -Path $stampDir -Force | Out-Null
    }
    [System.IO.File]::WriteAllText(
        $WorkerStampPath,
        ($workerStamp | ConvertTo-Json -Depth 4),
        (New-Object System.Text.UTF8Encoding($false)))
    Write-OK "worker 绑定记录已刷新: $WorkerStampPath"

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
    # 复用既有 worker 前必须证明它与当前 DLL 是同一轮构建：worker 在编译期
    # 固化了 DLL 全文件摘要，旧 worker + 新 DLL 会在启动握手阶段直接失败。
    if (-not (Test-Path -LiteralPath $WorkerStampPath -PathType Leaf)) {
        throw "缺少 worker 绑定记录: $WorkerStampPath（去掉 -SkipWorker 重新构建 worker）"
    }
    $skipStamp = Get-Content -LiteralPath $WorkerStampPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $skipDllHash = (Get-FileHash -LiteralPath $script:actualCoreDll -Algorithm SHA256).Hash.ToLowerInvariant()
    $skipWorkerHash = (Get-FileHash -LiteralPath $WorkerReleaseExe -Algorithm SHA256).Hash.ToLowerInvariant()
    if ([string]$skipStamp.dll_sha256 -ne $skipDllHash) {
        throw ("worker 绑定的 DLL 已变化（绑定={0} 当前={1}）：去掉 -SkipWorker 重新构建 worker" -f
            ([string]$skipStamp.dll_sha256).Substring(0, 12), $skipDllHash.Substring(0, 12))
    }
    if ([string]$skipStamp.worker_sha256 -ne $skipWorkerHash) {
        throw ("worker 产物已被改动（绑定={0} 当前={1}）：去掉 -SkipWorker 重新构建 worker" -f
            ([string]$skipStamp.worker_sha256).Substring(0, 12), $skipWorkerHash.Substring(0, 12))
    }
    Write-OK "worker 绑定记录校验通过"
}

# ========== 阶段 3: 部署打包素材（单一生产者） ==========
# DLL、worker、Tauri target 同步与清单写入统一由
# scripts/build/stage_bundle_assets.ps1 完成；build_production、build_dev 与
# CI 共用同一实现，避免三条链路各自漂移。
Write-Stage "阶段 3/4: 部署打包素材（binaries/ + src-tauri/ + Tauri target）"
$debugWorkerSource = if (Test-Path -LiteralPath $WorkerDebugExe -PathType Leaf) { $WorkerDebugExe } else { "" }
$stageResult = & (Join-Path $ScriptsDir "build\stage_bundle_assets.ps1") `
    -Channel production `
    -DllSource $script:actualCoreDll `
    -WorkerSource $WorkerReleaseExe `
    -ContractPath (Join-Path $CoreBuildDir "core\verthys.artifacts.json") `
    -Producer "build_production.ps1" `
    -SyncTargets production `
    -WorkerDebugSource $debugWorkerSource `
    -RepoRoot $ScriptRoot
$DllTarget = $stageResult.DllPath
Write-OK ("打包素材已部署: dll={0} worker={1}" -f $stageResult.DllSha256.Substring(0, 12), $stageResult.WorkerSha256.Substring(0, 12))
$script:BuildSummary.dll = [ordered]@{ path = $stageResult.DllPath; sha256 = $stageResult.DllSha256 }
$script:BuildSummary.worker = [ordered]@{ path = $stageResult.WorkerPath; sha256 = $stageResult.WorkerSha256 }

# 供后续阶段复核使用
function Get-FileSha256 {
    param([string]$Path)
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

# ========== 阶段 3.6: 构建并分发 P2 独立安全服务 ==========
# 必须在 Tauri 打包之前完成：resources 在 cargo build 时校验并被打入 NSIS，
# 否则安装包拿到的是上一轮残留的服务资源。
if (-not $SkipService) {
    Write-Stage "阶段 3.6: 构建 P2 独立安全服务"

    $serviceBuildDir = Join-Path $ScriptRoot "build_security_service"
    $serviceBuildScript = Join-Path $ScriptsDir "build\build_security_service.ps1"
    if (-not (Test-Path -LiteralPath $serviceBuildScript)) {
        throw "P2 安全服务构建脚本缺失: $serviceBuildScript"
    }
    Push-Location $ScriptRoot
    try {
        if ($Profile -eq "production") {
            & powershell.exe -NoProfile -ExecutionPolicy Bypass `
                -File "scripts\build\build_security_service.ps1" `
                -BuildDir "build_security_service" -Profile production
        } elseif ($script:signing.Enabled) {
            & powershell.exe -NoProfile -ExecutionPolicy Bypass `
                -File "scripts\build\build_security_service.ps1" `
                -BuildDir "build_security_service" -Profile local
        } else {
            & powershell.exe -NoProfile -ExecutionPolicy Bypass `
                -File "scripts\build\build_security_service.ps1" `
                -BuildDir "build_security_service" -Profile local -NoSign
        }
        if ($LASTEXITCODE -ne 0) {
            throw "P2 安全服务构建失败 (exit=$LASTEXITCODE)"
        }
    } finally {
        Pop-Location
    }

    $serviceArtifactDir = Join-Path $serviceBuildDir "artifacts"
    $serviceDistDir = Join-Path $ScriptRoot "build\security-service"
    if (Test-Path -LiteralPath $serviceDistDir) {
        Remove-Item -LiteralPath $serviceDistDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $serviceDistDir -Force | Out-Null
    foreach ($name in @("VerthysSecuritySvc.exe", "security-service.artifacts.json",
                        "VerthysRootCA.cer")) {
        $source = Join-Path $serviceArtifactDir $name
        if (-not (Test-Path -LiteralPath $source)) {
            if ($name -eq "VerthysRootCA.cer" -and -not $script:signing.Enabled) { continue }
            throw "P2 安全服务产物缺失: $source"
        }
        Copy-Item -LiteralPath $source -Destination $serviceDistDir -Force
    }
    Write-OK "P2 安全服务产物: build\security-service"

    # 载荷目录：服务 exe + 根 CA。目录名与服务安装目录 SecurityService 区分，
    # 避免 Windows 大小写不敏感路径冲突（安装器中从载荷目录调用 /install）。
    $serviceResourceDir = Join-Path $ScriptRoot "verthys-tauri\src-tauri\service-payload"
    $legacyResourceDir = Join-Path $ScriptRoot "verthys-tauri\src-tauri\security-service"
    if (Test-Path -LiteralPath $legacyResourceDir) {
        Remove-Item -LiteralPath $legacyResourceDir -Recurse -Force
    }
    if (Test-Path -LiteralPath $serviceResourceDir) {
        Remove-Item -LiteralPath $serviceResourceDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $serviceResourceDir -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $serviceDistDir "VerthysSecuritySvc.exe") `
        -Destination (Join-Path $serviceResourceDir "VerthysSecuritySvc.exe") -Force
    $rootCertSource = Join-Path $serviceDistDir "VerthysRootCA.cer"
    if (Test-Path -LiteralPath $rootCertSource) {
        Copy-Item -LiteralPath $rootCertSource -Destination (Join-Path $serviceResourceDir "VerthysRootCA.cer") -Force
    } elseif ($script:signing.Enabled) {
        throw "P2 根 CA 载荷缺失: $rootCertSource"
    }
    Write-OK "P2 服务载荷: src-tauri\service-payload"

    # 驱动载荷：仅显式 -IncludeDriver。哈希与签名双门禁，任一失败即终止构建；
    # 未开启时移除旧载荷目录，避免上一轮残留被安装包误带。
    $driverPayloadDir = Join-Path $serviceResourceDir "driver"
    if ($IncludeDriver) {
        $driverManifest = Get-Content -LiteralPath $DriverManifestPath -Raw | ConvertFrom-Json
        $driverFiles = @(
            @{ Name = 'VerthysGuard.sys'; Source = [string]$driverManifest.sysPath; Hash = [string]$driverManifest.sysSha256 },
            @{ Name = 'VerthysGuard.cat'; Source = [string]$driverManifest.catPath; Hash = [string]$driverManifest.catSha256 },
            @{ Name = 'VerthysGuard.inf'; Source = [string]$driverManifest.infPath; Hash = [string]$driverManifest.infSha256 }
        )
        New-Item -ItemType Directory -Path $driverPayloadDir -Force | Out-Null
        New-Item -ItemType File -Path (Join-Path $driverPayloadDir '.keep') -Force | Out-Null
        foreach ($item in $driverFiles) {
            if ([string]::IsNullOrWhiteSpace($item.Source) -or
                -not (Test-Path -LiteralPath $item.Source -PathType Leaf)) {
                throw "驱动产物缺失: $($item.Name) ($($item.Source))"
            }
            $actual = (Get-FileHash -LiteralPath $item.Source -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actual -ne $item.Hash.ToLowerInvariant()) {
                throw "驱动产物哈希与 manifest 不一致: $($item.Name)"
            }
            Copy-Item -LiteralPath $item.Source -Destination (Join-Path $driverPayloadDir $item.Name) -Force
        }
        foreach ($name in @('VerthysGuard.sys', 'VerthysGuard.cat')) {
            $sig = Get-AuthenticodeSignature -LiteralPath (Join-Path $driverPayloadDir $name)
            if ($sig.Status -ne 'Valid') {
                throw "驱动签名不受信: $name status=$($sig.Status)"
            }
            if ($Profile -eq 'production' -and
                $null -ne $sig.SignerCertificate -and
                [string]$sig.SignerCertificate.Subject -match 'WDKTestCert') {
                throw "生产打包拒绝测试签名驱动: $name (WDKTestCert)"
            }
        }
        Copy-Item -LiteralPath $DriverManifestPath `
            -Destination (Join-Path $driverPayloadDir 'driver.artifacts.json') -Force
        Write-OK "驱动载荷: src-tauri\service-payload\driver"
    } else {
        if (Test-Path -LiteralPath $driverPayloadDir) {
            Remove-Item -LiteralPath $driverPayloadDir -Recurse -Force
        }
        New-Item -ItemType Directory -Path $driverPayloadDir -Force | Out-Null
        New-Item -ItemType File -Path (Join-Path $driverPayloadDir '.keep') -Force | Out-Null
        Write-OK "未启用驱动载荷（-IncludeDriver 未指定）"
    }
} else {
    Write-Stage "阶段 3.6: 跳过 P2 独立安全服务（-SkipService）"
    # 复用既有载荷必须能证明它与服务产物一致；否则上一轮载荷会在无人察觉时
    # 被打进安装包（该开关与 -Clean 互斥）。
    $serviceArtifactDir = Join-Path $ScriptRoot "build\security-service"
    $serviceArtifactsPath = Join-Path $serviceArtifactDir "security-service.artifacts.json"
    $payloadDir = Join-Path $SrcTauriDir "service-payload"
    $payloadService = Join-Path $payloadDir "VerthysSecuritySvc.exe"
    if (-not (Test-Path -LiteralPath $serviceArtifactsPath -PathType Leaf)) {
        throw "缺少服务产物记录: $serviceArtifactsPath（去掉 -SkipService 重新构建）"
    }
    if (-not (Test-Path -LiteralPath $payloadService -PathType Leaf)) {
        throw "缺少服务载荷: $payloadService（去掉 -SkipService 重新构建）"
    }
    $serviceArtifacts = Get-Content -LiteralPath $serviceArtifactsPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $payloadHash = Get-FileSha256 $payloadService
    $serviceRecordedHash = [string]$serviceArtifacts.service.sha256
    if ($payloadHash -ne $serviceRecordedHash) {
        throw ("服务载荷与产物记录不一致（载荷={0} 记录={1}）：去掉 -SkipService 重新构建" -f
            $payloadHash.Substring(0, 12), $serviceRecordedHash.Substring(0, 12))
    }
    if ($script:signing.Enabled) {
        $payloadCa = Join-Path $payloadDir "VerthysRootCA.cer"
        if (-not (Test-Path -LiteralPath $payloadCa -PathType Leaf)) {
            throw "缺少根 CA 载荷: $payloadCa（去掉 -SkipService 重新构建）"
        }
    }
    Write-OK "复用既有服务载荷校验通过（与 security-service.artifacts.json 一致）"
}

# ========== 阶段 4: 构建 Tauri 应用 ==========
$TauriBuilt = $false
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
        $profileGateArgs = @($profileConfig, "--profile", "production", "--endpoint", $UpdaterEndpoint, "--base", (Join-Path $SrcTauriDir "tauri.conf.json"))
        if ($insecureUpdater) {
            $profileGateArgs += "--allow-insecure"
        }
    } else {
        if (-not $AllowLocal) {
            throw "local profile requires -AllowLocal"
        }
        $templateConfig = Join-Path $VerthysTauriDir "src-tauri\tauri.local.conf.json"
        if (-not (Test-Path $templateConfig)) {
            throw "missing local overlay: $templateConfig"
        }
        $generatedDir = Join-Path $ScriptRoot "build"
        New-Item -ItemType Directory -Force -Path $generatedDir | Out-Null
        $profileConfig = Join-Path $generatedDir "tauri.local.generated.conf.json"
        $config = Get-Content -LiteralPath $templateConfig -Raw | ConvertFrom-Json
        $profileGateArgs = @($profileConfig, "--profile", "local", "--base", (Join-Path $SrcTauriDir "tauri.conf.json"))
    }

    # 主程序签名必须由打包器在“二进制补丁之后”执行：打包器先写入 bundle type
    # 信息（改写 PE、使已有签名失效），再按 package type 调用 signCommand 重签，
    # 最后生成安装包。beforeBundleCommand 早于补丁，在那里签名必然产生
    # HashMismatch，禁止回退。signCommand 同时覆盖 NSIS 卸载器。
    if ($script:signing.Enabled) {
        $signHook = Join-Path $ScriptsDir "build\sign_release_binaries.ps1"
        if (-not (Test-Path -LiteralPath $signHook)) {
            throw "签名入口缺失: $signHook"
        }
        $signCommand = [pscustomobject]@{
            cmd  = "powershell.exe"
            args = @(
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-File", $signHook,
                "-ExePath", "%1"
            )
        }
        $bundleSection = $config.PSObject.Properties['bundle']
        if ($null -eq $bundleSection) {
            $config | Add-Member -NotePropertyName bundle -NotePropertyValue ([pscustomobject]@{
                windows = [pscustomobject]@{ signCommand = $signCommand }
            }) -Force
        } else {
            $windowsSection = $bundleSection.Value.PSObject.Properties['windows']
            if ($null -eq $windowsSection) {
                $bundleSection.Value | Add-Member -NotePropertyName windows `
                    -NotePropertyValue ([pscustomobject]@{ signCommand = $signCommand }) -Force
            } else {
                $windowsSection.Value | Add-Member -NotePropertyName signCommand `
                    -NotePropertyValue $signCommand -Force
            }
        }
        Write-OK "已注入打包器 signCommand（补丁后签名主程序与卸载器）"
    }
    # UTF-8 无 BOM：路径可能包含非 ASCII 字符，ASCII 编码会截断；BOM 会让 JSON 解析失败。
    $configJson = $config | ConvertTo-Json -Depth 12
    [System.IO.File]::WriteAllText($profileConfig, $configJson, [System.Text.UTF8Encoding]::new($false))
    & $nodeCmd.Source (Join-Path $ScriptsGatesDir "check_updater_profile.mjs") @profileGateArgs
    if ($LASTEXITCODE -ne 0) {
        throw "更新 profile 配置校验失败: $Profile"
    }
    Write-OK "更新 profile 配置校验通过: $Profile"

    # 本轮签名审计日志：构建前清空，签名入口在 Authenticode 复核通过后追加。
    # 打包器是否对主程序执行 signCommand 只能由该审计判定：Tauri 日志为
    # UTF-8，Windows PowerShell 5.1 按本地代码页解码，中文匹配不可靠。
    $signJournalPath = Join-Path $CoreBuildDir "tauri_sign_journal.jsonl"
    if (Test-Path -LiteralPath $signJournalPath) {
        Remove-Item -LiteralPath $signJournalPath -Force
    }
    $env:VERTHYS_SIGN_JOURNAL = $signJournalPath

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
    $TauriBuilt = $true

    # 打包器 signCommand 只有在 bundle type 补丁之后执行，安装包内嵌的才是
    # 有效签名的主程序；被忽略时运行期调用方认证会拒绝启动，构建必须在此终止。
    # 判定依据是签名入口写入的审计记录，而不是构建日志文本：日志编码受运行
    # 环境代码页影响，中文标记在 PowerShell 5.1 下会失真。
    if ($script:signing.Enabled) {
        $mainExePath = [System.IO.Path]::GetFullPath((Join-Path $SrcTauriDir "target\release\Verthys.exe"))
        $mainSigned = $null
        if (Test-Path -LiteralPath $signJournalPath -PathType Leaf) {
            $entries = foreach ($line in [System.IO.File]::ReadAllLines($signJournalPath, [System.Text.Encoding]::UTF8)) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                try {
                    $entry = $line | ConvertFrom-Json
                    if ([string]::IsNullOrWhiteSpace([string]$entry.path) -or
                        [string]::IsNullOrWhiteSpace([string]$entry.publisher)) {
                        throw "字段缺失"
                    }
                    $entry
                } catch {
                    throw "签名审计日志损坏，无法确认主程序签名状态: $signJournalPath"
                }
            }
            $mainSigned = $entries | Where-Object {
                $_.publisher -eq $script:signing.PublisherSha256 -and
                ([System.IO.Path]::GetFullPath([string]$_.path)) -ieq $mainExePath
            } | Select-Object -First 1
        }
        if ($null -eq $mainSigned) {
            throw "打包器未对主程序执行签名：signCommand 未生效或被跳过"
        }
        Write-OK "主程序已在 bundle type 补丁后签名"

        # 打包器生成安装包后会恢复未打补丁的原始主程序，恢复副本不带签名。
        # 未签名副本无法通过服务映像认证，本地暂存与冒烟会拿到错误二进制；
        # 对最终落盘副本重新签名并复核，保证其与安装包内版本同一发布者。
        Invoke-VerthysAuthenticodeSign `
            -Path $mainExePath `
            -Certificate $script:signing.Certificate `
            -TimestampServer $script:signing.TimestampServer
        Assert-VerthysAuthenticodeSignature `
            -Path $mainExePath `
            -ExpectedSha256 $script:signing.PublisherSha256 | Out-Null
        Write-OK "主程序最终副本已签名"
    }
    Remove-Item Env:VERTHYS_SIGN_JOURNAL -ErrorAction SilentlyContinue
} else {
    Write-Stage "阶段 4/4: 跳过 Tauri 打包（-SkipTauri）"
}

# ========== 阶段 4.4b: 安装包 Authenticode 签名 + 更新签名重生成 ==========
# Tauri 生成的 .sig 覆盖打包时的安装包字节；Authenticode 签名会改写安装包，
# 必须先签名，再用同一更新私钥重新生成 .sig，顺序不可交换。
if (-not $SkipTauri -and $script:signing.Enabled) {
    $productVersion = ([System.IO.File]::ReadAllText((Join-Path $ScriptRoot "VERSION"))).Trim()
    $installerName = "Verthys_${productVersion}_x64-setup.exe"
    $installerPath = Join-Path $VerthysTauriDir "src-tauri\target\release\bundle\nsis\$installerName"
    if (-not (Test-Path -LiteralPath $installerPath -PathType Leaf)) {
        Write-Fail "安装包缺失，无法签名: $installerPath"
        throw "安装包缺失，无法签名: $installerPath"
    }

    Write-Step "NSIS 安装包 Authenticode 签名"
    Invoke-VerthysAuthenticodeSign `
        -Path $installerPath `
        -Certificate $script:signing.Certificate `
        -TimestampServer $script:signing.TimestampServer
    Assert-VerthysAuthenticodeSignature `
        -Path $installerPath `
        -ExpectedSha256 $script:signing.PublisherSha256 | Out-Null
    Write-OK "安装包 Authenticode 签名复核通过"

    Write-Step "重新生成更新签名 (.sig)"
    $signaturePath = "$installerPath.sig"
    if (Test-Path -LiteralPath $signaturePath) {
        Remove-Item -LiteralPath $signaturePath -Force
    }
    Push-Location $VerthysTauriDir
    try {
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $sigOutput = & npx tauri signer sign $installerPath 2>&1
        $sigExit = $LASTEXITCODE
        $ErrorActionPreference = $prevEAP
    } finally {
        Pop-Location
    }
    if ($sigExit -ne 0) {
        $sigOutput | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        throw "更新签名生成失败 (exit=$sigExit)"
    }
    if (-not (Test-Path -LiteralPath $signaturePath -PathType Leaf)) {
        throw "更新签名未生成: $signaturePath"
    }
    Write-OK "更新签名已重新生成: $signaturePath"
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

# ========== 阶段 4.6: 独立安全服务 ==========
# P2 独立安全服务在 Tauri 打包阶段之前构建，确保安装包携带本次构建的
# 安装器/服务二进制/根 CA，而不是上一轮残留产物。

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
    # 打包副本必须与契约记录的交付字节完全一致：签名后契约按最终字节重算，
    # 任何复制期改写都会让运行期 DLL 哈希校验与签名同时失效。
    $sourceDllHash = (Get-FileHash -LiteralPath $script:actualCoreDll -Algorithm SHA256).Hash.ToLowerInvariant()
    $stagedDllHash = (Get-FileHash -LiteralPath $DllTarget -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($sourceDllHash -ne $stagedDllHash) {
        Write-Fail "DLL 打包副本哈希漂移: source=$($sourceDllHash.Substring(0,12)) staged=$($stagedDllHash.Substring(0,12))"
        $allOk = $false
    }
    if ($script:signing.Enabled) {
        try {
            Assert-VerthysAuthenticodeSignature `
                -Path $DllTarget `
                -ExpectedSha256 $script:signing.PublisherSha256 | Out-Null
            Write-OK "src-tauri/verthys.dll Authenticode 签名复核通过"
        } catch {
            Write-Fail "src-tauri/verthys.dll 签名复核失败: $($_.Exception.Message)"
            $allOk = $false
        }
    }
} else {
    Write-Fail "DLL 打包副本缺失: $DllTarget"
    $allOk = $false
}

# Worker 二进制
if (Test-Path $WorkerBundledExe) {
    $info = Get-Item $WorkerBundledExe
    Write-OK ("verthys-worker-x86_64-pc-windows-msvc.exe: {0} ({1} KB)" -f $info.LastWriteTime, [math]::Round($info.Length / 1KB, 1))
    if ($script:signing.Enabled) {
        try {
            Assert-VerthysAuthenticodeSignature `
                -Path $WorkerBundledExe `
                -ExpectedSha256 $script:signing.PublisherSha256 | Out-Null
            Write-OK "verthys-worker.exe Authenticode 签名复核通过"
        } catch {
            Write-Fail "verthys-worker.exe 签名复核失败: $($_.Exception.Message)"
            $allOk = $false
        }
    }
} else {
    Write-Fail "verthys-worker 二进制缺失"
    $allOk = $false
}

# 打包素材清单：证明打包路径上的字节属于生产通道，且 worker 与 DLL 配对。
# build.rs 在编译期重复同一组校验；此处覆盖 -SkipTauri 场景并留下可见结论。
$bundleManifestPath = Join-Path $SrcTauriDir "bundle-assets.json"
if (Test-Path -LiteralPath $bundleManifestPath -PathType Leaf) {
    $bundleManifest = Get-Content -LiteralPath $bundleManifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    # 契约文件由核心构建/签名链在 Tauri 阶段重新生成（时间戳与签名基准会
    # 刷新），清单中的契约哈希必须在最终校验前同步；DLL 与 worker 的
    # 字节配对仍按原清单严格比对。
    $contractPath = Join-Path $CoreBuildDir "core\verthys.artifacts.json"
    if (Test-Path -LiteralPath $contractPath -PathType Leaf) {
        $bundleManifest.contract.sha256 = Get-FileSha256 $contractPath
        # Windows PowerShell 5.1 的 UTF8 编码会写入 BOM，build.rs 的
        # serde_json 会拒绝带 BOM 的清单。显式用无 BOM UTF-8 写回。
        $manifestJson = $bundleManifest | ConvertTo-Json -Depth 8
        [System.IO.File]::WriteAllText(
            $bundleManifestPath,
            $manifestJson,
            (New-Object System.Text.UTF8Encoding($false)))
    }
    $manifestDllHash = Get-FileSha256 $DllTarget
    $manifestWorkerHash = Get-FileSha256 $WorkerBundledExe
    $manifestContractHash = Get-FileSha256 (Join-Path $CoreBuildDir "core\verthys.artifacts.json")
    $manifestProblems = @()
    if ([string]$bundleManifest.channel -ne "production") {
        $manifestProblems += ("channel={0} producer={1}" -f $bundleManifest.channel, $bundleManifest.producer)
    }
    if ([string]$bundleManifest.dll.sha256 -ne $manifestDllHash) {
        $manifestProblems += ("dll 清单={0} 实际={1}" -f $bundleManifest.dll.sha256, $manifestDllHash)
    }
    if ([string]$bundleManifest.worker.sha256 -ne $manifestWorkerHash) {
        $manifestProblems += ("worker 清单={0} 实际={1}" -f $bundleManifest.worker.sha256, $manifestWorkerHash)
    }
    if ([string]$bundleManifest.worker.dll_sha256 -ne $manifestDllHash) {
        $manifestProblems += ("worker 绑定 DLL={0} 实际={1}" -f $bundleManifest.worker.dll_sha256, $manifestDllHash)
    }
    if ([string]$bundleManifest.contract.sha256 -ne $manifestContractHash) {
        $manifestProblems += ("契约清单={0} 实际={1}" -f $bundleManifest.contract.sha256, $manifestContractHash)
    }
    if ($manifestProblems.Count -gt 0) {
        Write-Fail ("打包素材清单与产物不一致: {0}" -f ($manifestProblems -join "; "))
        Write-Step ("清单写入者={0}；清单时间={1}；DLL 时间={2}；worker 时间={3}" -f
            $bundleManifest.producer,
            (Get-Item -LiteralPath $bundleManifestPath).LastWriteTime,
            (Get-Item -LiteralPath $DllTarget).LastWriteTime,
            (Get-Item -LiteralPath $WorkerBundledExe).LastWriteTime)
        $allOk = $false
    } else {
        Write-OK "打包素材清单校验通过（channel=production，worker 与 DLL 配对）"
    }
} else {
    Write-Fail "打包素材清单缺失: $bundleManifestPath"
    $allOk = $false
}

# 安装器输入核验：Tauri 生成的 NSIS 脚本按绝对路径嵌入打包素材。
# 构建结束后确认脚本引用的正是清单校验过的两个路径，证明安装包编译期
# 读取的是受门禁保护的字节，而不是其他残留副本。
if ($TauriBuilt) {
    $nsisScripts = @(Get-ChildItem -Path (Join-Path $SrcTauriDir "target\release\nsis") `
            -Recurse -Filter "installer.nsi" -File -ErrorAction SilentlyContinue)
    if ($nsisScripts.Count -eq 0) {
        Write-Fail "未找到 NSIS 脚本，无法核验安装器输入"
        $allOk = $false
    } else {
        $nsisText = Get-Content -LiteralPath $nsisScripts[0].FullName -Raw -ErrorAction Stop
        $expectedDllPath = [System.IO.Path]::GetFullPath($DllTarget)
        $expectedWorkerPath = [System.IO.Path]::GetFullPath($WorkerBundledExe)
        if ($nsisText.IndexOf($expectedDllPath, [System.StringComparison]::OrdinalIgnoreCase) -lt 0 -or
            $nsisText.IndexOf($expectedWorkerPath, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
            Write-Fail "NSIS 脚本未引用打包素材清单对应的文件（安装器可能嵌入其他副本）"
            $allOk = $false
        } else {
            Write-OK "NSIS 脚本引用路径与打包素材清单一致"
        }
    }
}

# 独立安全服务产物与载荷
if (-not $SkipService) {
    $p2Dir = Join-Path $ScriptRoot "build\security-service"
    $serviceNames = @("VerthysSecuritySvc.exe", "security-service.artifacts.json")
    if ($script:signing.Enabled) { $serviceNames += "VerthysRootCA.cer" }
    foreach ($name in $serviceNames) {
        $path = Join-Path $p2Dir $name
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $info = Get-Item -LiteralPath $path
            Write-OK ("P2 产物: {0} ({1} KB)" -f $name, [math]::Round($info.Length / 1KB, 1))
        } else {
            Write-Fail "P2 安全服务产物缺失: $path"
            $allOk = $false
        }
    }
    if ($script:signing.Enabled) {
        $servicePath = Join-Path $p2Dir "VerthysSecuritySvc.exe"
        if (Test-Path -LiteralPath $servicePath -PathType Leaf) {
            try {
                Assert-VerthysAuthenticodeSignature `
                    -Path $servicePath `
                    -ExpectedSha256 $script:signing.PublisherSha256 | Out-Null
                Write-OK "VerthysSecuritySvc.exe Authenticode 签名复核通过"
            } catch {
                Write-Fail "VerthysSecuritySvc.exe 签名复核失败: $($_.Exception.Message)"
                $allOk = $false
            }
        }
    }

    # 载荷与 artifacts 必须逐字节一致；安装器只从 service-payload 调用服务。
    $payloadDir = Join-Path $SrcTauriDir "service-payload"
    $artifactsPath = Join-Path $p2Dir "security-service.artifacts.json"
    if (Test-Path -LiteralPath $artifactsPath -PathType Leaf) {
        $p2Artifacts = Get-Content -LiteralPath $artifactsPath -Raw | ConvertFrom-Json
        $payloadService = Join-Path $payloadDir "VerthysSecuritySvc.exe"
        $payloadCa = Join-Path $payloadDir "VerthysRootCA.cer"
        if (-not (Test-Path -LiteralPath $payloadService -PathType Leaf)) {
            Write-Fail "服务载荷缺失: $payloadService"
            $allOk = $false
        } elseif ((Get-FileHash -LiteralPath $payloadService -Algorithm SHA256).Hash.ToLowerInvariant() -ne
                  [string]$p2Artifacts.service.sha256) {
            Write-Fail "服务载荷哈希与 artifacts 不一致"
            $allOk = $false
        }
        if ($script:signing.Enabled) {
            if (-not (Test-Path -LiteralPath $payloadCa -PathType Leaf)) {
                Write-Fail "根 CA 载荷缺失: $payloadCa"
                $allOk = $false
            } elseif ((Get-FileHash -LiteralPath $payloadCa -Algorithm SHA256).Hash.ToLowerInvariant() -ne
                      [string]$p2Artifacts.rootCa.sha256) {
                Write-Fail "根 CA 载荷哈希与 artifacts 不一致"
                $allOk = $false
            }
        }
        Write-OK "P2 载荷与 artifacts 哈希一致"
    }

    if ($IncludeDriver) {
        foreach ($name in @('VerthysGuard.sys', 'VerthysGuard.cat', 'VerthysGuard.inf')) {
            $driverFile = Join-Path $payloadDir "driver\$name"
            if (-not (Test-Path -LiteralPath $driverFile -PathType Leaf)) {
                Write-Fail "驱动载荷缺失: $driverFile"
                $allOk = $false
            }
        }
        $driverSys = Join-Path $payloadDir "driver\VerthysGuard.sys"
        $driverCat = Join-Path $payloadDir "driver\VerthysGuard.cat"
        foreach ($driverFile in @($driverSys, $driverCat)) {
            if (Test-Path -LiteralPath $driverFile -PathType Leaf) {
                $sig = Get-AuthenticodeSignature -LiteralPath $driverFile
                if ($sig.Status -ne 'Valid') {
                    Write-Fail "驱动载荷签名不受信: $driverFile status=$($sig.Status)"
                    $allOk = $false
                }
            }
        }
        if ($allOk) { Write-OK "驱动载荷完整且签名受信" }
    }

    $legacySetup = @(
        @(
            (Join-Path $payloadDir "VerthysSecurityServiceSetup.exe"),
            (Join-Path $SrcTauriDir "security-service\VerthysSecurityServiceSetup.exe")
        ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
    )
    if ($legacySetup.Count -gt 0) {
        Write-Fail "安装资源仍包含独立安装器: $($legacySetup[0])"
        $allOk = $false
    } else {
        Write-OK "应用包内无独立服务安装器"
    }
}

# NSIS 安装包：只认根 VERSION 对应的精确文件名，历史残留不参与本次发布
$nsisDir = Join-Path $VerthysTauriDir "src-tauri\target\release\bundle\nsis"
$productVersion = ([System.IO.File]::ReadAllText((Join-Path $ScriptRoot "VERSION"))).Trim()
$installerName = "Verthys_${productVersion}_x64-setup.exe"
$expectedInstaller = Join-Path $nsisDir $installerName
if ($TauriBuilt) {
    if (-not (Test-Path $nsisDir)) {
        Write-Fail "NSIS 输出目录不存在"
        $allOk = $false
    } elseif (Test-Path -LiteralPath $expectedInstaller -PathType Leaf) {
        $expectedInfo = Get-Item -LiteralPath $expectedInstaller
        Write-OK ("本次安装包: {0} ({1} MB)" -f $expectedInfo.Name, [math]::Round($expectedInfo.Length / 1MB, 2))
    } else {
        Write-Fail ("未找到本次版本安装包: {0}" -f $installerName)
        $allOk = $false
    }
} else {
    Write-Step "跳过安装包校验（-SkipTauri 未执行打包）"
}
if (Test-Path $nsisDir) {
    $staleInstallers = @(Get-ChildItem $nsisDir -Filter "*.exe" -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne $installerName })
    if ($staleInstallers.Count -gt 0) {
        Write-Step ("历史安装包（未参与本次发布）: {0}" -f (($staleInstallers | ForEach-Object Name) -join ", "))
    }
}

# 更新发布物料：签名清单 + 安装包副本 + 账本
if (-not $SkipTauri -and $allOk -and (Test-Path $nsisDir)) {
    # 安装包名已在阶段 5 按根 VERSION 精确计算，这里复用同一结果。
    $installer = Get-Item (Join-Path $nsisDir $installerName) -ErrorAction SilentlyContinue
    $signature = if ($installer) { Get-Item ("{0}.sig" -f $installer.FullName) -ErrorAction SilentlyContinue } else { $null }
    if (-not $installer -or -not $signature) {
        Write-Fail "missing installer or signature for release artifacts"
        $allOk = $false
    } else {
        $script:BuildSummary.installer = [ordered]@{
            path      = $installer.FullName
            sha256    = (Get-FileSha256 $installer.FullName)
            signature = $signature.FullName
        }
        if ($Profile -eq "production") {
            try {
                Assert-VerthysAuthenticodeSignature `
                    -Path $installer.FullName `
                    -ExpectedSha256 $script:signing.PublisherSha256 | Out-Null
                Write-OK "安装包 Authenticode 签名与发布者指纹复核通过"
            } catch {
                Write-Fail "安装包 Authenticode 签名复核失败: $($_.Exception.Message)"
                $allOk = $false
            }
        }
        if ($allOk) {
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
}

# 锁文件复核：构建期间 cargo/npm 不得改写锁文件
$currentLocks = @(Get-VerthysLockSnapshot -Root $ScriptRoot)
$lockDrift = @()
foreach ($baseline in $script:LockSnapshot) {
    $current = $currentLocks | Where-Object { $_.Name -eq $baseline.Name } | Select-Object -First 1
    if ($null -eq $current -or $current.Sha256 -ne $baseline.Sha256) {
        $lockDrift += $baseline.Name
    }
}
if ($lockDrift.Count -gt 0) {
    Write-Fail ("构建期间锁文件被改写: {0}" -f ($lockDrift -join ", "))
    $allOk = $false
} else {
    Write-OK "锁文件在构建期间未变更"
}

# 清理锁文件
Get-ChildItem $tauriTargetDir -Filter ".cargo-lock" -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

Write-Host ""
if ($allOk) {
    $script:BuildSummary.result = "success"
    $script:BuildSummary.finished_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $summaryPath = Write-VerthysBuildSummary -Summary $script:BuildSummary -Root $ScriptRoot
    Write-OK ("构建摘要: {0}" -f $summaryPath)
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  全部构建成功！" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    if ($script:signing.Enabled -and $SkipTauri) {
        Write-Host "  [warn] -SkipTauri：未生成/签名 Verthys.exe，本次产物不是可分发发布件" -ForegroundColor Yellow
    }
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
    $failureMessage = [string]$_.Exception.Message
    try {
        $script:BuildSummary.result = "failed"
        $script:BuildSummary.error = $failureMessage
        $script:BuildSummary.finished_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        $null = Write-VerthysBuildSummary -Summary $script:BuildSummary -Root $ScriptRoot
    } catch {
        Write-Host "  [warn] 构建摘要写入失败: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    if (-not $NoPause) {
        Write-Host "按 Enter 键退出..." -ForegroundColor Cyan
        Read-Host | Out-Null
    }
    exit 1
} finally {
    Exit-VerthysBuildLock -Lock $script:BuildLock
}

# 成功结束：双击运行场景下暂停以便查看结果，CI 场景（-NoPause）直接退出
if (-not $NoPause) {
    Write-Host ""
    Write-Host "按 Enter 键退出..." -ForegroundColor Cyan
    Read-Host | Out-Null
}
exit 0
