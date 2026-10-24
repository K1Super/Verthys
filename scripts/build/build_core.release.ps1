# scripts/build/build_core.release.ps1 - 核心安全 DLL 生产环境构建（Release，无测试，供 Tauri 打包消费）
#
# 编码警告：本文件必须保存为 UTF-8 with BOM 编码！
#   Windows PowerShell 5.1 对无 BOM 文件按 ANSI/GBK 解码，中文注释乱码会
#   破坏字符串配对导致解析错误（ParseError），而解析错误发生在任何代码
#   执行之前，try/catch 与暂停完全失效——表现为窗口一闪而过且无任何
#   错误显示。保存后请确认文件头 3 字节为 EF BB BF。
#
# 环境隔离声明：
#   - 本脚本仅用于生产环境（Release），产物路径固定为 build/core/Release/
#   - 与 build_core.dev.ps1 完全独立，禁止互相调用或共享构建目录
#   - 所有工具路径来自系统环境变量（经 env.load.ps1 注入），脚本内零硬编码
#   - Release 构建跳过测试（测试已在开发环境完成），仅产出加固后的 DLL
#
# 用法: powershell -ExecutionPolicy Bypass -File scripts\build\build_core.release.ps1 [-Clean] [-NoPause]
#   -Clean    构建前清理 build 目录
#   -NoPause  失败/成功后不暂停等待 Enter（CI 场景使用；双击运行时不传此参数以便查看输出）
param(
    [switch]$Clean,
    [switch]$NoPause
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

# ========== 主流程（try/catch 包裹防止闪退） ==========
# 任何未捕获错误（含 env.load.ps1 环境变量缺失的 throw、CMake 配置/构建失败、
# DLL 产物缺失校验失败）都会进入 catch 块显示错误信息并暂停，双击运行场景不会窗口一闪而过
try {

# 加载环境变量（必需变量缺失会 fail-fast）
. (Join-Path $PSScriptRoot "..\lib\env.load.ps1")
# 加载 CMake 缓存自愈工具（陈旧缓存检测，见函数头注释）
. (Join-Path $PSScriptRoot "..\lib\cmake.utils.ps1")
# .vsec 完整性基准注入（build_production.ps1 复用同一实现）
. (Join-Path $PSScriptRoot "..\lib\vsec.ps1")
# 产物契约读取/重生成（注入改写 DLL 字节后必须刷新）
. (Join-Path $PSScriptRoot "..\lib\artifacts.ps1")

$root       = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
# 生产环境固定构建目录：build/（Tauri 打包配置消费 build/core/Release/verthys.dll）
$buildDir   = Join-Path $root "build"
$config     = "Release"

if ($Clean -and (Test-Path $buildDir)) {
    Write-Host "[clean] 移除 $buildDir" -ForegroundColor Yellow
    Remove-Item -Recurse -Force $buildDir
}

# 陈旧缓存自愈（根因修复）：项目目录迁移/重命名后，
# build/CMakeCache.txt 记录的绝对路径（CMAKE_HOME_DIRECTORY）失效，
# CMake 报 "CMakeCache.txt directory ... is different than the directory
# ... where CMakeCache.txt was created" 并拒绝配置。此处检测到不一致时
# 自动清理构建目录并全量重建，保证任意路径变更后脚本仍可一键自愈。
Clear-StaleCMakeCache -BuildDir $buildDir -SourceDir $root

Write-Host "[configure] 生产环境 Release 构建" -ForegroundColor Cyan
Write-Host "  生成器: $VERTHYS_VS_GENERATOR"
Write-Host "  构建目录: $buildDir"

& $VERTHYS_CMAKE_EXE -S $root -B $buildDir -G $VERTHYS_VS_GENERATOR -A x64
if ($LASTEXITCODE -ne 0) { throw "configure 失败" }

Write-Host "[build] $config（安全加固：/O2 /GL /GS /guard:cf，剥离符号）" -ForegroundColor Cyan
& $VERTHYS_CMAKE_EXE --build $buildDir --config $config
if ($LASTEXITCODE -ne 0) { throw "build 失败" }

$dllPath = Join-Path $buildDir "core\$config\verthys.dll"
if (-not (Test-Path $dllPath)) {
    throw "DLL 产物缺失: $dllPath"
}


# ========== .vsec 完整性基准注入 ==========
# 注入实现位于 scripts/lib/vsec.ps1（与 build_production.ps1 共用同一份逻辑，
# 避免两条生产链路出现基准口径漂移）。时序红线：
#   链接 + rhash_gen .rhat 补丁 → .vsec 注入 → 产物契约按最终字节重生成 →
#   Authenticode 签名（若有）→ 打包。
Update-VsecBaseline -DllPath $dllPath
if (-not (Test-VsecBaseline -DllPath $dllPath)) {
    throw ".vsec 注入后独立验证失败：交付字节未被完整性基准覆盖"
}

# ========== 按最终字节重生成产物契约 ==========
# .vsec 注入改写 DLL 字节，而 CMake POST_BUILD 写的契约早于注入；
# 不刷新会让所有消费方校验的 SHA256 与交付字节不一致。
# 版本号与容器格式版本分别来自 VERSION 与 core/CMakeLists.txt（单一事实源），
# 生成后由函数校验哈希/版本/生成器，任何不一致立即失败。
$contract = Write-VerthysArtifactContract `
    -DllPath $dllPath `
    -CmakeExe $VERTHYS_CMAKE_EXE `
    -Generator $VERTHYS_VS_GENERATOR `
    -Config $config `
    -SourceDir $root
if ($null -eq $contract) { throw "artifact contract regeneration returned no manifest" }

Write-Host "[done] 生产构建完成" -ForegroundColor Green
Write-Host "  产物: $dllPath"
$info = Get-Item $dllPath
Write-Host ("  大小: {0} KB（{1}）" -f [math]::Round($info.Length / 1KB, 1), $info.LastWriteTime)
Write-Host "  Tauri 打包将通过 tauri.conf.json resources 引用此路径" -ForegroundColor Gray

} catch {
    # 顶层错误捕获：防止任何未处理异常导致脚本直接闪退
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  生产构建失败：$($_.Exception.Message)" -ForegroundColor Red
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
