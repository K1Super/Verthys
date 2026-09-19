# scripts/build_core.dev.ps1 - 核心安全 DLL 开发环境构建（Debug + 测试）
#
# ★ 编码警告：本文件必须保存为 UTF-8 with BOM 编码！
#   Windows PowerShell 5.1 对无 BOM 文件按 ANSI/GBK 解码，中文注释乱码会
#   破坏字符串配对导致解析错误（ParseError），而解析错误发生在任何代码
#   执行之前，try/catch 与暂停完全失效——表现为窗口一闪而过且无任何
#   错误显示。保存后请确认文件头 3 字节为 EF BB BF。
#
# 环境隔离声明：
#   - 本脚本仅用于开发环境（Debug），不参与生产打包
#   - 与 build_core.release.ps1 完全独立，禁止互相调用或共享构建目录
#   - 所有工具路径来自系统环境变量（经 env.load.ps1 注入），脚本内零硬编码
#
# 用法: powershell -ExecutionPolicy Bypass -File scripts\build_core.dev.ps1 [-Clean] [-NoPause]
#   -Clean    构建前清理 build_dev 目录
#   -NoPause  失败/成功后不暂停等待 Enter（CI 场景使用；双击运行时不传此参数以便查看输出）
param(
    [switch]$Clean,
    [switch]$NoPause
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

# ========== 主流程（try/catch 包裹防止闪退） ==========
# 任何未捕获错误（含 env.load.ps1 环境变量缺失的 throw、CMake 配置/构建失败、
# 测试失败）都会进入 catch 块显示错误信息并暂停，双击运行场景不会窗口一闪而过
try {

# 加载环境变量（必需变量缺失会 fail-fast）
. $PSScriptRoot\env.load.ps1
# 加载 CMake 缓存自愈工具（陈旧缓存检测，见函数头注释）
. $PSScriptRoot\cmake.utils.ps1

$root       = Split-Path -Parent $PSScriptRoot
# 开发环境独立构建目录，避免与 release 产物混淆
$buildDir   = Join-Path $root "build_dev"
$config     = "Debug"

if ($Clean -and (Test-Path $buildDir)) {
    Write-Host "[clean] 移除 $buildDir" -ForegroundColor Yellow
    Remove-Item -Recurse -Force $buildDir
}

# ★ 陈旧缓存自愈（根因修复）：项目目录迁移/重命名后，
# build_dev/CMakeCache.txt 记录的绝对路径（CMAKE_HOME_DIRECTORY）失效，
# CMake 报 "CMakeCache.txt directory ... is different than the directory
# ... where CMakeCache.txt was created" 并拒绝配置。此处检测到不一致时
# 自动清理构建目录并全量重建，保证任意路径变更后脚本仍可一键自愈。
Clear-StaleCMakeCache -BuildDir $buildDir -SourceDir $root

Write-Host "[configure] 开发环境 Debug 构建" -ForegroundColor Cyan
Write-Host "  生成器: $VERTHYS_VS_GENERATOR"
Write-Host "  构建目录: $buildDir"

& $VERTHYS_CMAKE_EXE -S $root -B $buildDir -G $VERTHYS_VS_GENERATOR -A x64
if ($LASTEXITCODE -ne 0) { throw "configure 失败" }

Write-Host "[build] $config" -ForegroundColor Cyan
& $VERTHYS_CMAKE_EXE --build $buildDir --config $config
if ($LASTEXITCODE -ne 0) { throw "build 失败" }

# 开发环境强制运行测试（安全核心不容许跳过测试的开发构建）
Write-Host "[test] 运行单元测试" -ForegroundColor Cyan
$testExe = Join-Path $buildDir "core\tests\$config\verthys_tests.exe"
if (-not (Test-Path $testExe)) {
    throw "测试可执行文件不存在: $testExe"
}
& $testExe
if ($LASTEXITCODE -ne 0) { throw "测试失败" }

$dllPath = Join-Path $buildDir "core\$config\verthys.dll"
Write-Host "[done] 开发构建完成（Debug + 测试通过）" -ForegroundColor Green
Write-Host "  产物: $dllPath"
Write-Host "  构建目录: $buildDir"

} catch {
    # 顶层错误捕获：防止任何未处理异常导致脚本直接闪退
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  开发构建失败：$($_.Exception.Message)" -ForegroundColor Red
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
