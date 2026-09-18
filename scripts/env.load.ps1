# scripts/env.load.ps1 - 构建环境配置加载器（仅从系统环境变量读取，零硬编码）
#
# 设计原则（环境隔离 + 敏感信息零明文）：
#   - 所有工具路径、SDK 版本、镜像地址均通过系统环境变量注入
#   - 脚本内不出现任何绝对路径、版本号、密钥、镜像 URL
#   - 缺失必需变量时立即 fail-fast，并给出设置提示
#
# 使用方式：在构建脚本顶部 dot-source 引入
#   . $PSScriptRoot\env.load.ps1
#
# 必需环境变量（用户需在系统预先设置）：
#   VERTHYS_VS_ROOT     Visual Studio 安装根目录（如 D:\IDE\VisualStudio\18\Community）
#   VERTHYS_MSVC_VER    MSVC 工具链版本号（如 14.51.36231）
#   VERTHYS_SDK_ROOT    Windows SDK 安装目录（如 D:\Windows Kits\10）
#   VERTHYS_SDK_VER     Windows SDK 版本号（如 10.0.26100.0）
#
# 可选环境变量：
#   VERTHYS_GH_MIRROR   GitHub 镜像（Tauri 下载 NSIS/WiX 工具用，国内可设为 ghproxy）
#   VERTHYS_VS_GENERATOR MSVC 生成器名称（默认 "Visual Studio 18 2026"）

# 强制严格模式：引用未定义变量直接报错，避免静默 fallback 到硬编码
Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

function Assert-EnvVar {
    param([string]$Name, [string]$Description)
    $val = [System.Environment]::GetEnvironmentVariable($Name, "Process")
    if ([string]::IsNullOrEmpty($val)) {
        # 再查 User 与 Machine 级别
        $val = [System.Environment]::GetEnvironmentVariable($Name, "User")
        if ([string]::IsNullOrEmpty($val)) {
            $val = [System.Environment]::GetEnvironmentVariable($Name, "Machine")
        }
    }
    if ([string]::IsNullOrEmpty($val)) {
        Write-Host "[env.load] 缺失必需环境变量: $Name" -ForegroundColor Red
        Write-Host "  说明: $Description" -ForegroundColor Yellow
        Write-Host "  设置方式（PowerShell，永久生效）:" -ForegroundColor Cyan
        Write-Host "    [System.Environment]::SetEnvironmentVariable('$Name', '<值>', 'User')" -ForegroundColor Cyan
        Write-Host ""
        throw "环境变量 $Name 未设置，拒绝继续构建"
    }
    return $val
}

# ---------- 必需变量校验 ----------
$script:VERTHYS_VS_ROOT   = Assert-EnvVar "VERTHYS_VS_ROOT"   "Visual Studio 安装根目录"
$script:VERTHYS_MSVC_VER  = Assert-EnvVar "VERTHYS_MSVC_VER"  "MSVC 工具链版本号"
$script:VERTHYS_SDK_ROOT  = Assert-EnvVar "VERTHYS_SDK_ROOT"  "Windows SDK 安装目录"
$script:VERTHYS_SDK_VER   = Assert-EnvVar "VERTHYS_SDK_VER"   "Windows SDK 版本号"

# ---------- 可选变量（带默认值，但默认值不含敏感信息） ----------
$script:VERTHYS_GH_MIRROR = [System.Environment]::GetEnvironmentVariable("VERTHYS_GH_MIRROR", "Process")
if ([string]::IsNullOrEmpty($script:VERTHYS_GH_MIRROR)) {
    $script:VERTHYS_GH_MIRROR = [System.Environment]::GetEnvironmentVariable("VERTHYS_GH_MIRROR", "User")
}

$script:VERTHYS_VS_GENERATOR = [System.Environment]::GetEnvironmentVariable("VERTHYS_VS_GENERATOR", "Process")
if ([string]::IsNullOrEmpty($script:VERTHYS_VS_GENERATOR)) {
    $script:VERTHYS_VS_GENERATOR = "Visual Studio 18 2026"
}

# ---------- 派生路径（拼接，不引入新的硬编码绝对路径） ----------
$script:VERTHYS_MSVC_ROOT    = Join-Path $script:VERTHYS_VS_ROOT "VC\Tools\MSVC\$script:VERTHYS_MSVC_VER"
$script:VERTHYS_CMAKE_EXE    = Join-Path $script:VERTHYS_VS_ROOT "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
$script:VERTHYS_CL_EXE       = Join-Path $script:VERTHYS_MSVC_ROOT "bin\Hostx64\x64\cl.exe"
$script:VERTHYS_LINK_EXE     = Join-Path $script:VERTHYS_MSVC_ROOT "bin\Hostx64\x64\link.exe"
$script:VERTHYS_LIB_EXE      = Join-Path $script:VERTHYS_MSVC_ROOT "bin\Hostx64\x64\lib.exe"

$script:VERTHYS_INCLUDE = "$($script:VERTHYS_MSVC_ROOT)\include;$($script:VERTHYS_SDK_ROOT)\Include\$($script:VERTHYS_SDK_VER)\um;$($script:VERTHYS_SDK_ROOT)\Include\$($script:VERTHYS_SDK_VER)\ucrt;$($script:VERTHYS_SDK_ROOT)\Include\$($script:VERTHYS_SDK_VER)\shared"
$script:VERTHYS_LIB     = "$($script:VERTHYS_MSVC_ROOT)\lib\x64;$($script:VERTHYS_SDK_ROOT)\Lib\$($script:VERTHYS_SDK_VER)\um\x64;$($script:VERTHYS_SDK_ROOT)\Lib\$($script:VERTHYS_SDK_VER)\ucrt\x64"
$script:VERTHYS_PATH_PREFIX = "$($script:VERTHYS_MSVC_ROOT)\bin\Hostx64\x64;$($script:VERTHYS_SDK_ROOT)\bin\$($script:VERTHYS_SDK_VER)\x64"

# ---------- 应用到当前进程环境 ----------
$env:INCLUDE = $script:VERTHYS_INCLUDE
$env:LIB     = $script:VERTHYS_LIB
$env:PATH    = "$($script:VERTHYS_PATH_PREFIX);$($env:PATH)"

# 强制 cc/cmake 使用 cl.exe（避免 vswhere/注册表探测失败）
$env:CC  = $script:VERTHYS_CL_EXE
$env:CXX = $script:VERTHYS_CL_EXE
$env:LD  = $script:VERTHYS_LINK_EXE
$env:AR  = $script:VERTHYS_LIB_EXE
$env:CMAKE_C_COMPILER   = $script:VERTHYS_CL_EXE
$env:CMAKE_CXX_COMPILER = $script:VERTHYS_CL_EXE

# GitHub 镜像（仅当用户设置时应用）
if (-not [string]::IsNullOrEmpty($script:VERTHYS_GH_MIRROR)) {
    $env:TAURI_BUNDLER_TOOLS_GITHUB_MIRROR = $script:VERTHYS_GH_MIRROR
}

# ---------- 工具存在性校验 ----------
foreach ($tool in @($script:VERTHYS_CMAKE_EXE, $script:VERTHYS_CL_EXE)) {
    if (-not (Test-Path $tool)) {
        throw "工具不存在: $tool（请检查 VERTHYS_VS_ROOT / VERTHYS_MSVC_VER 环境变量）"
    }
}

Write-Host "[env.load] 环境变量已加载" -ForegroundColor Green
Write-Host "  VS_ROOT    = $($script:VERTHYS_VS_ROOT)"
Write-Host "  MSVC_VER   = $($script:VERTHYS_MSVC_VER)"
Write-Host "  SDK_VER    = $($script:VERTHYS_SDK_VER)"
Write-Host "  Generator  = $($script:VERTHYS_VS_GENERATOR)"
if (-not [string]::IsNullOrEmpty($script:VERTHYS_GH_MIRROR)) {
    Write-Host "  GH_MIRROR  = $($script:VERTHYS_GH_MIRROR)"
}
Write-Host ""
