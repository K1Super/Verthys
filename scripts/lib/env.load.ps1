# scripts/lib/env.load.ps1 - 构建环境配置加载器（仅从系统环境变量读取，零硬编码）
#
# 设计原则（环境隔离 + 敏感信息零明文）：
#   - 所有工具路径、SDK 版本、镜像地址均通过系统环境变量注入
#   - 脚本内不出现任何绝对路径、版本号、密钥、镜像 URL
#   - 缺失必需变量时立即 fail-fast，并给出设置提示
#
# 使用方式：在构建脚本顶部 dot-source 引入
#   . (Join-Path $PSScriptRoot "..\lib\env.load.ps1")
#
# 环境来源（按优先级探测，二者都不可用时 fail-fast）：
#
#   来源 1（本机定制安装）：四个 VERTHYS_* 变量显式注入 VS / MSVC / SDK 路径
#     VERTHYS_VS_ROOT     Visual Studio 安装根目录（如 D:\IDE\VisualStudio\18\Community）
#     VERTHYS_MSVC_VER    MSVC 工具链版本号（如 14.51.36231）
#     VERTHYS_SDK_ROOT    Windows SDK 安装目录（如 D:\Windows Kits\10）
#     VERTHYS_SDK_VER     Windows SDK 版本号（如 10.0.26100.0）
#
#   来源 2（已注入的 MSVC 开发者环境）：VCToolsInstallDir + INCLUDE + LIB +
#     PATH 中的 cl.exe。ilammy/msvc-dev-cmd（CI）与 "x64 Native Tools Command
#     Prompt" 天然满足。此时从注入环境反推 VS / MSVC / SDK 路径并复用现成的
#     INCLUDE / LIB / PATH；生成器名称经 vswhere 探测真实安装版本，禁止把
#     版本号硬编码到 CI 里（runner 的 VS 版本会随镜像升级）。
#
# 可选环境变量：
#   VERTHYS_GH_MIRROR   GitHub 镜像（Tauri 下载 NSIS/WiX 工具用，国内可设为 ghproxy）
#   VERTHYS_VS_GENERATOR MSVC 生成器名称（来源 1 默认 "Visual Studio 18 2026"；
#                        来源 2 未设置时由 vswhere 探测）

# 强制严格模式：引用未定义变量直接报错，避免静默 fallback 到硬编码
Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

function Read-ScopedEnv {
    param([string]$Name)
    foreach ($scope in @("Process", "User", "Machine")) {
        $val = [System.Environment]::GetEnvironmentVariable($Name, $scope)
        if (-not [string]::IsNullOrEmpty($val)) { return $val }
    }
    return ""
}

function Assert-EnvVar {
    param([string]$Name, [string]$Description)
    $val = Read-ScopedEnv $Name
    if ([string]::IsNullOrEmpty($val)) {
        Write-Host "[env.load] 缺失必需环境变量: $Name" -ForegroundColor Red
        Write-Host "  说明: $Description" -ForegroundColor Yellow
        Write-Host "  设置方式（PowerShell，永久生效）:" -ForegroundColor Cyan
        Write-Host "    [System.Environment]::SetEnvironmentVariable('$Name', '<值>', 'User')" -ForegroundColor Cyan
        Write-Host "  或改从已注入的 MSVC 开发者环境运行（VCToolsInstallDir + INCLUDE + LIB + cl.exe）" -ForegroundColor Cyan
        Write-Host ""
        throw "环境变量 $Name 未设置，拒绝继续构建"
    }
    return $val
}

# 从真实安装探测 CMake 生成器名称（如 "Visual Studio 17 2022"）。
# 仅来源 2 使用：CI runner 的 VS 版本不能假定，硬编码会在镜像升级后立即失效。
function Resolve-InjectedVsGenerator {
    $programFilesX86 = [System.Environment]::GetEnvironmentVariable("ProgramFiles(x86)")
    $vswhere = Join-Path $programFilesX86 "Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path -LiteralPath $vswhere) {
        $selector = @("-latest", "-products", "*", "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64")
        $display = (& $vswhere @selector -property displayName 2>$null | Select-Object -First 1)
        $install = (& $vswhere @selector -property installationVersion 2>$null | Select-Object -First 1)
        $major = (($install -split '\.')[0])
        if ($display -match '(\d{4})' -and $major) {
            return "Visual Studio $major $($Matches[1])"
        }
    }
    throw "无法探测 Visual Studio 生成器：请显式设置 VERTHYS_VS_GENERATOR（如 'Visual Studio 17 2022'）"
}

# ---------- 来源探测 ----------
$customVsRoot  = Read-ScopedEnv "VERTHYS_VS_ROOT"
$customMsvcVer = Read-ScopedEnv "VERTHYS_MSVC_VER"
$customSdkRoot = Read-ScopedEnv "VERTHYS_SDK_ROOT"
$customSdkVer  = Read-ScopedEnv "VERTHYS_SDK_VER"
$customReady = -not ([string]::IsNullOrEmpty($customVsRoot) -or
                     [string]::IsNullOrEmpty($customMsvcVer) -or
                     [string]::IsNullOrEmpty($customSdkRoot) -or
                     [string]::IsNullOrEmpty($customSdkVer))

$injectedMsvcRoot = Read-ScopedEnv "VCToolsInstallDir"
$injectedCl = Get-Command cl.exe -ErrorAction SilentlyContinue
$injectedReady = (-not [string]::IsNullOrEmpty($injectedMsvcRoot)) -and
                 (-not [string]::IsNullOrEmpty($env:INCLUDE)) -and
                 (-not [string]::IsNullOrEmpty($env:LIB)) -and
                 ($null -ne $injectedCl)

# ---------- 可选变量（带默认值，但默认值不含敏感信息） ----------
$script:VERTHYS_GH_MIRROR = Read-ScopedEnv "VERTHYS_GH_MIRROR"
$explicitGenerator = Read-ScopedEnv "VERTHYS_VS_GENERATOR"

if ($customReady) {
    # ---------- 来源 1：VERTHYS_* 显式注入（本机定制安装） ----------
    $script:VERTHYS_ENV_SOURCE     = "VERTHYS_* 显式注入"
    $script:VERTHYS_VS_ROOT      = $customVsRoot.TrimEnd([char[]]("\", "/"))
    $script:VERTHYS_MSVC_VER     = $customMsvcVer.Trim()
    $script:VERTHYS_SDK_ROOT     = $customSdkRoot.TrimEnd([char[]]("\", "/"))
    $script:VERTHYS_SDK_VER      = $customSdkVer.TrimEnd([char[]]("\", "/"))
    $script:VERTHYS_VS_GENERATOR = if ([string]::IsNullOrEmpty($explicitGenerator)) { "Visual Studio 18 2026" } else { $explicitGenerator.Trim() }

    # 派生路径（拼接，不引入新的硬编码绝对路径）
    $script:VERTHYS_MSVC_ROOT   = Join-Path $script:VERTHYS_VS_ROOT "VC\Tools\MSVC\$script:VERTHYS_MSVC_VER"
    $script:VERTHYS_CMAKE_EXE   = Join-Path $script:VERTHYS_VS_ROOT "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
    $script:VERTHYS_CL_EXE      = Join-Path $script:VERTHYS_MSVC_ROOT "bin\Hostx64\x64\cl.exe"
    $script:VERTHYS_LINK_EXE    = Join-Path $script:VERTHYS_MSVC_ROOT "bin\Hostx64\x64\link.exe"
    $script:VERTHYS_LIB_EXE     = Join-Path $script:VERTHYS_MSVC_ROOT "bin\Hostx64\x64\lib.exe"

    $script:VERTHYS_INCLUDE = "$($script:VERTHYS_MSVC_ROOT)\include;$($script:VERTHYS_SDK_ROOT)\Include\$($script:VERTHYS_SDK_VER)\um;$($script:VERTHYS_SDK_ROOT)\Include\$($script:VERTHYS_SDK_VER)\ucrt;$($script:VERTHYS_SDK_ROOT)\Include\$($script:VERTHYS_SDK_VER)\shared"
    $script:VERTHYS_LIB     = "$($script:VERTHYS_MSVC_ROOT)\lib\x64;$($script:VERTHYS_SDK_ROOT)\Lib\$($script:VERTHYS_SDK_VER)\um\x64;$($script:VERTHYS_SDK_ROOT)\Lib\$($script:VERTHYS_SDK_VER)\ucrt\x64"
    $script:VERTHYS_PATH_PREFIX = "$($script:VERTHYS_MSVC_ROOT)\bin\Hostx64\x64;$($script:VERTHYS_SDK_ROOT)\bin\$($script:VERTHYS_SDK_VER)\x64"

    $env:INCLUDE = $script:VERTHYS_INCLUDE
    $env:LIB     = $script:VERTHYS_LIB
    $env:PATH    = "$($script:VERTHYS_PATH_PREFIX);$($env:PATH)"
} elseif ($injectedReady) {
    # ---------- 来源 2：复用已注入的 MSVC 开发者环境 ----------
    # 工具链与 SDK 已在 PATH / INCLUDE / LIB 中；此处只反推路径与生成器，
    # 不覆盖 INCLUDE / LIB / PATH（避免破坏 runner 已注入的完整环境）。
    $script:VERTHYS_ENV_SOURCE = "已注入的 MSVC 环境"
    $script:VERTHYS_MSVC_ROOT   = $injectedMsvcRoot.TrimEnd([char[]]("\", "/"))
    $script:VERTHYS_MSVC_VER    = Split-Path -Leaf $script:VERTHYS_MSVC_ROOT
    $script:VERTHYS_VS_ROOT     = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $script:VERTHYS_MSVC_ROOT)))
    $script:VERTHYS_SDK_ROOT    = (Read-ScopedEnv "WindowsSdkDir").TrimEnd([char[]]("\", "/"))
    $script:VERTHYS_SDK_VER     = (Read-ScopedEnv "WindowsSDKVersion").TrimEnd([char[]]("\", "/"))
    $script:VERTHYS_VS_GENERATOR = if ([string]::IsNullOrEmpty($explicitGenerator)) { Resolve-InjectedVsGenerator } else { $explicitGenerator.Trim() }

    $bundledCmake = Join-Path $script:VERTHYS_VS_ROOT "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
    if (Test-Path -LiteralPath $bundledCmake) {
        $script:VERTHYS_CMAKE_EXE = $bundledCmake
    } else {
        $cmakeCmd = Get-Command cmake.exe -ErrorAction SilentlyContinue
        if ($null -eq $cmakeCmd) {
            throw "已注入 MSVC 环境，但 cmake.exe 既不在 VS 安装目录也不在 PATH"
        }
        $script:VERTHYS_CMAKE_EXE = $cmakeCmd.Source
    }
    $script:VERTHYS_CL_EXE      = $injectedCl.Source
    $script:VERTHYS_LINK_EXE    = Join-Path $script:VERTHYS_MSVC_ROOT "bin\Hostx64\x64\link.exe"
    $script:VERTHYS_LIB_EXE     = Join-Path $script:VERTHYS_MSVC_ROOT "bin\Hostx64\x64\lib.exe"
    $script:VERTHYS_INCLUDE     = $env:INCLUDE
    $script:VERTHYS_LIB         = $env:LIB
    $script:VERTHYS_PATH_PREFIX = ""
} else {
    # ---------- 两种来源均不可用：逐项 fail-fast（保留原有可操作提示） ----------
    $script:VERTHYS_ENV_SOURCE     = "缺少环境"
    $script:VERTHYS_VS_ROOT      = Assert-EnvVar "VERTHYS_VS_ROOT"   "Visual Studio 安装根目录"
    $script:VERTHYS_MSVC_VER     = Assert-EnvVar "VERTHYS_MSVC_VER"  "MSVC 工具链版本号"
    $script:VERTHYS_SDK_ROOT     = Assert-EnvVar "VERTHYS_SDK_ROOT"  "Windows SDK 安装目录"
    $script:VERTHYS_SDK_VER      = Assert-EnvVar "VERTHYS_SDK_VER"   "Windows SDK 版本号"
    $script:VERTHYS_VS_GENERATOR = if ([string]::IsNullOrEmpty($explicitGenerator)) { "Visual Studio 18 2026" } else { $explicitGenerator.Trim() }
    throw "环境变量校验分支异常"
}

# ---------- 应用到当前进程环境（编译器映射对两种来源都必要） ----------

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
    if (-not (Test-Path -LiteralPath $tool)) {
        throw "工具不存在: $tool（请检查 VERTHYS_VS_ROOT / VERTHYS_MSVC_VER，或注入的 MSVC 环境）"
    }
}

Write-Host "[env.load] 环境变量已加载（来源: $($script:VERTHYS_ENV_SOURCE)）" -ForegroundColor Green
Write-Host "  VS_ROOT    = $($script:VERTHYS_VS_ROOT)"
Write-Host "  MSVC_VER   = $($script:VERTHYS_MSVC_VER)"
Write-Host "  SDK_VER    = $($script:VERTHYS_SDK_VER)"
Write-Host "  Generator  = $($script:VERTHYS_VS_GENERATOR)"
if (-not [string]::IsNullOrEmpty($script:VERTHYS_GH_MIRROR)) {
    Write-Host "  GH_MIRROR  = $($script:VERTHYS_GH_MIRROR)"
}
Write-Host ""
