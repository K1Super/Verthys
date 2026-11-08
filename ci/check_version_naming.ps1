<#
 * ci/check_version_naming.ps1 — 版本号工程化守卫
 *
 * 规则：
 *   1. 代码文件名/目录名禁止出现代际后缀（_v2/_v3/_v4、v2_/v3_/v4_ 前缀、/v2//v3//v4/ 目录段）。
 *   2. 构建与脚本文件禁止出现已退役的 V3 构建标识（VERTHYS_V3_SUPPORT、
 *      verthys_core_legacy、verthys.legacy.def、VERTHYS_V3_VERSION、
 *      verthys_container_v3）。
 *   3. 版本常量只允许定义在 core/include/verthys_version.h。
 *
 * 允许的 V4 位置：导出 ABI 名（Verthys_V4*）、worker 协议 op 字符串
 * （"v4_*"）、磁盘 magic/格式字段、产品版本号；这些不是文件名/内部符号，
 * 本脚本不拦截。
 *
 * 退出码：0=通过；1=违规（输出逐条明细）。
#>
param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

$violations = New-Object System.Collections.Generic.List[string]

function Add-Violation([string]$Message) {
    [void]$violations.Add($Message)
}

$codeRoots = @(
    (Join-Path $Root "core\src"),
    (Join-Path $Root "core\tests"),
    (Join-Path $Root "security-service"),
    (Join-Path $Root "scripts\build"),
    (Join-Path $Root "tests\service"),
    (Join-Path $Root "verthys-tauri\src-tauri\src"),
    (Join-Path $Root "verthys-tauri\verthys-worker\src"),
    (Join-Path $Root "verthys-tauri\src")
)

# 目录段/文件名代际后缀；允许 v4 出现在协议字符串或 ABI 名，但它们不是文件名。
$generationPath = '(?i)(^|[\\/])v[234]([\\/]|$)|(_v[234]([._-]|$))|(^|_)v[234]_'

foreach ($codeRoot in $codeRoots) {
    if (-not (Test-Path -LiteralPath $codeRoot)) { continue }
    Get-ChildItem -LiteralPath $codeRoot -Recurse -Force |
        Where-Object {
            $_.FullName -notmatch '(?i)[\\/](target|node_modules|dist|build|build_[^\\/]+)([\\/]|$)'
        } |
        ForEach-Object {
            $relative = $_.FullName.Substring($Root.Length).TrimStart('\', '/')
            if ($relative -match $generationPath) {
                Add-Violation "代际命名残留: $relative"
            }
        }
}

$buildFiles = @(
    "core\CMakeLists.txt",
    "core\tests\CMakeLists.txt",
    "core\verthys.def",
    "security-service\CMakeLists.txt",
    "scripts\build\build_security_service.ps1",
    "build_dev.ps1",
    "build_production.ps1",
    "ci\release_preflight.ps1",
    "verthys-tauri\src-tauri\build.rs",
    "verthys-tauri\src-tauri\Cargo.toml",
    "scripts\release\make_updater_manifest.mjs"
)

$retiredTokens = @(
    "VERTHYS_V3_SUPPORT",
    "verthys_core_legacy",
    "verthys.legacy.def",
    "VERTHYS_V3_VERSION",
    "verthys_container_v3"
)

foreach ($relative in $buildFiles) {
    $path = Join-Path $Root $relative
    if (-not (Test-Path -LiteralPath $path)) { continue }
    $text = [System.IO.File]::ReadAllText($path)
    foreach ($token in $retiredTokens) {
        if ($text.Contains($token)) {
            Add-Violation "退役构建标识 '$token' 仍出现在 $relative"
        }
    }
}

# 版本常量唯一来源：只允许 verthys_version.h 定义。
$versionHeader = Join-Path $Root "core\include\verthys_version.h"
$definePattern = '#define\s+(VERTHYS_API_VERSION|VERTHYS_CONTAINER_FORMAT_VERSION)\b'
Get-ChildItem -LiteralPath (Join-Path $Root "core") -Recurse -File -Include *.h,*.c |
        Where-Object { $_.FullName -notmatch '(?i)[\\/](build|build_[^\\/]+)([\\/]|$)' } |
        ForEach-Object {
            $text = [System.IO.File]::ReadAllText($_.FullName)
            if ($text -match $definePattern -and $_.FullName -ne $versionHeader) {
                Add-Violation "版本常量在非唯一来源中定义: $($_.FullName.Substring($Root.Length))"
            }
        }

if ($violations.Count -gt 0) {
    Write-Host "[FAIL] 版本命名守卫发现 $($violations.Count) 项违规:" -ForegroundColor Red
    $violations | ForEach-Object { Write-Host "  - $_" }
    exit 1
}

Write-Host "[OK] 版本命名守卫通过：无代际文件名/目录、无退役 V3 构建标识、版本常量单一来源。"
exit 0
