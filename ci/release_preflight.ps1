# ci/release_preflight.ps1 - 发布前置检查
#
# 在构建开始前核对版本、配置、签名密钥、Authenticode 证书、工作区与文档。
# production 的任一阻断项都必须先解决；local 仅用于本机复现，证书与端点不强制。
#
# 用法:
#   powershell -File ci\release_preflight.ps1 -Profile local
#   powershell -File ci\release_preflight.ps1 -Profile production `
#       -UpdaterEndpoint https://updates.example.com/stable/latest.json `
#       -AuthenticodeThumbprint <40 位指纹>

param(
    [ValidateSet("local", "production")]
    [string]$Profile = "production",
    [string]$UpdaterEndpoint = $env:VERTHYS_UPDATER_ENDPOINT,
    [string]$AuthenticodeThumbprint = $env:VERTHYS_AUTHENTICODE_THUMBPRINT,
    [switch]$AllowDirty,
    [switch]$SkipEndpointProbe
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

$Root = Split-Path -Parent $PSScriptRoot
$Blockers = New-Object System.Collections.Generic.List[string]
$Warnings = New-Object System.Collections.Generic.List[string]

function Add-Blocker([string]$Message) { [void]$Blockers.Add($Message) }
function Add-Warning([string]$Message) { [void]$Warnings.Add($Message) }

function Test-CommandExists([string]$Name) {
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

# ---- 版本单源 ----
$versionPath = Join-Path $Root "VERSION"
if (-not (Test-Path -LiteralPath $versionPath)) {
    Add-Blocker "缺少 VERSION 文件"
} else {
    $version = ([System.IO.File]::ReadAllText($versionPath)).Trim()
    if ($version -notmatch '^\d+\.\d+\.\d+$') {
        Add-Blocker "VERSION 不是 MAJOR.MINOR.PATCH: $version"
    }
    $sync = & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "sync_version.ps1") -CheckOnly 2>&1
    if ($LASTEXITCODE -ne 0) {
        Add-Blocker "版本载体不一致（运行 ci\sync_version.ps1）"
    }
}

# ---- 工作区状态 ----
$dirty = (& git -C $Root status --porcelain 2>$null)
if ($dirty) {
    if ($Profile -eq "production" -and -not $AllowDirty) {
        Add-Blocker "生产发布要求干净工作区（或显式 -AllowDirty 走预演）"
    } else {
        Add-Warning "工作区存在未提交改动"
    }
}

# ---- 更新配置门 ----
if (-not (Test-CommandExists "node")) {
    Add-Blocker "node 不在 PATH，无法校验更新配置"
} else {
    $overlay = if ($Profile -eq "production") {
        Join-Path $Root "verthys-tauri\src-tauri\tauri.production.conf.json"
    } else {
        Join-Path $Root "verthys-tauri\src-tauri\tauri.local.conf.json"
    }
    $gateArgs = @($overlay, "--profile", $Profile)
    if ($Profile -eq "production") {
        if ([string]::IsNullOrWhiteSpace($UpdaterEndpoint)) {
            Add-Blocker "production 必须提供 -UpdaterEndpoint 或 VERTHYS_UPDATER_ENDPOINT"
        } else {
            $uri = $null
            if (-not [Uri]::TryCreate($UpdaterEndpoint, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -ne "https") {
                Add-Blocker "UpdaterEndpoint 必须是绝对 HTTPS URL"
            } else {
                $gateArgs += @("--endpoint", $UpdaterEndpoint)
                if (-not $SkipEndpointProbe) {
                    try {
                        $probe = Invoke-WebRequest -UseBasicParsing -Method Head -Uri $UpdaterEndpoint -TimeoutSec 10
                        if ($probe.StatusCode -lt 200 -or $probe.StatusCode -ge 400) {
                            Add-Blocker "更新端点返回异常状态: $($probe.StatusCode)"
                        }
                    } catch {
                        Add-Blocker "更新端点不可达或 TLS 无效: $($_.Exception.Message)"
                    }
                }
            }
        }
    }
    & node (Join-Path $Root "scripts\check_updater_profile.mjs") @gateArgs
    if ($LASTEXITCODE -ne 0) {
        Add-Blocker "有效更新配置校验失败"
    }
}

# ---- 安装包 minisign 密钥 ----
$keyEnv = $env:TAURI_SIGNING_PRIVATE_KEY
$keyFile = Join-Path $env:USERPROFILE ".tauri\verthys-updater.key"
$passFile = Join-Path $env:USERPROFILE ".tauri\verthys-updater.pass"
if ([string]::IsNullOrWhiteSpace($keyEnv) -and -not (Test-Path -LiteralPath $keyFile)) {
    Add-Blocker "缺少安装包签名私钥（环境变量或 ~/.tauri/verthys-updater.key）"
}
if ([string]::IsNullOrWhiteSpace($env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD) -and -not (Test-Path -LiteralPath $passFile)) {
    Add-Warning "私钥密码未注入且无默认密码文件；无密码密钥可忽略"
}

# ---- 生产 Authenticode 证书与工具 ----
if ($Profile -eq "production") {
    $thumbprint = ($AuthenticodeThumbprint -replace '[\s:]', '').ToUpperInvariant()
    if ($thumbprint -notmatch '^[0-9A-F]{40}$') {
        Add-Blocker "production 必须提供有效的 Authenticode 证书指纹"
    } else {
        $stores = @("Cert:\CurrentUser\My", "Cert:\LocalMachine\My")
        $cert = Get-ChildItem -Path $stores -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $thumbprint } |
            Select-Object -First 1
        if (-not $cert) {
            Add-Blocker "未找到指纹对应的证书: $thumbprint"
        } elseif (-not $cert.HasPrivateKey) {
            Add-Blocker "证书缺少私钥，无法签名: $thumbprint"
        } else {
            $codeSigning = $cert.EnhancedKeyUsageList | Where-Object { $_.FriendlyName -eq "Code Signing" }
            if (-not $codeSigning) {
                Add-Blocker "证书不含 Code Signing 用途: $thumbprint"
            }
        }
    }

    $signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if (-not $signtool) {
        $kits = @(
            "C:\Program Files (x86)\Windows Kits\10",
            "D:\Windows Kits\10"
        ) | Where-Object { Test-Path $_ }
        foreach ($kit in $kits) {
            $found = Get-ChildItem $kit -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
                Select-Object -First 1
            if ($found) { $signtool = $found; break }
        }
    }
    if (-not $signtool) {
        Add-Blocker "未找到 signtool.exe，无法完成 Authenticode 签名"
    }
}

# ---- 文档与构建脚本 ----
$requiredDocs = @(
    "docs\updater\UPDATER_MASTER_PLAN.md",
    "docs\updater\UPDATER_LOCAL_VERIFICATION.md",
    "CHANGELOG.md"
)
foreach ($doc in $requiredDocs) {
    if (-not (Test-Path -LiteralPath (Join-Path $Root $doc))) {
        Add-Blocker "缺少发布文档: $doc"
    }
}
$buildScript = Join-Path $Root "build_production.ps1"
if (Test-Path -LiteralPath $buildScript) {
    $bytes = [System.IO.File]::ReadAllBytes($buildScript)
    if ($bytes.Length -lt 3 -or $bytes[0] -ne 0xEF -or $bytes[1] -ne 0xBB -or $bytes[2] -ne 0xBF) {
        Add-Blocker "build_production.ps1 缺少 UTF-8 BOM，PowerShell 5.1 可能解析失败"
    }
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($buildScript, [ref]$null, [ref]$errors) | Out-Null
    if ($errors.Count -gt 0) {
        Add-Blocker "build_production.ps1 解析失败: $($errors[0].Message)"
    }
} else {
    Add-Blocker "缺少 build_production.ps1"
}

# ---- 结果 ----
Write-Host ""
Write-Host "发布前置检查（$Profile）："
foreach ($warning in $Warnings) { Write-Host "  [WARN] $warning" -ForegroundColor Yellow }
if ($Blockers.Count -eq 0) {
    Write-Host "  [ OK ] 全部阻断项通过" -ForegroundColor Green
    exit 0
}
foreach ($blocker in $Blockers) { Write-Host "  [BLOCK] $blocker" -ForegroundColor Red }
Write-Host "  [FAIL] $($Blockers.Count) 个阻断项未解决" -ForegroundColor Red
exit 1
