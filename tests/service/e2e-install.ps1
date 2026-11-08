# tests/service/e2e-install.ps1 — 安全服务 SCM/安装 E2E（仅在干净 Windows VM 提权执行）
#
# 默认 SKIP。执行前必须满足：
#   - 干净 VM，尚未安装 VerthysSecuritySvc；
#   - 已构建 security-service 产物（VerthysSecuritySvc.exe 与其根 CA 同目录）；
#   - 以管理员身份运行，并显式传入 -AllowElevatedE2E。
#
# 未签名本地验证使用 /test-allow-unsigned /test-skip-ping；正式验收必须使用
# 发布者签名产物与签名探针（-Signed + -SignedProbe）。
param(
    [switch]$AllowElevatedE2E,
    [string]$Artifacts = "",
    [switch]$Signed,
    [string]$SignedProbe = "",
    [switch]$KeepArtifacts
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

if (-not $AllowElevatedE2E) {
    Write-Host "[SKIP] e2e-install requires a clean VM and -AllowElevatedE2E" -ForegroundColor Yellow
    exit 0
}

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "e2e-install must run elevated"
}

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ([string]::IsNullOrEmpty($Artifacts)) {
    $Artifacts = Join-Path $repoRoot "build_security_service\Debug"
}
$serviceExe = Join-Path $Artifacts "VerthysSecuritySvc.exe"
$stateDir = Join-Path $env:ProgramData "Verthys\Security"
$installDir = Join-Path $env:ProgramFiles "Verthys\SecurityService"
$regKey = "HKLM:\SOFTWARE\Verthys\SecurityService"

foreach ($path in @($serviceExe)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "missing artifact: $path"
    }
}

$script:Checks = 0
$script:Failures = New-Object System.Collections.Generic.List[string]

function Assert-True {
    param([bool]$Condition, [string]$Message)
    $script:Checks++
    if (-not $Condition) {
        $script:Failures.Add($Message)
        Write-Host "[FAIL] $Message" -ForegroundColor Red
    } else {
        Write-Host "[PASS] $Message" -ForegroundColor Green
    }
}

function Invoke-Setup {
    param([string[]]$Arguments)
    $full = @($serviceExe) + $Arguments
    if (-not $Signed) {
        $full += @("/test-allow-unsigned", "/test-skip-ping")
    }
    & $full[0] @($full[1..($full.Count - 1)])
    return $LASTEXITCODE
}

function Get-ServiceState {
    $output = & sc.exe query VerthysSecuritySvc 2>&1
    if ($LASTEXITCODE -ne 0) { return "MISSING" }
    if ($output -match "RUNNING") { return "RUNNING" }
    if ($output -match "STOPPED") { return "STOPPED" }
    return "OTHER"
}

function Test-AclNoUsersWrite {
    param([string]$Path)
    $output = & icacls.exe $Path 2>&1 | Out-String
    return -not ($output -match "BUILTIN\\Users.*(W|M|F)" -or $output -match "Users.*(W|M|F)")
}

$existing = Get-ServiceState
Assert-True -Condition ($existing -eq "MISSING") -Message "E0 clean VM has no existing service"

try {
    Write-Host "[ E1 ] fresh install" -ForegroundColor Cyan
    $rc = Invoke-Setup @("/install", "/quiet")
    Assert-True -Condition ($rc -eq 0) -Message "E1 install exit code (actual=$rc)"
    Assert-True -Condition ((Get-ServiceState) -eq "RUNNING") -Message "E1 service RUNNING"
    Assert-True -Condition (Test-Path -LiteralPath $stateDir) -Message "E1 state directory exists"
    Assert-True -Condition (Test-Path -LiteralPath (Join-Path $stateDir "machine_rate.bin")) -Message "E1 state file exists"
    Assert-True -Condition (Test-Path -LiteralPath (Join-Path $stateDir "machine_state.key")) -Message "E1 HMAC key exists"
    Assert-True -Condition (Test-Path -LiteralPath (Join-Path $stateDir "service_signing.key")) -Message "E1 signing key exists"
    Assert-True -Condition (Test-AclNoUsersWrite $stateDir) -Message "E1 state dir denies Users write"
    if (Test-Path -LiteralPath $regKey) {
        $props = Get-ItemProperty -LiteralPath $regKey
        Assert-True -Condition ($props.Installed -eq 1) -Message "E1 Installed=1"
        Assert-True -Condition ($props.StateInitialized -eq 1) -Message "E1 StateInitialized=1"
        Assert-True -Condition ($props.ProtocolVersion -eq 1) -Message "E1 ProtocolVersion=1"
        Assert-True -Condition ($null -ne $props.ServerPubKey) -Message "E1 ServerPubKey present"
    } else {
        Assert-True -Condition $false -Message "E1 registry key exists"
    }

    Write-Host "[ E2 ] probe Ping" -ForegroundColor Cyan
    if ($Signed -and -not [string]::IsNullOrEmpty($SignedProbe)) {
        & $SignedProbe --command ping --expect-status 0
        Assert-True -Condition ($LASTEXITCODE -eq 0) -Message "E2 signed probe Ping OK"
    } else {
        Write-Host "[SKIP] E2 unsigned test artifact cannot pass client Authenticode auth" -ForegroundColor Yellow
    }

    Write-Host "[ E3 ] reinstall preserves state" -ForegroundColor Cyan
    $stateHashBefore = (Get-FileHash -LiteralPath (Join-Path $stateDir "machine_rate.bin") -Algorithm SHA256).Hash
    $rc = Invoke-Setup @("/install", "/quiet")
    Assert-True -Condition ($rc -eq 0) -Message "E3 reinstall exit code (actual=$rc)"
    Assert-True -Condition ((Get-ServiceState) -eq "RUNNING") -Message "E3 service RUNNING after reinstall"
    $stateHashAfter = (Get-FileHash -LiteralPath (Join-Path $stateDir "machine_rate.bin") -Algorithm SHA256).Hash
    Assert-True -Condition ($stateHashBefore -eq $stateHashAfter) -Message "E3 state preserved byte-for-byte"

    Write-Host "[ E5 ] reboot persistence is not automated by this script" -ForegroundColor Yellow
    Write-Host "[SKIP] E5 requires VM reboot; verify service AUTO_START manually" -ForegroundColor Yellow

    Write-Host "[ E7 ] uninstall" -ForegroundColor Cyan
    $rc = Invoke-Setup @("/uninstall", "/quiet")
    Assert-True -Condition ($rc -eq 0) -Message "E7 uninstall exit code (actual=$rc)"
    Assert-True -Condition ((Get-ServiceState) -eq "MISSING") -Message "E7 service removed"
    Assert-True -Condition (-not (Test-Path -LiteralPath $regKey)) -Message "E7 registry key removed"
    Assert-True -Condition (-not (Test-Path -LiteralPath $installDir)) -Message "E7 install directory removed"
    Assert-True -Condition (-not (Test-Path -LiteralPath $stateDir)) -Message "E7 state directory removed"
}
finally {
    if ($KeepArtifacts) {
        Write-Host "[e2e] artifacts kept: $stateDir / $installDir" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "=== E2E summary: $($script:Checks - $script:Failures.Count) passed, $($script:Failures.Count) failed ===" -ForegroundColor Cyan
if ($script:Failures.Count -gt 0) {
    foreach ($failure in $script:Failures) { Write-Host "  - $failure" -ForegroundColor Red }
    exit 1
}
exit 0
