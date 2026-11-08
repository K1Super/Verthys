# tests/service/attack.ps1 — 安全服务攻击回归（控制台模式可执行子集）
#
# 覆盖：伪造服务端、未签名客户端、reset 洗预算、单用户预算抽干、
#       停服务 fail-closed、非管理员改 HKLM。
# 需要真实 SCM 安装/管理员与第二台机器的场景由 e2e-install.ps1
# 或干净 VM 手工证据覆盖。
param(
    [string]$BuildDir = ""
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ([string]::IsNullOrEmpty($BuildDir)) {
    $BuildDir = Join-Path $repoRoot "build_security_service"
}
$svcExe = Join-Path $BuildDir "Debug\VerthysSecuritySvc.exe"
$probeExe = Join-Path $BuildDir "Debug\verthys_service_probe.exe"
$fakeExe = Join-Path $BuildDir "Debug\verthys_fake_service.exe"
$workRoot = Join-Path $BuildDir "attack"

foreach ($exe in @($svcExe, $probeExe, $fakeExe)) {
    if (-not (Test-Path -LiteralPath $exe)) { throw "missing $exe" }
}
if (-not (Test-Path -LiteralPath $workRoot)) {
    New-Item -ItemType Directory -Path $workRoot | Out-Null
}

$script:Checks = 0
$script:Failures = New-Object System.Collections.Generic.List[string]
$script:Counter = 0

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

function New-Scenario {
    param([string]$Name)
    $script:Counter++
    $suffix = "$Name-$PID-$script:Counter"
    $dir = Join-Path $workRoot $suffix
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    return [pscustomobject]@{
        Dir = $dir
        Root = "Software\VerthysTest\Attack-$suffix"
        Pipe = "\\.\pipe\VerthysAttack-$suffix"
        Paths = $null
    }
}

function Start-Svc {
    param($Scenario, [switch]$IgnoreAuth, [switch]$IgnoreQuota)
    $args = @("--test-console", "--test-state-dir", $Scenario.Dir,
        "--test-registry-root", $Scenario.Root, "--test-pipe", $Scenario.Pipe,
        "--test-run-seconds", "0")
    if ($IgnoreAuth) { $args += "--test-ignore-client-auth" }
    if ($IgnoreQuota) { $args += "--test-ignore-user-quota" }
    $err = Join-Path $Scenario.Dir "service.err"
    $p = Start-Process -FilePath $svcExe -ArgumentList $args `
        -RedirectStandardError $err -PassThru -WindowStyle Hidden
    for ($i = 0; $i -lt 200; $i++) {
        if ($p.HasExited) { break }
        if (Test-Path -LiteralPath $err) {
            $text = Get-Content -LiteralPath $err -Raw -ErrorAction SilentlyContinue
            if ($null -ne $text -and $text -match "READY") { break }
        }
        Start-Sleep -Milliseconds 50
    }
    $Scenario.Paths = [pscustomobject]@{ Process = $p; Err = $err }
}

function Stop-Svc {
    param($Scenario)
    if ($null -eq $Scenario.Paths) { return }
    $p = $Scenario.Paths.Process
    if (-not $p.HasExited) {
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        $p.WaitForExit(5000) | Out-Null
    }
    $Scenario.Paths = $null
}

function Remove-Scenario {
    param($Scenario)
    Stop-Svc $Scenario
    if (Test-Path -LiteralPath "HKCU:\$($Scenario.Root)") {
        Remove-Item -LiteralPath "HKCU:\$($Scenario.Root)" -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $Scenario.Dir) {
        Remove-Item -LiteralPath $Scenario.Dir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Probe {
    param($Scenario, [string]$Command, [int]$Repeat = 1, [string]$Pipe = "", [string]$PubFile = "", [switch]$SkipVerify)
    $args = @("--pipe", ($(if ($Pipe) { $Pipe } else { $Scenario.Pipe })), "--command", $Command)
    if ($PubFile) { $args += @("--pubkey-file", $PubFile) }
    elseif ($Scenario.Root) { $args += @("--registry-root", $Scenario.Root) }
    if ($SkipVerify) { $args += "--skip-verify" }
    if ($Repeat -gt 1) { $args += @("--repeat", "$Repeat") }
    $out = & $probeExe @args 2>&1
    $code = $LASTEXITCODE
    $text = ($out | Out-String).Trim()
    $matches = [regex]::Matches($text, "status=(\d+) retry=(\d+) remaining=(\d+)")
    $last = if ($matches.Count -gt 0) { $matches[$matches.Count - 1] } else { $null }
    return [pscustomobject]@{
        ExitCode = $code
        Status = if ($last) { [int]$last.Groups[1].Value } else { -1 }
        Remaining = if ($last) { [int]$last.Groups[3].Value } else { -1 }
        Text = $text
    }
}

Write-Host "=== P2 attack regression (console subset) ===" -ForegroundColor Cyan

# 伪造服务端
$scenario = New-Scenario "a3"
try {
    Start-Svc $scenario -IgnoreAuth
    $pubFile = Join-Path $scenario.Dir "pub.bin"
    $props = Get-ItemProperty -LiteralPath "HKCU:\$($scenario.Root)"
    [System.IO.File]::WriteAllBytes($pubFile, [byte[]]$props.ServerPubKey)
    Stop-Svc $scenario
    $fakePipe = "\\.\pipe\VerthysAttackFake-$PID"
    $fakeErr = Join-Path $scenario.Dir "fake.err"
    $fake = Start-Process -FilePath $fakeExe -ArgumentList @("--pipe", $fakePipe) `
        -RedirectStandardError $fakeErr -PassThru -WindowStyle Hidden
    for ($i = 0; $i -lt 100; $i++) {
        if ($fake.HasExited) { break }
        if (Test-Path -LiteralPath $fakeErr) {
            $text = Get-Content -LiteralPath $fakeErr -Raw -ErrorAction SilentlyContinue
            if ($null -ne $text -and $text -match "FAKE_READY") { break }
        }
        Start-Sleep -Milliseconds 50
    }
    $r = Probe $scenario "ping" -Pipe $fakePipe -PubFile $pubFile
    Assert-True -Condition ($r.ExitCode -eq 11) -Message "S-A3 forged server rejected (exit=$($r.ExitCode))"
    if (-not $fake.HasExited) { Stop-Process -Id $fake.Id -Force -ErrorAction SilentlyContinue }
}
finally { Remove-Scenario $scenario }

# 未签名客户端
$scenario = New-Scenario "a4"
try {
    Start-Svc $scenario
    $r = Probe $scenario "ping"
    Assert-True -Condition ($r.Status -eq 2) -Message "S-A4 unsigned client DENIED (status=$($r.Status))"
}
finally { Remove-Scenario $scenario }

# reset 不恢复预算
$scenario = New-Scenario "a5"
try {
    Start-Svc $scenario -IgnoreAuth
    $record = Probe $scenario "record"
    Assert-True -Condition ($record.Remaining -eq 9) -Message "S-A5 baseline token 9"
    $reset = Probe $scenario "reset" -Repeat 20
    Assert-True -Condition ($reset.ExitCode -eq 0) -Message "S-A5 reset x20 succeeded"
    $check = Probe $scenario "check"
    Assert-True -Condition ($check.Remaining -eq 9) -Message "S-A5 reset did not restore tokens"
}
finally { Remove-Scenario $scenario }

# 单用户预算抽干与每用户配额
$scenario = New-Scenario "a6"
try {
    Start-Svc $scenario -IgnoreAuth
    $drain = Probe $scenario "record" -Repeat 7
    Assert-True -Condition ($drain.Status -eq 1) -Message "S-A6 7th failure blocked by per-user quota"
    $check = Probe $scenario "check"
    Assert-True -Condition ($check.Status -eq 1) -Message "S-A6 global budget protected (check LOCKED)"
    Assert-True -Condition ($check.Remaining -eq 4) -Message "S-A6 remaining tokens preserved (expect 4)"
}
finally { Remove-Scenario $scenario }

# 停服务 fail-closed（客户端连接不可达）
$scenario = New-Scenario "a8"
try {
    Start-Svc $scenario -IgnoreAuth
    Stop-Svc $scenario
    $r = Probe $scenario "ping"
    Assert-True -Condition ($r.ExitCode -eq 10) -Message "S-A8 service stopped -> client cannot connect"
}
finally { Remove-Scenario $scenario }

# 非管理员改 HKLM
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Host "[SKIP] S-A9 requires a non-elevated process to prove HKLM write denial" -ForegroundColor Yellow
} else {
    $output = & reg.exe add "HKLM\SOFTWARE\Verthys\SecurityService" /v Installed /t REG_DWORD /d 1 /f 2>&1
    $ok = $LASTEXITCODE -ne 0
    Assert-True -Condition $ok -Message "S-A9 non-admin HKLM write denied"
}

Write-Host "[SKIP] S-A1/S-A2/S-A10 require installed SCM service + administrator (see e2e-install)" -ForegroundColor Yellow
Write-Host "[SKIP] S-A7 remote pipe requires a second machine" -ForegroundColor Yellow

Write-Host ""
Write-Host "=== Attack summary: $($script:Checks - $script:Failures.Count) passed, $($script:Failures.Count) failed ===" -ForegroundColor Cyan
if ($script:Failures.Count -gt 0) {
    foreach ($failure in $script:Failures) { Write-Host "  - $failure" -ForegroundColor Red }
    exit 1
}
exit 0
