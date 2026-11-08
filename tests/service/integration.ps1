# tests/service/integration.ps1 — 安全服务控制台模式集成测试
#
# 不安装 SCM 服务，不触碰真实 %ProgramData%\Verthys\Security 与 HKLM 服务键。
# 服务以 --test-console 运行，状态目录/HKCU 注册表根/管道名全部重定向。
#
# 运行：pwsh -NoProfile -File tests/service/integration.ps1
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
$workRoot = Join-Path $BuildDir "integration"

foreach ($exe in @($svcExe, $probeExe, $fakeExe)) {
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
        throw "missing executable: $exe (build verthys_security_svc/verthys_service_probe/verthys_fake_service first)"
    }
}
if (-not (Test-Path -LiteralPath $workRoot)) {
    New-Item -ItemType Directory -Path $workRoot | Out-Null
}

$script:Checks = 0
$script:Failures = New-Object System.Collections.Generic.List[string]
$script:ScenarioCounter = 0

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

function Assert-Equal {
    param($Actual, $Expected, [string]$Message)
    Assert-True -Condition ($Actual -eq $Expected) -Message "$Message (actual=$Actual expected=$Expected)"
}

function Get-RealStateSnapshot {
    $keyPath = "HKLM:\SOFTWARE\Verthys\SecurityService"
    $dirPath = Join-Path $env:ProgramData "Verthys\Security"
    $keyExists = Test-Path -LiteralPath $keyPath
    $dirExists = Test-Path -LiteralPath $dirPath
    $files = @()
    if ($dirExists) {
        $files = Get-ChildItem -LiteralPath $dirPath -File -ErrorAction SilentlyContinue |
            Sort-Object Name |
            ForEach-Object {
                try {
                    $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
                    "$($_.Name):$hash"
                } catch {
                    "$($_.Name):unreadable"
                }
            }
    }
    return "key=$keyExists;dir=$dirExists;files=$($files -join ',')"
}

function New-Scenario {
    param([string]$Name)
    $script:ScenarioCounter++
    $suffix = "$Name-$PID-$script:ScenarioCounter"
    $dir = Join-Path $workRoot $suffix
    if (Test-Path -LiteralPath $dir) {
        Remove-Item -LiteralPath $dir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $dir | Out-Null
    return [pscustomobject]@{
        Name = $Name
        Dir = $dir
        Root = "Software\VerthysTest\VerthysP2-$suffix"
        Pipe = "\\.\pipe\VerthysP2-$suffix"
        Service = $null
        ErrFile = (Join-Path $dir "service.err")
    }
}

function Start-TestService {
    param(
        [Parameter(Mandatory=$true)]$Scenario,
        [switch]$IgnoreAuth,
        [switch]$IgnoreQuota,
        [int]$ClockOffsetSec = 0
    )
    if ($Scenario.Service -ne $null -and -not $Scenario.Service.Process.HasExited) {
        throw "service already running for scenario $($Scenario.Name)"
    }
    $arguments = @(
        "--test-console",
        "--test-state-dir", $Scenario.Dir,
        "--test-registry-root", $Scenario.Root,
        "--test-pipe", $Scenario.Pipe,
        "--test-run-seconds", "0"
    )
    if ($IgnoreAuth) { $arguments += "--test-ignore-client-auth" }
    if ($IgnoreQuota) { $arguments += "--test-ignore-user-quota" }
    if ($ClockOffsetSec -ne 0) {
        $arguments += @("--test-clock-offset-sec", "$ClockOffsetSec")
    }
    if (Test-Path -LiteralPath $Scenario.ErrFile) {
        Remove-Item -LiteralPath $Scenario.ErrFile -Force
    }
    $process = Start-Process -FilePath $svcExe -ArgumentList $arguments `
        -RedirectStandardError $Scenario.ErrFile -PassThru -WindowStyle Hidden
    $ready = $false
    for ($i = 0; $i -lt 200; $i++) {
        if ($process.HasExited) { break }
        if (Test-Path -LiteralPath $Scenario.ErrFile) {
            $text = Get-Content -LiteralPath $Scenario.ErrFile -Raw -ErrorAction SilentlyContinue
            if ($null -ne $text -and $text -match "READY") {
                $ready = $true
                break
            }
        }
        Start-Sleep -Milliseconds 50
    }
    if (-not $ready) {
        $err = ""
        if (Test-Path -LiteralPath $Scenario.ErrFile) {
            $err = Get-Content -LiteralPath $Scenario.ErrFile -Raw
        }
        throw "service did not become ready for $($Scenario.Name): $err"
    }
    $Scenario.Service = [pscustomobject]@{ Process = $process; ErrFile = $Scenario.ErrFile }
    return $Scenario.Service
}

function Stop-TestService {
    param([Parameter(Mandatory=$true)]$Scenario)
    if ($null -eq $Scenario.Service) { return }
    $process = $Scenario.Service.Process
    if (-not $process.HasExited) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        $process.WaitForExit(5000) | Out-Null
    }
    $Scenario.Service = $null
}

function Remove-Scenario {
    param([Parameter(Mandatory=$true)]$Scenario)
    Stop-TestService -Scenario $Scenario
    $regPath = "HKCU:\$($Scenario.Root)"
    if (Test-Path -LiteralPath $regPath) {
        Remove-Item -LiteralPath $regPath -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $Scenario.Dir) {
        Remove-Item -LiteralPath $Scenario.Dir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-Probe {
    param(
        [Parameter(Mandatory=$true)]$Scenario,
        [Parameter(Mandatory=$true)][string]$Command,
        [int]$ExpectStatus = -1,
        [int]$Repeat = 1,
        [int]$DelayMs = 0,
        [string]$PipeOverride = "",
        [string]$PubKeyFile = "",
        [switch]$SkipVerify
    )
    $pipe = if ([string]::IsNullOrEmpty($PipeOverride)) { $Scenario.Pipe } else { $PipeOverride }
    $arguments = @("--pipe", $pipe, "--command", $Command)
    if (-not [string]::IsNullOrEmpty($PubKeyFile)) {
        $arguments += @("--pubkey-file", $PubKeyFile)
    } elseif (-not [string]::IsNullOrEmpty($Scenario.Root)) {
        $arguments += @("--registry-root", $Scenario.Root)
    }
    if ($SkipVerify) { $arguments += "--skip-verify" }
    if ($ExpectStatus -ge 0) { $arguments += @("--expect-status", "$ExpectStatus") }
    if ($Repeat -gt 1) { $arguments += @("--repeat", "$Repeat") }
    if ($DelayMs -gt 0) { $arguments += @("--delay-ms", "$DelayMs") }

    $output = & $probeExe @arguments 2>&1
    $exitCode = $LASTEXITCODE
    $text = ($output | Out-String).Trim()
    $status = -1
    $retry = -1
    $remaining = -1
    $matches = [regex]::Matches($text, "status=(\d+) retry=(\d+) remaining=(\d+)")
    if ($matches.Count -gt 0) {
        $last = $matches[$matches.Count - 1]
        $status = [int]$last.Groups[1].Value
        $retry = [int]$last.Groups[2].Value
        $remaining = [int]$last.Groups[3].Value
    }
    return [pscustomobject]@{
        ExitCode = $exitCode
        Status = $status
        Retry = $retry
        Remaining = $remaining
        Text = $text
    }
}

function Assert-Probe {
    param($Result, [int]$ExpectedStatus, [string]$Label)
    Assert-True -Condition ($Result.ExitCode -eq 0) -Message "$Label exit code (actual=$($Result.ExitCode), output=$($Result.Text))"
    Assert-Equal -Actual $Result.Status -Expected $ExpectedStatus -Message "$Label status"
}

function Invoke-RawPipeRequest {
    param([string]$PipeName, [byte[]]$Payload)
    $shortName = $PipeName -replace '^\\\\\.\\pipe\\', ''
    $client = [System.IO.Pipes.NamedPipeClientStream]::new(".", $shortName,
        [System.IO.Pipes.PipeDirection]::InOut)
    try {
        $client.Connect(1000)
        $client.Write($Payload, 0, $Payload.Length)
        $client.Flush()
        $response = New-Object byte[] 128
        $total = 0
        $deadline = [DateTime]::UtcNow.AddSeconds(2)
        while ($total -lt 128 -and [DateTime]::UtcNow -lt $deadline) {
            $read = $client.Read($response, $total, 128 - $total)
            if ($read -le 0) { break }
            $total += $read
        }
        return [pscustomobject]@{ Length = $total; Bytes = $response }
    } finally {
        $client.Dispose()
    }
}

Write-Host "=== P2 integration tests ===" -ForegroundColor Cyan
$realBefore = Get-RealStateSnapshot
$scenarios = New-Object System.Collections.Generic.List[object]

try {
    # baseline 已采集；全部场景结束后复核。
    Write-Host "[ I1/I2 ] Ping / Check / RecordFailure" -ForegroundColor Cyan
    $basic = New-Scenario "basic"
    $scenarios.Add($basic)
    Start-TestService -Scenario $basic -IgnoreAuth | Out-Null
    $ping = Invoke-Probe -Scenario $basic -Command "ping" -ExpectStatus 0
    Assert-Probe -Result $ping -ExpectedStatus 0 -Label "I1 Ping"
    Assert-Equal -Actual $ping.Remaining -Expected 10 -Message "I1 initial tokens"
    $check1 = Invoke-Probe -Scenario $basic -Command "check" -ExpectStatus 0
    Assert-Probe -Result $check1 -ExpectedStatus 0 -Label "I2 Check before failure"
    $record = Invoke-Probe -Scenario $basic -Command "record" -ExpectStatus 0
    Assert-Probe -Result $record -ExpectedStatus 0 -Label "I2 RecordFailure"
    Assert-Equal -Actual $record.Remaining -Expected 9 -Message "I2 token decrement"
    $check2 = Invoke-Probe -Scenario $basic -Command "check" -ExpectStatus 0
    Assert-Probe -Result $check2 -ExpectedStatus 0 -Label "I2 Check after failure"
    Assert-Equal -Actual $check2.Remaining -Expected 9 -Message "I2 token stays 9"
    $reg = Get-ItemProperty -LiteralPath "HKCU:\$($basic.Root)"
    Assert-Equal -Actual $reg.StateInitialized -Expected 1 -Message "I1 StateInitialized anchor"
    Assert-Equal -Actual $reg.ProtocolVersion -Expected 1 -Message "I1 ProtocolVersion anchor"
    Assert-True -Condition (Test-Path -LiteralPath (Join-Path $basic.Dir "machine_rate.bin")) -Message "I1 state file exists"
    Stop-TestService -Scenario $basic

    Write-Host "[ I3/I4 ] global bucket exhaustion and clock refill" -ForegroundColor Cyan
    $bucket = New-Scenario "bucket"
    $scenarios.Add($bucket)
    Start-TestService -Scenario $bucket -IgnoreAuth -IgnoreQuota | Out-Null
    $ten = Invoke-Probe -Scenario $bucket -Command "record" -Repeat 10
    Assert-Equal -Actual $ten.Remaining -Expected 0 -Message "I3 ten failures drain bucket"
    $locked = Invoke-Probe -Scenario $bucket -Command "check" -ExpectStatus 1
    Assert-Probe -Result $locked -ExpectedStatus 1 -Label "I3 Check is LOCKED"
    Assert-True -Condition ($locked.Retry -gt 0) -Message "I3 retry_after_sec > 0"
    Stop-TestService -Scenario $bucket
    Start-TestService -Scenario $bucket -IgnoreAuth -IgnoreQuota -ClockOffsetSec 60 | Out-Null
    $refill = Invoke-Probe -Scenario $bucket -Command "check" -ExpectStatus 0
    Assert-Probe -Result $refill -ExpectedStatus 0 -Label "I4 Check after 60s"
    Assert-Equal -Actual $refill.Remaining -Expected 1 -Message "I4 one token refilled"
    Stop-TestService -Scenario $bucket

    Write-Host "[ I5 ] unsigned client is DENIED" -ForegroundColor Cyan
    $unsigned = New-Scenario "unsigned"
    $scenarios.Add($unsigned)
    Start-TestService -Scenario $unsigned | Out-Null
    $denied = Invoke-Probe -Scenario $unsigned -Command "ping" -ExpectStatus 2
    Assert-Probe -Result $denied -ExpectedStatus 2 -Label "I5 unsigned client"
    Stop-TestService -Scenario $unsigned

    Write-Host "[ I6 ] forged server signature is rejected" -ForegroundColor Cyan
    $fake = New-Scenario "fake"
    $scenarios.Add($fake)
    Start-TestService -Scenario $fake -IgnoreAuth | Out-Null
    $pubFile = Join-Path $fake.Dir "server_pubkey.bin"
    $props = Get-ItemProperty -LiteralPath "HKCU:\$($fake.Root)"
    [System.IO.File]::WriteAllBytes($pubFile, [byte[]]$props.ServerPubKey)
    Stop-TestService -Scenario $fake
    $fakePipe = "\\.\pipe\VerthysP2Fake-$PID"
    $fakeErr = Join-Path $fake.Dir "fake.err"
    $fakeProcess = Start-Process -FilePath $fakeExe `
        -ArgumentList @("--pipe", $fakePipe) `
        -RedirectStandardError $fakeErr -PassThru -WindowStyle Hidden
    for ($i = 0; $i -lt 100; $i++) {
        if ($fakeProcess.HasExited) { break }
        if (Test-Path -LiteralPath $fakeErr) {
            $text = Get-Content -LiteralPath $fakeErr -Raw -ErrorAction SilentlyContinue
            if ($null -ne $text -and $text -match "FAKE_READY") { break }
        }
        Start-Sleep -Milliseconds 50
    }
    $forged = Invoke-Probe -Scenario $fake -Command "ping" `
        -PipeOverride $fakePipe -PubKeyFile $pubFile
    Assert-Equal -Actual $forged.ExitCode -Expected 11 -Message "I6 forged response rejected (verify failure)"
    if (-not $fakeProcess.HasExited) {
        Stop-Process -Id $fakeProcess.Id -Force -ErrorAction SilentlyContinue
        $fakeProcess.WaitForExit(5000) | Out-Null
    }

    Write-Host "[ I7/I8 ] restart preserves state; tamper fail-closed" -ForegroundColor Cyan
    $restart = New-Scenario "restart"
    $scenarios.Add($restart)
    Start-TestService -Scenario $restart -IgnoreAuth | Out-Null
    $r1 = Invoke-Probe -Scenario $restart -Command "record" -ExpectStatus 0
    Assert-Equal -Actual $r1.Remaining -Expected 9 -Message "I7 record before restart"
    Stop-TestService -Scenario $restart
    Start-TestService -Scenario $restart -IgnoreAuth | Out-Null
    $r2 = Invoke-Probe -Scenario $restart -Command "check" -ExpectStatus 0
    Assert-Probe -Result $r2 -ExpectedStatus 0 -Label "I7 Check after restart"
    Assert-Equal -Actual $r2.Remaining -Expected 9 -Message "I7 tokens preserved"
    Stop-TestService -Scenario $restart

    $stateFile = Join-Path $restart.Dir "machine_rate.bin"
    $blob = [System.IO.File]::ReadAllBytes($stateFile)
    $blob[70] = [byte]($blob[70] -bxor 0x01)
    [System.IO.File]::WriteAllBytes($stateFile, $blob)
    Start-TestService -Scenario $restart -IgnoreAuth | Out-Null
    $tampered = Invoke-Probe -Scenario $restart -Command "ping" -ExpectStatus 5
    Assert-Probe -Result $tampered -ExpectedStatus 5 -Label "I8 tampered state Ping"
    $failClosedText = Get-Content -LiteralPath $restart.ErrFile -Raw
    Assert-True -Condition ($failClosedText -match "FAIL_CLOSED") -Message "I8 service reports FAIL_CLOSED"
    Stop-TestService -Scenario $restart

    Write-Host "[ I9 ] 32 concurrent RecordFailure" -ForegroundColor Cyan
    $concurrent = New-Scenario "concurrent"
    $scenarios.Add($concurrent)
    Start-TestService -Scenario $concurrent -IgnoreAuth -IgnoreQuota | Out-Null
    $okCount = 0
    $lockedCount = 0
    $badCount = 0
    $waveIndex = 0
    for ($wave = 0; $wave -lt 4; $wave++) {
        $processes = @()
        for ($j = 0; $j -lt 8; $j++) {
            $waveIndex++
            $outFile = Join-Path $concurrent.Dir ("probe-{0}.out" -f $waveIndex)
            $processes += Start-Process -FilePath $probeExe `
                -ArgumentList @("--pipe", $concurrent.Pipe,
                    "--registry-root", $concurrent.Root,
                    "--command", "record") `
                -RedirectStandardOutput $outFile -PassThru -NoNewWindow
        }
        $processes | Wait-Process
        # 给服务端工作线程回收并重建实例留出时间，避免下一波客户端全部
        # 命中 ERROR_PIPE_BUSY（服务端实例上限 8 是设计约束）。
        Start-Sleep -Milliseconds 300
    }
    for ($k = 1; $k -le 32; $k++) {
        $outFile = Join-Path $concurrent.Dir ("probe-{0}.out" -f $k)
        if (-not (Test-Path -LiteralPath $outFile)) { $badCount++; continue }
        $text = Get-Content -LiteralPath $outFile -Raw
        if ($text -match "status=0") { $okCount++ }
        elseif ($text -match "status=1") { $lockedCount++ }
        else { $badCount++ }
    }
    Assert-Equal -Actual $okCount -Expected 10 -Message "I9 OK count"
    Assert-Equal -Actual $lockedCount -Expected 22 -Message "I9 LOCKED count"
    Assert-Equal -Actual $badCount -Expected 0 -Message "I9 malformed probe output"
    $afterConcurrent = Invoke-Probe -Scenario $concurrent -Command "check" -ExpectStatus 1
    Assert-Probe -Result $afterConcurrent -ExpectedStatus 1 -Label "I9 Check after concurrency"
    Stop-TestService -Scenario $concurrent

    Write-Host "[ I10/I11 ] reset does not refill; clock rollback does not refill" -ForegroundColor Cyan
    $reset = New-Scenario "reset"
    $scenarios.Add($reset)
    Start-TestService -Scenario $reset -IgnoreAuth | Out-Null
    $resetRecord = Invoke-Probe -Scenario $reset -Command "record" -ExpectStatus 0
    Assert-Equal -Actual $resetRecord.Remaining -Expected 9 -Message "I10 record before reset"
    $resetMany = Invoke-Probe -Scenario $reset -Command "reset" -Repeat 10 -ExpectStatus 0
    Assert-Probe -Result $resetMany -ExpectedStatus 0 -Label "I10 reset x10"
    $afterReset = Invoke-Probe -Scenario $reset -Command "check" -ExpectStatus 0
    Assert-Probe -Result $afterReset -ExpectedStatus 0 -Label "I10 Check after reset"
    Assert-Equal -Actual $afterReset.Remaining -Expected 9 -Message "I10 reset did not refill"
    Stop-TestService -Scenario $reset
    Start-TestService -Scenario $reset -IgnoreAuth -ClockOffsetSec -60 | Out-Null
    $rollback = Invoke-Probe -Scenario $reset -Command "check" -ExpectStatus 0
    Assert-Probe -Result $rollback -ExpectedStatus 0 -Label "I11 Check after clock rollback"
    Assert-Equal -Actual $rollback.Remaining -Expected 9 -Message "I11 rollback did not refill"
    Stop-TestService -Scenario $reset

    Write-Host "[ I12 ] malformed requests are BAD_REQUEST" -ForegroundColor Cyan
    $badreq = New-Scenario "badreq"
    $scenarios.Add($badreq)
    Start-TestService -Scenario $badreq -IgnoreAuth | Out-Null
    $bad64 = New-Object byte[] 64
    $magicBytes = [BitConverter]::GetBytes([uint32]0x51535456)
    for ($i = 0; $i -lt 4; $i++) { $bad64[$i] = $magicBytes[$i] }
    $bad64[4] = 1; $bad64[5] = 0
    $bad64[6] = 99; $bad64[7] = 0
    $raw1 = Invoke-RawPipeRequest -PipeName $badreq.Pipe -Payload $bad64
    $status1 = if ($raw1.Length -ge 128) { [BitConverter]::ToUInt16($raw1.Bytes, 6) } else { -1 }
    Assert-Equal -Actual $status1 -Expected 3 -Message "I12 invalid command -> BAD_REQUEST"
    $bad65 = New-Object byte[] 65
    $raw2 = Invoke-RawPipeRequest -PipeName $badreq.Pipe -Payload $bad65
    $status2 = if ($raw2.Length -ge 128) { [BitConverter]::ToUInt16($raw2.Bytes, 6) } else { -1 }
    Assert-Equal -Actual $status2 -Expected 3 -Message "I12 overlong request -> BAD_REQUEST"
    $afterBad = Invoke-Probe -Scenario $badreq -Command "ping" -ExpectStatus 0
    Assert-Equal -Actual $afterBad.Remaining -Expected 10 -Message "I12 budget unchanged"
    Stop-TestService -Scenario $badreq
}
finally {
    foreach ($scenario in $scenarios) {
        Remove-Scenario -Scenario $scenario
    }
}

$realAfter = Get-RealStateSnapshot
Assert-Equal -Actual $realAfter -Expected $realBefore -Message "I0 real ProgramData/HKLM untouched"

Write-Host ""
Write-Host "=== Integration summary: $($script:Checks - $script:Failures.Count) passed, $($script:Failures.Count) failed ===" -ForegroundColor Cyan
if ($script:Failures.Count -gt 0) {
    foreach ($failure in $script:Failures) {
        Write-Host "  - $failure" -ForegroundColor Red
    }
    exit 1
}
exit 0
