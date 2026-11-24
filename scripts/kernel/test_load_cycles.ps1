# test_load_cycles.ps1 - VerthysGuard load/unload stability test (P6)
#
# Usage (elevated):
#   pwsh -NoProfile -File scripts\kernel\test_load_cycles.ps1 -Count 1000
#   pwsh -NoProfile -File scripts\kernel\test_load_cycles.ps1 -Count 10 -OutputPath C:\gate\cycles.json
#
# Starts and stops the demand-start driver repeatedly, records the per-cycle
# latency and stops on the first failure. The driver must be installed and the
# service must not be running when the test begins.

param(
    [int]$Count = 1000,
    [int]$TimeoutSeconds = 30,
    [string]$OutputPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\kernel_guard_common.ps1"

Assert-KernelGuardAdmin

if ($Count -lt 1) { throw 'Count must be >= 1' }
$repoRoot = Get-KernelGuardRepoRoot
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $repoRoot 'build_driver\load-cycles.json'
}
$outputFull = [IO.Path]::GetFullPath($OutputPath)
$serviceName = 'VerthysGuard'

$service = New-Object System.ServiceProcess.ServiceController($serviceName)
$timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
$failures = New-Object System.Collections.Generic.List[object]
$passed = 0
$maxStartMs = 0
$maxStopMs = 0
$startedAt = Get-Date
$failedCycle = 0
$failedStage = ''
$failedMessage = ''

function Set-Stopped {
    param([System.ServiceProcess.ServiceController]$Controller)
    $Controller.Refresh()
    if ($Controller.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
        $Controller.Stop()
        $Controller.WaitForStatus(
            [System.ServiceProcess.ServiceControllerStatus]::Stopped, $timeout)
    }
}

try {
    Set-Stopped -Controller $service
} catch {
    throw "Driver is not in a stoppable state: $($_.Exception.Message)"
}

for ($i = 1; $i -le $Count; $i++) {
    $startWatch = [Diagnostics.Stopwatch]::StartNew()
    $stopWatch = [Diagnostics.Stopwatch]::StartNew()
    $stage = 'start'
    try {
        $service.Start()
        $service.WaitForStatus(
            [System.ServiceProcess.ServiceControllerStatus]::Running, $timeout)
        $startWatch.Stop()

        $stage = 'stop'
        $stopWatch.Restart()
        $service.Stop()
        $service.WaitForStatus(
            [System.ServiceProcess.ServiceControllerStatus]::Stopped, $timeout)
        $stopWatch.Stop()

        $passed++
        if ($startWatch.ElapsedMilliseconds -gt $maxStartMs) {
            $maxStartMs = [int]$startWatch.ElapsedMilliseconds
        }
        if ($stopWatch.ElapsedMilliseconds -gt $maxStopMs) {
            $maxStopMs = [int]$stopWatch.ElapsedMilliseconds
        }
    } catch {
        $startWatch.Stop()
        $stopWatch.Stop()
        $failedCycle = $i
        $failedStage = $stage
        $failedMessage = $_.Exception.Message
        $failures.Add([pscustomobject]@{
            cycle = $i
            stage = $stage
            message = $_.Exception.Message
        })
        Write-Host "Cycle $i failed at ${stage}: $($_.Exception.Message)"
        break
    }
    if (($i % 100) -eq 0) {
        Write-Host "Cycle $i/$Count passed (startMax=${maxStartMs}ms stopMax=${maxStopMs}ms)"
    }
}

try {
    Set-Stopped -Controller $service
} catch {
    $failures.Add([pscustomobject]@{
        cycle = 0
        stage = 'final-stop'
        message = $_.Exception.Message
    })
}

$service.Refresh()
$finishedAt = Get-Date
$summary = [ordered]@{
    startedAtUtc = $startedAt.ToUniversalTime().ToString('o')
    finishedAtUtc = $finishedAt.ToUniversalTime().ToString('o')
    elapsedSeconds = [math]::Round(($finishedAt - $startedAt).TotalSeconds, 1)
    requested = $Count
    passed = $passed
    failed = $failures.Count
    failedCycle = $failedCycle
    failedStage = $failedStage
    failedMessage = $failedMessage
    maxStartMs = $maxStartMs
    maxStopMs = $maxStopMs
    finalStatus = "$($service.Status)"
    failures = $failures
}

$directory = Split-Path -Parent $outputFull
if (-not [string]::IsNullOrWhiteSpace($directory)) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
}
$summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $outputFull -Encoding UTF8
Write-Host "Cycle evidence: $outputFull"
Write-Host "Passed=$passed Failed=$($failures.Count) MaxStart=${maxStartMs}ms MaxStop=${maxStopMs}ms"

if ($passed -eq $Count -and $failures.Count -eq 0) { exit 0 }
exit 1
