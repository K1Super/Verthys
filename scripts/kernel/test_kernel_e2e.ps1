# test_kernel_e2e.ps1 - VerthysGuard service/application end-to-end test
#
# Usage (elevated):
#   pwsh -NoProfile -File scripts\kernel\test_kernel_e2e.ps1 -PreflightOnly
#   pwsh -NoProfile -File scripts\kernel\test_kernel_e2e.ps1 -LaunchApp
#   pwsh -NoProfile -File scripts\kernel\test_kernel_e2e.ps1 -LaunchApp -StopDriverAfterActive
#
# Flow:
#   1. Validate the staged candidate app (Verthys.exe + worker + DLL).
#   2. Verify the installed security service matches the candidate build.
#   3. Start the driver and confirm the pre-session state.
#   4. Launch the app as the normal (limited) user and wait for the worker.
#   5. Poll the driver to ACTIVE/count=1 via a SYSTEM probe.
#   6. Attempt a same-user PROCESS_VM_READ against the worker and expect denial.
#   7. Wait for the session to end and confirm the protected count returns to 0.
#
# Optional loss scenario (-StopDriverAfterActive): stop the driver while the
# session is ACTIVE, expect the kernel watchdog to destroy the worker, then
# restart the driver. The UI lock is visible in the app; this script records
# the worker exit and the driver recovery.
#
# The script never stores credentials and never reads user data. It requires
# the candidate local build (scripts/kernel output) and the candidate service
# installed; it does not install anything.

param(
    [string]$AppDir = '',
    [string]$OutputPath = '',
    [int]$TimeoutSeconds = 300,
    [switch]$LaunchApp,
    [switch]$PreflightOnly,
    [switch]$StopDriverAfterActive,
    [switch]$SkipServiceMatch,
    [switch]$SkipAppMatch,
    [switch]$SkipStartDriver,
    [switch]$KeepWorkDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\kernel_guard_common.ps1"

Assert-KernelGuardAdmin

$repoRoot = Get-KernelGuardRepoRoot
$probeDir = Join-Path $repoRoot 'build_kernel_probe'
$kgProbe = Join-Path $probeDir 'kg_probe.exe'
$accessProbe = Join-Path $probeDir 'kg_a14_probe.exe'
$candidateService = Join-Path $repoRoot 'build\security-service\VerthysSecuritySvc.exe'
if ([string]::IsNullOrWhiteSpace($AppDir)) {
    $AppDir = Join-Path $repoRoot 'build\kernel-e2e-candidate'
}
$AppDir = [IO.Path]::GetFullPath($AppDir)
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $repoRoot 'build_driver\kernel-e2e.json'
}
$OutputPath = [IO.Path]::GetFullPath($OutputPath)
$workRoot = Join-Path $env:WINDIR ('Temp\VerthysKgE2E-' + [guid]::NewGuid().ToString('N'))
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$probeTaskName = 'VerthysKgE2EProbe'
$accessTaskName = 'VerthysKgE2EAccess'
$appTaskName = 'VerthysKgE2EApp'
$failures = New-Object System.Collections.Generic.List[string]
$result = [ordered]@{
    startedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    appDir = $AppDir
    serviceInstalledPath = ''
    serviceCandidatePath = $candidateService
    serviceMatch = $false
    driverStarted = $false
    preState = $null
    workerPid = 0
    workerImage = ''
    activeState = $null
    access = $null
    loss = $null
    postState = $null
    failures = $failures
    status = 'FAIL'
}
$driverStartedByScript = $false
$appProcessId = 0
$workerPid = 0
$accessPassed = $false
$activeSeen = $false
$postCountZero = $false
$lossWorkerExited = $false
$lossElapsedMs = 0

function Write-Step {
    param([string]$Message)
    Write-Host "[e2e] $Message"
}

function Get-JsonValue {
    param($Object, [string]$Name, $Default = $null)
    if ($null -ne $Object -and $null -ne $Object.PSObject.Properties[$Name]) {
        return $Object.PSObject.Properties[$Name].Value
    }
    return $Default
}

function Wait-File {
    param([string]$Path, [int]$Seconds)
    for ($i = 0; $i -lt $Seconds * 10; $i++) {
        if (Test-Path -LiteralPath $Path) { return $true }
        Start-Sleep -Milliseconds 100
    }
    return $false
}

function Read-JsonFile {
    param([string]$Path, [int]$Seconds = 15)
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path -LiteralPath $Path) {
            try {
                $raw = Get-Content -LiteralPath $Path -Raw
                if (-not [string]::IsNullOrWhiteSpace($raw)) {
                    return ($raw | ConvertFrom-Json)
                }
            } catch { }
        }
        Start-Sleep -Milliseconds 200
    }
    throw "Timed out reading JSON: $Path"
}

function Remove-Task {
    param([string]$Name, [switch]$Stop)
    if ($Stop) {
        try { Stop-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue } catch { }
    }
    try {
        Unregister-ScheduledTask -TaskName $Name -Confirm:$false -ErrorAction SilentlyContinue
    } catch { }
}

function New-SystemTask {
    param([string]$Name, [string]$Exe, [string]$Arguments, [string]$WorkDir)
    Remove-Task -Name $Name -Stop
    $action = New-ScheduledTaskAction -Execute $Exe -Argument $Arguments -WorkingDirectory $WorkDir
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $Name -Action $action -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName $Name
}

function New-UserTask {
    param([string]$Name, [string]$Exe, [string]$Arguments, [string]$WorkDir)
    Remove-Task -Name $Name -Stop
    $action = New-ScheduledTaskAction -Execute $Exe -Argument $Arguments -WorkingDirectory $WorkDir
    $principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Limited
    Register-ScheduledTask -TaskName $Name -Action $action -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName $Name
}

function Invoke-SystemProbe {
    param([int]$TimeoutSeconds = 20)
    $out = Join-Path $workRoot ('status-' + [guid]::NewGuid().ToString('N') + '.json')
    New-SystemTask -Name $probeTaskName -Exe $kgProbe -Arguments ('--out "' + $out + '"') -WorkDir $workRoot
    try {
        $null = Wait-File -Path $out -Seconds $TimeoutSeconds
        $probe = Read-JsonFile -Path $out -Seconds 10
    } finally {
        Remove-Task -Name $probeTaskName -Stop
    }
    if ((Get-JsonValue $probe 'status' '') -ne 'PASS') {
        throw ("SYSTEM probe failed: open=$((Get-JsonValue $probe 'open_ok' $false)) " +
               "ping=$((Get-JsonValue $probe 'ping_ok' $false)) " +
               "query=$((Get-JsonValue $probe 'query_ok' $false))")
    }
    return $probe
}

function Invoke-AccessProbe {
    param([string]$ImageName, [int]$TargetPid, [int]$TimeoutSeconds = 40)
    $out = Join-Path $workRoot ('access-' + [guid]::NewGuid().ToString('N') + '.json')
    $args = '--image "' + $ImageName + '" --pid ' + $TargetPid +
        ' --out "' + $out + '" --timeout 20'
    New-UserTask -Name $accessTaskName -Exe $accessProbe -Arguments $args -WorkDir $workRoot
    try {
        $null = Wait-File -Path $out -Seconds $TimeoutSeconds
        $probe = Read-JsonFile -Path $out -Seconds 10
    } finally {
        Remove-Task -Name $accessTaskName -Stop
    }
    return $probe
}

function Get-WorkerProcess {
    $rootFull = $AppDir.TrimEnd('\')
    $candidates = @(Get-Process -Name 'verthys-worker*' -ErrorAction SilentlyContinue)
    foreach ($process in $candidates) {
        $path = $null
        try { $path = $process.Path } catch { }
        if ([string]::IsNullOrWhiteSpace($path)) {
            try {
                $cim = Get-CimInstance Win32_Process -Filter "ProcessId=$($process.Id)"
                $path = $cim.ExecutablePath
            } catch { }
        }
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        $dir = Split-Path -Parent $path
        if (-not [string]::IsNullOrWhiteSpace($dir) -and
            ([IO.Path]::GetFullPath($dir).TrimEnd('\') -ieq $rootFull)) {
            return $process
        }
    }
    return $null
}

function Get-AppProcess {
    param([string]$ExePath)
    $candidates = @(Get-Process -Name 'Verthys' -ErrorAction SilentlyContinue)
    foreach ($process in $candidates) {
        $path = $null
        try { $path = $process.Path } catch { }
        if ([string]::IsNullOrWhiteSpace($path)) {
            try {
                $cim = Get-CimInstance Win32_Process -Filter "ProcessId=$($process.Id)"
                $path = $cim.ExecutablePath
            } catch { }
        }
        if (-not [string]::IsNullOrWhiteSpace($path) -and
            ([IO.Path]::GetFullPath($path) -ieq [IO.Path]::GetFullPath($ExePath))) {
            return $process
        }
    }
    return $null
}

function Wait-DriverState {
    param([int]$DesiredState, [int]$MinCount, [int]$Seconds)
    $deadline = (Get-Date).AddSeconds($Seconds)
    $last = $null
    while ((Get-Date) -lt $deadline) {
        $probe = Invoke-SystemProbe
        $last = $probe
        $state = [int](Get-JsonValue $probe 'state' -1)
        $count = [int](Get-JsonValue $probe 'protected_count' -1)
        if ($state -eq $DesiredState -and $count -ge $MinCount) {
            return $probe
        }
        Start-Sleep -Milliseconds 1200
    }
    return $last
}

function Stop-Driver {
    $svc = Get-Service -Name 'VerthysGuard' -ErrorAction Stop
    if ("$($svc.Status)" -ne 'Stopped') {
        & sc.exe stop VerthysGuard | Out-Null
        for ($i = 0; $i -lt 60; $i++) {
            $svc = Get-Service -Name 'VerthysGuard' -ErrorAction SilentlyContinue
            if ($null -ne $svc -and "$($svc.Status)" -eq 'Stopped') { return $true }
            Start-Sleep -Milliseconds 500
        }
        return $false
    }
    return $true
}

function Start-Driver {
    param([switch]$AllowAlreadyRunning)
    $svc = Get-Service -Name 'VerthysGuard' -ErrorAction Stop
    if ("$($svc.Status)" -eq 'Running') { return $true }
    & sc.exe start VerthysGuard | Out-Null
    for ($i = 0; $i -lt 60; $i++) {
        $svc = Get-Service -Name 'VerthysGuard' -ErrorAction SilentlyContinue
        if ($null -ne $svc -and "$($svc.Status)" -eq 'Running') { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Get-ServiceImagePath {
    param($Service)
    $raw = ([string]$Service.PathName).Trim()
    if ($raw -match '^"([^"]+)"') { return $matches[1] }
    if (Test-Path -LiteralPath $raw -PathType Leaf) { return $raw }
    if ($raw -match '^(.*?\.exe)(\s|$)') { return $matches[1] }
    if ($raw -match '^(\S+)') { return $matches[1] }
    return ''
}

function Assert-CandidateFile {
    param([string]$Path, [string]$Label)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label missing: $Path"
    }
}

function Assert-ValidSignature {
    param([string]$Path, [string]$Label)
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid') {
        throw "$Label signature is not valid: $($signature.Status)"
    }
}

function Stage-Candidate {
    $srcExe = Join-Path $repoRoot 'verthys-tauri\src-tauri\target\release\Verthys.exe'
    $srcWorker = Join-Path $repoRoot 'verthys-tauri\verthys-worker\target\release\verthys-worker.exe'
    $srcDll = Join-Path $repoRoot 'build\core\Release\verthys.dll'
    Assert-CandidateFile $srcExe 'candidate Verthys.exe'
    Assert-CandidateFile $srcWorker 'candidate worker'
    Assert-CandidateFile $srcDll 'candidate DLL'
    New-Item -ItemType Directory -Path $AppDir -Force | Out-Null
    Copy-Item -LiteralPath $srcExe -Destination (Join-Path $AppDir 'Verthys.exe') -Force
    Copy-Item -LiteralPath $srcWorker -Destination (Join-Path $AppDir 'verthys-worker.exe') -Force
    Copy-Item -LiteralPath $srcDll -Destination (Join-Path $AppDir 'verthys.dll') -Force
    Write-Step "Candidate staged: $AppDir"
}

try {
    Assert-CandidateFile $kgProbe 'kg_probe.exe'
    Assert-CandidateFile $accessProbe 'kg_a14_probe.exe'
    if (-not (Test-Path -LiteralPath $AppDir -PathType Container)) {
        Stage-Candidate
    }
    $appExe = Join-Path $AppDir 'Verthys.exe'
    $appWorker = Join-Path $AppDir 'verthys-worker.exe'
    $appDll = Join-Path $AppDir 'verthys.dll'
    Assert-CandidateFile $appExe 'Verthys.exe'
    Assert-CandidateFile $appWorker 'worker'
    Assert-CandidateFile $appDll 'verthys.dll'
    Assert-ValidSignature $appExe 'Verthys.exe'
    Assert-ValidSignature $appWorker 'worker'
    Assert-ValidSignature $appDll 'verthys.dll'
    $result.appExeSha256 = (Get-FileHash -LiteralPath $appExe -Algorithm SHA256).Hash
    $result.appWorkerSha256 = (Get-FileHash -LiteralPath $appWorker -Algorithm SHA256).Hash
    $result.appDllSha256 = (Get-FileHash -LiteralPath $appDll -Algorithm SHA256).Hash

    $buildAppExe = Join-Path $repoRoot 'verthys-tauri\src-tauri\target\release\Verthys.exe'
    $stagingDir = [IO.Path]::GetFullPath((Join-Path $repoRoot 'build\kernel-e2e-candidate'))
    $appVersionText = ([string](Get-Item -LiteralPath $appExe).VersionInfo.FileVersion).Trim()
    $result.appFileVersion = $appVersionText
    if (-not $SkipAppMatch) {
        if ($AppDir -ieq $stagingDir) {
            if (Test-Path -LiteralPath $buildAppExe -PathType Leaf) {
                $buildAppHash = (Get-FileHash -LiteralPath $buildAppExe -Algorithm SHA256).Hash
                if ($buildAppHash -ne $result.appExeSha256) {
                    throw ("Staged app does not match the latest build. " +
                           "app=$($result.appExeSha256) build=$buildAppHash.")
                }
            }
            $result.appMatch = $true
            $result.appMatchMode = 'staging-hash'
        } else {
            $productVersionText = (Get-Content -LiteralPath (Join-Path $repoRoot 'VERSION') -Raw).Trim()
            $productVersion = $null
            $appVersion = $null
            try { $productVersion = [version]$productVersionText } catch { }
            if ($appVersionText -match '^(\d+\.\d+\.\d+)') {
                try { $appVersion = [version]$matches[1] } catch { }
            }
            $versionOk = ($null -ne $productVersion -and $null -ne $appVersion -and
                $appVersion.Major -eq $productVersion.Major -and
                $appVersion.Minor -eq $productVersion.Minor -and
                $appVersion.Build -eq $productVersion.Build)
            if (-not $versionOk) {
                throw ("AppDir is not the staging build and its version ($appVersionText) " +
                       "does not match the candidate ($productVersionText). Install the candidate first.")
            }
            $result.appMatch = $true
            $result.appMatchMode = 'installed-version'
        }
    }

    $service = Get-CimInstance Win32_Service -Filter "Name='VerthysSecuritySvc'" -ErrorAction SilentlyContinue
    if ($null -eq $service) { throw 'VerthysSecuritySvc is not installed.' }
    if ("$($service.State)" -ne 'Running') {
        Start-Service -Name 'VerthysSecuritySvc'
        $deadline = (Get-Date).AddSeconds(30)
        while ((Get-Date) -lt $deadline) {
            $service = Get-CimInstance Win32_Service -Filter "Name='VerthysSecuritySvc'"
            if ("$($service.State)" -eq 'Running') { break }
            Start-Sleep -Milliseconds 500
        }
    }
    if ("$($service.State)" -ne 'Running') { throw 'VerthysSecuritySvc did not reach Running.' }
    $installedService = Get-ServiceImagePath -Service $service
    $result.serviceInstalledPath = $installedService
    Assert-CandidateFile $candidateService 'candidate service'
    Assert-ValidSignature $candidateService 'candidate service'
    $candidateHash = (Get-FileHash -LiteralPath $candidateService -Algorithm SHA256).Hash
    $installedHash = if (Test-Path -LiteralPath $installedService -PathType Leaf) {
        (Get-FileHash -LiteralPath $installedService -Algorithm SHA256).Hash
    } else { '' }
    $result.serviceHash = $installedHash
    $result.candidateServiceHash = $candidateHash
    $result.serviceMatch = ($installedHash -eq $candidateHash)
    if (-not $result.serviceMatch -and -not $SkipServiceMatch) {
        throw ("Installed service does not match the candidate. " +
               "installed=$installedHash candidate=$candidateHash. " +
               "Install the candidate before running the end-to-end test.")
    }

    if (-not (Test-Path -LiteralPath $workRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $workRoot -Force | Out-Null
    }
    & icacls.exe $workRoot /grant "$($currentUser):(OI)(CI)M" 2>&1 | Out-Null

    $driver = Get-Service -Name 'VerthysGuard' -ErrorAction SilentlyContinue
    if ($null -eq $driver) { throw 'VerthysGuard service is not installed.' }
    if ("$($driver.Status)" -ne 'Running') {
        if ($SkipStartDriver) { throw "VerthysGuard is $($driver.Status); start it or drop -SkipStartDriver." }
        if (-not (Start-Driver)) { throw 'VerthysGuard did not reach Running.' }
        $driverStartedByScript = $true
    }
    $result.driverStarted = $true
    Start-Sleep -Milliseconds 500

    $preProbe = Invoke-SystemProbe
    $result.preState = $preProbe
    $preState = [int](Get-JsonValue $preProbe 'state' -1)
    $preCount = [int](Get-JsonValue $preProbe 'protected_count' -1)
    if ($preCount -ne 0 -or ($preState -ne 0 -and $preState -ne 1)) {
        throw "Pre-session driver state is not clean: state=$preState count=$preCount. Close any running Verthys session and retry."
    }
    Write-Step "Driver ready: state=$preState count=$preCount"

    if ($PreflightOnly) {
        $result.status = if ($failures.Count -eq 0) { 'PREFLIGHT_PASS' } else { 'FAIL' }
    } else {
        $existingApp = Get-AppProcess -ExePath $appExe
        if ($null -ne $existingApp) {
            $appProcessId = $existingApp.Id
            Write-Step "Using running app: PID=$appProcessId"
        } elseif ($LaunchApp) {
            $appAction = New-ScheduledTaskAction -Execute $appExe -WorkingDirectory $AppDir
            $appPrincipal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Limited
            Remove-Task -Name $appTaskName -Stop
            Register-ScheduledTask -TaskName $appTaskName -Action $appAction -Principal $appPrincipal -Force | Out-Null
            Start-ScheduledTask -TaskName $appTaskName
            $deadline = (Get-Date).AddSeconds(40)
            while ((Get-Date) -lt $deadline) {
                $app = Get-AppProcess -ExePath $appExe
                if ($null -ne $app) { $appProcessId = $app.Id; break }
                Start-Sleep -Milliseconds 500
            }
            if ($appProcessId -eq 0) { throw 'Verthys.exe did not start from the candidate directory.' }
            Write-Step "App started: PID=$appProcessId"
        } else {
            throw "Verthys.exe is not running. Start it from $AppDir and unlock the vault, or pass -LaunchApp."
        }

        Write-Step "Unlock the vault in the app to spawn verthys-worker..."
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        $lastNotice = Get-Date
        $worker = $null
        while ((Get-Date) -lt $deadline) {
            $worker = Get-WorkerProcess
            if ($null -ne $worker) { break }
            $app = Get-AppProcess -ExePath $appExe
            if ($null -eq $app) { throw 'The app exited before the worker appeared.' }
            if (((Get-Date) - $lastNotice).TotalSeconds -ge 15) {
                Write-Step "Still waiting for the worker; unlock the vault in the app."
                $lastNotice = Get-Date
            }
            Start-Sleep -Milliseconds 800
        }
        if ($null -eq $worker) { throw "Worker did not appear within $TimeoutSeconds seconds." }
        $workerPid = [int]$worker.Id
        $workerPath = ''
        try { $workerPath = $worker.Path } catch { }
        $result.workerPid = $workerPid
        $result.workerPath = $workerPath
        $result.workerImage = Split-Path -Leaf $workerPath
        Write-Step "Worker found: PID=$workerPid image=$($result.workerImage)"

        $activeProbe = Wait-DriverState -DesiredState 2 -MinCount 1 -Seconds 30
        $result.activeState = $activeProbe
        $activeSeen = ([int](Get-JsonValue $activeProbe 'state' -1) -eq 2 -and
                       [int](Get-JsonValue $activeProbe 'protected_count' -1) -ge 1)
        if (-not $activeSeen) { throw 'Driver did not reach ACTIVE with one protected process.' }
        Write-Step "Driver ACTIVE: protected_count=$((Get-JsonValue $activeProbe 'protected_count' 0))"

        $accessProbeResult = Invoke-AccessProbe -ImageName $result.workerImage -TargetPid $workerPid
        $result.access = $accessProbeResult
        $accessStatus = [string](Get-JsonValue $accessProbeResult 'status' '')
        $accessPid = [int](Get-JsonValue $accessProbeResult 'pid' 0)
        $accessPassed = ($accessStatus -eq 'PASS' -and $accessPid -eq $workerPid)
        Write-Step "Same-user access: status=$accessStatus pid=$accessPid open=$((Get-JsonValue $accessProbeResult 'open_ok' $false)) op=$((Get-JsonValue $accessProbeResult 'op_ok' $false))"
        if (-not $accessPassed) { throw 'Same-user access probe did not observe the expected denial on the worker.' }

        if ($StopDriverAfterActive) {
            Write-Step 'Loss scenario requires the SECURE preset; stopping the driver now...'
            $lossWatch = [Diagnostics.Stopwatch]::StartNew()
            $lossStopOk = Stop-Driver
            if (-not $lossStopOk) { throw 'VerthysGuard did not stop within the timeout.' }
            $lossDeadline = (Get-Date).AddSeconds(20)
            while ((Get-Date) -lt $lossDeadline) {
                if ($null -eq (Get-Process -Id $workerPid -ErrorAction SilentlyContinue)) {
                    $lossWorkerExited = $true
                    break
                }
                Start-Sleep -Milliseconds 300
            }
            $lossWatch.Stop()
            $lossElapsedMs = [int]$lossWatch.ElapsedMilliseconds
            $result.loss = [ordered]@{
                driverStopped = $true
                workerExited = $lossWorkerExited
                elapsedMs = $lossElapsedMs
                uiLock = 'manual'
            }
            if (-not (Start-Driver)) { throw 'VerthysGuard did not restart after the loss scenario.' }
            if (-not $lossWorkerExited) { throw 'Worker did not exit after the driver was stopped (watchdog did not lock).' }
            Write-Step "Worker exited after driver loss in $lossElapsedMs ms"
            $recoverProbe = Invoke-SystemProbe
            $result.postState = $recoverProbe
            $postCountZero = ([int](Get-JsonValue $recoverProbe 'protected_count' -1) -eq 0)
            Write-Step "Driver restarted: state=$((Get-JsonValue $recoverProbe 'state' '')) count=$((Get-JsonValue $recoverProbe 'protected_count' ''))"
        } else {
            Write-Step 'Close the app to end the protected session (locking alone keeps the worker running).'
            $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
            while ((Get-Date) -lt $deadline) {
                if ($null -eq (Get-Process -Id $workerPid -ErrorAction SilentlyContinue)) { break }
                Start-Sleep -Milliseconds 500
            }
            if ($null -ne (Get-Process -Id $workerPid -ErrorAction SilentlyContinue)) {
                throw 'Worker is still running; lock the vault or close the app to continue.'
            }
            $postProbe = $null
            $deadline = (Get-Date).AddSeconds(20)
            while ((Get-Date) -lt $deadline) {
                $postProbe = Invoke-SystemProbe
                $count = [int](Get-JsonValue $postProbe 'protected_count' -1)
                if ($count -eq 0) { break }
                Start-Sleep -Milliseconds 1200
            }
            $result.postState = $postProbe
            $postCountZero = ([int](Get-JsonValue $postProbe 'protected_count' -1) -eq 0)
            Write-Step "Post-session state: state=$((Get-JsonValue $postProbe 'state' '')) count=$((Get-JsonValue $postProbe 'protected_count' ''))"
            if (-not $postCountZero) { throw 'Protected count did not return to zero after the session ended.' }
        }

        if ($activeSeen -and $accessPassed -and $postCountZero -and
            (-not $StopDriverAfterActive -or $lossWorkerExited)) {
            $result.status = 'PASS'
        }
    }
} catch {
    $failures.Add($_.Exception.Message)
    Write-Host "[e2e] FAILED: $($_.Exception.Message)"
} finally {
    Remove-Task -Name $probeTaskName -Stop
    Remove-Task -Name $accessTaskName -Stop
    Remove-Task -Name $appTaskName
    if ($driverStartedByScript -and -not $StopDriverAfterActive) {
        [void](Stop-Driver)
        $result.driverStarted = $false
    }
    if (-not $KeepWorkDir) {
        Remove-Item -LiteralPath $workRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    $result.finishedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    $result.appProcessId = $appProcessId
    $result.accessPassed = $accessPassed
    $result.postCountZero = $postCountZero
    $directory = Split-Path -Parent $OutputPath
    if (-not [string]::IsNullOrWhiteSpace($directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    $result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    Write-Host "E2E evidence: $OutputPath"
    Write-Host "E2E status: $($result.status)"
}

if ($result.status -eq 'PASS' -or $result.status -eq 'PREFLIGHT_PASS') { exit 0 }
exit 1
