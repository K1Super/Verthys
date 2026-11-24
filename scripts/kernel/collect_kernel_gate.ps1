# collect_kernel_gate.ps1 - collect VerthysGuard release-gate evidence
#
# Usage (elevated, on the target VM):
#   pwsh -NoProfile -File scripts\kernel\collect_kernel_gate.ps1
#   pwsh -NoProfile -File scripts\kernel\collect_kernel_gate.ps1 -OutputPath C:\gate\kernel.json
#
# This script does not load the driver and does not run attack cases. It
# records the environment, package and service facts required by the release
# gate, and exits non-zero when the recorded state cannot pass. Attack
# regression results must be appended by the VM operator; the pending case
# list makes missing evidence explicit.

param(
    [string]$InstallDir = '',
    [string]$OutputPath = ''
)

. "$PSScriptRoot\kernel_guard_common.ps1"

Assert-KernelGuardAdmin

$target = Get-KernelGuardInstallDir -InstallDir $InstallDir
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path (Get-KernelGuardRepoRoot) 'build_driver\kernel-gate.json'
}
$outputFull = [IO.Path]::GetFullPath($OutputPath)

$checks = New-Object System.Collections.Generic.List[object]
function Add-GateCheck {
    param([string]$Name, [bool]$Ok, [string]$Detail)
    $checks.Add([pscustomobject]@{ name = $Name; ok = $Ok; detail = $Detail })
}

$os = Get-CimInstance -ClassName Win32_OperatingSystem
$testSigning = Test-KernelGuardTestSigningEnabled

$secureBoot = $null
try {
    $secureBoot = [bool](Confirm-SecureBootUEFI)
}
catch {
    $secureBoot = $null
}

$hvciRunning = $null
$hvciEnabled = $null
try {
    $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard `
        -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
    $hvciRunning = [bool]($deviceGuard.SecurityServicesRunning -contains 2)
    $hvciEnabled = [bool]($deviceGuard.SecurityServicesConfigured -contains 2)
}
catch {
    $hvciRunning = $null
    $hvciEnabled = $null
}

$serviceState = Get-KernelGuardServiceState
$statePath = Join-Path $target $script:DriverStateName
$stateFilePresent = Test-Path -LiteralPath $statePath -PathType Leaf
$installed = $stateFilePresent

$state = $null
$stateParseError = $null
if ($stateFilePresent) {
    try {
        $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    }
    catch {
        $stateParseError = $_.Exception.Message
    }
}

$sysPath = Join-Path $target 'VerthysGuard.sys'
$catPath = Join-Path $target 'VerthysGuard.cat'
$sysPresent = Test-Path -LiteralPath $sysPath -PathType Leaf
$catPresent = Test-Path -LiteralPath $catPath -PathType Leaf

$sysSignature = $null
$catSignature = $null
$sysSha256 = $null
$catSha256 = $null
if ($sysPresent) {
    $sysSignature = [string](Get-AuthenticodeSignature -LiteralPath $sysPath).Status
    $sysSha256 = (Get-FileHash -LiteralPath $sysPath -Algorithm SHA256).Hash
}
if ($catPresent) {
    $catSignature = [string](Get-AuthenticodeSignature -LiteralPath $catPath).Status
    $catSha256 = (Get-FileHash -LiteralPath $catPath -Algorithm SHA256).Hash
}

$signatureTrusted = ($sysSignature -eq 'Valid' -and $catSignature -eq 'Valid')
$signatureHardFailures = @('HashMismatch', 'Incompatible')
$signatureUsable = $signatureTrusted -or
    ($testSigning -and $null -ne $sysSignature -and
        $signatureHardFailures -notcontains $sysSignature)

Add-GateCheck -Name 'installed' -Ok $installed -Detail "stateFile=$stateFilePresent"
Add-GateCheck -Name 'service-running' -Ok ($serviceState -eq 'RUNNING') -Detail "state=$serviceState"
Add-GateCheck -Name 'package-files' -Ok ($sysPresent -and $catPresent) `
    -Detail "sys=$sysPresent cat=$catPresent"
Add-GateCheck -Name 'signature-usable' -Ok $signatureUsable `
    -Detail "sys=$sysSignature cat=$catSignature testsigning=$testSigning"
Add-GateCheck -Name 'secure-boot-vs-testsigning' `
    -Ok (-not ($secureBoot -eq $true -and $testSigning)) `
    -Detail "secureBoot=$secureBoot testsigning=$testSigning"
Add-GateCheck -Name 'hvci-vs-signature' `
    -Ok (-not ($hvciRunning -eq $true -and -not $signatureTrusted)) `
    -Detail "hvciRunning=$hvciRunning signatureTrusted=$signatureTrusted"

if ($installed -and $null -ne $state) {
    Add-GateCheck -Name 'state-hash-sys' -Ok ($state.sysSha256 -eq $sysSha256) `
        -Detail "state=$($state.sysSha256) actual=$sysSha256"
    Add-GateCheck -Name 'state-hash-cat' -Ok ($state.catSha256 -eq $catSha256) `
        -Detail "state=$($state.catSha256) actual=$catSha256"
}
elseif ($stateFilePresent) {
    Add-GateCheck -Name 'state-parse' -Ok $false -Detail ([string]$stateParseError)
}

$failed = @($checks | Where-Object { -not $_.ok })
if (-not $installed) {
    $result = 'BLOCKED'
}
elseif ($failed.Count -eq 0) {
    $result = 'PASS'
}
else {
    $result = 'FAIL'
}

$driverVersion = $null
$driverProtocol = $null
$driverSignatureStatus = $null
if ($installed -and $null -ne $state) {
    $driverVersion = [string]$state.version
    $driverProtocol = [string]$state.protocol
    $driverSignatureStatus = [string]$state.signatureStatus
}

$evidence = [ordered]@{
    collectedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    computer       = [Environment]::MachineName
    os             = [ordered]@{
        caption = [string]$os.Caption
        version = [string]$os.Version
        build   = [string]$os.BuildNumber
    }
    environment    = [ordered]@{
        secureBoot  = $secureBoot
        testSigning = $testSigning
        hvciRunning = $hvciRunning
        hvciEnabled = $hvciEnabled
    }
    driver         = [ordered]@{
        installed       = $installed
        serviceState    = $serviceState
        installDir      = $target
        version         = $driverVersion
        protocol        = $driverProtocol
        signatureStatus = $driverSignatureStatus
        sysSha256       = $sysSha256
        catSha256       = $catSha256
        sysSignature    = $sysSignature
        catSignature    = $catSignature
    }
    gate           = [ordered]@{
        result  = $result
        checks  = $checks
        pending = @(
            'state machine S1/S5/S6/S10',
            'Driver Verifier, 1000 load/unload and 72-hour stability (P5/P6)',
            'service/application end-to-end (host pre-ARM, REGISTER, LOST lock)',
            'HVCI + production-signed driver (C4)'
        )
    }
}

$directory = Split-Path -Parent $outputFull
if (-not [string]::IsNullOrWhiteSpace($directory)) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
}
$evidence | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $outputFull -Encoding UTF8
Write-Host "Gate evidence: $outputFull"
Write-Host "Gate result  : $result"

if ($result -eq 'FAIL') { exit 1 }
if ($result -eq 'BLOCKED') { exit 2 }
exit 0
