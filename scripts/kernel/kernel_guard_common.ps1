# kernel_guard_common.ps1 - shared helpers for the VerthysGuard driver lifecycle
#
# This file is dot-sourced by install/upgrade/rollback/uninstall/gate scripts.
# It owns package integrity checks, path validation, SCM operations and the
# local transition journal. Output is ASCII only.
#
# Safety rules:
#   - Every destructive target must resolve under %ProgramFiles%.
#   - Package hashes must match driver.artifacts.json before any copy.
#   - A failed service operation never leaves a half-installed driver behind.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:DriverServiceName = 'VerthysGuard'
$script:DriverDisplayName = 'Verthys Kernel Guard'
$script:DriverManifestName = 'driver.artifacts.json'
$script:DriverStateName = 'kernel-guard-state.json'
$script:DriverAuditName = 'kernel-guard-audit.log'
$script:DriverFileNames = @('VerthysGuard.sys', 'VerthysGuard.inf', 'VerthysGuard.cat')

function Assert-KernelGuardAdmin {
    if (-not [Environment]::Is64BitProcess) {
        throw 'Run this script from 64-bit PowerShell; 32-bit PowerShell resolves the wrong Program Files.'
    }
    $principal = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This script must run elevated (Administrator).'
    }
}

function Get-KernelGuardRepoRoot {
    return (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}

# Locate sys/inf/cat recursively under the package directory; the WDK build
# keeps the catalog in a per-target subdirectory, so a flat listing is not
# guaranteed. The artifact manifest lives one level above the configuration
# directory in build_driver.
function Resolve-KernelGuardPackage {
    param(
        [string]$PackageDir,
        [string]$Configuration
    )
    if ([string]::IsNullOrWhiteSpace($PackageDir)) {
        $PackageDir = Join-Path (Get-KernelGuardRepoRoot) "build_driver\driver\$Configuration"
    }
    if (-not (Test-Path -LiteralPath $PackageDir -PathType Container)) {
        throw "Driver package directory not found: $PackageDir"
    }
    $resolved = (Resolve-Path -LiteralPath $PackageDir).Path

    $found = @{}
    foreach ($name in $script:DriverFileNames) {
        $match = Get-ChildItem -LiteralPath $resolved -Recurse -File -Filter $name |
            Sort-Object FullName | Select-Object -First 1
        if ($null -eq $match) {
            throw "Driver package is incomplete, missing: $name under $resolved"
        }
        $found[$name] = $match.FullName
    }

    $parent = Split-Path -Parent $resolved
    $grandParent = Split-Path -Parent $parent
    $manifestCandidates = @(
        (Join-Path $resolved $script:DriverManifestName),
        (Join-Path $parent $script:DriverManifestName)
    )
    if (-not [string]::IsNullOrWhiteSpace($grandParent)) {
        $manifestCandidates += (Join-Path $grandParent $script:DriverManifestName)
    }
    $manifestPath = $manifestCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($manifestPath)) {
        throw "Driver artifact manifest not found (expected $($script:DriverManifestName) near $resolved)"
    }

    return [pscustomobject]@{
        PackageDir   = $resolved
        SysPath      = $found['VerthysGuard.sys']
        InfPath      = $found['VerthysGuard.inf']
        CatPath      = $found['VerthysGuard.cat']
        ManifestPath = (Resolve-Path -LiteralPath $manifestPath).Path
    }
}

function Get-KernelGuardManifestValue {
    param($Manifest, [string]$Name)
    $property = $Manifest.PSObject.Properties[$Name]
    if ($null -eq $property) {
        throw "Driver manifest is missing required field: $Name"
    }
    return $property.Value
}

# Verify every package file against the build manifest. A mismatch means the
# package was modified after build and must not be installed.
function Assert-KernelGuardPackageIntegrity {
    param($Package)
    $manifest = Get-Content -LiteralPath $Package.ManifestPath -Raw | ConvertFrom-Json

    $checks = @(
        @{ File = $Package.SysPath; Expected = (Get-KernelGuardManifestValue $manifest 'sysSha256') },
        @{ File = $Package.CatPath; Expected = (Get-KernelGuardManifestValue $manifest 'catSha256') },
        @{ File = $Package.InfPath; Expected = (Get-KernelGuardManifestValue $manifest 'infSha256') }
    )
    foreach ($check in $checks) {
        $actual = (Get-FileHash -LiteralPath $check.File -Algorithm SHA256).Hash
        if ($actual -ne [string]$check.Expected) {
            throw "Package hash mismatch: $($check.File)"
        }
    }

    $protocolMajor = [int](Get-KernelGuardManifestValue $manifest 'protocolMajor')
    if ($protocolMajor -ne 1) {
        throw "Unsupported driver protocol major: $protocolMajor (expected 1)"
    }

    return $manifest
}

function Test-KernelGuardTestSigningEnabled {
    $output = & bcdedit.exe /enum '{current}' 2>&1 | Out-String
    return [bool]($output -match '(?im)^\s*testsigning\s+(Yes|On|是|开启|启用)\s*$')
}

function Test-KernelGuardSecureBootEnabled {
    $state = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' `
        -ErrorAction SilentlyContinue
    if ($null -eq $state) { return $false }
    return ([int]$state.UEFISecureBootEnabled -eq 1)
}

function Test-KernelGuardHvciEnabled {
    $guard = Get-CimInstance -ClassName Win32_DeviceGuard `
        -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    if ($null -eq $guard) { return $false }
    $running = @($guard.SecurityServicesRunning)
    return ($running -contains 2 -or [int]$guard.VirtualizationBasedSecurityStatus -eq 2)
}

function Test-KernelGuardTestCertificate {
    param($Signature)
    if ($null -eq $Signature -or $null -eq $Signature.SignerCertificate) {
        return $false
    }
    $subject = [string]$Signature.SignerCertificate.Subject
    $issuer = [string]$Signature.SignerCertificate.Issuer
    return ($subject -match 'WDKTestCert' -or $issuer -match 'WDKTestCert')
}

# Production packages must verify with a trusted chain. Test-signed packages
# are accepted only with explicit -AllowTestSigned, after verifying that the
# host can actually load them (TESTSIGNING on, Secure Boot/HVCI off).
# HashMismatch/Incompatible always fail: those statuses mean the signature no
# longer matches the binary, which is not a trust-policy question.
function Assert-KernelGuardSignature {
    param($Package, [switch]$AllowTestSigned)
    $sysSig = Get-AuthenticodeSignature -LiteralPath $Package.SysPath
    $catSig = Get-AuthenticodeSignature -LiteralPath $Package.CatPath
    $testCert = (Test-KernelGuardTestCertificate $sysSig) -or
        (Test-KernelGuardTestCertificate $catSig)

    if ($sysSig.Status -eq 'Valid' -and $catSig.Status -eq 'Valid' -and -not $testCert) {
        return 'Valid'
    }

    $hardFailures = @('HashMismatch', 'Incompatible')
    if ($hardFailures -contains $sysSig.Status -or $hardFailures -contains $catSig.Status) {
        throw "Driver signature is invalid: sys=$($sysSig.Status), cat=$($catSig.Status)"
    }

    if ($testCert -and -not $AllowTestSigned) {
        throw 'Driver is test-signed. Pass -AllowTestSigned only on a dedicated TESTSIGNING host.'
    }
    if (-not $AllowTestSigned) {
        throw "Driver signature is not trusted: sys=$($sysSig.Status), cat=$($catSig.Status). " +
            'Use -AllowTestSigned only on a TESTSIGNING test host.'
    }
    if (-not (Test-KernelGuardTestSigningEnabled)) {
        throw 'Package is not trusted and TESTSIGNING is not enabled; the kernel will reject the driver.'
    }
    if (Test-KernelGuardSecureBootEnabled) {
        throw 'Test-signed driver requires Secure Boot to be disabled.'
    }
    if (Test-KernelGuardHvciEnabled) {
        throw 'Test-signed driver requires HVCI/VBS to be disabled on this host.'
    }

    return "TestSigned(sys=$($sysSig.Status),cat=$($catSig.Status))"
}

# Resolve and constrain the install directory before any write or delete.
function Get-KernelGuardInstallDir {
    param([string]$InstallDir)
    if ([string]::IsNullOrWhiteSpace($InstallDir)) {
        $InstallDir = Join-Path $env:ProgramFiles 'Verthys\SecurityService\driver'
    }
    $full = [IO.Path]::GetFullPath($InstallDir)
    $programFiles = [IO.Path]::GetFullPath($env:ProgramFiles)
    $normalizedProgramFiles = $programFiles.TrimEnd('\')
    $normalizedFull = $full.TrimEnd('\')
    if ($normalizedFull -eq $normalizedProgramFiles) {
        throw "Refusing to use the Program Files root as the driver directory: $full"
    }
    if (-not $normalizedFull.StartsWith($normalizedProgramFiles + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Driver directory must stay under Program Files: $full"
    }
    return $normalizedFull
}

function Get-KernelGuardServiceState {
    $service = Get-Service -Name $script:DriverServiceName -ErrorAction SilentlyContinue
    if ($null -eq $service) { return 'MISSING' }
    if ($service.Status -eq 'Running') { return 'RUNNING' }
    if ($service.Status -eq 'Stopped') { return 'STOPPED' }
    return [string]$service.Status
}

# Guard against a name collision with a Win32 service: only a registered kernel
# driver may be stopped or deleted by these scripts.
function Test-KernelGuardDriverService {
    $driver = Get-CimInstance -ClassName Win32_SystemDriver `
        -Filter "Name='$($script:DriverServiceName)'" -ErrorAction SilentlyContinue
    return ($null -ne $driver)
}

function Stop-KernelGuardService {
    $state = Get-KernelGuardServiceState
    if ($state -eq 'MISSING' -or $state -eq 'STOPPED') { return }
    if (-not (Test-KernelGuardDriverService)) {
        throw "A service named $($script:DriverServiceName) exists but is not a kernel driver; refusing to stop it."
    }
    & sc.exe stop $script:DriverServiceName | Out-Null
    for ($i = 0; $i -lt 60; $i++) {
        Start-Sleep -Milliseconds 500
        $current = Get-KernelGuardServiceState
        if ($current -eq 'STOPPED' -or $current -eq 'MISSING') { return }
    }
    throw "Timed out waiting for driver service to stop (state=$current)"
}

function Remove-KernelGuardService {
    Stop-KernelGuardService
    if ((Get-KernelGuardServiceState) -eq 'MISSING') { return }
    if (-not (Test-KernelGuardDriverService)) {
        throw "A service named $($script:DriverServiceName) exists but is not a kernel driver; refusing to delete it."
    }
    $output = & sc.exe delete $script:DriverServiceName 2>&1 | Out-String
    $code = $LASTEXITCODE
    # 1072 = marked for deletion; the SCM will remove it once handles close.
    if ($code -ne 0 -and $code -ne 1072) {
        throw "Failed to delete driver service (exit $code): $($output.Trim())"
    }
    for ($i = 0; $i -lt 60; $i++) {
        if ((Get-KernelGuardServiceState) -eq 'MISSING') { return }
        Start-Sleep -Milliseconds 500
    }
    throw 'Timed out waiting for driver service deletion'
}

# Create the kernel service through sc.exe. Direct advapi32 CreateService
# produced an entry that StartService rejected with 1243 on Windows 11 22631,
# while the sc.exe-created entry with the same configuration started normally.
# The binary path is quoted as a whole because it contains spaces; the SCM
# stores the NT path without the quotes.
function New-KernelGuardService {
    param([string]$BinaryPath)
    $ntPath = '\??\' + $BinaryPath
    $arguments = 'create ' + $script:DriverServiceName +
        ' type= kernel start= demand error= normal binPath= "' + $ntPath +
        '" DisplayName= "' + $script:DriverDisplayName + '"'
    $process = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\sc.exe') `
        -ArgumentList $arguments -Wait -PassThru -NoNewWindow
    if ($process.ExitCode -ne 0) {
        throw "CreateService failed (sc.exe exit $($process.ExitCode))"
    }
}

function Start-KernelGuardService {
    $output = & sc.exe start $script:DriverServiceName 2>&1 | Out-String
    $code = $LASTEXITCODE
    if ($code -ne 0 -and (Get-KernelGuardServiceState) -ne 'RUNNING') {
        throw "Driver service failed to start (exit $code): $($output.Trim())"
    }
    for ($i = 0; $i -lt 60; $i++) {
        if ((Get-KernelGuardServiceState) -eq 'RUNNING') { return }
        Start-Sleep -Milliseconds 500
    }
    throw "Driver service did not reach RUNNING: $($output.Trim())"
}

# Copy package files with a rename step per file so a partial copy never
# leaves a truncated driver in place.
function Copy-KernelGuardPackage {
    param($Package, [string]$TargetDir)
    New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
    $map = @(
        @{ Source = $Package.SysPath; Name = 'VerthysGuard.sys' },
        @{ Source = $Package.InfPath; Name = 'VerthysGuard.inf' },
        @{ Source = $Package.CatPath; Name = 'VerthysGuard.cat' }
    )
    foreach ($item in $map) {
        $staged = Join-Path $TargetDir ($item.Name + '.new')
        $final = Join-Path $TargetDir $item.Name
        Copy-Item -LiteralPath $item.Source -Destination $staged -Force
        Move-Item -LiteralPath $staged -Destination $final -Force
    }
    Copy-Item -LiteralPath $Package.ManifestPath `
        -Destination (Join-Path $TargetDir $script:DriverManifestName) -Force
}

function Write-KernelGuardState {
    param(
        [string]$InstallDir,
        $Manifest,
        [string]$SignatureStatus,
        [string]$SourcePackage
    )
    $state = [ordered]@{
        product         = 'VerthysGuard'
        version         = [string]$Manifest.driverVersion
        protocol        = "$($Manifest.protocolMajor).$($Manifest.protocolMinor)"
        serviceName     = $script:DriverServiceName
        installDir      = $InstallDir
        sourcePackage   = $SourcePackage
        sysSha256       = (Get-FileHash -LiteralPath (Join-Path $InstallDir 'VerthysGuard.sys') -Algorithm SHA256).Hash
        catSha256       = (Get-FileHash -LiteralPath (Join-Path $InstallDir 'VerthysGuard.cat') -Algorithm SHA256).Hash
        infSha256       = (Get-FileHash -LiteralPath (Join-Path $InstallDir 'VerthysGuard.inf') -Algorithm SHA256).Hash
        signatureStatus = $SignatureStatus
        updatedAtUtc    = (Get-Date).ToUniversalTime().ToString('o')
    }
    $path = Join-Path $InstallDir $script:DriverStateName
    $staged = $path + '.new'
    $state | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $staged -Encoding UTF8
    Move-Item -LiteralPath $staged -Destination $path -Force
}

function Write-KernelGuardAudit {
    param(
        [string]$InstallDir,
        [string]$Action,
        [string]$Result,
        [string]$Detail
    )
    if ([string]::IsNullOrWhiteSpace($InstallDir) -or -not (Test-Path -LiteralPath $InstallDir)) {
        return
    }
    $entry = [ordered]@{
        timestamp = (Get-Date).ToUniversalTime().ToString('o')
        action    = $Action
        result    = $Result
        detail    = $Detail
        user      = [Environment]::UserName
    }
    Add-Content -LiteralPath (Join-Path $InstallDir $script:DriverAuditName) `
        -Value ($entry | ConvertTo-Json -Compress) -Encoding UTF8
}

function Backup-KernelGuardInstall {
    param([string]$InstallDir)
    $state = Join-Path $InstallDir $script:DriverStateName
    if (-not (Test-Path -LiteralPath $state -PathType Leaf)) {
        throw "Cannot back up, install state is missing: $state"
    }
    $current = Get-Content -LiteralPath $state -Raw | ConvertFrom-Json

    # A partially replaced package must not be treated as a rollback baseline:
    # verify the files on disk still match the state that describes them.
    $hashChecks = @(
        @{ Name = 'VerthysGuard.sys'; Expected = [string]$current.sysSha256 },
        @{ Name = 'VerthysGuard.cat'; Expected = [string]$current.catSha256 },
        @{ Name = 'VerthysGuard.inf'; Expected = [string]$current.infSha256 }
    )
    foreach ($check in $hashChecks) {
        $path = Join-Path $InstallDir $check.Name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Cannot back up, current package is incomplete: $path"
        }
        $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        if ($actual -ne $check.Expected) {
            throw "Current install is inconsistent ($($check.Name)); run rollback or uninstall first."
        }
    }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
    $snapshotDir = Join-Path $InstallDir "rollback\$stamp"
    New-Item -ItemType Directory -Path $snapshotDir -Force | Out-Null
    foreach ($name in $script:DriverFileNames) {
        Copy-Item -LiteralPath (Join-Path $InstallDir $name) `
            -Destination (Join-Path $snapshotDir $name) -Force
    }
    Copy-Item -LiteralPath $state -Destination (Join-Path $snapshotDir $script:DriverStateName) -Force
    return $snapshotDir
}

function Get-KernelGuardSnapshots {
    param([string]$InstallDir)
    $root = Join-Path $InstallDir 'rollback'
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { return @() }
    return @(Get-ChildItem -LiteralPath $root -Directory | Sort-Object Name -Descending)
}

function Restore-KernelGuardSnapshot {
    param([string]$SnapshotDir, [string]$InstallDir)
    # Validate the snapshot as a whole before touching the live package; a
    # partial restore would leave the service pointing at a mixed file set.
    foreach ($name in $script:DriverFileNames) {
        $source = Join-Path $SnapshotDir $name
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "Snapshot is incomplete, missing: $source"
        }
    }
    $state = Join-Path $SnapshotDir $script:DriverStateName
    if (-not (Test-Path -LiteralPath $state -PathType Leaf)) {
        throw "Snapshot is missing install state: $state"
    }

    foreach ($name in $script:DriverFileNames) {
        $staged = Join-Path $InstallDir ($name + '.restore')
        Copy-Item -LiteralPath (Join-Path $SnapshotDir $name) -Destination $staged -Force
        Move-Item -LiteralPath $staged -Destination (Join-Path $InstallDir $name) -Force
    }
    Copy-Item -LiteralPath $state -Destination (Join-Path $InstallDir $script:DriverStateName) -Force
}
