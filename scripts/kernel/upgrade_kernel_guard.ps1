# upgrade_kernel_guard.ps1 - replace an installed VerthysGuard package
#
# Usage (elevated):
#   pwsh -NoProfile -File scripts\kernel\upgrade_kernel_guard.ps1
#   pwsh -NoProfile -File scripts\kernel\upgrade_kernel_guard.ps1 -AllowTestSigned
#
# Flow: verify new package -> snapshot current files -> stop -> replace ->
# recreate service -> start. Any failure restores the snapshot and restarts
# the previous package. A failed rollback is reported explicitly; it is never
# hidden behind a success exit code.

param(
    [string]$PackageDir = '',
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [string]$InstallDir = '',
    [switch]$AllowTestSigned,
    [switch]$SkipStart,
    [switch]$DryRun
)

. "$PSScriptRoot\kernel_guard_common.ps1"

Assert-KernelGuardAdmin

$package = Resolve-KernelGuardPackage -PackageDir $PackageDir -Configuration $Configuration
$manifest = Assert-KernelGuardPackageIntegrity -Package $package
$signature = Assert-KernelGuardSignature -Package $package -AllowTestSigned:$AllowTestSigned
$target = Get-KernelGuardInstallDir -InstallDir $InstallDir

$statePath = Join-Path $target $script:DriverStateName
if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
    throw "No installed package found under $target. Run install_kernel_guard.ps1 first."
}

Write-Host "Package : $($package.PackageDir)"
Write-Host "Version : $($manifest.driverVersion)"
Write-Host "Protocol: $($manifest.protocolMajor).$($manifest.protocolMinor)"
Write-Host "Target  : $target"
Write-Host "Signature: $signature"

if ($DryRun) {
    Write-Host 'Dry run complete; nothing was changed.'
    exit 0
}

$snapshot = Backup-KernelGuardInstall -InstallDir $target
Write-Host "Current package snapshot: $snapshot"

$failure = $null
try {
    Stop-KernelGuardService
    Copy-KernelGuardPackage -Package $package -TargetDir $target
    Remove-KernelGuardService
    New-KernelGuardService -BinaryPath (Join-Path $target 'VerthysGuard.sys')
    if (-not $SkipStart) {
        Start-KernelGuardService
    }
    Write-KernelGuardState -InstallDir $target -Manifest $manifest `
        -SignatureStatus $signature -SourcePackage $package.PackageDir
    Write-KernelGuardAudit -InstallDir $target -Action 'upgrade' -Result 'success' `
        -Detail "version=$($manifest.driverVersion) signature=$signature snapshot=$snapshot"
}
catch {
    $failure = $_.Exception.Message
}

if ($null -ne $failure) {
    Write-KernelGuardAudit -InstallDir $target -Action 'upgrade' -Result 'failure' -Detail $failure
    try {
        Stop-KernelGuardService
        Remove-KernelGuardService
        Restore-KernelGuardSnapshot -SnapshotDir $snapshot -InstallDir $target
        New-KernelGuardService -BinaryPath (Join-Path $target 'VerthysGuard.sys')
        if (-not $SkipStart) {
            Start-KernelGuardService
        }
        Write-KernelGuardAudit -InstallDir $target -Action 'upgrade-rollback' `
            -Result 'success' -Detail "restored=$snapshot reason=$failure"
    }
    catch {
        $rollbackReason = $_.Exception.Message
        Write-KernelGuardAudit -InstallDir $target -Action 'upgrade-rollback' `
            -Result 'failure' -Detail "reason=$failure rollback=$rollbackReason"
        throw "Upgrade failed and automatic rollback failed. Manual intervention required. " +
            "Upgrade error: $failure. Rollback error: $rollbackReason"
    }
    throw "Upgrade failed; the previous package was restored. Reason: $failure"
}

$state = Get-KernelGuardServiceState
Write-Host "VerthysGuard upgraded (service state: $state)."
if ($signature -like 'TestSigned*') {
    Write-Warning 'Test-signed package installed. This host must keep TESTSIGNING enabled; do not distribute this package.'
}
