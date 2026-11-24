# install_kernel_guard.ps1 - install VerthysGuard as a demand-start kernel service
#
# Usage (elevated):
#   pwsh -NoProfile -File scripts\kernel\install_kernel_guard.ps1
#   pwsh -NoProfile -File scripts\kernel\install_kernel_guard.ps1 -AllowTestSigned
#
# Refuses to overwrite an existing installation. Use upgrade_kernel_guard.ps1
# for replacement and uninstall_kernel_guard.ps1 to remove it.

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

Write-Host "Package : $($package.PackageDir)"
Write-Host "Version : $($manifest.driverVersion)"
Write-Host "Protocol: $($manifest.protocolMajor).$($manifest.protocolMinor)"
Write-Host "Target  : $target"
Write-Host "Signature: $signature"

if ($DryRun) {
    Write-Host 'Dry run complete; nothing was changed.'
    exit 0
}

if ((Get-KernelGuardServiceState) -ne 'MISSING') {
    throw 'VerthysGuard service already exists. Use upgrade_kernel_guard.ps1 or uninstall it first.'
}
if (Test-Path -LiteralPath (Join-Path $target $script:DriverStateName)) {
    throw "Existing install state found under $target. Use upgrade or uninstall first."
}
foreach ($name in $script:DriverFileNames) {
    if (Test-Path -LiteralPath (Join-Path $target $name)) {
        throw "Existing driver file found: $(Join-Path $target $name). Use uninstall first."
    }
}

$createdFiles = @()
foreach ($name in $script:DriverFileNames) {
    $createdFiles += (Join-Path $target $name)
}
$createdFiles += (Join-Path $target $script:DriverManifestName)

try {
    Copy-KernelGuardPackage -Package $package -TargetDir $target

    New-KernelGuardService -BinaryPath (Join-Path $target 'VerthysGuard.sys')
    if (-not $SkipStart) {
        Start-KernelGuardService
    }

    Write-KernelGuardState -InstallDir $target -Manifest $manifest `
        -SignatureStatus $signature -SourcePackage $package.PackageDir
    Write-KernelGuardAudit -InstallDir $target -Action 'install' -Result 'success' `
        -Detail "version=$($manifest.driverVersion) signature=$signature"
}
catch {
    $reason = $_.Exception.Message
    try {
        Stop-KernelGuardService
        Remove-KernelGuardService
    }
    catch {
        $reason = "$reason | service cleanup failed: $($_.Exception.Message)"
    }
    foreach ($file in $createdFiles) {
        if (Test-Path -LiteralPath $file) {
            Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
        }
    }
    foreach ($staged in Get-ChildItem -LiteralPath $target -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like '*.new' }) {
        Remove-Item -LiteralPath $staged.FullName -Force -ErrorAction SilentlyContinue
    }
    Write-KernelGuardAudit -InstallDir $target -Action 'install' -Result 'failure' -Detail $reason
    throw "VerthysGuard installation failed: $reason"
}

$state = Get-KernelGuardServiceState
Write-Host "VerthysGuard installed (service state: $state)."
if ($signature -like 'TestSigned*') {
    Write-Warning 'Test-signed package installed. This host must keep TESTSIGNING enabled; do not distribute this package.'
}
