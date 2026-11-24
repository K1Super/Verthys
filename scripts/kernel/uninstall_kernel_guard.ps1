# uninstall_kernel_guard.ps1 - remove the VerthysGuard service and driver files
#
# Usage (elevated):
#   pwsh -NoProfile -File scripts\kernel\uninstall_kernel_guard.ps1
#
# Removes only the kernel driver service and the driver package directory.
# User containers, P2 security state and presets are never touched.

param(
    [string]$InstallDir = ''
)

. "$PSScriptRoot\kernel_guard_common.ps1"

Assert-KernelGuardAdmin

$target = Get-KernelGuardInstallDir -InstallDir $InstallDir
$serviceState = Get-KernelGuardServiceState

Write-Host "Target  : $target"
Write-Host "Service : $serviceState"

if ($serviceState -ne 'MISSING') {
    Write-KernelGuardAudit -InstallDir $target -Action 'uninstall' -Result 'begin' `
        -Detail "service=$serviceState"
}
Remove-KernelGuardService

foreach ($name in $script:DriverFileNames) {
    $file = Join-Path $target $name
    if (Test-Path -LiteralPath $file) {
        Remove-Item -LiteralPath $file -Force
    }
}
foreach ($name in @($script:DriverManifestName, $script:DriverStateName)) {
    $file = Join-Path $target $name
    if (Test-Path -LiteralPath $file) {
        Remove-Item -LiteralPath $file -Force
    }
}

$rollbackRoot = Join-Path $target 'rollback'
if (Test-Path -LiteralPath $rollbackRoot -PathType Container) {
    $resolvedRollback = (Resolve-Path -LiteralPath $rollbackRoot).Path
    if (-not $resolvedRollback.StartsWith($target + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove rollback directory outside the install target: $resolvedRollback"
    }
    Remove-Item -LiteralPath $resolvedRollback -Recurse -Force
}

$audit = Join-Path $target $script:DriverAuditName
if (Test-Path -LiteralPath $audit) {
    Remove-Item -LiteralPath $audit -Force
}

if ((Test-Path -LiteralPath $target -PathType Container) -and
    -not (Get-ChildItem -LiteralPath $target -Force | Select-Object -First 1)) {
    Remove-Item -LiteralPath $target -Force
}

$remaining = Get-KernelGuardServiceState
if ($remaining -ne 'MISSING') {
    throw "Driver service still present after uninstall: $remaining"
}

Write-Host 'VerthysGuard uninstalled; driver service and package files removed.'
