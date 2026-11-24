# rollback_kernel_guard.ps1 - restore a previous VerthysGuard package snapshot
#
# Usage (elevated):
#   pwsh -NoProfile -File scripts\kernel\rollback_kernel_guard.ps1
#   pwsh -NoProfile -File scripts\kernel\rollback_kernel_guard.ps1 -Snapshot 20261122-101010-123
#
# The current package is snapshotted before the restore, so a rollback can be
# undone by running the script again with that new snapshot name.

param(
    [string]$InstallDir = '',
    [string]$Snapshot = '',
    [switch]$SkipStart
)

. "$PSScriptRoot\kernel_guard_common.ps1"

Assert-KernelGuardAdmin

$target = Get-KernelGuardInstallDir -InstallDir $InstallDir
$snapshots = @(Get-KernelGuardSnapshots -InstallDir $target)
if ($snapshots.Count -eq 0) {
    throw "No rollback snapshot found under $target. Nothing to restore."
}

if ([string]::IsNullOrWhiteSpace($Snapshot)) {
    $selected = $snapshots[0]
}
else {
    $rollbackRoot = (Resolve-Path -LiteralPath (Join-Path $target 'rollback')).Path
    $candidate = Join-Path $rollbackRoot $Snapshot
    if (-not (Test-Path -LiteralPath $candidate -PathType Container)) {
        throw "Snapshot not found: $candidate"
    }
    $selected = Get-Item -LiteralPath $candidate
    if (-not $selected.FullName.StartsWith($rollbackRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to restore outside the rollback root: $($selected.FullName)"
    }
}

if (-not (Test-Path -LiteralPath (Join-Path $target $script:DriverStateName) -PathType Leaf)) {
    throw "No installed package state found under $target. Nothing to roll back from."
}

Write-Host "Restoring snapshot: $($selected.FullName)"

$preRollback = Backup-KernelGuardInstall -InstallDir $target
Write-Host "Current package snapshot: $preRollback"

$failure = $null
try {
    Stop-KernelGuardService
    Restore-KernelGuardSnapshot -SnapshotDir $selected.FullName -InstallDir $target
    Remove-KernelGuardService
    New-KernelGuardService -BinaryPath (Join-Path $target 'VerthysGuard.sys')
    if (-not $SkipStart) {
        Start-KernelGuardService
    }
    Write-KernelGuardAudit -InstallDir $target -Action 'rollback' -Result 'success' `
        -Detail "restored=$($selected.Name) current=$preRollback"
}
catch {
    $failure = $_.Exception.Message
}

if ($null -ne $failure) {
    Write-KernelGuardAudit -InstallDir $target -Action 'rollback' -Result 'failure' -Detail $failure
    try {
        Stop-KernelGuardService
        Remove-KernelGuardService
        Restore-KernelGuardSnapshot -SnapshotDir $preRollback -InstallDir $target
        New-KernelGuardService -BinaryPath (Join-Path $target 'VerthysGuard.sys')
        if (-not $SkipStart) {
            Start-KernelGuardService
        }
        Write-KernelGuardAudit -InstallDir $target -Action 'rollback-undo' `
            -Result 'success' -Detail "restored=$preRollback reason=$failure"
    }
    catch {
        $undoReason = $_.Exception.Message
        Write-KernelGuardAudit -InstallDir $target -Action 'rollback-undo' `
            -Result 'failure' -Detail "reason=$failure undo=$undoReason"
        throw "Rollback failed and the pre-rollback package could not be restored. " +
            "Manual intervention required. Rollback error: $failure. Undo error: $undoReason"
    }
    throw "Rollback failed; the pre-rollback package was restored. Reason: $failure"
}

$state = Get-KernelGuardServiceState
Write-Host "VerthysGuard rolled back (service state: $state)."
