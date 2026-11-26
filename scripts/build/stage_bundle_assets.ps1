# scripts/build/stage_bundle_assets.ps1 - single producer for packaging assets
#
# ASCII only: Windows PowerShell 5.1 decodes BOM-less files with the ANSI code
# page, so localized text can break parsing.
#
# Copies verthys.dll and the worker sidecar into the Tauri packaging paths,
# optionally syncs the Tauri target directories used at runtime, verifies byte
# identity, and writes the bundle manifest consumed by the Rust build gate.
# Every producer (production build, dev runtime, CI jobs) calls this script so
# the staging paths, hashes, and manifest can never diverge.
#
# Channel semantics:
#   dev        - dev-signed DLL / dev worker, contract under build_dev/
#   production - release-signed DLL / release worker, contract under build/
#
# Exit code is non-zero on any verification failure.

param(
    [Parameter(Mandatory = $true)][ValidateSet("dev", "production")][string]$Channel,
    [Parameter(Mandatory = $true)][string]$DllSource,
    [Parameter(Mandatory = $true)][string]$WorkerSource,
    [Parameter(Mandatory = $true)][string]$ContractPath,
    [Parameter(Mandatory = $true)][string]$Producer,
    [ValidateSet("none", "dev", "production")][string]$SyncTargets = "none",
    [string]$WorkerDebugSource = "",
    [string]$RepoRoot = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrEmpty($RepoRoot)) {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
}
$repoFull = [System.IO.Path]::GetFullPath($RepoRoot).TrimEnd('\')

. (Join-Path $repoFull "scripts\lib\artifacts.ps1")

$srcTauri = Join-Path $repoFull "verthys-tauri\src-tauri"
$binariesDir = Join-Path $srcTauri "binaries"
$stagedDll = Join-Path $srcTauri "verthys.dll"
$stagedWorker = Join-Path $binariesDir "verthys-worker-x86_64-pc-windows-msvc.exe"

foreach ($required in @($DllSource, $WorkerSource, $ContractPath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "staging source missing: $required"
    }
}
foreach ($dir in @($srcTauri, $binariesDir)) {
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Copy-VerifiedFile {
    param([string]$Source, [string]$Destination)

    $sourceHash = Get-Sha256 $Source
    if (Test-Path -LiteralPath $Destination -PathType Leaf) {
        if ((Get-Sha256 $Destination) -eq $sourceHash) {
            return $sourceHash
        }
    }

    for ($attempt = 0; $attempt -lt 10; $attempt++) {
        try {
            Copy-Item -LiteralPath $Source -Destination $Destination -Force -ErrorAction Stop
            break
        } catch {
            if ($attempt -eq 9) {
                throw ("failed to stage {0} -> {1}: {2}" -f $Source, $Destination, $_.Exception.Message)
            }
            Start-Sleep -Milliseconds 300
        }
    }

    if ((Get-Sha256 $Destination) -ne $sourceHash) {
        throw ("staged file hash mismatch: {0}" -f $Destination)
    }
    return $sourceHash
}

$dllHash = Copy-VerifiedFile -Source $DllSource -Destination $stagedDll
$workerHash = Copy-VerifiedFile -Source $WorkerSource -Destination $stagedWorker

if ($SyncTargets -eq "dev") {
    $debugDir = Join-Path $srcTauri "target\debug"
    if (-not (Test-Path -LiteralPath $debugDir)) {
        New-Item -ItemType Directory -Path $debugDir -Force | Out-Null
    }
    $null = Copy-VerifiedFile -Source $DllSource -Destination (Join-Path $debugDir "verthys.dll")
    $null = Copy-VerifiedFile -Source $WorkerSource -Destination (Join-Path $debugDir "verthys-worker.exe")
} elseif ($SyncTargets -eq "production") {
    $releaseDir = Join-Path $srcTauri "target\release"
    $debugDir = Join-Path $srcTauri "target\debug"
    if (Test-Path -LiteralPath $releaseDir) {
        $null = Copy-VerifiedFile -Source $WorkerSource -Destination (Join-Path $releaseDir "verthys-worker.exe")
    }
    if (Test-Path -LiteralPath $debugDir) {
        $debugSource = $WorkerSource
        if (-not [string]::IsNullOrEmpty($WorkerDebugSource) -and
            (Test-Path -LiteralPath $WorkerDebugSource -PathType Leaf)) {
            $debugSource = $WorkerDebugSource
        }
        $null = Copy-VerifiedFile -Source $debugSource -Destination (Join-Path $debugDir "verthys-worker.exe")
    }
}

$manifest = Write-VerthysBundleManifest `
    -Channel $Channel `
    -DllPath $stagedDll `
    -DllSource $DllSource `
    -WorkerPath $stagedWorker `
    -WorkerSource $WorkerSource `
    -ContractPath $ContractPath `
    -WorkerDllSha256 $dllHash `
    -WorkerSha256 $workerHash `
    -Producer $Producer `
    -RepoRoot $repoFull

Write-Host ("[stage] channel={0} dll={1} worker={2} targets={3}" -f `
    $Channel, $dllHash.Substring(0, 12), $workerHash.Substring(0, 12), $SyncTargets)

return [pscustomobject]@{
    Channel      = $Channel
    DllPath      = $stagedDll
    WorkerPath   = $stagedWorker
    DllSha256    = $dllHash
    WorkerSha256 = $workerHash
    Manifest     = $manifest
}
