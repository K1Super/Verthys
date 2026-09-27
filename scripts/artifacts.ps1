# artifacts.ps1 - shared build-artifact contract reader
#
# Single source of truth for locating the built C core DLL.
# The C core build (CMake POST_BUILD) writes a machine-readable contract to
#   <repo>\build\core\verthys.artifacts.json
# containing the DLL path relative to the repo root plus its SHA-256.
# Consumers (build scripts, dev launcher) read this contract instead of
# guessing generator-specific output layouts (Ninja single-config outputs
# build\core\verthys.dll; Visual Studio multi-config outputs
# build\core\Release\verthys.dll). Guessing wrong previously degraded the
# DLL integrity hash to None and broke the material gates.
#
# Note: keep this file ASCII-only (no localized characters) so PowerShell 5.1
# parses it under any ANSI code page.

$script:ArtifactsRepoRoot = Split-Path -Parent $PSScriptRoot
$script:ArtifactsManifestPath = Join-Path $script:ArtifactsRepoRoot "build\core\verthys.artifacts.json"

# Reads the artifact contract and returns its parsed object.
# Throws with an actionable message when the contract is missing or malformed.
function Get-VerthysArtifactManifest {
    if (-not (Test-Path $script:ArtifactsManifestPath)) {
        throw "artifact contract missing: $($script:ArtifactsManifestPath). Build the C core first (run build_production.ps1 without -SkipCore)."
    }
    $raw = Get-Content $script:ArtifactsManifestPath -Raw -ErrorAction Stop
    $m = $raw | ConvertFrom-Json -ErrorAction Stop
    if ($null -eq $m -or [string]::IsNullOrEmpty($m.dll) -or [string]::IsNullOrEmpty($m.sha256)) {
        throw "artifact contract malformed: $($script:ArtifactsManifestPath)"
    }
    return $m
}

# Returns the absolute path of the built DLL recorded in the contract.
# Verifies the file exists (contract regenerates on every core link, so a
# missing file means the build tree was cleaned after contract generation).
function Get-VerthysArtifactDll {
    $m = Get-VerthysArtifactManifest
    $dllPath = Join-Path $script:ArtifactsRepoRoot ($m.dll -replace '/', '\')
    if (-not (Test-Path $dllPath)) {
        throw "artifact DLL missing: $dllPath. Rebuild the C core (this refreshes the contract)."
    }
    return $dllPath
}