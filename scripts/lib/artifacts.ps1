# scripts/lib/artifacts.ps1 - shared build-artifact contract reader/writer
#
# Single source of truth for locating the built C core DLL (Get-*) and for
# refreshing the contract from the final on-disk bytes after post-link
# mutations such as the .vsec baseline injection (Write-*).
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

$script:ArtifactsRepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
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

# Regenerates the artifact contract from the final on-disk DLL bytes.
#
# Call after any post-link mutation of the DLL (the .vsec baseline injection
# rewrites section bytes) because the CMake POST_BUILD contract is written
# before that mutation. The regenerated contract is verified against the
# actual file so a stale or mismatched hash can never reach a consumer.
#
# Version and fmt_version are read from their single sources of truth:
#   <repo>\VERSION and core\CMakeLists.txt (VERTHYS_FMT_VERSION).
function Write-VerthysArtifactContract {
    param(
        [Parameter(Mandatory = $true)][string]$DllPath,
        [Parameter(Mandatory = $true)][string]$CmakeExe,
        [Parameter(Mandatory = $true)][string]$Generator,
        [Parameter(Mandatory = $true)][string]$Config,
        [Parameter(Mandatory = $true)][string]$SourceDir,
        [string]$OutPath = ""
    )

    if (-not (Test-Path -LiteralPath $DllPath -PathType Leaf)) {
        throw "artifact DLL missing: $DllPath"
    }
    if (-not (Test-Path -LiteralPath $CmakeExe -PathType Leaf)) {
        throw "cmake executable missing: $CmakeExe"
    }

    $versionSrc = Join-Path $SourceDir "VERSION"
    if (-not (Test-Path -LiteralPath $versionSrc)) { throw "VERSION file missing: $versionSrc" }
    $version = ([System.IO.File]::ReadAllText($versionSrc)).Trim()
    if ($version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') { throw "VERSION format invalid: $version" }

    $coreCmake = Join-Path $SourceDir "core\CMakeLists.txt"
    if (-not (Test-Path -LiteralPath $coreCmake)) { throw "core CMakeLists missing: $coreCmake" }
    $fmtMatch = Select-String -LiteralPath $coreCmake -Pattern '^\s*set\(\s*VERTHYS_FMT_VERSION\s+(\d+)\s*\)' -AllMatches
    if ($null -eq $fmtMatch -or $fmtMatch.Matches.Count -ne 1) {
        throw "VERTHYS_FMT_VERSION not found exactly once in $coreCmake"
    }
    $fmtVersion = $fmtMatch.Matches[0].Groups[1].Value

    $contractScript = Join-Path $SourceDir "cmake\write_artifacts.cmake"
    if (-not (Test-Path -LiteralPath $contractScript)) {
        throw "artifact contract script missing: $contractScript"
    }
    if ([string]::IsNullOrEmpty($OutPath)) {
        $OutPath = Join-Path $SourceDir "build\core\verthys.artifacts.json"
    }

    & $CmakeExe `
        "-DVER_DLL_PATH=$DllPath" `
        "-DVER_OUT_PATH=$OutPath" `
        "-DVER_SOURCE_DIR=$SourceDir" `
        "-DVER_VERSION=$version" `
        "-DVER_FMT_VERSION=$fmtVersion" `
        "-DVER_GENERATOR=$Generator" `
        "-DVER_CONFIG=$Config" `
        -P $contractScript | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "artifact contract regeneration failed" }
    if (-not (Test-Path -LiteralPath $OutPath)) {
        throw "artifact contract missing after regeneration: $OutPath"
    }

    $m = Get-Content -LiteralPath $OutPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $DllPath).Hash.ToLowerInvariant()
    if ($m.sha256 -ne $actualHash) {
        throw "artifact contract sha256 mismatch: contract=$($m.sha256) actual=$actualHash"
    }
    if ($m.version -ne $version) {
        throw "artifact contract version mismatch: $($m.version) != $version"
    }
    if ([int]$m.fmt_version -ne [int]$fmtVersion) {
        throw "artifact contract fmt_version mismatch: $($m.fmt_version) != $fmtVersion"
    }
    if ($m.generator -ne $Generator) {
        throw "artifact contract generator mismatch: $($m.generator) != $Generator"
    }
    if ($m.config -ne $Config) {
        throw "artifact contract config mismatch: $($m.config) != $Config"
    }
    return $m
}