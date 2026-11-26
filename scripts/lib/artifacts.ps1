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
# build\core\Release\verthys.dll). Guessing wrong degrades the DLL integrity
# hash to None and breaks the material gates.
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

# Converts an absolute path to a repo-relative path with forward slashes.
# Rejects paths outside the repository so the manifest can never reference
# arbitrary host files.
function ConvertTo-VerthysRepoRelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $full = [System.IO.Path]::GetFullPath($Path)
    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    if (-not $full.StartsWith($rootFull + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "path outside repository root: $Path"
    }
    return $full.Substring($rootFull.Length + 1).Replace('\', '/')
}

# Writes the packaging bundle manifest consumed by the Tauri build gate.
#
# The packaging paths (src-tauri\verthys.dll and
# src-tauri\binaries\verthys-worker-x86_64-pc-windows-msvc.exe) are shared by
# two channels: the isolated dev runtime (dev-signed DLL + dev worker) and the
# production pipeline (release-signed DLL + release worker). Identical paths
# with different bytes mean a single-channel hash baseline can never tell
# "fresh" from "wrong channel"; the manifest records which channel the staged
# bytes belong to.
#
# Recorded fields: channel, artifact contract, both file hashes, and the DLL
# hash the worker was compiled against (pair binding). The worker hash is the
# only invariant that prevents "new DLL + old worker" from reaching packaging:
# the worker verifies the DLL digest at runtime and aborts on mismatch.
#
# Callers must prove the worker binding before calling:
#   - dev: build_dev\dev-runtime.json (workerDllSha256 / workerSha256)
#   - production: build\core\worker.artifacts.json (dll_sha256 / worker_sha256)
# The write is atomic (temp file + replace) and verified by reading it back.
function Write-VerthysBundleManifest {
    param(
        [Parameter(Mandatory = $true)][ValidateSet("dev", "production")][string]$Channel,
        [Parameter(Mandatory = $true)][string]$DllPath,
        [Parameter(Mandatory = $true)][string]$DllSource,
        [Parameter(Mandatory = $true)][string]$WorkerPath,
        [Parameter(Mandatory = $true)][string]$WorkerSource,
        [Parameter(Mandatory = $true)][string]$ContractPath,
        [Parameter(Mandatory = $true)][string]$WorkerDllSha256,
        [Parameter(Mandatory = $true)][string]$WorkerSha256,
        [Parameter(Mandatory = $true)][string]$Producer,
        [string]$OutPath = "",
        [string]$RepoRoot = ""
    )

    if ([string]::IsNullOrEmpty($RepoRoot)) { $RepoRoot = $script:ArtifactsRepoRoot }
    $repoFull = [System.IO.Path]::GetFullPath($RepoRoot).TrimEnd('\')
    if ([string]::IsNullOrEmpty($OutPath)) {
        $OutPath = Join-Path $repoFull "verthys-tauri\src-tauri\bundle-assets.json"
    }

    $stagedDll = Join-Path $repoFull "verthys-tauri\src-tauri\verthys.dll"
    $stagedWorker = Join-Path $repoFull "verthys-tauri\src-tauri\binaries\verthys-worker-x86_64-pc-windows-msvc.exe"
    if (-not [System.IO.Path]::GetFullPath($DllPath).Equals(
            [System.IO.Path]::GetFullPath($stagedDll), [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "bundle manifest: DLL must be staged at $stagedDll (got $DllPath)"
    }
    if (-not [System.IO.Path]::GetFullPath($WorkerPath).Equals(
            [System.IO.Path]::GetFullPath($stagedWorker), [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "bundle manifest: worker must be staged at $stagedWorker (got $WorkerPath)"
    }
    foreach ($required in @($DllPath, $WorkerPath, $ContractPath, $DllSource, $WorkerSource)) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "bundle manifest: required file missing: $required"
        }
    }

    $dllHash = (Get-FileHash -LiteralPath $DllPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $workerHash = (Get-FileHash -LiteralPath $WorkerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $contractFileHash = (Get-FileHash -LiteralPath $ContractPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($WorkerSha256.ToLowerInvariant() -ne $workerHash) {
        throw "bundle manifest: worker hash drift (declared=$WorkerSha256 staged=$workerHash)"
    }
    if ($WorkerDllSha256.ToLowerInvariant() -ne $dllHash) {
        throw "bundle manifest: worker was built against a different DLL (bound=$WorkerDllSha256 staged=$dllHash)"
    }

    $contract = Get-Content -LiteralPath $ContractPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ([string]$contract.sha256 -ne $dllHash) {
        throw "bundle manifest: DLL does not match its artifact contract (contract=$($contract.sha256) dll=$dllHash)"
    }
    $versionPath = Join-Path $repoFull "VERSION"
    if (-not (Test-Path -LiteralPath $versionPath -PathType Leaf)) {
        throw "bundle manifest: VERSION file missing: $versionPath"
    }
    $version = ([System.IO.File]::ReadAllText($versionPath)).Trim()
    if ([string]$contract.version -ne $version) {
        throw "bundle manifest: contract version $($contract.version) != VERSION $version"
    }

    $dllInfo = Get-Item -LiteralPath $DllPath
    $workerInfo = Get-Item -LiteralPath $WorkerPath
    $manifest = [ordered]@{
        schema      = 1
        channel     = $Channel
        version     = $version
        fmt_version = [int]$contract.fmt_version
        producer    = $Producer
        dll         = [ordered]@{
            path     = "verthys.dll"
            source   = (ConvertTo-VerthysRepoRelativePath -Path $DllSource -Root $repoFull)
            sha256   = $dllHash
            built_at = $dllInfo.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
        }
        worker      = [ordered]@{
            path       = "binaries/verthys-worker-x86_64-pc-windows-msvc.exe"
            source     = (ConvertTo-VerthysRepoRelativePath -Path $WorkerSource -Root $repoFull)
            sha256     = $workerHash
            built_at   = $workerInfo.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
            dll_sha256 = $dllHash
        }
        contract    = [ordered]@{
            path   = (ConvertTo-VerthysRepoRelativePath -Path $ContractPath -Root $repoFull)
            sha256 = $contractFileHash
        }
    }

    $outDir = Split-Path -Parent $OutPath
    if (-not (Test-Path -LiteralPath $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }
    $json = $manifest | ConvertTo-Json -Depth 6
    $tmpPath = "$OutPath.tmp"
    [System.IO.File]::WriteAllText($tmpPath, $json, (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $tmpPath -Destination $OutPath -Force

    $written = Get-Content -LiteralPath $OutPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ([int]$written.schema -ne 1 -or
        [string]$written.channel -ne $Channel -or
        [string]$written.dll.sha256 -ne $dllHash -or
        [string]$written.worker.sha256 -ne $workerHash -or
        [string]$written.worker.dll_sha256 -ne $dllHash -or
        [string]$written.contract.sha256 -ne $contractFileHash) {
        throw "bundle manifest: read-back verification failed: $OutPath"
    }
    return $written
}
