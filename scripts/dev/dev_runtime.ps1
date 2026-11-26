# scripts/dev/dev_runtime.ps1 - signed development runtime preparation
#
# ASCII only: Windows PowerShell 5.1 decodes BOM-less files with the ANSI code
# page, so localized comments can break parsing.
#
# Responsibilities:
#   - validate the signing certificate against the installed service publisher pin
#   - build a production-parity C core into an isolated build directory
#   - build and sign the worker against that core
#   - stage the signed DLL/worker for the Tauri dev host
#   - configure the cargo target runner used by tauri dev

$script:DevRepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

function Get-VerthysDevRepoRoot {
    return $script:DevRepoRoot
}

function Read-VerthysDevServicePublisher {
    param([string]$ArtifactPath = "")

    if ([string]::IsNullOrWhiteSpace($ArtifactPath)) {
        $ArtifactPath = Join-Path $script:DevRepoRoot "build\security-service\security-service.artifacts.json"
    }
    if (-not (Test-Path -LiteralPath $ArtifactPath -PathType Leaf)) {
        throw ("Missing service build metadata: {0}. Build and install the P2 service first." -f $ArtifactPath)
    }

    $meta = Get-Content -LiteralPath $ArtifactPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($null -eq $meta -or [string]::IsNullOrWhiteSpace([string]$meta.publisherSha256)) {
        throw ("Service build metadata has no publisherSha256: {0}" -f $ArtifactPath)
    }
    return ([string]$meta.publisherSha256).Trim().ToLowerInvariant()
}

function Resolve-VerthysDevSigning {
    param([string]$ServiceArtifactPath = "")

    . (Join-Path $script:DevRepoRoot "scripts\lib\release_signing.ps1")

    $signing = Resolve-VerthysReleaseSigning -Required
    if (-not $signing.Enabled) {
        throw "A code-signing certificate is required for the dev kernel runtime."
    }

    $servicePin = Read-VerthysDevServicePublisher -ArtifactPath $ServiceArtifactPath
    if ($servicePin -ne $signing.PublisherSha256) {
        throw ("Publisher pin mismatch: service={0} certificate={1}. " -f $servicePin, $signing.PublisherSha256 +
               "Use the certificate pinned by the installed service, or rebuild the service with this publisher.")
    }

    $service = Get-Service -Name "VerthysSecuritySvc" -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        throw "VerthysSecuritySvc is not installed. Install the P2 security service before using the dev kernel runtime."
    }
    if ($service.Status -ne "Running") {
        throw ("VerthysSecuritySvc is not running (status={0}). Start it and retry." -f $service.Status)
    }

    return $signing
}

function Get-VerthysDevFingerprint {
    param(
        [Parameter(Mandatory = $true)][string[]]$Roots,
        [string[]]$Files = @()
    )

    $root = $script:DevRepoRoot
    $all = New-Object System.Collections.Generic.List[string]

    foreach ($item in $Files) {
        $full = Join-Path $root $item
        if (Test-Path -LiteralPath $full -PathType Leaf) {
            $all.Add($full)
        }
    }
    foreach ($item in $Roots) {
        $full = Join-Path $root $item
        if (-not (Test-Path -LiteralPath $full)) {
            continue
        }
        if (Test-Path -LiteralPath $full -PathType Leaf) {
            $all.Add($full)
            continue
        }
        Get-ChildItem -LiteralPath $full -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object {
                $_.FullName -notmatch '\\target\\' -and
                $_.FullName -notmatch '\\build_dev\\' -and
                $_.FullName -notmatch '\\build\\'
            } |
            ForEach-Object { $all.Add($_.FullName) }
    }

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("generator=" + [string]$env:VERTHYS_VS_GENERATOR)
    foreach ($file in ($all | Sort-Object -Unique)) {
        $relative = $file
        if ($relative.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
            $relative = $relative.Substring($root.Length).TrimStart('\')
        }
        $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        $lines.Add($relative + "=" + $hash)
    }

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes(($lines -join "`n"))
        $digest = $sha.ComputeHash($bytes)
        return (($digest | ForEach-Object { $_.ToString("x2") }) -join "")
    } finally {
        $sha.Dispose()
    }
}

function Get-VerthysDevCoreFingerprint {
    return Get-VerthysDevFingerprint -Roots @("core", "cmake") -Files @(
        "VERSION",
        "CMakeLists.txt",
        "scripts\build\build_core.release.ps1",
        "scripts\lib\vsec.ps1",
        "scripts\lib\artifacts.ps1",
        "scripts\lib\release_signing.ps1"
    )
}

function Get-VerthysDevWorkerFingerprint {
    return Get-VerthysDevFingerprint -Roots @("verthys-tauri\verthys-worker")
}

function Get-VerthysDevCoreApiVersion {
    $header = Join-Path $script:DevRepoRoot "core\include\verthys_version.h"
    if (-not (Test-Path -LiteralPath $header -PathType Leaf)) {
        throw ("Core version header missing: {0}" -f $header)
    }
    $match = Select-String -LiteralPath $header -Pattern '^\s*#define\s+VERTHYS_API_VERSION\s+(0[xX][0-9A-Fa-f]+|\d+)' |
        Select-Object -First 1
    if ($null -eq $match -or $match.Matches.Count -eq 0) {
        throw ("VERTHYS_API_VERSION not found in {0}" -f $header)
    }
    $raw = $match.Matches[0].Groups[1].Value
    if ($raw -match '^0[xX]') {
        return "0x" + $raw.Substring(2).ToUpperInvariant()
    }
    return ("0x{0:X4}" -f [int]$raw)
}

function Get-VerthysDevStampField {
    param($Stamp, [string]$Name)
    if ($null -eq $Stamp) {
        return $null
    }
    $property = $Stamp.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function Read-VerthysDevStamp {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    try {
        return Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return $null
    }
}

function Write-VerthysDevStamp {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$CoreFingerprint,
        [Parameter(Mandatory = $true)][string]$WorkerFingerprint,
        [Parameter(Mandatory = $true)]$Signing,
        [Parameter(Mandatory = $true)][string]$DllSha256,
        [Parameter(Mandatory = $true)][string]$WorkerSha256
    )

    $stamp = [ordered]@{
        schema            = 1
        coreFingerprint   = $CoreFingerprint
        workerFingerprint = $WorkerFingerprint
        publisherSha256   = $Signing.PublisherSha256
        dllSha256         = $DllSha256
        workerDllSha256   = $DllSha256
        workerSha256      = $WorkerSha256
        updatedAt         = (Get-Date).ToUniversalTime().ToString("o")
    }
    $json = $stamp | ConvertTo-Json
    [System.IO.File]::WriteAllText($Path, $json, [System.Text.UTF8Encoding]::new($false))
}

function Get-VerthysDevSignerSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne "Valid" -or $null -eq $signature.SignerCertificate) {
        return ""
    }
    return $signature.SignerCertificate.GetCertHashString(
        [System.Security.Cryptography.HashAlgorithmName]::SHA256).ToLowerInvariant()
}

function Test-VerthysDevCoreUpToDate {
    param(
        [string]$DllPath,
        [string]$StampPath,
        [string]$Fingerprint,
        $Signing
    )

    if (-not (Test-Path -LiteralPath $DllPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $StampPath -PathType Leaf)) {
        return $false
    }
    $stamp = Read-VerthysDevStamp -Path $StampPath
    if ($null -eq $stamp) {
        return $false
    }
    if ([int](Get-VerthysDevStampField -Stamp $stamp -Name "schema") -ne 1) {
        return $false
    }
    if ([string](Get-VerthysDevStampField -Stamp $stamp -Name "coreFingerprint") -ne $Fingerprint) {
        return $false
    }
    if ([string](Get-VerthysDevStampField -Stamp $stamp -Name "publisherSha256") -ne $Signing.PublisherSha256) {
        return $false
    }

    $hash = (Get-FileHash -LiteralPath $DllPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ([string](Get-VerthysDevStampField -Stamp $stamp -Name "dllSha256") -ne $hash) {
        return $false
    }
    if ((Get-VerthysDevSignerSha256 -Path $DllPath) -ne $Signing.PublisherSha256) {
        return $false
    }

    $contract = [System.IO.Path]::GetFullPath(
        (Join-Path (Split-Path -Parent $DllPath) "..\verthys.artifacts.json"))
    if (-not (Test-Path -LiteralPath $contract -PathType Leaf)) {
        return $false
    }
    try {
        $meta = Get-Content -LiteralPath $contract -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return $false
    }
    return ([string]$meta.sha256 -eq $hash)
}

function Test-VerthysDevWorkerUpToDate {
    param(
        [string]$WorkerPath,
        [string]$StampPath,
        [string]$Fingerprint,
        [string]$DllSha256,
        $Signing
    )

    if (-not (Test-Path -LiteralPath $WorkerPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $StampPath -PathType Leaf)) {
        return $false
    }
    $stamp = Read-VerthysDevStamp -Path $StampPath
    if ($null -eq $stamp) {
        return $false
    }
    if ([string](Get-VerthysDevStampField -Stamp $stamp -Name "workerFingerprint") -ne $Fingerprint) {
        return $false
    }
    if ([string](Get-VerthysDevStampField -Stamp $stamp -Name "workerDllSha256") -ne $DllSha256) {
        return $false
    }
    $hash = (Get-FileHash -LiteralPath $WorkerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ([string](Get-VerthysDevStampField -Stamp $stamp -Name "workerSha256") -ne $hash) {
        return $false
    }
    return ((Get-VerthysDevSignerSha256 -Path $WorkerPath) -eq $Signing.PublisherSha256)
}

function Sync-VerthysDevStage {
    param(
        [Parameter(Mandatory = $true)][string]$DllPath,
        [Parameter(Mandatory = $true)][string]$WorkerPath
    )

    # Single producer shared with build_production and CI. It stages the DLL,
    # the worker, syncs target\debug, verifies byte identity, and writes the
    # bundle manifest consumed by the Rust build gate.
    $stage = & (Join-Path $script:DevRepoRoot "scripts\build\stage_bundle_assets.ps1") `
        -Channel dev `
        -DllSource $DllPath `
        -WorkerSource $WorkerPath `
        -ContractPath (Join-Path $script:DevRepoRoot "build_dev\core\verthys.artifacts.json") `
        -Producer "build_dev.ps1" `
        -SyncTargets dev `
        -RepoRoot $script:DevRepoRoot

    return [pscustomobject]@{
        HostDir  = (Join-Path $script:DevRepoRoot "verthys-tauri\src-tauri\target\debug")
        Manifest = $stage.Manifest
    }
}

function Initialize-VerthysDevRuntime {
    param([Parameter(Mandatory = $true)]$Signing)

    $coreScript = Join-Path $script:DevRepoRoot "scripts\build\build_core.release.ps1"
    if (-not (Test-Path -LiteralPath $coreScript -PathType Leaf)) {
        throw ("Core build script missing: {0}" -f $coreScript)
    }

    $devBuildDir = Join-Path $script:DevRepoRoot "build_dev"
    $dllPath = Join-Path $devBuildDir "core\Release\verthys.dll"
    $workerDir = Join-Path $script:DevRepoRoot "verthys-tauri\verthys-worker"
    $workerTargetDir = Join-Path $devBuildDir "worker-target"
    $workerPath = Join-Path $workerTargetDir "release\verthys-worker.exe"
    $stampPath = Join-Path $devBuildDir "dev-runtime.json"

    . (Join-Path $script:DevRepoRoot "scripts\lib\release_signing.ps1")

    $coreFingerprint = Get-VerthysDevCoreFingerprint
    if (Test-VerthysDevCoreUpToDate `
            -DllPath $dllPath `
            -StampPath $stampPath `
            -Fingerprint $coreFingerprint `
            -Signing $Signing) {
        Write-Host "[dev] Dev core up to date; skipping rebuild" -ForegroundColor Green
    } else {
        Write-Host "[dev] Building isolated core (build_dev, ReleaseSigning)..." -ForegroundColor Cyan
        & $coreScript -BuildDir $devBuildDir -ReleaseSigning -NoPause
        if ($LASTEXITCODE -ne 0) {
            throw ("Isolated core build failed (exit={0})." -f $LASTEXITCODE)
        }
        if (-not (Test-Path -LiteralPath $dllPath -PathType Leaf)) {
            throw ("Dev core DLL missing: {0}" -f $dllPath)
        }
        Assert-VerthysAuthenticodeSignature -Path $dllPath -ExpectedSha256 $Signing.PublisherSha256 | Out-Null
        Write-Host ("[dev] Dev core signed: {0}" -f $dllPath) -ForegroundColor Green
    }

    $dllHash = (Get-FileHash -LiteralPath $dllPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $workerFingerprint = Get-VerthysDevWorkerFingerprint
    if (Test-VerthysDevWorkerUpToDate `
            -WorkerPath $workerPath `
            -StampPath $stampPath `
            -Fingerprint $workerFingerprint `
            -DllSha256 $dllHash `
            -Signing $Signing) {
        Write-Host "[dev] Dev worker up to date; skipping rebuild" -ForegroundColor Green
    } else {
        $workerExit = 1
        $apiVersion = Get-VerthysDevCoreApiVersion
        $env:VERTHYS_DLL_PATH = $dllPath
        $env:VERTHYS_WORKER_API_VERSION = $apiVersion
        try {
            Push-Location $workerDir
            Write-Host ("[dev] Building worker against the signed dev DLL (API {0})..." -f $apiVersion) -ForegroundColor Cyan
            & cargo build --release --target-dir $workerTargetDir
            $workerExit = $LASTEXITCODE
        } finally {
            Pop-Location
        }
        if ($workerExit -ne 0) {
            throw ("Dev worker build failed (exit={0})." -f $workerExit)
        }
        if (-not (Test-Path -LiteralPath $workerPath -PathType Leaf)) {
            throw ("Dev worker missing: {0}" -f $workerPath)
        }
        Invoke-VerthysAuthenticodeSign `
            -Path $workerPath `
            -Certificate $Signing.Certificate `
            -TimestampServer $Signing.TimestampServer
        Assert-VerthysAuthenticodeSignature -Path $workerPath -ExpectedSha256 $Signing.PublisherSha256 | Out-Null
        Write-Host ("[dev] Dev worker signed: {0}" -f $workerPath) -ForegroundColor Green
    }

    $workerHash = (Get-FileHash -LiteralPath $workerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-VerthysDevStamp `
        -Path $stampPath `
        -CoreFingerprint $coreFingerprint `
        -WorkerFingerprint $workerFingerprint `
        -Signing $Signing `
        -DllSha256 $dllHash `
        -WorkerSha256 $workerHash

    $stage = Sync-VerthysDevStage -DllPath $dllPath -WorkerPath $workerPath
    Write-Host ("[dev] Packaging assets staged (channel=dev, dll={0}, worker={1})" -f $dllHash.Substring(0, 12), $workerHash.Substring(0, 12)) -ForegroundColor Gray

    return [pscustomobject]@{
        DllPath         = $dllPath
        WorkerPath      = $workerPath
        PublisherSha256 = $Signing.PublisherSha256
        StagedHostDir   = $stage.HostDir
    }
}

function Set-VerthysDevCargoRunner {
    $rustc = Get-Command rustc.exe -ErrorAction SilentlyContinue
    if ($null -eq $rustc) {
        throw "rustc.exe is not available in PATH."
    }

    $hostLine = @(& $rustc.Source -vV | Where-Object { $_ -match '^host:\s*' })
    if ($hostLine.Count -eq 0) {
        throw "Unable to determine the Rust host triple."
    }
    $triple = ($hostLine[0] -replace '^host:\s*', '').Trim()
    if ($triple -ne "x86_64-pc-windows-msvc") {
        throw ("Unsupported Rust host triple: {0} (expected x86_64-pc-windows-msvc)." -f $triple)
    }

    # Cargo treats CARGO_TARGET_<TRIPLE>_RUNNER as a single executable path, so
    # arguments cannot be embedded in the value. Use a compiled shim instead of
    # passing PowerShell command-line switches through the environment variable.
    $sourcePath = Join-Path $script:DevRepoRoot "scripts\dev\dev_runner.cs"
    $runnerExe = Join-Path $script:DevRepoRoot "build_dev\dev_runner.exe"
    if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
        throw ("Dev runner source missing: {0}" -f $sourcePath)
    }
    if ($runnerExe -match '\s') {
        throw ("Dev runner path must not contain whitespace: {0}" -f $runnerExe)
    }

    $needsBuild = -not (Test-Path -LiteralPath $runnerExe -PathType Leaf)
    if (-not $needsBuild) {
        $needsBuild = (Get-Item -LiteralPath $sourcePath).LastWriteTimeUtc -gt
            (Get-Item -LiteralPath $runnerExe).LastWriteTimeUtc
    }
    if ($needsBuild) {
        $buildDir = Split-Path -Parent $runnerExe
        if (-not (Test-Path -LiteralPath $buildDir)) {
            New-Item -ItemType Directory -Path $buildDir -Force | Out-Null
        }
        if (Test-Path -LiteralPath $runnerExe) {
            Remove-Item -LiteralPath $runnerExe -Force -ErrorAction Stop
        }
        Write-Host "[dev] Compiling cargo dev runner..." -ForegroundColor Cyan
        Add-Type `
            -Path $sourcePath `
            -OutputAssembly $runnerExe `
            -OutputType ConsoleApplication `
            -ReferencedAssemblies "System.Management" `
            -ErrorAction Stop
    }
    if (-not (Test-Path -LiteralPath $runnerExe -PathType Leaf)) {
        throw ("Dev runner executable missing after compilation: {0}" -f $runnerExe)
    }

    $variableName = "CARGO_TARGET_" + ($triple.ToUpperInvariant().Replace('-', '_')) + "_RUNNER"
    Set-Item -Path ("Env:" + $variableName) -Value $runnerExe

    return [pscustomobject]@{
        Name   = $variableName
        Value  = $runnerExe
        Triple = $triple
    }
}
