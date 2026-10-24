# publish_update.ps1 - Upload a signed Verthys release and atomically switch a channel pointer.
#
# This script never builds or signs anything. It performs six stages:
#   1. resolve the release directory (newest, or -ReleaseId)
#   2. validate local materials against the signed manifest and ledger
#   3. validate SSH access, remote layout and release immutability
#   4. upload materials to <remote-root>/.incoming/<release_id>
#   5. run /usr/local/bin/verthys-publish (hash re-check + atomic symlink switch)
#   6. verify the public manifest, cache headers, Range support and installer hash
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\release\publish_update.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\release\publish_update.ps1 -ReleaseId 0ppkb4jnzs5ae
#   powershell -ExecutionPolicy Bypass -File scripts\release\publish_update.ps1 -Channel beta
#
# Requirements:
#   - build\updater\releases\<release_id>\ produced by build_production.ps1
#   - OpenSSH client (ssh.exe / scp.exe) available in PATH
#   - the private key is authorized on the server (default: %USERPROFILE%\.ssh\k1super.pem)
#
# Exit codes: 0 success, 1 any validation, upload, publish or verification failure.

[CmdletBinding()]
param(
    [string]$ReleaseId = "",
    [ValidateSet("stable", "beta", "internal")]
    [string]$Channel = "stable",
    [string]$Server = "120.79.122.69",
    [int]$SshPort = 22,
    [string]$SshUser = "root",
    [string]$KeyPath = (Join-Path $env:USERPROFILE ".ssh\k1super.pem"),
    [string]$RemoteRoot = "/srv/verthys/updates",
    [string]$PublicBaseUrl = "",
    [switch]$NoPause
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Write-Stage([string]$Text) {
    Write-Host ""
    Write-Host "== $Text ==" -ForegroundColor Cyan
}

function Write-Ok([string]$Text) {
    Write-Host "  [OK] $Text" -ForegroundColor Green
}

function Write-Fail([string]$Text) {
    Write-Host "  [FAIL] $Text" -ForegroundColor Red
}

function Write-Info([string]$Text) {
    Write-Host "  $Text" -ForegroundColor Gray
}

function Assert([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Invoke-Remote([string]$Command, [string]$What) {
    $exe = $script:SshExe
    $sshArgs = $script:SshArgs
    $output = & $exe @sshArgs $Command 2>&1
    $code = $LASTEXITCODE
    foreach ($line in $output) { Write-Info ([string]$line) }
    if ($code -ne 0) { throw "$What failed (exit $code)" }
}

function Invoke-Upload([string]$LocalPath, [string]$RemoteDirectory) {
    $exe = $script:ScpExe
    $scpArgs = $script:ScpArgs
    $destination = "$($SshUser)@$($Server):$RemoteDirectory/"
    $output = & $exe @scpArgs $LocalPath $destination 2>&1
    foreach ($line in $output) { Write-Info ([string]$line) }
    if ($LASTEXITCODE -ne 0) { throw "upload failed: $LocalPath" }
}

$exitCode = 0
try {
    Write-Stage "[1/6] Resolve release directory"
    $scriptRoot = $PSScriptRoot
    $repoRoot = Split-Path -Parent (Split-Path -Parent $scriptRoot)
    $releasesRoot = Join-Path $repoRoot "build\updater\releases"
    Assert (Test-Path -LiteralPath $releasesRoot) "release root not found: $releasesRoot"

    $newIdPattern = '^[0-9a-hjkmnp-tv-z]{13}$'
    $legacyIdPattern = '^\d{8}-\d{6}-\d+\.\d+\.\d+-[0-9a-f]{8}$'

    if (-not [string]::IsNullOrWhiteSpace($ReleaseId)) {
        Assert (($ReleaseId -match $newIdPattern) -or ($ReleaseId -match $legacyIdPattern)) "invalid release id: $ReleaseId"
        $releaseDir = Join-Path $releasesRoot $ReleaseId
        Assert (Test-Path -LiteralPath $releaseDir) "release directory not found: $releaseDir"
    } else {
        $candidate = Get-ChildItem -LiteralPath $releasesRoot -Directory |
            Where-Object { $_.Name -match $newIdPattern -or $_.Name -match $legacyIdPattern } |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
        Assert ($null -ne $candidate) "no valid release directory under $releasesRoot"
        $releaseDir = $candidate.FullName
        $ReleaseId = $candidate.Name
    }
    Write-Ok "release: $ReleaseId"
    Write-Info "path: $releaseDir"

    Write-Stage "[2/6] Validate local materials"
    $manifestPath = Join-Path $releaseDir "latest.json"
    $ledgerPath = Join-Path $releaseDir "release-manifest.json"
    Assert (Test-Path -LiteralPath $manifestPath) "missing latest.json"
    Assert (Test-Path -LiteralPath $ledgerPath) "missing release-manifest.json"

    $installers = @(Get-ChildItem -LiteralPath $releaseDir -File -Filter "Verthys_*_x64-setup.exe")
    Assert ($installers.Count -eq 1) "expected exactly one installer, found $($installers.Count)"
    $installer = $installers[0]
    $signaturePath = "$($installer.FullName).sig"
    Assert (Test-Path -LiteralPath $signaturePath) "missing installer signature: $signaturePath"

    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $ledger = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
    $platform = $manifest.platforms.'windows-x86_64'
    Assert ($null -ne $platform) "manifest missing windows-x86_64 platform"
    Assert ($manifest.release_id -ceq $ReleaseId) "manifest release_id mismatch: $($manifest.release_id) != $ReleaseId"
    Assert ($manifest.channel -eq $Channel) "manifest channel mismatch: $($manifest.channel) != $Channel"
    Assert ($platform.file_version -eq $manifest.version) "file_version mismatch: $($platform.file_version) != $($manifest.version)"

    $versionPath = Join-Path $repoRoot "VERSION"
    if (Test-Path -LiteralPath $versionPath) {
        $currentVersion = (Get-Content -LiteralPath $versionPath -Raw).Trim()
        if ($currentVersion -ne $manifest.version) {
            Write-Warning "manifest version $($manifest.version) differs from VERSION $currentVersion"
        }
    }

    $downloadUri = [Uri]$platform.url
    Assert (($downloadUri.Scheme -eq "http") -or ($downloadUri.Scheme -eq "https")) "installer URL scheme must be http or https"
    Assert ($downloadUri.Host -eq $Server) "installer URL host $($downloadUri.Host) does not match server $Server"
    $expectedArtifactPath = "/releases/$ReleaseId/artifacts/$($installer.Name)"
    Assert ($downloadUri.AbsolutePath -ceq $expectedArtifactPath) "installer URL path mismatch: $($downloadUri.AbsolutePath) != $expectedArtifactPath"

    $localSha = (Get-FileHash -LiteralPath $installer.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert ($localSha -ceq ([string]$platform.sha256).ToLowerInvariant()) "installer hash does not match manifest"
    Assert ($installer.Length -eq [int64]$platform.size) "installer size does not match manifest"
    Assert ($localSha -ceq ([string]$ledger.installer.sha256).ToLowerInvariant()) "installer hash does not match ledger"

    $manifestSha = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($null -ne $ledger.manifests) {
        $ledgerManifests = @($ledger.manifests)
        if ($ledgerManifests.Count -gt 0) {
            $ledgerManifestSha = [string]$ledgerManifests[0].sha256
            if (-not [string]::IsNullOrWhiteSpace($ledgerManifestSha)) {
                Assert ($manifestSha -ceq $ledgerManifestSha.ToLowerInvariant()) "manifest hash does not match ledger"
            }
        }
    }
    Write-Ok "materials and hashes verified"

    Write-Stage "[3/6] Validate server access"
    Assert ($Server -match '^[A-Za-z0-9][A-Za-z0-9.-]*$') "invalid server host: $Server"
    Assert ($SshUser -match '^[A-Za-z0-9._-]+$') "invalid ssh user: $SshUser"
    Assert (($SshPort -ge 1) -and ($SshPort -le 65535)) "invalid ssh port: $SshPort"
    Assert (($RemoteRoot -match '^/[A-Za-z0-9._/-]+$') -and (-not $RemoteRoot.Contains(".."))) "invalid remote root: $RemoteRoot"
    Assert (Test-Path -LiteralPath $KeyPath) "ssh key not found: $KeyPath"

    $sshCommand = Get-Command ssh.exe -ErrorAction SilentlyContinue
    if ($null -eq $sshCommand) { $sshCommand = Get-Command ssh -ErrorAction SilentlyContinue }
    Assert ($null -ne $sshCommand) "ssh client not found in PATH"
    $scpCommand = Get-Command scp.exe -ErrorAction SilentlyContinue
    if ($null -eq $scpCommand) { $scpCommand = Get-Command scp -ErrorAction SilentlyContinue }
    Assert ($null -ne $scpCommand) "scp client not found in PATH"

    $script:SshExe = $sshCommand.Source
    $script:ScpExe = $scpCommand.Source
    $script:SshArgs = @(
        "-i", $KeyPath,
        "-p", "$SshPort",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "$SshUser@$Server"
    )
    $script:ScpArgs = @(
        "-i", $KeyPath,
        "-P", "$SshPort",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new"
    )

    $sshExe = $script:SshExe
    $sshArgs = $script:SshArgs
    $probe = & $sshExe @sshArgs "echo __VERTHYS_SSH_OK__" 2>&1
    $probeCode = $LASTEXITCODE
    foreach ($line in $probe) { Write-Info ([string]$line) }
    Assert (($probeCode -eq 0) -and (($probe -join "`n") -match "__VERTHYS_SSH_OK__")) "ssh login failed for $SshUser@$Server`:$SshPort"
    Write-Ok "ssh login: $SshUser@$Server`:$SshPort"

    Invoke-Remote "test -d '$RemoteRoot/releases' && test -d '$RemoteRoot/channels' && command -v verthys-publish >/dev/null" "remote layout and publish helper check"

    $remoteRelease = "$RemoteRoot/releases/$ReleaseId"
    $existsProbe = & $sshExe @sshArgs "test ! -e '$remoteRelease'" 2>&1
    $existsCode = $LASTEXITCODE
    foreach ($line in $existsProbe) { Write-Info ([string]$line) }
    if ($existsCode -ne 0) {
        throw "release already exists on server and is immutable: $remoteRelease. Build a newer version or pass -ReleaseId for another local release."
    }
    Write-Ok "release path is free: $remoteRelease"

    Write-Stage "[4/6] Upload materials"
    $incoming = "$RemoteRoot/.incoming/$ReleaseId"
    Invoke-Remote "rm -rf '$incoming' && mkdir -p '$incoming'" "prepare incoming directory"

    $files = @(Get-ChildItem -LiteralPath $releaseDir -File)
    Assert ($files.Count -gt 0) "no files to upload in $releaseDir"
    foreach ($file in $files) {
        Invoke-Upload $file.FullName $incoming
        Write-Ok "uploaded: $($file.Name)"
    }

    Write-Stage "[5/6] Atomic publish"
    $publishOutput = & $sshExe @sshArgs "verthys-publish '$incoming' '$Channel'" 2>&1
    $publishCode = $LASTEXITCODE
    foreach ($line in $publishOutput) { Write-Info ([string]$line) }
    if ($publishCode -ne 0) {
        throw "atomic publish failed (exit $publishCode); incoming directory kept for diagnosis"
    }
    Write-Ok "channel pointer switched: $Channel"

    $cleanup = & $sshExe @sshArgs "rm -rf '$incoming'" 2>&1
    foreach ($line in $cleanup) { Write-Info ([string]$line) }

    Write-Stage "[6/6] Verify public endpoint"
    if ([string]::IsNullOrWhiteSpace($PublicBaseUrl)) { $PublicBaseUrl = "http://$Server" }
    $baseUrl = $PublicBaseUrl.TrimEnd('/')
    $manifestUrl = "$baseUrl/$Channel/latest.json"

    $response = Invoke-WebRequest -UseBasicParsing -Uri $manifestUrl -TimeoutSec 30
    Assert ($response.StatusCode -eq 200) "public manifest returned $($response.StatusCode)"
    $cacheControl = [string]$response.Headers["Cache-Control"]
    Assert ($cacheControl -match "no-store") "manifest must be no-store, got: $cacheControl"

    $publicManifest = $response.Content | ConvertFrom-Json
    Assert ($publicManifest.release_id -ceq $ReleaseId) "public manifest release_id mismatch: $($publicManifest.release_id) != $ReleaseId"
    Assert ($publicManifest.version -eq $manifest.version) "public manifest version mismatch: $($publicManifest.version) != $($manifest.version)"
    $publicPlatform = $publicManifest.platforms.'windows-x86_64'
    Assert ($null -ne $publicPlatform) "public manifest missing windows-x86_64 platform"
    Assert ([string]$publicPlatform.url -ceq $platform.url) "public installer URL mismatch"

    $head = Invoke-WebRequest -UseBasicParsing -Method Head -Uri $platform.url -TimeoutSec 30
    $artifactCache = [string]$head.Headers["Cache-Control"]
    Assert ($artifactCache -match "immutable") "installer must be immutable, got: $artifactCache"
    Assert ([string]$head.Headers["Accept-Ranges"] -eq "bytes") "installer must accept byte ranges"

    $tempInstaller = Join-Path $env:TEMP ("verthys-verify-" + [Guid]::NewGuid().ToString("N") + ".exe")
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $platform.url -OutFile $tempInstaller -TimeoutSec 300
        $remoteSha = (Get-FileHash -LiteralPath $tempInstaller -Algorithm SHA256).Hash.ToLowerInvariant()
        Assert ($remoteSha -ceq $localSha) "downloaded installer hash mismatch"
    } finally {
        Remove-Item -LiteralPath $tempInstaller -Force -ErrorAction SilentlyContinue
    }
    Write-Ok "public manifest, headers and installer hash verified"

    $nodeCommand = Get-Command node -ErrorAction SilentlyContinue
    $originCheck = Join-Path $repoRoot "scripts\updater\check_updater_origin.mjs"
    if (($null -ne $nodeCommand) -and (Test-Path -LiteralPath $originCheck)) {
        & $nodeCommand.Source $originCheck --url $manifestUrl
        Assert ($LASTEXITCODE -eq 0) "origin contract check failed"
        Write-Ok "origin contract check passed"
    } else {
        Write-Warning "node or check_updater_origin.mjs missing; skipped origin contract check"
    }

    Write-Stage "Published"
    Write-Ok "$ReleaseId ($($manifest.version)) -> $Channel"
    Write-Info "manifest:  $manifestUrl"
    Write-Info "installer: $($platform.url)"
}
catch {
    Write-Fail $_.Exception.Message
    $exitCode = 1
}
finally {
    if (-not $NoPause) {
        Write-Host ""
        Read-Host "Press Enter to exit" | Out-Null
    }
}
exit $exitCode
