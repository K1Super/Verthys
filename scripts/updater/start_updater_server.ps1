<#
.SYNOPSIS
    Start the local updater fixture service.

.DESCRIPTION
    Starts scripts/updater/updater_server.mjs in the foreground. The service binds to
    127.0.0.1 only and serves the updater manifest, installer, and signature
    from the configured artifact directory.

    Press Ctrl+C to stop the service.

.PARAMETER Port
    TCP port for the loopback service. Default: 8765.

.PARAMETER Root
    Directory containing latest.json and release artifacts.
    Default: build/updater relative to the repository root.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\updater\start_updater_server.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\updater\start_updater_server.ps1 -Port 9000
#>
param(
    [int]$Port = 8765,
    [string]$Root = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$ServerScript = Join-Path $PSScriptRoot "updater_server.mjs"

if (-not (Test-Path -LiteralPath $ServerScript)) {
    throw "Updater server script not found: $ServerScript"
}

if ($Port -lt 1 -or $Port -gt 65535) {
    throw "Port must be between 1 and 65535."
}

$NodeCommand = Get-Command node.exe -ErrorAction SilentlyContinue
if (-not $NodeCommand) {
    throw "node.exe was not found on PATH."
}

if ([string]::IsNullOrWhiteSpace($Root)) {
    $Root = Join-Path $RepoRoot "build\updater"
} else {
    $Root = [System.IO.Path]::GetFullPath($Root)
}

if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
    throw "Updater root directory not found: $Root"
}

$ManifestPath = Join-Path $Root "latest.json"
if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
    throw "Updater manifest not found: $ManifestPath"
}

try {
    $Manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
} catch {
    throw "Updater manifest is not valid JSON: $ManifestPath"
}

# StrictMode 3.0 throws PropertyNotFoundException for missing properties.
# Read fields defensively so a malformed manifest yields an actionable error
# instead of a raw exception stack.
function Get-JsonField {
    param($Object, [string]$Name)
    if ($null -eq $Object -or $Object -isnot [System.Management.Automation.PSCustomObject]) {
        return $null
    }
    $Property = $Object.PSObject.Properties[$Name]
    if ($null -eq $Property) { return $null }
    return $Property.Value
}

$Platforms = Get-JsonField $Manifest "platforms"
$Platform = Get-JsonField $Platforms "windows-x86_64"
$DownloadUrl = Get-JsonField $Platform "url"
if ($DownloadUrl -isnot [string] -or [string]::IsNullOrWhiteSpace($DownloadUrl)) {
    throw "Manifest has no windows-x86_64 download URL."
}

try {
    $DownloadUri = [System.Uri]::new($DownloadUrl)
} catch {
    throw "Manifest download URL is not a valid URI: $DownloadUrl"
}
$InstallerName = [System.IO.Path]::GetFileName($DownloadUri.AbsolutePath)
$InstallerName = [System.Uri]::UnescapeDataString($InstallerName)
if ([string]::IsNullOrWhiteSpace($InstallerName)) {
    throw "Manifest download URL has no installer file name: $DownloadUrl"
}

$InstallerPath = Join-Path $Root $InstallerName
if (-not (Test-Path -LiteralPath $InstallerPath -PathType Leaf)) {
    throw "Installer not found: $InstallerPath"
}

if (-not (Test-Path -LiteralPath "$InstallerPath.sig" -PathType Leaf)) {
    throw "Installer signature not found: $InstallerPath.sig"
}

$ExistingListener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($ExistingListener) {
    throw "Port $Port is already in use. Stop the existing service first."
}

Write-Host "[INFO] Manifest version: $(Get-JsonField $Manifest 'version')"
Write-Host "[INFO] Release ID: $(Get-JsonField $Manifest 'release_id')"
Write-Host "[INFO] Installer: $InstallerName"
Write-Host "[INFO] Endpoint: http://127.0.0.1:$Port/latest.json"
Write-Host "[INFO] Press Ctrl+C to stop."

& $NodeCommand.Source $ServerScript --root $Root --port $Port
exit $LASTEXITCODE
