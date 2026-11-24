param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',
    [switch]$Clean
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptRoot = $PSScriptRoot
$repoRoot = (Resolve-Path (Join-Path $scriptRoot '..\..')).Path
$buildRoot = Join-Path $repoRoot 'build_driver'
$wdkRoot = 'D:\Windows Kits\10'
$wdkVersion = '10.0.28000.0'
$msbuild = 'D:\IDE\Visual Studio 2026\18\Community\MSBuild\Current\Bin\amd64\MSBuild.exe'

if (-not (Test-Path (Join-Path $wdkRoot "Include\$wdkVersion\km\wdm.h"))) {
    throw "WDK $wdkVersion not found under $wdkRoot"
}

if (-not (Test-Path $msbuild)) {
    $vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vswhere)) {
        throw '64-bit MSBuild not found and vswhere is unavailable'
    }
    $vsRoot = (& $vswhere -latest -products * -property installationPath).Trim()
    if ([string]::IsNullOrWhiteSpace($vsRoot)) {
        throw 'Visual Studio installation not found'
    }
    $msbuild = Join-Path $vsRoot 'MSBuild\Current\Bin\amd64\MSBuild.exe'
}

if (-not (Test-Path $msbuild)) {
    throw "64-bit MSBuild not found: $msbuild"
}

if ($Clean -and (Test-Path $buildRoot)) {
    $resolvedBuild = (Resolve-Path $buildRoot).Path
    if (-not $resolvedBuild.EndsWith('\build_driver')) {
        throw "Refusing to clean unexpected path: $resolvedBuild"
    }
    Remove-Item $resolvedBuild -Recurse -Force
}

New-Item -ItemType Directory -Path $buildRoot -Force | Out-Null
$env:WDKContentRoot = $wdkRoot.TrimEnd('\') + '\'
$buildRootSlash = $buildRoot.TrimEnd('\') + '\'

$driverProject = Join-Path $repoRoot 'kernel\VerthysGuard.vcxproj'
$testProject = Join-Path $repoRoot 'kernel\tests\vtg_protocol_test.vcxproj'

$commonArgs = @(
    "/p:Configuration=$Configuration",
    '/p:Platform=x64',
    "/p:WindowsTargetPlatformVersion=$wdkVersion",
    "/p:VtgBuildRoot=$buildRootSlash",
    '/v:minimal',
    '/nologo'
)

Write-Host "Building VerthysGuard driver ($Configuration x64)"
& $msbuild $driverProject '/t:Rebuild' @commonArgs
if ($LASTEXITCODE -ne 0) {
    throw "Driver build failed with exit code $LASTEXITCODE"
}

Write-Host "Building protocol test ($Configuration x64)"
& $msbuild $testProject '/t:Rebuild' @commonArgs
if ($LASTEXITCODE -ne 0) {
    throw "Protocol test build failed with exit code $LASTEXITCODE"
}

$testExe = Join-Path $buildRoot "tests\$Configuration\vtg_protocol_test.exe"
if (-not (Test-Path $testExe)) {
    throw "Protocol test executable not found: $testExe"
}

& $testExe
if ($LASTEXITCODE -ne 0) {
    throw "Protocol test failed with exit code $LASTEXITCODE"
}

$driverDir = Join-Path $buildRoot 'driver'
$sysFile = Get-ChildItem $driverDir -Recurse -File -Filter 'VerthysGuard.sys' |
    Sort-Object FullName |
    Select-Object -First 1
$catFile = Get-ChildItem $driverDir -Recurse -File -Filter 'VerthysGuard.cat' |
    Sort-Object FullName |
    Select-Object -First 1
$infFile = Get-ChildItem $driverDir -Recurse -File -Filter 'VerthysGuard.inf' |
    Sort-Object FullName |
    Select-Object -First 1

if ($null -eq $sysFile -or $null -eq $catFile -or $null -eq $infFile) {
    throw 'Driver artifacts are incomplete (sys/cat/inf)'
}

$version = (Get-Content (Join-Path $repoRoot 'VERSION') -Raw).Trim()
$signature = Get-AuthenticodeSignature $sysFile.FullName
$manifest = [ordered]@{
    product = 'VerthysGuard'
    configuration = $Configuration
    platform = 'x64'
    protocolMajor = 1
    protocolMinor = 0
    driverVersion = $version
    wdkVersion = $wdkVersion
    wdkContentRoot = $env:WDKContentRoot
    builtAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    sysPath = $sysFile.FullName
    sysSha256 = (Get-FileHash $sysFile.FullName -Algorithm SHA256).Hash
    catPath = $catFile.FullName
    catSha256 = (Get-FileHash $catFile.FullName -Algorithm SHA256).Hash
    infPath = $infFile.FullName
    infSha256 = (Get-FileHash $infFile.FullName -Algorithm SHA256).Hash
    signatureStatus = $signature.Status.ToString()
}

$manifestPath = Join-Path $buildRoot 'driver.artifacts.json'
$manifest | ConvertTo-Json -Depth 4 | Set-Content -Path $manifestPath -Encoding UTF8
Write-Host "Driver artifacts: $manifestPath"
Write-Host 'VerthysGuard build passed'
