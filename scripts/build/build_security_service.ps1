# scripts/build/build_security_service.ps1 — 安全服务独立构建/签名/测试入口
#
# 用法：
#   pwsh -File scripts/build/build_security_service.ps1 -Profile local -TestHooks -RunTests
#   pwsh -File scripts/build/build_security_service.ps1 -Profile production
#
# 生产构建必须提供发布者证书与钉扎指纹；本地构建禁止分发未签名产物。
param(
    [string]$BuildDir = "",
    [ValidateSet("local", "production")]
    [string]$Profile = "local",
    [ValidateSet("Debug", "Release")]
    [string]$Config = "",
    [switch]$TestHooks,
    [switch]$RunTests,
    [switch]$NoSign,
    [string]$PublisherSha256 = ""
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repoRoot "scripts\lib\env.load.ps1")

$isProduction = $Profile -eq "production"
if ([string]::IsNullOrEmpty($BuildDir)) {
    $BuildDir = Join-Path $repoRoot "build_security_service"
}
if ([string]::IsNullOrEmpty($Config)) {
    $Config = if ($isProduction) { "Release" } else { "Debug" }
}
if ($isProduction) {
    $TestHooks = $false
    if ($NoSign) { throw "production build refuses -NoSign" }
} elseif ($TestHooks) {
    # local 默认不启用 hooks；显式 -TestHooks 才构建测试二进制。
}

$sourceDir = Join-Path $repoRoot "security-service"
$versionLine = (Get-Content -LiteralPath (Join-Path $repoRoot "VERSION") -Raw).Trim()

# 解析签名上下文（生产必须成功；本地可选）。
$signContext = $null
if (-not $NoSign) {
    . (Join-Path $repoRoot "scripts\lib\release_signing.ps1")
    $signContext = Resolve-VerthysReleaseSigning -Required:$isProduction
    if ($null -ne $signContext -and $signContext.Enabled) {
        if (-not [string]::IsNullOrEmpty($PublisherSha256)) {
            $explicit = ConvertTo-VerthysPublisherSha256 -Raw $PublisherSha256 -SourceName "PublisherSha256"
            $derived = Get-VerthysCertificateSha256 -Certificate $signContext.Certificate
            if ($explicit -ne $derived) {
                throw "PublisherSha256 与签名证书不一致：$explicit != $derived"
            }
            $signContext.PublisherSha256 = $explicit
        }
    }
}
$publisher = if ($null -ne $signContext -and $signContext.Enabled) { $signContext.PublisherSha256 } else { $PublisherSha256 }
if ($isProduction -and [string]::IsNullOrEmpty($publisher)) {
    throw "production 构建必须提供发布者钉扎指纹（证书库或 -PublisherSha256）"
}

# 根 CA 钉扎：构建前从发布者证书链导出根 CA，计算 DER SHA-256 并编入服务 exe。
# 干净机安装时先按该指纹校验载荷 CA，再导入 LocalMachine\Root，最后验服务签名。
$rootCaSha = ""
$rootCaDer = $null
if ($null -ne $signContext -and $signContext.Enabled) {
    $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    $chain.ChainPolicy.RevocationMode =
        [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    if (-not $chain.Build($signContext.Certificate)) {
        throw "无法构建发布者证书链，不能导出根 CA"
    }
    $rootCert = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
    $rootCaDer = $rootCert.RawData
    $rootCaSha = ([System.BitConverter]::ToString(
        [System.Security.Cryptography.SHA256]::Create().ComputeHash($rootCaDer))).Replace('-', '').ToLowerInvariant()
    if ($rootCaSha.Length -ne 64) {
        throw "根 CA SHA-256 计算失败"
    }
} elseif ($isProduction) {
    throw "production 构建必须导出并钉扎根 CA"
}

$cmake = $script:VERTHYS_CMAKE_EXE
$generator = $script:VERTHYS_VS_GENERATOR
$testHooksFlag = if ($TestHooks) { "ON" } else { "OFF" }
$requireSigFlag = if ($isProduction) { "ON" } else { "OFF" }
$configureArgs = @(
    "-S", $sourceDir,
    "-B", $BuildDir,
    "-G", $generator,
    "-A", "x64",
    "-DVERTHYS_SERVICE_TEST_HOOKS=$testHooksFlag",
    "-DVERTHYS_REQUIRE_SERVICE_SIG=$requireSigFlag",
    "-DVERTHYS_SERVICE_PUBLISHER_SHA256=$publisher",
    "-DVERTHYS_ROOT_CA_SHA256=$rootCaSha"
)
& $cmake @configureArgs
if ($LASTEXITCODE -ne 0) { throw "security-service configure failed" }

$targets = @("verthys_security_svc")
$targets += @("verthys_service_probe", "verthys_fake_service")
if ($TestHooks) { $targets += "verthys_service_tests" }
& $cmake --build $BuildDir --config $Config --target @targets
if ($LASTEXITCODE -ne 0) { throw "security-service build failed" }

if ($RunTests) {
    if (-not $TestHooks) { throw "-RunTests requires -TestHooks" }
    $ctest = Join-Path (Split-Path -Parent $cmake) "ctest.exe"
    & $ctest --test-dir $BuildDir -C $Config --output-on-failure --no-tests=error
    if ($LASTEXITCODE -ne 0) { throw "security-service tests failed" }
}

$outDir = Join-Path $BuildDir $Config
$serviceExe = Join-Path $outDir "VerthysSecuritySvc.exe"
$probeExe = Join-Path $outDir "verthys_service_probe.exe"

if ($null -ne $signContext -and $signContext.Enabled) {
    Invoke-VerthysAuthenticodeSign -Path $serviceExe `
        -Certificate $signContext.Certificate `
        -TimestampServer $signContext.TimestampServer
    Assert-VerthysAuthenticodeSignature -Path $serviceExe `
        -ExpectedSha256 $signContext.PublisherSha256 | Out-Null
} elseif ($isProduction) {
    throw "production artifacts must be signed"
}

$artifactDir = Join-Path $BuildDir "artifacts"
if (Test-Path -LiteralPath $artifactDir) {
    Remove-Item -LiteralPath $artifactDir -Recurse -Force
}
New-Item -ItemType Directory -Path $artifactDir | Out-Null
Copy-Item -LiteralPath $serviceExe -Destination $artifactDir
$rootCaPath = Join-Path $artifactDir "VerthysRootCA.cer"
if ($null -ne $rootCaDer) {
    [System.IO.File]::WriteAllBytes($rootCaPath, $rootCaDer)
}

function Get-Sha256Lower([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

$rootCaFileSha = if (Test-Path -LiteralPath $rootCaPath) {
    Get-Sha256Lower $rootCaPath
} else { "" }
if ($isProduction -and $rootCaFileSha -ne $rootCaSha) {
    throw "根 CA 载荷缺失或指纹不一致"
}

$artifacts = [ordered]@{
    version = $versionLine
    protocolVersion = 1
    buildTimeUtc = (Get-Date).ToUniversalTime().ToString("o")
    profile = $Profile
    configuration = $Config
    testHooks = $TestHooks.IsPresent
    signed = ($null -ne $signContext -and $signContext.Enabled)
    publisherSha256 = $publisher
    rootCaSha256 = $rootCaSha
    service = [ordered]@{
        path = "VerthysSecuritySvc.exe"
        sha256 = (Get-Sha256Lower (Join-Path $artifactDir "VerthysSecuritySvc.exe"))
    }
    rootCa = [ordered]@{
        path = "VerthysRootCA.cer"
        sha256 = $rootCaFileSha
    }
}
$artifacts | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $artifactDir "security-service.artifacts.json") -Encoding UTF8

Write-Host "[security-service] artifacts: $artifactDir" -ForegroundColor Green
Write-Host "  version=$versionLine protocol=1 signed=$($artifacts.signed) testHooks=$($artifacts.testHooks)"
Write-Host "  service sha256=$($artifacts.service.sha256)"
Write-Host "  rootCA  sha256=$($artifacts.rootCaSha256)"
