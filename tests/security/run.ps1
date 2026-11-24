# tests/security/run.ps1 — 非内核安全测试统一入口。
#
# 用法：
#   pwsh tests/security/run.ps1 -Suite vault -Profile standard
#   pwsh tests/security/run.ps1 -Suite vault -Profile release -A6EvidenceDir <dir>
#   pwsh tests/security/run.ps1 -Suite vault -Profile baseline
#   pwsh tests/security/run.ps1 -Suite service -Profile standard -ServiceBuildDir build_security_service
#   pwsh tests/security/run.ps1 -Suite tpm -Profile release -TpmProbe <path>
#   pwsh tests/security/run.ps1 -Suite offmachine -OffmachineMode prepare -OffmachineDir <dir>
#
# 产物：result.json / result.junit.xml / result.sarif / summary.md
# 退出码：0 成功；1 FAIL/ERROR；2 注册表/schema/未知 ID；3 release 必需项非 PASS

[CmdletBinding()]
param(
    [ValidateSet('vault', 'service', 'tpm', 'offmachine', 'all')]
    [string]$Suite = 'vault',
    [ValidateSet('dev', 'standard', 'release', 'baseline')]
    [string]$Profile = 'standard',
    [string]$OutDir,
    [switch]$Baseline,
    [string]$DllPath,
    [string]$BuildDir,
    [string]$ServiceBuildDir,
    [string]$WorkerPath,
    [string]$A6EvidenceDir,
    [ValidateSet('prepare', 'verify')]
    [string]$OffmachineMode = 'verify',
    [string]$OffmachineDir,
    [string]$TpmProbe,
    [switch]$KeepWork,
    [int]$TimeoutMinutes = 40
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$registryPath = Join-Path $PSScriptRoot 'cases.json'
$executeScript = Join-Path $PSScriptRoot 'suites'

Import-Module (Join-Path $PSScriptRoot 'lib/Registry.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'lib/Result.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'lib/Metadata.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'lib/Isolation.psm1') -Force

if ($Baseline) {
    $Profile = 'baseline'
    $Suite = 'vault'
}
if ($Profile -eq 'baseline' -and $Suite -ne 'vault') {
    Write-Host "配置错误：baseline profile 只接受 -Suite vault（实际 $Suite）" -ForegroundColor Red
    exit 2
}
if ($Suite -eq 'all' -and $Profile -eq 'baseline') {
    Write-Host '配置错误：baseline profile 不支持 -Suite all' -ForegroundColor Red
    exit 2
}

if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $repoRoot ('build/security/' + $Suite)
}
elseif (-not [System.IO.Path]::IsPathRooted($OutDir)) {
    $OutDir = Join-Path $repoRoot $OutDir
}
$OutDir = [System.IO.Path]::GetFullPath($OutDir)

$metadataError = $null
try {
    $metadata = Get-SecurityMetadata -RepoRoot $repoRoot -RegistryPath $registryPath `
        -DllPath $DllPath -WorkerPath $WorkerPath -ServiceBuildDir $ServiceBuildDir
}
catch {
    $metadataError = '元数据采集失败: ' + $_.Exception.Message
    $registryHash = Get-SecurityFileSha256 -Path $registryPath
    $metadata = [pscustomobject]@{
        gitCommit     = $null
        gitDirty      = $null
        osBuild       = [Environment]::OSVersion.Version.Build.ToString()
        powershell    = $PSVersionTable.PSVersion.ToString()
        dllSha256     = $null
        workerSha256  = $null
        serviceSha256 = $null
        registrySha256 = $(if ($null -eq $registryHash) { '' } else { $registryHash })
        dllPath       = $null
        workerPath    = $null
        servicePath   = $null
    }
}

$registryError = $null
try {
    $registry = Import-SecurityCaseRegistry -Path $registryPath
    if (-not $registry.Valid) {
        $registryError = '注册表校验失败: ' + ($registry.Errors -join '; ')
    }
}
catch {
    $registryError = '注册表加载失败: ' + $_.Exception.Message
    $registry = [pscustomobject]@{
        Path          = $registryPath
        SchemaVersion = 0
        Cases         = @()
        ById          = @{}
        ByLegacy      = @{}
        Valid         = $false
        Errors        = @($registryError)
    }
}

$workDir = New-SecurityTempDir
$caseIds = $null
if ($Suite -eq 'offmachine') {
    $caseIds = if ($OffmachineMode -eq 'prepare') { [string[]]@() } else { [string[]]@('VAULT-A06') }
}

$mode = if ($Profile -eq 'baseline') { 'Baseline' }
elseif ($Suite -eq 'offmachine') { "Offmachine-$OffmachineMode" }
else { 'PostFix' }

$context = New-SecurityRunContext -Registry $registry -Profile $Profile -Suite $Suite `
    -Mode $mode -OutDir $OutDir -RepoRoot $repoRoot -Metadata $metadata -WorkDir $workDir `
    -CaseIds $caseIds

if ($registryError) { $context.Errors.Add($registryError) }
if ($metadataError) { $context.Errors.Add($metadataError) }

$timeoutSeconds = [Math]::Max(1, $TimeoutMinutes) * 60
$suitesToRun = if ($Profile -eq 'baseline') { @('vault') }
elseif ($Suite -eq 'all') { @('vault', 'service', 'tpm') }
else { @($Suite) }

$resolvedDll = if (-not [string]::IsNullOrWhiteSpace($DllPath)) { $DllPath } else { $metadata.dllPath }
$resolvedTpmProbe = $TpmProbe
if ([string]::IsNullOrWhiteSpace($resolvedTpmProbe) -and -not [string]::IsNullOrWhiteSpace($BuildDir)) {
    $resolvedTpmProbe = Join-Path $BuildDir 'tests/Release/vty_tpm_probe.exe'
}
$resolvedOffmachineProbe = if (-not [string]::IsNullOrWhiteSpace($BuildDir)) {
    Join-Path $BuildDir 'tests/Release/vty_probe.exe'
}
else {
    Join-Path $repoRoot 'build/core/tests/Release/vty_probe.exe'
}

foreach ($suiteName in $suitesToRun) {
    $adapter = Join-Path $executeScript ($suiteName + '.ps1')
    $suiteWork = Join-Path $workDir $suiteName
    New-Item -ItemType Directory -Path $suiteWork -Force | Out-Null

    $adapterParams = @{
        RepoRoot     = $repoRoot
        RegistryPath = $registryPath
        Profile      = $Profile
        WorkDir      = $suiteWork
        TimeoutSeconds = $timeoutSeconds
    }
    switch ($suiteName) {
        'vault' {
            if (-not [string]::IsNullOrWhiteSpace($resolvedDll)) { $adapterParams.DllPath = $resolvedDll }
            if (-not [string]::IsNullOrWhiteSpace($A6EvidenceDir)) { $adapterParams.A6EvidenceDir = $A6EvidenceDir }
            if ($Profile -eq 'baseline') { $adapterParams.Baseline = $true }
            if ($KeepWork) { $adapterParams.KeepWork = $true }
        }
        'service' {
            if (-not [string]::IsNullOrWhiteSpace($ServiceBuildDir)) { $adapterParams.ServiceBuildDir = $ServiceBuildDir }
        }
        'tpm' {
            if (-not [string]::IsNullOrWhiteSpace($resolvedTpmProbe)) { $adapterParams.TpmProbe = $resolvedTpmProbe }
            if (-not [string]::IsNullOrWhiteSpace($BuildDir)) { $adapterParams.BuildDir = $BuildDir }
        }
        'offmachine' {
            $adapterParams.OffmachineMode = $OffmachineMode
            if (-not [string]::IsNullOrWhiteSpace($OffmachineDir)) { $adapterParams.OffmachineDir = $OffmachineDir }
            $adapterParams.ProbePath = $resolvedOffmachineProbe
        }
    }

    try {
        if (-not (Test-Path -LiteralPath $adapter)) {
            throw "适配器缺失: $adapter"
        }
        $rows = @(& $adapter @adapterParams)
        foreach ($row in $rows) {
            if ($null -eq $row) { continue }
            if ($null -eq $row.PSObject.Properties['Id']) {
                $context.Errors.Add("适配器 $suiteName 返回无 Id 的结果")
                continue
            }
            $durationMs = if ($null -ne $row.PSObject.Properties['DurationMs']) { [int]$row.DurationMs } else { 0 }
            $executorExit = if ($null -ne $row.PSObject.Properties['ExecutorExit']) { $row.ExecutorExit } else { $null }
            Add-SecurityCaseResult -Context $context -Id ([string]$row.Id) -Status ([string]$row.Status) `
                -Expected ([string]$row.Expected) -Observed ([string]$row.Observed) `
                -Evidence ([string]$row.Evidence) -DurationMs $durationMs -ExecutorExit $executorExit
        }
    }
    catch {
        $context.Errors.Add("套件 $suiteName 执行异常: $($_.Exception.Message)")
    }
}

$evidenceDir = Copy-SecurityWorkArtifacts -WorkDir $workDir -OutDir $OutDir -RunId $context.RunId
Update-SecurityEvidencePaths -Context $context -OldRoot $workDir -NewRoot $evidenceDir

$artifacts = Write-SecurityArtifacts -Context $context
$summary = Get-SecuritySummary -Context $context
$exitCode = Get-SecurityExitCode -Context $context

Write-Host ''
Write-Host ("=== Verthys security suite: {0} / {1} ===" -f $Suite, $Profile) -ForegroundColor Cyan
Write-Host ("PASS {0} · FAIL {1} · SKIP {2} · BLOCKED {3} · ERROR {4} · NOT_RUN {5} · requiredFailures {6}" -f
    $summary.pass, $summary.fail, $summary.skip, $summary.blocked, $summary.error,
    $summary.notRun, $summary.requiredFailures)
Write-Host ("用例构成: behavioral {0} · static {1} · evidence {2} · control {3}" -f
    $summary.behavioral, $summary.static, $summary.evidence, $summary.control)
foreach ($row in @(Get-SecurityCaseRows -Context $context)) {
    $color = switch ($row.status) {
        'PASS' { 'Green' }
        'FAIL' { 'Red' }
        'ERROR' { 'Red' }
        'BLOCKED' { 'Yellow' }
        default { 'DarkYellow' }
    }
    Write-Host ("  [{0}] {1} ({2}): {3}" -f $row.status, $row.id, $row.legacyId, $row.observed) -ForegroundColor $color
}
if ($context.Errors.Count -gt 0) {
    foreach ($message in $context.Errors) {
        Write-Host ("  [ERR ] " + $message) -ForegroundColor Red
    }
}
Write-Host ("证据: {0}" -f $artifacts.Json)
Write-Host ("JUnit: {0}" -f $artifacts.JUnit)
Write-Host ("SARIF: {0}" -f $artifacts.Sarif)
Write-Host ("摘要: {0}" -f $artifacts.Markdown)
if ($KeepWork) { Write-Host ("工作目录: {0}" -f $workDir) }

Remove-SecurityTempDir -Path $workDir -Keep:$KeepWork
exit $exitCode
