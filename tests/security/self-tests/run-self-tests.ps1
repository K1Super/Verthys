# tests/security/self-tests/run-self-tests.ps1 — 框架自检。
#
# 覆盖：注册表结构、ID 命名空间、profile 选择、状态策略、退出码、
# schema 结构校验、四类证据生成、证据复制与路径改写、进程参数转义。
# 不依赖真实构建产物，可在任意 Windows + PowerShell 7 上运行。

[CmdletBinding()]
param([switch]$KeepWork)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$securityRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$registryPath = Join-Path $securityRoot 'cases.json'

Import-Module (Join-Path $securityRoot 'lib/Registry.psm1') -Force
Import-Module (Join-Path $securityRoot 'lib/Result.psm1') -Force
Import-Module (Join-Path $securityRoot 'lib/Metadata.psm1') -Force
Import-Module (Join-Path $securityRoot 'lib/Isolation.psm1') -Force
Import-Module (Join-Path $securityRoot 'lib/Process.psm1') -Force

$script:Checks = 0
$script:Failures = New-Object System.Collections.Generic.List[string]
$root = New-SecurityTempDir -Prefix 'verthys_selftest_'

function Assert-True {
    param([bool]$Condition, [string]$Message)
    $script:Checks++
    if ($Condition) {
        Write-Host "[PASS] $Message" -ForegroundColor Green
    }
    else {
        $script:Failures.Add($Message)
        Write-Host "[FAIL] $Message" -ForegroundColor Red
    }
}

function Assert-Equal {
    param($Expected, $Actual, [string]$Message)
    $ok = ($Expected -eq $Actual)
    if ($ok) {
        Assert-True -Condition $true -Message $Message
    }
    else {
        Assert-True -Condition $false -Message ("{0}（期望 {1}，实际 {2}）" -f $Message, $Expected, $Actual)
    }
}

function New-FakeMetadata {
    return [pscustomobject]@{
        gitCommit     = 'deadbeef'
        gitDirty      = $false
        osBuild       = '22631'
        powershell    = '7.4.0'
        dllSha256     = $null
        workerSha256  = $null
        serviceSha256 = $null
        registrySha256 = ('a' * 64)
    }
}

function New-TestContext {
    param([string]$Profile = 'standard', [string]$Suite = 'vault', [string]$OutDir = $root)
    return New-SecurityRunContext -Registry $registry -Profile $Profile -Suite $Suite -Mode 'PostFix' `
        -OutDir $OutDir -RepoRoot $repoRoot -Metadata (New-FakeMetadata) -WorkDir $root
}

function New-MinimalCase {
    param([string]$Id, [string]$Legacy, [string]$Suite = 'vault', [string]$Kind = 'behavioral')
    return [ordered]@{
        id          = $Id
        legacyId    = $Legacy
        suite       = $Suite
        name        = "case $Id"
        severity    = 'high'
        requirement = 'P0-A'
        kind        = $Kind
        requiredIn  = @('standard')
        executor    = 'tests/attack/run.ps1'
        evidence    = 'x.json'
        description = 'self-test'
    }
}

function Write-TestRegistry {
    param([string]$Name, $Cases)
    $path = Join-Path $root $Name
    $document = [ordered]@{ schemaVersion = 1; cases = @($Cases) }
    [System.IO.File]::WriteAllText($path, ($document | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
    return $path
}

try {
    $registry = Import-SecurityCaseRegistry -Path $registryPath
    Assert-True -Condition $registry.Valid -Message '注册表通过结构校验'
    Assert-Equal -Expected 33 -Actual $registry.Cases.Count -Message '注册表用例总数为 33'

    # ID 唯一性与命名空间
    Assert-Equal -Expected $registry.Cases.Count -Actual $registry.ById.Count -Message '用例 ID 无重复'
    Assert-Equal -Expected $registry.Cases.Count -Actual $registry.ByLegacy.Count -Message 'legacyId 无重复'

    # 既有覆盖必须全部登记
    $requiredLegacy = @('PC-1', 'SC-1', 'BC-1',
        'A1', 'A1b', 'A2', 'A3', 'A4', 'A5', 'A6', 'A6b', 'A7', 'A8', 'A9', 'A10',
        'A11', 'A12', 'A13', 'A14', 'A15', 'A16', 'A17', 'A18', 'A18S', 'A20', 'A20b',
        'S-A3', 'S-A4', 'S-A5', 'S-A6', 'S-A8', 'S-A9', 'VTPM')
    foreach ($legacy in $requiredLegacy) {
        Assert-True -Condition $registry.ByLegacy.ContainsKey($legacy) -Message "登记 legacyId $legacy"
    }

    # profile 选择
    $vaultStandard = @(Resolve-SecurityCaseSelection -Registry $registry -Suite vault -Profile standard)
    $serviceStandard = @(Resolve-SecurityCaseSelection -Registry $registry -Suite service -Profile standard)
    $tpmStandard = @(Resolve-SecurityCaseSelection -Registry $registry -Suite tpm -Profile standard)
    $baseline = @(Resolve-SecurityCaseSelection -Registry $registry -Suite vault -Profile baseline)
    Assert-Equal -Expected 25 -Actual $vaultStandard.Count -Message 'vault standard 选择 25 项'
    Assert-Equal -Expected 6 -Actual $serviceStandard.Count -Message 'service standard 选择 6 项'
    Assert-Equal -Expected 1 -Actual $tpmStandard.Count -Message 'tpm standard 选择 1 项'
    Assert-Equal -Expected 1 -Actual $baseline.Count -Message 'baseline 仅选择 1 项'
    Assert-Equal -Expected 'CTRL-BC1' -Actual $baseline[0].id -Message 'baseline 选择 CTRL-BC1'
    Assert-True -Condition (-not (@($vaultStandard | Where-Object { $_.id -eq 'CTRL-BC1' }).Count -gt 0)) -Message 'standard 不包含 baseline 专用用例'

    # 注册表负向 fixture
    $caseA = New-MinimalCase -Id 'VAULT-X01' -Legacy 'X1'
    $caseB = New-MinimalCase -Id 'VAULT-X01' -Legacy 'X2'
    $duplicate = Import-SecurityCaseRegistry -Path (Write-TestRegistry -Name 'dup-id.json' -Cases @($caseA, $caseB))
    Assert-True -Condition (-not $duplicate.Valid) -Message '重复 ID 被拒绝'
    Assert-True -Condition (@($duplicate.Errors | Where-Object { $_ -match '重复用例 ID' }).Count -gt 0) -Message '重复 ID 错误信息明确'

    $legacyDupA = New-MinimalCase -Id 'VAULT-X02' -Legacy 'X9'
    $legacyDupB = New-MinimalCase -Id 'VAULT-X03' -Legacy 'X9'
    $duplicateLegacy = Import-SecurityCaseRegistry -Path (Write-TestRegistry -Name 'dup-legacy.json' -Cases @($legacyDupA, $legacyDupB))
    Assert-True -Condition (-not $duplicateLegacy.Valid) -Message '重复 legacyId 被拒绝'

    $badSuite = New-MinimalCase -Id 'VAULT-X04' -Legacy 'X4'
    $badSuite.suite = 'kernel'
    $suiteFixture = Import-SecurityCaseRegistry -Path (Write-TestRegistry -Name 'bad-suite.json' -Cases @($badSuite))
    Assert-True -Condition (-not $suiteFixture.Valid) -Message '未知 suite 被拒绝'

    $badLegacy = New-MinimalCase -Id 'VAULT-X05' -Legacy ''
    $legacyFixture = Import-SecurityCaseRegistry -Path (Write-TestRegistry -Name 'bad-legacy.json' -Cases @($badLegacy))
    Assert-True -Condition (-not $legacyFixture.Valid) -Message '缺失 legacyId 被拒绝'

    $badKind = New-MinimalCase -Id 'VAULT-X06' -Legacy 'X6' -Kind 'probe'
    $kindFixture = Import-SecurityCaseRegistry -Path (Write-TestRegistry -Name 'bad-kind.json' -Cases @($badKind))
    Assert-True -Condition (-not $kindFixture.Valid) -Message '未知 kind 被拒绝'

    # 状态归一
    Assert-Equal -Expected 'PASS' -Actual (ConvertTo-SecurityStatus -Verdict 'PASS') -Message 'verdict PASS 归一'
    Assert-Equal -Expected 'BLOCKED' -Actual (ConvertTo-SecurityStatus -Verdict 'SKELETON' -Kind 'evidence') -Message 'SKELETON evidence 归一为 BLOCKED'
    Assert-Equal -Expected 'SKIP' -Actual (ConvertTo-SecurityStatus -Verdict 'KNOWN_GAP' -Kind 'behavioral') -Message 'KNOWN_GAP 行为用例归一为 SKIP'
    Assert-Equal -Expected 'ERROR' -Actual (ConvertTo-SecurityStatus -Verdict 'WHAT') -Message '未知 verdict 归一为 ERROR'

    # 退出码策略
    $releaseCtx = New-TestContext -Profile release
    Add-SecurityCaseResult -Context $releaseCtx -Id 'VAULT-A01' -Status 'SKIP' `
        -Expected '全部拒绝' -Observed '环境不满足'
    Assert-Equal -Expected 3 -Actual (Get-SecurityExitCode -Context $releaseCtx) -Message 'release 必需项 SKIP 退出码 3'

    $standardCtx = New-TestContext -Profile standard
    Add-SecurityCaseResult -Context $standardCtx -Id 'VAULT-A01' -Status 'SKIP' `
        -Expected '全部拒绝' -Observed '环境不满足'
    Assert-Equal -Expected 0 -Actual (Get-SecurityExitCode -Context $standardCtx) -Message 'standard 容忍 SKIP'

    $failCtx = New-TestContext -Profile release
    Add-SecurityCaseResult -Context $failCtx -Id 'VAULT-A01' -Status 'FAIL' `
        -Expected '全部拒绝' -Observed '公开常量解锁成功'
    Assert-Equal -Expected 1 -Actual (Get-SecurityExitCode -Context $failCtx) -Message 'FAIL 退出码 1'

    $errorCtx = New-TestContext -Profile standard
    Add-SecurityCaseResult -Context $errorCtx -Id 'VAULT-A01' -Status 'ERROR' `
        -Expected '全部拒绝' -Observed '执行器异常'
    Assert-Equal -Expected 1 -Actual (Get-SecurityExitCode -Context $errorCtx) -Message 'ERROR 退出码 1'

    $unknownCtx = New-TestContext -Profile standard
    Add-SecurityCaseResult -Context $unknownCtx -Id 'VAULT-NOPE' -Status 'PASS' `
        -Expected 'x' -Observed 'y'
    Assert-Equal -Expected 2 -Actual (Get-SecurityExitCode -Context $unknownCtx) -Message '未知 ID 退出码 2'

    $duplicateCtx = New-TestContext -Profile standard
    Add-SecurityCaseResult -Context $duplicateCtx -Id 'VAULT-A01' -Status 'PASS' `
        -Expected '全部拒绝' -Observed '拒绝'
    Add-SecurityCaseResult -Context $duplicateCtx -Id 'VAULT-A01' -Status 'FAIL' `
        -Expected '全部拒绝' -Observed '解锁成功'
    Assert-Equal -Expected 2 -Actual (Get-SecurityExitCode -Context $duplicateCtx) -Message '重复结果退出码 2'

    $missingFieldsCtx = New-TestContext -Profile standard
    Add-SecurityCaseResult -Context $missingFieldsCtx -Id 'VAULT-A01' -Status 'PASS' `
        -Expected '' -Observed ''
    Assert-Equal -Expected 'ERROR' -Actual $missingFieldsCtx.Results[0].status -Message '缺少 expected/observed 自动降级为 ERROR'

    $baselineEmpty = New-TestContext -Profile baseline
    Assert-Equal -Expected 3 -Actual (Get-SecurityExitCode -Context $baselineEmpty) -Message 'baseline 缺少正控退出码 3'
    Add-SecurityCaseResult -Context $baselineEmpty -Id 'CTRL-BC1' -Status 'PASS' `
        -Expected 'OK' -Observed 'rc=0'
    Assert-Equal -Expected 0 -Actual (Get-SecurityExitCode -Context $baselineEmpty) -Message 'baseline 正控 PASS 退出码 0'

    $blockedCtx = New-TestContext -Profile release
    Add-SecurityCaseResult -Context $blockedCtx -Id 'VAULT-A06' -Status 'BLOCKED' `
        -Expected '离机后 fail-closed' -Observed '未提供离机报告'
    Assert-Equal -Expected 3 -Actual (Get-SecurityExitCode -Context $blockedCtx) -Message 'release 证据缺失 BLOCKED 退出码 3'

    $blockedStandardCtx = New-TestContext -Profile standard
    Add-SecurityCaseResult -Context $blockedStandardCtx -Id 'VAULT-A06' -Status 'BLOCKED' `
        -Expected '离机后 fail-closed' -Observed '未提供离机报告'
    Assert-Equal -Expected 0 -Actual (Get-SecurityExitCode -Context $blockedStandardCtx) -Message 'standard 容忍 BLOCKED'

    $releaseMissingCtx = New-TestContext -Profile release
    Assert-Equal -Expected 3 -Actual (Get-SecurityExitCode -Context $releaseMissingCtx) -Message 'release 无结果时必需项 NOT_RUN 退出码 3'

    # release 成功路径：单用例注册表，required 全部 PASS
    $releaseCase = New-MinimalCase -Id 'VAULT-X07' -Legacy 'X7'
    $releaseCase.requiredIn = @('release')
    $releaseRegistry = Import-SecurityCaseRegistry -Path (Write-TestRegistry -Name 'release-ok.json' -Cases @($releaseCase))
    $releaseOkCtx = New-SecurityRunContext -Registry $releaseRegistry -Profile release -Suite vault -Mode 'PostFix' `
        -OutDir $root -RepoRoot $repoRoot -Metadata (New-FakeMetadata) -WorkDir $root
    Add-SecurityCaseResult -Context $releaseOkCtx -Id 'VAULT-X07' -Status 'PASS' `
        -Expected '拒绝' -Observed '拒绝'
    Assert-Equal -Expected 0 -Actual (Get-SecurityExitCode -Context $releaseOkCtx) -Message 'release 必需项全部 PASS 退出码 0'

    # 单用例文档必须保持 cases 为数组，防止单元素数组被管道展开
    $singleCtx = New-TestContext -Profile standard -Suite tpm
    Add-SecurityCaseResult -Context $singleCtx -Id 'TPM-VTPM' -Status 'PASS' `
        -Expected '能力成立' -Observed 'PASS'
    $singleDocument = Get-SecurityResultDocument -Context $singleCtx
    Assert-True -Condition ($singleDocument['cases'] -is [System.Array]) -Message '单用例文档 cases 仍为数组'
    Assert-Equal -Expected 1 -Actual @($singleDocument['cases']).Count -Message '单用例文档 cases 数量为 1'
    Assert-True -Condition (Test-SecurityResultDocument -Document $singleDocument).Valid -Message '单用例文档通过 schema 校验'

    # 证据生成与 schema 校验
    $artifactCtx = New-TestContext -Profile standard -OutDir (Join-Path $root 'artifacts')
    Add-SecurityCaseResult -Context $artifactCtx -Id 'VAULT-A01' -Status 'PASS' `
        -Expected '全部拒绝' -Observed 'constant/empty/weak 均拒绝' -Evidence 'executor.json' -DurationMs 12
    Add-SecurityCaseResult -Context $artifactCtx -Id 'VAULT-A03' -Status 'FAIL' `
        -Expected 'LOCKED' -Observed 'rc=0' -DurationMs 5
    Add-SecurityCaseResult -Context $artifactCtx -Id 'VAULT-A04' -Status 'SKIP' `
        -Expected '零命中' -Observed '前置不满足'
    $artifacts = Write-SecurityArtifacts -Context $artifactCtx
    Assert-True -Condition (Test-Path -LiteralPath $artifacts.Json) -Message 'result.json 已生成'
    Assert-True -Condition (Test-Path -LiteralPath $artifacts.JUnit) -Message 'result.junit.xml 已生成'
    Assert-True -Condition (Test-Path -LiteralPath $artifacts.Sarif) -Message 'result.sarif 已生成'
    Assert-True -Condition (Test-Path -LiteralPath $artifacts.Markdown) -Message 'summary.md 已生成'

    $jsonDocument = Get-Content -LiteralPath $artifacts.Json -Raw | ConvertFrom-Json
    $schemaCheck = Test-SecurityResultDocument -Document $jsonDocument
    Assert-True -Condition $schemaCheck.Valid -Message 'result.json 通过 schema 结构校验'
    if (-not $schemaCheck.Valid) {
        foreach ($message in $schemaCheck.Errors) { Write-Host "    schema: $message" -ForegroundColor Red }
    }
    try {
        $schemaFile = Join-Path $securityRoot 'schema/result.schema.json'
        $rawValid = Test-Json -Path $artifacts.Json -SchemaFile $schemaFile -ErrorAction Stop
        Assert-True -Condition $rawValid -Message 'result.json 通过 JSON Schema 校验'
    }
    catch {
        Assert-True -Condition $false -Message ('JSON Schema 校验失败: ' + $_.Exception.Message)
    }

    $junit = [xml](Get-Content -LiteralPath $artifacts.JUnit -Raw)
    Assert-Equal -Expected 'testsuites' -Actual $junit.DocumentElement.LocalName -Message 'JUnit 根节点正确'
    $sarif = Get-Content -LiteralPath $artifacts.Sarif -Raw | ConvertFrom-Json
    Assert-Equal -Expected '2.1.0' -Actual $sarif.version -Message 'SARIF 版本为 2.1.0'
    $markdown = Get-Content -LiteralPath $artifacts.Markdown -Raw
    Assert-True -Condition ($markdown -match 'VAULT-A01') -Message 'Markdown 含用例 ID'

    # schema 负向
    $badDocument = Get-SecurityResultDocument -Context $artifactCtx
    $badDocument.Remove('runId')
    Assert-True -Condition (-not (Test-SecurityResultDocument -Document $badDocument).Valid) -Message 'schema 拒绝缺失 runId'

    $badDocument2 = Get-SecurityResultDocument -Context $artifactCtx
    $badDocument2['cases'][0]['status'] = 'BOGUS'
    Assert-True -Condition (-not (Test-SecurityResultDocument -Document $badDocument2).Valid) -Message 'schema 拒绝非法状态'

    $badDocument3 = Get-SecurityResultDocument -Context $artifactCtx
    $badDocument3['unexpected'] = 1
    Assert-True -Condition (-not (Test-SecurityResultDocument -Document $badDocument3).Valid) -Message 'schema 拒绝未声明字段'

    # 元数据
    $metadata = Get-SecurityMetadata -RepoRoot $repoRoot -RegistryPath $registryPath
    Assert-True -Condition ($metadata.registrySha256 -match '^[0-9a-f]{64}$') -Message '注册表 SHA-256 为 64 位小写'
    Assert-True -Condition (-not [string]::IsNullOrWhiteSpace([string]$metadata.osBuild)) -Message 'OS build 已采集'
    Assert-True -Condition (-not [string]::IsNullOrWhiteSpace([string]$metadata.powershell)) -Message 'PowerShell 版本已采集'

    # 证据复制与路径改写
    $copySource = Join-Path $root 'copy-source'
    New-Item -ItemType Directory -Path $copySource -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $copySource 'executor.json') -Value '{"ok":true}' -Encoding utf8
    $copyContext = New-TestContext -Profile standard -OutDir (Join-Path $root 'copy-out')
    Add-SecurityCaseResult -Context $copyContext -Id 'VAULT-A01' -Status 'PASS' `
        -Expected 'x' -Observed 'y' -Evidence (Join-Path $copySource 'executor.json')
    $copyDestination = Copy-SecurityWorkArtifacts -WorkDir $copySource -OutDir $copyContext.OutDir -RunId 'run-test'
    Update-SecurityEvidencePaths -Context $copyContext -OldRoot $copySource -NewRoot $copyDestination
    Assert-True -Condition (Test-Path -LiteralPath (Join-Path $copyDestination 'executor.json')) -Message '证据文件已复制'
    Assert-True -Condition ($copyContext.Results[0].evidence.StartsWith($copyDestination)) -Message '证据路径已改写'

    # 进程参数转义
    Assert-Equal -Expected '"a b" c' -Actual (ConvertTo-SecurityArgumentString -Arguments @('a b', 'c')) -Message '参数含空格时加引号'
    Assert-Equal -Expected '""' -Actual (ConvertTo-SecurityArgumentString -Arguments @('')) -Message '空参数转义为双引号'
    Assert-Equal -Expected '"a\"b"' -Actual (ConvertTo-SecurityArgumentString -Arguments @('a"b')) -Message '内嵌双引号转义'

    # 子进程 UTF-8 与退出码传播
    $childScript = Join-Path $root 'encoding-child.ps1'
    [System.IO.File]::WriteAllText($childScript,
        "Write-Output '中文观测'; exit 7`r`n",
        (New-Object System.Text.UTF8Encoding($false)))
    $childRun = Invoke-SecurityPowerShellScript -ScriptPath $childScript -TimeoutSeconds 60
    Assert-True -Condition ($childRun.StdOut -match '中文观测') -Message '子进程中文输出按 UTF-8 解码'
    Assert-Equal -Expected 7 -Actual $childRun.ExitCode -Message '子进程退出码正确传播'
}
catch {
    $script:Failures.Add('自检异常: ' + $_.Exception.Message)
    Write-Host ('[FAIL] 自检异常: ' + $_.Exception.Message) -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
}
finally {
    Remove-SecurityTempDir -Path $root -Keep:$KeepWork
}

Write-Host ''
if ($script:Failures.Count -gt 0) {
    Write-Host ("=== self-tests: {0} checks, {1} failed ===" -f $script:Checks, $script:Failures.Count) -ForegroundColor Red
    foreach ($message in $script:Failures) { Write-Host ("  - " + $message) -ForegroundColor Red }
    exit 1
}
Write-Host ("=== self-tests: {0} checks, 0 failed ===" -f $script:Checks) -ForegroundColor Green
exit 0
