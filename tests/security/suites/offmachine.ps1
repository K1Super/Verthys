# tests/security/suites/offmachine.ps1 — 离机证据（A6）适配器。
#
# prepare 只生成可复制包，不计入用例结果；verify 在目标机执行并产出
# VAULT-A06 结论。当前构建绑定由执行器自身校验，适配器不重复解释哈希。

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RepoRoot,
    [Parameter(Mandatory = $true)][string]$RegistryPath,
    [Parameter(Mandatory = $true)][string]$Profile,
    [Parameter(Mandatory = $true)][string]$WorkDir,
    [ValidateSet('prepare', 'verify')][string]$OffmachineMode = 'verify',
    [string]$OffmachineDir,
    [string]$ProbePath,
    [int]$TimeoutSeconds = 1800
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '../lib/Registry.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '../lib/Result.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '../lib/Process.psm1') -Force

$registry = Import-SecurityCaseRegistry -Path $RegistryPath
if (-not $registry.ById.ContainsKey('VAULT-A06')) {
    throw '注册表缺少 VAULT-A06'
}
$case = $registry.ById['VAULT-A06']

if ([string]::IsNullOrWhiteSpace($ProbePath)) {
    $ProbePath = Join-Path $RepoRoot 'build/core/tests/Release/vty_probe.exe'
}

$executor = Join-Path $RepoRoot 'tests/attack/offmachine/run.ps1'
if (-not (Test-Path -LiteralPath $executor)) {
    return @([pscustomobject]@{
            Id           = 'VAULT-A06'
            Status       = 'ERROR'
            Expected     = [string]$case.description
            Observed     = 'tests/attack/offmachine/run.ps1 缺失'
            Evidence     = $executor
            DurationMs   = 0
            ExecutorExit = $null
        })
}

function New-OffmachineRow {
    param([string]$Status, [string]$Observed, [string]$Evidence, $ExecutorExit = $null)
    return [pscustomobject]@{
        Id           = 'VAULT-A06'
        Status       = $Status
        Expected     = [string]$case.description
        Observed     = $Observed
        Evidence     = $Evidence
        DurationMs   = 0
        ExecutorExit = $ExecutorExit
    }
}

if ([string]::IsNullOrWhiteSpace($OffmachineDir)) {
    if ($OffmachineMode -eq 'prepare') {
        throw 'prepare 需要 -OffmachineDir'
    }
    return @(New-OffmachineRow -Status 'BLOCKED' `
            -Observed '未提供离机包目录；release 需要绑定当前构建的离机报告' `
            -Evidence 'tests/attack/offmachine/run.ps1')
}

$reportPath = Join-Path $WorkDir 'a6-report.json'
$arguments = @('-Mode', $OffmachineMode, '-Dir', $OffmachineDir, '-Probe', $ProbePath)
if ($OffmachineMode -eq 'verify') { $arguments += @('-OutJson', $reportPath) }

$run = Invoke-SecurityPowerShellScript -ScriptPath $executor -Arguments $arguments -TimeoutSeconds $TimeoutSeconds
$evidence = '{0}; executorExit={1}; durationMs={2}' -f $reportPath, $run.ExitCode, $run.DurationMs

if ($OffmachineMode -eq 'prepare') {
    $ready = @(($run.StdOut + "`n" + $run.StdErr) -split "`r?`n" | Where-Object { $_ -match '^PACKAGE READY ' })
    if ($run.ExitCode -ne 0 -or $ready.Count -eq 0) {
        $tail = Get-SecurityTextTail -Text ($run.StdErr + ' ' + $run.StdOut) -MaxLength 500
        throw "prepare 失败（exit=$($run.ExitCode)）：$tail"
    }
    Write-Host ("[offmachine] 包已生成: {0}" -f $OffmachineDir)
    return @()
}

$verdict = ''
$detail = ''
foreach ($line in @(($run.StdOut + "`n" + $run.StdErr) -split "`r?`n")) {
    if ($line -match '^RESULT A6 (PASS|FAIL) (.*)$') {
        $verdict = $Matches[1]
        $detail = $Matches[2]
        break
    }
}
if ($verdict -eq '' -and (Test-Path -LiteralPath $reportPath)) {
    try {
        $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
        if ($null -ne $report.PSObject.Properties['verdict']) {
            $verdict = [string]$report.verdict
            if ($null -ne $report.PSObject.Properties['detail']) { $detail = [string]$report.detail }
        }
    }
    catch {
        # 报告损坏时保持 ERROR。
    }
}

if ($verdict -eq '') {
    $tail = Get-SecurityTextTail -Text ($run.StdErr + ' ' + $run.StdOut) -MaxLength 500
    $observed = if ($run.TimedOut) { "执行器超时 $TimeoutSeconds s" } else { '执行器未返回 A6 结果' }
    if ($tail) { $observed = "$observed；输出: $tail" }
    return @(New-OffmachineRow -Status 'ERROR' -Observed $observed -Evidence $evidence -ExecutorExit $run.ExitCode)
}

$status = ConvertTo-SecurityStatus -Verdict $verdict -Kind ([string]$case.kind)
if ([string]::IsNullOrWhiteSpace($detail)) { $detail = "执行器返回 $verdict" }
return @(New-OffmachineRow -Status $status -Observed $detail -Evidence $evidence -ExecutorExit $run.ExitCode)
