# tests/security/suites/vault.ps1 — 容器/核心执行器适配器。
#
# 调用 tests/attack/run.ps1 产出 JSON，再按 legacyId 映射到注册表。
# 执行器保持原样：适配器只做调用、解析、状态归一与缺口补齐。

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RepoRoot,
    [Parameter(Mandatory = $true)][string]$RegistryPath,
    [Parameter(Mandatory = $true)][string]$Profile,
    [Parameter(Mandatory = $true)][string]$WorkDir,
    [string]$DllPath,
    [string]$A6EvidenceDir,
    [switch]$Baseline,
    [switch]$KeepWork,
    [int]$TimeoutSeconds = 2400
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '../lib/Registry.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '../lib/Result.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '../lib/Process.psm1') -Force

$registry = Import-SecurityCaseRegistry -Path $RegistryPath
$selected = @(Resolve-SecurityCaseSelection -Registry $registry -Suite 'vault' -Profile $Profile)

function New-VaultRow {
    param($Case, [string]$Status, [string]$Expected, [string]$Observed,
        [string]$Evidence, [int]$DurationMs = 0, $ExecutorExit = $null)
    return [pscustomobject]@{
        Id           = [string]$Case.id
        Status       = $Status
        Expected     = $Expected
        Observed     = $Observed
        Evidence     = $Evidence
        DurationMs   = $DurationMs
        ExecutorExit = $ExecutorExit
    }
}

function New-SelectionErrors {
    param([string]$Observed, [string]$Evidence)
    foreach ($case in $selected) {
        New-VaultRow -Case $case -Status 'ERROR' -Expected '执行器产出可解析结果' `
            -Observed $Observed -Evidence $Evidence
    }
}

$executor = Join-Path $RepoRoot 'tests/attack/run.ps1'
if (-not (Test-Path -LiteralPath $executor)) {
    return @(New-SelectionErrors -Observed 'tests/attack/run.ps1 缺失' -Evidence $executor)
}

$executorJson = Join-Path $WorkDir 'vault-executor.json'
$arguments = @('-OutJson', $executorJson)
if (-not [string]::IsNullOrWhiteSpace($DllPath)) { $arguments += @('-DllPath', $DllPath) }
if (-not [string]::IsNullOrWhiteSpace($A6EvidenceDir)) { $arguments += @('-A6EvidenceDir', $A6EvidenceDir) }
if ($Baseline) { $arguments += '-Baseline' }
if ($KeepWork) { $arguments += '-KeepWork' }

$run = Invoke-SecurityPowerShellScript -ScriptPath $executor -Arguments $arguments -TimeoutSeconds $TimeoutSeconds
$evidenceBase = '{0}; executorExit={1}; durationMs={2}' -f $executorJson, $run.ExitCode, $run.DurationMs

if (-not (Test-Path -LiteralPath $executorJson)) {
    $detail = if ($run.TimedOut) {
        "执行器超时 $TimeoutSeconds s"
    }
    elseif ($run.Error) {
        "执行器无法启动: $($run.Error)"
    }
    else {
        '执行器未产出 JSON'
    }
    $tail = Get-SecurityTextTail -Text ($run.StdErr + ' ' + $run.StdOut) -MaxLength 500
    if ($tail) { $detail = "$detail；输出: $tail" }
    return @(New-SelectionErrors -Observed $detail -Evidence $evidenceBase)
}

try {
    $document = Get-Content -LiteralPath $executorJson -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
}
catch {
    $detail = '执行器 JSON 无法解析: ' + $_.Exception.Message
    return @(New-SelectionErrors -Observed (Get-SecurityTextTail -Text $detail -MaxLength 500) -Evidence $evidenceBase)
}

$executorRows = @()
if ($null -ne $document.PSObject.Properties['Results']) {
    $executorRows = @($document.Results)
}

$rowsById = @{}
foreach ($row in $executorRows) {
    if ($null -eq $row) { continue }
    $legacyId = [string]$row.Id
    if ($legacyId -eq 'A8W') { continue }
    if (-not $rowsById.ContainsKey($legacyId)) { $rowsById[$legacyId] = $row }
}

$output = New-Object System.Collections.Generic.List[object]
foreach ($case in $selected) {
    $legacyId = [string]$case.legacyId
    if (-not $rowsById.ContainsKey($legacyId)) {
        $output.Add((New-VaultRow -Case $case -Status 'NOT_RUN' -Expected '本轮应执行该用例' `
                    -Observed "执行器未返回 legacyId=$legacyId" -Evidence $evidenceBase -ExecutorExit $run.ExitCode))
        continue
    }

    $row = $rowsById[$legacyId]
    $verdict = if ($null -ne $row.PSObject.Properties['Verdict']) { [string]$row.Verdict } else { 'ERROR' }
    $status = ConvertTo-SecurityStatus -Verdict $verdict -Kind ([string]$case.kind)
    $expected = if ($null -ne $row.PSObject.Properties['Expected']) { [string]$row.Expected } else { '' }
    $observed = if ($null -ne $row.PSObject.Properties['Observed']) { [string]$row.Observed } else { '' }
    $rowEvidence = if ($null -ne $row.PSObject.Properties['Evidence']) { [string]$row.Evidence } else { '' }
    if ([string]::IsNullOrWhiteSpace($expected)) { $expected = '按用例注册表要求执行' }
    if ([string]::IsNullOrWhiteSpace($observed)) { $observed = "执行器返回 $verdict 但缺少观测" }

    $detail = if ([string]::IsNullOrWhiteSpace($rowEvidence)) {
        $evidenceBase
    }
    else {
        "$evidenceBase; $rowEvidence"
    }
    $output.Add((New-VaultRow -Case $case -Status $status -Expected $expected `
                -Observed (Get-SecurityTextTail -Text $observed -MaxLength 800) `
                -Evidence (Get-SecurityTextTail -Text $detail -MaxLength 800) `
                -ExecutorExit $run.ExitCode))
}

foreach ($legacyId in @($rowsById.Keys)) {
    if ($legacyId -eq 'HARNESS') {
        $harness = $rowsById[$legacyId]
        $output.Add([pscustomobject]@{
                Id           = 'HARNESS'
                Status       = 'ERROR'
                Expected     = '执行器无异常'
                Observed     = (Get-SecurityTextTail -Text ([string]$harness.Observed) -MaxLength 500)
                Evidence     = $evidenceBase
                DurationMs   = 0
                ExecutorExit = $run.ExitCode
            })
        continue
    }
    if (-not $registry.ByLegacy.ContainsKey($legacyId)) {
        $output.Add([pscustomobject]@{
                Id           = $legacyId
                Status       = 'ERROR'
                Expected     = '用例必须先在 cases.json 注册'
                Observed     = '执行器返回未注册用例 ID'
                Evidence     = $evidenceBase
                DurationMs   = 0
                ExecutorExit = $run.ExitCode
            })
    }
}

return $output.ToArray()
