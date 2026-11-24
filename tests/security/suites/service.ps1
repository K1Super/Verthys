# tests/security/suites/service.ps1 — P2 安全服务控制台攻击适配器。
#
# 先检查 Debug 构建产物；缺失时按平台前置缺失记 BLOCKED，而不是 ERROR，
# 让 standard 本地运行可继续、release 明确失败。

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RepoRoot,
    [Parameter(Mandatory = $true)][string]$RegistryPath,
    [Parameter(Mandatory = $true)][string]$Profile,
    [Parameter(Mandatory = $true)][string]$WorkDir,
    [string]$ServiceBuildDir,
    [int]$TimeoutSeconds = 1200
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '../lib/Registry.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '../lib/Result.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '../lib/Process.psm1') -Force

$registry = Import-SecurityCaseRegistry -Path $RegistryPath
$selected = @(Resolve-SecurityCaseSelection -Registry $registry -Suite 'service' -Profile $Profile)

if ([string]::IsNullOrWhiteSpace($ServiceBuildDir)) {
    $ServiceBuildDir = Join-Path $RepoRoot 'build_security_service'
}
elseif (-not [System.IO.Path]::IsPathRooted($ServiceBuildDir)) {
    $ServiceBuildDir = Join-Path $RepoRoot $ServiceBuildDir
}

function New-ServiceRow {
    param($Case, [string]$Status, [string]$Expected, [string]$Observed,
        [string]$Evidence, $ExecutorExit = $null)
    return [pscustomobject]@{
        Id           = [string]$Case.id
        Status       = $Status
        Expected     = $Expected
        Observed     = $Observed
        Evidence     = $Evidence
        DurationMs   = 0
        ExecutorExit = $ExecutorExit
    }
}

function New-ServiceSelectionRows {
    param([string]$Status, [string]$Expected, [string]$Observed, [string]$Evidence)
    foreach ($case in $selected) {
        New-ServiceRow -Case $case -Status $Status -Expected $Expected `
            -Observed $Observed -Evidence $Evidence
    }
}

$executor = Join-Path $RepoRoot 'tests/service/attack.ps1'
if (-not (Test-Path -LiteralPath $executor)) {
    return @(New-ServiceSelectionRows -Status 'ERROR' -Expected '执行器可运行' `
            -Observed 'tests/service/attack.ps1 缺失' -Evidence $executor)
}

$requiredExes = @(
    (Join-Path $ServiceBuildDir 'Debug/VerthysSecuritySvc.exe'),
    (Join-Path $ServiceBuildDir 'Debug/verthys_service_probe.exe'),
    (Join-Path $ServiceBuildDir 'Debug/verthys_fake_service.exe')
)
$missing = @($requiredExes | Where-Object { -not (Test-Path -LiteralPath $_) })
if ($missing.Count -gt 0) {
    $observed = '服务构建产物缺失: ' + (($missing | ForEach-Object { Split-Path -Leaf $_ }) -join ', ')
    return @(New-ServiceSelectionRows -Status 'BLOCKED' -Expected 'Debug 服务构建产物可用' `
            -Observed $observed -Evidence $ServiceBuildDir)
}

$executorJson = Join-Path $WorkDir 'service-executor.json'
$arguments = @('-BuildDir', $ServiceBuildDir, '-OutJson', $executorJson)
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
    return @(New-ServiceSelectionRows -Status 'ERROR' -Expected '执行器产出可解析结果' `
            -Observed $detail -Evidence $evidenceBase)
}

try {
    $document = Get-Content -LiteralPath $executorJson -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
}
catch {
    return @(New-ServiceSelectionRows -Status 'ERROR' -Expected '执行器产出可解析结果' `
            -Observed ('执行器 JSON 无法解析: ' + $_.Exception.Message) -Evidence $evidenceBase)
}

$rowsById = @{}
if ($null -ne $document.PSObject.Properties['results']) {
    foreach ($row in @($document.results)) {
        if ($null -eq $row) { continue }
        $id = [string]$row.Id
        if (-not $rowsById.ContainsKey($id)) { $rowsById[$id] = $row }
    }
}

$output = New-Object System.Collections.Generic.List[object]
foreach ($case in $selected) {
    $legacyId = [string]$case.legacyId
    if (-not $rowsById.ContainsKey($legacyId)) {
        $output.Add((New-ServiceRow -Case $case -Status 'NOT_RUN' -Expected '本轮应执行该用例' `
                    -Observed "执行器未返回 legacyId=$legacyId" -Evidence $evidenceBase -ExecutorExit $run.ExitCode))
        continue
    }

    $row = $rowsById[$legacyId]
    $verdict = if ($null -ne $row.PSObject.Properties['Status']) { [string]$row.Status } else { 'ERROR' }
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
    $output.Add((New-ServiceRow -Case $case -Status $status -Expected $expected `
                -Observed (Get-SecurityTextTail -Text $observed -MaxLength 800) `
                -Evidence (Get-SecurityTextTail -Text $detail -MaxLength 800) `
                -ExecutorExit $run.ExitCode))
}

foreach ($id in @($rowsById.Keys)) {
    if (-not $registry.ByLegacy.ContainsKey($id)) {
        $output.Add([pscustomobject]@{
                Id           = $id
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
