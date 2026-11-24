# tests/security/suites/tpm.ps1 — vTPM 能力证据适配器。
#
# 探针缺失属于平台能力缺失（BLOCKED），探针存在但执行失败属于 ERROR。

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RepoRoot,
    [Parameter(Mandatory = $true)][string]$RegistryPath,
    [Parameter(Mandatory = $true)][string]$Profile,
    [Parameter(Mandatory = $true)][string]$WorkDir,
    [string]$TpmProbe,
    [string]$BuildDir,
    [int]$TimeoutSeconds = 300
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '../lib/Registry.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '../lib/Result.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '../lib/Process.psm1') -Force

$registry = Import-SecurityCaseRegistry -Path $RegistryPath
$selected = @(Resolve-SecurityCaseSelection -Registry $registry -Suite 'tpm' -Profile $Profile)

function New-TpmRow {
    param($Case, [string]$Status, [string]$Observed, [string]$Evidence, $ExecutorExit = $null)
    return [pscustomobject]@{
        Id           = [string]$Case.id
        Status       = $Status
        Expected     = [string]$Case.description
        Observed     = $Observed
        Evidence     = $Evidence
        DurationMs   = 0
        ExecutorExit = $ExecutorExit
    }
}

if ([string]::IsNullOrWhiteSpace($TpmProbe)) {
    if (-not [string]::IsNullOrWhiteSpace($BuildDir)) {
        if (-not [System.IO.Path]::IsPathRooted($BuildDir)) {
            $BuildDir = Join-Path $RepoRoot $BuildDir
        }
        $TpmProbe = Join-Path $BuildDir 'tests/Release/vty_tpm_probe.exe'
    }
    else {
        $TpmProbe = Join-Path $RepoRoot 'build/core/tests/Release/vty_tpm_probe.exe'
    }
}
elseif (-not [System.IO.Path]::IsPathRooted($TpmProbe)) {
    $TpmProbe = Join-Path $RepoRoot $TpmProbe
}

$output = New-Object System.Collections.Generic.List[object]
foreach ($case in $selected) {
    if (-not (Test-Path -LiteralPath $TpmProbe)) {
        $output.Add((New-TpmRow -Case $case -Status 'BLOCKED' `
                    -Observed "vTPM 探针缺失: $TpmProbe" -Evidence $TpmProbe))
        continue
    }

    $executor = Join-Path $RepoRoot 'tests/attack/vtpm/run.ps1'
    if (-not (Test-Path -LiteralPath $executor)) {
        $output.Add((New-TpmRow -Case $case -Status 'ERROR' `
                    -Observed 'tests/attack/vtpm/run.ps1 缺失' -Evidence $executor))
        continue
    }

    $reportPath = Join-Path $WorkDir 'vtpm-report.json'
    $run = Invoke-SecurityPowerShellScript -ScriptPath $executor `
        -Arguments @('-Probe', $TpmProbe, '-OutJson', $reportPath) `
        -TimeoutSeconds $TimeoutSeconds
    $evidence = '{0}; executorExit={1}; durationMs={2}' -f $reportPath, $run.ExitCode, $run.DurationMs

    $verdict = ''
    $detail = ''
    foreach ($line in @(($run.StdOut + "`n" + $run.StdErr) -split "`r?`n")) {
        if ($line -match '^RESULT VTPM (PASS|BLOCKED|FAIL) (.*)$') {
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
            # 报告损坏时保持 ERROR，由下方统一处理。
        }
    }

    if ($verdict -eq '') {
        $tail = Get-SecurityTextTail -Text ($run.StdErr + ' ' + $run.StdOut) -MaxLength 500
        $observed = if ($run.TimedOut) { "执行器超时 $TimeoutSeconds s" } else { '执行器未返回 VTPM 结果' }
        if ($tail) { $observed = "$observed；输出: $tail" }
        $output.Add((New-TpmRow -Case $case -Status 'ERROR' -Observed $observed `
                    -Evidence $evidence -ExecutorExit $run.ExitCode))
        continue
    }

    $status = ConvertTo-SecurityStatus -Verdict $verdict -Kind ([string]$case.kind)
    if ([string]::IsNullOrWhiteSpace($detail)) { $detail = "执行器返回 $verdict" }
    $output.Add((New-TpmRow -Case $case -Status $status -Observed $detail `
                -Evidence $evidence -ExecutorExit $run.ExitCode))
}

return $output.ToArray()
