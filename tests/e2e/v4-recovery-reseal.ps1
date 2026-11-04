<#
  tests/e2e/v4-recovery-reseal.ps1 — 换机恢复后容器槽重绑端到端

  覆盖：创建 → 锁定 → 恢复码解锁 → 新本机口令重绑 user/device 槽 →
  锁定 → 新口令普通解锁成功 / 旧口令失败；keyfile 启用时缺文件必须拒绝。

  说明：本脚本直接运行 C 公共 API 验收用例（同一 DLL 源码、独立进程），
  不伪造 worker/Tauri 证据；worker 侧命令注入由宿主单测覆盖。
#>
[CmdletBinding()]
param(
    [string]$TestsExe = "",
    [string]$OutJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
if (-not $TestsExe) {
    $TestsExe = Join-Path $repoRoot 'build/core/tests/Release/verthys_tests.exe'
}
if (-not (Test-Path -LiteralPath $TestsExe)) { throw "测试可执行文件缺失: $TestsExe" }

$cases = @(
    'v4_reseal_device_roundtrip_restores_normal_unlock',
    'v4_reseal_device_rejects_normal_session',
    'v4_reseal_device_keyfile_required_and_roundtrip'
)

Import-Module (Join-Path $PSScriptRoot '../lib/VerthysTestHygiene.psm1') -Force
# C 用例同样会写 CNG 持久化见证密钥，LOCALAPPDATA 隔离覆盖不到。
$hygiene = Start-VerthysTestHygiene

$results = New-Object System.Collections.Generic.List[object]
$failed = 0
try {
foreach ($case in $cases) {
    $output = @(& $TestsExe $case 2>&1 | ForEach-Object { "$_" })
    $summary = @($output | Where-Object { $_ -match '^=== Summary: (\d+) passed, (\d+) failed ===' })
    $passed = 0
    $caseFailed = 1
    if ($summary.Count -eq 1 -and $summary[0] -match '^=== Summary: (\d+) passed, (\d+) failed ===') {
        $passed = [int]$Matches[1]
        $caseFailed = [int]$Matches[2]
    }
    $verdict = if ($passed -eq 1 -and $caseFailed -eq 0) { 'PASS' } else { 'FAIL' }
    if ($verdict -ne 'PASS') { $failed++ }
    $results.Add([pscustomobject]@{
            Case    = $case
            Verdict = $verdict
            Passed  = $passed
            Failed  = $caseFailed
            Output  = $output
        })
}
}
finally {
    Complete-VerthysTestHygiene -Scope $hygiene
}

Write-Host "=== E2E V4-RECOVERY-RESEAL ==="
foreach ($r in $results) {
    Write-Host ("{0}: {1} (passed={2}, failed={3})" -f $r.Case, $r.Verdict, $r.Passed, $r.Failed)
}
$verdict = if ($failed -eq 0) { 'PASS' } else { 'FAIL' }
Write-Host "E2E V4-RECOVERY-RESEAL $verdict"

if ($OutJson) {
    $parent = Split-Path -Parent $OutJson
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    [pscustomobject]@{
        Timestamp = (Get-Date).ToString('s')
        Stage     = 'V4-RECOVERY-RESEAL-E2E'
        Verdict   = $verdict
        Results   = $results
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutJson -Encoding utf8
}

if ($verdict -ne 'PASS') { exit 1 }
exit 0
