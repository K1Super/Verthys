<#
  tests/e2e/product.ps1 — 产品链端到端门禁

  范围：公共 C API 建库 → 记录 → 模块启用 → 保存/锁定/口令解锁 →
  模块解锁 → 导出 → 新库导入 → 恢复码解锁。真实 DLL 同源代码、独立进程，
  工件仅落在测试沙箱。

  说明：Tauri/worker IPC 链路由对应门禁阶段的 worker/Rust/前端测试覆盖；
  本脚本只负责 C 公共 API 的产品链往返，避免把 Rust 单测冒充端到端。

  输出：可选 JSON（Stage/Test/Verdict/Passed/Failed/Output）。
#>
[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [string]$OutJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$buildDir = Join-Path $repoRoot 'build'
$testsExe = Join-Path $buildDir 'core/tests/Release/verthys_tests.exe'
$cmake = $null
$cmakeCandidates = @(
    'D:/IDE/Visual Studio 2026/18/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe',
    (Join-Path ${env:ProgramFiles} 'Microsoft Visual Studio/2026/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe'),
    (Join-Path ${env:ProgramFiles} 'Microsoft Visual Studio/2026/Professional/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe'),
    (Join-Path ${env:ProgramFiles} 'Microsoft Visual Studio/2026/Enterprise/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe')
)
foreach ($candidate in $cmakeCandidates) {
    if (Test-Path -LiteralPath $candidate) { $cmake = $candidate; break }
}
if (-not $cmake) { throw '找不到 cmake' }

if (-not $SkipBuild) {
    & $cmake --build $buildDir --config Release --target verthys_tests | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'e2e 构建失败' }
}
if (-not (Test-Path -LiteralPath $testsExe)) { throw 'verthys_tests.exe 缺失' }

Import-Module (Join-Path $PSScriptRoot '../lib/VerthysTestHygiene.psm1') -Force
# C 用例会按库 UUID 写 TPM 见证密钥，测试目录隔离无法覆盖，运行前后做差集回收。
$hygiene = Start-VerthysTestHygiene

$output = @(& $testsExe api_product_e2e 2>&1 | ForEach-Object { "$_" })
Complete-VerthysTestHygiene -Scope $hygiene
$summary = @($output | Where-Object { $_ -match '^=== Summary: (\d+) passed, (\d+) failed ===' })
if ($summary.Count -ne 1) {
    $verdict = 'FAIL'
    $passed = 0
    $failed = 1
} elseif ($summary[0] -match '^=== Summary: (\d+) passed, (\d+) failed ===') {
    $passed = [int]$Matches[1]
    $failed = [int]$Matches[2]
    $verdict = if ($passed -eq 1 -and $failed -eq 0) { 'PASS' } else { 'FAIL' }
} else {
    $verdict = 'FAIL'
    $passed = 0
    $failed = 1
}

Write-Host "=== E2E PRODUCT ==="
Write-Host ("api_product_e2e: {0} passed, {1} failed" -f $passed, $failed)
Write-Host "E2E PRODUCT $verdict"

if ($OutJson) {
    $parent = Split-Path -Parent $OutJson
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $report = [pscustomobject]@{
        Timestamp = (Get-Date).ToString('s')
        Stage     = 'PRODUCT-E2E'
        Tests     = @('api_product_e2e')
        Verdict   = $verdict
        Passed    = $passed
        Failed    = $failed
        Output    = $output
    }
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutJson -Encoding utf8
}

if ($verdict -ne 'PASS') { exit 1 }
exit 0
