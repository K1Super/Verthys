<#
 * tests/gate.ps1 — 分阶段安全门禁
 *
 * 用法：
 *   pwsh tests/gate.ps1 -Stage P0-B
 *   pwsh tests/gate.ps1 -Stage P0-G -Full
 *   pwsh tests/gate.ps1 -Stage P0-C -SkipBuild
 *   pwsh tests/gate.ps1 -Stage P2
 *
 * P2 额外要求：PCR 读取、PCR 绑定密钥的正控与负控必须同时成立；
 * TBS 授权会话与 TPM NV 的可用性写入报告（平台不支持时记录为能力边界）。
 *
 * 判定口径：
 *   - 全量单元/集成测试必须 0 失败；
 *   - 该阶段对应的攻击用例必须 PASS（SKELETON/KNOWN_GAP 视为未达标）；
 *   - 任一不满足则退出码 1。
 *
 * 说明：仓库没有独立的 v4 产品库样本，攻击用例由自建随机口令容器与
 * vty_probe 直接驱动 v4 原语生成证据；工件全部落在临时目录。
#>
[CmdletBinding()]
param(
    [ValidateSet('P0-B', 'P0-C', 'P0-D', 'P0-E', 'P0-F', 'P0-G', 'P2')]
    [string]$Stage = 'P0-G',
    [switch]$Full,
    [switch]$SkipBuild,
    [int]$TestTimeoutMinutes = 40,
    [string]$OutJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
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
if (-not $cmake) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
    if (Test-Path -LiteralPath $vswhere) {
        $vsRoot = & $vswhere -latest -property installationPath
        $candidate = Join-Path $vsRoot 'Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe'
        if (Test-Path -LiteralPath $candidate) { $cmake = $candidate }
    }
}
if (-not $cmake) {
    throw '找不到 cmake'
}

$stageChecks = @{
    'P0-B' = @{ Tests = @('v4_blake3', 'v4_hkdf', 'v4_hmac', 'v4_argon2', 'v4_kdf', 'v4_wrap', 'v4_recovery', 'v4_keyring', 'v4_header', 'v4_slot', 'v4_vault'); Attacks = @('PC-1', 'A1', 'A1b', 'A2', 'A3', 'A12', 'A15') }
    'P0-C' = @{ Tests = @('v4_record', 'v4_name_index'); Attacks = @('A4', 'A9', 'A13') }
    'P0-D' = @{ Tests = @('v4_chunk', 'v4_manifest'); Attacks = @('A5') }
    'P0-E' = @{ Tests = @('v4_module'); Attacks = @('A6', 'A6b') }
    'P0-F' = @{ Tests = @('v4_lockout'); Attacks = @('A7', 'A8') }
    'P0-G' = @{ Tests = @('v4_'); Attacks = @('PC-1', 'A1', 'A1b', 'A2', 'A3', 'A4', 'A5', 'A6', 'A6b', 'A7', 'A8', 'A9', 'A10', 'A11', 'A12', 'A13', 'A14', 'A15') }
    'P2'   = @{ Tests = @('v4_pcr', 'v4_tpm_pcr', 'v4_witness'); Attacks = @('PC-1', 'A7', 'A8', 'A12', 'A14') }
}

$checks = $stageChecks[$Stage]

if (-not $SkipBuild) {
    & $cmake --build $buildDir --config Release --target verthys_tests | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "GATE $Stage FAIL build" -ForegroundColor Red
        exit 1
    }

    # worker 在构建期把 verthys.dll 的全文件摘要固化为常量：核心 DLL 每次
    # 重建后必须同步重建 worker，否则 A8 的 worker 侧会因摘要不匹配拒绝加载。
    $workerDir = Join-Path $repoRoot 'verthys-tauri/verthys-worker'
    $workerExe = Join-Path $workerDir 'target/release/verthys-worker.exe'
    if (Test-Path -LiteralPath $workerExe) {
        if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
            Write-Host "GATE $Stage FAIL worker-rebuild-unavailable" -ForegroundColor Red
            exit 1
        }
        Push-Location $workerDir
        try { & cargo build --release | Out-Null; $workerBuildExit = $LASTEXITCODE }
        finally { Pop-Location }
        if ($workerBuildExit -ne 0) {
            Write-Host "GATE $Stage FAIL worker-build" -ForegroundColor Red
            exit 1
        }
    }
}
if (-not (Test-Path -LiteralPath $testsExe)) {
    Write-Host "GATE $Stage FAIL tests-exe-missing" -ForegroundColor Red
    exit 1
}

# 1) 全量测试：任一 FAIL 直接阻断
# 用文件重定向而非 PowerShell 管道：测试会派生子进程并输出数千行，
# 管道在部分环境下会因句柄/缓冲问题长期不返回 EOF。
$logOut = Join-Path $env:TEMP ('verthys_gate_' + [guid]::NewGuid().ToString('N') + '.out')
$logErr = Join-Path $env:TEMP ('verthys_gate_' + [guid]::NewGuid().ToString('N') + '.err')
$proc = Start-Process -FilePath $testsExe -PassThru -NoNewWindow `
    -RedirectStandardOutput $logOut -RedirectStandardError $logErr
$timeoutMs = [int]$TestTimeoutMinutes * 60 * 1000
if (-not $proc.WaitForExit($timeoutMs)) {
    try { $proc.Kill() } catch { }
    Write-Host "GATE $Stage FAIL tests-timeout" -ForegroundColor Red
    exit 1
}
$stdoutLines = @(Get-Content -LiteralPath $logOut -ErrorAction SilentlyContinue)
$stderrLines = @(Get-Content -LiteralPath $logErr -ErrorAction SilentlyContinue)
$testLines = @($stdoutLines) + @($stderrLines)
Remove-Item -LiteralPath $logOut, $logErr -Force -ErrorAction SilentlyContinue
$summary = @($testLines | Where-Object { $_ -match '^=== Summary: (\d+) passed, (\d+) failed ===' })
if ($summary.Count -ne 1 -or $summary[0] -notmatch '^=== Summary: (\d+) passed, (\d+) failed ===') {
    Write-Host "GATE $Stage FAIL tests-summary-missing" -ForegroundColor Red
    exit 1
}
$passedCount = [int]$Matches[1]
$failedCount = [int]$Matches[2]
$okNames = @($testLines | ForEach-Object {
        if ($_ -match '^\[\s+OK\s+\] (.+)$') { $Matches[1] }
    })

$testFailures = New-Object System.Collections.Generic.List[string]
if ($failedCount -gt 0) { $testFailures.Add("全量测试失败 $failedCount 项") }
foreach ($prefix in $checks.Tests) {
    $hit = @($okNames | Where-Object { $_ -like "$prefix*" })
    if ($hit.Count -eq 0) { $testFailures.Add("未发现通过的用例前缀 $prefix") }
}

# 2) 攻击回归：该阶段用例必须 PASS
$attackJson = Join-Path $env:TEMP ('verthys_gate_' + [guid]::NewGuid().ToString('N') + '.json')
$attackArgs = @('-NoProfile', '-File', (Join-Path $PSScriptRoot 'attack/run.ps1'), '-OutJson', $attackJson)
if ($Stage -eq 'P0-G' -and $Full) {
    # -Full 保留给后续长时模糊/浸泡扩展；当前等价于标准全量门禁
    $attackArgs += '-KeepWork'
}
& pwsh @attackArgs | Out-Null
$attackExit = $LASTEXITCODE
$attack = Get-Content -LiteralPath $attackJson -Raw | ConvertFrom-Json
$attackById = @{}
foreach ($row in $attack.Results) { $attackById[$row.Id] = $row }

$attackFailures = New-Object System.Collections.Generic.List[string]
foreach ($id in $checks.Attacks) {
    if (-not $attackById.ContainsKey($id)) { $attackFailures.Add("$id 未执行"); continue }
    if ($attackById[$id].Verdict -ne 'PASS') {
        $attackFailures.Add("$id=$($attackById[$id].Verdict)")
    }
}

# 3) P2 能力门：PCR 读取与 PCR 绑定正/负控必须在真实 TPM 上成立；
#    TBS 授权会话与 TPM NV 的可用性只记录，由偏差登记说明平台边界。
$p2Caps = $null
if ($Stage -eq 'P2') {
    $probeExe = Join-Path $buildDir 'core/tests/Release/vty_tpm_probe.exe'
    if (-not $SkipBuild) {
        & $cmake --build $buildDir --config Release --target vty_tpm_probe | Out-Null
    }
    if (-not (Test-Path -LiteralPath $probeExe)) {
        $testFailures.Add('vty_tpm_probe 缺失')
    } else {
        $probeText = (& $probeExe 2>&1 | Out-String)
        $p2Caps = [pscustomobject]@{
            TbsPcrRead          = [bool]($probeText -match '\[PCR\] policyDigest\(pcr7\|\|pcr11\)=')
            TbsSessions         = -not [bool]($probeText -match '\[SESS\] plain rc=0x0000008B')
            TbsNvCounter        = [bool]($probeText -match '\[NV\] after-2 value=2')
            PcrBindingPositive  = [bool]($probeText -match '\[PCP2\] oaep tpm decrypt st=0x00000000 .* match=YES')
            PcrBindingNegative  = [bool]($probeText -match '\[PCP2\] oaep tpm decrypt st=0x80280084 .* match=NO')
        }
        if (-not $p2Caps.TbsPcrRead) { $testFailures.Add('TPM PCR 读取不可用') }
        if (-not $p2Caps.PcrBindingPositive) { $testFailures.Add('PCR 绑定正控未命中') }
        if (-not $p2Caps.PcrBindingNegative) { $testFailures.Add('PCR 绑定负控未命中') }
    }
}

# 4) 汇总
$total = $checks.Tests.Count + $checks.Attacks.Count
$bad = $testFailures.Count + $attackFailures.Count
$verdict = if ($bad -eq 0) { 'PASS' } else { 'FAIL' }

Write-Host ""
Write-Host "=== GATE $Stage ===" -ForegroundColor Cyan
Write-Host ("单元/集成: {0} passed, {1} failed" -f $passedCount, $failedCount)
Write-Host ("攻击用例: {0}" -f (($checks.Attacks | ForEach-Object {
                if ($attackById.ContainsKey($_) ) { "$_=$($attackById[$_].Verdict)" } else { "$_=MISSING" }
            }) -join ' '))
foreach ($msg in $testFailures) { Write-Host ("  [TEST] " + $msg) -ForegroundColor Red }
foreach ($msg in $attackFailures) { Write-Host ("  [ATK ] " + $msg) -ForegroundColor Red }
Write-Host ("GATE {0} {1}" -f $Stage, $verdict) -ForegroundColor $(if ($verdict -eq 'PASS') { 'Green' } else { 'Red' })

if ($OutJson) {
    $report = [pscustomobject]@{
        Timestamp    = (Get-Date).ToString('s')
        Stage        = $Stage
        Verdict      = $verdict
        TestsPassed  = $passedCount
        TestsFailed  = $failedCount
        TestsChecked = $checks.Tests
        Attacks      = $checks.Attacks
        Failures     = @($testFailures) + @($attackFailures)
        P2Capabilities = $p2Caps
        AttackRun    = $attack
    }
    $parent = Split-Path -Parent $OutJson
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutJson -Encoding utf8
}

Remove-Item -LiteralPath $attackJson -Force -ErrorAction SilentlyContinue
exit $(if ($verdict -eq 'PASS') { 0 } else { 1 })
