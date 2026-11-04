<#
 * tests/gate.ps1 — 分阶段安全门禁
 *
 * 用法：
 *   pwsh tests/gate.ps1 -Stage P0-B
 *   pwsh tests/gate.ps1 -Stage P0-G -Full
 *   pwsh tests/gate.ps1 -Stage P0-C -SkipBuild
 *   pwsh tests/gate.ps1 -Stage P2
 *   pwsh tests/gate.ps1 -Stage V4-PI
 *   pwsh tests/gate.ps1 -Stage V4-PI-2
 *   pwsh tests/gate.ps1 -Stage V4-PI-3
 *   pwsh tests/gate.ps1 -Stage V4-PI-4
 *   pwsh tests/gate.ps1 -Stage V4-PI-5
 *
 * P2 额外要求：PCR 读取、PCR 绑定密钥的正控与负控必须同时成立；
 * TBS 授权会话与 TPM NV 的可用性写入报告（平台不支持时记录为能力边界）。
 * V4-PI 要求：v4 数据区/目录/DataRoot、公共会话入口与 v3 拒绝用例
 * （A16）通过；现有 P0/P2 用例不得回退。
 * V4-PI-2 要求：记录仓库/扫描/摘要/删除/导出导入与公共 API v4 分支
 * （A4/A5/A9/A11/A13）全绿；V4-PI 的格式与会话用例不得回退。
 * V4-PI-3 要求：模块表/启用重写/分片/恢复/回滚/API 用例全绿；
 * A6b/A8/A14/A15 与 A4/A5/A9/A11/A12/A13 通过；Rust worker 与前端
 * vitest 必须同时零失败；旧 V4-PI-2/V4-PI/P0-B/P0-F/P2 不得回退。
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
    [ValidateSet('P0-B', 'P0-C', 'P0-D', 'P0-E', 'P0-F', 'P0-G', 'P2', 'V4-PI', 'V4-PI-2', 'V4-PI-3', 'V4-PI-4', 'V4-PI-5')]
    [string]$Stage = 'P0-G',
    [switch]$Full,
    [switch]$SkipBuild,
    [int]$TestTimeoutMinutes = 40,
    [string]$OutJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

# 测试卫生闸门：LOCALAPPDATA 隔离只能挡住 rollback.state 落盘，挡不住 CNG
# 持久化见证密钥按库 UUID 累积；这里在整轮门禁前后做快照差集回收，并在
# 结束时校验真实锚点状态未被任何测试路径改写。
Import-Module (Join-Path $PSScriptRoot 'lib/VerthysTestHygiene.psm1') -Force
$hygiene = Start-VerthysTestHygiene

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
    'P0-G' = @{ Tests = @('v4_'); Attacks = @('PC-1', 'A1', 'A1b', 'A2', 'A3', 'A4', 'A5', 'A6', 'A6b', 'A7', 'A8', 'A9', 'A10', 'A11', 'A12', 'A13', 'A14', 'A15', 'A16', 'A17', 'A19') }
    'P2'   = @{ Tests = @('v4_pcr', 'v4_tpm_pcr', 'v4_witness'); Attacks = @('PC-1', 'A7', 'A8', 'A12', 'A14') }
    'V4-PI' = @{ Tests = @('v4_store_', 'v4_api_', 'v4_header_', 'v4_slot_', 'v4_data_root_', 'v4_segment_', 'v4_rollback', 'v4_witness'); Attacks = @('PC-1', 'A4', 'A5', 'A9', 'A12', 'A14', 'A15', 'A16') }
    'V4-PI-2' = @{ Tests = @('v4_repo', 'v4_api_records', 'v4_transfer', 'v4_store_', 'v4_crash_record'); Attacks = @('PC-1', 'A4', 'A5', 'A9', 'A11', 'A13') }
    'V4-PI-3' = @{ Tests = @('v4_module_table', 'v4_module_m1', 'v4_module_delete', 'v4_module_recovery', 'v4_module_crash', 'v4_api_modules', 'v4_api_module_delete', 'v4_api_recovery_rotate', 'v4_repo', 'v4_store_'); Attacks = @('PC-1', 'A4', 'A5', 'A9', 'A11', 'A12', 'A13', 'A6b', 'A8', 'A14', 'A15') }
    'V4-PI-4' = @{ Tests = @('v4_api_pcr', 'v4_pcr_', 'v4_api_product', 'v4_api_module', 'v4_recovery', 'v4_api_records', 'v4_module_', 'v4_store_', 'v4_reseal_device_'); Attacks = @('PC-1', 'A4', 'A5', 'A9', 'A11', 'A12', 'A13', 'A6b', 'A8', 'A14', 'A15', 'A16', 'A17', 'A19', 'A20', 'A20b') }
    'V4-PI-5' = @{ Tests = @('v4_repo_system_', 'v4_api_', 'v4_module_'); Attacks = @('PC-1', 'A4', 'A9', 'A11', 'A13', 'A20', 'A20b') }
}

$checks = $stageChecks[$Stage]

# 所有测试与攻击回归都在这层 try/finally 内执行：无论中途提前 exit 还是
# 抛错，都会走统一回收，避免半途退出把见证密钥留在机器上。
try {

# V4-PI-5 的验收证据固定落到 reports/（可由 -OutJson 覆盖）
if ($Stage -eq 'V4-PI-5' -and -not $OutJson) {
    $OutJson = Join-Path $repoRoot 'reports/gate-v4-pi-5.json'
}

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

# 3b) V4-PI-3：模块事务涉及 worker 会话与渲染层密钥面移除，
#     该阶段必须同时跑 Rust worker 单测与前端 vitest（零失败）。
if ($Stage -in @('V4-PI-3', 'V4-PI-4')) {
    $workerDir = Join-Path $repoRoot 'verthys-tauri/verthys-worker'
    Push-Location $workerDir
    try { & cargo test --release | Out-Null; $workerTestExit = $LASTEXITCODE }
    finally { Pop-Location }
    if ($workerTestExit -ne 0) { $testFailures.Add('worker cargo test 失败') }

    $frontDir = Join-Path $repoRoot 'verthys-tauri'
    Push-Location $frontDir
    try { & npm test | Out-Null; $frontTestExit = $LASTEXITCODE }
    finally { Pop-Location }
    if ($frontTestExit -ne 0) { $testFailures.Add('前端 vitest 失败') }

    if ($Stage -eq 'V4-PI-4') {
        Push-Location $frontDir
        try { & npx vue-tsc --noEmit | Out-Null; $tscExit = $LASTEXITCODE }
        finally { Pop-Location }
        if ($tscExit -ne 0) { $testFailures.Add('前端类型检查失败') }

        $e2eScript = Join-Path $PSScriptRoot 'e2e/v4-product.ps1'
        & pwsh -NoProfile -File $e2eScript -SkipBuild | Out-Null
        if ($LASTEXITCODE -ne 0) { $testFailures.Add('v4 产品链 e2e 失败') }

        $workerE2e = Join-Path $PSScriptRoot 'e2e/v4-worker-smoke.ps1'
        & pwsh -NoProfile -File $workerE2e | Out-Null
        if ($LASTEXITCODE -ne 0) { $testFailures.Add('v4 worker IPC e2e 失败') }

        # 宿主层全库轮换：真实 AppHandle/AppState/worker/DLL，覆盖
        # Begin→UnlockModule→Run→Abort/Commit 与提交后记录读回。
        # 依赖可用的 Windows 桌面会话（WebView2）；以隐藏窗口运行。
        $rotateHostE2e = Join-Path $PSScriptRoot 'e2e/v4-rotate-host.ps1'
        & pwsh -NoProfile -File $rotateHostE2e | Out-Null
        if ($LASTEXITCODE -ne 0) { $testFailures.Add('v4 全库轮换宿主层 e2e 失败') }
    }
}

# 3c) V4-PI-4/V4-PI-5：P1-1 身份键门禁 —— 生产代码禁止内容哈希作为去重/寻址键。
#     旧字段名（已删除）不得复活；A20/A20b 回归用例必须在场（由全量 vitest 执行）。
if ($Stage -in @('V4-PI-4', 'V4-PI-5')) {
    $idKeyRoots = @(
        (Join-Path $repoRoot 'verthys-tauri/src'),
        (Join-Path $repoRoot 'verthys-tauri/src-tauri/src')
    )
    $idKeyHits = @(foreach ($root in $idKeyRoots) {
            if (Test-Path -LiteralPath $root) {
                Get-ChildItem -LiteralPath $root -Recurse -Include *.ts,*.vue,*.rs -File -ErrorAction SilentlyContinue |
                    Select-String -Pattern 'committed_hashes|chunk_ids_by_hash|chunk_<hash>' -ErrorAction SilentlyContinue
            }
        })
    if ($idKeyHits.Count -gt 0) {
        $testFailures.Add("内容哈希身份键残留 $($idKeyHits.Count) 处")
        foreach ($hit in ($idKeyHits | Select-Object -First 5)) {
            Write-Host ("  [KEY ] {0}:{1}" -f $hit.Path, $hit.LineNumber) -ForegroundColor Red
        }
    }
    $a20File = Join-Path $repoRoot 'verthys-tauri/src/composables/file-verthys/useFileImport.spec.ts'
    $a20Text = if (Test-Path -LiteralPath $a20File) { Get-Content -LiteralPath $a20File -Raw } else { '' }
    if ($a20Text -notmatch '同内容不同路径' -or $a20Text -notmatch '同一会话内同路径') {
        $testFailures.Add('A20/A20b 回归用例缺失（同内容不同路径 / 同条目键重试）')
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

}
finally {
    Complete-VerthysTestHygiene -Scope $hygiene
}
