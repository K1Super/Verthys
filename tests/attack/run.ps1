<#
 * tests/attack/run.ps1 — 攻击回归基线
 *
 * 用法：
 *   pwsh tests/attack/run.ps1                          # 期望：默认口令/未解锁枚举/明文扫描全部拒绝
 *   pwsh tests/attack/run.ps1 -OutJson <路径>            # 输出机器可读证据
 *   pwsh tests/attack/run.ps1 -A6EvidenceDir <目录>      # 离机报告目录（默认自动查找）
 *
 * 判定口径：
 *   PASS      = 实际结果符合该模式下的期望
 *   FAIL      = 实际结果不符合期望（修复后出现即回归）
 *   KNOWN_GAP = 当前阶段尚未实现的防护（登记目标阶段，不计入退出码）
 *   SKELETON  = 攻击用例骨架已登记，具体实现随对应阶段落地
 *
 * 安全约束：
 *   - 每次运行自生成随机口令 容器，不读取外部副本。
 *   - 所有临时容器在结束时删除（-KeepWork 可保留用于取证）。
 *   - 不打印任何口令内容。
 *   - 熔断/回滚状态目录由 VERTHYS_TEST_STATE_DIR 注入；被加载的 DLL 必须由
 *     build_core.release.ps1 -TestHooks 构建。生产 DLL 不识别该变量。
#>
[CmdletBinding()]
param(
    [string]$DllPath,
    [string]$OutJson,
    [switch]$KeepWork,
    # 离机证据目录（默认 <repo>/reports 与同级 AttackTest/reports）；仅接受合格报告
    [string]$A6EvidenceDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'VerthysHarness.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '../lib/VerthysTestHygiene.psm1') -Force

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path

# 必须在改写 LOCALAPPDATA 之前抓取真实锚点指纹与见证快照，否则差集把
# 隔离目录当成真实目录，回收对象会出错。
$hygiene = Start-VerthysTestHygiene

# 必须在加载 DLL 之前设置隔离目录：DLL 的测试钩子读取进程环境，
# 首次状态解析发生在 Verthys_Init/创建路径上。
$workDir = Join-Path $env:TEMP ('verthys_attack_' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workDir -Force | Out-Null
$env:LOCALAPPDATA = Join-Path $workDir 'localappdata'
New-Item -ItemType Directory -Path $env:LOCALAPPDATA -Force | Out-Null
# 熔断/回滚状态固定走 KnownFolder；攻击回归用测试构建的显式覆盖避免触碰
# 真实用户状态。生产 DLL 不编译该钩子。
$env:VERTHYS_TEST_STATE_DIR = Join-Path $workDir 'security_state'
New-Item -ItemType Directory -Path $env:VERTHYS_TEST_STATE_DIR -Force | Out-Null
# 安全服务是强制依赖；攻击回归不启动真实服务，测试构建显式旁路机器预算调用。
$env:VERTHYS_TEST_MACHINE_LIMITER_BYPASS = "1"

if (-not $DllPath) {
    $DllPath = Join-Path $repoRoot 'build/core/Release/verthys.dll'
}
$DllPath = Initialize-VerthysNative -DllPath $DllPath
# 攻击探针：独立进程直接驱动 原语（不扩大生产 DLL 导出面）。
# 构建目标 verthys_tests 依赖 vty_probe，正常构建后必然存在。
$probePath = Join-Path $repoRoot 'build/core/tests/Release/vty_probe.exe'

$vaultPath = Join-Path $workDir 'attack.verthys'

$runId = [guid]::NewGuid().ToString('N')
$nameMarker = "A9_NAME_MARKER_$runId"
$dataMarker = "A4_SECRET_MARKER_$runId"
$accountJson = "{`"account`":`"attack-probe`",`"secret`":`"$dataMarker`",`"note`":`"plaintext-canary`"}"

$results = New-Object System.Collections.Generic.List[object]
$mode = 'PostFix'
$vaultOrigin = 'generated'

function Add-Result {
    param(
        [string]$Id,
        [string]$Name,
        [string]$Expected,
        [string]$Observed,
        [string]$Verdict,
        [string]$Evidence
    )
    $results.Add([pscustomobject]@{
            Id       = $Id
            Name     = $Name
            Expected = $Expected
            Observed = $Observed
            Verdict  = $Verdict
            Evidence = $Evidence
        })
}

function Invoke-ProbeRaw {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    if (-not (Test-Path -LiteralPath $probePath)) {
        return [pscustomobject]@{ Pass = $false; Detail = 'vty_probe.exe 未构建'; Exit = -1 }
    }
    $lines = @(& $probePath @Arguments 2>&1 | ForEach-Object { "$_" })
    $exitCode = $LASTEXITCODE
    $pattern = '^RESULT ' + [regex]::Escape($Id) + ' (PASS|FAIL) (.*)$'
    $pass = $false
    $detail = if ($lines.Count -gt 0) { $lines -join ' | ' } else { '无输出' }
    foreach ($line in $lines) {
        if ($line -match $pattern) {
            $pass = ($Matches[1] -eq 'PASS')
            $detail = $Matches[2]
            break
        }
    }
    return [pscustomobject]@{ Pass = $pass; Detail = $detail; Exit = $exitCode }
}

function Invoke-ResultScript {
    param([string]$File, [string]$Tag)
    $scriptPath = Join-Path $PSScriptRoot $File
    if (-not (Test-Path -LiteralPath $scriptPath)) {
        return [pscustomobject]@{ Pass = $false; Detail = "$File 缺失"; Exit = -1 }
    }
    $lines = @(& pwsh -NoProfile -File $scriptPath 2>&1 | ForEach-Object { "$_" })
    $exitCode = $LASTEXITCODE
    $pass = $false
    $detail = '未返回结果'
    $pattern = '^RESULT ' + [regex]::Escape($Tag) + ' (PASS|FAIL) (.*)$'
    foreach ($line in $lines) {
        if ($line -match $pattern) {
            $pass = ($Matches[1] -eq 'PASS')
            $detail = $Matches[2]
            break
        }
    }
    return [pscustomobject]@{ Pass = $pass; Detail = $detail; Exit = $exitCode }
}

function Invoke-A8Probe {
    # 主进程（C 库）与 worker 进程（内容层密钥）都必须零残留；
    # 任一失败即内存残留用例失败，避免只验证一侧而给出片面的 PASS。
    # worker 产物未构建时（如仅 C 核心的 CI 通道）跳过 worker 部分并显式标注。
    $main = Invoke-ResultScript 'a8.ps1' 'A8'
    if (-not $main.Pass -or $main.Exit -ne 0) {
        return [pscustomobject]@{ Pass = $false; Detail = "主进程[$($main.Detail)]"; Exit = 1 }
    }
    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $workerExe = Join-Path $repoRoot 'verthys-tauri/verthys-worker/target/release/verthys-worker.exe'
    if (-not (Test-Path -LiteralPath $workerExe)) {
        return [pscustomobject]@{
            Pass = $false; Detail = "主进程[$($main.Detail)]；worker 产物未构建，A8W 跳过"
            Exit = 0; Verdict = 'SKIP'
        }
    }
    $worker = Invoke-ResultScript 'a8-worker.ps1' 'A8W'
    $pass = ($worker.Pass -and $worker.Exit -eq 0)
    $detail = "主进程[$($main.Detail)]；worker[$($worker.Detail)]"
    return [pscustomobject]@{ Pass = $pass; Detail = $detail; Exit = $(if ($pass) { 0 } else { 1 }) }
}

function Invoke-A2Probe {
    $scriptPath = Join-Path $PSScriptRoot 'a2.ps1'
    if (-not (Test-Path -LiteralPath $scriptPath)) {
        return [pscustomobject]@{ Pass = $false; Detail = 'a2.ps1 缺失'; Exit = -1 }
    }
    $lines = @(& pwsh -NoProfile -File $scriptPath 2>&1 | ForEach-Object { "$_" })
    $exitCode = $LASTEXITCODE
    $pass = $false
    $detail = '未返回结果'
    foreach ($line in $lines) {
        if ($line -match '^RESULT A2 (PASS|FAIL) (.*)$') {
            $pass = ($Matches[1] -eq 'PASS')
            $detail = $Matches[2]
            break
        }
    }
    return [pscustomobject]@{ Pass = $pass; Detail = $detail; Exit = $exitCode }
}

function Add-ProbeResult {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Expected,
        [Parameter(Mandatory = $true)]$Probe,
        [string]$EvidencePrefix = ''
    )
    # 探针可显式给出 Verdict（如 SKIP：依赖产物未构建），否则按 Pass/Exit 推导
    $verdict = if ($Probe.PSObject.Properties['Verdict'] -and $Probe.Verdict) {
        [string]$Probe.Verdict
    } elseif ([bool]$Probe.Pass -and [int]$Probe.Exit -eq 0) {
        'PASS'
    } else {
        'FAIL'
    }
    $observed = switch ($verdict) {
        'PASS' { 'PASS' }
        'SKIP' { '跳过' }
        default { 'FAIL' }
    }
    Add-Result -Id $Id -Name $Name -Expected $Expected `
        -Observed $observed `
        -Verdict $verdict `
        -Evidence ("$EvidencePrefix exit=$($Probe.Exit); $($Probe.Detail)")
}

function Find-A6Evidence {
    # 只认离机报告中的结构化字段，不认 verdict 单一字段：缺项、同机、
    # 模块密钥仍可解、明文命中或清单不完整一律拒绝，保持 SKELETON。
    # 报告必须绑定当前构建（DLL/probe/worker 哈希 + 生成时间），
    # 哈希不符或早于当前 DLL 构建时间即 STALE，不得计为 PASS。
    param([string]$Dir)
    $roots = New-Object System.Collections.Generic.List[string]
    if ($Dir) {
        $roots.Add($Dir)
    }
    else {
        $roots.Add((Join-Path $repoRoot 'reports'))
        $roots.Add((Join-Path (Split-Path -Parent $repoRoot) 'AttackTest/reports'))
    }

    # 当前构建指纹（用于判定报告是否绑定本次产物）
    $currentDllHash = if (Test-Path -LiteralPath $DllPath) {
        (Get-FileHash -LiteralPath $DllPath -Algorithm SHA256).Hash.ToLowerInvariant()
    } else { '' }
    $currentProbeHash = if (Test-Path -LiteralPath $probePath) {
        (Get-FileHash -LiteralPath $probePath -Algorithm SHA256).Hash.ToLowerInvariant()
    } else { '' }
    $workerExePath = Join-Path $repoRoot 'verthys-tauri/verthys-worker/target/release/verthys-worker.exe'
    $currentWorkerHash = if (Test-Path -LiteralPath $workerExePath) {
        (Get-FileHash -LiteralPath $workerExePath -Algorithm SHA256).Hash.ToLowerInvariant()
    } else { '' }
    $dllBuiltAt = if (Test-Path -LiteralPath $DllPath) {
        (Get-Item -LiteralPath $DllPath).LastWriteTimeUtc
    } else { [datetime]::MinValue }

    $candidates = New-Object System.Collections.Generic.List[object]
    $staleReasons = New-Object System.Collections.Generic.List[string]
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $root -Filter 'a6-*.json' -File -ErrorAction SilentlyContinue)) {
            try {
                # 保留原始 JSON 文本：ConvertFrom-Json 会把 ISO 日期转成
                # 本机 DateTime 并丢失时区偏移，直接 [string] 后再解析会把
                # +08:00 当 UTC（偏差 8 小时）。
                $raw = Get-Content -LiteralPath $file.FullName -Raw
                $report = $raw | ConvertFrom-Json
                if ($report.case -ne 'A6' -or $report.verdict -ne 'PASS') { continue }
                $envObj = $report.environment
                if ($null -eq $envObj -or $envObj.is_offmachine -ne $true) { continue }
                $src = [string]$envObj.source_machine_guid_sha256
                $dst = [string]$envObj.machine_guid_sha256
                if ($src -eq '' -or $dst -eq '' -or $dst -eq $src) { continue }

                $obs = $report.observed
                if ($null -eq $obs) { continue }
                $hasFields = $true
                foreach ($field in @('vault_open', 'module_unlock', 'plaintext_hits', 'artifacts_verified')) {
                    if (-not $obs.PSObject.Properties[$field]) { $hasFields = $false; break }
                }
                if (-not $hasFields) { continue }
                if ([int]$obs.vault_open -ne 9) { continue }
                if ([int]$obs.module_unlock -eq 0) { continue }
                if ([int]$obs.plaintext_hits -ne 0) { continue }
                if ($obs.artifacts_verified -ne $true) { continue }

                $hashes = $report.artifacts_sha256
                if ($null -eq $hashes) { continue }
                $hasArtifacts = $true
                foreach ($name in @('a6.verthys', 'vty_probe.exe')) {
                    if (-not $hashes.PSObject.Properties[$name]) { $hasArtifacts = $false; break }
                }
                if (-not $hasArtifacts) { continue }

                # 构建绑定：字段齐全 + 与当前产物哈希一致 + 晚于 DLL 构建
                $bindingFields = @('core_dll_sha256', 'probe_sha256', 'worker_sha256',
                    'git_commit', 'generated_at', 'signer')
                $missingBinding = $false
                foreach ($field in $bindingFields) {
                    # StrictMode 下读取不存在的属性会抛异常：必须先判属性存在
                    if (-not $report.PSObject.Properties[$field]) {
                        $missingBinding = $true
                        break
                    }
                    if ([string]::IsNullOrWhiteSpace([string]$report.$field)) {
                        $missingBinding = $true
                        break
                    }
                }
                if ($missingBinding) {
                    $staleReasons.Add("$($file.Name): 构建绑定字段缺失")
                    continue
                }
                if ([string]$report.core_dll_sha256 -ne $currentDllHash) {
                    $staleReasons.Add("$($file.Name): core_dll_sha256 与当前 verthys.dll 不一致")
                    continue
                }
                if ([string]$report.probe_sha256 -ne $currentProbeHash) {
                    $staleReasons.Add("$($file.Name): probe_sha256 与当前 vty_probe.exe 不一致")
                    continue
                }
                if ([string]$report.worker_sha256 -ne $currentWorkerHash) {
                    $staleReasons.Add("$($file.Name): worker_sha256 与当前 worker 不一致")
                    continue
                }
                $generatedText = ''
                $dateMatch = [regex]::Match($raw,
                    '"generated_at"\s*:\s*"([^"]+)"')
                if ($dateMatch.Success) {
                    $generatedText = $dateMatch.Groups[1].Value
                }
                $generatedAt = [datetimeoffset]::MinValue
                if (-not [datetimeoffset]::TryParse($generatedText,
                        [Globalization.CultureInfo]::InvariantCulture,
                        [Globalization.DateTimeStyles]::None,
                        [ref]$generatedAt)) {
                    $staleReasons.Add("$($file.Name): generated_at 无法解析")
                    continue
                }
                if ($generatedAt.UtcDateTime -lt $dllBuiltAt) {
                    $staleReasons.Add("$($file.Name): 报告早于当前 DLL 构建时间")
                    continue
                }

                $candidates.Add([pscustomobject]@{
                        Path     = $file.FullName
                        Observed = $obs
                        Written  = $file.LastWriteTime
                    })
            }
            catch {
                # 报告缺字段/类型异常：视为不合格，保持 SKELETON，不中断攻击回归
                continue
            }
        }
    }
    if ($candidates.Count -eq 0) {
        if ($staleReasons.Count -gt 0) {
            return [pscustomobject]@{ StaleReason = $staleReasons[0] }
        }
        return $null
    }
    return ($candidates | Sort-Object Written -Descending | Select-Object -First 1)
}

function Invoke-UnlockAfterCooldown {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][byte[]]$Password,
        [int]$TimeoutSeconds = 30
    )
    $start = Get-Date
    while (((Get-Date) - $start).TotalSeconds -lt $TimeoutSeconds) {
        $code = Test-VaultUnlock -Path $Path -Password $Password
        if ($code -ne 10) {
            return [pscustomobject]@{ Code = $code; Waited = [math]::Round(((Get-Date) - $start).TotalSeconds, 1) }
        }
        Start-Sleep -Milliseconds 200
    }
    return [pscustomobject]@{ Code = 10; Waited = $TimeoutSeconds }
}

try {
    $containerSecret = New-ContainerSecret
    New-TestVault -Path $vaultPath -Password (New-Utf8Bytes -Text $containerSecret) -Records @(
        @{ Name = $nameMarker; Data = $accountJson; Type = 2 }
    )

    $hashBefore = (Get-FileHash -LiteralPath $vaultPath -Algorithm SHA256).Hash

    # 正向对照：正确口令必须能打开，排除 harness 自身失效导致的假阴性
    $positive = Test-VaultUnlock -Path $vaultPath -Password (New-Utf8Bytes -Text $containerSecret)
    $positiveName = ConvertTo-VerthysResultName $positive
    Add-Result -Id 'PC-1' -Name '正向对照：正确口令解锁' -Expected 'OK' `
        -Observed $positiveName -Verdict $(if ($positive -eq 0) { 'PASS' } else { 'FAIL' }) `
        -Evidence "rc=$positive"

    # 成功解锁本身允许写盘，先取基准，失败尝试的副作用相对此基准判定
    $hashAfterOpen = (Get-FileHash -LiteralPath $vaultPath -Algorithm SHA256).Hash

    # 公开默认口令：基线模式期望攻击成功，修复后期望拒绝
    $probeCodes = [ordered]@{}
    foreach ($probe in @(
            @{ Label = 'public-constant'; Value = 'VERTHYS_DEFAULT_PASSWORD_v1' },
            @{ Label = 'empty'; Value = '' },
            @{ Label = 'weak-666666'; Value = '666666' }
        )) {
        $code = Test-VaultUnlock -Path $vaultPath -Password (New-Utf8Bytes -Text $probe.Value)
        $probeCodes[$probe.Label] = $code
    }

    $constantAttack = ($probeCodes['public-constant'] -eq 0)
    $emptyAttack = ($probeCodes['empty'] -eq 0)
    $weakAttack = ($probeCodes['weak-666666'] -eq 0)

    $a1Expected = '全部拒绝'
    $a1Observed = "constant=$(ConvertTo-VerthysResultName $probeCodes['public-constant']) " +
    "empty=$(ConvertTo-VerthysResultName $probeCodes['empty']) " +
    "weak=$(ConvertTo-VerthysResultName $probeCodes['weak-666666'])"

    $a1Pass = (-not $constantAttack) -and (-not $emptyAttack) -and (-not $weakAttack)
    Add-Result -Id 'A1' -Name '公开默认口令解锁' -Expected $a1Expected -Observed $a1Observed `
        -Verdict $(if ($a1Pass) { 'PASS' } else { 'FAIL' }) `
        -Evidence "constant=$($probeCodes['public-constant']) empty=$($probeCodes['empty']) weak=$($probeCodes['weak-666666'])"

    $hashAfter = (Get-FileHash -LiteralPath $vaultPath -Algorithm SHA256).Hash
    $postFailure = Invoke-UnlockAfterCooldown -Path $vaultPath -Password (New-Utf8Bytes -Text $containerSecret)
    Add-Result -Id 'A1b' -Name '退避冷却后仍可用' -Expected 'OK（不永久锁死）' `
        -Observed (ConvertTo-VerthysResultName $postFailure.Code) `
        -Verdict $(if ($postFailure.Code -eq 0) { 'PASS' } else { 'FAIL' }) `
        -Evidence "rc=$($postFailure.Code); 冷却等待=$($postFailure.Waited)s; 失败尝试未写盘=$($hashAfterOpen -eq $hashAfter); 创建后总变化=$($hashBefore -ne $hashAfter)"

    # 导入身份键去内容化：生产代码无内容哈希身份键，
    # 且同内容不同路径/同条目键重试的回归用例在场（行为由 vitest/宿主单测执行）。
    $typeFile = Join-Path $repoRoot 'verthys-tauri/src/types/verthys.ts'
    $fvSpec = Join-Path $repoRoot 'verthys-tauri/src/composables/file-verthys/useFileImport.spec.ts'
    $hostWriter = Join-Path $repoRoot 'verthys-tauri/src-tauri/src/state/import_writer.rs'
    $idKeyForbidden = @()
    foreach ($rel in @(
            'verthys-tauri/src-tauri/src/controller/types.rs',
            'verthys-tauri/src-tauri/src/repository/verthys_wal.rs',
            'verthys-tauri/src-tauri/src/state/import_writer.rs',
            'verthys-tauri/src/composables/photo-album/importPipeline.ts',
            'verthys-tauri/src/composables/file-verthys/useFileImport.ts'
        )) {
        $p = Join-Path $repoRoot $rel
        if (Test-Path -LiteralPath $p) {
            $idKeyForbidden += @(Select-String -LiteralPath $p -Pattern 'committed_hashes|chunk_ids_by_hash|chunk_<hash>' -ErrorAction SilentlyContinue)
        }
    }
    $typeHasKeys = (Test-Path -LiteralPath $typeFile) -and
        (@(Select-String -LiteralPath $typeFile -Pattern 'entry_key' -ErrorAction SilentlyContinue).Count -gt 0) -and
        (@(Select-String -LiteralPath $typeFile -Pattern 'chunk_key' -ErrorAction SilentlyContinue).Count -gt 0)
    $a20Pass = ($idKeyForbidden.Count -eq 0) -and $typeHasKeys
    Add-Result -Id 'A20' -Name '导入身份键不含内容哈希' `
        -Expected '生产代码零内容哈希身份键；entry_key/chunk_key 已定义' `
        -Observed $(if ($a20Pass) { 'PASS' } else { "残留 $($idKeyForbidden.Count) 处 / 类型缺键" }) `
        -Verdict $(if ($a20Pass) { 'PASS' } else { 'FAIL' }) `
        -Evidence "forbidden=$($idKeyForbidden.Count); entry_key/chunk_key=$typeHasKeys"

    $fvSpecText = if (Test-Path -LiteralPath $fvSpec) { Get-Content -LiteralPath $fvSpec -Raw } else { '' }
    $hostWriterText = if (Test-Path -LiteralPath $hostWriter) { Get-Content -LiteralPath $hostWriter -Raw } else { '' }
    $a20bPass = ($fvSpecText -match '同内容不同路径') -and
        ($fvSpecText -match '同一会话内同路径') -and
        ($hostWriterText -match 'test_process_append_pending_dedup_skips_committed')
    Add-Result -Id 'A20b' -Name '同条目键重试幂等' `
        -Expected '前端同内容不同路径/同键重试用例与宿主 dedup 用例在场' `
        -Observed $(if ($a20bPass) { 'PASS' } else { '用例缺失' }) `
        -Verdict $(if ($a20bPass) { 'PASS' } else { 'FAIL' }) `
        -Evidence 'vitest useFileImport.spec.ts；host import_writer::test_process_append_pending_dedup_skips_committed'

    # 未解锁枚举：新句柄直接读记录必须 LOCKED
    $lockedCode = Test-LockedRecordAccess -Path $vaultPath
    Add-Result -Id 'A3' -Name '未解锁枚举记录' -Expected 'LOCKED' `
        -Observed (ConvertTo-VerthysResultName $lockedCode) `
        -Verdict $(if ($lockedCode -eq 7) { 'PASS' } else { 'FAIL' }) `
        -Evidence "GetRecord(1)=$lockedCode"

    # 明文扫描前先自检扫描器：避免“扫描失效”被误判为零命中
    $scannerControl = Join-Path $env:TEMP ('verthys_scan_control_' + [guid]::NewGuid().ToString('N') + '.bin')
    $scannerHit = $false
    try {
        Set-Content -LiteralPath $scannerControl -Value "control-$dataMarker" -NoNewline -Encoding utf8
        $scannerHit = [VerthysAttackNative]::ContainsMarker($scannerControl, (New-Utf8Bytes -Text $dataMarker))
    }
    finally {
        Remove-Item -LiteralPath $scannerControl -Force -ErrorAction SilentlyContinue
    }
    Add-Result -Id 'SC-1' -Name '明文扫描器自检' -Expected '命中对照文件' `
        -Observed $(if ($scannerHit) { '命中' } else { '未命中' }) `
        -Verdict $(if ($scannerHit) { 'PASS' } else { 'FAIL' }) `
        -Evidence '对照文件含标记时必须被扫描器检出'

    # 明文扫描：容器与附属文件中不得出现已知明文标记
    $dataHits = @(Get-MarkerHitFiles -Root $workDir -Marker (New-Utf8Bytes -Text $dataMarker))
    Add-Result -Id 'A4' -Name '账号数据明文' -Expected '零命中' `
        -Observed $(if ($dataHits.Count -eq 0) { '零命中' } else { "$($dataHits.Count) 个文件命中" }) `
        -Verdict $(if ($dataHits.Count -eq 0) { 'PASS' } else { 'FAIL' }) `
        -Evidence ($(if ($dataHits.Count -eq 0) { 'marker 未出现在任何文件' } else { ($dataHits | Select-Object -First 3) -join '; ' }))

    $nameHits = @(Get-MarkerHitFiles -Root $workDir -Marker (New-Utf8Bytes -Text $nameMarker))
    Add-Result -Id 'A9' -Name '名称明文' -Expected '零命中' `
        -Observed $(if ($nameHits.Count -eq 0) { '零命中' } else { "$($nameHits.Count) 个文件命中" }) `
        -Verdict $(if ($nameHits.Count -eq 0) { 'PASS' } else { 'FAIL' }) `
        -Evidence ($(if ($nameHits.Count -eq 0) { 'marker 未出现在任何文件' } else { ($nameHits | Select-Object -First 3) -join '; ' }))

    # 攻击探针：分片、熔断、封装、重放、恢复码、回滚与 keyfile 各攻击面由独立进程直接驱动
    # 原语，工件全部写入临时目录，不触碰活动库。
    $probeRoot = Join-Path $workDir 'probe'
    foreach ($sub in @('a5', 'a6b', 'a14', 'a15', 'a10', 'a12', 'a16', 'a18')) {
        New-Item -ItemType Directory -Path (Join-Path $probeRoot $sub) -Force | Out-Null
    }

    $a5 = Invoke-ProbeRaw -Id 'A5' -Arguments @('a5', (Join-Path $probeRoot 'a5'))
    Add-ProbeResult -Id 'A5' -Name '分片还原' -Expected '失败：无明文、错误 seq/epoch 不可还原' -Probe $a5
    Add-ProbeResult -Id 'A6b' -Name '同机错误模块口令' -Expected '失败并熔断' `
        -Probe (Invoke-ProbeRaw -Id 'A6b' -Arguments @('a6b', (Join-Path $probeRoot 'a6b')))
    Add-ProbeResult -Id 'A14' -Name '设备根破坏' -Expected 'fail-closed（E_TPM）' `
        -Probe (Invoke-ProbeRaw -Id 'A14' -Arguments @('a14', (Join-Path $probeRoot 'a14')))

    $a7State = Join-Path $probeRoot 'a7.state'
    $a7Phase1 = Invoke-ProbeRaw -Id 'A7' -Arguments @('a7', $a7State, 'phase1')
    $a7Phase2 = Invoke-ProbeRaw -Id 'A7' -Arguments @('a7', $a7State, 'phase2')
    $a7Pass = [bool]$a7Phase1.Pass -and [int]$a7Phase1.Exit -eq 0 -and
              [bool]$a7Phase2.Pass -and [int]$a7Phase2.Exit -eq 0
    Add-Result -Id 'A7' -Name '熔断绕过' -Expected '锁定（跨进程持久）' `
        -Observed $(if ($a7Pass) { 'PASS' } else { 'FAIL' }) `
        -Verdict $(if ($a7Pass) { 'PASS' } else { 'FAIL' }) `
        -Evidence "phase1(exit=$($a7Phase1.Exit): $($a7Phase1.Detail)); phase2(exit=$($a7Phase2.Exit): $($a7Phase2.Detail))"

    Add-ProbeResult -Id 'A10' -Name 'nonce 复用' -Expected '无重复' `
        -Probe (Invoke-ProbeRaw -Id 'A10' -Arguments @('a10', (Join-Path $probeRoot 'a10')))
    Add-ProbeResult -Id 'A11' -Name '槽/记录交换重放' -Expected '认证失败' `
        -Probe (Invoke-ProbeRaw -Id 'A11' -Arguments @('a11', (Join-Path $probeRoot 'a10')))
    Add-ProbeResult -Id 'A13' -Name '明文回退注入' -Expected '拒绝' `
        -Probe (Invoke-ProbeRaw -Id 'A13' -Arguments @('a13', (Join-Path $probeRoot 'a10')))
    Add-ProbeResult -Id 'A15' -Name '恢复码流程' -Expected '正向成功、错误恢复码拒绝' `
        -Probe (Invoke-ProbeRaw -Id 'A15' -Arguments @('a15', (Join-Path $probeRoot 'a15')))
    Add-ProbeResult -Id 'A16' -Name '异种格式注入' -Expected '拒绝（E_VERSION）' `
        -Probe (Invoke-ProbeRaw -Id 'A16' -Arguments @('a16', (Join-Path $probeRoot 'a16')))
    # keyfile 因子：缺失/坏文件/换文件/剥 KEYFILE 标志（含修头哈希）/关闭
    Add-ProbeResult -Id 'A18' -Name 'keyfile 因子绕过' `
        -Expected '缺/坏/换 keyfile 均 fail-closed；剥标志仍拒绝；关闭后仅口令可开' `
        -Probe (Invoke-ProbeRaw -Id 'A18' -Arguments @('a18', (Join-Path $probeRoot 'a18')))

    Add-ProbeResult -Id 'A2' -Name '任意进程加载 DLL' -Expected '未签名/异发布者/篡改/未签名 DLL 全部拒绝；签名宿主放行' `
        -Probe (Invoke-A2Probe) -EvidencePrefix 'tests/attack/a2.ps1'
    # 渲染进程模块内容密钥材料扫描（静态源码 + dist 构建产物）
    Add-ProbeResult -Id 'A17' -Name '渲染进程模块密钥派生' `
        -Expected '源码与构建产物均无 MDEK/域标签/HKDF/原生 符号' `
        -Probe (Invoke-ResultScript 'a17-renderer-keys.ps1' 'A17') `
        -EvidencePrefix 'tests/attack/a17-renderer-keys.ps1'
    # 离机用例依赖异机人工演练：只有合格报告才升级为 PASS，否则保持 SKELETON。
    # 不接受仅改 verdict 的报告；报告路径与关键观测一并留档。
    $a6Evidence = Find-A6Evidence -Dir $A6EvidenceDir
    if ($null -ne $a6Evidence -and $a6Evidence.PSObject.Properties['StaleReason']) {
        Add-Result -Id 'A6' -Name '离机 + 已知模块口令' -Expected '失败（E_TPM）' `
            -Observed 'STALE' -Verdict 'SKELETON' `
            -Evidence ("报告存在但未绑定当前构建：" + $a6Evidence.StaleReason +
                "；需在当前 DLL/worker 上重新执行离机演练")
    }
    elseif ($null -ne $a6Evidence) {
        Add-Result -Id 'A6' -Name '离机 + 已知模块口令' -Expected '失败（E_TPM）' `
            -Observed 'PASS' -Verdict 'PASS' `
            -Evidence ("$($a6Evidence.Path); is_offmachine=true vault_open=9 " +
                "module_unlock=$($a6Evidence.Observed.module_unlock) plaintext_hits=0 artifacts_verified=true " +
                "binding=current-dll/probe/worker")
    }
    else {
        Add-Result -Id 'A6' -Name '离机 + 已知模块口令' -Expected '失败（E_TPM）' `
            -Observed '未实现' -Verdict 'SKELETON' `
            -Evidence '未找到合格离机报告（需 is_offmachine=true、vault_open=9、module_unlock≠0、plaintext_hits=0、产物哈希完整）；先运行 tests/attack/offmachine/run.ps1 -Mode prepare/verify'
    }
    Add-ProbeResult -Id 'A8' -Name '密钥内存/日志' -Expected '重启/锁定后转储 0 命中；解锁态正控必须命中' `
        -Probe (Invoke-A8Probe) -EvidencePrefix 'tests/attack/a8.ps1 + tests/attack/a8-worker.ps1'
    Add-ProbeResult -Id 'A18S' -Name 'worker 挂起处置' `
        -Expected '健康期无误杀；挂起全部线程后 3s 级触发处置并终止 worker' `
        -Probe (Invoke-ResultScript 'a18-suspend.ps1' 'A18S') `
        -EvidencePrefix 'tests/attack/a18-suspend.ps1'
    Add-ProbeResult -Id 'A12' -Name '回滚旧副本' -Expected '旧副本被锚点拒绝；恢复码可重设；锚点篡改 fail-closed' `
        -Probe (Invoke-ProbeRaw -Id 'A12' -Arguments @('a12', (Join-Path $probeRoot 'a12')))
}
catch {
    Add-Result -Id 'HARNESS' -Name '执行异常' -Expected '无异常' -Observed $_.Exception.Message `
        -Verdict 'FAIL' -Evidence $_.ScriptStackTrace
}
finally {
    if (-not $KeepWork) {
        Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    Complete-VerthysTestHygiene -Scope $hygiene
}

Write-Host ""
Write-Host "=== Verthys 攻击回归基线（$mode）===" -ForegroundColor Cyan
Write-Host "DLL: $DllPath"
Write-Host "容器来源: $vaultOrigin"
if ($KeepWork) {
    Write-Host "取证目录: $workDir"
}
$results | Format-Table -Property Id, Name, Expected, Observed, Verdict -AutoSize | Out-String -Width 220 | Write-Host

$failed = @($results | Where-Object Verdict -eq 'FAIL')
$passed = @($results | Where-Object Verdict -eq 'PASS')
$skipped = @($results | Where-Object { $_.Verdict -in @('SKELETON', 'KNOWN_GAP', 'SKIP') })

Write-Host ("汇总: PASS={0} FAIL={1} SKIP/KNOWN_GAP={2}" -f $passed.Count, $failed.Count, $skipped.Count)

$summary = [pscustomobject]@{
    Timestamp   = (Get-Date).ToString('s')
    Mode        = $mode
    Dll         = $DllPath
    VaultOrigin = $vaultOrigin
    Passed      = $passed.Count
    Failed      = $failed.Count
    Skipped     = $skipped.Count
    Results     = $results
}

if ($OutJson) {
    $parent = Split-Path -Parent $OutJson
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutJson -Encoding utf8
    Write-Host "证据已写入: $OutJson"
}

if ($failed.Count -gt 0) {
    exit 1
}
exit 0
