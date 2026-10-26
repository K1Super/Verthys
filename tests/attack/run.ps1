<#
 * tests/attack/run.ps1 — 攻击回归基线
 *
 * 用法：
 *   pwsh tests/attack/run.ps1                          # 修复后期望：A1/A3/A4/A9 全部拒绝
 *   pwsh tests/attack/run.ps1 -Vault <旧副本> -Baseline  # 旧格式基线：A1 应能攻击成功
 *   pwsh tests/attack/run.ps1 -OutJson <路径>            # 输出机器可读证据
 *
 * 判定口径：
 *   PASS      = 实际结果符合该模式下的期望
 *   FAIL      = 实际结果不符合期望（修复后出现即回归）
 *   KNOWN_GAP = 当前阶段尚未实现的防护（登记目标阶段，不计入退出码）
 *   SKELETON  = 攻击用例骨架已登记，具体实现随对应阶段落地
 *
 * 安全约束：
 *   - 传入的 -Vault 一律先复制到独立临时目录再操作，原副本保持只读。
 *   - 所有临时容器在结束时删除（-KeepWork 可保留用于取证）。
 *   - 不打印任何口令内容。
#>
[CmdletBinding()]
param(
    [string]$Vault,
    [switch]$Baseline,
    [string]$DllPath,
    [string]$OutJson,
    [switch]$KeepWork
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'VerthysHarness.psm1') -Force

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
if (-not $DllPath) {
    $DllPath = Join-Path $repoRoot 'build/core/Release/verthys.dll'
}
$DllPath = Initialize-VerthysNative -DllPath $DllPath
# v4 攻击探针：独立进程直接驱动 v4 原语（不扩大生产 DLL 导出面）。
# 构建目标 verthys_tests 依赖 vty_probe，正常构建后必然存在。
$probePath = Join-Path $repoRoot 'build/core/tests/Release/vty_probe.exe'

if ($Vault -and -not $Baseline) {
    throw '传入 -Vault 时必须同时指定 -Baseline：非基线模式使用自生成的随机口令容器，避免误判他人副本。'
}
if ($Vault) {
    $Vault = (Resolve-Path -LiteralPath $Vault).Path
}

$workDir = Join-Path $env:TEMP ('verthys_attack_' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workDir -Force | Out-Null
# 持久化熔断状态默认落在 %LOCALAPPDATA%\Verthys：攻击回归会故意制造失败，
# 必须把本次进程树的 LOCALAPPDATA 指向临时目录，避免污染真实用户状态、
# 也避免上次运行遗留的锁定影响本次判定。
$env:LOCALAPPDATA = Join-Path $workDir 'localappdata'
New-Item -ItemType Directory -Path $env:LOCALAPPDATA -Force | Out-Null
$vaultPath = Join-Path $workDir 'attack.verthys'

$runId = [guid]::NewGuid().ToString('N')
$nameMarker = "A9_NAME_MARKER_$runId"
$dataMarker = "A4_SECRET_MARKER_$runId"
$accountJson = "{`"account`":`"attack-probe`",`"secret`":`"$dataMarker`",`"note`":`"plaintext-canary`"}"

$results = New-Object System.Collections.Generic.List[object]
$mode = if ($Baseline) { 'Baseline' } else { 'PostFix' }
$vaultOrigin = 'unknown'
$inject = 0

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
    # 任一失败即 A8 失败，避免只验证一侧而给出片面的 PASS。
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
    if ($Vault) {
        Copy-Item -LiteralPath $Vault -Destination $vaultPath -Force
        $containerSecret = 'VERTHYS_DEFAULT_PASSWORD_v1'
        $vaultOrigin = 'copied'
    }
    else {
        $containerSecret = if ($Baseline) { 'VERTHYS_DEFAULT_PASSWORD_v1' } else { New-ContainerSecret }
        New-TestVault -Path $vaultPath -Password (New-Utf8Bytes -Text $containerSecret) -Preset 0 -Records @(
            @{ Name = $nameMarker; Data = $accountJson; Type = 2 }
        )
        $vaultOrigin = 'generated'
    }

    if ($Vault -and $Baseline) {
        $inject = Add-TestRecordToVault -Path $vaultPath -Password (New-Utf8Bytes -Text $containerSecret) `
            -Name $nameMarker -Data $accountJson
        if ($inject -ne 0) {
            $injectName = ConvertTo-VerthysResultName $inject
            Write-Warning "基线副本无法用公开常量解锁（$injectName），A4/A9 仅做静态扫描，证据不完整。"
        }
    }

    $hashBefore = (Get-FileHash -LiteralPath $vaultPath -Algorithm SHA256).Hash

    # 正向对照：正确口令必须能打开，排除 harness 自身失效导致的假阴性
    $positive = Test-VaultUnlock -Path $vaultPath -Password (New-Utf8Bytes -Text $containerSecret)
    $positiveName = ConvertTo-VerthysResultName $positive
    Add-Result -Id 'PC-1' -Name '正向对照：正确口令解锁' -Expected 'OK' `
        -Observed $positiveName -Verdict $(if ($positive -eq 0) { 'PASS' } else { 'FAIL' }) `
        -Evidence "rc=$positive"

    # 成功解锁本身允许写盘，先取基准，失败尝试的副作用相对此基准判定
    $hashAfterOpen = (Get-FileHash -LiteralPath $vaultPath -Algorithm SHA256).Hash

    # A1 公开默认口令：基线模式期望攻击成功，修复后期望拒绝
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

    $a1Expected = if ($Baseline) { '公开常量解锁成功' } else { '全部拒绝' }
    $a1Observed = "constant=$(ConvertTo-VerthysResultName $probeCodes['public-constant']) " +
    "empty=$(ConvertTo-VerthysResultName $probeCodes['empty']) " +
    "weak=$(ConvertTo-VerthysResultName $probeCodes['weak-666666'])"

    $a1Pass = if ($Baseline) {
        $constantAttack -and (-not $emptyAttack) -and (-not $weakAttack)
    }
    else {
        (-not $constantAttack) -and (-not $emptyAttack) -and (-not $weakAttack)
    }
    Add-Result -Id 'A1' -Name '公开默认口令解锁' -Expected $a1Expected -Observed $a1Observed `
        -Verdict $(if ($a1Pass) { 'PASS' } else { 'FAIL' }) `
        -Evidence "constant=$($probeCodes['public-constant']) empty=$($probeCodes['empty']) weak=$($probeCodes['weak-666666'])"

    $hashAfter = (Get-FileHash -LiteralPath $vaultPath -Algorithm SHA256).Hash
    $postFailure = Invoke-UnlockAfterCooldown -Path $vaultPath -Password (New-Utf8Bytes -Text $containerSecret)
    Add-Result -Id 'A1b' -Name '退避冷却后仍可用' -Expected 'OK（不永久锁死）' `
        -Observed (ConvertTo-VerthysResultName $postFailure.Code) `
        -Verdict $(if ($postFailure.Code -eq 0) { 'PASS' } else { 'FAIL' }) `
        -Evidence "rc=$($postFailure.Code); 冷却等待=$($postFailure.Waited)s; 失败尝试未写盘=$($hashAfterOpen -eq $hashAfter); 创建后总变化=$($hashBefore -ne $hashAfter)"

    # A3 未解锁枚举：新句柄直接读记录必须 LOCKED
    $lockedCode = Test-LockedRecordAccess -Path $vaultPath
    Add-Result -Id 'A3' -Name '未解锁枚举记录' -Expected 'LOCKED' `
        -Observed (ConvertTo-VerthysResultName $lockedCode) `
        -Verdict $(if ($lockedCode -eq 7) { 'PASS' } else { 'FAIL' }) `
        -Evidence "GetRecord(1)=$lockedCode"

    # A4/A9 明文扫描前先自检扫描器：避免“扫描失效”被误判为零命中
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

    # A4/A9 明文扫描：容器与附属文件中不得出现已知明文标记
    if ($Vault -and $Baseline -and $inject -ne 0) {
        Add-Result -Id 'A4' -Name '账号数据明文' -Expected '零命中' -Observed 'SKIP' `
            -Verdict 'SKIP' -Evidence '基线副本口令不匹配，标记未能注入'
        Add-Result -Id 'A9' -Name '名称明文' -Expected '零命中' -Observed 'SKIP' `
            -Verdict 'SKIP' -Evidence '基线副本口令不匹配，标记未能注入'
    }
    else {
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
    }

    # v4 攻击探针：A5/A6b/A7/A10/A11/A12/A13/A14/A15 由独立进程直接驱动 v4 原语，
    # 工件全部写入临时目录，不触碰活动库。
    $probeRoot = Join-Path $workDir 'probe'
    foreach ($sub in @('a5', 'a6b', 'a14', 'a15', 'a10', 'a12')) {
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

    Add-ProbeResult -Id 'A2' -Name '任意进程加载 DLL' -Expected '未签名/异发布者/篡改/未签名 DLL 全部拒绝；签名宿主放行' `
        -Probe (Invoke-A2Probe) -EvidencePrefix 'tests/attack/a2.ps1'
    # 尚未实现的攻击面：登记目标阶段，避免“未覆盖”被误解为“已通过”
    Add-Result -Id 'A6' -Name '离机 + 已知模块口令' -Expected '失败' -Observed '未实现' -Verdict 'SKELETON' `
        -Evidence '探针与离机脚本已就绪（vty_probe a6/a6run、tests/attack/offmachine/run.ps1）；异机 Tier 2 未执行'
    Add-ProbeResult -Id 'A8' -Name '密钥内存/日志' -Expected '重启/锁定后转储 0 命中；解锁态正控必须命中' `
        -Probe (Invoke-A8Probe) -EvidencePrefix 'tests/attack/a8.ps1 + tests/attack/a8-worker.ps1'
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
if ($Baseline -and -not ($results | Where-Object { $_.Id -eq 'A1' -and $_.Verdict -eq 'PASS' })) {
    Write-Warning '基线前提未成立：公开常量未能打开该副本，基线证据无效。'
    exit 2
}
exit 0
