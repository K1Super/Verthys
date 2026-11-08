<#
  tests/e2e/worker-smoke.ps1 — worker IPC 层的 产品链端到端

  覆盖：创建返回恢复码 → PCR 状态/启用/关闭 → 恢复码轮换 → 锁定 →
  旧码拒绝 / 新码解锁。使用与宿主相同的 IPC v2 引导、AEAD 信封与路径授权。
  验证完成后删除临时库；所有密钥只驻留本脚本内存。
#>
param(
    [string]$Worker = "",
    [string]$Dll = ""
)
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
if (-not $Worker) { $Worker = Join-Path $repoRoot 'verthys-tauri/verthys-worker/target/release/verthys-worker.exe' }
if (-not $Dll) { $Dll = Join-Path $repoRoot 'build/core/Release/verthys.dll' }
if (-not (Test-Path -LiteralPath $Worker)) { throw "worker 缺失: $Worker" }
if (-not (Test-Path -LiteralPath $Dll)) { throw "verthys.dll 缺失: $Dll" }

Import-Module (Join-Path $PSScriptRoot '../lib/VerthysTestHygiene.psm1') -Force
# 见证密钥不受 LOCALAPPDATA 隔离影响，必须在改写环境变量前记录真实快照。
$hygiene = Start-VerthysTestHygiene

# 隔离锁存/回滚状态：状态文件走 KnownFolder，LOCALAPPDATA 覆盖无效；
# 测试钩子构建通过 VERTHYS_TEST_STATE_DIR 显式隔离，避免跨脚本运行累计
# 失败次数或改写真实用户状态。必须在启动 worker 之前设置，子进程继承。
$isoRoot = Join-Path $env:TEMP ("smoke_env_" + [guid]::NewGuid().ToString('N'))
$env:LOCALAPPDATA = Join-Path $isoRoot 'localappdata'
New-Item -ItemType Directory -Path $env:LOCALAPPDATA -Force | Out-Null
# 熔断/回滚状态走 KnownFolder，LOCALAPPDATA 覆盖不到；测试钩子构建用
# VERTHYS_TEST_STATE_DIR 显式隔离，避免改写真实用户状态。
$oldTestStateDir = $env:VERTHYS_TEST_STATE_DIR
$env:VERTHYS_TEST_STATE_DIR = Join-Path $isoRoot 'security_state'
New-Item -ItemType Directory -Path $env:VERTHYS_TEST_STATE_DIR -Force | Out-Null
# P2 安全服务是生产强制依赖；worker 测试使用测试钩子 DLL，显式旁路机器预算。
$oldMachineBypass = $env:VERTHYS_TEST_MACHINE_LIMITER_BYPASS
$env:VERTHYS_TEST_MACHINE_LIMITER_BYPASS = '1'

Add-Type -TypeDefinition @"
using System;
using System.Security.Cryptography;
public static class P4GcmDec {
    public static byte[] Decrypt(byte[] key, byte[] nonce, byte[] ct, byte[] tag, byte[] aad) {
        using (var aes = new AesGcm(key, 16)) {
            var pt = new byte[ct.Length];
            aes.Decrypt(nonce, ct, tag, pt, aad);
            return pt;
        }
    }
}
public sealed class P4Sealed { public byte[] Ct; public byte[] Tag; }
public static class P4GcmEnc {
    public static P4Sealed Seal(byte[] key, byte[] nonce, byte[] pt, byte[] aad) {
        using (var aes = new AesGcm(key, 16)) {
            var ct = new byte[pt.Length];
            var tag = new byte[16];
            aes.Encrypt(nonce, pt, ct, tag, aad);
            return new P4Sealed { Ct = ct, Tag = tag };
        }
    }
}
"@

function Hex([byte[]]$b) { ($b | ForEach-Object { $_.ToString('x2') }) -join '' }
function Bytes([string]$s) { [Text.Encoding]::UTF8.GetBytes($s) }

$master = [byte[]]::new(32)
$sid = [byte[]]::new(16)
$chal = [byte[]]::new(32)
[Security.Cryptography.RandomNumberGenerator]::Fill($master)
[Security.Cryptography.RandomNumberGenerator]::Fill($sid)
[Security.Cryptography.RandomNumberGenerator]::Fill($chal)

$bootstrap = (@{ v = 2; ch = 'b'; sid = (Hex $sid); key = (Hex $master); challenge = (Hex $chal) } | ConvertTo-Json -Compress)

$psi = [Diagnostics.ProcessStartInfo]::new()
$psi.FileName = $Worker
$psi.ArgumentList.Add($Dll)
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$p = [Diagnostics.Process]::Start($psi)

$work = Join-Path $env:TEMP ("smoke_" + [guid]::NewGuid().ToString('N') + ".vty")
$password = "smoke-pw"
$requestSeq = 0
$responseSeq = 1
$script:progressLines = 0

try {
    $p.StandardInput.WriteLine($bootstrap)
    $p.StandardInput.Flush()
    $task = $p.StandardOutput.ReadLineAsync()
    if (-not $task.Wait(20000)) { throw "就绪信号超时" }
    $line = $task.Result
    if ([string]::IsNullOrWhiteSpace($line)) { throw "未收到就绪信号" }
    $env = $line | ConvertFrom-Json
    if ($env.v -ne 2 -or $env.ch -ne 'r') { throw "就绪信封非法" }

    $respKey = [Security.Cryptography.HMACSHA256]::new($master).ComputeHash((Bytes 'verthys/ipc/response'))
    $reqKey = [Security.Cryptography.HMACSHA256]::new($master).ComputeHash((Bytes 'verthys/ipc/request'))

    function Build-Aad([byte]$channel, [long]$seq, [long]$re) {
        $prefix = [byte[]]::new(15)
        [Array]::Copy((Bytes 'VERTHYS-IPC-V2'), 0, $prefix, 0, 14)
        $aad = [byte[]]::new($prefix.Length + 1 + 16 + 8 + 8)
        [Array]::Copy($prefix, 0, $aad, 0, $prefix.Length)
        $aad[$prefix.Length] = $channel
        [Array]::Copy($sid, 0, $aad, $prefix.Length + 1, 16)
        $sb = [BitConverter]::GetBytes([long]$seq); [Array]::Reverse($sb)
        [Array]::Copy($sb, 0, $aad, $prefix.Length + 17, 8)
        $rb = [BitConverter]::GetBytes([long]$re); [Array]::Reverse($rb)
        [Array]::Copy($rb, 0, $aad, $prefix.Length + 25, 8)
        return $aad
    }

    # 就绪响应解密
    $nonce = [Convert]::FromHexString($env.nonce)
    $ctAll = [Convert]::FromBase64String($env.ct)
    $tag = $ctAll[($ctAll.Length - 16)..($ctAll.Length - 1)]
    $ct = $ctAll[0..($ctAll.Length - 17)]
    $plain = [P4GcmDec]::Decrypt($respKey, $nonce, $ct, $tag, (Build-Aad 2 $env.seq $env.re))
    $ready = [Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json
    if (-not $ready.ok -or $ready.op -ne 'ready') { throw "就绪载荷非法" }

    function Send-Request($payload) {
        $script:requestSeq++
        $seq = [long]$script:requestSeq
        $plain = Bytes ($payload | ConvertTo-Json -Compress)
        $nonce = [byte[]]::new(12)
        $prefix = [byte[]]::new(4)
        [Security.Cryptography.RandomNumberGenerator]::Fill($prefix)
        [Array]::Copy($prefix, 0, $nonce, 0, 4)
        $sb = [BitConverter]::GetBytes($seq); [Array]::Reverse($sb)
        [Array]::Copy($sb, 0, $nonce, 4, 8)
        $sealed = [P4GcmEnc]::Seal($reqKey, $nonce, $plain, (Build-Aad 1 $seq 0))
        $all = [byte[]]::new($sealed.Ct.Length + 16)
        [Array]::Copy($sealed.Ct, 0, $all, 0, $sealed.Ct.Length)
        [Array]::Copy($sealed.Tag, 0, $all, $sealed.Ct.Length, 16)
        $envelope = @{ v = 2; ch = 'q'; sid = (Hex $sid); seq = $seq; re = 0; nonce = (Hex $nonce); ct = [Convert]::ToBase64String($all) } | ConvertTo-Json -Compress
        $p.StandardInput.WriteLine($envelope)
        $p.StandardInput.Flush()
        return $seq
    }

    function Read-Response([long]$replyTo) {
        while ($true) {
            $line = $p.StandardOutput.ReadLine()
            if ([string]::IsNullOrWhiteSpace($line)) { throw "响应为空（worker 可能崩溃）" }
            $env = $line | ConvertFrom-Json
            if ($env.re -ne $replyTo) { throw "响应关联号不匹配" }
            # 进度行（ch='p'）只用于流式观测，不参与响应序号校验；继续等待终止行。
            if ($env.ch -eq 'p') { $script:progressLines++; continue }
            $script:responseSeq++
            if ($env.seq -ne $script:responseSeq) { throw "响应序号失配" }
            $nonce = [Convert]::FromHexString($env.nonce)
            $ctAll = [Convert]::FromBase64String($env.ct)
            $tag = $ctAll[($ctAll.Length - 16)..($ctAll.Length - 1)]
            $ct = $ctAll[0..($ctAll.Length - 17)]
            $plain = [P4GcmDec]::Decrypt($respKey, $nonce, $ct, $tag, (Build-Aad 2 $env.seq $env.re))
            return ([Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json)
        }
    }

    function Op($payload) { $s = Send-Request $payload; return Read-Response $s }

    $auth = Op @{ op = 'authorize_path'; target_op = 'v4_create'; mode = 'write'; path = $work }
    if (-not $auth.ok) { throw "v4_create 路径授权失败" }

    $created = Op @{ op = 'v4_create'; path = $work; password = $password }
    if (-not $created.ok) { throw "v4_create 失败: $($created.error)" }
    $code = $created.recovery_code
    if ([string]::IsNullOrWhiteSpace($code)) { throw "创建未返回恢复码" }
    Write-Host "PASS create recovery_code_len=$($code.Length)"

    # 内容路径：模块启用 → 分片加解密 → 文件口令内层校验
    $enable = Op @{ op = 'v4_module_enable'; module_id = 0; password = 'content-mod-pw' }
    if (-not $enable.ok) { throw "照片模块启用失败: $($enable.error)" }
    $saltBytes = [byte[]]::new(16)
    [Security.Cryptography.RandomNumberGenerator]::Fill($saltBytes)
    $saltB64 = [Convert]::ToBase64String($saltBytes)
    $metaPlain = '{"name":"e2e.jpg","size":3}'
    $metaSeal = Op @{
        op = 'module_seal'; module = 'photo'; kind = 'meta'
        data = [Convert]::ToBase64String((Bytes $metaPlain)); salt = $saltB64
    }
    if (-not $metaSeal.ok) { throw "元数据 加封失败: $($metaSeal.error)" }
    $metaOpen = Op @{ op = 'module_open'; module = 'photo'; kind = 'meta'; data = $metaSeal.data }
    if (-not $metaOpen.ok) { throw "元数据 解封失败: $($metaOpen.error)" }
    if ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($metaOpen.data)) -ne $metaPlain) {
        throw "元数据往返不一致"
    }
    Write-Host "PASS photo meta chunk roundtrip"

    $v2Plain = [Convert]::ToBase64String((Bytes 'file-block-plain'))
    $v2Seal = Op @{
        op = 'module_seal'; module = 'file'; kind = 'v2_chunk'; data = $v2Plain
        salt = $saltB64; iterations = 150000; password = 'file-pass'
    }
    if (-not $v2Seal.ok) { throw "文件块 加封失败: $($v2Seal.error)" }
    $v2Open = Op @{
        op = 'module_open'; module = 'file'; kind = 'v2_chunk'; data = $v2Seal.data
        salt = $saltB64; iterations = 150000; password = 'file-pass'
    }
    if (-not $v2Open.ok -or $v2Open.data -ne $v2Plain) { throw "文件块口令往返失败" }
    $v2Wrong = Op @{
        op = 'module_open'; module = 'file'; kind = 'v2_chunk'; data = $v2Seal.data
        salt = $saltB64; iterations = 150000; password = 'wrong-pass'
    }
    if ($v2Wrong.ok) { throw "错误文件口令仍可解密" }
    Write-Host "PASS file chunk password binding"

    $checkSeal = Op @{
        op = 'module_seal'; module = 'file'; kind = 'v2_check'; data = ''
        salt = $saltB64; iterations = 150000; password = 'file-pass'
    }
    if (-not $checkSeal.ok) { throw "口令校验块 加封失败" }
    $checkOk = Op @{
        op = 'module_open'; module = 'file'; kind = 'v2_check'; data = $checkSeal.data
        salt = $saltB64; iterations = 150000; password = 'file-pass'
    }
    $checkBad = Op @{
        op = 'module_open'; module = 'file'; kind = 'v2_check'; data = $checkSeal.data
        salt = $saltB64; iterations = 150000; password = 'wrong-pass'
    }
    if (-not $checkOk.ok -or $checkBad.ok) { throw "口令校验块语义错误" }
    Write-Host "PASS file password check"

    $lockMod = Op @{ op = 'v4_module_lock'; module_id = 0 }
    if (-not $lockMod.ok) { throw "照片模块锁定失败" }
    $lockedSeal = Op @{
        op = 'module_seal'; module = 'photo'; kind = 'meta'
        data = [Convert]::ToBase64String((Bytes $metaPlain)); salt = $saltB64
    }
    if ($lockedSeal.ok -or $lockedSeal.error -ne 'ERR_00000007') {
        throw "模块锁定后内容加封未被拒绝（应 LOCKED）"
    }
    Write-Host "PASS content requires module unlock"

    # 模块解锁：错误口令拒绝，正确口令恢复内容路径
    $unlockBad = Op @{ op = 'v4_module_unlock'; module_id = 0; password = 'wrong-mod-pw' }
    if ($unlockBad.ok -or $unlockBad.error -ne 'ERR_00000002') {
        throw "错误模块口令未被拒绝"
    }
    $unlockOk = Op @{ op = 'v4_module_unlock'; module_id = 0; password = 'content-mod-pw' }
    if (-not $unlockOk.ok -or $unlockOk.unlocked -ne $true) {
        throw "模块解锁失败或状态未标记 unlocked: $($unlockOk.error)"
    }
    Write-Host "PASS module unlock requires password"

    # 恢复槽绑定：模块口令 + 容器恢复码；状态必须回传 has_recovery
    $bindRecovery = Op @{
        op = 'v4_module_bind_recovery'; module_id = 0
        password = 'content-mod-pw'; recovery_code = $code
    }
    if (-not $bindRecovery.ok -or $bindRecovery.has_recovery -ne $true) {
        throw "模块恢复槽绑定失败: $($bindRecovery.error)"
    }
    # 普通（口令）会话重密封设备槽必须被策略拒绝
    $resealDenied = Op @{ op = 'v4_module_reseal_device'; module_id = 0; password = 'content-mod-pw' }
    if ($resealDenied.ok -or $resealDenied.error -ne 'ERR_00000017') {
        throw "普通会话重密封未被策略拒绝"
    }
    Write-Host "PASS module recovery bind and reseal policy"

    # 内容种类错配必须被拒绝：C 分片 AAD 不含 kind，由 worker 域标签绑定
    $mismatch = Op @{ op = 'module_open'; module = 'photo'; kind = 'thumb'; data = $metaSeal.data }
    if ($mismatch.ok -or $mismatch.error -ne 'ERR_00000002') {
        throw "种类错配未被拒绝"
    }
    Write-Host "PASS content kind binding"

    # 模块口令轮换：只重封 user 槽；旧口令失效、新口令可用
    $rotate = Op @{
        op = 'v4_module_rotate_password'; module_id = 0
        old_password = 'content-mod-pw'; new_password = 'content-mod-pw-2'
    }
    if (-not $rotate.ok) { throw "模块口令轮换失败: $($rotate.error)" }
    $lockAgain = Op @{ op = 'v4_module_lock'; module_id = 0 }
    if (-not $lockAgain.ok) { throw "轮换后锁定失败" }
    $oldUnlock = Op @{ op = 'v4_module_unlock'; module_id = 0; password = 'content-mod-pw' }
    if ($oldUnlock.ok) { throw "轮换后旧口令仍可解锁" }
    $newUnlock = Op @{ op = 'v4_module_unlock'; module_id = 0; password = 'content-mod-pw-2' }
    if (-not $newUnlock.ok) { throw "轮换后新口令解锁失败: $($newUnlock.error)" }
    Write-Host "PASS module password rotation"

    # 关闭保护：MDEK 回 Keyring；内容路径无需解锁即可用（数据保留）
    $disable = Op @{ op = 'v4_module_disable'; module_id = 0; password = 'content-mod-pw-2' }
    if (-not $disable.ok -or $disable.enabled -ne $false) {
        throw "模块关闭失败: $($disable.error)"
    }
    $afterDisable = Op @{
        op = 'module_seal'; module = 'photo'; kind = 'meta'
        data = [Convert]::ToBase64String((Bytes $metaPlain)); salt = $saltB64
    }
    if (-not $afterDisable.ok) { throw "关闭保护后内容路径仍不可用（MDEK 应回 Keyring）" }
    Write-Host "PASS module disable returns MDEK to keyring"

    # 删除模块：密码学销毁 + 叶清除，进入 deleted；之后可重建空模块
    $del = Op @{ op = 'v4_module_delete'; module_id = 0; password = $password; confirm = 'DELETE' }
    if (-not $del.ok -or $del.deleted -ne $true) {
        throw "模块删除失败或状态未标记 deleted: $($del.error)"
    }
    $reenable = Op @{ op = 'v4_module_enable'; module_id = 0; password = 'content-mod-pw-3' }
    if (-not $reenable.ok -or $reenable.enabled -ne $true) {
        throw "删除后重建模块失败: $($reenable.error)"
    }
    Write-Host "PASS module delete and recreate"

    $st = Op @{ op = 'v4_pcr_status' }
    if (-not $st.ok -or $st.pcr_enabled -ne $false) { throw "初始 PCR 状态非法" }
    $en = Op @{ op = 'v4_pcr_enable'; pcr_select = 0x880; recovery_code = $code }
    if (-not $en.ok) { throw "PCR 启用失败: $($en.error)" }
    $st = Op @{ op = 'v4_pcr_status' }
    if (-not $st.ok -or $st.pcr_enabled -ne $true -or $st.pcr_select -ne 0x880) { throw "PCR 启用后状态非法" }
    $off = Op @{ op = 'v4_pcr_disable'; recovery_code = $code }
    if (-not $off.ok) { throw "PCR 关闭失败: $($off.error)" }
    $st = Op @{ op = 'v4_pcr_status' }
    if (-not $st.ok -or $st.pcr_enabled -ne $false) { throw "PCR 关闭后状态非法" }
    Write-Host "PASS pcr enable/disable"

    $rot = Op @{ op = 'v4_recovery_rotate'; password = $password; old_recovery = $code }
    if (-not $rot.ok -or [string]::IsNullOrWhiteSpace($rot.recovery_code)) { throw "恢复码轮换失败: $($rot.error)" }
    $newCode = $rot.recovery_code
    if ($newCode -eq $code) { throw "新恢复码未变化" }
    Write-Host "PASS recovery rotate"

    $lock = Op @{ op = 'lock' }
    if (-not $lock.ok) { throw "锁定失败" }
    $auth = Op @{ op = 'authorize_path'; target_op = 'v4_unlock_recovery'; mode = 'read'; path = $work }
    if (-not $auth.ok) { throw "恢复解锁路径授权失败" }

    $old = Op @{ op = 'v4_unlock_recovery'; path = $work; recovery_code = $code }
    if ($old.ok) { throw "旧恢复码仍可解锁" }
    $auth = Op @{ op = 'authorize_path'; target_op = 'v4_unlock_recovery'; mode = 'read'; path = $work }
    if (-not $auth.ok) { throw "新恢复码解锁路径授权失败" }
    $new = Op @{ op = 'v4_unlock_recovery'; path = $work; recovery_code = $newCode }
    if (-not $new.ok) { throw "新恢复码解锁失败: $($new.error)" }
    Write-Host "PASS recovery rotate invalidates old code"

    # 恢复会话删除模块：worker 以 C 层 recovery_mode 为权威，传空口令；
    # 请求里携带错误口令也必须成功（普通会话才校验口令）。
    $delRecovery = Op @{ op = 'v4_module_delete'; module_id = 0; password = 'wrong-password'; confirm = 'DELETE' }
    if (-not $delRecovery.ok) { throw "恢复会话删除模块失败: $($delRecovery.error)" }
    $delStatus = Op @{ op = 'v4_module_status'; module_id = 0 }
    if (-not $delStatus.ok -or $delStatus.deleted -ne $true) { throw "恢复会话删除后状态非法" }
    Write-Host "PASS recovery session module delete without container password"

    # 恢复会话重绑容器 user/device 槽：新本机口令必须可普通解锁。
    $resealPassword = "smoke-pw-2"
    $reseal = Op @{ op = 'v4_reseal_device'; password = $resealPassword; keyfile_path = '' }
    if (-not $reseal.ok) { throw "恢复会话容器槽重绑失败: $($reseal.error)" }
    Write-Host "PASS recovery reseal device"

    $lock = Op @{ op = 'lock' }
    if (-not $lock.ok) { throw "重绑后锁定失败" }
    $auth = Op @{ op = 'authorize_path'; target_op = 'unlock'; mode = 'read'; path = $work }
    if (-not $auth.ok) { throw "重绑后解锁路径授权失败" }
    $reopen = Op @{ op = 'unlock'; path = $work; password = $resealPassword; flags = 0 }
    if (-not $reopen.ok) { throw "重绑后普通解锁失败: $($reopen.error)" }
    Write-Host "PASS recovery reseal normal unlock"

    # 全库 DEK 轮换：恢复码会话 + 已启用模块口令登记；
    # 先验证 Run→Abort（源库不变），再验证 Run→Commit（记录随新库保留）。
    $reenableRotate = Op @{ op = 'v4_module_enable'; module_id = 0; password = 'rotate-mod-pw' }
    if (-not $reenableRotate.ok) { throw "轮换前启用模块失败: $($reenableRotate.error)" }
    $rotateRecord = Op @{
        op = 'add_record'; rtype = 1; name = 'rotate-e2e'
        data = [Convert]::ToBase64String((Bytes 'rotate-payload'))
    }
    if (-not $rotateRecord.ok) { throw "轮换前写入记录失败: $($rotateRecord.error)" }

    $lock = Op @{ op = 'lock' }
    if (-not $lock.ok) { throw "轮换前锁定失败" }
    $auth = Op @{ op = 'authorize_path'; target_op = 'v4_unlock_recovery'; mode = 'read'; path = $work }
    if (-not $auth.ok) { throw "轮换前恢复解锁路径授权失败" }
    $recoveryAgain = Op @{ op = 'v4_unlock_recovery'; path = $work; recovery_code = $newCode }
    if (-not $recoveryAgain.ok) { throw "轮换前恢复解锁失败: $($recoveryAgain.error)" }

    $rotateNewA = "$work.rot-a"
    Remove-Item -LiteralPath $rotateNewA -Force -ErrorAction SilentlyContinue
    $auth = Op @{ op = 'authorize_path'; target_op = 'v4_rotate_begin'; mode = 'write'; path = $rotateNewA }
    if (-not $auth.ok) { throw "轮换 A 路径授权失败" }
    $beginA = Op @{ op = 'v4_rotate_begin'; new_path = $rotateNewA; password = $resealPassword; flags = 1 }
    if (-not $beginA.ok) { throw "轮换 Begin 失败: $($beginA.error)" }
    if ($beginA.rotate_stage -ne 1) { throw "轮换 Begin 阶段非法: $($beginA.rotate_stage)" }
    $unlockModA = Op @{ op = 'v4_rotate_unlock_module'; module_id = 0; password = 'rotate-mod-pw' }
    if (-not $unlockModA.ok) { throw "轮换模块口令登记失败: $($unlockModA.error)" }
    $runA = Op @{ op = 'v4_rotate_run' }
    if (-not $runA.ok) { throw "轮换 Run 失败: $($runA.error)" }
    if ($script:progressLines -lt 1) { throw "轮换 Run 未产生进度行" }
    $abortA = Op @{ op = 'v4_rotate_abort' }
    if (-not $abortA.ok) { throw "轮换 Abort 失败: $($abortA.error)" }
    if (Test-Path -LiteralPath $rotateNewA) { throw "Abort 后临时库仍然存在" }
    Write-Host "PASS vault dek rotation run + abort"

    $rotateNewB = "$work.rot-b"
    Remove-Item -LiteralPath $rotateNewB -Force -ErrorAction SilentlyContinue
    $auth = Op @{ op = 'authorize_path'; target_op = 'v4_rotate_begin'; mode = 'write'; path = $rotateNewB }
    if (-not $auth.ok) { throw "轮换 B 路径授权失败" }
    $beginB = Op @{ op = 'v4_rotate_begin'; new_path = $rotateNewB; password = $resealPassword; flags = 1 }
    if (-not $beginB.ok) { throw "轮换 Begin（提交）失败: $($beginB.error)" }
    $unlockModB = Op @{ op = 'v4_rotate_unlock_module'; module_id = 0; password = 'rotate-mod-pw' }
    if (-not $unlockModB.ok) { throw "轮换模块口令登记（提交）失败: $($unlockModB.error)" }
    $runB = Op @{ op = 'v4_rotate_run' }
    if (-not $runB.ok) { throw "轮换 Run（提交）失败: $($runB.error)" }
    $commitB = Op @{ op = 'v4_rotate_commit'; keep_old = $false }
    if (-not $commitB.ok) { throw "轮换 Commit 失败: $($commitB.error)" }
    $afterCommit = Op @{ op = 'get_record'; id = $rotateRecord.id }
    if (-not $afterCommit.ok) { throw "轮换提交后记录读取失败: $($afterCommit.error)" }
    $decoded = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($afterCommit.data))
    if ($decoded -ne 'rotate-payload') { throw "轮换提交后记录内容不一致" }
    Write-Host "PASS vault dek rotation run + commit"

    $lock = Op @{ op = 'lock' }
    if (-not $lock.ok) { throw "最终锁定失败" }
    Write-Host "RESULT PI-4-SMOKE PASS"
    exit 0
} catch {
    # 失败时回收 worker stderr（诊断输出），便于定位失败阶段；
    # 先终止进程再读管道，避免 ReadToEnd 阻塞在仍存活的子进程上。
    try {
        if (-not $p.HasExited) { $p.Kill(); $p.WaitForExit(3000) | Out-Null }
        $err = $p.StandardError.ReadToEnd()
        if (-not [string]::IsNullOrWhiteSpace($err)) {
            Write-Host "--- worker stderr ---"
            Write-Host $err
            Write-Host "----------------------"
        }
    } catch { }
    throw
} finally {
    try { if (-not $p.HasExited) { $p.Kill(); $p.WaitForExit(5000) | Out-Null } } catch { }
    Remove-Item -LiteralPath $work -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath "$work.lock" -Force -ErrorAction SilentlyContinue
    Get-ChildItem -LiteralPath (Split-Path -Parent $work) -Filter ((Split-Path -Leaf $work) + "*") -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    $env:VERTHYS_TEST_MACHINE_LIMITER_BYPASS = $oldMachineBypass
    $env:VERTHYS_TEST_STATE_DIR = $oldTestStateDir
    if (Test-Path -LiteralPath $isoRoot) { Remove-Item -LiteralPath $isoRoot -Recurse -Force -ErrorAction SilentlyContinue }
    Complete-VerthysTestHygiene -Scope $hygiene
}
