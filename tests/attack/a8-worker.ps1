# tests/attack/a8-worker.ps1 — Rust worker 内容层密钥内存零残留
#
# 覆盖内容层行为：
#   正控：worker 处理过的容器路径文本必须能在转储中命中（证明转储与扫描有效）；
#   负控：解锁态转储中模块口令/文件口令/包裹密钥/文件块 v2 派生密钥 0 命中
#         —— 内容层密钥已全部收敛到 C 层 MDEK，worker 不再缓存口令与派生密钥；
#   v4_module_lock（全部）后同一批 secret 仍 0 命中，且内容操作返回 LOCKED；
#   进程 stdout/stderr 捕获文本 0 命中（日志不落密钥）。
#
# 协议：与 build/ipc-smoke.ps1 相同的 IPC v2 引导行 + AEAD 信封；
#       密钥只在本脚本内存中用于计算扫描模式，不写入命令行或磁盘。
# 输出契约：供 run.ps1 解析的单行结果，可选 -OutJson 证据文件。
param(
    [string]$OutJson,
    [string]$Worker = '',
    [string]$Dll = '',
    [string]$MemHost = ''
)
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $Worker) { $Worker = Join-Path $repoRoot 'verthys-tauri/verthys-worker/target/release/verthys-worker.exe' }
if (-not $Dll) { $Dll = Join-Path $repoRoot 'build/core/Release/verthys.dll' }
if (-not $MemHost) { $MemHost = Join-Path $repoRoot 'build/core/tests/Release/vty_mem_host.exe' }
$memHost = $MemHost

if (-not (Test-Path -LiteralPath $Worker)) {
    Write-Output 'RESULT A8W FAIL release worker 缺失'
    exit 1
}
if (-not (Test-Path -LiteralPath $Dll)) {
    Write-Output 'RESULT A8W FAIL verthys.dll 缺失'
    exit 1
}
if (-not (Test-Path -LiteralPath $memHost)) {
    Write-Output 'RESULT A8W FAIL vty_mem_host.exe 缺失'
    exit 1
}

Import-Module (Join-Path $PSScriptRoot '../lib/VerthysTestHygiene.psm1') -Force
# 必须在改写 LOCALAPPDATA 前抓取真实锚点与见证快照。
$hygiene = Start-VerthysTestHygiene

Add-Type -TypeDefinition @"
using System;
using System.Security.Cryptography;
public static class A8wGcmDec {
    public static byte[] Decrypt(byte[] key, byte[] nonce, byte[] ct, byte[] tag, byte[] aad) {
        using (var aes = new AesGcm(key, 16)) {
            var pt = new byte[ct.Length];
            aes.Decrypt(nonce, ct, tag, pt, aad);
            return pt;
        }
    }
}
public sealed class A8wSealedPayload {
    public byte[] Ct;
    public byte[] Tag;
}
public static class A8wGcmEnc {
    public static A8wSealedPayload Seal(byte[] key, byte[] nonce, byte[] pt, byte[] aad) {
        using (var aes = new AesGcm(key, 16)) {
            var ct = new byte[pt.Length];
            var tag = new byte[16];
            aes.Encrypt(nonce, pt, ct, tag, aad);
            return new A8wSealedPayload { Ct = ct, Tag = tag };
        }
    }
}
"@

function Hex([byte[]]$b) { ($b | ForEach-Object { $_.ToString('x2') }) -join '' }
function Bytes([string]$s) { [Text.Encoding]::UTF8.GetBytes($s) }

function DeriveFileKeyV2([byte[]]$salt) {
    $kdf = [Security.Cryptography.Rfc2898DeriveBytes]::new(
        $script:filePass, $salt, 150000, [Security.Cryptography.HashAlgorithmName]::SHA256)
    try { return $kdf.GetBytes(32) } finally { $kdf.Dispose() }
}

$workDir = Join-Path $env:TEMP ('verthys_a8w_' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workDir -Force | Out-Null
$env:LOCALAPPDATA = Join-Path $workDir 'localappdata'
New-Item -ItemType Directory -Path $env:LOCALAPPDATA -Force | Out-Null
$dumpUnlocked = Join-Path $workDir 'worker_unlocked.dmp'
$dumpLocked = Join-Path $workDir 'worker_locked.dmp'

$suffix = [guid]::NewGuid().ToString('N').Substring(0, 8)
$script:photoSecret = "a8w-photo-$suffix"
$script:filePass = "a8w-file-$suffix"
$containerPass = "a8w-container-$suffix"
$work = Join-Path $workDir 'a8w.vty'
$salt = [byte[]]::new(16)
$salt[0] = 0xA8; $salt[15] = 0x57
$v2Key = DeriveFileKeyV2 $salt
$saltB64 = [Convert]::ToBase64String($salt)

$patterns = New-Object System.Collections.ArrayList
function Add-TextPatterns([string]$label, [string]$text) {
    $u8 = [Text.Encoding]::UTF8.GetBytes($text)
    [void]$patterns.Add(@{ Name = "$label/utf8"; Bytes = $u8 })
    [void]$patterns.Add(@{ Name = "$label/utf16"; Bytes = [Text.Encoding]::Unicode.GetBytes($text) })
    [void]$patterns.Add(@{ Name = "$label/hex"; Bytes = [Text.Encoding]::ASCII.GetBytes((Hex $u8)) })
    [void]$patterns.Add(@{ Name = "$label/b64"; Bytes = [Text.Encoding]::ASCII.GetBytes([Convert]::ToBase64String($u8)) })
}
function Add-KeyPatterns([string]$label, [byte[]]$raw) {
    [void]$patterns.Add(@{ Name = "$label/raw"; Bytes = $raw })
    [void]$patterns.Add(@{ Name = "$label/hex"; Bytes = [Text.Encoding]::ASCII.GetBytes((Hex $raw)) })
    [void]$patterns.Add(@{ Name = "$label/b64"; Bytes = [Text.Encoding]::ASCII.GetBytes([Convert]::ToBase64String($raw)) })
}
# 正控标记：容器路径（非密钥，worker 必然处理过；证明转储/扫描链路有效）
Add-TextPatterns 'container-path' $work
# 必须 0 命中的密钥面：容器口令 + 模块口令 + 文件口令 + 文件块 v2 派生密钥
Add-TextPatterns 'photo-secret' $script:photoSecret
Add-TextPatterns 'file-pass' $script:filePass
Add-TextPatterns 'container-pass' $containerPass
Add-KeyPatterns 'file-v2-key' $v2Key

function Measure-AllHits([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return -1 }
    if ((Get-Item -LiteralPath $path).Length -gt 1024MB) { return -1 }
    $bytes = [IO.File]::ReadAllBytes($path)
    $text = [Text.Encoding]::Latin1.GetString($bytes)
    [Array]::Clear($bytes, 0, $bytes.Length)
    $hits = 0
    foreach ($pat in $patterns) {
        $needle = [Text.Encoding]::Latin1.GetString($pat.Bytes)
        $idx = 0
        while (($idx = $text.IndexOf($needle, $idx, [StringComparison]::Ordinal)) -ge 0) {
            $hits++
            $idx++
        }
    }
    return $hits
}

function Measure-HitsByPattern([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $bytes = [IO.File]::ReadAllBytes($path)
    $text = [Text.Encoding]::Latin1.GetString($bytes)
    [Array]::Clear($bytes, 0, $bytes.Length)
    $result = [ordered]@{}
    foreach ($pat in $patterns) {
        $needle = [Text.Encoding]::Latin1.GetString($pat.Bytes)
        $hits = 0
        $idx = 0
        while (($idx = $text.IndexOf($needle, $idx, [StringComparison]::Ordinal)) -ge 0) {
            $hits++
            $idx++
        }
        if ($hits -gt 0) { $result[$pat.Name] = $hits }
    }
    return $result
}

function Measure-ListHits([string]$path, $list) {
    if (-not (Test-Path -LiteralPath $path)) { return -1 }
    # worker 以共享读持有容器句柄：用 ReadWrite 共享打开，避免共享冲突
    $fs = [IO.FileStream]::new($path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite)
    $ms = [IO.MemoryStream]::new()
    try {
        $fs.CopyTo($ms)
        $bytes = $ms.ToArray()
    } finally {
        $fs.Dispose()
        $ms.Dispose()
    }
    $text = [Text.Encoding]::Latin1.GetString($bytes)
    [Array]::Clear($bytes, 0, $bytes.Length)
    $hits = 0
    foreach ($pat in $list) {
        $needle = [Text.Encoding]::Latin1.GetString($pat.Bytes)
        $idx = 0
        while (($idx = $text.IndexOf($needle, $idx, [StringComparison]::Ordinal)) -ge 0) {
            $hits++
            $idx++
        }
    }
    return $hits
}

# ===== IPC v2 引导与信封 =====
$master = [byte[]]::new(32)
$sid = [byte[]]::new(16)
$chal = [byte[]]::new(32)
[Security.Cryptography.RandomNumberGenerator]::Fill($master)
[Security.Cryptography.RandomNumberGenerator]::Fill($sid)
[Security.Cryptography.RandomNumberGenerator]::Fill($chal)
$bootstrap = (@{
    v = 2; ch = 'b'; sid = (Hex $sid); key = (Hex $master); challenge = (Hex $chal)
} | ConvertTo-Json -Compress)

$psi = [Diagnostics.ProcessStartInfo]::new()
$psi.FileName = $Worker
$psi.ArgumentList.Add($Dll)
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true

$logText = New-Object System.Text.StringBuilder
$proc = [Diagnostics.Process]::Start($psi)
$pass = $true
$detail = ''
$unlockedHits = 0
$lockedHits = 0
$unlockedByPattern = $null
$lockedByPattern = $null

try {
    $proc.StandardInput.WriteLine($bootstrap)
    $proc.StandardInput.Flush()
    $line = $proc.StandardOutput.ReadLine()
    if ([string]::IsNullOrWhiteSpace($line)) { throw '未收到就绪信号' }
    [void]$logText.AppendLine($line)
    $env = $line | ConvertFrom-Json
    if ($env.v -ne 2 -or $env.ch -ne 'r') { throw '就绪信封非法' }
    if ($env.sid -ne (Hex $sid)) { throw '会话标识不匹配' }
    $respKey = [Security.Cryptography.HMACSHA256]::new($master).ComputeHash((Bytes 'verthys/ipc/response'))
    $reqKey = [Security.Cryptography.HMACSHA256]::new($master).ComputeHash((Bytes 'verthys/ipc/request'))

    $nonce = [Convert]::FromHexString($env.nonce)
    $ctAll = [Convert]::FromBase64String($env.ct)
    $tag = $ctAll[($ctAll.Length - 16)..($ctAll.Length - 1)]
    $ct = $ctAll[0..($ctAll.Length - 17)]
    $prefix = [byte[]]::new(15)
    [Array]::Copy((Bytes 'VERTHYS-IPC-V2'), 0, $prefix, 0, 14)
    $proofAad = [byte[]]::new($prefix.Length + 1 + 16 + 8 + 8)
    [Array]::Copy($prefix, 0, $proofAad, 0, $prefix.Length)
    $proofAad[$prefix.Length] = 2
    [Array]::Copy($sid, 0, $proofAad, $prefix.Length + 1, 16)
    $proofAad[$prefix.Length + 1 + 16 + 7] = 1
    $plain = [A8wGcmDec]::Decrypt($respKey, $nonce, $ct, $tag, $proofAad)
    $payload = [Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json
    if (-not $payload.ok -or $payload.op -ne 'ready') { throw '就绪载荷语义非法' }

    $requestSeq = 0
    $responseSeq = 1
    function Build-Aad([byte]$channel, [long]$seq, [long]$re) {
        $pfx = [byte[]]::new(15)
        [Array]::Copy((Bytes 'VERTHYS-IPC-V2'), 0, $pfx, 0, 14)
        $aad = [byte[]]::new($pfx.Length + 1 + 16 + 8 + 8)
        [Array]::Copy($pfx, 0, $aad, 0, $pfx.Length)
        $aad[$pfx.Length] = $channel
        [Array]::Copy($sid, 0, $aad, $pfx.Length + 1, 16)
        $seqBytes = [BitConverter]::GetBytes([long]$seq)
        [Array]::Reverse($seqBytes)
        [Array]::Copy($seqBytes, 0, $aad, $pfx.Length + 17, 8)
        $reBytes = [BitConverter]::GetBytes([long]$re)
        [Array]::Reverse($reBytes)
        [Array]::Copy($reBytes, 0, $aad, $pfx.Length + 25, 8)
        return $aad
    }

    function Send-Request($payloadObj) {
        $script:requestSeq++
        $seq = [long]$script:requestSeq
        $plain = Bytes ($payloadObj | ConvertTo-Json -Compress)
        $nonce = [byte[]]::new(12)
        $prefix = [byte[]]::new(4)
        [Security.Cryptography.RandomNumberGenerator]::Fill($prefix)
        [Array]::Copy($prefix, 0, $nonce, 0, 4)
        $seqBytes = [BitConverter]::GetBytes($seq)
        [Array]::Reverse($seqBytes)
        [Array]::Copy($seqBytes, 0, $nonce, 4, 8)
        $sealed = [A8wGcmEnc]::Seal($reqKey, $nonce, $plain, (Build-Aad 1 $seq 0))
        $ctAll = [byte[]]::new($sealed.Ct.Length + 16)
        [Array]::Copy($sealed.Ct, 0, $ctAll, 0, $sealed.Ct.Length)
        [Array]::Copy($sealed.Tag, 0, $ctAll, $sealed.Ct.Length, 16)
        $envelope = @{
            v = 2; ch = 'q'; sid = (Hex $sid); seq = $seq; re = 0
            nonce = (Hex $nonce); ct = [Convert]::ToBase64String($ctAll)
        } | ConvertTo-Json -Compress
        $proc.StandardInput.WriteLine($envelope)
        $proc.StandardInput.Flush()
        return $seq
    }

    function Read-Response([long]$replyTo) {
        $line = $proc.StandardOutput.ReadLine()
        if ([string]::IsNullOrWhiteSpace($line)) { throw '响应为空（worker 已退出）' }
        [void]$logText.AppendLine($line)
        $respEnv = $line | ConvertFrom-Json
        if ($respEnv.v -ne 2 -or $respEnv.ch -ne 'r') { throw '响应通道或版本非法' }
        if ($respEnv.re -ne $replyTo) { throw '响应关联号不匹配' }
        $script:responseSeq++
        if ($respEnv.seq -ne $script:responseSeq) { throw '响应序号失配' }
        $n = [Convert]::FromHexString($respEnv.nonce)
        $all = [Convert]::FromBase64String($respEnv.ct)
        $t = $all[($all.Length - 16)..($all.Length - 1)]
        $c = $all[0..($all.Length - 17)]
        $p = [A8wGcmDec]::Decrypt($respKey, $n, $c, $t, (Build-Aad 2 $respEnv.seq $respEnv.re))
        return ([Text.Encoding]::UTF8.GetString($p) | ConvertFrom-Json)
    }

    function Invoke-Op($payloadObj) {
        $sent = Send-Request $payloadObj
        return Read-Response $sent
    }

    # 创建 容器（宿主同路径：先路径授权，再单次创建）
    $auth = Invoke-Op @{ op = 'authorize_path'; target_op = 'v4_create'; mode = 'write'; path = $work }
    if (-not $auth.ok) { throw 'v4_create 路径授权失败' }
    $created = Invoke-Op @{ op = 'v4_create'; path = $work; password = $containerPass }
    if (-not $created.ok) { throw "容器创建失败: $($created.error)" }

    # keyfile：启用后从生成的 VKFL 读取 secret 作为密钥面负控模式；
    # secret 只在本脚本内存中用于扫描，不写入日志或证据文件。
    $kfPath = Join-Path $workDir 'a8w.vkf'
    $kfAuth = Invoke-Op @{
        op = 'authorize_path'; target_op = 'v4_keyfile_enable'; mode = 'write'; path = $kfPath
    }
    if (-not $kfAuth.ok) { throw 'v4_keyfile_enable 路径授权失败' }
    $kfEn = Invoke-Op @{
        op = 'v4_keyfile_enable'; password = $containerPass; keyfile_path = $kfPath
    }
    if (-not $kfEn.ok) { throw "keyfile 启用失败: $($kfEn.error)" }
    $kfStatus = Invoke-Op @{ op = 'v4_keyfile_status' }
    if (-not $kfStatus.ok -or -not $kfStatus.keyfile_enabled) {
        throw 'keyfile 状态未生效'
    }
    if (-not (Test-Path -LiteralPath $kfPath)) { throw 'keyfile 文件未生成' }
    $kfBytes = [IO.File]::ReadAllBytes($kfPath)
    if ($kfBytes.Length -ne 72) { throw 'keyfile 长度非法（期望 VKFL 72B）' }
    $kfSecret = $kfBytes[8..39]
    [Array]::Clear($kfBytes, 0, $kfBytes.Length)
    Add-KeyPatterns 'keyfile-secret' $kfSecret
    $kfSecretPatterns = @(
        @{ Name = 'keyfile-secret/raw'; Bytes = $kfSecret },
        @{ Name = 'keyfile-secret/hex'; Bytes = [Text.Encoding]::ASCII.GetBytes((Hex $kfSecret)) },
        @{ Name = 'keyfile-secret/b64'; Bytes = [Text.Encoding]::ASCII.GetBytes([Convert]::ToBase64String($kfSecret)) }
    )
    # keyfile secret 不得写入容器（容器里只有口令槽密文与 flag）
    $containerKfHits = Measure-ListHits $work $kfSecretPatterns
    if ($containerKfHits -ne 0) {
        $pass = $false
        $detail = "A8W-0 keyfile secret 写入容器（命中 $containerKfHits）"
    }

    # 启用照片模块：模块口令只经 C 层 user 槽，worker 不留副本
    $en = Invoke-Op @{ op = 'v4_module_enable'; module_id = 0; password = $script:photoSecret }
    if (-not $en.ok) { throw "照片模块启用失败: $($en.error)" }

    $seal = Invoke-Op @{
        op = 'module_seal'; module = 'photo'; kind = 'meta'; salt = $saltB64
        data = [Convert]::ToBase64String((Bytes '{"n":"a8w.jpg"}'))
    }
    if (-not $seal.ok) { throw "照片元数据加密失败: $($seal.error)" }

    # 文件块 v2：每文件口令 → PBKDF2 → AES-GCM，密钥只在调用期内驻留
    $v2Seal = Invoke-Op @{
        op = 'module_seal'; module = 'file'; kind = 'v2_chunk'; salt = $saltB64
        iterations = 150000; password = $script:filePass
        data = [Convert]::ToBase64String((Bytes 'a8w-file-block'))
    }
    if (-not $v2Seal.ok) { throw "文件块 v2 加密失败: $($v2Seal.error)" }

    $forbidden = @(
        'photo-secret/utf8', 'file-pass/utf8', 'container-pass/utf8',
        'file-v2-key/raw',
        'keyfile-secret/raw', 'keyfile-secret/hex', 'keyfile-secret/b64'
    )

    Start-Sleep -Milliseconds 500
    & $memHost dump $proc.Id $dumpUnlocked | Out-Null
    if (-not (Test-Path -LiteralPath $dumpUnlocked)) { throw '解锁态 worker 转储生成失败' }
    $unlockedByPattern = Measure-HitsByPattern $dumpUnlocked
    $unlockedHits = Measure-AllHits $dumpUnlocked
    # 正控：worker 处理过的容器路径必须命中，证明转储与扫描链路有效
    if (-not $unlockedByPattern.Contains('container-path/utf8')) {
        $pass = $false
        $detail = 'A8W-1 正控未命中容器路径（扫描器或转储无效）'
    }
    # 负控：内容层密钥已收敛到 C 层 MDEK，worker 不得保留口令/派生密钥
    foreach ($key in $forbidden) {
        if ($pass -and $unlockedByPattern.Contains($key)) {
            $pass = $false
            $detail = "A8W-1 解锁态 worker 内存残留 $key"
        }
    }

    # 全部模块锁定后：密钥残留仍必须为 0，且内容操作返回 LOCKED
    if ($pass) {
        # 0xFFFFFFFF 在 PowerShell 里是 Int32 -1，JSON 会变成 -1：必须显式用 UInt32
        $lockResp = Invoke-Op @{ op = 'v4_module_lock'; module_id = 4294967295 }
        if (-not $lockResp.ok) { throw 'v4_module_lock 失败' }
        $lockedSeal = Invoke-Op @{
            op = 'module_seal'; module = 'photo'; kind = 'meta'; salt = $saltB64
            data = [Convert]::ToBase64String((Bytes '{"n":"a8w.jpg"}'))
        }
        if ($lockedSeal.ok -or $lockedSeal.error -ne 'ERR_00000007') {
            $pass = $false
            $detail = 'A8W-2 锁定后内容加密未被拒绝（MDEK 未清除）'
        }
        # lock：清零 K_c/Keyring/DataRoot 与 keyfile_digest，再转储
        $vaultLock = Invoke-Op @{ op = 'lock' }
        if (-not $vaultLock.ok) { throw 'lock 失败' }
        Start-Sleep -Milliseconds 1500
        & $memHost dump $proc.Id $dumpLocked | Out-Null
        if (-not (Test-Path -LiteralPath $dumpLocked)) { throw '锁定态 worker 转储生成失败' }
        $lockedByPattern = Measure-HitsByPattern $dumpLocked
        $lockedHits = Measure-AllHits $dumpLocked
        foreach ($key in $forbidden) {
            if ($pass -and $lockedByPattern.Contains($key)) {
                $pass = $false
                $detail = "A8W-2 锁定后 worker 内存残留 $key"
            }
        }
    }

    # 日志文本（信封行不含明文口令；worker release 诊断不输出载荷）
    if ($pass) {
        $log = $logText.ToString()
        $logHits = 0
        foreach ($pat in $patterns) {
            $needle = [Text.Encoding]::Latin1.GetString($pat.Bytes)
            if ($log.Contains($needle)) { $logHits++ }
        }
        # keyfile 路径不得出现在输出流（路径不落日志）
        $kfPathU8 = [Text.Encoding]::UTF8.GetBytes($kfPath)
        $kfPathPatterns = @(
            $kfPathU8,
            [Text.Encoding]::Unicode.GetBytes($kfPath),
            [Text.Encoding]::ASCII.GetBytes((Hex $kfPathU8)),
            [Text.Encoding]::ASCII.GetBytes([Convert]::ToBase64String($kfPathU8))
        )
        foreach ($pat in $kfPathPatterns) {
            $needle = [Text.Encoding]::Latin1.GetString($pat)
            if ($log.Contains($needle)) { $logHits++ }
        }
        if ($logHits -ne 0) {
            $pass = $false
            $detail = "A8W-3 worker 输出流命中 $logHits 个 secret/路径模式"
        }
    }

    if ($pass) {
        $detail = "A8W-1 正控命中 $unlockedHits（容器路径），密钥面 0 命中；A8W-2 锁定后密钥面 0 命中且内容 LOCKED；A8W-3 输出流 0 命中；A8W-0 keyfile secret 未写入容器"
    }
} catch {
    $pass = $false
    if ($detail -eq '') { $detail = 'A8W 执行异常：' + $_.Exception.Message }
} finally {
    try {
        if (-not $proc.HasExited) {
            $proc.StandardInput.Close()
            if (-not $proc.WaitForExit(5000)) { $proc.Kill() }
        }
    } catch { }
    foreach ($d in @($dumpUnlocked, $dumpLocked, $work)) {
        if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Force -ErrorAction SilentlyContinue }
    }
    if (Test-Path -LiteralPath $workDir) { Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue }
    foreach ($arr in @($v2Key, $salt, $kfSecret)) {
        if ($arr) { [Array]::Clear($arr, 0, $arr.Length) }
    }
    [Array]::Clear($master, 0, $master.Length)
    [Array]::Clear($chal, 0, $chal.Length)
    Complete-VerthysTestHygiene -Scope $hygiene
}

if ($OutJson) {
    $report = [ordered]@{
        case = 'A8W'
        verdict = $(if ($pass) { 'PASS' } else { 'FAIL' })
        steps = @(
            'worker release + IPC v2 bootstrap',
            'authorize_path + v4_create (container password)',
            'v4_keyfile_enable → VKFL secret 负控模式；扫描容器无 secret',
            'v4_module_enable photo (module password) + seal(meta, fixed salt)',
            'seal(file v2_chunk, fixed salt, 150000, file password)',
            'MiniDumpWriteDump worker (path positive control + key negative control)',
            'v4_module_lock(all) → LOCKED probe → lock → 1.5s → MiniDumpWriteDump worker',
            'scan worker stdout/stderr capture (secrets + keyfile path)'
        )
        observed = [ordered]@{
            dump_unlocked_positive = $unlockedHits
            dump_locked = $lockedHits
            container_keyfile_secret_hits = $containerKfHits
            unlocked_patterns = $unlockedByPattern
            locked_patterns = $lockedByPattern
        }
        artifacts_sha256 = [ordered]@{
            worker = (Get-FileHash -LiteralPath $Worker -Algorithm SHA256).Hash.ToLowerInvariant()
            dll = (Get-FileHash -LiteralPath $Dll -Algorithm SHA256).Hash.ToLowerInvariant()
            mem_host = (Get-FileHash -LiteralPath $memHost -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        detail = $detail
        executed_at = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
    }
    $parent = Split-Path -Parent $OutJson
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutJson -Encoding utf8
}

Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
if ($pass) {
    Write-Output "RESULT A8W PASS $detail"
    exit 0
}
Write-Output "RESULT A8W FAIL $detail"
exit 1
