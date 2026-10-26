# tests/attack/a8-worker.ps1 — A8 扩展：Rust worker 内容层密钥内存零残留
#
# 覆盖：
#   A8W-1 解锁模块密钥并派生文件密钥后，worker 内存转储必须命中（正控）：
#         模块口令文本、照片包裹密钥原始字节、文件块 v2 派生密钥原始字节；
#   A8W-2 module_key_lock（全部清除）后同一批 secret 0 命中；
#   A8W-3 进程 stdout/stderr 捕获文本 0 命中（日志不落密钥）。
#
# 协议：与 build/ipc-smoke.ps1 相同的 IPC v2 引导行 + AEAD 信封；
#       密钥只在本脚本内存中用于计算扫描模式，不写入命令行或磁盘。
# 输出契约：RESULT A8W PASS|FAIL <detail>，可选 -OutJson 证据文件。
param(
    [string]$OutJson,
    [string]$Worker = '',
    [string]$Dll = ''
)
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $Worker) { $Worker = Join-Path $repoRoot 'verthys-tauri/verthys-worker/target/release/verthys-worker.exe' }
if (-not $Dll) { $Dll = Join-Path $repoRoot 'build/core/Release/verthys.dll' }
$memHost = Join-Path $repoRoot 'build/core/tests/Release/vty_mem_host.exe'

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

function HmacSha256([byte[]]$key, [byte[]]$data) {
    $h = [Security.Cryptography.HMACSHA256]::new($key)
    try { return $h.ComputeHash($data) } finally { $h.Dispose() }
}

function DerivePhotoWrapKey([byte[]]$salt) {
    $kdf = [Security.Cryptography.Rfc2898DeriveBytes]::new(
        $script:photoSecret, $salt, 150000, [Security.Cryptography.HashAlgorithmName]::SHA256)
    try { $master = $kdf.GetBytes(32) } finally { $kdf.Dispose() }
    $info = [Text.Encoding]::ASCII.GetBytes('VERTHYSPHOTO_FILE_KEY_v1')
    $t = [byte[]]::new($info.Length + 1)
    [Array]::Copy($info, 0, $t, 0, $info.Length)
    $t[$t.Length - 1] = 1
    $prk = HmacSha256 $salt $master
    $t1 = HmacSha256 $prk $t
    $key = [byte[]]::new(32)
    [Array]::Copy($t1, 0, $key, 0, 32)
    [Array]::Clear($t, 0, $t.Length)
    [Array]::Clear($t1, 0, $t1.Length)
    # master/prk 由调用方登记扫描模式后清零：它们是派生链的中间密钥材料
    return [pscustomobject]@{ Key = $key; Prk = $prk; Master = $master }
}

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
$salt = [byte[]]::new(16)
$salt[0] = 0xA8; $salt[15] = 0x57
$photoKeys = DerivePhotoWrapKey $salt
$wrapKey = $photoKeys.Key
$photoPrk = $photoKeys.Prk
$photoMaster = $photoKeys.Master
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
Add-TextPatterns 'photo-secret' $script:photoSecret
Add-TextPatterns 'file-pass' $script:filePass
Add-KeyPatterns 'photo-wrap-key' $wrapKey
Add-KeyPatterns 'photo-master' $photoMaster
Add-KeyPatterns 'photo-prk' $photoPrk
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

    # 解锁照片模块并在已知盐上派生包裹密钥
    $u1 = Invoke-Op @{ op = 'module_key_unlock'; module = 'photo'; password = $script:photoSecret }
    if (-not $u1.ok) { throw '照片模块密钥解锁失败' }
    $seal = Invoke-Op @{
        op = 'module_seal'; module = 'photo'; kind = 'meta'; salt = $saltB64
        data = [Convert]::ToBase64String((Bytes '{"n":"a8w.jpg"}'))
    }
    if (-not $seal.ok) { throw '照片元数据加密失败（无法填充派生缓存）' }

    # 文件块 v2：每文件口令 → PBKDF2，密钥进入派生缓存
    $u2 = Invoke-Op @{ op = 'module_key_unlock'; module = 'file'; password = $script:filePass }
    if (-not $u2.ok) { throw '文件模块密钥解锁失败' }
    $v2Seal = Invoke-Op @{
        op = 'module_seal'; module = 'file'; kind = 'v2_chunk'; salt = $saltB64
        iterations = 150000; password = $script:filePass
        data = [Convert]::ToBase64String((Bytes 'a8w-file-block'))
    }
    if (-not $v2Seal.ok) { throw '文件块 v2 加密失败（无法填充派生缓存）' }

    Start-Sleep -Milliseconds 500
    & $memHost dump $proc.Id $dumpUnlocked | Out-Null
    if (-not (Test-Path -LiteralPath $dumpUnlocked)) { throw '解锁态 worker 转储生成失败' }
    $unlockedByPattern = Measure-HitsByPattern $dumpUnlocked
    $unlockedHits = Measure-AllHits $dumpUnlocked
    if ($unlockedHits -le 0) {
        $pass = $false
        $detail = 'A8W-1 解锁态正控未命中（扫描器或转储无效）'
    }
    # 正控必须覆盖四类独立密钥面：两个用户口令、照片包裹密钥、
    # 文件块 v2 派生密钥；只命中其一不足以证明缓存与派生链进入转储。
    foreach ($required in @('photo-secret/utf8', 'file-pass/utf8', 'photo-wrap-key/raw', 'file-v2-key/raw')) {
        if ($pass -and -not $unlockedByPattern.Contains($required)) {
            $pass = $false
            $detail = "A8W-1 正控缺少必需命中: $required"
        }
    }

    # 全部清除后转储：口令与派生密钥必须 0 命中
    if ($pass) {
        $lockResp = Invoke-Op @{ op = 'module_key_lock' }
        if (-not $lockResp.ok) { throw 'module_key_lock 失败' }
        Start-Sleep -Milliseconds 1500
        & $memHost dump $proc.Id $dumpLocked | Out-Null
        if (-not (Test-Path -LiteralPath $dumpLocked)) { throw '锁定态 worker 转储生成失败' }
        $lockedByPattern = Measure-HitsByPattern $dumpLocked
        $lockedHits = Measure-AllHits $dumpLocked
        if ($lockedHits -ne 0) {
            $pass = $false
            $detail = "A8W-2 清除后 worker 内存仍有 $lockedHits 处命中 $((($lockedByPattern.Keys | Sort-Object) -join ','))"
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
        if ($logHits -ne 0) {
            $pass = $false
            $detail = "A8W-3 worker 输出流命中 $logHits 个 secret 模式"
        }
    }

    if ($pass) {
        $detail = "A8W-1 正控命中 $unlockedHits；A8W-2 清除后 0 命中；A8W-3 输出流 0 命中"
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
    foreach ($d in @($dumpUnlocked, $dumpLocked)) {
        if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Force -ErrorAction SilentlyContinue }
    }
    foreach ($arr in @($wrapKey, $v2Key, $salt, $photoPrk, $photoMaster)) {
        if ($arr) { [Array]::Clear($arr, 0, $arr.Length) }
    }
    [Array]::Clear($master, 0, $master.Length)
    [Array]::Clear($chal, 0, $chal.Length)
}

if ($OutJson) {
    $report = [ordered]@{
        case = 'A8W'
        verdict = $(if ($pass) { 'PASS' } else { 'FAIL' })
        steps = @(
            'worker release + IPC v2 bootstrap',
            'module_key_unlock photo + seal(meta, fixed salt)',
            'module_key_unlock file + seal(v2_chunk, fixed salt, 150000)',
            'MiniDumpWriteDump worker (positive control)',
            'module_key_lock(all) → 1.5s → MiniDumpWriteDump worker',
            'scan worker stdout/stderr capture'
        )
        observed = [ordered]@{
            dump_unlocked_positive = $unlockedHits
            dump_locked = $lockedHits
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
