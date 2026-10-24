# scripts/lib/vsec.ps1 - .vsec 完整性基准注入与验证（构建后补丁，全链路单一实现）
#
# 编码警告：本文件必须保存为 UTF-8 with BOM 编码！
#   Windows PowerShell 5.1 对无 BOM 文件按 ANSI/GBK 解码，中文注释乱码会
#   破坏字符串配对导致解析错误（ParseError）。保存后请确认文件头 3 字节
#   为 EF BB BF。
#
# 使用方式（在构建脚本中 dot-source 引入，链接/POST_BUILD 之后调用）：
#   . (Join-Path $PSScriptRoot "..\lib\vsec.ps1")
#   Update-VsecBaseline -DllPath $dllPath      # 写入基准
#   Test-VsecBaseline   -DllPath $shippedPath  # 验证交付字节（CI / 产物校验）
#
# 契约（与 core/src/security/integrity/integrity.c 严格一致）：
#   .vsec 只读节 128 字节布局：
#     [0..3]   magic 'VESC'（小端 0x43534556）
#     [4..5]   version = 2
#     [6..7]   flags = 0
#     [8..39]  HMAC-SHA256(.text  文件内容)
#     [40..71] HMAC-SHA256(.rdata 文件内容)
#     [72..103] HMAC-SHA256(.rhat 文件内容)
#     [104..127] 保留全零
#   运行时 integrity_verify_startup 从磁盘重算 .text / .rdata / .rhat 三节
#   HMAC 后与本节逐槽比对；节全零 = 未配置（开发构建）→ 验签跳过。
#   因此生产链路必须在打包与 Authenticode 签名之前完成注入。
#
# 时序红线：
#   - rhash_gen 的 .rhat POST_BUILD 补丁必须先完成（本函数要求 .rhat 存在）
#   - 注入改写 DLL 字节 → 产物契约必须随后按最终字节重生成
#   - Authenticode 签名必须在注入【之后】进行（否则签名被改写失效）

# 解析 DLL 并返回三节哈希 + 现有 .vsec 基准；节缺失/越界直接抛错。
# Update 与 Test 共用此函数，保证“写入”与“验证”使用同一套节定位与
# HMAC 算法，不会出现构建期与校验期口径漂移。
function Get-VsecSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$DllPath
    )

    if (-not (Test-Path -LiteralPath $DllPath)) {
        throw ".vsec 操作失败：DLL 不存在: $DllPath"
    }

    # 域密钥与 core/src/security/integrity/integrity.c 的
    # K_VSEC_DOMAIN_KEY 逐字节一致（非秘密，仅防跨域复用）。
    $domainKey = [byte[]](
        0x76,0x65,0x72,0x74,0x68,0x79,0x73,0x2F,0x76,0x73,0x65,0x63,0x2D,0x76,0x31,0x2F,
        0x9E,0x37,0x79,0xB9,0x7F,0x4A,0x7C,0x15,
        0xBF,0x61,0x83,0xD2,0x55,0x0A,0x34,0x6C)

    $bytes = [System.IO.File]::ReadAllBytes($DllPath)
    $ms = New-Object System.IO.MemoryStream(,$bytes)
    $br = New-Object System.IO.BinaryReader($ms)

    try {
        # --- 解析 PE 头 ---
        $ms.Seek(0x3C, 'Begin') | Out-Null
        $eLfanew = $br.ReadInt32()
        if ($eLfanew -le 0 -or $eLfanew + 24 -gt $bytes.Length) { throw ".vsec 操作失败：e_lfanew 越界" }
        $ms.Seek($eLfanew, 'Begin') | Out-Null
        $sig = $br.ReadBytes(4)
        if ($sig[0] -ne 0x50 -or $sig[1] -ne 0x45) { throw ".vsec 操作失败：PE 签名不符" }
        [void]$br.ReadUInt16()             # e_lfanew+4：Machine（COFF 头首字段）
        $numSections = $br.ReadUInt16()    # e_lfanew+6：NumberOfSections
        $ms.Seek(12, 'Current') | Out-Null # 跳过 TimeDateStamp(4)+PtrSymbol(4)+NumSymbols(4) → 到 +20
        $optSize = $br.ReadUInt16()        # e_lfanew+20：SizeOfOptionalHeader
        $ms.Seek(2, 'Current') | Out-Null # 跳过 Characteristics（+22）
        $secStart = $eLfanew + 4 + 20 + $optSize

        $sections = @()
        for ($i = 0; $i -lt $numSections; $i++) {
            $headerOffset = $secStart + 40 * $i
            if ($headerOffset + 40 -gt $bytes.Length) { throw ".vsec 操作失败：节表越界" }
            $ms.Seek($headerOffset, 'Begin') | Out-Null
            $nameBytes = $br.ReadBytes(8)
            $name = [System.Text.Encoding]::ASCII.GetString($nameBytes).TrimEnd([char]0)
            [void]$br.ReadUInt32()         # VirtualSize
            [void]$br.ReadUInt32()         # VirtualAddress
            $rawSize = $br.ReadUInt32()
            $rawPtr = $br.ReadUInt32()
            $sections += [pscustomobject]@{ Name=$name; RawSize=$rawSize; RawPtr=$rawPtr }
        }
    } finally {
        $br.Dispose()
        $ms.Dispose()
    }

    $textSec  = $sections | Where-Object { $_.Name -eq ".text" }
    $rdataSec = $sections | Where-Object { $_.Name -eq ".rdata" }
    $vsec     = $sections | Where-Object { $_.Name -eq ".vsec" }
    $rhatSec  = $sections | Where-Object { $_.Name -eq ".rhat" }
    if ($null -eq $textSec  -or $textSec.RawSize  -eq 0) { throw ".vsec 操作失败：.text 节缺失" }
    if ($null -eq $rdataSec -or $rdataSec.RawSize -eq 0) { throw ".vsec 操作失败：.rdata 节缺失" }
    if ($null -eq $vsec -or $vsec.RawSize -lt 128) { throw ".vsec 操作失败：.vsec 节缺失或过小" }
    if ($null -eq $rhatSec -or $rhatSec.RawSize -eq 0) {
        throw ".vsec 操作失败：.rhat 节缺失（rhash_gen POST_BUILD 未执行?）"
    }
    if ($vsec.RawPtr + 128 -gt $bytes.Length) { throw ".vsec 操作失败：节偏移越界" }

    # 三槽必须各自取自对应节的文件内容。取错节（例如误用 .vsec 自身）
    # 会让构建“成功”但运行时验签必然失配 → KILL + CORRUPT。
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($domainKey)
    try {
        $textHash  = $hmac.ComputeHash($bytes, $textSec.RawPtr, $textSec.RawSize)
        $rdataHash = $hmac.ComputeHash($bytes, $rdataSec.RawPtr, $rdataSec.RawSize)
        $rhatHash  = $hmac.ComputeHash($bytes, $rhatSec.RawPtr, $rhatSec.RawSize)
    } finally {
        $hmac.Dispose()
    }

    $blob = New-Object byte[] 128
    [Array]::Copy($bytes, $vsec.RawPtr, $blob, 0, 128)

    return [pscustomobject]@{
        Bytes        = $bytes
        VsecRawPtr   = $vsec.RawPtr
        Blob         = $blob
        TextHash     = $textHash
        RdataHash    = $rdataHash
        RhatHash     = $rhatHash
    }
}

# 比较 .vsec 槽位与重算哈希（HMAC-SHA256 为 32 字节定长）。
function Test-VsecSlot {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Expected,
        [Parameter(Mandatory = $true)][byte[]]$Blob,
        [Parameter(Mandatory = $true)][int]$Offset
    )
    for ($i = 0; $i -lt 32; $i++) {
        if ($Expected[$i] -ne $Blob[$Offset + $i]) { return $false }
    }
    return $true
}

# 写入 .vsec v2 基准，并在落盘后逐字节自校验。
function Update-VsecBaseline {
    param(
        [Parameter(Mandatory = $true)][string]$DllPath
    )

    $snapshot = Get-VsecSnapshot -DllPath $DllPath

    # --- 写入 .vsec v2 ---
    $blob = New-Object byte[] 128
    $blob[0]=0x56; $blob[1]=0x45; $blob[2]=0x53; $blob[3]=0x43
    $blob[4]=0x02; $blob[5]=0x00
    $blob[6]=0x00; $blob[7]=0x00
    [Array]::Copy($snapshot.TextHash, 0, $blob, 8, 32)
    [Array]::Copy($snapshot.RdataHash, 0, $blob, 40, 32)
    [Array]::Copy($snapshot.RhatHash, 0, $blob, 72, 32)
    [Array]::Copy($blob, 0, $snapshot.Bytes, $snapshot.VsecRawPtr, 128)

    [System.IO.File]::WriteAllBytes($DllPath, $snapshot.Bytes)

    # 落盘后自校验：重新读取 .vsec 并与刚写入的基准逐字节比对。
    # 部分写入 / 节偏移漂移会在这里直接失败，而不是留到运行时验签。
    $persisted = [System.IO.File]::ReadAllBytes($DllPath)
    if ($persisted.Length -ne $snapshot.Bytes.Length) { throw ".vsec 注入自校验失败：DLL 长度发生变化" }
    $persistedBlob = New-Object byte[] 128
    [Array]::Copy($persisted, $snapshot.VsecRawPtr, $persistedBlob, 0, 128)
    for ($i = 0; $i -lt 128; $i++) {
        if ($persistedBlob[$i] -ne $blob[$i]) {
            throw ".vsec 注入自校验失败：落盘字节与预期基准不一致（offset=$i）"
        }
    }

    Write-Host "[vsec] 完整性基准已注入 .vsec v2（text+rdata+rhat HMAC-SHA256）" -ForegroundColor Cyan
}

# 验证交付 DLL 的 .vsec 基准：要求 magic 'VESC'、version >= 2 且三槽全部匹配。
# 返回 $true/$false（节缺失等基础设施异常仍抛错，避免静默放过）。
function Test-VsecBaseline {
    param(
        [Parameter(Mandatory = $true)][string]$DllPath
    )

    $snapshot = Get-VsecSnapshot -DllPath $DllPath
    $magic = [System.Text.Encoding]::ASCII.GetString($snapshot.Blob, 0, 4)
    if ($magic -ne 'VESC') { return $false }
    $version = [int]$snapshot.Blob[4] -bor ([int]$snapshot.Blob[5] -shl 8)
    if ($version -lt 2) { return $false }

    $textOk  = Test-VsecSlot -Expected $snapshot.TextHash  -Blob $snapshot.Blob -Offset 8
    $rdataOk = Test-VsecSlot -Expected $snapshot.RdataHash -Blob $snapshot.Blob -Offset 40
    $rhatOk  = Test-VsecSlot -Expected $snapshot.RhatHash  -Blob $snapshot.Blob -Offset 72
    return ($textOk -and $rdataOk -and $rhatOk)
}
