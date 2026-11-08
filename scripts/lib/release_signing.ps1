# scripts/lib/release_signing.ps1 - Release 发布者签名基础设施
#
# 职责边界：
#   - 解析发布者代码签名证书（证书库指纹或 PFX 内存加载）
#   - 由证书 DER 派生 SHA-256 指纹，并与可选的显式钉扎值交叉校验
#   - 对 PE 文件执行 Authenticode 签名与复核，失败一律抛错
#
# 安全约束：
#   - 证书口令只从环境变量读取，函数不落盘、不回显、不写入日志
#   - PFX 使用 EphemeralKeySet 加载，私钥只存在于当前进程内存
#   - 指纹由实际签名证书派生，避免“签了 A 证书、钉了 B 指纹”的部署事故
#
# 使用方式：dot-source 后在构建脚本中调用 Resolve-VerthysReleaseSigning
#
# 编码警告：本文件必须保存为 UTF-8 with BOM 编码！
#   Windows PowerShell 5.1 对无 BOM 文件按 ANSI/GBK 解码，中文注释乱码会
#   破坏字符串配对导致解析错误（ParseError）。

Set-StrictMode -Version 3.0

# 按 Process → User → Machine 依次读取环境变量，任一非空即返回。
# 与构建环境加载口径一致，避免“本机持久变量看不到”的部署差异。
function Read-VerthysSigningEnv {
    param([string]$Name)
    foreach ($scope in @("Process", "User", "Machine")) {
        $value = [System.Environment]::GetEnvironmentVariable($Name, $scope)
        if (-not [string]::IsNullOrEmpty($value)) { return $value }
    }
    return ""
}

# 证书公钥指纹：SHA-256 over DER，与运行期 WinVerifyTrust 取出的
# pCert->pbCertEncoded 再哈希的口径完全一致。
function Get-VerthysCertificateSha256 {
    param([Parameter(Mandatory = $true)]$Certificate)
    return $Certificate.GetCertHashString(
        [System.Security.Cryptography.HashAlgorithmName]::SHA256).ToLowerInvariant()
}

# 归一化外部传入的 SHA-256 指纹：允许分隔符与大写，最终要求 64 位小写十六进制。
function ConvertTo-VerthysPublisherSha256 {
    param([Parameter(Mandatory = $true)][string]$Raw, [string]$SourceName = "发布者指纹")
    $normalized = ($Raw -replace '[^0-9A-Fa-f]', '').ToLowerInvariant()
    if ($normalized.Length -ne 64) {
        throw "$SourceName 不是有效的 SHA-256（需要 64 位十六进制，实际 $($normalized.Length) 位）"
    }
    return $normalized
}

# 解析发布者证书：
#   优先 VERTHYS_SIGNING_THUMBPRINT（证书库，私钥不需导出）
#   其次 VERTHYS_SIGNING_PFX + VERTHYS_SIGNING_PFX_PASSWORD（临时内存加载）
# -Required 为真时缺失即抛错；否则返回 $null 供调用方显式降级。
function Get-VerthysSigningCertificate {
    param([switch]$Required)

    $thumbprintRaw = Read-VerthysSigningEnv "VERTHYS_SIGNING_THUMBPRINT"
    if (-not [string]::IsNullOrEmpty($thumbprintRaw)) {
        $thumbprint = ($thumbprintRaw -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
        if ($thumbprint.Length -ne 40) {
            throw "VERTHYS_SIGNING_THUMBPRINT 不是有效的证书指纹（需要 40 位十六进制）"
        }
        foreach ($store in @("Cert:\CurrentUser\My", "Cert:\LocalMachine\My")) {
            $cert = Get-ChildItem -LiteralPath $store -ErrorAction SilentlyContinue |
                Where-Object { $_.Thumbprint -eq $thumbprint } |
                Select-Object -First 1
            if ($null -ne $cert) {
                if (-not $cert.HasPrivateKey) {
                    throw "证书 $thumbprint 存在于 $store 但缺少私钥，无法签名"
                }
                if ($cert.NotAfter -lt (Get-Date)) {
                    throw "证书 $thumbprint 已过期（$($cert.NotAfter.ToString('yyyy-MM-dd'))），拒绝签名"
                }
                return $cert
            }
        }
        throw "未在 CurrentUser\My 或 LocalMachine\My 找到证书 $thumbprint（需含私钥）"
    }

    $pfxPath = Read-VerthysSigningEnv "VERTHYS_SIGNING_PFX"
    if (-not [string]::IsNullOrEmpty($pfxPath)) {
        if (-not (Test-Path -LiteralPath $pfxPath -PathType Leaf)) {
            throw "VERTHYS_SIGNING_PFX 指向的证书文件不存在: $pfxPath"
        }
        $password = Read-VerthysSigningEnv "VERTHYS_SIGNING_PFX_PASSWORD"
        try {
            # EphemeralKeySet：私钥只驻留进程内存，不写入用户证书库与磁盘密钥容器。
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                $pfxPath, $password,
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
        } catch {
            throw "无法加载 PFX（口令错误、文件损坏或平台不支持临时私钥）: $($_.Exception.Message)"
        }
        if (-not $cert.HasPrivateKey) {
            throw "PFX 中的证书缺少私钥，无法签名: $pfxPath"
        }
        if ($cert.NotAfter -lt (Get-Date)) {
            throw "PFX 证书已过期（$($cert.NotAfter.ToString('yyyy-MM-dd'))），拒绝签名"
        }
        return $cert
    }

    if ($Required) {
        throw ("生产签名缺少发布者证书：请设置 VERTHYS_SIGNING_THUMBPRINT（推荐）" +
            " 或 VERTHYS_SIGNING_PFX + VERTHYS_SIGNING_PFX_PASSWORD")
    }
    return $null
}

# 计算并交叉校验发布者指纹。
# 显式值用于职责分离场景（信任根由发布负责人生成），与证书不一致时必须失败。
function Resolve-VerthysPublisherSha256 {
    param(
        [Parameter(Mandatory = $true)]$Certificate,
        [string]$ExplicitSha256 = ""
    )
    $derived = Get-VerthysCertificateSha256 -Certificate $Certificate
    if (-not [string]::IsNullOrEmpty($ExplicitSha256)) {
        $explicit = ConvertTo-VerthysPublisherSha256 -Raw $ExplicitSha256 -SourceName "VERTHYS_PUBLISHER_SHA256"
        if ($explicit -ne $derived) {
            throw ("发布者指纹不一致：证书实际 SHA-256=$derived，" +
                "VERTHYS_PUBLISHER_SHA256=$explicit。拒绝把不同证书的指纹注入运行期校验")
        }
    }
    return $derived
}

# 解析本轮构建的签名上下文。
# 返回对象字段：Enabled / Certificate / PublisherSha256 / TimestampServer。
function Resolve-VerthysReleaseSigning {
    param([switch]$Required)

    $cert = Get-VerthysSigningCertificate -Required:$Required
    if ($null -eq $cert) {
        return [pscustomobject]@{
            Enabled         = $false
            Certificate     = $null
            PublisherSha256 = ""
            TimestampServer = ""
        }
    }

    $explicit = Read-VerthysSigningEnv "VERTHYS_PUBLISHER_SHA256"
    $publisherSha = Resolve-VerthysPublisherSha256 -Certificate $cert -ExplicitSha256 $explicit
    $timestamp = Read-VerthysSigningEnv "VERTHYS_SIGNING_TIMESTAMP_URL"
    if ([string]::IsNullOrEmpty($timestamp)) {
        Write-Warning "未设置 VERTHYS_SIGNING_TIMESTAMP_URL：签名不带可信时间戳，证书过期后签名将失效"
    }

    return [pscustomobject]@{
        Enabled         = $true
        Certificate     = $cert
        PublisherSha256 = $publisherSha
        TimestampServer = $timestamp
    }
}

# 复核 PE 的 Authenticode 状态与签名者指纹。
# 任何“未签名、链不受信、指纹不符”都抛错，不返回布尔降级值。
function Assert-VerthysAuthenticodeSignature {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "待复核文件不存在: $Path"
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne "Valid") {
        throw "Authenticode 无效: $Path（状态 $($signature.Status): $($signature.StatusMessage)）"
    }
    if ($null -eq $signature.SignerCertificate) {
        throw "Authenticode 状态有效但缺少签名者证书: $Path"
    }
    $actual = Get-VerthysCertificateSha256 -Certificate $signature.SignerCertificate
    $expected = ConvertTo-VerthysPublisherSha256 -Raw $ExpectedSha256
    if ($actual -ne $expected) {
        throw "签名者证书 SHA-256 与钉扎值不一致: $Path（actual=$actual expected=$expected）"
    }
    return $signature
}

# 对单个 PE 执行 Authenticode 签名。
# 幂等：已由目标证书有效签名时跳过，避免重复改写字节与刷新时间戳。
function Invoke-VerthysAuthenticodeSign {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Certificate,
        [string]$TimestampServer = ""
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "待签名文件不存在: $Path"
    }
    $expected = Get-VerthysCertificateSha256 -Certificate $Certificate

    $current = Get-AuthenticodeSignature -LiteralPath $Path
    if ($current.Status -eq "Valid" -and $null -ne $current.SignerCertificate) {
        $currentSha = Get-VerthysCertificateSha256 -Certificate $current.SignerCertificate
        if ($currentSha -eq $expected) {
            Write-Host "[sign] 已由目标发布者签名，跳过: $Path" -ForegroundColor Cyan
            return
        }
    }

    $parameters = @{
        FilePath      = $Path
        Certificate   = $Certificate
        HashAlgorithm = "SHA256"
    }
    if (-not [string]::IsNullOrEmpty($TimestampServer)) {
        $parameters["TimestampServer"] = $TimestampServer
    }
    $signature = Set-AuthenticodeSignature @parameters
    if ($signature.Status -ne "Valid") {
        throw "签名后校验不通过: $Path（状态 $($signature.Status): $($signature.StatusMessage)）"
    }
    Assert-VerthysAuthenticodeSignature -Path $Path -ExpectedSha256 $expected | Out-Null
    Write-Host "[sign] 已签名并复核: $Path" -ForegroundColor Cyan
}
