# scripts/signing/New-VerthysCodeSigningCert.ps1 - 用离线根 CA 签发 Verthys 代码签名证书
#
# 编码警告：本文件必须保存为 UTF-8 with BOM 编码！
#   Windows PowerShell 5.1 对无 BOM 文件按 ANSI/GBK 解码，中文注释乱码会破坏
#   字符串配对导致 ParseError。
#
# 设计约束：
#   - 根 PFX 只在签发期间临时导入证书库，签发完成后立即删除
#   - 叶证书留在 CurrentUser\My 供构建按指纹调用
#   - 口令只从文件读取，不打印、不写入日志
#
# 用法:
#   powershell -ExecutionPolicy Bypass -File scripts\signing\New-VerthysCodeSigningCert.ps1 `
#       -RootPfxPath "$env:USERPROFILE\.verthys-ca\VerthysRootCA.pfx" `
#       -RootPassphrasePath "$env:USERPROFILE\.verthys-ca\root.passphrase.txt"

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RootPfxPath,
    [Parameter(Mandatory = $true)][string]$RootPassphrasePath,
    [string]$Subject = "CN=Verthys, O=K1Super, C=CN",
    [int]$Years = 2,
    [string]$OutputDir = (Join-Path $env:USERPROFILE ".verthys-ca")
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

$codeSigningEku = "1.3.6.1.5.5.7.3.3"

function New-RandomPassphrase {
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $bytes = New-Object byte[] 32
        $rng.GetBytes($bytes)
        return [Convert]::ToBase64String($bytes)
    } finally {
        $rng.Dispose()
    }
}

function Write-Utf8File {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text
    )
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

function Assert-LeafExtensions {
    param([Parameter(Mandatory = $true)]$Certificate)

    if (-not $Certificate.HasPrivateKey) { throw "叶证书缺少私钥，无法签名" }

    $bcExt = $Certificate.Extensions |
        Where-Object { $_.Oid.Value -eq "2.5.29.19" } |
        Select-Object -First 1
    if ($null -eq $bcExt) { throw "叶证书缺少 BasicConstraints 扩展" }
    $bc = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]$bcExt
    if ($bc.CertificateAuthority) { throw "叶证书 BasicConstraints 不能标记为 CA" }

    $ekuExt = $Certificate.Extensions |
        Where-Object { $_.Oid.Value -eq "2.5.29.37" } |
        Select-Object -First 1
    if ($null -eq $ekuExt) { throw "叶证书缺少 EnhancedKeyUsage 扩展" }
    $eku = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$ekuExt
    if (-not ($eku.EnhancedKeyUsages | Where-Object { $_.Value -eq $codeSigningEku })) {
        throw "叶证书缺少代码签名 EKU（$codeSigningEku）"
    }
}

Write-Host "[ca] 签发代码签名证书: $Subject" -ForegroundColor Cyan

$resolvedPfx = (Resolve-Path -LiteralPath $RootPfxPath).Path
if (-not (Test-Path -LiteralPath $RootPassphrasePath -PathType Leaf)) {
    throw "根证书口令文件不存在: $RootPassphrasePath"
}
$passphrase = (Get-Content -LiteralPath $RootPassphrasePath -Raw).Trim()
if ([string]::IsNullOrEmpty($passphrase)) { throw "根证书口令文件为空" }
$secure = ConvertTo-SecureString -String $passphrase -AsPlainText -Force

$imported = @(Import-PfxCertificate -FilePath $resolvedPfx -CertStoreLocation "Cert:\CurrentUser\My" -Password $secure)
$root = $imported | Where-Object { $_.HasPrivateKey } | Select-Object -First 1
if ($null -eq $root) {
    foreach ($item in $imported) {
        Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $item.Thumbprint) -Force -ErrorAction SilentlyContinue
    }
    throw "根 PFX 中未找到含私钥的证书"
}
if ($root.Subject -notlike "CN=Verthys Root CA*") {
    Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $root.Thumbprint) -Force -ErrorAction SilentlyContinue
    throw "根证书主题不符合预期: $($root.Subject)"
}

try {
    $leaf = New-SelfSignedCertificate `
        -Type Custom `
        -Subject $Subject `
        -Signer $root `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -KeyExportPolicy Exportable `
        -KeyUsage DigitalSignature `
        -KeyUsageProperty Sign `
        -NotAfter (Get-Date).AddYears($Years) `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -TextExtension @(
            "2.5.29.19={critical}{text}ca=0",
            "2.5.29.37={text}$codeSigningEku"
        )

    if ($leaf.Subject -ne $Subject) { throw "叶证书主题不符合预期: $($leaf.Subject)" }
    if ($leaf.Issuer -ne $root.Subject) { throw "叶证书签发者与根证书不一致: $($leaf.Issuer)" }
    Assert-LeafExtensions -Certificate $leaf

    $keySize = $leaf.PublicKey.Key.KeySize
    if ($keySize -lt 3072) { throw "叶证书密钥长度不足 3072 位（实际 $keySize）" }

    # 生成阶段不依赖本机信任库：.NET 5+ 用自定义信任链做密码学校验；
    # Windows PowerShell 5.1 的 .NET Framework 无此能力，退化为 AKI/SKI 结构校验，
    # 完整信任链校验由信任安装后的 Test 脚本与构建门禁承担。
    $supportsCustomTrust = $null -ne (
        [System.Management.Automation.PSTypeName]'System.Security.Cryptography.X509Certificates.X509ChainTrustMode').Type

    if ($supportsCustomTrust) {
        $rootPublic = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($root.RawData)
        $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
        try {
            $chain.ChainPolicy.TrustMode =
                [System.Security.Cryptography.X509Certificates.X509ChainTrustMode]::CustomRootTrust
            $chain.ChainPolicy.CustomTrustStore.Add($rootPublic)
            $chain.ChainPolicy.ExtraStore.Add($rootPublic)
            $chain.ChainPolicy.RevocationMode =
                [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
            $chainOk = $chain.Build($leaf)
            if (-not $chainOk) {
                $statusText = ($chain.ChainStatus | ForEach-Object { $_.Status.ToString() }) -join "; "
                throw "叶证书链校验失败（生成阶段）: $statusText"
            }
        } finally {
            $chain.Dispose()
        }
    } else {
        $akiExt = $leaf.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.35" } | Select-Object -First 1
        $skiExt = $root.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.14" } | Select-Object -First 1
        if ($null -eq $akiExt -or $null -eq $skiExt) {
            throw "叶证书缺少 AuthorityKeyIdentifier 或根证书缺少 SubjectKeyIdentifier，无法确认签发关系"
        }
        $ski = [System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]$skiExt
        $akiHex = ($akiExt.RawData | ForEach-Object { $_.ToString("X2") }) -join ""
        if (-not $akiHex.Contains($ski.SubjectKeyIdentifier.ToUpperInvariant())) {
            throw "叶证书 AuthorityKeyIdentifier 与根证书 SubjectKeyIdentifier 不匹配"
        }
        Write-Host "[ca] 当前宿主不支持自定义信任链，已完成 AKI/SKI 结构校验" -ForegroundColor Yellow
    }

    if (-not (Test-Path -LiteralPath $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

    $cerPath = Join-Path $OutputDir "VerthysCodeSigning.cer"
    $pfxPath = Join-Path $OutputDir "VerthysCodeSigning.pfx"
    $passPath = Join-Path $OutputDir "code-signing.passphrase.txt"
    $metaPath = Join-Path $OutputDir "code-signing.json"

    $leafPassphrase = New-RandomPassphrase
    $leafSecure = ConvertTo-SecureString -String $leafPassphrase -AsPlainText -Force

    Export-Certificate -Cert $leaf -FilePath $cerPath -Type CERT -Force | Out-Null
    Export-PfxCertificate -Cert $leaf -FilePath $pfxPath -Password $leafSecure -Force | Out-Null
    Write-Utf8File -Path $passPath -Text $leafPassphrase

    $publisherSha256 = $leaf.GetCertHashString(
        [System.Security.Cryptography.HashAlgorithmName]::SHA256).ToLowerInvariant()

    $meta = [ordered]@{
        subject          = $leaf.Subject
        issuer           = $leaf.Issuer
        thumbprint       = $leaf.Thumbprint
        publisherSha256  = $publisherSha256
        serialNumber     = $leaf.SerialNumber
        notBefore        = $leaf.NotBefore.ToString("yyyy-MM-dd")
        notAfter         = $leaf.NotAfter.ToString("yyyy-MM-dd")
        cerPath          = $cerPath
        pfxPath          = $pfxPath
        passphrasePath   = $passPath
        createdAt        = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }
    Write-Utf8File -Path $metaPath -Text ($meta | ConvertTo-Json)

    foreach ($path in @($cerPath, $pfxPath, $passPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "导出失败: $path" }
    }

    Write-Host "[ok] 代码签名证书已签发并导入 CurrentUser\My" -ForegroundColor Green
    Write-Host "  Subject          : $($leaf.Subject)"
    Write-Host "  Thumbprint       : $($leaf.Thumbprint)"
    Write-Host "  Publisher SHA-256: $publisherSha256"
    Write-Host "  有效期           : $($leaf.NotBefore.ToString('yyyy-MM-dd')) ~ $($leaf.NotAfter.ToString('yyyy-MM-dd'))"
    Write-Host "  证书             : $cerPath"
    Write-Host "  加密 PFX         : $pfxPath"
    Write-Host "  口令文件         : $passPath"
    Write-Host "  元数据           : $metaPath"
    Write-Host ""
    Write-Host "[必做] 把叶证书 PFX 与口令抄入密码管理器/离线介质，然后删除本机口令文件" -ForegroundColor Yellow
    Write-Host "[必做] 构建前先安装根证书信任，否则签名复核会返回 NotTrusted" -ForegroundColor Yellow
} finally {
    Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $root.Thumbprint) -Force -ErrorAction SilentlyContinue
}
