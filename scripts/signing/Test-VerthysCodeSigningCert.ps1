# scripts/signing/Test-VerthysCodeSigningCert.ps1 - 校验代码签名证书与产物签名
#
# 编码警告：本文件必须保存为 UTF-8 with BOM 编码！
#   Windows PowerShell 5.1 对无 BOM 文件按 ANSI/GBK 解码，中文注释乱码会破坏
#   字符串配对导致 ParseError。
#
# 校验内容：
#   - 叶证书存在、含私钥、有效期、代码签名 EKU、非 CA
#   - 证书链可构建到已安装的 Verthys 根证书
#   - 指定产物的 Authenticode 状态为 Valid，签名者指纹与叶证书一致
#
# 用法:
#   powershell -ExecutionPolicy Bypass -File scripts\signing\Test-VerthysCodeSigningCert.ps1 `
#       -ArtifactPath build\core\Release\verthys.dll, verthys-tauri\src-tauri\target\release\Verthys.exe

[CmdletBinding()]
param(
    [string]$Thumbprint = "",
    [string[]]$ArtifactPath = @(),
    [string]$OutputDir = (Join-Path $env:USERPROFILE ".verthys-ca")
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

$codeSigningEku = "1.3.6.1.5.5.7.3.3"

if ([string]::IsNullOrWhiteSpace($Thumbprint)) {
    $metaPath = Join-Path $OutputDir "code-signing.json"
    if (-not (Test-Path -LiteralPath $metaPath -PathType Leaf)) {
        throw "未提供 -Thumbprint，且元数据文件不存在: $metaPath"
    }
    $meta = Get-Content -LiteralPath $metaPath -Raw | ConvertFrom-Json
    $Thumbprint = [string]$meta.thumbprint
}

$leaf = Get-ChildItem "Cert:\CurrentUser\My" -ErrorAction SilentlyContinue |
    Where-Object { $_.Thumbprint -eq $Thumbprint } |
    Select-Object -First 1
if ($null -eq $leaf) { throw "CurrentUser\My 未找到证书 $Thumbprint" }
if (-not $leaf.HasPrivateKey) { throw "证书 $Thumbprint 缺少私钥" }
if ($leaf.NotAfter -lt (Get-Date)) { throw "证书 $Thumbprint 已过期（$($leaf.NotAfter.ToString('yyyy-MM-dd'))）" }

$bcExt = $leaf.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.19" } | Select-Object -First 1
if ($null -eq $bcExt) { throw "证书缺少 BasicConstraints 扩展" }
$bc = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]$bcExt
if ($bc.CertificateAuthority) { throw "证书被标记为 CA，不能作为代码签名证书使用" }

$ekuExt = $leaf.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.37" } | Select-Object -First 1
if ($null -eq $ekuExt) { throw "证书缺少 EnhancedKeyUsage 扩展" }
$eku = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$ekuExt
if (-not ($eku.EnhancedKeyUsages | Where-Object { $_.Value -eq $codeSigningEku })) {
    throw "证书缺少代码签名 EKU（$codeSigningEku）"
}

$publisherSha256 = $leaf.GetCertHashString(
    [System.Security.Cryptography.HashAlgorithmName]::SHA256).ToLowerInvariant()

$chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
try {
    # 自建离线根没有 CRL/OCSP，强行在线吊销检查会把正常链判为未知；
    # 这里校验的是签名信任关系，吊销由根移除与版本替换流程承担。
    $chain.ChainPolicy.RevocationMode =
        [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    $chainOk = $chain.Build($leaf)
    if (-not $chainOk) {
        $statusText = ($chain.ChainStatus | ForEach-Object { $_.Status.ToString() }) -join "; "
        throw "证书链校验失败：$statusText（确认根证书已安装到 CurrentUser\Root 或 LocalMachine\Root）"
    }
} finally {
    $chain.Dispose()
}

Write-Host "[verify] 证书校验通过" -ForegroundColor Green
Write-Host "  Subject          : $($leaf.Subject)"
Write-Host "  Thumbprint       : $($leaf.Thumbprint)"
Write-Host "  Publisher SHA-256: $publisherSha256"
Write-Host "  有效期           : $($leaf.NotBefore.ToString('yyyy-MM-dd')) ~ $($leaf.NotAfter.ToString('yyyy-MM-dd'))"

$failures = New-Object System.Collections.Generic.List[string]
$results = New-Object System.Collections.Generic.List[object]

foreach ($artifact in $ArtifactPath) {
    if ([string]::IsNullOrWhiteSpace($artifact)) { continue }
    $resolved = Resolve-Path -LiteralPath $artifact -ErrorAction SilentlyContinue
    if ($null -eq $resolved) {
        $failures.Add("产物不存在: $artifact")
        continue
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $resolved.Path
    $signerSha = ""
    if ($null -ne $signature.SignerCertificate) {
        $signerSha = $signature.SignerCertificate.GetCertHashString(
            [System.Security.Cryptography.HashAlgorithmName]::SHA256).ToLowerInvariant()
    }
    $results.Add([pscustomobject]@{
        Path     = $resolved.Path
        Status   = $signature.Status
        Signer   = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { "" }
        Sha256   = $signerSha
    })
    if ($signature.Status -ne "Valid") {
        $failures.Add("Authenticode 状态不是 Valid: $($resolved.Path)（$($signature.Status)）")
    } elseif ($signerSha -ne $publisherSha256) {
        $failures.Add("签名者指纹不一致: $($resolved.Path)（actual=$signerSha expected=$publisherSha256）")
    }
}

if ($results.Count -gt 0) {
    Write-Host ""
    $results | Format-Table Path, Status, Signer -AutoSize | Out-String | Write-Host
}

if ($failures.Count -gt 0) {
    throw ("签名校验失败：`n - " + ($failures -join "`n - "))
}

Write-Host "[ok] 全部校验通过" -ForegroundColor Green
