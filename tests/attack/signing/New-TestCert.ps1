# tests/attack/signing/New-TestCert.ps1 — A2 测试签名证书
#
# 生成两张自签代码签名证书：
#   CN=Verthys-Test-Publisher  受信发布者（正向对照）
#   CN=Other-Publisher         非受信发布者（必须被拒绝）
# 证书仅用于测试机；安装时写入 CurrentUser\Root 与 TrustedPeople
# （Authenticode 自签链需要进入 Root，TrustedPeople 作为显式信任补充）。
#
# 用法：pwsh New-TestCert.ps1 -Install
# 输出：CERT <subject> <thumbprint> <sha256>
param(
    [switch]$Install,
    [switch]$Force
)
$ErrorActionPreference = 'Stop'

$subjects = @('CN=Verthys-Test-Publisher', 'CN=Other-Publisher')

function Get-PublisherCert([string]$subject, [switch]$Recreate) {
    $cert = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object { $_.Subject -eq $subject -and $_.HasPrivateKey } |
        Sort-Object NotAfter -Descending | Select-Object -First 1
    if ($cert -and -not $Recreate) { return $cert }
    if ($cert -and $Recreate) {
        Remove-Item -LiteralPath $cert.PSPath -Force -ErrorAction SilentlyContinue
    }
    return New-SelfSignedCertificate -Type CodeSigningCert -Subject $subject `
        -CertStoreLocation Cert:\CurrentUser\My -KeyUsage DigitalSignature `
        -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(2)
}

foreach ($subject in $subjects) {
    $cert = Get-PublisherCert $subject -Recreate:$Force
    if ($Install) {
        $cer = Join-Path $env:TEMP ((($subject -replace '[^A-Za-z0-9]', '_')) + '.cer')
        Export-Certificate -Cert $cert -FilePath $cer -Force | Out-Null
        foreach ($store in @('Root', 'TrustedPeople')) {
            $dest = "Cert:\CurrentUser\$store"
            $exists = Get-ChildItem $dest | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
            if (-not $exists) { Import-Certificate -FilePath $cer -CertStoreLocation $dest | Out-Null }
        }
        Remove-Item -LiteralPath $cer -Force -ErrorAction SilentlyContinue
    }
    $sha = $cert.GetCertHashString([Security.Cryptography.HashAlgorithmName]::SHA256)
    Write-Output ("CERT {0} {1} {2}" -f $subject, $cert.Thumbprint, $sha.ToLowerInvariant())
}
