# tests/attack/signing/New-TestCert.ps1 — 攻击回归专用自签发布者证书
#
# 只服务 A2（调用方签名校验）测试：生成可导出的代码签名证书，并把公钥
# 加入 CurrentUser 的 Root/TrustedPeople，使 WinVerifyTrust 能验证签名链。
# 私钥留在 CurrentUser\My 供 Set-AuthenticodeSignature 使用。
#
# 输出契约：每个证书一行
#   CERT CN=<subject> <thumbprint> <sha256-of-der>
# 其中 sha256-of-der 与核心 caller_auth 的发布者指纹口径一致。
param(
    [switch]$Install,
    [string[]]$Subjects = @('CN=Verthys-Test-Publisher', 'CN=Other-Publisher')
)
$ErrorActionPreference = 'Stop'

if (-not $Install) {
    throw '需要 -Install：A2 要求证书已进入 CurrentUser 信任存储'
}

function Get-OrCreateCert {
    param([Parameter(Mandatory = $true)][string]$Subject)

    $existing = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object {
            $_.Subject -eq $Subject -and $_.HasPrivateKey -and
            $_.NotAfter -gt (Get-Date).AddDays(1)
        } |
        Sort-Object NotAfter -Descending | Select-Object -First 1
    if ($existing) { return $existing }

    # CodeSigningCert 带有代码签名 EKU；Exportable 让签名调用方取到私钥。
    return New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $Subject `
        -KeyUsage DigitalSignature `
        -KeyExportPolicy Exportable `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -NotAfter (Get-Date).AddYears(3)
}

function Add-TrustedCert {
    param(
        [Parameter(Mandatory = $true)]$Cert,
        [Parameter(Mandatory = $true)][string]$Store
    )

    $present = Get-ChildItem $Store |
        Where-Object { $_.Thumbprint -eq $Cert.Thumbprint }
    if ($present) { return }

    $tmp = Join-Path $env:TEMP ('verthys_cert_' + [guid]::NewGuid().ToString('N') + '.cer')
    try {
        Export-Certificate -Cert $Cert -FilePath $tmp -Type CERT | Out-Null
        Import-Certificate -FilePath $tmp -CertStoreLocation $Store | Out-Null
    }
    finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

function Get-DerSha256 {
    param([Parameter(Mandatory = $true)]$Cert)

    $digest = [System.Security.Cryptography.SHA256]::HashData($Cert.RawData)
    return (($digest | ForEach-Object { $_.ToString('x2') }) -join '')
}

foreach ($subject in $Subjects) {
    $cert = Get-OrCreateCert -Subject $subject
    Add-TrustedCert -Cert $cert -Store 'Cert:\CurrentUser\Root'
    Add-TrustedCert -Cert $cert -Store 'Cert:\CurrentUser\TrustedPeople'
    Write-Output ("CERT {0} {1} {2}" -f $cert.Subject, $cert.Thumbprint,
        (Get-DerSha256 -Cert $cert))
}
