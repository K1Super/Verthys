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

    Write-Host "[cert] locate or create $Subject"
    $existing = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object {
            $_.Subject -eq $Subject -and $_.HasPrivateKey -and
            $_.NotAfter -gt (Get-Date).AddDays(1)
        } |
        Sort-Object NotAfter -Descending | Select-Object -First 1
    if ($existing) { return $existing }

    # CodeSigningCert 带有代码签名 EKU；Exportable 让签名调用方取到私钥。
    # 显式使用软件 KSP：默认提供程序在无 TPM 的 runner 上可能反复尝试
    # Platform KSP，导致证书生成长时间阻塞。
    return New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $Subject `
        -KeyUsage DigitalSignature `
        -KeyExportPolicy Exportable `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -Provider 'Microsoft Software Key Storage Provider' `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -NotAfter (Get-Date).AddYears(3)
}

function Add-TrustedCert {
    param(
        [Parameter(Mandatory = $true)]$Cert,
        [Parameter(Mandatory = $true)][string]$StoreName
    )

    $present = Get-ChildItem "Cert:\CurrentUser\$StoreName" |
        Where-Object { $_.Thumbprint -eq $Cert.Thumbprint }
    if ($present) { return }

    # 用 .NET 直接导出证书 DER，再用 certutil 非交互导入：PowerShell 的
    # PKI cmdlet 在无桌面会话的 runner 上可能等待 UI 确认。
    $tmp = Join-Path $env:TEMP ('verthys_cert_' + [guid]::NewGuid().ToString('N') + '.cer')
    try {
        Write-Host "[cert] trust $StoreName $($Cert.Thumbprint)"
        [IO.File]::WriteAllBytes($tmp, $Cert.Export(
                [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
        & certutil.exe -addstore -user -f $StoreName $tmp 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "证书导入失败: CurrentUser\$StoreName"
        }
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
    Add-TrustedCert -Cert $cert -StoreName 'Root'
    Add-TrustedCert -Cert $cert -StoreName 'TrustedPeople'
    Write-Output ("CERT {0} {1} {2}" -f $cert.Subject, $cert.Thumbprint,
        (Get-DerSha256 -Cert $cert))
}
