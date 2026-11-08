# scripts/signing/New-VerthysRootCA.ps1 - 生成 Verthys 自建根 CA（一次性离线操作）
#
# 编码警告：本文件必须保存为 UTF-8 with BOM 编码！
#   Windows PowerShell 5.1 对无 BOM 文件按 ANSI/GBK 解码，中文注释乱码会破坏
#   字符串配对导致 ParseError。
#
# 设计约束：
#   - 根私钥只在生成期间驻留证书库，导出加密 PFX 后立即从库中删除
#   - 口令与 PFX 写入受限目录，脚本不回显任何秘密
#   - 产物目录默认位于用户主目录，远离仓库，避免误提交
#
# 用法:
#   powershell -ExecutionPolicy Bypass -File scripts\signing\New-VerthysRootCA.ps1

[CmdletBinding()]
param(
    [string]$Subject = "CN=Verthys Root CA, O=K1Super, C=CN",
    [int]$Years = 10,
    [string]$OutputDir = (Join-Path $env:USERPROFILE ".verthys-ca")
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

function New-RestrictedDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
        "FullControl",
        "ContainerInherit,ObjectInherit",
        "None",
        "Allow")
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

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

function Assert-RootExtensions {
    param([Parameter(Mandatory = $true)]$Certificate)

    $bcExt = $Certificate.Extensions |
        Where-Object { $_.Oid.Value -eq "2.5.29.19" } |
        Select-Object -First 1
    if ($null -eq $bcExt) { throw "根证书缺少 BasicConstraints 扩展" }
    $bc = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]$bcExt
    if (-not $bc.CertificateAuthority) { throw "根证书 BasicConstraints 未标记 CA" }
    if ($bc.PathLengthConstraint -ne 0) { throw "根证书 pathlen 必须为 0（仅签发末端证书）" }

    $kuExt = $Certificate.Extensions |
        Where-Object { $_.Oid.Value -eq "2.5.29.15" } |
        Select-Object -First 1
    if ($null -eq $kuExt) { throw "根证书缺少 KeyUsage 扩展" }
    $ku = [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]$kuExt
    $required = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor
        [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign
    if (($ku.KeyUsages -band $required) -ne $required) {
        throw "根证书 KeyUsage 必须包含 KeyCertSign 与 CrlSign"
    }
}

Write-Host "[ca] 生成根 CA: $Subject" -ForegroundColor Cyan
New-RestrictedDirectory -Path $OutputDir

$existing = Get-ChildItem "Cert:\CurrentUser\My" -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -eq $Subject }
if ($existing) {
    throw "证书库已存在同主题根证书（$($existing[0].Thumbprint)），拒绝重复生成；如确需重建请先人工移除"
}

$root = New-SelfSignedCertificate `
    -Type Custom `
    -Subject $Subject `
    -KeyAlgorithm RSA `
    -KeyLength 4096 `
    -HashAlgorithm SHA256 `
    -KeyExportPolicy Exportable `
    -KeyUsage CertSign, CRLSign `
    -KeyUsageProperty Sign `
    -NotAfter (Get-Date).AddYears($Years) `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -TextExtension @("2.5.29.19={critical}{text}ca=1&pathlength=0")

if (-not $root.HasPrivateKey) { throw "根证书未生成私钥" }
if ($root.Subject -ne $root.Issuer) { throw "根证书必须是自签名（Subject 与 Issuer 相同）" }
Assert-RootExtensions -Certificate $root

$cerPath = Join-Path $OutputDir "VerthysRootCA.cer"
$pfxPath = Join-Path $OutputDir "VerthysRootCA.pfx"
$passPath = Join-Path $OutputDir "root.passphrase.txt"
$metaPath = Join-Path $OutputDir "root.json"

$passphrase = New-RandomPassphrase
$secure = ConvertTo-SecureString -String $passphrase -AsPlainText -Force

Export-Certificate -Cert $root -FilePath $cerPath -Type CERT -Force | Out-Null
Export-PfxCertificate -Cert $root -FilePath $pfxPath -Password $secure -Force | Out-Null
Write-Utf8File -Path $passPath -Text $passphrase

$meta = [ordered]@{
    subject   = $root.Subject
    thumbprint = $root.Thumbprint
    notBefore = $root.NotBefore.ToString("yyyy-MM-dd")
    notAfter  = $root.NotAfter.ToString("yyyy-MM-dd")
    cerPath   = $cerPath
    pfxPath   = $pfxPath
    passphrasePath = $passPath
    createdAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
}
Write-Utf8File -Path $metaPath -Text ($meta | ConvertTo-Json)

foreach ($path in @($cerPath, $pfxPath, $passPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "导出失败: $path" }
}

# 根私钥用完即删：后续签发叶证书时从加密 PFX 临时导入
Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $root.Thumbprint) -Force

Write-Host "[ok] 根 CA 已生成并导出" -ForegroundColor Green
Write-Host "  Subject    : $($root.Subject)"
Write-Host "  Thumbprint : $($root.Thumbprint)"
Write-Host "  有效期     : $($root.NotBefore.ToString('yyyy-MM-dd')) ~ $($root.NotAfter.ToString('yyyy-MM-dd'))"
Write-Host "  证书       : $cerPath"
Write-Host "  加密 PFX   : $pfxPath"
Write-Host "  口令文件   : $passPath"
Write-Host ""
Write-Host "[必做] 把 PFX 与口令抄入密码管理器/离线介质，然后删除本机口令文件" -ForegroundColor Yellow
Write-Host "[必做] 根私钥已从证书库删除，PFX 与口令丢失将无法再签发新证书" -ForegroundColor Yellow
