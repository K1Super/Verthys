# scripts/signing/Install-VerthysRootTrust.ps1 - 将 Verthys 根证书安装到信任库
#
# 编码警告：本文件必须保存为 UTF-8 with BOM 编码！
#   Windows PowerShell 5.1 对无 BOM 文件按 ANSI/GBK 解码，中文注释乱码会破坏
#   字符串配对导致 ParseError。
#
# 安全边界：
#   - 只安装根证书到 Trusted Root，不写入 Trusted Publishers
#   - 安装前校验主题与 CA 扩展，避免误装普通证书为根
#   - LocalMachine 需要管理员权限，普通会话下退化为 CurrentUser
#
# 用法:
#   powershell -ExecutionPolicy Bypass -File scripts\signing\Install-VerthysRootTrust.ps1 `
#       -CerPath "$env:USERPROFILE\.verthys-ca\VerthysRootCA.cer" -Scope CurrentUser

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CerPath,
    [ValidateSet("CurrentUser", "LocalMachine")]
    [string]$Scope = "CurrentUser"
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

$resolvedCer = (Resolve-Path -LiteralPath $CerPath).Path
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($resolvedCer)

if ($cert.Subject -notlike "CN=Verthys Root CA*") {
    throw "根证书主题不符合预期: $($cert.Subject)"
}

$bcExt = $cert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.19" } | Select-Object -First 1
if ($null -eq $bcExt) { throw "根证书缺少 BasicConstraints 扩展" }
$bc = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]$bcExt
if (-not $bc.CertificateAuthority) { throw "根证书 BasicConstraints 未标记 CA" }

if ($Scope -eq "LocalMachine") {
    $principal = [System.Security.Principal.WindowsPrincipal]::new(
        [System.Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "LocalMachine 作用域需要管理员权限；当前会话未提权，请改用 CurrentUser 或以管理员身份运行"
    }
}

$storePath = "Cert:\$Scope\Root"
$alreadyTrusted = Get-ChildItem $storePath -ErrorAction SilentlyContinue |
    Where-Object { $_.Thumbprint -eq $cert.Thumbprint } |
    Select-Object -First 1

if ($alreadyTrusted) {
    Write-Host "[trust] 根证书已存在于 $Scope\Root，无需重复安装" -ForegroundColor Cyan
} else {
    Import-Certificate -FilePath $resolvedCer -CertStoreLocation $storePath | Out-Null
    Write-Host "[trust] 已安装根证书到 $Scope\Root" -ForegroundColor Green
}

Write-Host "  Subject    : $($cert.Subject)"
Write-Host "  Thumbprint : $($cert.Thumbprint)"
Write-Host "  有效期     : $($cert.NotBefore.ToString('yyyy-MM-dd')) ~ $($cert.NotAfter.ToString('yyyy-MM-dd'))"
Write-Host ""
Write-Host "[注意] 该根证书仅对当前用户/本机生效；对外分发需由目标环境的管理员用 GPO/Intune 推送" -ForegroundColor Yellow
Write-Host "[移除] Remove-Item Cert:\$Scope\Root\$($cert.Thumbprint)" -ForegroundColor Yellow
