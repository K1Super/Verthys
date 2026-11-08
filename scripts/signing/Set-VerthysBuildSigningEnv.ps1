# scripts/signing/Set-VerthysBuildSigningEnv.ps1 - 把当前发布者证书指纹写入构建环境
#
# 编码警告：本文件必须保存为 UTF-8 with BOM 编码！
#   Windows PowerShell 5.1 对无 BOM 文件按 ANSI/GBK 解码，中文注释乱码会破坏
#   字符串配对导致 ParseError。
#
# 设计约束：
#   - 只写入指纹与时间戳地址，两者都是公开信息，不涉及私钥或口令
#   - 指纹来源是签发脚本生成的 code-signing.json，轮换后重跑本脚本即可
#   - 默认写入用户级，保证新开的终端与构建进程都能读到
#
# 用法:
#   powershell -ExecutionPolicy Bypass -File scripts\signing\Set-VerthysBuildSigningEnv.ps1

[CmdletBinding()]
param(
    [string]$OutputDir = (Join-Path $env:USERPROFILE ".verthys-ca"),
    [ValidateSet("User", "Process")]
    [string]$Scope = "User",
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

$metaPath = Join-Path $OutputDir "code-signing.json"
if (-not (Test-Path -LiteralPath $metaPath -PathType Leaf)) {
    throw "未找到证书元数据: $metaPath；请先执行 New-VerthysCodeSigningCert.ps1"
}

$meta = Get-Content -LiteralPath $metaPath -Raw | ConvertFrom-Json
$thumbprint = ([string]$meta.thumbprint).Trim().ToUpperInvariant()
if (($thumbprint -replace "[^0-9A-F]", "").Length -ne 40) {
    throw "元数据中的证书指纹不是 40 位十六进制: $($meta.thumbprint)"
}

$cert = Get-ChildItem "Cert:\CurrentUser\My" -ErrorAction SilentlyContinue |
    Where-Object { $_.Thumbprint -eq $thumbprint } |
    Select-Object -First 1
if ($null -eq $cert) {
    throw "CurrentUser\My 未找到证书 $thumbprint；请重新导入叶证书或重跑签发脚本"
}
if (-not $cert.HasPrivateKey) { throw "证书 $thumbprint 缺少私钥，无法用于签名" }
if ($cert.NotAfter -lt (Get-Date)) { throw "证书 $thumbprint 已过期（$($cert.NotAfter.ToString('yyyy-MM-dd'))）" }

if ([string]::IsNullOrWhiteSpace($TimestampUrl)) {
    Write-Host "[env] 未提供时间戳地址，跳过 VERTHYS_SIGNING_TIMESTAMP_URL" -ForegroundColor Yellow
} else {
    $uri = $null
    if (-not [Uri]::TryCreate($TimestampUrl, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -notin @("http", "https")) {
        throw "时间戳地址必须是 http/https 绝对 URL: $TimestampUrl"
    }
}

[Environment]::SetEnvironmentVariable("VERTHYS_SIGNING_THUMBPRINT", $thumbprint, $Scope)
if (-not [string]::IsNullOrWhiteSpace($TimestampUrl)) {
    [Environment]::SetEnvironmentVariable("VERTHYS_SIGNING_TIMESTAMP_URL", $TimestampUrl, $Scope)
}

# 用户级写入不会影响当前已打开的终端，这里同步设置进程级，便于本轮直接构建
if ($Scope -eq "User") {
    $env:VERTHYS_SIGNING_THUMBPRINT = $thumbprint
    if (-not [string]::IsNullOrWhiteSpace($TimestampUrl)) {
        $env:VERTHYS_SIGNING_TIMESTAMP_URL = $TimestampUrl
    }
}

$rootInstalled = $false
foreach ($store in @("Cert:\CurrentUser\Root", "Cert:\LocalMachine\Root")) {
    $trusted = Get-ChildItem $store -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -like "CN=Verthys Root CA*" } |
        Select-Object -First 1
    if ($trusted) { $rootInstalled = $true; break }
}
if (-not $rootInstalled) {
    Write-Host "[env] 警告：未检测到 Verthys 根证书信任，构建签名复核会失败" -ForegroundColor Yellow
}

Write-Host "[env] 构建签名环境已写入（Scope=$Scope）" -ForegroundColor Green
Write-Host "  VERTHYS_SIGNING_THUMBPRINT      = $thumbprint"
Write-Host "  VERTHYS_SIGNING_TIMESTAMP_URL   = $TimestampUrl"
Write-Host "  Subject                          = $($cert.Subject)"
Write-Host "  有效期                           = $($cert.NotBefore.ToString('yyyy-MM-dd')) ~ $($cert.NotAfter.ToString('yyyy-MM-dd'))"
Write-Host ""
Write-Host "[提示] 已打开的旧终端不会继承用户级变量，请新开终端或使用当前进程级变量构建" -ForegroundColor Yellow
