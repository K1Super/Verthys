# scripts/build/sign.ps1 — Authenticode 签名（发布者证书）
#
# 用测试/发布证书给 DLL 与宿主签名，并在签名前保留未签名副本
# （A2 负向用例需要“真未签名”的样本；复制已签名文件无法得到该状态）。
# 使用 Set-AuthenticodeSignature 而非 signtool：开发机不要求安装 Windows SDK。
#
# 用法：
#   pwsh scripts/build/sign.ps1 -Files build/core/Release/verthys.dll,...
#   pwsh scripts/build/sign.ps1 -Files ... -Subject 'CN=Other-Publisher'
param(
    [Parameter(Mandatory = $true)][string[]]$Files,
    [string]$Subject = 'CN=Verthys-Test-Publisher',
    [switch]$NoBackup
)
$ErrorActionPreference = 'Stop'

$cert = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Subject -eq $Subject -and $_.HasPrivateKey } |
    Sort-Object NotAfter -Descending | Select-Object -First 1
if (-not $cert) { throw "找不到签名证书: $Subject" }

foreach ($file in $Files) {
    if (-not (Test-Path -LiteralPath $file)) { throw "待签名文件缺失: $file" }
    if (-not $NoBackup) {
        # 只把“当前确实未签名”的二进制留作副本：
        # 若文件已是签名态（重复执行本脚本）就保留原副本，否则会把签名态
        # 当成“未签名样本”，让 A2-5 变成假阴性。
        $backup = $file + '.unsigned'
        $current = Get-AuthenticodeSignature -FilePath $file
        if ($current.Status -ne 'Valid') {
            Copy-Item -LiteralPath $file -Destination $backup -Force
        }
    }
    $sig = Set-AuthenticodeSignature -FilePath $file -Certificate $cert -HashAlgorithm SHA256
    if ($sig.Status -ne 'Valid') { throw "签名失败: $file ($($sig.StatusMessage))" }
    $sha = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Output ("SIGNED {0} {1}" -f $file, $sha)
}
