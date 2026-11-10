# scripts/build/sign_release_binaries.ps1 - Tauri 打包器签名入口
#
# 由生成的 Tauri profile 覆盖层通过 bundle.windows.signCommand 调用：
# 打包器写入 bundle type 补丁后、生成安装包之前，对目标 PE 执行 Authenticode
# 签名。补丁会改写二进制并使既有签名失效，因此不能在 beforeBundleCommand
# 中签名，否则安装包内的主程序必然 HashMismatch。
#
# 同一入口也用于 NSIS 卸载器、安装包与 NSIS 插件副本的签名（打包器在
# 相应步骤以 %1 传入目标路径）。
#
# 失败即非零退出，由 Tauri 终止打包，禁止未签名二进制进入安装包。
#
# 编码警告：本文件必须保存为 UTF-8 with BOM 编码！

[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$ExePath = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

# Tauri 打包器以 powershell.exe (5.1) 子进程运行签名命令；若父进程是
# PowerShell 7，PSModulePath 会被继承为 7 的路径，导致 5.1 无法加载
# Microsoft.PowerShell.Security，Cert: 驱动器不存在，证书查找必然失败。
if ($PSVersionTable.PSEdition -eq "Desktop") {
    $env:PSModulePath = @(
        (Join-Path $env:USERPROFILE "Documents\WindowsPowerShell\Modules"),
        (Join-Path $env:ProgramFiles "WindowsPowerShell\Modules"),
        (Join-Path $env:WINDIR "system32\WindowsPowerShell\v1.0\Modules")
    ) -join ";"
    Import-Module Microsoft.PowerShell.Security -ErrorAction Stop
}

try {
    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $repoRoot "scripts\lib\release_signing.ps1")

    $signing = Resolve-VerthysReleaseSigning -Required
    if (-not $signing.Enabled) {
        throw "打包前签名已启用但未解析到发布者证书"
    }

    if ([string]::IsNullOrWhiteSpace($ExePath)) {
        $ExePath = Join-Path $repoRoot "verthys-tauri\src-tauri\target\release\Verthys.exe"
    }

    Invoke-VerthysAuthenticodeSign `
        -Path $ExePath `
        -Certificate $signing.Certificate `
        -TimestampServer $signing.TimestampServer

    Assert-VerthysAuthenticodeSignature `
        -Path $ExePath `
        -ExpectedSha256 $signing.PublisherSha256 | Out-Null

    # 构建审计：Tauri 以 UTF-8 输出构建日志，Windows PowerShell 5.1 按本地
    # 代码页解码，中文判定不可靠。签名入口在 Authenticode 复核通过后追加
    # 审计记录，构建脚本据此判定主程序是否真的执行了 signCommand。
    $journalPath = $env:VERTHYS_SIGN_JOURNAL
    if (-not [string]::IsNullOrWhiteSpace($journalPath)) {
        $entry = [pscustomobject]@{
            path        = [System.IO.Path]::GetFullPath($ExePath)
            publisher   = $signing.PublisherSha256
            verified_at = (Get-Date).ToUniversalTime().ToString("o")
        }
        [System.IO.File]::AppendAllText(
            $journalPath,
            ($entry | ConvertTo-Json -Compress) + [Environment]::NewLine,
            [System.Text.UTF8Encoding]::new($false))
    }

    Write-Host "[sign] 签名完成，发布者指纹=$($signing.PublisherSha256)" -ForegroundColor Green
    exit 0
} catch {
    Write-Host "[sign] 签名失败: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
