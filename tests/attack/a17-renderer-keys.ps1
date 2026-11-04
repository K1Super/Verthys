<#
 * tests/attack/a17-renderer-keys.ps1 — 渲染进程模块内容密钥扫描
 *
 * 口径（静态源码 + 构建产物）：
 *   1. 前端源码不得出现 v4 内容密钥派生元素：MDEK 标识、v4 域分离字符串、
 *      HKDF 调用、原生 v4 分片/清单导出符号；
 *   2. WebCrypto 派生接口与 @noble/ciphers 只允许出现在导出容器实现
 *      （lib/crypto.ts）。导出容器是用户令牌驱动的独立信封，与库内模块
 *      内容密钥无关，属登记例外；
 *   3. dist 构建产物不得出现上述 v4 内容密钥/域标签字符串，确保打包后
 *      渲染层仍无模块密钥派生材料。
 *
 * 说明：本扫描不读取运行时内存，也不检查 worker/C 层；模块内容密钥派生
 * 必须集中在 worker，该边界由源码结构约束与 e2e 往返共同证明。
 *
 * 输出：RESULT A17 PASS/FAIL <摘要>；退出码 0/1。
#>
[CmdletBinding()]
param(
    [string]$RepoRoot,
    [string]$SourceDir,
    [string]$DistDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $RepoRoot) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}
if (-not $SourceDir) {
    $SourceDir = Join-Path $RepoRoot 'verthys-tauri/src'
}
if (-not $DistDir) {
    $DistDir = Join-Path $RepoRoot 'verthys-tauri/dist'
}

# 导出容器实现：用户令牌 + PBKDF2 + XChaCha20 的独立信封，不是库内容密钥
$cryptoAllowlist = @('verthys-tauri/src/lib/crypto.ts')

$sourceForbidden = @(
    @{ Id = 'MDEK'; Pattern = '\bMDEK\b' },
    @{ Id = 'v4-domain'; Pattern = 'verthys/v4/(record|name|chunk|manifest|type-index|name-index|file-uuid)' },
    @{ Id = 'v4-ffi'; Pattern = 'Verthys_V4(Chunk|Manifest)(Seal|Open)' },
    @{ Id = 'HKDF'; Pattern = '(?i)\bhkdf\b' }
)

$distForbidden = @(
    @{ Id = 'MDEK'; Pattern = '\bMDEK\b' },
    @{ Id = 'v4-domain'; Pattern = 'verthys/v4/(record|name|chunk|manifest|type-index|name-index|file-uuid)' },
    @{ Id = 'v4-ffi'; Pattern = 'Verthys_V4(Chunk|Manifest)(Seal|Open)' }
)

function Remove-Comments {
    param([string]$Text)
    $Text = [regex]::Replace($Text, '(?s)/\*.*?\*/', '')
    $Text = [regex]::Replace($Text, '(?s)<!--.*?-->', '')
    $Text = [regex]::Replace($Text, '(?m)//.*$', '')
    return $Text
}

function Get-RelativePath {
    param([string]$Base, [string]$Full)
    return ($Full.Substring($Base.Length).TrimStart('\', '/') -replace '\\', '/')
}

$findings = New-Object System.Collections.Generic.List[string]
$sourceCount = 0
$distCount = 0

if (-not (Test-Path -LiteralPath $SourceDir)) {
    Write-Host 'RESULT A17 FAIL 源码目录缺失'
    exit 1
}

$sourceFiles = @(Get-ChildItem -LiteralPath $SourceDir -Recurse -File |
        Where-Object {
            $_.Extension -in @('.ts', '.vue') -and
            $_.Name -notlike '*.spec.ts' -and
            $_.FullName -notmatch '\\vendor\\'
        })

foreach ($file in $sourceFiles) {
    $sourceCount++
    $relative = Get-RelativePath -Base $SourceDir -Full $file.FullName
    $normalized = "verthys-tauri/src/$relative"
    $text = Remove-Comments -Text ([System.IO.File]::ReadAllText($file.FullName))

    foreach ($rule in $sourceForbidden) {
        if ($text -match $rule.Pattern) {
            $findings.Add("$($rule.Id)@src/$relative")
        }
    }

    $isCryptoAllowlisted = $cryptoAllowlist -contains $normalized
    if (-not $isCryptoAllowlisted) {
        if ($text -match '\bderiveBits\b|\bderiveKey\b') {
            $findings.Add("webcrypto-kdf@src/$relative")
        }
        if ($text -match '@noble/ciphers') {
            $findings.Add("noble-ciphers@src/$relative")
        }
    }
}

if (-not (Test-Path -LiteralPath $DistDir)) {
    $findings.Add('dist-missing')
}
else {
    $distFiles = @(Get-ChildItem -LiteralPath $DistDir -Recurse -File -Filter '*.js')
    if ($distFiles.Count -eq 0) {
        $findings.Add('dist-js-empty')
    }
    foreach ($file in $distFiles) {
        $distCount++
        $text = [System.IO.File]::ReadAllText($file.FullName)
        foreach ($rule in $distForbidden) {
            if ($text -match $rule.Pattern) {
                $findings.Add("$($rule.Id)@dist/$($file.Name)")
            }
        }
    }
}

if ($findings.Count -gt 0) {
    $detail = $findings | Select-Object -First 6
    Write-Host ("RESULT A17 FAIL 源码={0} dist={1} 命中: {2}" -f $sourceCount, $distCount, ($detail -join ', '))
    exit 1
}

Write-Host ("RESULT A17 PASS 源码={0} dist={1} 无 MDEK/域标签/HKDF/原生 v4 符号；导出容器例外仅 lib/crypto.ts" -f $sourceCount, $distCount)
exit 0
