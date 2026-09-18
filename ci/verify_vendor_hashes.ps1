# ci/verify_vendor_hashes.ps1
# 供应链完整性门（P2-2 修复，2026-09-19）：
#   1. 逐文件比对 ci/vendor_hashes.txt 记录的 SHA-256 与磁盘实际哈希
#   2. 与 git 跟踪集双向核对：跟踪却未入清单 / 清单却未跟踪，均判失败
#      （防止依赖被替换后未更新清单，或攻击者新增清单外文件）
# 退出码：0 通过；1 失败（列出全部差异后统一 throw）
# 用法：pwsh ./ci/verify_vendor_hashes.ps1   （在仓库根执行）
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$listPath = Join-Path $PSScriptRoot 'vendor_hashes.txt'
if (-not (Test-Path $listPath)) { throw "清单不存在: $listPath" }

# ---- 解析清单（跳过注释/空行；格式: <SHA256>  <path>）----
$manifest = @{}
$badLines = @()
foreach ($raw in Get-Content $listPath) {
    $line = $raw.Trim()
    if ($line -eq '' -or $line.StartsWith('#')) { continue }
    $parts = $line -split '\s+', 2
    if ($parts.Count -ne 2 -or $parts[0] -notMatch '^[0-9A-Fa-f]{64}$') {
        $badLines += $line; continue
    }
    $key = $parts[1].Replace('\', '/')
    $manifest[$key] = $parts[0].ToUpperInvariant()
}
if ($badLines.Count -gt 0) { throw "清单存在 $($badLines.Count) 行格式错误，首行: $($badLines[0])" }
if ($manifest.Count -eq 0) { throw '清单为空' }

# ---- git 跟踪集（vendored 三目录）----
$tracked = @(git ls-files third_party/flatcc third_party/libsodium third_party/xxhash)
if ($tracked.Count -eq 0) { throw 'git 未跟踪任何 vendored 文件（third_party 缺失？）' }

$failures = New-Object System.Collections.Generic.List[string]

# ---- 1) 哈希逐文件比对 ----
foreach ($kv in $manifest.GetEnumerator()) {
    $rel = $kv.Key
    if (-not (Test-Path $rel)) {
        $failures.Add("MISSING  $rel"); continue
    }
    $actual = (Get-FileHash $rel -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($actual -ne $kv.Value) { $failures.Add("HASH-MISMATCH  $rel") }
}

# ---- 2) 跟踪集 vs 清单 双向核对 ----
$manifestKeys = $manifest.Keys
foreach ($t in $tracked) {
    if ($manifestKeys -notcontains $t) { $failures.Add("TRACKED-NOT-IN-MANIFEST  $t") }
}
foreach ($m in $manifestKeys) {
    if ($tracked -notcontains $m) { $failures.Add("MANIFEST-NOT-TRACKED  $m") }
}

# ---- 结果 ----
if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Host $_ }
    throw "vendor 哈希门失败: $($failures.Count) 项差异（清单 $($manifest.Count) 条 / 跟踪 $($tracked.Count) 条）"
}
Write-Host "vendor 哈希门通过: $($manifest.Count) 个文件，与 git 跟踪集一致"
exit 0
