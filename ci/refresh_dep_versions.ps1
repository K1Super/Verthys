# ci/refresh_dep_versions.ps1 - 依赖版本快照生成器（幂等）
#
# 生成仓库根 dep-versions.txt：
#   - cargo 段：verthys-tauri/src-tauri 与 verthys-tauri/verthys-worker
#     两个 Cargo.lock 的全部依赖（name/version 合并去重，同名多版本各占一条）
#   - npm 段：verthys-tauri/package-lock.json 完整安装树（含 @scope 包）
#
# 与 CI 的比对 job 配套：快照与锁文件不一致即门禁变红。
# 依赖升级后必须运行本脚本重新生成快照并一并提交。
#
# 用法: powershell -ExecutionPolicy Bypass -File ci\refresh_dep_versions.ps1
$ErrorActionPreference = "Stop"

$script:Root = Split-Path -Parent $PSScriptRoot
$script:Output = Join-Path $script:Root "dep-versions.txt"

# 收集 "name|version" 对（自动去重后排序输出）
$script:Entries = New-Object System.Collections.Generic.SortedSet[string](
    [System.StringComparer]::Ordinal)

function Add-DepPair {
    param([string]$Name, [string]$Version)
    if ([string]::IsNullOrEmpty($Name) -or [string]::IsNullOrEmpty($Version)) { return }
    [void]$script:Entries.Add("$Name|$Version")
}

# ===== cargo 段：解析两个 Cargo.lock 的 [[package]] 块 =====
foreach ($lockRel in @(
        "verthys-tauri\src-tauri\Cargo.lock",
        "verthys-tauri\verthys-worker\Cargo.lock")) {
    $lockPath = Join-Path $script:Root $lockRel
    if (-not (Test-Path $lockPath)) {
        throw "Cargo.lock 不存在: $lockPath"
    }
    $content = Get-Content $lockPath -Raw
    $blocks = $content -split '\[\[package\]\]'
    # 首块为文件头部（无 [[package]] 标记），跳过
    for ($i = 1; $i -lt $blocks.Count; $i++) {
        $block = $blocks[$i]
        $name = [regex]::Match($block, 'name\s*=\s*"([^"]+)"').Groups[1].Value
        $version = [regex]::Match($block, 'version\s*=\s*"([^"]+)"').Groups[1].Value
        Add-DepPair -Name $name -Version $version
    }
}

# npm 段合并进同一集合：npm 包名与 cargo 包名互不重叠（含 @scope 前缀），
# 同名同版本条目合并去重后条目来源仍可独立追溯（锁文件比对为权威）。
# 解析走 node（package-lock.json 体积与键名对 Windows PowerShell 5.1 的
# ConvertFrom-Json 不友好；node 为前端工程基线依赖，本地与 CI 均具备）。
$pkgLockPath = Join-Path $script:Root "verthys-tauri\package-lock.json"
if (-not (Test-Path $pkgLockPath)) {
    throw "package-lock.json 不存在: $pkgLockPath"
}
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw "node 不可用：解析 package-lock.json 需要 Node 环境"
}
$nodeScript = @'
const lock = require(process.argv[2]);
const s = new Set();
for (const [k, v] of Object.entries(lock.packages || {})) {
  if (!k) continue;
  if (!v || !v.version) continue;
  // v3 锁的 entries 不含 name 字段，包名取 key 最后一个 node_modules/ 段
  // （@scope 包保留完整 "name = @scope/pkg" 形态）
  const name = k.split("node_modules/").pop();
  if (!name) continue;
  s.add(name + "|" + v.version);
}
console.log([...s].sort().join("\n"));
'@
# -e 传参在 Windows PowerShell 5.1 下会被再解析破坏引号，走临时文件执行
$nodeTemp = Join-Path $env:TEMP ("verthys_parse_lock_" + $PID + ".js")
if (Test-Path $nodeTemp) { Remove-Item $nodeTemp -Force }
[System.IO.File]::WriteAllText($nodeTemp, $nodeScript, (New-Object System.Text.UTF8Encoding($false)))
try {
    $npmLines = & node $nodeTemp $pkgLockPath
    if ($LASTEXITCODE -ne 0) {
        throw "package-lock.json 解析失败 (node exit=$LASTEXITCODE)"
    }
    foreach ($line in $npmLines) {
        $line = $line.Trim()
        if ([string]::IsNullOrEmpty($line)) { continue }
        $parts = $line -split '\|', 2
        Add-DepPair -Name $parts[0] -Version $parts[1]
    }
} finally {
    Remove-Item $nodeTemp -Force -ErrorAction SilentlyContinue
}

# ===== 输出快照（UTF-8，无 BOM，换行 LF） =====
$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("# 本文件由 ci/refresh_dep_versions.ps1 生成，请勿手工编辑。")
[void]$sb.AppendLine("# cargo 段：src-tauri 与 verthys-worker 两个 Cargo.lock 全部依赖（name/version 合并去重）。")
[void]$sb.AppendLine("# npm 段：verthys-tauri 的 package-lock.json 完整安装树。")
[void]$sb.AppendLine("# 依赖升级后必须重新运行生成脚本；与锁文件漂移将导致 CI 依赖快照门禁变红。")
[void]$sb.AppendLine("")

foreach ($entry in $script:Entries) {
    $parts = $entry -split '\|', 2
    [void]$sb.AppendLine('name = "' + $parts[0] + '"')
    [void]$sb.AppendLine('version = "' + $parts[1] + '"')
}

[System.IO.File]::WriteAllText($script:Output, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
Write-Host "[refresh] 快照已生成: $script:Output" -ForegroundColor Green
Write-Host ("[refresh] 条目总数: {0}" -f $script:Entries.Count)

exit 0