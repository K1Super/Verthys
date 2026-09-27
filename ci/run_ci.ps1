<#
.SYNOPSIS
    CI 统一执行入口

.DESCRIPTION
    执行两级 CI 静态校验：
      第一级：快速正则过滤（Python，目标 < 0.5 秒）
      第二级：AST 深度分析（Rust，目标 < 10 秒）

    第一级仅输出警告，不阻断构建。
    第二级任何违规将直接导致构建失败。

.NOTES
    "CI静态校验双引擎实现策略"
#>

param(
    [switch]$Level1Only,  # 仅执行第一级扫描
    [switch]$Level2Only,  # 仅执行第二级扫描
    [switch]$SkipBuild    # 跳过第二级编译（使用已编译的二进制）
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot

Write-Host "=" * 60
Write-Host "Verthys CI 统一执行入口"
Write-Host "=" * 60

# ===== 版本号一致性门禁 =====
# 全仓版本号以根 VERSION 文件为唯一手改点；漂移即拒绝，防止版本再分裂。
Write-Host ""
Write-Host "[版本门禁] 校验全仓版本与根 VERSION 文件一致..."
& (Join-Path $PSScriptRoot "sync_version.ps1") -CheckOnly
if ($LASTEXITCODE -ne 0) {
    Write-Host "[版本门禁] 检测到漂移：编辑根 VERSION 文件后运行 ci\sync_version.ps1 并提交同步结果"
    exit 1
}
Write-Host "[版本门禁] 通过：全仓版本一致"

# ===== 零容忍锚点门（防回退） =====
# 三条文本级精确锚点，命中即红，成本毫秒级、零误报：
#   1. 已删除的负数错误码体系不得复活（单一定义源为 verthys.h 正数枚举）；
#   2. worker 主循环禁止 .unwrap()（panic 与 abort 语义冲突，见受控错误路径约定）；
#   3. 容器格式版本禁止字面量赋值（必须经 VERTHYS_FMT_* 枚举）。
Write-Host ""
Write-Host "[锚点门] 零容忍防回退检查..."
$anchorFiles = @()
$anchorFiles += Get-ChildItem -Path (Join-Path $projectRoot "core\src"), (Join-Path $projectRoot "core\include"), (Join-Path $projectRoot "core\examples") -Recurse -Include *.c,*.h -ErrorAction SilentlyContinue
$anchorFiles += Get-ChildItem -Path (Join-Path $projectRoot "verthys-tauri\src-tauri\src"), (Join-Path $projectRoot "verthys-tauri\verthys-worker\src") -Recurse -Include *.rs -ErrorAction SilentlyContinue

$anchorRed = $false

# 锚点 1：负数错误码体系（禁止复活）
$hits = $anchorFiles | Select-String -Pattern 'VERTHYS_C_ERR_' -ErrorAction SilentlyContinue
if ($hits) {
    Write-Host "[锚点门][RED] VERTHYS_C_ERR_ 负数错误码体系禁止复活："
    $hits | ForEach-Object { Write-Host ("  {0}:{1}" -f $_.Path, $_.LineNumber) }
    $anchorRed = $true
}

# 锚点 2：worker 主循环 unwrap 清零（受控错误路径红线）。
# 扫描范围排除 #[cfg(test)] 测试模块：测试内 unwrap 作用于确定性
# Cursor<&[u8]> 输入（模块头注释已标注理由），不属于生产 panic 源。
$mainLoop = Join-Path $projectRoot "verthys-tauri\verthys-worker\src\runtime\main_loop.rs"
if (Test-Path $mainLoop) {
    $uwHits = Select-String -Path $mainLoop -Pattern '\.unwrap\(\)' -AllMatches -ErrorAction SilentlyContinue
    $testLine = (Select-String -Path $mainLoop -Pattern '^\s*#\[cfg\(test\)\]' -ErrorAction SilentlyContinue | Select-Object -First 1).LineNumber
    $prodHits = if ($testLine) { $uwHits | Where-Object { $_.LineNumber -lt $testLine } } else { $uwHits }
    $uwCount = ($prodHits | ForEach-Object { $_.Matches.Count } | Measure-Object -Sum).Sum
    if ($uwCount) {
        Write-Host "[锚点门][RED] main_loop.rs 生产路径存在 .unwrap() 调用 $uwCount 处，必须走受控错误路径"
        $anchorRed = $true
    }
}

# 锚点 3：容器格式版本禁用字面量赋值
$fmtMagic = Get-ChildItem -Path (Join-Path $projectRoot "core\src") -Recurse -Include *.c,*.h -ErrorAction SilentlyContinue |
    Select-String -Pattern 'fmt_version\s*=\s*[0-9]' -ErrorAction SilentlyContinue
if ($fmtMagic) {
    Write-Host "[锚点门][RED] fmt_version 禁止字面量赋值（必须经 VERTHYS_FMT_* 枚举）："
    $fmtMagic | ForEach-Object { Write-Host ("  {0}:{1}" -f $_.Path, $_.LineNumber) }
    $anchorRed = $true
}

# 锚点 4：批量导入域全部数据命令必须挂接解锁闸门（防回退）。
# 导入/删除/GC 均为写入型数据域命令，闸门挂接不得少于 8 处
# （begin / add_records / add_chunk / forget_hashes / dev_reset_wal /
#   import_end / import_checkpoint / gc_orphan_chunks 各一）。
$batchCtrl = Join-Path $projectRoot "verthys-tauri\src-tauri\src\controller\verthys_batch_controller.rs"
if (Test-Path $batchCtrl) {
    $gateHits = Select-String -Path $batchCtrl -Pattern 'require_unlocked' -AllMatches -ErrorAction SilentlyContinue
    $gateCount = ($gateHits | ForEach-Object { $_.Matches.Count } | Measure-Object -Sum).Sum
    if ($gateCount -lt 8) {
        Write-Host "[锚点门][RED] verthys_batch_controller.rs 授权闸门挂接不足：require_unlocked 命中 $gateCount 处，要求 >= 8（导入域八命令各一）"
        $anchorRed = $true
    }
}

if ($anchorRed) {
    Write-Host "[锚点门] 失败：存在防回退红线违规"
    exit 1
}
Write-Host "[锚点门] 通过：零容忍红线全部满足"

# ===== 常量生成物门禁 =====
# 跨层预算常量以权威来源文件为单一定义，生成物（前端 TS 与 Rust 同源常量）
# 与来源漂移即红：防手改生成物造成三端取值分裂。
Write-Host ""
Write-Host "[常量门] 校验跨层预算常量生成物与权威来源一致..."
$budgetGen = Join-Path $projectRoot "verthys-tauri\constants\generate.mjs"
if (-not (Test-Path $budgetGen)) {
    Write-Host "[常量门][RED] 缺少跨层预算常量生成器"
    exit 1
}
$nodeCmd = Get-Command node -ErrorAction SilentlyContinue
if ($null -eq $nodeCmd) {
    Write-Host "[常量门][RED] 未找到 node，无法校验常量生成物"
    exit 1
}
& $nodeCmd.Source $budgetGen --check
if ($LASTEXITCODE -ne 0) {
    Write-Host "[常量门][RED] 生成物与权威来源不一致：请重新运行常量生成器并提交生成物"
    exit 1
}
Write-Host "[常量门] 通过：生成物与权威来源一致"

$exitCode = 0

# ===== 第一级：快速正则过滤 =====
if (-not $Level2Only) {
    Write-Host ""
    Write-Host "[第一级] 快速正则过滤..."
    # 探测可实际运行的 Python：Windows 上 python3 常为商店存根（Get-Command
    # 命中但执行失败），Get-Command 存在性不可信，须实测 --version 退出码
    $pythonExe = $null
    foreach ($cand in @("python", "python3")) {
        try {
            $cmd = Get-Command $cand -ErrorAction Stop
            if ($null -ne $cmd) {
                & $cmd.Source --version 2>$null | Out-Null
                if ($LASTEXITCODE -eq 0) { $pythonExe = $cmd.Source; break }
            }
        } catch { }
    }
    $scanScript = Join-Path $PSScriptRoot "regex_scan.py"

    if ($null -eq $pythonExe) {
        Write-Host "[第一级] Python 不可用（python/python3 均无法执行），跳过"
    } elseif (Test-Path $scanScript) {
        Push-Location $projectRoot
        & $pythonExe $scanScript
        $level1Exit = $LASTEXITCODE
        Pop-Location

        if ($level1Exit -ne 0) {
            Write-Host "[第一级] 扫描异常，退出码: $level1Exit"
        } else {
            Write-Host "[第一级] 扫描完成（仅警告，不阻断）"
        }
    } else {
        Write-Host "[第一级] 脚本不存在: $scanScript"
    }
}

# ===== 第二级：AST 深度分析 =====
if (-not $Level1Only) {
    Write-Host ""
    Write-Host "[第二级] AST 深度分析..."
    $astProject = Join-Path $PSScriptRoot "ast_analyze"

    if (Test-Path (Join-Path $astProject "Cargo.toml")) {
        if (-not $SkipBuild) {
            Write-Host "[第二级] 编译 AST 分析工具..."
            Push-Location $astProject
            # cargo 的进度/下载信息走 stderr，EAP=Stop 下会包装为终止错误，
            # 编译期间临时降级为 Continue，恢复后按退出码判定
            $prevEAP = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            & cargo build --release 2>&1 | ForEach-Object { Write-Host $_ }
            $buildExit = $LASTEXITCODE
            $ErrorActionPreference = $prevEAP
            if ($buildExit -ne 0) {
                Write-Host "[第二级] 编译失败 (exit=$buildExit)"
                Pop-Location
                exit 1
            }
            Pop-Location
        }

        $astBinary = Join-Path $astProject "target\release\verthys-ci-ast.exe"
        if (Test-Path $astBinary) {
            Push-Location $projectRoot
            # 存量豁免基线：与基线重合的违规跳过，新增违规仍阻断
            $baselinePath = Join-Path $PSScriptRoot "ast_baseline.txt"
            if (Test-Path $baselinePath) {
                & $astBinary --baseline $baselinePath
            } else {
                & $astBinary
            }
            $level2Exit = $LASTEXITCODE
            Pop-Location

            if ($level2Exit -ne 0) {
                Write-Host "[第二级] 扫描失败，存在架构红线违规"
                $exitCode = 1
            } else {
                Write-Host "[第二级] 扫描通过"
            }
        } else {
            Write-Host "[第二级] 二进制不存在: $astBinary"
            Write-Host "[第二级] 请先运行: cargo build --release"
            $exitCode = 1
        }
    } else {
        Write-Host "[第二级] AST 项目不存在: $astProject"
    }
}

# ===== 汇总 =====
Write-Host ""
Write-Host "=" * 60
if ($exitCode -eq 0) {
    Write-Host "CI 检查全部通过"
} else {
    Write-Host "CI 检查失败：存在架构红线违规"
}
Write-Host "=" * 60

exit $exitCode
