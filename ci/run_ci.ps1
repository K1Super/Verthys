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

# 锚点 5：清藏写入必须经导入会话（防单条写入复活）。
# 判定范围：清藏模块组件与清藏组合式目录（其内任何文件命中即红）。
$fvComp = Join-Path $projectRoot "verthys-tauri\src\composables\file-verthys"
$fvTargets = @(Join-Path $projectRoot "verthys-tauri\src\components\modules\FileVerthys.vue")
if (Test-Path $fvComp) {
    $fvTargets += Get-ChildItem -Path $fvComp -Recurse -Include *.ts,*.vue -ErrorAction SilentlyContinue |
        ForEach-Object { $_.FullName }
}
$fvTargets = $fvTargets | Where-Object { Test-Path $_ }
$a1Hits = Select-String -Path $fvTargets -Pattern 'verthysAddRecord\s*\(|"verthys_add_record"'
if ($a1Hits) {
    Write-Host "[锚点门][RED] 清藏写入必须经导入会话，单条写入禁止复活："
    $a1Hits | ForEach-Object { Write-Host ("  {0}:{1}" -f $_.Path, $_.LineNumber) }
    $anchorRed = $true
}

# 锚点 6：清藏导入必须分片读取（禁整文件读载）。
# 判定对象为导入管线本体：命名区分 readUserFileChunked，不会误伤分片读取。
$fvImport = Join-Path $fvComp "useFileImport.ts"
if (Test-Path $fvImport) {
    $a2Hits = Select-String -Path $fvImport -Pattern 'readUserFile\s*\('
    if ($a2Hits) {
        Write-Host "[锚点门][RED] 清藏导入必须分片读取（整文件读载禁止出现在导入管线）："
        $a2Hits | ForEach-Object { Write-Host ("  {0}:{1}" -f $_.Path, $_.LineNumber) }
        $anchorRed = $true
    }

    # 锚点 7：清藏导入路径禁止读取单条记录（记录读取仅限导出路径）。
    $bHits = Select-String -Path $fvImport -Pattern 'verthysGetRecord'
    if ($bHits) {
        Write-Host "[锚点门][RED] 导入路径禁止读取单条记录（记录读取仅限导出路径）："
        $bHits | ForEach-Object { Write-Host ("  {0}:{1}" -f $_.Path, $_.LineNumber) }
        $anchorRed = $true
    }
}

# 锚点 8（C）：旧格式写保护字符串分支禁止复活（T-1 收口，判定范围为全前端）。
# 该字符串在核心与进程间层无生产者（非 V3 容器在解锁即被格式门禁拒绝，
# 不存在"已解锁但格式需升级"的状态），前端消费分支属死代码，已全量删除；
# 按整串禁入以覆盖等式 / 包含 / 变量判等等全部复活形态。
$srcRoot = Join-Path $projectRoot "verthys-tauri\src"
$srcFiles = @(Get-ChildItem -Path $srcRoot -Recurse -Include *.ts,*.vue -ErrorAction SilentlyContinue |
    ForEach-Object { $_.FullName })
$cHits = if ($srcFiles.Count -gt 0) {
    Select-String -Path $srcFiles -Pattern 'VERTHYS_WRITE_BLOCKED' -ErrorAction SilentlyContinue
} else { $null }
if ($cHits) {
    Write-Host "[锚点门][RED] 旧格式写保护字符串分支禁止复活（全前端整串禁入）："
    $cHits | ForEach-Object { Write-Host ("  {0}:{1}" -f $_.Path, $_.LineNumber) }
    $anchorRed = $true
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

# ===== 常量消费门 =====
# 跨层行为常量必须有真实消费点：生成常量失去消费者时，权威来源即失效
# （历史发生过硬编码与生成值并存的静默漂移）。
Write-Host ""
Write-Host "[常量消费门] 校验跨层常量的消费点..."
$tsSrc = Join-Path $projectRoot "verthys-tauri\src"
$rsRoots = @(
    (Join-Path $projectRoot "verthys-tauri\src-tauri\src"),
    (Join-Path $projectRoot "verthys-tauri\verthys-worker\src")
)
$tsGenerated = Join-Path $tsSrc "constants\photo_budget.generated.ts"
$rsGenerated = Join-Path $projectRoot "verthys-tauri\photo_budget.rs"
$tsRequired = @(
    'FLUSH_MAX_RETRIES', 'FLUSH_RETRY_BACKOFF_MS', 'FLUSH_VERIFY_TIMEOUT_MS',
    'SESSION_BEGIN_TIMEOUT_MS', 'SESSION_END_TIMEOUT_MS', 'SESSION_FORCE_CLOSE_TIMEOUT_MS',
    'DATAB64_CACHE_MAX_BYTES', 'PHOTO_INDEX_MAX_BYTES', 'PHOTO_THUMB_MAX_CHARS',
    'PHOTO_MAX_BYTES', 'MAX_EXPORT_SINGLE_BYTES'
)
$rsRequired = @(
    'PB_IPC_MAX_RESPONSE_LINE_BYTES', 'PB_IPC_MAX_REQUEST_LINE_BYTES', 'PB_IPC_MAX_LINE_BYTES',
    'PB_ENUM_RESPONSE_DATA_BUDGET_BYTES', 'PB_SCAN_INDEX_INLINE_MAX_BYTES',
    'PB_IPC_MAX_PAYLOAD_BYTES', 'PB_MAX_CHUNKS_PER_IPC',
    'PB_MAX_RECORD_NAME_BYTES', 'PB_WRITE_FILE_CHUNK_BYTES', 'PB_MAX_EXPORT_SINGLE_BYTES'
)
$consumerRed = $false
foreach ($name in $tsRequired) {
    $hits = Get-ChildItem -Path $tsSrc -Recurse -Filter *.ts |
        Where-Object { $_.FullName -ne $tsGenerated } |
        Select-String -Pattern "\b$name\b"
    if (-not $hits) {
        Write-Host "[常量消费门][RED] 生成常量 $name 无消费点"
        $consumerRed = $true
    }
}
foreach ($name in $rsRequired) {
    $hits = Get-ChildItem -Path $rsRoots -Recurse -Filter *.rs |
        Where-Object { $_.FullName -ne $rsGenerated } |
        Select-String -Pattern "\b$name\b"
    if (-not $hits) {
        Write-Host "[常量消费门][RED] 生成常量 $name 无消费点"
        $consumerRed = $true
    }
}
if ($consumerRed) { $exitCode = 1 } else { Write-Host "[常量消费门] 通过：清单内常量均存在消费点" }

# ===== 导出契约门 =====
# verthys.def 为导出符号权威清单，export_baseline 为验收快照；
# 集合不相等即红（历史发生过新增导出未同步基线）。
Write-Host ""
Write-Host "[导出契约门] 校验导出符号与基线一致..."
$defSyms = (Select-String -Path (Join-Path $projectRoot "core\verthys.def") -Pattern '^\s*Verthys_\w+' |
    ForEach-Object { $_.Line.Trim() }) | Sort-Object
$baseSyms = (Get-Content (Join-Path $projectRoot "ci\export_baseline.txt") |
    Where-Object { $_.Trim() -ne '' }) | Sort-Object
$symDiff = Compare-Object $defSyms $baseSyms
if ($symDiff) {
    Write-Host "[导出契约门][RED] 导出符号与基线不一致："
    $symDiff | ForEach-Object { Write-Host ("  {0} {1}" -f $_.SideIndicator, $_.InputObject) }
    $exitCode = 1
} else {
    Write-Host "[导出契约门] 通过：$($defSyms.Count) 个符号一致"
}

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
