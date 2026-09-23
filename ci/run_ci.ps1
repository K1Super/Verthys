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
