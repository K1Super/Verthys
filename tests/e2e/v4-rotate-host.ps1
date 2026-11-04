<#
  tests/e2e/v4-rotate-host.ps1 — Tauri 宿主层全库 DEK 轮换集成用例

  范围：真实 AppHandle / AppState / worker 子进程 / DLL：
    创建容器（返回恢复码）→ 写记录 → 启用模块 → 锁库 → 恢复码解锁 →
    轮换 Begin/UnlockModule/Run/Abort → 轮换 Begin/UnlockModule/Run/Commit
    → 提交后读回记录 → 清理

  构建：cargo build --features e2e_rotate（默认 debug）。
  运行：以隐藏窗口启动应用，结果写入沙箱 result.txt；本脚本只在全部步骤
        通过且退出码为 0 时判 PASS。

  沙箱隔离：应用通过 --data-dir 指向临时目录，容器/DPAPI 口令/审计日志
  全部落在沙箱内，测试结束后整体删除。
#>
[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [string]$OutJson,
    [int]$TimeoutSeconds = 180
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$srcTauri = Join-Path $repoRoot 'verthys-tauri/src-tauri'
$exePath = Join-Path $srcTauri 'target/debug/verthys-tauri.exe'

if (-not $SkipBuild) {
    $envLoader = Join-Path $repoRoot 'scripts/lib/env.load.ps1'
    if (Test-Path -LiteralPath $envLoader) { . $envLoader }
    Push-Location $srcTauri
    try { & cargo build --features e2e_rotate --quiet; $buildExit = $LASTEXITCODE }
    finally { Pop-Location }
    if ($buildExit -ne 0) { throw 'e2e_rotate 构建失败' }
}
if (-not (Test-Path -LiteralPath $exePath)) { throw "应用二进制缺失: $exePath" }

Import-Module (Join-Path $PSScriptRoot '../lib/VerthysTestHygiene.psm1') -Force
# 宿主进程同样会按库 UUID 写 TPM 见证密钥；LOCALAPPDATA 隔离覆盖不到
# 这一层，必须在隔离生效前记录真实快照。
$hygiene = Start-VerthysTestHygiene

$sandbox = Join-Path $env:TEMP ("v4_rotate_host_" + [guid]::NewGuid().ToString('N'))
$dataDir = Join-Path $sandbox 'data'
$resultPath = Join-Path $sandbox 'result.txt'
New-Item -ItemType Directory -Path $dataDir -Force | Out-Null

$oldRotate = $env:VERTHYS_E2E_ROTATE
$oldDir = $env:VERTHYS_E2E_ROTATE_DIR
$oldResult = $env:VERTHYS_E2E_ROTATE_RESULT
$env:VERTHYS_E2E_ROTATE = '1'
$env:VERTHYS_E2E_ROTATE_DIR = $sandbox
$env:VERTHYS_E2E_ROTATE_RESULT = $resultPath

# 隔离 C 层跨进程状态：lockout / rollback / 设备源状态位于
# %LOCALAPPDATA%\Verthys，不隔离时连续门禁复跑与攻击回归会互相污染。
# 实测根因：rollback.state 的锚点表写满 64 条后新库登记失败；create 失败
# 路径曾先删文件后关句柄，DeleteFileW 失败并把错误改写为 IO，worker 再把
# IO 统一成 AUTH（与 v4-worker-smoke 的隔离口径一致）。
$oldLocalAppData = $env:LOCALAPPDATA
$isoLocalAppData = Join-Path $sandbox 'localappdata'
New-Item -ItemType Directory -Path $isoLocalAppData -Force | Out-Null
$env:LOCALAPPDATA = $isoLocalAppData

$proc = $null
$output = @()
$verdict = 'FAIL'
$passed = 0
$failed = 1

try {
    $proc = Start-Process -FilePath $exePath `
        -ArgumentList @('--data-dir', $dataDir) `
        -PassThru -NoNewWindow
    if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
        try { & taskkill.exe /PID $proc.Id /T /F | Out-Null } catch { }
        throw "宿主层轮换用例超时（${TimeoutSeconds}s）"
    }

    $text = ''
    if (Test-Path -LiteralPath $resultPath) {
        $text = Get-Content -LiteralPath $resultPath -Raw
    }
    $output = @($text -split "`r?`n" | Where-Object { $_ -ne '' })

    if ($proc.ExitCode -eq 0 -and $text -match '^PASS') {
        $passed = 1
        $failed = 0
        $verdict = 'PASS'
    } else {
        $detail = if ($output.Count -gt 1) { $output[1] } else { '无结果文件或结果非法' }
        throw "宿主层轮换用例失败（exit=$($proc.ExitCode)）: $detail"
    }
} catch {
    $output += "ERROR: $($_.Exception.Message)"
    throw
} finally {
    if ($null -ne $proc -and -not $proc.HasExited) {
        try { & taskkill.exe /PID $proc.Id /T /F | Out-Null } catch { }
    }
    $env:VERTHYS_E2E_ROTATE = $oldRotate
    $env:VERTHYS_E2E_ROTATE_DIR = $oldDir
    $env:VERTHYS_E2E_ROTATE_RESULT = $oldResult
    $env:LOCALAPPDATA = $oldLocalAppData

    Remove-Item -LiteralPath $sandbox -Recurse -Force -ErrorAction SilentlyContinue
    Complete-VerthysTestHygiene -Scope $hygiene
}

Write-Host "=== E2E V4-ROTATE-HOST ==="
$output | ForEach-Object { Write-Host $_ }
Write-Host "E2E V4-ROTATE-HOST $verdict"

if ($OutJson) {
    $parent = Split-Path -Parent $OutJson
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $report = [pscustomobject]@{
        Timestamp = (Get-Date).ToString('s')
        Stage     = 'V4-ROTATE-HOST'
        Tests     = @('host_rotate_begin_run_abort_commit')
        Verdict   = $verdict
        Passed    = $passed
        Failed    = $failed
        Output    = $output
    }
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutJson -Encoding utf8
}

if ($verdict -ne 'PASS') { exit 1 }
exit 0
