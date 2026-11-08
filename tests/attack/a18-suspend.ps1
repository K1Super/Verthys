# tests/attack/a18-suspend.ps1 — worker 挂起看门狗端到端验证
#
# 覆盖：
#   健康期：真实 worker 心跳正常，看门狗不得误杀；
#   挂起全部 worker 线程后 3s 级触发处置（实测毫秒落盘）；
#   处置后 worker 进程终止（会话密钥随进程消亡）。
#
# 实现边界：看门狗与心跳均为产品代码（src-tauri worker/session.rs +
# worker runtime）。脚本只负责设置环境、驱动受门控的 Rust 用例并核对结果，
# 不在 PowerShell 中模拟产品逻辑。UI 锁定路径由 security-session.spec 与
# M2 手工锁屏/挂起验证覆盖。
#
# 输出契约：单行 RESULT PASS|FAIL <detail>
param(
    [string]$OutJson,
    [string]$Worker = '',
    [string]$Dll = ''
)
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $Worker) { $Worker = Join-Path $repoRoot 'verthys-tauri/verthys-worker/target/release/verthys-worker.exe' }
if (-not $Dll) { $Dll = Join-Path $repoRoot 'build/core/Release/verthys.dll' }
$srcTauri = Join-Path $repoRoot 'verthys-tauri/src-tauri'

if (-not (Test-Path -LiteralPath $Worker)) {
    Write-Output 'RESULT A18S FAIL release worker 缺失'
    exit 1
}
if (-not (Test-Path -LiteralPath $Dll)) {
    Write-Output 'RESULT A18S FAIL verthys.dll 缺失'
    exit 1
}

Import-Module (Join-Path $PSScriptRoot '../lib/VerthysTestHygiene.psm1') -Force
$hygiene = Start-VerthysTestHygiene

$workDir = Join-Path $env:TEMP ('verthys_a18s_' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workDir -Force | Out-Null
$oldLocalAppData = $env:LOCALAPPDATA
$env:LOCALAPPDATA = Join-Path $workDir 'localappdata'
New-Item -ItemType Directory -Path $env:LOCALAPPDATA -Force | Out-Null

$env:VERTHYS_A18 = '1'
$env:VERTHYS_A18_WORKER = $Worker
$env:VERTHYS_A18_DLL = $Dll
$lines = @()
$exitCode = -1
try {
    Push-Location -LiteralPath $srcTauri
    $lines = @(& cargo test --lib suspend_watchdog -- --nocapture --test-threads=1 2>&1 |
        ForEach-Object { "$_" })
    $exitCode = $LASTEXITCODE
}
finally {
    Pop-Location
    $env:VERTHYS_A18 = $null
    $env:VERTHYS_A18_WORKER = $null
    $env:VERTHYS_A18_DLL = $null
    $env:LOCALAPPDATA = $oldLocalAppData
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
    Complete-VerthysTestHygiene -Scope $hygiene
}

$elapsedMs = -1
foreach ($line in $lines) {
    if ($line -match 'A18S_ELAPSED_MS=(\d+)') {
        $elapsedMs = [int]$Matches[1]
        break
    }
}
$testOk = @($lines | Where-Object { $_ -match '1 passed; 0 failed' }).Count -gt 0
$pass = ($exitCode -eq 0) -and $testOk -and ($elapsedMs -ge 2000) -and ($elapsedMs -le 5000)

$detail = "exit=$exitCode; elapsed=${elapsedMs}ms; testOk=$testOk"
$result = if ($pass) { 'PASS' } else { 'FAIL' }

if ($OutJson) {
    $parent = Split-Path -Parent $OutJson
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    [pscustomobject]@{
        case      = 'A18S'
        verdict   = $result
        elapsed_ms = $elapsedMs
        worker    = $Worker
        dll       = $Dll
        detail    = ($lines | Select-Object -Last 12) -join "`n"
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $OutJson -Encoding utf8
}

Write-Output "RESULT A18S $result $detail"
if ($pass) { exit 0 } else { exit 1 }
