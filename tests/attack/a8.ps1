# tests/attack/a8.ps1 — A8 密钥内存/日志零残留自动化
#
# A8-1 文件/状态目录：口令、恢复码、K_c/K_g/MDEK 以 UTF-8、UTF-16LE、
#      hex、base64 四种表示均 0 命中；
# A8-2 解锁态完整内存转储：密钥必须命中（正控，证明扫描器有效）；
# A8-3 Lock 后内存转储：同一批 secret 0 命中；
# A8-4 异常退出后 WER/CrashDumps 转储：0 命中。
#
# 输出契约：RESULT A8 PASS|FAIL <detail>，并为 run.ps1/gate.ps1 提供 JSON。
# 证据只记录命中次数，不落任何口令/恢复码/密钥内容。
param(
    [string]$OutJson
)
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$memHost = Join-Path $repoRoot 'build/core/tests/Release/vty_mem_host.exe'
if (-not (Test-Path $memHost)) {
    Write-Output 'RESULT A8 FAIL vty_mem_host.exe 缺失'
    exit 1
}

$workDir = Join-Path $env:TEMP ('verthys_a8_' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workDir -Force | Out-Null
# 崩溃/持驻宿主从工作目录副本启动：WER 会在进程退出后短暂持有镜像句柄，
# 直接运行构建产物会让下一轮链接报 LNK1104（文件被占用）。
$memHostRun = Join-Path $workDir 'vty_mem_host.exe'
Copy-Item -LiteralPath $memHost -Destination $memHostRun -Force
# 熔断/回滚状态默认写用户目录：隔离到本次工作目录，既避免污染真实状态，
# 也让状态文件进入 A8-1 的落盘扫描范围。
$env:LOCALAPPDATA = Join-Path $workDir 'localappdata'
New-Item -ItemType Directory -Path $env:LOCALAPPDATA -Force | Out-Null

$vault = Join-Path $workDir 'a8.verthys'
$dumpUnlocked = Join-Path $workDir 'a8_unlocked.dmp'
$dumpLocked = Join-Path $workDir 'a8_locked.dmp'
$password = 'a8-memory-pass'

function Start-MemHost([string]$mode, [string]$vaultPath, [string]$pw) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $memHostRun
    $psi.Arguments = '{0} "{1}"' -f $mode, $vaultPath
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.StandardOutputEncoding = [Text.Encoding]::UTF8
    $proc = [System.Diagnostics.Process]::Start($psi)
    if ($pw -ne $null) {
        $proc.StandardInput.WriteLine($pw)
        $proc.StandardInput.Flush()
    }
    $secrets = @{}
    while ($null -ne ($line = $proc.StandardOutput.ReadLine())) {
        if ($line -like 'SECRET *') {
            $parts = $line.Split(' ', 3)
            if ($parts.Length -eq 3) { $secrets[$parts[1]] = $parts[2] }
        } elseif ($line -like 'READY *') {
            break
        } elseif ($line -like 'ERROR *') {
            break
        }
    }
    return [pscustomobject]@{ Proc = $proc; Secrets = $secrets }
}

function ConvertFrom-Hex([string]$hex) {
    $bytes = New-Object byte[] ($hex.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16)
    }
    return $bytes
}

$patterns = New-Object System.Collections.ArrayList

# secret 的四种表示：原始字节 / hex 文本 / hex(UTF-16LE) / base64
function Add-KeyPatterns([string]$label, [string]$hex) {
    $raw = ConvertFrom-Hex $hex
    [void]$patterns.Add(@{ Name = "$label/raw"; Bytes = $raw })
    [void]$patterns.Add(@{ Name = "$label/hex"; Bytes = [Text.Encoding]::ASCII.GetBytes($hex) })
    [void]$patterns.Add(@{ Name = "$label/hex16"; Bytes = [Text.Encoding]::Unicode.GetBytes($hex) })
    [void]$patterns.Add(@{ Name = "$label/b64"; Bytes = [Text.Encoding]::ASCII.GetBytes([Convert]::ToBase64String($raw)) })
}

function Add-TextPatterns([string]$label, [string]$text) {
    $u8 = [Text.Encoding]::UTF8.GetBytes($text)
    $u16 = [Text.Encoding]::Unicode.GetBytes($text)
    $hex = ($u8 | ForEach-Object { $_.ToString('x2') }) -join ''
    [void]$patterns.Add(@{ Name = "$label/utf8"; Bytes = $u8 })
    [void]$patterns.Add(@{ Name = "$label/utf16"; Bytes = $u16 })
    [void]$patterns.Add(@{ Name = "$label/hex"; Bytes = [Text.Encoding]::ASCII.GetBytes($hex) })
    [void]$patterns.Add(@{ Name = "$label/b64"; Bytes = [Text.Encoding]::ASCII.GetBytes([Convert]::ToBase64String($u8)) })
}

function Get-ScanText([string]$path) {
    $bytes = [IO.File]::ReadAllBytes($path)
    $text = [Text.Encoding]::Latin1.GetString($bytes)
    [Array]::Clear($bytes, 0, $bytes.Length)
    return $text
}

function Measure-PatternHits([string]$text, [byte[]]$pattern) {
    if ($pattern.Length -lt 4) { return 0 }
    $needle = [Text.Encoding]::Latin1.GetString($pattern)
    $count = 0
    $idx = 0
    while (($idx = $text.IndexOf($needle, $idx, [StringComparison]::Ordinal)) -ge 0) {
        $count++
        $idx++
    }
    return $count
}

function Measure-AllHits([string]$path, $list) {
    if (-not (Test-Path -LiteralPath $path)) { return 0 }
    if ((Get-Item -LiteralPath $path).Length -gt 768MB) { return 0 }
    $text = Get-ScanText $path
    $hits = 0
    foreach ($pat in $list) {
        $hits += Measure-PatternHits $text $pat.Bytes
    }
    return $hits
}

$detail = ''
$fileHits = 0
$positiveHits = 0
$lockedHits = 0
$werHits = 0
$werFiles = 0
$hold = $null
$crash = $null
$pass = $true

try {
    # ---------- 建库 → 保存 → 轮换 → 解锁（hold 角色） ----------
    $hold = Start-MemHost 'hold' $vault $password
    if ($hold.Secrets.Count -lt 2 -or -not $hold.Secrets.ContainsKey('kc')) {
        throw 'hold 未返回密钥材料'
    }
    Add-KeyPatterns 'kc' $hold.Secrets['kc']
    if ($hold.Secrets.ContainsKey('kg')) { Add-KeyPatterns 'kg' $hold.Secrets['kg'] }
    foreach ($key in $hold.Secrets.Keys) {
        if ($key -like 'mdek*') { Add-KeyPatterns $key $hold.Secrets[$key] }
    }
    Add-TextPatterns 'password' $hold.Secrets['password']
    if ($hold.Secrets.ContainsKey('recovery')) {
        Add-TextPatterns 'recovery' $hold.Secrets['recovery']
    }

    # ---------- A8-2：解锁态转储（正控必须命中） ----------
    & $memHostRun dump $hold.Proc.Id $dumpUnlocked | Out-Null
    if (-not (Test-Path $dumpUnlocked)) { throw '解锁态转储生成失败' }
    $positiveHits = Measure-AllHits $dumpUnlocked $patterns
    if ($positiveHits -le 0) {
        $pass = $false
        $detail = 'A8-2 正控未命中（扫描器或转储无效）'
    }

    # ---------- A8-3：Lock 后转储（必须 0 命中） ----------
    if ($pass) {
        $hold.Proc.StandardInput.WriteLine('LOCK')
        $hold.Proc.StandardInput.Flush()
        $sawLocked = $false
        while ($null -ne ($line = $hold.Proc.StandardOutput.ReadLine())) {
            if ($line -eq 'LOCKED') { $sawLocked = $true; break }
        }
        if (-not $sawLocked) { throw 'hold 未确认 LOCKED' }
        Start-Sleep -Seconds 2   # 给分配器归还/清零窗口
        & $memHostRun dump $hold.Proc.Id $dumpLocked | Out-Null
        if (-not (Test-Path $dumpLocked)) { throw '锁定态转储生成失败' }
        $lockedHits = Measure-AllHits $dumpLocked $patterns
        if ($lockedHits -ne 0) {
            $pass = $false
            $detail = "A8-3 锁定后内存仍有 $lockedHits 处命中"
        }
    }
    if ($hold -ne $null -and -not $hold.Proc.HasExited) {
        $hold.Proc.StandardInput.WriteLine('EXIT')
        $hold.Proc.StandardInput.Flush()
        [void]$hold.Proc.WaitForExit(10000)
    }

    # ---------- A8-1：落盘文件与状态目录（必须 0 命中） ----------
    if ($pass) {
        $files = Get-ChildItem -LiteralPath $workDir -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -ne $dumpUnlocked -and $_.FullName -ne $dumpLocked }
        foreach ($f in $files) {
            $fileHits += Measure-AllHits $f.FullName $patterns
        }
        if ($fileHits -ne 0) {
            $pass = $false
            $detail = "A8-1 落盘文件命中 $fileHits 处"
        }
    }

    # ---------- A8-4：异常退出后的 WER/CrashDumps ----------
    if ($pass) {
        $crashStart = Get-Date
        $crash = Start-MemHost 'crash' $vault $hold.Secrets['password']
        Start-Sleep -Milliseconds 500
        $crash.Proc.StandardInput.WriteLine('CRASH')
        $crash.Proc.StandardInput.Flush()
        [void]$crash.Proc.WaitForExit(15000)
        # 崩溃进程可能被 WER 挂起：Process.Kill 在挂起态可能失败，改用系统命令兜底；
        # 已退出时 taskkill 只是返回错误，不影响结果。
        & taskkill /F /PID $crash.Proc.Id 2>$null | Out-Null
        $werDirs = @(
            (Join-Path $env:LOCALAPPDATA 'CrashDumps'),
            (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\WER\ReportArchive'),
            (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\WER\ReportQueue')
        )
        foreach ($dir in $werDirs) {
            if (-not (Test-Path $dir)) { continue }
            $items = Get-ChildItem -LiteralPath $dir -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt $crashStart.AddMinutes(-2) }
            foreach ($f in $items) {
                $werFiles++
                $werHits += Measure-AllHits $f.FullName $patterns
            }
        }
        if ($werHits -ne 0) {
            $pass = $false
            $detail = "A8-4 崩溃/WER 转储命中 $werHits 处"
        }
        # WER 挂起窗口内 taskkill 会被拒绝；短暂重试回收进程，失败也不改变判定
        for ($attempt = 0; $attempt -lt 10; $attempt++) {
            if ($crash.Proc.HasExited) { break }
            & taskkill /F /PID $crash.Proc.Id 2>$null | Out-Null
            if ($crash.Proc.HasExited) { break }
            Start-Sleep -Milliseconds 1000
        }
    }

    if ($pass) {
        $werNote = if ($werFiles -eq 0) { 'A8-4 无 WER/崩溃转储生成' } else { "A8-4 扫描 $werFiles 个 WER 文件 0 命中" }
        $detail = "A8-1 文件 0 命中；A8-2 正控命中 $positiveHits；A8-3 锁定后 0 命中；$werNote"
    }
} catch {
    $pass = $false
    if ($detail -eq '') { $detail = 'A8 执行异常：' + $_.Exception.Message }
} finally {
    foreach ($p in @($hold, $crash)) {
        if ($p -eq $null -or $p.Proc -eq $null) { continue }
        try {
            if (-not $p.Proc.HasExited) { $p.Proc.Kill() }
        } catch { }
        # 原生命令兜底：WER 挂起态下 Process.Kill 可能静默失败
        try { & taskkill /F /PID $p.Proc.Id 2>$null | Out-Null } catch { }
        try { $p.Proc.Dispose() } catch { }
    }
    foreach ($d in @($dumpUnlocked, $dumpLocked)) {
        if (Test-Path $d) { Remove-Item -LiteralPath $d -Force -ErrorAction SilentlyContinue }
    }
}
if ($OutJson) {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $guidHash = ''
    $machineGuid = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -ErrorAction SilentlyContinue).MachineGuid
    if ($machineGuid) {
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $guidHash = ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($machineGuid)) | ForEach-Object { $_.ToString('x2') }) -join '' }
        finally { $sha.Dispose() }
    }
    $virtual = $false
    if ($os) { $virtual = ($os.Model -match 'Virtual|VMware|Hyper-V|KVM|QEMU') }
    $artifacts = [ordered]@{}
    foreach ($path in @($memHost, (Join-Path $repoRoot 'build/core/Release/verthys.dll'))) {
        if (Test-Path -LiteralPath $path) {
            $artifacts[(Split-Path -Leaf $path)] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    $report = [ordered]@{
        case = 'A8'
        verdict = $(if ($pass) { 'PASS' } else { 'FAIL' })
        environment = [ordered]@{
            os = $(if ($os) { $os.Caption + ' ' + $os.Version } else { 'unknown' })
            is_vm = $virtual
            machine_guid_sha256 = $guidHash
            localappdata_isolated = $true
        }
        steps = @(
            'hold: create → save → rotate → open',
            'MiniDumpWriteDump unlocked (positive control)',
            'LOCK → 2s → MiniDumpWriteDump locked',
            'scan workdir + isolated LOCALAPPDATA files',
            'crash role → scan WER/CrashDumps'
        )
        observed = [ordered]@{
            files = $fileHits
            dump_unlocked_positive = $positiveHits
            dump_locked = $lockedHits
            wer = $werHits
            wer_files = $werFiles
        }
        artifacts_sha256 = $artifacts
        detail = $detail
        executed_at = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
    }
    $parent = Split-Path -Parent $OutJson
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $report | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath $OutJson -Encoding utf8
}

Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
if ($pass) {
    Write-Output "RESULT A8 PASS $detail"
    exit 0
}
Write-Output "RESULT A8 FAIL $detail"
exit 1
