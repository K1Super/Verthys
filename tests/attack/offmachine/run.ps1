# tests/attack/offmachine/run.ps1 — 离机验证（两阶段）
#
# 阶段 1（源机）：在隔离目录生成 库 + 模块密钥文件，跑正控，
#   记录产物 SHA-256 与源机 MachineGuid 的 SHA-256（不记录明文 GUID）。
# 阶段 2（目标机/VM）：把整个目录复制过去后执行 verify，
#   要求 MachineGuid 哈希不同（否则是假阴性），并断言：
#     vault_open=E_TPM(9)、module_unlock 取不到密钥、明文扫描 0 命中。
#
# 用法：
#   pwsh run.ps1 -Mode prepare -Dir <pkg>
#   pwsh run.ps1 -Mode verify  -Dir <pkg> -OutJson reports\a6-<runid>.json
param(
    [ValidateSet('prepare', 'verify')]
    [string]$Mode = 'prepare',
    [Parameter(Mandatory = $true)][string]$Dir,
    [string]$Probe,
    [string]$OutJson
)
$ErrorActionPreference = 'Stop'

# 包在目标机上可能位于浅层目录（如 C:\A6）：连续取父目录会得到空串并
# 让 Split-Path 参数绑定失败，因此逐级上溯并在到顶时停止。
$repoRoot = $PSScriptRoot
for ($i = 0; $i -lt 3; $i++) {
    $parent = Split-Path -Parent $repoRoot
    if ([string]::IsNullOrEmpty($parent)) { break }
    $repoRoot = $parent
}
if (-not $Probe) { $Probe = Join-Path $repoRoot 'build/core/tests/Release/vty_probe.exe' }
$manifestPath = Join-Path $Dir 'a6-manifest.json'
$VTY_E_TPM = 9

function Get-MachineGuidHash {
    $guid = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -ErrorAction SilentlyContinue).MachineGuid
    if (-not $guid) { return '' }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return (($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($guid)) |
                ForEach-Object { $_.ToString('x2') }) -join '')
    } finally { $sha.Dispose() }
}

function Get-OsName {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($os) { return $os.Caption + ' ' + $os.Version }
    return 'unknown'
}

if ($Mode -eq 'prepare') {
    if (-not (Test-Path -LiteralPath $Probe)) { throw "探针缺失: $Probe" }
    New-Item -ItemType Directory -Path $Dir -Force | Out-Null
    $Dir = (Resolve-Path -LiteralPath $Dir).Path
    Copy-Item -LiteralPath $Probe -Destination (Join-Path $Dir 'vty_probe.exe') -Force
    # 探针按 /MD 链接，目标机（Sandbox/干净 VM）可能没有 VC++ 运行库；
    # 同目录放置 VCRUNTIME140.dll，加载器优先使用包内副本。
    $runtime = Join-Path $env:SystemRoot 'System32\VCRUNTIME140.dll'
    if (-not (Test-Path -LiteralPath $runtime)) {
        Write-Output 'RESULT A6 FAIL 源机缺少 VCRUNTIME140.dll，无法生成自包含包'
        exit 1
    }
    Copy-Item -LiteralPath $runtime -Destination (Join-Path $Dir 'VCRUNTIME140.dll') -Force
    # 包必须自包含：目标机不一定有仓库，复制验证脚本本身并纳入清单哈希。
    # 目标机可能只有 Windows PowerShell 5.1：UTF-8 无 BOM 会把中文解析成
    # 乱码并导致语法错误，因此包内副本显式写成带 BOM 的 UTF-8。
    $verifyText = [System.IO.File]::ReadAllText($PSCommandPath)
    [System.IO.File]::WriteAllText(
        (Join-Path $Dir 'run.ps1'),
        $verifyText,
        (New-Object System.Text.UTF8Encoding($true))
    )

    $lines = @(& $Probe 'a6' $Dir 2>&1 | ForEach-Object { "$_" })
    $ok = @($lines | Where-Object { $_ -match '^RESULT A6 PASS ' }).Count -eq 1
    $lines | Write-Output
    if (-not $ok) {
        Write-Output 'RESULT A6 FAIL 源机正控失败，未生成可复制产物'
        exit 1
    }

    $sourceGuid = Get-MachineGuidHash
    if ([string]::IsNullOrWhiteSpace($sourceGuid)) {
        Write-Output 'RESULT A6 FAIL 无法读取源机 MachineGuid，不能证明离机前提'
        exit 1
    }

    # 自包含沙盒入口：预先写入 launch.cmd 与 .wsb，重建包即可一键复现，
    # 不依赖仓库外的手工产物。路径中的 XML 元字符必须转义。
    $wsbName = 'a6-sandbox.wsb'
    $launchText = @'
@echo off
echo START %DATE% %TIME% > C:\A6\logon-started.txt
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\A6\run.ps1 -Mode verify -Dir C:\A6 -OutJson C:\A6\a6-sandbox-report.json > C:\A6\verify-out.txt 2>&1
echo EXIT %ERRORLEVEL% >> C:\A6\logon-started.txt
'@
    [System.IO.File]::WriteAllText(
        (Join-Path $Dir 'launch.cmd'),
        $launchText.Replace("`r`n", "`n").Replace("`n", "`r`n"),
        (New-Object System.Text.UTF8Encoding($false)
        )
    )
    $xmlDir = $Dir.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;')
    $wsbText = @"
<Configuration>
  <Networking>Disable</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$xmlDir</HostFolder>
      <SandboxFolder>C:\A6</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>cmd.exe /c C:\A6\launch.cmd</Command>
  </LogonCommand>
</Configuration>
"@
    [System.IO.File]::WriteAllText(
        (Join-Path $Dir $wsbName),
        $wsbText,
        (New-Object System.Text.UTF8Encoding($false)
        )
    )

    $artifacts = [ordered]@{}
    foreach ($name in @('a6.verthys', 'vty_probe.exe', 'run.ps1',
            'VCRUNTIME140.dll', 'launch.cmd', $wsbName)) {
        $p = Join-Path $Dir $name
        if (-not (Test-Path -LiteralPath $p)) {
            Write-Output "RESULT A6 FAIL 源机产物缺失: $name"
            exit 1
        }
        $artifacts[$name] = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    # 构建绑定：离机报告必须能与当前 DLL / 探针 / worker 对号，否则攻击
    # 门禁会把报告判为 STALE（仅 verdict=PASS 不能作为证据）。
    $coreDll = Join-Path $repoRoot 'build/core/Release/verthys.dll'
    $workerExe = Join-Path $repoRoot 'verthys-tauri/verthys-worker/target/release/verthys-worker.exe'
    if (-not (Test-Path -LiteralPath $coreDll)) {
        Write-Output 'RESULT A6 FAIL 源机缺少 build/core/Release/verthys.dll，无法绑定当前构建'
        exit 1
    }
    if (-not (Test-Path -LiteralPath $workerExe)) {
        Write-Output 'RESULT A6 FAIL 源机缺少 Release worker，无法绑定当前构建'
        exit 1
    }
    $gitCommit = ''
    try {
        $gitCommit = (& git -C $repoRoot rev-parse HEAD 2>$null | Select-Object -First 1)
    } catch { }
    if ([string]::IsNullOrWhiteSpace([string]$gitCommit)) {
        $gitCommit = 'worktree-no-git'
    }
    $binding = [ordered]@{
        core_dll_sha256 = (Get-FileHash -LiteralPath $coreDll -Algorithm SHA256).Hash.ToLowerInvariant()
        worker_sha256   = (Get-FileHash -LiteralPath $workerExe -Algorithm SHA256).Hash.ToLowerInvariant()
        probe_sha256    = $artifacts['vty_probe.exe']
        git_commit      = [string]$gitCommit
        signer          = 'local-release-build'
    }

    $manifest = [ordered]@{
        case = 'A6'
        source_machine_sha256 = $sourceGuid
        os = (Get-OsName)
        artifacts_sha256 = $artifacts
        build_binding = $binding
        created_at = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
        note = '复制整个目录到异机后运行 .\run.ps1 -Mode verify；MachineGuid 哈希必须不同'
    }
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding utf8
    Write-Output "PACKAGE READY $Dir"
    exit 0
}

# ---------------- verify（目标机） ----------------
if (-not (Test-Path -LiteralPath $manifestPath)) { throw "缺少清单: $manifestPath" }
$Dir = (Resolve-Path -LiteralPath $Dir).Path
$manifestPath = Join-Path $Dir 'a6-manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$sourceGuid = [string]$manifest.source_machine_sha256
# 构建绑定随清单复制到目标机；报告顶层必须带这些字段，攻击门禁
# 据此判断证据是否属于当前构建（缺失或为空即视为 STALE）。
$binding = if ($manifest.PSObject.Properties['build_binding']) { $manifest.build_binding } else { $null }

function Get-BindingValue {
    param([string]$Name)
    if ($binding -and $binding.PSObject.Properties[$Name]) { return [string]$binding.$Name }
    return ''
}

$bindingFields = @('core_dll_sha256', 'probe_sha256', 'worker_sha256', 'git_commit', 'signer')
$bindingComplete = $true
foreach ($field in $bindingFields) {
    if ((Get-BindingValue $field) -eq '') { $bindingComplete = $false; break }
}

$localGuid = Get-MachineGuidHash
$isOffmachine = ($sourceGuid -ne '' -and $localGuid -ne '' -and $localGuid -ne $sourceGuid)

# 复制过程中产物被截断/替换会让结论失真：先按清单核对哈希。
# 清单必须同时包含库与探针；缺项视为清单损坏，不能凭“空集合”通过。
$integrity = $true
$expectedArtifacts = @('a6.verthys', 'vty_probe.exe', 'run.ps1',
    'VCRUNTIME140.dll', 'launch.cmd', 'a6-sandbox.wsb')
foreach ($name in $expectedArtifacts) {
    if (-not $manifest.artifacts_sha256.PSObject.Properties[$name]) {
        $integrity = $false
        break
    }
    $p = Join-Path $Dir $name
    if (-not (Test-Path -LiteralPath $p)) { $integrity = $false; break }
    $h = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($h -ne $manifest.artifacts_sha256.$name) { $integrity = $false; break }
}

$localProbe = Join-Path $Dir 'vty_probe.exe'
if (-not (Test-Path -LiteralPath $localProbe)) { $localProbe = $Probe }
# 清单校验失败时不执行包内探针：被替换的二进制不应再有执行机会。
$lines = @()
if ($integrity) {
    $lines = @(& $localProbe 'a6run' $Dir 2>&1 | ForEach-Object { "$_" })
}
else {
    $lines = @('A6RUN skipped: artifact integrity failed')
}
$runLine = @($lines | Where-Object { $_ -like 'A6RUN *' }) | Select-Object -First 1
$observed = [ordered]@{
    vault_open = -1
    module_unlock = -1
    plaintext_hits = -1
    device_level = -1
    device_provider = -1
    artifacts_verified = $integrity
}
if ($runLine -and $runLine -match 'device_level=(-?\d+) device_provider=(-?\d+) vault_open=(-?\d+) module_unlock=(-?\d+) plaintext_hits=(-?\d+)') {
    $observed.device_level = [int]$Matches[1]
    $observed.device_provider = [int]$Matches[2]
    $observed.vault_open = [int]$Matches[3]
    $observed.module_unlock = [int]$Matches[4]
    $observed.plaintext_hits = [int]$Matches[5]
}

$pass = $false
$detail = ''
if ($sourceGuid -eq '') {
    $detail = '源机 MachineGuid 哈希缺失：离机前提无法证明（不得判 PASS）'
} elseif (-not $isOffmachine) {
    $detail = '本机 MachineGuid 与源机相同或不可读：未离机，结论无效（不得判 PASS）'
} elseif (-not $integrity) {
    $detail = '产物与清单哈希不一致或清单缺项：复制损坏或被替换'
} elseif (-not $bindingComplete) {
    $detail = '清单缺少构建绑定字段：报告无法与当前 DLL/probe/worker 对号，不得判 PASS'
} elseif ($observed.vault_open -ne $VTY_E_TPM) {
    $detail = "离机后库仍可打开: vault_open=$($observed.vault_open)"
} elseif ($observed.module_unlock -eq 0) {
    $detail = '离机后模块密钥仍可解出: module_unlock=0'
} elseif ($observed.plaintext_hits -ne 0) {
    $detail = "离机产物存在明文泄漏: hits=$($observed.plaintext_hits)"
} else {
    $pass = $true
    $detail = "离机后 vault_open=E_TPM，模块解锁未成功（module_unlock=$($observed.module_unlock)），明文 0 命中"
}

if ($OutJson) {
    $report = [ordered]@{
        case = 'A6'
        verdict = $(if ($pass) { 'PASS' } else { 'FAIL' })
        environment = [ordered]@{
            os = (Get-OsName)
            is_offmachine = $isOffmachine
            machine_guid_sha256 = $localGuid
            source_machine_guid_sha256 = $manifest.source_machine_sha256
        }
        steps = @(
            'prepare on source machine (vty_probe a6)',
            'copy package to target machine',
            'verify on target (vty_probe a6run)'
        )
        observed = $observed
        artifacts_sha256 = $manifest.artifacts_sha256
        core_dll_sha256 = (Get-BindingValue 'core_dll_sha256')
        probe_sha256 = (Get-BindingValue 'probe_sha256')
        worker_sha256 = (Get-BindingValue 'worker_sha256')
        git_commit = (Get-BindingValue 'git_commit')
        signer = (Get-BindingValue 'signer')
        detail = $detail
        executed_at = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
        # 攻击门禁按 generated_at 判定报告是否早于当前 DLL 构建时间
        generated_at = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
    }
    $parent = Split-Path -Parent $OutJson
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutJson -Encoding utf8
}

$lines | Write-Output
if ($pass) {
    Write-Output "RESULT A6 PASS $detail"
    exit 0
}
Write-Output "RESULT A6 FAIL $detail"
exit 1
