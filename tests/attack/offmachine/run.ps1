# tests/attack/offmachine/run.ps1 — A6 离机验证（两阶段）
#
# 阶段 1（源机）：在隔离目录生成 v4 库 + 模块密钥文件，跑正控，
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

$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
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
    Copy-Item -LiteralPath $Probe -Destination (Join-Path $Dir 'vty_probe.exe') -Force

    $lines = @(& $Probe 'a6' $Dir 2>&1 | ForEach-Object { "$_" })
    $ok = @($lines | Where-Object { $_ -match '^RESULT A6 PASS ' }).Count -eq 1
    $lines | Write-Output
    if (-not $ok) {
        Write-Output 'RESULT A6 FAIL 源机正控失败，未生成可复制产物'
        exit 1
    }

    $artifacts = [ordered]@{}
    foreach ($name in @('a6.verthys', 'a6.mod', 'vty_probe.exe')) {
        $p = Join-Path $Dir $name
        if (Test-Path -LiteralPath $p) {
            $artifacts[$name] = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    $manifest = [ordered]@{
        case = 'A6'
        source_machine_sha256 = (Get-MachineGuidHash)
        os = (Get-OsName)
        artifacts_sha256 = $artifacts
        created_at = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
        note = '复制整个目录到异机后运行 -Mode verify；MachineGuid 哈希必须不同'
    }
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding utf8
    Write-Output "PACKAGE READY $Dir"
    exit 0
}

# ---------------- verify（目标机） ----------------
if (-not (Test-Path -LiteralPath $manifestPath)) { throw "缺少清单: $manifestPath" }
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$localGuid = Get-MachineGuidHash
$isOffmachine = ($localGuid -ne '' -and $localGuid -ne $manifest.source_machine_sha256)

# 复制过程中产物被截断/替换会让结论失真：先按清单核对哈希
$integrity = $true
foreach ($name in $manifest.artifacts_sha256.PSObject.Properties.Name) {
    $p = Join-Path $Dir $name
    if (-not (Test-Path -LiteralPath $p)) { $integrity = $false; break }
    $h = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($h -ne $manifest.artifacts_sha256.$name) { $integrity = $false; break }
}

$localProbe = Join-Path $Dir 'vty_probe.exe'
if (-not (Test-Path -LiteralPath $localProbe)) { $localProbe = $Probe }
$lines = @(& $localProbe 'a6run' $Dir 2>&1 | ForEach-Object { "$_" })
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
if (-not $isOffmachine) {
    $detail = '本机 MachineGuid 与源机相同：未离机，结论无效（不得判 PASS）'
} elseif (-not $integrity) {
    $detail = '产物与清单哈希不一致：复制损坏或被替换'
} elseif ($observed.vault_open -ne $VTY_E_TPM) {
    $detail = "离机后库仍可打开: vault_open=$($observed.vault_open)"
} elseif ($observed.plaintext_hits -ne 0) {
    $detail = "离机产物存在明文泄漏: hits=$($observed.plaintext_hits)"
} else {
    $pass = $true
    $detail = "离机后 vault_open=E_TPM，模块密钥不可得，明文 0 命中"
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
        detail = $detail
        executed_at = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
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
