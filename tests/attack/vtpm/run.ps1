# tests/attack/vtpm/run.ps1 — vTPM 能力验收（平台差异确认）
#
# 用途：在 VM/vTPM 来宾系统中运行 `vty_tpm_probe.exe`，采集 PCR 读取、
# TBS 授权会话与 TPM NV 计数器的可用性，产出可复核证据。
#
# 判定：
#   - 探针必须成功运行；PCR 读取与 PCP PCR 绑定正/负控必须成立；
#   - `TbsSessions` / `TbsNvCounter` 如实记录：两者为 true 才说明该平台
#     具备实现 NV 单调计数器的条件。
#
# 输出契约：
#   RESULT VTPM PASS|BLOCKED|FAIL <detail>
#   -OutJson 时写入环境、能力布尔值与关键原始行（不含密钥材料）。
param(
    [string]$Probe = '',
    [string]$OutJson
)
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
if (-not $Probe) {
    $Probe = Join-Path $repoRoot 'build/core/tests/Release/vty_tpm_probe.exe'
}
if (-not (Test-Path -LiteralPath $Probe)) {
    Write-Output "RESULT VTPM FAIL 探针缺失: $Probe"
    exit 1
}

$text = (& $Probe 2>&1 | Out-String)
if ([string]::IsNullOrWhiteSpace($text)) {
    Write-Output 'RESULT VTPM FAIL 探针无输出'
    exit 1
}

$caps = [ordered]@{
    TbsPcrRead         = [bool]($text -match '\[PCR\] policyDigest\(pcr7\|\|pcr11\)=')
    PcrBindingPositive = [bool]($text -match '\[PCP2\] oaep tpm decrypt st=0x00000000 .* match=YES')
    PcrBindingNegative = [bool]($text -match '\[PCP2\] oaep tpm decrypt st=0x80280084 .* match=NO')
    TbsSessions        = -not [bool]($text -match '\[SESS\] plain rc=0x0000008B')
    TbsNvCounter       = [bool]($text -match '\[NV\] after-2 value=2')
}

$pcrOk = $caps.TbsPcrRead -and $caps.PcrBindingPositive -and $caps.PcrBindingNegative
$nvOk = $caps.TbsSessions -and $caps.TbsNvCounter
if (-not $pcrOk) {
    $verdict = 'FAIL'
    $detail = 'PCR/PCP 能力不成立'
} elseif ($nvOk) {
    $verdict = 'PASS'
    $detail = 'PCR/PCP 成立；TBS 授权会话与 NV 计数器可用'
} else {
    $verdict = 'BLOCKED'
    $detail = 'PCR/PCP 成立；TBS 授权会话或 NV 计数器不可用'
}

$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
$isVm = $false
if ($cs) {
    $isVm = [bool]($cs.Model -match 'Virtual|VMware|Hyper-V|KVM|QEMU|VirtualBox') -or
            [bool]($cs.Manufacturer -match 'VMware|Microsoft Corporation|QEMU|innotek')
}
$tpmLine = @($text -split "`n" | Where-Object { $_ -match '^\[TPM\]' }) -join ' '
$sessLine = @($text -split "`n" | Where-Object { $_ -match '^\[SESS\] plain' }) -join ' '
$nvLine = @($text -split "`n" | Where-Object { $_ -match '^\[NV\] define\(hmac\)' }) -join ' '

if ($OutJson) {
    $parent = Split-Path -Parent $OutJson
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $report = [ordered]@{
        case = 'VTPM'
        verdict = $verdict
        detail = $detail
        capabilities = $caps
        environment = [ordered]@{
            os_caption = $(if ($os) { $os.Caption } else { '' })
            os_build = $(if ($os) { $os.BuildNumber } else { '' })
            is_vm = $isVm
            model = $(if ($cs) { $cs.Model } else { '' })
            manufacturer = $(if ($cs) { $cs.Manufacturer } else { '' })
        }
        observed = [ordered]@{
            tpm = $tpmLine
            tbs_session = $sessLine
            nv_counter = $nvLine
        }
        executed_at = (Get-Date).ToString('s')
    }
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutJson -Encoding utf8
}

Write-Output "RESULT VTPM $verdict $detail"
exit $(if ($verdict -eq 'FAIL') { 1 } else { 0 })
