# tests/attack/a2.ps1 — 任意进程加载 DLL 调用 Init
#
# 判定矩阵：
#   未签名宿主                      → Init 拒绝
#   其他发布者签名的宿主            → Init 拒绝（指纹不匹配）
#   已签名但被改 1 字节的宿主        → Init 拒绝（签名失效）
#   受信发布者签名的宿主 + 签名 DLL  → Init 成功（正向对照）
#   签名宿主 + 未签名 DLL            → Init 拒绝（自身签名）
#
# 使用独立构建目录 build/a2（VERTHYS_REQUIRE_CALLER_SIG=ON），
# 不影响主构建目录的普通回归；证书为测试专用自签证书。
# 输出契约：单行 RESULT PASS|FAIL <detail>
param(
    [string]$OutJson
)
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
# 工具链与生成器统一由环境加载器解析：本机显式注入与 CI 注入环境两条路径
# 共用同一探测逻辑，禁止在测试脚本里写死 VS 版本或安装路径。
. (Join-Path $repoRoot 'scripts/lib/env.load.ps1')
. (Join-Path $repoRoot 'scripts/lib/cmake.utils.ps1')
$cmake = $VERTHYS_CMAKE_EXE
$generator = $VERTHYS_VS_GENERATOR
if (-not (Test-Path -LiteralPath $cmake -PathType Leaf)) {
    throw "找不到 cmake（env.load 解析结果: $cmake）"
}

$expectedReject = 'INIT result=0x00000016'
$workDir = Join-Path $env:TEMP ('verthys_a2_' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workDir -Force | Out-Null

$detail = ''
$pass = $true
$observed = [ordered]@{}
$artifacts = [ordered]@{}

function Invoke-HostExe([string]$dir) {
    $exe = Join-Path $dir 'vty_signed_host.exe'
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe
    $psi.WorkingDirectory = $dir
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $proc = [System.Diagnostics.Process]::Start($psi)
    $out = ''
    $code = -1
    if ($proc.WaitForExit(30000)) {
        $out = $proc.StandardOutput.ReadToEnd()
        [void]$proc.StandardError.ReadToEnd()
        $code = $proc.ExitCode
    } else {
        # 初始化卡死同样属于“未按预期拒绝/放行”，必须显式失败而不是挂住门禁
        try { $proc.Kill() } catch { }
        $out = 'TIMEOUT'
    }
    return [pscustomobject]@{ Code = $code; Out = $out.Trim() }
}

try {
    # ---------- 证书 + 独立构建 ----------
    $certOut = & (Join-Path $PSScriptRoot 'signing/New-TestCert.ps1') -Install
    $publisherLine = @($certOut | Where-Object { $_ -like 'CERT CN=Verthys-Test-Publisher *' })
    if ($publisherLine.Count -ne 1) { throw '测试证书创建失败' }
    $publisherSha = $publisherLine[0].Split(' ')[3]

    $a2Build = Join-Path $repoRoot 'build/a2'
    # 生成器变更后缓存不可复用：不同生成器的产物布局与配置语义不同，
    # 沿用旧缓存会让产物路径解析落到不存在的目录。
    $cacheFile = Join-Path $a2Build 'CMakeCache.txt'
    if (Test-Path -LiteralPath $cacheFile) {
        $cachedGenerator = Select-String -LiteralPath $cacheFile -Pattern '^CMAKE_GENERATOR:INTERNAL=(.+)$' |
            Select-Object -First 1
        if ($cachedGenerator -and $cachedGenerator.Matches[0].Groups[1].Value -ne $generator) {
            Remove-Item -LiteralPath $a2Build -Recurse -Force
        } else {
            Clear-StaleCMakeCache -BuildDir $a2Build -SourceDir $repoRoot
        }
    }
    & $cmake -S $repoRoot -B $a2Build -G $generator -A x64 `
        '-DVERTHYS_REQUIRE_CALLER_SIG=ON' "-DVERTHYS_PUBLISHER_SHA256=$publisherSha" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'A2 构建配置失败' }
    & $cmake --build $a2Build --config Release --target verthys_core vty_signed_host | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'A2 构建失败' }

    # 产物路径以本轮构建契约与固定候选为准，不再假设单一生成器布局。
    $contractPath = Join-Path $a2Build 'core/verthys.artifacts.json'
    if (-not (Test-Path -LiteralPath $contractPath)) {
        throw "A2 产物契约缺失: $contractPath"
    }
    $contract = Get-Content -LiteralPath $contractPath -Raw | ConvertFrom-Json
    if ($null -eq $contract.dll -or [string]::IsNullOrEmpty($contract.dll)) {
        throw "A2 产物契约缺少 dll 字段: $contractPath"
    }
    $dll = Join-Path $repoRoot ($contract.dll -replace '/', '\')
    $hostCandidates = @(
        (Join-Path $a2Build 'core/tests/Release/vty_signed_host.exe'),
        (Join-Path $a2Build 'core/tests/vty_signed_host.exe')
    )
    $hostExe = $hostCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        Select-Object -First 1
    if (-not $hostExe) { throw 'A2 宿主产物缺失: vty_signed_host.exe' }
    foreach ($f in @($dll, $hostExe)) {
        if (-not (Test-Path -LiteralPath $f)) { throw "A2 产物缺失: $f" }
    }

    # 先签名（同时留下未签名副本供负向用例）
    $signScript = Join-Path $repoRoot 'scripts/build/sign.ps1'
    & $signScript -Files @($dll, $hostExe) | Out-Null

    $unsignedDll = $dll + '.unsigned'
    $unsignedHost = $hostExe + '.unsigned'
    if (-not (Test-Path $unsignedDll) -or -not (Test-Path $unsignedHost)) {
        throw '未签名副本缺失（首轮构建后签名会保留副本，请清理 build/a2 重试）'
    }

    # ---------- 场景目录 ----------
    $dirs = @{}
    foreach ($name in @('a1', 'a2', 'a3', 'a4', 'a5')) {
        $dirs[$name] = Join-Path $workDir $name
        New-Item -ItemType Directory -Path $dirs[$name] -Force | Out-Null
    }

    # 未签名宿主
    Copy-Item -LiteralPath $unsignedHost -Destination (Join-Path $dirs['a1'] 'vty_signed_host.exe')
    Copy-Item -LiteralPath $dll -Destination (Join-Path $dirs['a1'] 'verthys.dll')
    # 已签名宿主改 1 字节（DOS stub，仍可加载，但 Authenticode 摘要失效）
    $tamper = Join-Path $dirs['a3'] 'vty_signed_host.exe'
    Copy-Item -LiteralPath $hostExe -Destination $tamper
    $bytes = [IO.File]::ReadAllBytes($tamper)
    $bytes[0x40] = $bytes[0x40] -bxor 0x01
    [IO.File]::WriteAllBytes($tamper, $bytes)
    Copy-Item -LiteralPath $dll -Destination (Join-Path $dirs['a3'] 'verthys.dll')
    # 签名宿主 + 签名 DLL
    Copy-Item -LiteralPath $hostExe -Destination (Join-Path $dirs['a4'] 'vty_signed_host.exe')
    Copy-Item -LiteralPath $dll -Destination (Join-Path $dirs['a4'] 'verthys.dll')
    # 签名宿主 + 未签名 DLL
    Copy-Item -LiteralPath $hostExe -Destination (Join-Path $dirs['a5'] 'vty_signed_host.exe')
    Copy-Item -LiteralPath $unsignedDll -Destination (Join-Path $dirs['a5'] 'verthys.dll')
    # 用 Other-Publisher 对未签名宿主签名（签名有效但指纹不同）
    Copy-Item -LiteralPath $unsignedHost -Destination (Join-Path $dirs['a2'] 'vty_signed_host.exe')
    & $signScript -Files @((Join-Path $dirs['a2'] 'vty_signed_host.exe')) -Subject 'CN=Other-Publisher' -NoBackup | Out-Null
    Copy-Item -LiteralPath $dll -Destination (Join-Path $dirs['a2'] 'verthys.dll')

    # ---------- 执行矩阵 ----------
    $r4 = Invoke-HostExe $dirs['a4']
    $observed['A2-4'] = [ordered]@{ exit = $r4.Code; output = $r4.Out; expected = 'Init 成功' }
    if ($r4.Code -ne 0 -or $r4.Out -notlike '*INIT result=0x00000000*') {
        $pass = $false
        $detail = 'A2-4 正向对照未成功'
    }

    foreach ($case in @(@{ Id = 'A2-1'; Dir = 'a1' }, @{ Id = 'A2-2'; Dir = 'a2' }, @{ Id = 'A2-3'; Dir = 'a3' }, @{ Id = 'A2-5'; Dir = 'a5' })) {
        if (-not $pass) { break }
        $r = Invoke-HostExe $dirs[$case.Dir]
        $observed[$case.Id] = [ordered]@{ exit = $r.Code; output = $r.Out; expected = 'Init 拒绝' }
        if ($r.Out -notlike "*$expectedReject*") {
            $pass = $false
            $detail = "$($case.Id) 未被拒绝：$($r.Out)"
        }
    }

    foreach ($f in @($dll, $hostExe)) {
        $artifacts[(Split-Path -Leaf $f)] = (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    if ($pass) { $detail = 'A2-1/2/3/5 拒绝；A2-4 放行（签名宿主 + 签名 DLL）' }
} catch {
    $pass = $false
    if ($detail -eq '') { $detail = 'A2 执行异常：' + $_.Exception.Message }
} finally {
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}

if ($OutJson) {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $report = [ordered]@{
        case = 'A2'
        verdict = $(if ($pass) { 'PASS' } else { 'FAIL' })
        environment = [ordered]@{
            os = $(if ($os) { $os.Caption + ' ' + $os.Version } else { 'unknown' })
            require_caller_sig = $true
            build_dir = 'build/a2'
            certificate_store = 'CurrentUser (Root + TrustedPeople)'
        }
        steps = @(
            'New-TestCert.ps1 -Install (self-signed test publishers)',
            'configure build/a2 with VERTHYS_REQUIRE_CALLER_SIG=ON',
            'build verthys_core + vty_signed_host',
            'sign dll/host with Verthys-Test-Publisher',
            'run A2-1..A2-5 matrix from isolated directories'
        )
        observed = $observed
        artifacts_sha256 = $artifacts
        detail = $detail
        executed_at = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
    }
    $parent = Split-Path -Parent $OutJson
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutJson -Encoding utf8
}

if ($pass) {
    Write-Output "RESULT A2 PASS $detail"
    exit 0
}
Write-Output "RESULT A2 FAIL $detail"
exit 1
