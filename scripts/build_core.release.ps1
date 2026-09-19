# scripts/build_core.release.ps1 - 核心安全 DLL 生产环境构建（Release，无测试，供 Tauri 打包消费）
#
# ★ 编码警告：本文件必须保存为 UTF-8 with BOM 编码！
#   Windows PowerShell 5.1 对无 BOM 文件按 ANSI/GBK 解码，中文注释乱码会
#   破坏字符串配对导致解析错误（ParseError），而解析错误发生在任何代码
#   执行之前，try/catch 与暂停完全失效——表现为窗口一闪而过且无任何
#   错误显示。保存后请确认文件头 3 字节为 EF BB BF。
#
# 环境隔离声明：
#   - 本脚本仅用于生产环境（Release），产物路径固定为 build/core/Release/
#   - 与 build_core.dev.ps1 完全独立，禁止互相调用或共享构建目录
#   - 所有工具路径来自系统环境变量（经 env.load.ps1 注入），脚本内零硬编码
#   - Release 构建跳过测试（测试已在开发环境完成），仅产出加固后的 DLL
#
# 用法: powershell -ExecutionPolicy Bypass -File scripts\build_core.release.ps1 [-Clean] [-NoPause]
#   -Clean    构建前清理 build 目录
#   -NoPause  失败/成功后不暂停等待 Enter（CI 场景使用；双击运行时不传此参数以便查看输出）
param(
    [switch]$Clean,
    [switch]$NoPause
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

# ========== 主流程（try/catch 包裹防止闪退） ==========
# 任何未捕获错误（含 env.load.ps1 环境变量缺失的 throw、CMake 配置/构建失败、
# DLL 产物缺失校验失败）都会进入 catch 块显示错误信息并暂停，双击运行场景不会窗口一闪而过
try {

# 加载环境变量（必需变量缺失会 fail-fast）
. $PSScriptRoot\env.load.ps1
# 加载 CMake 缓存自愈工具（陈旧缓存检测，见函数头注释）
. $PSScriptRoot\cmake.utils.ps1

$root       = Split-Path -Parent $PSScriptRoot
# 生产环境固定构建目录：build/（Tauri 打包配置消费 build/core/Release/verthys.dll）
$buildDir   = Join-Path $root "build"
$config     = "Release"

if ($Clean -and (Test-Path $buildDir)) {
    Write-Host "[clean] 移除 $buildDir" -ForegroundColor Yellow
    Remove-Item -Recurse -Force $buildDir
}

# ★ 陈旧缓存自愈（根因修复）：项目目录迁移/重命名后，
# build/CMakeCache.txt 记录的绝对路径（CMAKE_HOME_DIRECTORY）失效，
# CMake 报 "CMakeCache.txt directory ... is different than the directory
# ... where CMakeCache.txt was created" 并拒绝配置。此处检测到不一致时
# 自动清理构建目录并全量重建，保证任意路径变更后脚本仍可一键自愈。
Clear-StaleCMakeCache -BuildDir $buildDir -SourceDir $root

Write-Host "[configure] 生产环境 Release 构建" -ForegroundColor Cyan
Write-Host "  生成器: $VERTHYS_VS_GENERATOR"
Write-Host "  构建目录: $buildDir"

& $VERTHYS_CMAKE_EXE -S $root -B $buildDir -G $VERTHYS_VS_GENERATOR -A x64
if ($LASTEXITCODE -ne 0) { throw "configure 失败" }

Write-Host "[build] $config（安全加固：/O2 /GL /GS /guard:cf，剥离符号）" -ForegroundColor Cyan
& $VERTHYS_CMAKE_EXE --build $buildDir --config $config
if ($LASTEXITCODE -ne 0) { throw "build 失败" }

$dllPath = Join-Path $buildDir "core\$config\verthys.dll"
if (-not (Test-Path $dllPath)) {
    throw "DLL 产物缺失: $dllPath"
}


# ========== ★ .vsec 完整性基准注入 ==========
# 链接完成后解析 PE，计算 .text / .rdata / .rhat 节的文件内容 HMAC-SHA256
# （域密钥与 core/src/security/integrity/integrity.c 中 K_VSEC_DOMAIN_KEY
#   逐字节一致），写入 DLL 的 .vsec 只读节。运行时 integrity_verify_startup
# 从磁盘重算比对（文件内容为校验对象，天然免疫 ASLR 重定位）。
# ★ .rhat（运行时函数哈希表，rhash_gen POST_BUILD 已在 cmake --build
#   阶段补丁）纳入第三槽——表文件级篡改 = 启动拒绝（构建期文件哈希被
#   改写即可绕过运行期校验的攻击面被 .vsec 封死）。
# 注意：Authenticode 签名（若有）必须在本步骤【之后】进行。
function Update-VsecBaseline {
    param([string]$DllPath)

    $domainKey = [byte[]](
        0x76,0x65,0x72,0x74,0x68,0x79,0x73,0x2F,0x76,0x73,0x65,0x63,0x2D,0x76,0x31,0x2F,
        0x9E,0x37,0x79,0xB9,0x7F,0x4A,0x7C,0x15,
        0xBF,0x61,0x83,0xD2,0x55,0x0A,0x34,0x6C)

    $bytes = [System.IO.File]::ReadAllBytes($DllPath)
    $ms = New-Object System.IO.MemoryStream(,$bytes)
    $br = New-Object System.IO.BinaryReader($ms)

    # --- 解析 PE 头 ---
    $ms.Seek(0x3C, 'Begin') | Out-Null
    $eLfanew = $br.ReadInt32()
    $ms.Seek($eLfanew, 'Begin') | Out-Null
    $sig = $br.ReadBytes(4)
    if ($sig[0] -ne 0x50 -or $sig[1] -ne 0x45) { throw ".vsec 注入失败：PE 签名不符" }
    [void]$br.ReadUInt16()             # e_lfanew+4：Machine（COFF 头首字段）
    $numSections = $br.ReadUInt16()    # e_lfanew+6：NumberOfSections
    $ms.Seek(12, 'Current') | Out-Null # 跳过 TimeDateStamp(4)+PtrSymbol(4)+NumSymbols(4) → 到 +20
    $optSize = $br.ReadUInt16()        # e_lfanew+20：SizeOfOptionalHeader
    $ms.Seek(2, 'Current') | Out-Null # 跳过 Characteristics（+22）
    $secStart = $eLfanew + 4 + 20 + $optSize

    $sections = @()
    for ($i = 0; $i -lt $numSections; $i++) {
        $ms.Seek($secStart + 40 * $i, 'Begin') | Out-Null
        $nameBytes = $br.ReadBytes(8)
        $name = [System.Text.Encoding]::ASCII.GetString($nameBytes).TrimEnd([char]0)
        $virtualSize = $br.ReadUInt32()
        $virtualAddr = $br.ReadUInt32()
        $rawSize = $br.ReadUInt32()
        $rawPtr = $br.ReadUInt32()
        $sections += [pscustomobject]@{ Name=$name; RawSize=$rawSize; RawPtr=$rawPtr }
    }

    $vsec = $sections | Where-Object { $_.Name -eq ".vsec" }
    if ($null -eq $vsec -or $vsec.RawSize -lt 128) { throw ".vsec 注入失败：节缺失或过小" }
    $rhatSec = $sections | Where-Object { $_.Name -eq ".rhat" }
    if ($null -eq $rhatSec) { throw ".vsec 注入失败：.rhat 节缺失（WP-8 rhash_gen POST_BUILD 未执行?）" }

    $hmac = [System.Security.Cryptography.HMACSHA256]::new($domainKey)
    try {
        $textHash  = $hmac.ComputeHash($bytes, $vsec.RawPtr, $vsec.RawSize)
        $rdataSec = $sections | Where-Object { $_.Name -eq ".rdata" }
        if ($null -eq $rdataSec) { throw ".vsec 注入失败：.rdata 节缺失" }
        $rdataHash = $hmac.ComputeHash($bytes, $rdataSec.RawPtr, $rdataSec.RawSize)
        $rhatHash  = $hmac.ComputeHash($bytes, $rhatSec.RawPtr, $rhatSec.RawSize)
    } finally {
        $hmac.Dispose()
    }

    # --- 写入 .vsec v2：magic 'VESV'(4) + version=2(2) + flags(2) +
    #     text(32) + rdata(32) + rhat(32) + 保留(24) ---
    $blob = New-Object byte[] 128
    $blob[0]=0x56; $blob[1]=0x45; $blob[2]=0x53; $blob[3]=0x43
    $blob[4]=0x02; $blob[5]=0x00
    $blob[6]=0x00; $blob[7]=0x00
    [Array]::Copy($textHash, 0, $blob, 8, 32)
    [Array]::Copy($rdataHash, 0, $blob, 40, 32)
    [Array]::Copy($rhatHash, 0, $blob, 72, 32)
    [Array]::Copy($blob, 0, $bytes, $vsec.RawPtr, 128)

    [System.IO.File]::WriteAllBytes($DllPath, $bytes)
    Write-Host "[vsec] 完整性基准已注入 .vsec v2（text+rdata+rhat HMAC-SHA256）" -ForegroundColor Cyan
}

Update-VsecBaseline -DllPath $dllPath

Write-Host "[done] 生产构建完成" -ForegroundColor Green
Write-Host "  产物: $dllPath"
$info = Get-Item $dllPath
Write-Host ("  大小: {0} KB（{1}）" -f [math]::Round($info.Length / 1KB, 1), $info.LastWriteTime)
Write-Host "  Tauri 打包将通过 tauri.conf.json resources 引用此路径" -ForegroundColor Gray

} catch {
    # 顶层错误捕获：防止任何未处理异常导致脚本直接闪退
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  生产构建失败：$($_.Exception.Message)" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "完整错误信息：" -ForegroundColor Yellow
    Write-Host "  $_" -ForegroundColor Yellow
    Write-Host ""
    if (-not $NoPause) {
        Write-Host "按 Enter 键退出..." -ForegroundColor Cyan
        Read-Host | Out-Null
    }
    exit 1
}

# 成功结束：双击运行场景下暂停以便查看结果，CI 场景（-NoPause）直接退出
if (-not $NoPause) {
    Write-Host ""
    Write-Host "按 Enter 键退出..." -ForegroundColor Cyan
    Read-Host | Out-Null
}
exit 0
