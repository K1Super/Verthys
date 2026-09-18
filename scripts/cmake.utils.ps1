# scripts/cmake.utils.ps1 - CMake 构建缓存健康度工具（陈旧缓存自动检测与自愈）
#
# ★ 编码警告：本文件必须保存为 UTF-8 with BOM 编码！
#   Windows PowerShell 5.1 对无 BOM 文件按 ANSI/GBK 解码，中文注释乱码会
#   破坏字符串配对导致解析错误（ParseError），而解析错误发生在任何代码
#   执行之前，try/catch 与 Read-Host 暂停完全失效。保存后请确认文件头
#   3 字节为 EF BB BF。
#
# 背景（2026-09-19 根因修复）：
#   项目目录从 Desktop\Project\ValtCore 迁移至 Desktop\Verthys 后，随目录
#   携带的 build/ 与 build_dev/ 中 CMakeCache.txt 仍记录旧绝对路径：
#     CMAKE_HOME_DIRECTORY:INTERNAL=c:/Users/.../ValtCore
#   CMake 以源目录不匹配为由直接拒绝配置：
#     "The current CMakeCache.txt directory ... is different than the directory
#      ... where CMakeCache.txt was created"
#   CMake 缓存按绝对路径寻址，项目根目录任何移动/重命名都会使缓存整体失效。
#   代码层面的品牌更名（project(Verthys)）不受影响——只要路径不变，缓存照常可用。
#
# 使用方式：在构建脚本顶部 dot-source 引入，于 cmake -S ... -B ... 之前调用
#   . $PSScriptRoot\cmake.utils.ps1
#   Clear-StaleCMakeCache -BuildDir <构建目录> -SourceDir <当前源目录>
#
# 行为契约：
#   - 构建目录无 CMakeCache.txt          → 不动（全新目录，正常配置）
#   - 缓存记录的源目录 == 当前源目录
#     且记录的缓存目录 == 当前构建目录    → 不动（缓存健康，保留增量构建）
#   - 任一记录与当前实际路径不一致        → 自动删除整个构建目录（全量重建自愈）
#   - 缓存存在但无法解析出记录路径        → 视为缓存损坏，同上自动清理
function Clear-StaleCMakeCache {
    param(
        [Parameter(Mandatory = $true)][string]$BuildDir,
        [Parameter(Mandatory = $true)][string]$SourceDir
    )

    $cacheFile = Join-Path $BuildDir "CMakeCache.txt"
    if (-not (Test-Path -LiteralPath $cacheFile)) { return }

    # 解析缓存中的两条权威路径记录（CMake 启动校验的正是这两项）
    # ★ 必须用 ReadAllLines 急切读取：ReadLines 返回惰性枚举，break 跳出后
    # 迭代器不释放文件句柄（PowerShell foreach 不会对中断的枚举确定性
    # Dispose），句柄滞留在本进程内 → 随后 Remove-Item 删除构建目录时报
    # "being used by another process"（自锁，实测复现）。ReadAllLines 读
    # 完即关句柄；CMakeCache.txt 仅数十 KB，急切读取无内存压力。
    $cachedSource   = $null
    $cachedBuildDir = $null
    foreach ($line in [System.IO.File]::ReadAllLines($cacheFile)) {
        if (-not $cachedSource -and $line -match '^CMAKE_HOME_DIRECTORY:INTERNAL=(.+?)\s*$') {
            $cachedSource = $Matches[1]
        } elseif (-not $cachedBuildDir -and $line -match '^CMAKE_CACHEFILE_DIR:INTERNAL=(.+?)\s*$') {
            $cachedBuildDir = $Matches[1]
        }
        if ($cachedSource -and $cachedBuildDir) { break }
    }

    # 归一化：统一正斜杠 + 去尾部斜杠（Windows 路径大小写不敏感，用 -ieq 比较）
    $normSource   = ((Resolve-Path -LiteralPath $SourceDir).ProviderPath -replace '\\', '/').TrimEnd('/')
    $normBuildDir = ((Resolve-Path -LiteralPath $BuildDir).ProviderPath   -replace '\\', '/').TrimEnd('/')

    if ($cachedSource -and $cachedBuildDir) {
        $normCachedSource   = ($cachedSource   -replace '\\', '/').TrimEnd('/')
        $normCachedBuildDir = ($cachedBuildDir -replace '\\', '/').TrimEnd('/')
        if ($normCachedSource -ieq $normSource -and $normCachedBuildDir -ieq $normBuildDir) {
            return   # 缓存健康，保留增量构建能力
        }
    }

    Write-Host "[cmake.cache] 检测到陈旧 CMake 缓存，自动清理（项目目录迁移/缓存损坏）" -ForegroundColor Yellow
    if ($cachedSource) {
        Write-Host "  缓存记录的源目录:   $cachedSource" -ForegroundColor Yellow
    } else {
        Write-Host "  缓存记录的源目录:   无法解析（缓存损坏）" -ForegroundColor Yellow
    }
    if ($cachedBuildDir) {
        Write-Host "  缓存记录的构建目录: $cachedBuildDir" -ForegroundColor Yellow
    }
    Write-Host "  当前源目录:         $normSource" -ForegroundColor Yellow
    Write-Host "  清理构建目录:       $normBuildDir（随后全量重建）" -ForegroundColor Yellow
    # ★ 有界重试：CMakeCache.txt 可能被正在退出的残留 cmake 进程或杀软/索引
    # 服务瞬时占用（实测出现过：进程已不存在但句柄延迟释放）。此类锁通常
    # 1-2 秒内释放，盲目 fail 会把可自愈的场景变成硬失败，故重试 3 次。
    $removed = $false
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            Remove-Item -Recurse -Force -LiteralPath $BuildDir -ErrorAction Stop
            $removed = $true
            break
        } catch {
            if ($attempt -lt 3) {
                Write-Host "  [retry] 目录被占用，2 秒后重试（第 $attempt/3 次）..." -ForegroundColor DarkYellow
                Start-Sleep -Seconds 2
            }
        }
    }
    if (-not $removed) {
        throw "陈旧缓存清理失败（构建目录被运行中的应用持续占用，请关闭后重试）: $BuildDir"
    }
}
