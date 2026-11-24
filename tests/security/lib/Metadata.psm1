# tests/security/lib/Metadata.psm1 — 运行元数据与产物指纹采集。
#
# 证据必须能回答“这是在哪份代码、哪个二进制上跑出来的”。所有哈希统一
# 小写十六进制；缺失产物记为 null，不伪造空字符串。

Set-StrictMode -Version Latest

function Get-SecurityFileSha256 {
    [CmdletBinding()]
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return $null
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Resolve-SecurityDllPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [string]$DllPath
    )

    if (-not [string]::IsNullOrWhiteSpace($DllPath)) { return $DllPath }
    if (-not [string]::IsNullOrWhiteSpace($env:VERTHYS_CORE_DLL)) { return $env:VERTHYS_CORE_DLL }
    foreach ($relative in @('build/core/Release/verthys.dll', 'build/core/Debug/verthys.dll')) {
        $candidate = Join-Path $RepoRoot $relative
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    return $null
}

function Resolve-SecurityWorkerPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [string]$WorkerPath
    )

    if (-not [string]::IsNullOrWhiteSpace($WorkerPath)) { return $WorkerPath }
    if (-not [string]::IsNullOrWhiteSpace($env:VERTHYS_WORKER_EXE)) { return $env:VERTHYS_WORKER_EXE }
    return (Join-Path $RepoRoot 'verthys-tauri/verthys-worker/target/release/verthys-worker.exe')
}

function Resolve-SecurityServicePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [string]$ServiceBuildDir
    )

    if ([string]::IsNullOrWhiteSpace($ServiceBuildDir)) {
        $ServiceBuildDir = if (-not [string]::IsNullOrWhiteSpace($env:VERTHYS_SERVICE_BUILD_DIR)) {
            $env:VERTHYS_SERVICE_BUILD_DIR
        }
        else {
            Join-Path $RepoRoot 'build_security_service'
        }
    }
    return (Join-Path $ServiceBuildDir 'Debug/VerthysSecuritySvc.exe')
}

function Get-SecurityMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$RegistryPath,
        [string]$DllPath,
        [string]$WorkerPath,
        [string]$ServiceBuildDir
    )

    $gitCommit = $null
    $gitDirty = $null
    try {
        $commit = @(& git -C $RepoRoot rev-parse HEAD 2>$null)
        if ($LASTEXITCODE -eq 0 -and $commit.Count -gt 0) {
            $gitCommit = ([string]$commit[0]).Trim()
        }
        $status = @(& git -C $RepoRoot status --porcelain 2>$null)
        if ($LASTEXITCODE -eq 0) {
            $gitDirty = ($status.Count -gt 0)
        }
    }
    catch {
        # 无 git 的工作目录（导出包/CI 浅克隆）不阻断测试，元数据如实留空。
    }

    $resolvedDll = if (-not [string]::IsNullOrWhiteSpace($DllPath)) { $DllPath } else { Resolve-SecurityDllPath -RepoRoot $RepoRoot }
    $resolvedWorker = Resolve-SecurityWorkerPath -RepoRoot $RepoRoot -WorkerPath $WorkerPath
    $resolvedService = Resolve-SecurityServicePath -RepoRoot $RepoRoot -ServiceBuildDir $ServiceBuildDir

    return [pscustomobject]@{
        gitCommit     = $gitCommit
        gitDirty      = $gitDirty
        osBuild       = [Environment]::OSVersion.Version.Build.ToString()
        powershell    = $PSVersionTable.PSVersion.ToString()
        dllSha256     = Get-SecurityFileSha256 -Path $resolvedDll
        workerSha256  = Get-SecurityFileSha256 -Path $resolvedWorker
        serviceSha256 = Get-SecurityFileSha256 -Path $resolvedService
        registrySha256 = (Get-SecurityFileSha256 -Path $RegistryPath)
        dllPath       = $resolvedDll
        workerPath    = $resolvedWorker
        servicePath   = $resolvedService
    }
}

Export-ModuleMember -Function Get-SecurityFileSha256, Resolve-SecurityDllPath,
Resolve-SecurityWorkerPath, Resolve-SecurityServicePath, Get-SecurityMetadata
