# tests/security/lib/Isolation.psm1 — 测试工作目录生命周期。
#
# 所有执行器工件落在系统临时目录下的独立 run 目录；默认删除，-KeepWork
# 保留用于取证。不在仓库内累积运行产物。

Set-StrictMode -Version Latest

function New-SecurityTempDir {
    [CmdletBinding()]
    param([string]$Prefix = 'verthys_security_')

    $path = Join-Path ([System.IO.Path]::GetTempPath()) ($Prefix + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    return $path
}

function Remove-SecurityTempDir {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$Keep
    )

    if ($Keep) { return }
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Copy-SecurityWorkArtifacts {
    <#
    .SYNOPSIS
    把临时工作目录中的执行器证据复制到 OutDir，使 result.json 的 evidence
    路径在临时目录清理后仍然可读。
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$WorkDir,
        [Parameter(Mandatory = $true)][string]$OutDir,
        [Parameter(Mandatory = $true)][string]$RunId
    )

    $destination = Join-Path $OutDir ('evidence/' + $RunId)
    New-Item -ItemType Directory -Path $destination -Force | Out-Null
    $children = @(Get-ChildItem -LiteralPath $WorkDir -Force -ErrorAction SilentlyContinue)
    foreach ($child in $children) {
        Copy-Item -LiteralPath $child.FullName -Destination $destination -Recurse -Force -ErrorAction SilentlyContinue
    }
    return $destination
}

function Update-SecurityEvidencePaths {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][string]$OldRoot,
        [Parameter(Mandatory = $true)][string]$NewRoot
    )

    foreach ($row in $Context.Results) {
        if ($null -eq $row.PSObject.Properties['evidence']) { continue }
        $value = [string]$row.evidence
        if ([string]::IsNullOrWhiteSpace($value)) { continue }
        $row.evidence = $value.Replace($OldRoot, $NewRoot)
    }
}

Export-ModuleMember -Function New-SecurityTempDir, Remove-SecurityTempDir,
Copy-SecurityWorkArtifacts, Update-SecurityEvidencePaths
