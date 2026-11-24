# scripts/build/build_kernel_probe.ps1 — build the user-mode kernel-guard probe.
param(
    [string]$OutDir = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $repoRoot 'scripts\lib\env.load.ps1')

if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $repoRoot 'build_kernel_probe'
}
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$sourceDir = Join-Path $repoRoot 'tests\kernel-guard'
$include = Join-Path $repoRoot 'kernel\include'
$targets = @(
    @{ Source = 'kg_probe.c'; Exe = 'kg_probe.exe' },
    @{ Source = 'kg_arm_probe.c'; Exe = 'kg_arm_probe.exe' },
    @{ Source = 'kg_create_probe.c'; Exe = 'kg_create_probe.exe' },
    @{ Source = 'kg_creator.c'; Exe = 'kg_creator.exe' },
    @{ Source = 'kg_attack.c'; Exe = 'kg_attack.exe' },
    @{ Source = 'kg_a14_probe.c'; Exe = 'kg_a14_probe.exe' },
    @{ Source = 'kg_dummy_worker.c'; Exe = 'kg_dummy_worker.exe' }
)

Write-Host "Building kernel-guard probes (x64)"
foreach ($target in $targets) {
    $source = Join-Path $sourceDir $target.Source
    $exe = Join-Path $OutDir $target.Exe
    & $script:VERTHYS_CL_EXE /nologo /W4 /WX /utf-8 /I $include $source `
        "/Fe:$exe" /link /SUBSYSTEM:CONSOLE advapi32.lib
    if ($LASTEXITCODE -ne 0) {
        throw "$($target.Source) build failed with exit code $LASTEXITCODE"
    }
    if (-not (Test-Path -LiteralPath $exe)) {
        throw "$($target.Exe) missing after build"
    }
    Write-Host "$($target.Exe): $exe"
    Get-Item -LiteralPath $exe | Select-Object FullName, Length, LastWriteTime | Format-List
}
