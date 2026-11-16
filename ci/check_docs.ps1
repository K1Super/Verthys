<#
.SYNOPSIS
    Documentation gate for link integrity, index coverage, metadata and version claims.

.DESCRIPTION
    Fails when any of the following is true:
      1. A relative Markdown link or HTML href/src points to a missing file.
      2. A Markdown file under docs/ is not indexed by docs/README.md.
      3. A docs file lacks a "Last updated: YYYY-MM-DD" metadata line
         (docs/references is exempt: frozen normative appendices).
      4. A deleted one-off document is still referenced.
      5. A product version, ABI version or container format claim in docs
         disagrees with VERSION or core/include/verthys_version.h.

    The script is ASCII-only and compatible with Windows PowerShell 5.1.
#>

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$docsRoot = Join-Path $projectRoot "docs"
$indexPath = Join-Path $docsRoot "README.md"
$errors = New-Object System.Collections.Generic.List[string]
$checkedLinks = 0

function Add-Error {
    param([string]$Message)
    $script:errors.Add($Message) | Out-Null
}

function Get-RelativePath {
    param([string]$BasePath, [string]$TargetPath)
    $base = (Resolve-Path -LiteralPath $BasePath).ProviderPath.TrimEnd('\') + '\'
    $target = (Resolve-Path -LiteralPath $TargetPath).ProviderPath
    if ($target.StartsWith($base, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $target.Substring($base.Length).Replace('\', '/')
    }
    return $target.Replace('\', '/')
}

if (-not (Test-Path -LiteralPath $indexPath)) {
    Write-Host "[docs gate][RED] missing index: docs/README.md"
    exit 1
}

# ---------------------------------------------------------------------------
# Collect documents
# ---------------------------------------------------------------------------
$docFiles = New-Object System.Collections.Generic.List[object]
foreach ($rootDoc in @("README.md", "CONTRIBUTING.md")) {
    $path = Join-Path $projectRoot $rootDoc
    if (Test-Path -LiteralPath $path) {
        $docFiles.Add((Get-Item -LiteralPath $path))
    }
}
foreach ($file in Get-ChildItem -Path $docsRoot -Recurse -File -Filter *.md) {
    $docFiles.Add($file)
}

# ---------------------------------------------------------------------------
# 1. Link integrity
# ---------------------------------------------------------------------------
$markdownLink = [regex]'!?\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)'
$htmlLink = [regex]'(?:href|src)\s*=\s*"([^"]+)"'

foreach ($file in $docFiles) {
    $text = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8
    $targets = New-Object System.Collections.Generic.List[string]
    foreach ($match in $markdownLink.Matches($text)) {
        $targets.Add($match.Groups[1].Value)
    }
    foreach ($match in $htmlLink.Matches($text)) {
        $targets.Add($match.Groups[1].Value)
    }

    foreach ($target in $targets) {
        if ([string]::IsNullOrWhiteSpace($target)) { continue }
        if ($target -match '^(https?:|mailto:|computer:|file:|#|javascript:)') { continue }
        $clean = $target.Split('#')[0]
        if ([string]::IsNullOrWhiteSpace($clean)) { continue }
        $clean = [System.Uri]::UnescapeDataString($clean)
        $resolved = Join-Path $file.DirectoryName $clean
        $checkedLinks++
        if (-not (Test-Path -LiteralPath $resolved)) {
            $relFile = Get-RelativePath -BasePath $projectRoot -TargetPath $file.FullName
            Add-Error "broken link: $relFile -> $target"
        }
    }
}

# ---------------------------------------------------------------------------
# 2. Index coverage
# ---------------------------------------------------------------------------
$indexText = Get-Content -LiteralPath $indexPath -Raw -Encoding UTF8
foreach ($file in Get-ChildItem -Path $docsRoot -Recurse -File -Filter *.md) {
    if ($file.FullName -eq $indexPath) { continue }
    $rel = Get-RelativePath -BasePath $docsRoot -TargetPath $file.FullName
    if (-not $indexText.Contains($rel)) {
        Add-Error "not indexed by docs/README.md: docs/$rel"
    }
}
foreach ($requiredRootLink in @("../README.md", "../CONTRIBUTING.md", "../CHANGELOG.md")) {
    if (-not $indexText.Contains($requiredRootLink)) {
        Add-Error "docs/README.md is missing root link: $requiredRootLink"
    }
}

# ---------------------------------------------------------------------------
# 3. Metadata
# ---------------------------------------------------------------------------
# CJK labels use \u escapes so this file stays ASCII and parses identically
# under Windows PowerShell 5.1 (which reads BOM-less files as ANSI).
$metadataPattern = [regex]'(Last updated|\u6700\u540E\u6838\u9A8C|\u6700\u540E\u66F4\u65B0)\s*[:\uFF1A]\s*(\d{4}-\d{2}-\d{2})'
foreach ($file in Get-ChildItem -Path $docsRoot -Recurse -File -Filter *.md) {
    $rel = Get-RelativePath -BasePath $docsRoot -TargetPath $file.FullName
    if ($rel.StartsWith('references/')) { continue }
    $head = (Get-Content -LiteralPath $file.FullName -TotalCount 20 -Encoding UTF8) -join "`n"
    if (-not $metadataPattern.IsMatch($head)) {
        Add-Error "missing metadata line in docs/$rel"
    }
}

# ---------------------------------------------------------------------------
# 4. Deleted one-off documents must stay deleted
# ---------------------------------------------------------------------------
$forbidden = @(
    'COMMENT_CLEANUP_REPORT',
    'DEV_DOCK_PRODUCTION_PLAN',
    'DEV_FIXTURE_FILL_PRODUCTION_PLAN',
    'key-material-persistence',
    'vault-create-failure',
    'vault-rotate-content-rekey',
    'p2-service-single-installer-plan',
    'UPDATER_LOCAL_VERIFICATION'
)
foreach ($file in $docFiles) {
    $text = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8
    foreach ($name in $forbidden) {
        if ($text.Contains($name)) {
            $relFile = Get-RelativePath -BasePath $projectRoot -TargetPath $file.FullName
            Add-Error "deleted document is still referenced: $relFile -> $name"
        }
    }
}

# ---------------------------------------------------------------------------
# 5. Version claims
# ---------------------------------------------------------------------------
$version = (Get-Content -LiteralPath (Join-Path $projectRoot "VERSION") -Raw).Trim()
$versionHeader = Get-Content -LiteralPath (Join-Path $projectRoot "core\include\verthys_version.h") -Raw

$abiMatch = [regex]::Match($versionHeader, 'VERTHYS_API_VERSION\s+(0x[0-9A-Fa-f]{4})u?')
if (-not $abiMatch.Success) {
    Add-Error "cannot read VERTHYS_API_VERSION from core/include/verthys_version.h"
    $abi = ""
} else {
    $abi = $abiMatch.Groups[1].Value.ToUpperInvariant()
}

$formatMatch = [regex]::Match($versionHeader, 'VERTHYS_CONTAINER_FORMAT_VERSION\s+(\d+)u?')
if (-not $formatMatch.Success) {
    Add-Error "cannot read VERTHYS_CONTAINER_FORMAT_VERSION from core/include/verthys_version.h"
    $containerFormat = ""
} else {
    $containerFormat = $formatMatch.Groups[1].Value
}

$productClaim = [regex]'(Verthys|\u5F53\u524D\u7248\u672C|\u4EA7\u54C1\u7248\u672C|\u4EA7\u54C1)\s*([0-9]+\.[0-9]+\.[0-9]+)'
$abiClaim = [regex]'VERTHYS_API_VERSION\s*[=:]\s*(0x[0-9A-Fa-f]{4})'
$containerClaim = [regex]'VERTHYS_CONTAINER_FORMAT_VERSION\s*[=:]\s*(\d+)'
$readmeAbiClaim = [regex]'ABI[^0-9]{0,40}(0x[0-9A-Fa-f]{4})'
$readmeContainerClaim = [regex]'\u5BB9\u5668[^0-9A-Za-z]{0,30}V(\d+)'

foreach ($file in $docFiles) {
    $relFile = Get-RelativePath -BasePath $projectRoot -TargetPath $file.FullName
    $text = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8

    foreach ($match in $productClaim.Matches($text)) {
        $claimed = $match.Groups[2].Value
        if ($claimed -ne $version) {
            Add-Error "stale product version in ${relFile}: $claimed (expected $version)"
        }
    }

    foreach ($match in $abiClaim.Matches($text)) {
        $claimed = $match.Groups[1].Value.ToUpperInvariant()
        if ($abi -ne "" -and $claimed -ne $abi) {
            Add-Error "stale ABI claim in ${relFile}: $claimed (expected $abi)"
        }
    }

    foreach ($match in $containerClaim.Matches($text)) {
        $claimed = $match.Groups[1].Value
        if ($containerFormat -ne "" -and $claimed -ne $containerFormat) {
            Add-Error "stale container format claim in ${relFile}: $claimed (expected $containerFormat)"
        }
    }

    if ($relFile -eq 'README.md') {
        foreach ($match in $readmeAbiClaim.Matches($text)) {
            $claimed = $match.Groups[1].Value.ToUpperInvariant()
            if ($abi -ne "" -and $claimed -ne $abi) {
                Add-Error "stale README ABI claim: $claimed (expected $abi)"
            }
        }
        foreach ($match in $readmeContainerClaim.Matches($text)) {
            $claimed = $match.Groups[1].Value
            if ($containerFormat -ne "" -and $claimed -ne $containerFormat) {
                Add-Error "stale README container claim: V$claimed (expected V$containerFormat)"
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "docs gate: $($docFiles.Count) files, $checkedLinks links checked"
if ($errors.Count -eq 0) {
    Write-Host "[docs gate] PASS"
    exit 0
}

foreach ($message in $errors) {
    Write-Host "[docs gate][RED] $message"
}
Write-Host "[docs gate] FAIL: $($errors.Count) issue(s)"
exit 1
