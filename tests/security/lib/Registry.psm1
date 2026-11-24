# tests/security/lib/Registry.psm1 — 用例注册表加载、校验与选择。
#
# 注册表是唯一权威来源：执行器只能返回注册表中存在的用例 ID，
# 新增用例必须先注册再实现，避免“脚本里多跑了一个检查但门禁不知道”。

Set-StrictMode -Version Latest

$script:AllowedProfiles = @('dev', 'standard', 'release', 'baseline')
$script:AllowedSuites = @('vault', 'service', 'tpm')
$script:AllowedKinds = @('behavioral', 'static', 'evidence', 'control')
$script:AllowedSeverities = @('critical', 'high', 'medium', 'low')

function Get-SecurityRegistryProperty {
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $Default }
    return $property.Value
}

function Test-SecurityRegistry {
    <#
    .SYNOPSIS
    校验注册表结构与 ID 约束，返回错误列表而不抛异常，便于自检逐项断言。
    #>
    [CmdletBinding()]
    param($Registry)

    $errors = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Registry) {
        $errors.Add('注册表为空')
        return [pscustomobject]@{ Valid = $false; Errors = @($errors) }
    }

    $schemaVersion = Get-SecurityRegistryProperty $Registry 'schemaVersion'
    if ($schemaVersion -ne 1) {
        $errors.Add("schemaVersion 必须为 1，实际为 $schemaVersion")
    }

    $cases = @(Get-SecurityRegistryProperty $Registry 'cases' @())
    if ($cases.Count -eq 0) {
        $errors.Add('cases 不能为空')
    }

    $ids = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $legacyIds = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)

    foreach ($case in $cases) {
        if ($null -eq $case) {
            $errors.Add('cases 包含空条目')
            continue
        }
        $id = [string](Get-SecurityRegistryProperty $case 'id' '')
        $legacyId = [string](Get-SecurityRegistryProperty $case 'legacyId' '')
        $suite = [string](Get-SecurityRegistryProperty $case 'suite' '')
        $name = [string](Get-SecurityRegistryProperty $case 'name' '')
        $severity = [string](Get-SecurityRegistryProperty $case 'severity' '')
        $requirement = [string](Get-SecurityRegistryProperty $case 'requirement' '')
        $kind = [string](Get-SecurityRegistryProperty $case 'kind' '')
        $requiredIn = @(Get-SecurityRegistryProperty $case 'requiredIn' @())
        $onlyIn = @(Get-SecurityRegistryProperty $case 'onlyIn' @())
        $executor = [string](Get-SecurityRegistryProperty $case 'executor' '')
        $evidence = [string](Get-SecurityRegistryProperty $case 'evidence' '')
        $description = [string](Get-SecurityRegistryProperty $case 'description' '')

        foreach ($pair in @(
                @('id', $id), @('legacyId', $legacyId), @('suite', $suite),
                @('name', $name), @('severity', $severity), @('requirement', $requirement),
                @('kind', $kind), @('executor', $executor), @('evidence', $evidence),
                @('description', $description)
            )) {
            if ([string]::IsNullOrWhiteSpace([string]$pair[1])) {
                $errors.Add("用例 $id 缺少字段 $($pair[0])")
            }
        }

        if (-not $ids.Add($id)) {
            $errors.Add("重复用例 ID: $id")
        }
        if (-not $legacyIds.Add($legacyId)) {
            $errors.Add("重复 legacyId: $legacyId")
        }

        if ($AllowedSuites -notcontains $suite) {
            $errors.Add("用例 $id 的 suite 未知: $suite")
        }
        if ($AllowedKinds -notcontains $kind) {
            $errors.Add("用例 $id 的 kind 未知: $kind")
        }
        if ($AllowedSeverities -notcontains $severity) {
            $errors.Add("用例 $id 的 severity 未知: $severity")
        }
        foreach ($profile in $requiredIn) {
            if ($AllowedProfiles -notcontains [string]$profile) {
                $errors.Add("用例 $id 的 requiredIn 含未知 profile: $profile")
            }
        }
        foreach ($profile in $onlyIn) {
            if ($AllowedProfiles -notcontains [string]$profile) {
                $errors.Add("用例 $id 的 onlyIn 含未知 profile: $profile")
            }
        }

        if ($isIdMatch = $id -match '^(CTRL|VAULT|SVC|TPM)-[A-Z0-9]+$') {
            $prefix = $Matches[1]
            $expectedSuite = switch ($prefix) {
                'CTRL' { 'vault' }
                'VAULT' { 'vault' }
                'SVC' { 'service' }
                'TPM' { 'tpm' }
                default { '' }
            }
            if ($expectedSuite -ne $suite) {
                $errors.Add("用例 $id 的 ID 前缀与 suite=$suite 不一致")
            }
        }
        else {
            $errors.Add("用例 ID 不符合命名空间: $id")
        }
    }

    return [pscustomobject]@{
        Valid  = ($errors.Count -eq 0)
        Errors = @($errors)
    }
}

function Import-SecurityCaseRegistry {
    <#
    .SYNOPSIS
    读取并校验 cases.json；结构错误通过 Errors 返回，JSON 解析失败直接抛出。
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "注册表不存在: $Path"
    }
    $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    $document = $raw | ConvertFrom-Json -ErrorAction Stop
    $validation = Test-SecurityRegistry -Registry $document

    $cases = @(Get-SecurityRegistryProperty $document 'cases' @())
    $byId = @{}
    $byLegacy = @{}
    foreach ($case in $cases) {
        $id = [string](Get-SecurityRegistryProperty $case 'id' '')
        $legacyId = [string](Get-SecurityRegistryProperty $case 'legacyId' '')
        if (-not [string]::IsNullOrWhiteSpace($id) -and -not $byId.ContainsKey($id)) {
            $byId[$id] = $case
        }
        if (-not [string]::IsNullOrWhiteSpace($legacyId) -and -not $byLegacy.ContainsKey($legacyId)) {
            $byLegacy[$legacyId] = $case
        }
    }

    return [pscustomobject]@{
        Path          = (Resolve-Path -LiteralPath $Path).Path
        SchemaVersion = Get-SecurityRegistryProperty $document 'schemaVersion' 0
        Cases         = $cases
        ById          = $byId
        ByLegacy      = $byLegacy
        Valid         = $validation.Valid
        Errors        = $validation.Errors
    }
}

function Resolve-SecurityCaseSelection {
    <#
    .SYNOPSIS
    按 profile 与 suite 返回本轮应执行的用例。
    baseline 只选 onlyIn 含 baseline 的控制用例；其他 profile 排除这些用例。
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Registry,
        [Parameter(Mandatory = $true)][string]$Suite,
        [Parameter(Mandatory = $true)][string]$Profile
    )

    $cases = @($Registry.Cases)
    if ($Profile -eq 'baseline') {
        return @($cases | Where-Object {
                @(Get-SecurityRegistryProperty $_ 'onlyIn' @()) -contains 'baseline'
            })
    }

    $suites = if ($Suite -eq 'all') { @('vault', 'service', 'tpm') } else { @($Suite) }
    return @($cases | Where-Object {
            $caseSuite = [string](Get-SecurityRegistryProperty $_ 'suite' '')
            $onlyIn = @(Get-SecurityRegistryProperty $_ 'onlyIn' @())
            ($suites -contains $caseSuite) -and ($onlyIn -notcontains 'baseline')
        })
}

function Get-SecurityRequiredCaseIds {
    <#
    .SYNOPSIS
    返回指定 profile 下必须 PASS 的用例 ID；dev 无必需项。
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Registry,
        [Parameter(Mandatory = $true)][string]$Profile
    )

    if ($Profile -eq 'dev') { return @() }
    return @($Registry.Cases | Where-Object {
            @(Get-SecurityRegistryProperty $_ 'requiredIn' @()) -contains $Profile
        } | ForEach-Object { [string]$_.id })
}

Export-ModuleMember -Function Import-SecurityCaseRegistry, Test-SecurityRegistry,
Resolve-SecurityCaseSelection, Get-SecurityRequiredCaseIds
